//! The start path: `kern box`/`kern run`, its plan preview, and `kern exec`.
//!
//! What turns a request into a live box: argument resolution, the rootfs staging, the optional
//! re-exec into a transient systemd scope, the supervisor that outlives a detached box and records
//! its exit, and the persistent unit. The largest and most interconnected part of the CLI, so the
//! shared machinery it sits on (the registry, the cgroup accessors, the config resolvers) stays in
//! the parent and is reached through `use super::*`.

use super::*;

/// `kern box <name> --plan` - show the ordered mount/pivot/remount sequence the sandbox setup
/// would perform. Privilege-free: it records the sequence via the isolation seam rather than
/// executing it, so it works anywhere and exercises the 0.2 step-sequence + mount-ordering
/// typestate end to end.
pub fn box_plan(
    name: &str,
    profiles: &[String],
    config: Option<&str>,
    gpus: Option<&str>,
    device: Option<&str>,
) -> Result<(), Error> {
    let name = BoxName::parse(name).map_err(Error::InvalidBox)?;
    let ctx = SandboxCtx::new(name);
    println!("isolation plan for box '{}':", ctx.name.as_str());
    for (i, step) in ctx.plan().iter().enumerate() {
        println!("  {}. {step}", i + 1);
    }
    // The mount sequence is only half of what a box gets. A profile hands over real caps, real
    // device nodes and a real mount, and a preview that lists three mounts while saying nothing
    // about `/dev/i2c-5`, a 256M ceiling or a 48M scratch disk is not a preview of what will be
    // created. That reasoning was applied to `vgpio:` alone, so a box carrying all three kinds
    // previewed one of them; all three are reported now.
    //
    // Every one is resolved against THIS host with the same call the launch makes, so the preview
    // and the launch cannot disagree, and a profile that cannot attach says so here instead of at
    // launch.
    let pick = |kind: &str| -> Vec<&str> {
        profiles
            .iter()
            .filter_map(|p| p.strip_prefix(kind))
            .filter(|n| !n.is_empty())
            .collect()
    };
    // THE GPU GRANT IS PREVIEWED AND NOTHING ELSE. The resolver mounts nothing and changes no
    // process state; this prints what a later phase would act on, which is the whole of S1's
    // surface. A host with no NVIDIA driver prints NOTHING rather than a reassuring line about an
    // absence, because the plan describes what this box would get and that host gives it none.
    //
    // The two faults that ARE worth naming do get named: a driver whose version line cannot be
    // parsed, and a driver that is loaded while its device nodes are missing. Both are states a
    // reader can act on, and both are invisible without being said.
    //
    // 🚨 AND IT NOW DEPENDS ON THE REQUEST, which it did not. `--gpus` and `--device` were dropped
    // by the parser on the `--plan` path, so this printed the whole host inventory for a box with
    // NO GPU flag, which previews hardware that box will never see, and printed the same inventory
    // for `--gpus device=0`, which previews cards it did not ask for. A preview that does not
    // depend on the request is not a preview of the request.
    //
    // ASKING FOR A CARD SELECTS `Detail::Full`, which had no production caller at all, so the one
    // thing an operator needs from a device preview was unreachable: the NAMES of the host paths
    // they are authorising. A box with no GPU flag still gets nothing, so the long form is only
    // printed to somebody who asked for hardware AND asked to see the plan.
    let gpu_request = match (gpus, device) {
        (Some(spec), _) => {
            // THE CAPABILITIES TOKEN, ANSWERED OUT LOUD on the plan as well: an operator reading
            // the plan to see what a box gets is entitled to know that the list they wrote chose
            // nothing and that nothing is missing either.
            if let Some(note) = crate::gpu_grant::capabilities_note(spec) {
                println!("  gpu grant: {note}");
            }
            // `Ok(None)` IS "no card asked for", which lands on the same path as no flag at all.
            let asked = crate::gpu_grant::selection_from_spec(std::path::Path::new("/"), spec)
                .or_else(|e| wsl_unchecked_uuid(spec, e, |note| println!("  gpu grant: {note}")))
                .map_err(|e| {
                    Error::Cli(format!("--plan: --gpus {spec} is not a selection: {e:?}"))
                })?;
            if asked.is_none() {
                println!("  gpu grant: {}", crate::gpu_grant::describe_no_gpu(spec));
            }
            asked
        }
        // Every CDI name on the line, and this is a preview, so a spec that does not name one of
        // them here is the launch's refusal to report and not the plan's.
        (None, Some(reference)) => {
            match crate::cdi::resolve_device_refs(std::path::Path::new("/"), reference) {
                Ok(resolved) => {
                    // ON THE PLAN TOO, and in the plan's own voice: an operator reading
                    // `--plan` to find out what a box will get is the reader most entitled to
                    // know which part of the spec kern does not act on.
                    if let Some(msg) =
                        crate::cdi::describe_hooks_not_run(reference, &resolved.hooks_not_run)
                    {
                        println!("  gpu grant: {msg}");
                    }
                    for kv in &resolved.env {
                        println!("  gpu grant: env {kv} (from the CDI spec)");
                    }
                    Some(match resolved.indices {
                        Some(indices) => crate::gpu_grant::GpuSelection::These(indices),
                        None => crate::gpu_grant::GpuSelection::All,
                    })
                }
                Err(_) => {
                    println!(
                    "  gpu grant: --device {reference} does not resolve on this host, so `kern \
                     box` would refuse it; run `kern doctor` for which CDI specs are readable"
                );
                    None
                }
            }
        }
        (None, None) => None,
    };

    match (gpu_request, crate::gpu_grant::resolve()) {
        // NO FLAG, NO PREVIEW. The box gets no card, and printing the host's inventory under the
        // heading of this box's plan said the opposite.
        (None, _) => {}
        (Some(selection), Ok(grant)) => {
            println!("  gpu grant (preview, nothing is mounted by --plan):");
            // THE SELECTION, not the grant. `mount_plan` is the same call the launch makes, so a
            // selection this host cannot satisfy is refused here with the launch's own reason
            // instead of being previewed as though it would work.
            let caller = crate::gpu_grant::Caller::current();
            match crate::gpu_grant::mount_plan(&grant, &selection, &caller) {
                Ok(_) => {
                    // EVERY PATH BY NAME. There is no short form any more: the enum that chose
                    // between them had a `Summary` variant nobody constructed once the plan
                    // started printing the full list, which is the same no-caller smell the
                    // `Full` variant had before. An operator who typed `--plan` AND asked for a
                    // card wants the paths they are authorising.
                    for line in crate::gpu_grant::render_plan(&grant, &selection).lines() {
                        println!("    {line}");
                    }
                    println!(
                        "    the libraries go into the image's library directory: {LIB_DIR_RULE}"
                    );
                    if let Some(spec) = gpus {
                        println!(
                            "    env NVIDIA_VISIBLE_DEVICES={}",
                            crate::gpu_grant::visible_devices(
                                spec,
                                &selection,
                                crate::gpu_grant::granted_indices(&grant, &selection).as_deref()
                            )
                        );
                    }
                }
                Err(why) => println!(
                    "    this selection would be refused: {}",
                    crate::gpu_grant::describe_mount_plan_error(&why)
                ),
            }
        }
        (Some(selection), Err(crate::gpu_grant::ResolveError::NoDriverVersionFile { .. }))
            if crate::gpu::wsl_grant(std::path::Path::new("/")).is_some() =>
        {
            // THE PREVIEW OF THE WSL2 GRANT, from the same function the launch calls, so what is
            // listed here is what `kern box` mounts.
            match crate::gpu::wsl_grant(std::path::Path::new("/")) {
                Some(Ok(w)) => {
                    println!(
                        "  gpu grant (preview, nothing is mounted by --plan): WSL2 paravirtual GPU"
                    );
                    for (source, target, read_only) in &w.binds {
                        println!(
                            "    {source} -> {target}{}",
                            if *read_only { " (read-only)" } else { "" }
                        );
                    }
                    println!(
                        "    libraries {}, each into the image's library directory: {LIB_DIR_RULE}",
                        w.libraries.len()
                    );
                    for (source, name) in &w.libraries {
                        println!("      lib {source} as {name}");
                    }
                    if let Some(spec) = gpus {
                        println!(
                            "    env NVIDIA_VISIBLE_DEVICES={}",
                            crate::gpu_grant::visible_devices(spec, &selection, None)
                        );
                    }
                    if !matches!(selection, crate::gpu_grant::GpuSelection::All) {
                        match crate::gpu::wsl_adapter_indices(std::path::Path::new("/")) {
                            Some(adapters) => {
                                match crate::gpu::wsl_check_selection(&selection, &adapters) {
                                    Ok(true) => println!(
                                        "    every adapter the WSL2 VM has ({}) comes with it: WSL2 \
                                         has no per-card node",
                                        adapters.len()
                                    ),
                                    Ok(false) => {}
                                    Err(e) => println!(
                                        "    this selection would be refused: {}",
                                        crate::gpu_grant::describe_mount_plan_error(&e)
                                    ),
                                }
                            }
                            None => println!(
                                "    the adapters could not be counted here, so the selection \
                                 is not checked; every adapter comes with /dev/dxg"
                            ),
                        }
                    }
                }
                Some(Err(e)) => {
                    println!("  gpu grant: {}", crate::gpu::describe_wsl_grant_error(&e))
                }
                None => {}
            }
        }
        (Some(_), Err(crate::gpu_grant::ResolveError::NoDriverVersionFile { .. })) => {
            // IN THIS KERNEL, not "on this host": on a WSL2 guest the driver IS loaded, on the
            // other side of the paravirtual boundary, and what is absent is the version file kern
            // reads. `with_foreign_shape` adds the sentence naming what is there instead.
            println!(
                "  gpu grant: {}",
                crate::gpu::with_foreign_shape(
                    "a GPU was asked for and no NVIDIA driver is loaded in this kernel, so \
                     `kern box` would refuse it",
                    std::path::Path::new("/"),
                )
            );
        }
        (Some(_), Err(crate::gpu_grant::ResolveError::DriverVersionUnparsable { first_line })) => {
            println!(
                "  gpu grant: an NVIDIA driver is loaded and its version line carries no version: \
                 {first_line:?}"
            );
        }
        (Some(_), Err(crate::gpu_grant::ResolveError::NoNodes { driver_version })) => {
            println!(
                "  gpu grant: driver {driver_version} is loaded and no device node exists under \
                 /dev, so no GPU can be granted"
            );
        }
    }

    let (vcpu, vgpio, vdisk) = (pick("vcpu:"), pick("vgpio:"), pick("vdisk:"));
    if vcpu.is_empty() && vgpio.is_empty() && vdisk.is_empty() {
        return Ok(());
    }
    // A PROFILE THAT CANNOT ATTACH IS AN OUTCOME, NOT A LINE. The preview names every one of them and
    // then exits non-zero, because the launch carrying that profile is going to fail. Measured before
    // this: `kern box … --config <file> vcpu:nope --plan` printed the refusal and exited 0, while the
    // same command without `--plan` exited 1, so `kern box … --plan && kern box …` walked on to a
    // launch the preview had already established could not happen, and a pipeline gating on the
    // preview learned nothing from it.
    //
    // COUNTED rather than returned at the first failure, so the whole plan still prints and every
    // broken profile is visible in one pass. Stopping at the first would send an operator round the
    // loop once per typo.
    let mut refused = 0usize;
    // Loaded once for all three: `--plan` is a preview, but reading the same file three times would
    // let two kinds disagree if it changed underneath.
    //
    // `config`, not None. Passing None here reads $KERN_CONFIG or the default location while the
    // launch would read the `--config` path, so the preview answered about a different file: with a
    // valid profile in the file that was passed, `--plan` printed "cannot attach: no [[vcpu]]
    // profile named 'slim' in kern.toml" and the launch attached it. A preview that resolves
    // against a different source than the launch is worse than no preview, because it is believed.
    let cfg = crate::config::load(config).map_err(Error::Config)?;
    for n in vcpu {
        match crate::config::resolve_vcpu(&cfg, n) {
            Ok(r) => {
                let mut caps: Vec<String> = Vec::new();
                if let Some(c) = r.cpus {
                    caps.push(format!("cpus {c}"));
                }
                if let Some(m) = r.memory {
                    caps.push(format!("memory {}", kern_common::fmt_bytes(m)));
                }
                if let Some(s) = &r.cpuset {
                    caps.push(format!("cpuset {s}"));
                }
                if let Some(nc) = r.nice {
                    caps.push(format!("nice {nc}"));
                }
                if caps.is_empty() {
                    // A profile that resolves to nothing is worth saying: it attaches and caps
                    // nothing, which is not what the name suggests.
                    println!("  resource caps from vcpu:{n}: none set");
                } else {
                    println!("  resource caps from vcpu:{n}: {}", caps.join(", "));
                }
            }
            Err(e) => {
                refused += 1;
                println!("  vcpu:{n}: cannot attach: {e}");
            }
        }
    }
    for n in vgpio {
        match crate::config::resolve_vgpio(&cfg, n) {
            Ok(r) if r.devs.is_empty() && r.sysfs.is_empty() && r.pins.is_empty() => {
                println!("  device grants from vgpio:{n}: none on this host");
            }
            Ok(r) => {
                println!("  device grants from vgpio:{n}:");
                for d in &r.devs {
                    println!("    bind {d}");
                }
                for s in &r.sysfs {
                    println!("    bind {s} (sysfs)");
                }
                if !r.pins.is_empty() {
                    println!(
                        "    pins {:?} (chip-granular: the chardev exposes every line)",
                        r.pins
                    );
                }
                // A GRANTED COMPUTE NODE IS WHERE THE CLAIM IS WORTH READING, and this line prints
                // only when a profile actually hands one over.
                //
                // IT USED TO DESCRIBE A MECHANISM kern DOES NOT HAVE: a "cooperative VRAM quota"
                // and, where a boundary was wanted, "a device-level partition (MIG or SR-IOV)".
                // kern caps no VRAM and partitions no device, so the sentence spent four lines
                // answering a question about a feature that was never offered. What a reader
                // handing over a compute node needs is what the node IS, and the promise that does
                // hold is the one about the cards they did not hand over.
                if r.devs.iter().any(|d| crate::gpu::is_compute_node(d)) {
                    println!("    {}", crate::gpu::COMPUTE_NODE_CLAIM);
                }
            }
            Err(e) => {
                refused += 1;
                println!("  vgpio:{n}: cannot attach: {e}");
            }
        }
    }
    for n in vdisk {
        match crate::config::resolve_vdisk(&cfg, n) {
            Ok(r) => {
                let size = r
                    .size
                    .map_or_else(|| "uncapped".to_string(), kern_common::fmt_bytes);
                println!("  disk from vdisk:{n}: mount /vdisk/{n}, size {size}");
                // Which backend actually lands is decided by privilege at launch, not by the
                // profile, so the preview says both rather than picking one and being wrong half
                // the time.
                match &r.backend_dir {
                    Some(d) => println!(
                        "    ext4-on-loop under {d} when privileged in the foreground, \
                         RAM-backed tmpfs otherwise"
                    ),
                    None => println!("    RAM-backed tmpfs (counts against the box's memory)"),
                }
                if let Some(i) = r.iops {
                    println!("    iops {i} (ext4-on-loop backend only)");
                }
                if let Some(bw) = r.bandwidth {
                    println!(
                        "    bandwidth {} (ext4-on-loop backend only)",
                        kern_common::fmt_bytes(bw)
                    );
                }
                if r.persistent {
                    println!("    persistent (ext4-on-loop backend only)");
                }
            }
            Err(e) => {
                refused += 1;
                println!("  vdisk:{n}: cannot attach: {e}");
            }
        }
    }
    // THE EXIT CODE HAS TO AGREE WITH THE TEXT, which is why the count above is kept.
    if refused > 0 {
        return Err(Error::Cli(format!(
            "{refused} profile(s) named above cannot attach, so this box would not start. The plan \
             is printed in full so every one of them can be fixed in one pass."
        )));
    }
    Ok(())
}

/// `--ssh` PREFLIGHT: sshd's privilege separation calls `setgroups()`, which a single-uid userns
/// forbids (`/proc/self/setgroups=deny`). It works only with a real uid RANGE via newuidmap/subuid.
/// On a host without those (common on edge boards), `--ssh` would leave a listening port whose auth
/// silently closes with a confusing "Connection closed" - so say it up front instead of at handshake.
///
/// A warning, never a refusal: the box itself is fine, only the ssh login will not be, and the caller
/// may well be starting it to run `kern exec` against.
/// Apply `nice`, and SAY SO when the kernel refuses it.
///
/// `setpriority`'s return value was discarded at both call sites (`kern box` and `kern run`), and the
/// difference matters in exactly one direction: LOWERING the nice value - a negative number, meaning
/// more CPU - needs `CAP_SYS_NICE` or `RLIMIT_NICE` headroom, and a rootless box has neither by
/// default. MEASURED on this host (`ulimit -e` 0): `--nice -5` and `--nice -1` both left the workload
/// at nice 0, while `--nice 5` and `--nice 19` took effect, and nothing was printed in any of the four
/// cases. A field report found the same thing through a `[[vcpu]]` profile's `nice = -5` and read it
/// as a profile bug; the profile is only one of the two routes to this line.
///
/// A WARNING, NOT A REFUSAL. Raising the nice value works everywhere, lowering it works for a caller
/// who has the privilege, and a `nice` is a scheduling preference rather than a boundary: refusing the
/// box would punish the hosts where it legitimately cannot apply. What the project does refuse is
/// accepting a flag and silently doing nothing with it.
///
/// The message reports the ERRNO and what the box is left with, and does not guess a cause beyond what
/// `setpriority` documents for that errno.
fn apply_nice(n: i32) {
    if unsafe { libc::setpriority(libc::PRIO_PROCESS as _, 0, n) } == 0 {
        return;
    }
    let e = std::io::Error::last_os_error();
    if n < 0 {
        eprintln!(
            "kern: warning: nice {n} not applied ({e}): lowering the nice value needs CAP_SYS_NICE \
             or RLIMIT_NICE headroom (`ulimit -e`), which a rootless box does not have by default - \
             the workload keeps the nice it inherited"
        );
    } else {
        eprintln!(
            "kern: warning: nice {n} not applied ({e}) - the workload keeps the nice it inherited"
        );
    }
}

fn warn_if_ssh_lacks_a_uid_range(ssh_port: Option<u16>) {
    if ssh_port.is_none() {
        return;
    }
    let uid = unsafe { libc::getuid() };
    let uname = kern_isolation::username(uid);
    let have_range = kern_isolation::trusted_helper("newuidmap").is_some()
        && kern_isolation::sub_range("/etc/subuid", uname.as_deref(), uid).is_some();
    if !have_range {
        eprintln!(
            "kern: warning: --ssh needs a uid range (newuidmap + /etc/subuid) for sshd's privsep; \
             this host has none, so sshd will refuse the login (setgroups denied). Install \
             newuidmap/uidmap + add a subuid allocation, or use `kern exec` instead of ssh."
        );
    }
}

/// The `nameserver` addresses in a pod's shared `resolv.conf`, in file order.
///
/// Read rather than re-derived: the pod's file is written once by `pod create` from whatever the host
/// resolver was at that moment, and deriving it a second time here could disagree with what the other
/// members are actually using. A line that is not a `nameserver` (a `search`, a comment) is skipped,
/// because this exists only to keep a box's resolvers when it asked to change something else.
fn pod_nameservers(path: &std::path::Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            l.split_whitespace()
                .next()
                .filter(|h| *h == "nameserver")
                .and(l.split_whitespace().nth(1))
        })
        .map(str::to_string)
        .collect()
}

/// `--pod <name>`: join the pod's shared user+net namespace (created by `kern pod create`). Resolves
/// its live holder PID, registers this box in the pod's shared `/etc/hosts` (so peers resolve it by
/// name), and binds that hosts file over the box's `/etc/hosts`. Returns the holder PID, or `None`
/// for a standalone box; pushes the pod's bind mounts onto `volumes`.
fn join_pod_and_bind_its_files(
    pod: Option<&str>,
    name: &str,
    volumes: &mut Vec<kern_isolation::Volume>,
    dns_requested: bool,
    inherit_nameservers: &mut Vec<String>,
    on_bridge: bool,
) -> Result<Option<i32>, Error> {
    let Some(pod) = pod else { return Ok(None) };
    // VALIDATED ON THE WAY IN, not only on the way out. `pod create` has always checked the name
    // against the shared resource-name rule (letters, digits, `_`, `-`, `.`, no traversal, no
    // leading `-`/`.`) because it becomes a DIRECTORY; the join path took the name straight from
    // argv and handed it to `pod_dir`, which is `pods_root().join(name)` with nothing in between.
    //
    // Nothing escapes in practice - the join then requires `<dir>/holder` to hold a live pid AND
    // `<dir>/netns` to match that process's namespace inode, a conjunction an arbitrary directory
    // does not satisfy - so this is closing an asymmetry rather than a hole. It is worth closing
    // anyway: a name that cannot NAME a pod should be refused as a name, not as a lookup that
    // happened to find nothing, and `--network <name>` gave that path a second entrance.
    crate::pod::validate_join_name(pod)?;
    // THE NAME REACHES HERE FROM TWO FLAGS, and the refusal has to serve both. `--pod <name>` is
    // kern's own spelling; `--network <name>` is the Docker habit (`run --rm --network <stack-net>`,
    // the one-off that talks to a running stack), and a stack started by `kern compose` IS a pod, so
    // the two are one operation. What the name can be is checked HERE rather than in the parser: the
    // answer depends on runtime state, and a parser that reads the registry is a parser whose result
    // depends on which boxes happen to be running.
    let holder = crate::pod::holder_pid(pod).ok_or_else(|| {
        // A `kern network` is a DIFFERENT object with the same shape of name, and it is the thing a
        // reader who typed `--network` is most likely to have meant. Say which one it found.
        if crate::network::exists(pod) {
            return Error::Sandbox(format!(
                "'{pod}' is a kern NETWORK, not a pod. A network is joined by a compose file \
                 declaring it `external: true`, not by a single box; for a one-off on a stack's \
                 network run it as a service of that file: \
                 `kern compose <file> run --rm <service> <cmd>`"
            ));
        }
        let live = crate::pod::live_names();
        let known = if live.is_empty() {
            "no pod is running".to_string()
        } else {
            format!("running: {}", live.join(", "))
        };
        Error::Sandbox(format!(
            "no running pod '{pod}' ({known}) - create it with `kern pod create {pod}`, or name a \
             stack's pod, which `kern pod ls` lists"
        ))
    })?;
    // A BRIDGE MEMBER GETS NEITHER THE ENTRY NOR THE FILE, and this is not an optimisation.
    //
    // The pod's shared hosts file maps every member to `127.0.0.1`, which is true of a SHARED
    // network namespace and false of a bridge: there each member has its own loopback and meets its
    // peers at their addresses. The file is bound over `/etc/hosts` BEFORE the driver's own
    // `--add-host` lines, and `/etc/hosts` is read top-down, so the pod's `127.0.0.1 <name>` shadows
    // the correct address whenever a `container_name:` makes the two names the same.
    //
    // MEASURED on a two-service file with `container_name: db` and `container_name: web`: inside
    // `web`, `/etc/hosts` carried `127.0.0.1 db` above `10.89.0.2 db`, and a connection to `db`
    // reached `web` itself - the same "a name answers as the wrong service" defect an outside
    // later pass found in the relay wiring, arriving by a different door.
    if on_bridge {
        return Ok(Some(holder));
    }
    crate::pod::add_member(pod, name)?;
    // Bind the pod's shared hosts over /etc/hosts. RW (not `:ro`): a read-only remount of a bind is
    // refused inside the pod's single-uid user ns (EPERM), and pod members are co-trusted anyway
    // (they already share the user+net ns).
    // Canonicalize the source: `setup_volumes` resolves every bind source with an `O_NOFOLLOW`
    // component walk, which fails if a component of the runtime dir is a symlink - so hand it the
    // symlink-free path the walk expects (the file exists; kern just created it for the pod).
    let symlink_free = |p: std::path::PathBuf| {
        std::fs::canonicalize(&p)
            .unwrap_or(p)
            .to_string_lossy()
            .into_owned()
    };
    volumes.push(kern_isolation::Volume {
        source: symlink_free(crate::pod::hosts_path(pod)),
        target: "/etc/hosts".to_string(),
        read_only: false,
    });
    // If the pod has outbound (a pasta NAT → a pod resolv.conf exists), bind it so DNS works.
    //
    // NOT WHEN THIS BOX ASKED FOR ITS OWN DNS. The bind is the pod's SHARED file, writable, and the
    // box writes `/etc/resolv.conf` from `--dns` later in its own setup - so with the bind in place
    // that write lands on the file every other member is reading. MEASURED before this branch
    // existed: a two-service stack where only service `a` declared `dns:` gave service `b`, which
    // declared none, `nameserver 1.1.1.1` and `nameserver 9.9.9.9`. One service's configuration
    // silently became the whole stack's, and the pod's own resolvers were destroyed for everyone.
    // Discriminated: no leak under `--no-pod` and none between standalone boxes, so the shared bind
    // was the whole mechanism.
    //
    // Skipping the bind leaves the write on the box's own root, which is private per box. What the
    // box must not lose is the pod's RESOLVERS when it only asked to add a `search` or an `options`
    // line: those are carried out through `inherit_nameservers` and re-emitted into the private
    // file, so "add a search domain" cannot silently mean "and drop DNS".
    let rp = crate::pod::resolv_path(pod);
    if rp.exists() {
        if dns_requested {
            inherit_nameservers.extend(pod_nameservers(&rp));
        } else {
            volumes.push(kern_isolation::Volume {
                source: symlink_free(rp),
                target: "/etc/resolv.conf".to_string(),
                read_only: false,
            });
        }
    }
    Ok(Some(holder))
}

/// The port the egress filter listens on inside the box's netns. One definition: the proxy is started
/// on it in the `on_started` callback, and the box's `*_PROXY` variables point at it.
const EGRESS_PROXY_PORT: u16 = 3128;

/// The `kern run` confinement commitment, carried across the scope re-exec beside the argv.
///
/// It holds a PREDICATE ("a `--landlock-rw` was requested"), never the paths themselves: the paths are
/// the argv's job. That asymmetry is the point. Two channels carrying the same fact would need a rule
/// for which one wins when they disagree; two channels carrying different halves of one fact have an
/// impossible state instead (predicate without content), which is precisely the signature of a lost
/// transport and can only be answered by refusing. See the check in [`run`].
///
/// Not folded into `KERN_SCOPE`: that one a user may set by hand to opt out of the scope path, and it
/// would then be asserting something about the argv that is not true.
const LANDLOCK_REQUIRED_ENV: &str = "KERN_LANDLOCK_REQUIRED";

/// `--egress-allow <domains>`: an outbound domain allowlist. The box keeps its default ISOLATED netns
/// (no route out, a real kernel boundary), and its ONLY egress is a kern-run filtering proxy started
/// once the box's netns exists. This points the box's proxy environment at it, after refusing the two
/// combinations where the flag would mean nothing.
///
/// See egress.rs and docs/EGRESS.md for the enforcement model and its honest limits.
/// What a box's egress filter is built from: the lists, and the `--egress-secret` keys already read.
/// ARMED AFRESH FOR EVERY ATTEMPT, because every attempt is a new network namespace: the foreground
/// box arms it once; a detached box's runner arms it before each attempt, `--restart` included.
pub(crate) struct EgressPlan {
    allow: Vec<String>,
    deny: Vec<String>,
    secrets: Vec<crate::egress::SecretRule>,
}

impl EgressPlan {
    /// `None` for a box with no egress filter. THE KEYS ARE READ HERE, from this kern's environment
    /// or their files, and nowhere else: a rule that cannot be resolved stops the start, because a
    /// box that was promised a key and runs without it fails later in a way that names nothing. For a
    /// detached box this runs in the launcher, so the refusal reaches the caller's terminal.
    fn from_args(args: &BoxRunArgs) -> Result<Option<Self>, Error> {
        if args.egress_allow.is_empty() {
            return Ok(None);
        }
        let mut secrets = Vec::with_capacity(args.egress_secrets.len());
        for raw in args.egress_secrets {
            let rule = crate::egress::SecretSpec::parse(raw)
                .and_then(|spec| spec.resolve(crate::global_env))
                .map_err(Error::Cli)?;
            secrets.push(rule);
        }
        Ok(Some(Self {
            allow: args.egress_allow.to_vec(),
            deny: args.egress_deny.to_vec(),
            secrets,
        }))
    }

    /// Start the proxy and the pump. Call it in the HOST pid namespace, BEFORE `run_in_sandbox_with`
    /// makes the box's (see the comment at the foreground site for the deadlock that placement
    /// avoids). Fail-closed: on any failure the box simply has no outbound, and says so.
    fn arm(&self) -> Option<crate::egress::EgressPending> {
        match crate::egress::spawn(&self.allow, &self.deny, &self.secrets, EGRESS_PROXY_PORT) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!(
                    "kern: warning: egress filter failed to start ({e}); the box has NO outbound"
                );
                None
            }
        }
    }
}

/// In a box's `on_started`: hand PID 1 to the armed filter. The filter's guard is kept in `guard`
/// for the attempt's life. `Some(why)` when the pump never came up: PID 1 is then SIGKILLed before
/// the workload's exec, because a box whose proxy is dead has no outbound at all, not even to the
/// hosts it was given, and would fail with a `Connection refused` that names neither cause nor flag.
fn deliver_egress(
    pending: &mut Option<crate::egress::EgressPending>,
    guard: &mut Option<crate::egress::EgressFilter>,
    pid1: i32,
) -> Option<String> {
    let p = pending.take()?;
    match p.deliver(pid1) {
        Ok(g) => {
            *guard = Some(g);
            None
        }
        Err(e) => {
            // SAFETY: kill with a pid this callback was handed for the box it just started.
            unsafe { libc::kill(pid1, libc::SIGKILL) };
            Some(e)
        }
    }
}

fn point_the_box_at_the_egress_proxy(
    args: &BoxRunArgs,
    env: &mut Vec<(String, String)>,
) -> Result<(), Error> {
    if args.egress_allow.is_empty() {
        return Ok(());
    }
    // A LIST THAT IS NOT ONE IS REFUSED HERE, before anything starts. The filter used to fail to
    // spawn later and the box ran with no outbound at all after a warning: a typo became a box that
    // was silently offline.
    crate::egress::EgressPolicy::parse(args.egress_allow, args.egress_deny)
        .map_err(Error::Sandbox)?;
    if args.share_net || args.pod.is_some() {
        return Err(Error::Sandbox(
            "--egress-allow filters the box's OWN isolated network, so it can't combine with --net \
             (host network) or --pod (shared pod network)"
                .to_string(),
        ));
    }
    let proxy = format!("http://127.0.0.1:{EGRESS_PROXY_PORT}");
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        env.push((k.to_string(), proxy.clone()));
    }
    Ok(())
}

/// The egress filter's one hole, said once: in the FINAL process, after the scope re-exec. Said
/// with the refusals in `point_the_box_at_the_egress_proxy`, a host whose boxes take the scope (an
/// SSH session outside the user manager, Ubuntu 24.04 measured) printed it twice.
fn say_what_the_egress_filter_cannot_close(args: &BoxRunArgs) {
    if args.egress_allow.is_empty() {
        return;
    }
    // FOR A PERSON AT A TERMINAL, as the rest of kern's narration: an SDK runs a box per call, and this
    // paragraph landed in the stderr of every cell and every transcript (MEASURED, kern-sandbox 0.3.0
    // with `egress_allow`). A script and an SDK read it in docs/EGRESS.md, which it names.
    if kern_common::progress_wanted() {
        eprintln!(
        "kern: note: --egress-allow gives the box outbound to the listed domains, addresses and ranges \
         only, minus --egress-deny (over an HTTP CONNECT/forward proxy; the box's isolated netns has no \
         other route). It resolves and pins the dialed host, refuses a resolved address the rules do \
         not open (non-public ones unless a range names them; loopback, link-local and cloud metadata \
         never), and tunnels only ports 80/443. The one \
         hole it can't close, and it is HTTPS-only: any allowed domain hosted on a SHARED CDN reaches \
         every other tenant of that CDN, because the site is chosen by the HTTP Host header INSIDE the \
         TLS session, which a non-intercepting proxy cannot read - a matching SNI does not change that. \
         Over plain HTTP that header is in plaintext and a head naming another host is refused. Allow \
         only origins you know are not shared; see docs/EGRESS.md. For a fully hostile workload prefer \
         a microVM with a real firewall."
    );
    }
}

/// Copy the image's content at each mount point into any NAMED volume that is still empty.
///
/// BEST EFFORT BY DESIGN, and every failure is silent on purpose: a volume that could not be seeded
/// behaves exactly as every kern volume behaved before this existed, so nothing that worked stops
/// working. Refusing to start a box because an optional copy failed would trade a subtle difference
/// for an outage.
///
/// THE MERGED VIEW IS THE ONLY CORRECT READER of a multi-layer image, for [`merged_view_extract`]'s
/// reason: a hand-rolled walk of the raw layer directories re-includes files a higher layer DELETED,
/// through per-file whiteouts and through opaque directories that carry no `.wh.` file at all. A
/// single-layer image cannot hold a cross-layer opaque and is copied directly, which is the same
/// split the push path makes.
fn seed_empty_named_volumes(lower: &[String], volumes: &[Volume]) {
    // NOTHING TO SEED: the common case, and it must cost nothing. Checked before the fork, because a
    // fork per box start would be a real cost on the hot path for a job that is almost always empty.
    let seedable: Vec<&Volume> = volumes.iter().filter(|v| is_seedable(v)).collect();
    if seedable.is_empty() {
        return;
    }
    // INSIDE THE MAPPED NAMESPACE, so the copy can carry the image's OWNERSHIP onto the volume and
    // the volume's own root can be given the image directory's owner and mode.
    //
    // Docker does both. A named volume mounted where the image put a directory owned by a non-root
    // user must arrive owned by that user, or the service cannot write it: MEASURED on
    // `prom/prometheus`, whose `/prometheus` is `nobody:nobody` and whose volume came back owned by
    // in-box root, so it died with `mkdir data/: permission denied` even after the image's own
    // ownership was fixed. The contents are only half of what a volume inherits.
    let owned: Vec<(String, String)> = seedable
        .iter()
        .map(|v| (v.source.clone(), v.target.clone()))
        .collect();
    let seed = move |_ranged: bool| {
        seed_now(lower, &owned);
        0
    };
    if kern_isolation::with_id_mapped_userns(seed).is_err() {
        // No namespace to map: the volume stays empty, which is where it started and what every kern
        // volume did before this existed.
    }
}

/// May this mount be seeded from the image? Three conditions, each excluding a different mistake.
///
/// NAMED: a bind mount of a host path is the caller's own directory, and writing image content into
/// it would be kern filling a directory nobody asked it to touch. EMPTY: Docker's rule, and the only
/// thing standing between this and overwriting live data. A TARGET THAT IS NOT THE ROOT: a volume
/// over `/` has no meaningful "the image's content at the mount point" to copy.
fn is_seedable(v: &Volume) -> bool {
    is_seedable_under(&crate::volume::volumes_dir(), v)
}

/// [`is_seedable`] against an explicit volumes root.
///
/// Split for the reason given on [`crate::volume::name_of_data_dir_under`]: the three conditions are
/// a rule about a path and a directory, and exercising them must not require writing into the one
/// directory every kern on this machine shares.
fn is_seedable_under(root: &std::path::Path, v: &Volume) -> bool {
    let src = std::path::Path::new(&v.source);
    crate::volume::name_of_data_dir_under(root, src).is_some()
        && crate::volume::data_dir_is_empty(src)
        && !v.target.trim_matches('/').is_empty()
}

/// The seeding itself, running as root of the mapped namespace (see [`seed_empty_named_volumes`]).
fn seed_now(lower: &[String], volumes: &[(String, String)]) {
    // The layers as they were resolved, TOP first. This used to be the joined string cut at every
    // `:`, so under a cache path with one the merged view was handed layers that did not exist and
    // the `let _` below swallowed the failure. It was never SEEN on its own, because the box's own
    // mount failed on the same `:` right after (measured); it would have been an empty volume the
    // day that mount worked, which is today.
    let Some(top) = lower.first() else {
        return; // no layer, nothing to seed from
    };
    for (source, target) in volumes {
        let src = std::path::Path::new(source);
        let rel = target.trim_start_matches('/');
        if lower.len() >= 2 {
            let _ = crate::commands::merged_view_extract(
                lower,
                crate::commands::Extract::Contents(rel),
                src,
            );
        } else {
            let from = std::path::Path::new(top).join(rel);
            if from.is_dir() {
                let _ = std::process::Command::new("cp")
                    .arg("-a")
                    .arg("--reflink=auto")
                    .arg("--")
                    .arg(format!("{}/.", from.display()))
                    .arg(src)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
        }
        // THE VOLUME'S OWN ROOT, which no content copy can set: `cp -a` fills the directory and
        // leaves the directory itself alone. An image whose mount point is an EMPTY directory owned
        // by a non-root user copies nothing at all, and that is exactly the Prometheus case.
        //
        // ONE LAYER ONLY: there the top layer IS the image. With two or more the merged view above
        // has already given the root its owner, from whichever layer the image shows; the top layer
        // alone often does not hold the directory at all (speaches, measured).
        if lower.len() >= 2 {
            continue;
        }
        let from = std::path::Path::new(top).join(rel);
        if let Ok(m) = std::fs::metadata(&from) {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::fs::PermissionsExt;
            if let Ok(c) = std::ffi::CString::new(source.as_bytes()) {
                // SAFETY: `c` is a live NUL-terminated path for the duration of the call.
                unsafe { libc::chown(c.as_ptr(), m.uid(), m.gid()) };
            }
            // AFTER the chown, which clears setgid.
            let _ = std::fs::set_permissions(
                src,
                std::fs::Permissions::from_mode(m.permissions().mode()),
            );
        }
    }
}

/// The signal that stops this box: the flag, else the image's `STOPSIGNAL`, else `SIGTERM`.
///
/// AN EXPLICIT FLAG WINS EVEN WHEN IT NAMES `SIGTERM`, which is why the flag arrives as an `Option`:
/// with kern's default folded in as a value, honouring the image would have meant overriding
/// somebody's deliberate choice, and keeping the flag would have meant never honouring the image.
///
/// A NAME THE IMAGE WROTE THAT KERN'S TABLE LACKS FALLS BACK rather than refusing. nextcloud ships
/// `SIGWINCH` (MEASURED), which kern has no mapping for; refusing there would stop a box from
/// running over a field it used to ignore entirely.
///
/// A FUNCTION so the precedence can be asserted. Written inline as an `.or_else` chain it was only
/// ever checked end to end, which needs a box, an image with a `STOPSIGNAL`, and a workload that
/// reports which signal it caught.
/// The lowest port an unprivileged process may bind on this host.
///
/// NOT A DECISION, ONLY A SENTENCE. The refusal that calls this comes from a bind that actually
/// failed with `EACCES`, so kern never assumes where the boundary is: a host that lowers this sysctl
/// publishes port 80 rootless and kern says nothing at all. The number is read so the message can
/// name the rule the kernel is applying instead of the `1024` it used to quote, which is a default
/// and not a law, and so the reader is pointed at the knob that would let the port through.
///
/// TAKES THE PATH so the parse can be asserted. A sentence built from an unreadable `/proc` file is
/// exactly the kind of thing that silently becomes `0` or panics, and neither would be visible from
/// the call site.
pub(crate) fn unprivileged_port_start_at(path: &str) -> u16 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        // The kernel's own default, and the answer for any host that does not expose the knob.
        .unwrap_or(1024)
}

fn unprivileged_port_start() -> u16 {
    unprivileged_port_start_at("/proc/sys/net/ipv4/ip_unprivileged_port_start")
}

pub(crate) fn resolve_stop_signal(flag: Option<i32>, image: Option<&str>) -> i32 {
    flag.or_else(|| image.and_then(crate::cli::parse_signal_name))
        .unwrap_or(libc::SIGTERM)
}

/// The check the CALLER named, in the form they named it in: `--health-cmd-argv` (repeatable) is
/// Docker's `CMD` exec form - argv exec'd directly, no shell - and `--health-cmd` is its
/// `CMD-SHELL`. The CLI parser refuses both at once, so the order here settles nothing a caller can
/// reach; it is written argv-first anyway, because a form that needs no shell is the safe reading
/// of an ambiguous pair.
pub(crate) fn flag_health_probe(
    cmd: Option<&str>,
    argv: &[String],
) -> Option<kern_oci::HealthTest> {
    if !argv.is_empty() {
        return Some(kern_oci::HealthTest::Exec(argv.to_vec()));
    }
    cmd.map(|c| kern_oci::HealthTest::Shell(c.to_string()))
}

/// What `kern box --device <host path>` says, which is docker's commonest device spelling.
///
/// ⛔ IT USED TO ASSUME A GPU. `--device /dev/dri/renderD128` answered "not a CDI name. Use
/// --device nvidia.com/gpu=0", and beside `--gpus` a path answered that the two flags "name the
/// same thing two ways". On `kern box`, `--device` names ONE card the way CDI does; a host node is a
/// bind, and the bind was RUN before being printed here: `-v /dev/dri/renderD128:...` and
/// `-v /dev/nvidia0:...` both opened O_RDWR inside a box on this host.
///
/// THE CONDITION IS SAID BECAUSE IT DECIDES THE ANSWER. renderD128 is `crw-rw---- root:render`
/// with a `+`: the session ACL logind gives the logged-in user is what let the box open it. A box
/// keeps no supplementary groups, so on a host where the node is reachable only through a group
/// (a server with no seat, typically) the bind lands and `open` is refused.
pub(crate) fn device_path_message(path: &str) -> String {
    format!(
        "--device {path}: on `kern box` --device names one GPU the way CDI does \
         (nvidia.com/gpu=0, or --gpus); a host node is bound like a path: -v {path}:{path}. \
         Whether the box can open it is the node's permission for YOUR uid: a box keeps no \
         supplementary groups, so a node readable only through a group such as `render` or \
         `video` lands in the box and refuses to open (a desktop session's ACL usually covers \
         it, a headless server's group does not). A missing node is refused, not created"
    )
}

/// The driver tool a health probe would try to run, if it names one.
///
/// ⛔ A HEALTHCHECK BUILT ON `nvidia-smi` CAN NEVER PASS IN A BOX, and until this existed it failed
/// in silence for the life of the box. MEASURED 2026-11-12 on this host: a compose service with
/// `gpus: all` and `healthcheck: test: ["CMD", "nvidia-smi"]` started, took its two cards
/// (`kern inspect` listed `nvidia0 nvidia1`), and sat at `unhealthy` with nothing anywhere saying
/// why; the same file is healthy under docker, whose NVIDIA runtime injects the binary. The cost is
/// not cosmetic: a `depends_on: {condition: service_healthy}` gate pointed at that service never
/// opens, so a stack hangs on a service whose GPU grant was perfectly correct.
///
/// This reads the EFFECTIVE probe, so one call covers all three origins: `kern box --health-cmd`,
/// a compose `healthcheck:` (which reaches this binary as that flag), and an image's own
/// `HEALTHCHECK` when the caller named none.
///
/// EVERY TOKEN IS SCANNED, not just the program: the shell form in the field is
/// `["CMD-SHELL", "nvidia-smi || exit 1"]` and a wrapped one is `sh -c nvidia-smi`, and both run the
/// tool. STATED LIMIT: the shell string is split on whitespace, so `nvidia-smi;true` is not seen.
/// The error leans to the FALSE NEGATIVE, which for a warning is the right direction.
pub(crate) fn health_probe_driver_tool(probe: Option<&kern_oci::HealthTest>) -> Option<String> {
    let tokens: Vec<&str> = match probe? {
        kern_oci::HealthTest::Exec(argv) => argv.iter().map(String::as_str).collect(),
        kern_oci::HealthTest::Shell(cmd) => cmd.split_whitespace().collect(),
    };
    tokens
        .into_iter()
        .find(|t| kern_isolation::is_driver_tool(t))
        .map(str::to_string)
}

/// A UUID that cannot be checked on a WSL2 guest becomes every adapter, said out loud; any other
/// error passes through untouched.
///
/// MEASURED on the Alpine WSL2 guest: `--gpus device=<the card's own UUID>` was refused with "this
/// host's driver publishes no GPU UUID at all", while the card was there and `/dev/dxg` granted it.
/// The UUID cannot be verified there (see [`crate::gpu::wsl_uuids_unreadable`]), and what the box
/// receives is every adapter whatever was named, so refusing it was refusing a grant that works.
fn wsl_unchecked_uuid(
    spec: &str,
    e: crate::gpu_grant::GpuSpecError,
    say: impl FnOnce(&str),
) -> Result<Option<crate::gpu_grant::GpuSelection>, crate::gpu_grant::GpuSpecError> {
    match e {
        crate::gpu_grant::GpuSpecError::UnknownUuid { ref known, .. }
            if known.is_empty() && crate::gpu::wsl_uuids_unreadable(std::path::Path::new("/")) =>
        {
            say(&crate::gpu::describe_wsl_unchecked_uuid(spec));
            Ok(Some(crate::gpu_grant::GpuSelection::All))
        }
        other => Err(other),
    }
}

/// The cards `--runtime nvidia` grants for a `NVIDIA_VISIBLE_DEVICES` value, read as NVIDIA's runtime
/// reads it: unset, empty, `void` and `none` are no GPU; `all` is every card; otherwise a list of
/// indices or GPU UUIDs. `Ok(None)` is "no GPU", which the caller says out loud.
pub(crate) fn runtime_nvidia_selection(
    value: Option<&str>,
) -> Result<Option<crate::gpu_grant::GpuSelection>, Error> {
    let v = value.map(str::trim).unwrap_or("");
    if v.is_empty() || v.eq_ignore_ascii_case("void") || v.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    if v.eq_ignore_ascii_case("all") {
        return Ok(Some(crate::gpu_grant::GpuSelection::All));
    }
    crate::gpu_grant::selection_from_spec(std::path::Path::new("/"), &format!("device={v}"))
        .map_err(|e| {
            Error::Cli(format!(
                "--runtime nvidia: NVIDIA_VISIBLE_DEVICES={v} names no card kern can read ({e:?}). \
                 It takes all, none, void, or card indices or GPU UUIDs separated by commas"
            ))
        })
}

/// What a GPU grant decided, for the launch to apply once the image is known.
struct GpuGrantOutcome {
    /// Which cards the box's `/proc/driver/nvidia` keeps.
    enumeration: kern_isolation::GpuEnumeration,
    /// The native grant and the selection, whose binds are placed after the image is resolved.
    for_identity: Option<(crate::gpu_grant::GpuGrant, crate::gpu_grant::GpuSelection)>,
    /// `NVIDIA_VISIBLE_DEVICES` as docker sets it for a `--gpus` spec; `None` leaves the variable alone.
    visible: Option<String>,
    /// The driver tools bound at `/usr/bin`, by name.
    tools: Option<Vec<String>>,
    /// The WSL2 grant, whose binds are placed after the image is resolved.
    wsl: Option<crate::gpu::WslGrant>,
    /// Nodes reached only through the caller's supplementary groups, as `(gids, nodes)`. Whether
    /// that refuses depends on the box's uid map, decided after the image: see `kern box`.
    groups_needed: Option<(Vec<u32>, Vec<std::path::PathBuf>)>,
}

/// Decide a GPU grant for `selected`: native or WSL2, refused here when the host cannot honour it.
///
/// ONE FUNCTION, TWO CALLERS: `--gpus`/`--device` decide before the image is pulled, so a request this
/// host cannot meet is refused in no time; `--runtime nvidia` decides after, because what it grants is
/// named by the image's own `NVIDIA_VISIBLE_DEVICES`. A copy of this logic for the second caller is
/// the shape this repository's recurring defect takes. `spec` is the `--gpus` text, for the
/// `NVIDIA_VISIBLE_DEVICES` docker writes; `None` leaves the box's own value in place.
fn decide_gpu_grant(
    selected: crate::gpu_grant::GpuSelection,
    spec: Option<&str>,
) -> Result<GpuGrantOutcome, Error> {
    let mut out = GpuGrantOutcome {
        enumeration: kern_isolation::GpuEnumeration::NoneGranted,
        for_identity: None,
        visible: None,
        tools: None,
        wsl: None,
        groups_needed: None,
    };
    let caller = crate::gpu_grant::Caller::current();
    let resolved = crate::gpu_grant::resolve();
    // THE WSL2 SHAPE IS TAKEN ONLY WHERE THE NATIVE GRANT HAS NOTHING: no NVIDIA driver in this
    // kernel, and `/dev/dxg` with the vendor libraries beside it. Every other host and every other
    // failure goes down the native path exactly as before.
    let wsl = match &resolved {
        Err(crate::gpu_grant::ResolveError::NoDriverVersionFile { .. }) => {
            crate::gpu::wsl_grant(std::path::Path::new("/"))
        }
        _ => None,
    };
    if let Some(wsl) = wsl {
        let w = wsl.map_err(|e| Error::Cli(crate::gpu::describe_wsl_grant_error(&e)))?;
        out.tools = Some(tools_bound_at_usr_bin(&w.binds));
        out.wsl = Some(w);
        // A SELECTION NARROWER THAN `all` IS CHECKED AGAINST THE ADAPTERS, as docker checks it:
        // a card the VM does not have is refused, and one it has is accepted. Only then is it
        // said that `/dev/dxg` carries every adapter, and only when there is more than the one
        // asked for. `all` asks nothing, so it costs no enumeration.
        let mut granted: Option<Vec<u32>> = None;
        if !matches!(selected, crate::gpu_grant::GpuSelection::All) {
            match crate::gpu::wsl_adapter_indices(std::path::Path::new("/")) {
                Some(adapters) => {
                    let narrower = crate::gpu::wsl_check_selection(&selected, &adapters)
                        .map_err(|e| Error::Cli(crate::gpu_grant::describe_mount_plan_error(&e)))?;
                    if narrower {
                        // ⛔ SAID, NOT HIDDEN: the box asked for fewer adapters than it holds.
                        eprintln!(
                            "kern: note: --gpus on WSL2: the GPU reaches this box through \
                             /dev/dxg, which carries every adapter the WSL2 VM has ({}), so \
                             this box sees all of them. WSL2 has no per-card node to narrow it \
                             to the ones asked for",
                            adapters.len()
                        );
                    }
                    if let crate::gpu_grant::GpuSelection::Count(n) = &selected {
                        granted = Some(adapters.iter().take(*n as usize).copied().collect());
                    }
                }
                None => eprintln!(
                    "kern: note: --gpus on WSL2: the adapters could not be counted here \
                     (neither the vendor's nvidia-smi nor /dev/dxg answered), so the selection \
                     was not checked. The GPU reaches this box through /dev/dxg, which carries \
                     every adapter the WSL2 VM has"
                ),
            }
        }
        out.visible =
            spec.map(|spec| crate::gpu_grant::visible_devices(spec, &selected, granted.as_deref()));
    } else {
        let grant = resolved.map_err(|e| match e {
            crate::gpu_grant::ResolveError::NoDriverVersionFile { .. } => {
                Error::Cli(crate::gpu::with_foreign_shape(
                    "--gpus was passed and no NVIDIA driver is loaded in this kernel: \
                 /proc/driver/nvidia/version does not exist",
                    std::path::Path::new("/"),
                ))
            }
            crate::gpu_grant::ResolveError::DriverVersionUnparsable { first_line } => {
                Error::Cli(format!(
                    "--gpus was passed and the driver's version line carries no version: \
                 {first_line:?}"
                ))
            }
            crate::gpu_grant::ResolveError::NoNodes { driver_version } => Error::Cli(format!(
                "--gpus was passed, driver {driver_version} is loaded, and no device node exists \
             under /dev"
            )),
        })?;

        // ONE SPELLING of every refusal, shared with `kern box --plan`. These four messages lived
        // here and the preview had none, so a plan printed the `Debug` form of the same error and a
        // reader could not compare the two.
        //
        // ⛔ A NODE REACHED THROUGH A GROUP IS DECIDED ONCE THE BOX'S UID MAP IS KNOWN, NOT HERE. The
        // single-uid map keeps the caller's groups and the ranged one drops them, and the map
        // depends on the image and on whether this host has a uid range at all. MEASURED on a
        // Jetson Orin Nano (no `newuidmap`, so every box is single-uid; nodes `root:video 0660`): the
        // grant was refused over the `video` group, and refused again with the `--no-uid-range` its
        // own message recommended.
        let binds = match crate::gpu_grant::mount_plan(&grant, &selected, &caller) {
            Ok(binds) => binds,
            Err(crate::gpu_grant::MountPlanError::GroupsNeeded { gids, nodes }) => {
                out.groups_needed = Some((gids, nodes));
                crate::gpu_grant::mount_plan_keeping_groups(&grant, &selected, &caller, None)
                    .map_err(|e| Error::Cli(crate::gpu_grant::describe_mount_plan_error(&e)))?
            }
            Err(e) => return Err(Error::Cli(crate::gpu_grant::describe_mount_plan_error(&e))),
        };
        out.tools = Some(tools_bound_at_usr_bin(&binds));

        out.enumeration = match crate::gpu_grant::pci_addresses_of(&grant, &selected) {
            Some(addresses) => kern_isolation::GpuEnumeration::Only(addresses),
            // A card the driver gave no PCI address for. Masking on a guess would hide a card this
            // box was just given, so the directory stays whole and the state says which case it is.
            None => kern_isolation::GpuEnumeration::Unnameable,
        };
        out.visible = spec.map(|spec| {
            crate::gpu_grant::visible_devices(
                spec,
                &selected,
                crate::gpu_grant::granted_indices(&grant, &selected).as_deref(),
            )
        });
        // MOVED, not cloned: it carries 29 libraries and 29 symlinks, and what reads it below
        // (the binds once the image is known, the identity probe) borrows it.
        out.for_identity = Some((grant, selected));
    }
    Ok(out)
}

/// docker's rule for the box's library directory, as `--plan` states it.
const LIB_DIR_RULE: &str = "/usr/lib/x86_64-linux-gnu for a Debian-family image \
     (/etc/debian_version), /usr/lib64 for any other, as docker places them";

/// The driver tools among `binds`, by name: the ones a grant put at `/usr/bin`.
fn tools_bound_at_usr_bin(binds: &[(String, String, bool)]) -> Vec<String> {
    let dir = format!("{}/", crate::gpu_grant::DRIVER_TOOLS_IN_BOX);
    binds
        .iter()
        .filter_map(|(_, target, _)| target.strip_prefix(&dir))
        .filter(|name| kern_isolation::is_driver_tool(name))
        .map(str::to_string)
        .collect()
}

/// Why a healthcheck running the driver tool `tool` cannot pass in this box, or `None` when the grant
/// put the tool where the probe looks.
///
/// SINCE A GRANT BINDS THE TOOLS AT `/usr/bin`, as docker's NVIDIA runtime does, the probe NVIDIA's
/// guides print (`test: ["CMD", "nvidia-smi"]`) passes in a granted glibc box, and warning about it
/// would be noise on every GPU stack. What is left to say is the three cases where it still cannot:
/// no grant at all, a host whose driver has no such tool, and a path other than the one the grant
/// binds. `granted` is `None` for "no GPU grant".
pub(crate) fn health_tool_absence(tool: &str, granted: Option<&[String]>) -> Option<String> {
    let bare = tool.rsplit('/').next().unwrap_or(tool);
    let at = format!("{}/{bare}", crate::gpu_grant::DRIVER_TOOLS_IN_BOX);
    let Some(granted) = granted else {
        return Some(format!(
            "and this box holds no GPU grant, so no driver tool is bound into it. Grant a card when \
             the box starts (--gpus, or `gpus:` in compose with --allow-device-grants), which binds \
             {at} with it"
        ));
    };
    if !granted.iter().any(|t| t == bare) {
        return Some(format!(
            "and this host's driver has no `{bare}` for the grant to bind (it looks where docker's \
             NVIDIA runtime looks, /usr/local/sbin to /bin). Probe what the grant does bind, e.g. \
             `test -c /dev/nvidiactl`, or `test -c /dev/dxg` on WSL2"
        ));
    }
    if tool.contains('/') && tool != at {
        return Some(format!(
            "and the grant binds `{bare}` at {at}, not at {tool}. Probe it by that path, or by the \
             bare name"
        ));
    }
    None
}

/// What an image's own `HEALTHCHECK` contributes, once the caller's flags have had their say.
///
/// EVERY FIELD `None` MEANS "THE IMAGE SAYS NOTHING HERE", so each falls back independently at the
/// call site to the flag's value (which already carries kern's default).
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct ImageHealthDefaults {
    /// The image's check WITH ITS FORM (`CMD` exec / `CMD-SHELL`), never flattened to a string: an
    /// image that ships `CMD ["prog"]` typically has no shell to run a flattened one with.
    pub(crate) probe: Option<kern_oci::HealthTest>,
    pub(crate) interval: Option<u64>,
    pub(crate) retries: Option<u32>,
    pub(crate) start_period: Option<u64>,
    /// How often to probe DURING the start period (Docker 25+'s `StartInterval`). `None` means the
    /// image said nothing, and the steady-state interval governs from the first probe as before.
    pub(crate) start_interval: Option<u64>,
    pub(crate) timeout: Option<u64>,
}

/// ALL OR NOTHING, which is what Docker does and what the flags allow us to know.
///
/// A caller who passes `--health-cmd` owns the whole check: their command with their (or kern's
/// default) numbers, and the image's is ignored - Compose's `healthcheck.test` REPLACES the image's
/// rather than merging with it. A caller who passes none gets the image's check entire.
///
/// FIELD-BY-FIELD FALLBACK IS NOT EXPRESSIBLE and pretending otherwise would be a guess: the numeric
/// flags carry kern's defaults already baked in (`--health-interval` is 30 whether or not anyone
/// typed it), so "did the caller choose this?" has no answer here. An all-or-nothing rule needs only
/// a question that can be answered.
///
/// A FUNCTION so the rule can be asserted: taken inline at the struct literal, a mutation swapping
/// which side wins leaves every test green.
pub(crate) fn image_health_defaults(
    img: Option<&kern_oci::ImageHealthcheck>,
    flag_probe: Option<&kern_oci::HealthTest>,
) -> ImageHealthDefaults {
    // The caller named a command: the image contributes nothing at all, numbers included.
    let Some(h) = img.filter(|_| flag_probe.is_none()) else {
        return ImageHealthDefaults::default();
    };
    // `HEALTHCHECK NONE` disables a check a base image set, so it contributes nothing either - and
    // must not leave its INTERVALS behind to be applied to a check that does not exist.
    let Some(probe) = h.probe() else {
        return ImageHealthDefaults::default();
    };
    ImageHealthDefaults {
        probe: Some(probe),
        interval: secs_from_nanos(h.interval_ns),
        retries: h.retries,
        start_period: secs_from_nanos(h.start_period_ns),
        start_interval: secs_from_nanos(h.start_interval_ns),
        timeout: secs_from_nanos(h.timeout_ns),
    }
}

/// An OCI config duration (NANOSECONDS, Go's `time.Duration`) as whole SECONDS, which is the unit
/// every kern health flag speaks.
///
/// A ZERO IS "UNSET", not "every zero seconds": the OCI spec writes 0 for a field the image left
/// out, and a zero interval would spin the checker in a loop. A sub-second value rounds UP to one
/// second rather than down to zero, for the same reason - the coarser unit must never turn a real
/// interval into no interval at all.
fn secs_from_nanos(ns: Option<u64>) -> Option<u64> {
    match ns? {
        0 => None,
        n => Some(n.div_ceil(1_000_000_000)),
    }
}

/// Attach the named volumes that carry a recorded quota, each on its own ext4 loop image so the limit
/// is a REAL filesystem quota rather than an advisory number.
///
/// `ext4_ok` is the host's verdict on whether that backend can be built here; where it cannot, each
/// volume degrades through `quota_fallback` to the plain directory, which is honest about losing the
/// enforcement rather than pretending to have it.
///
/// The seeding copy is NOT best-effort, and that is the part to read carefully: on the first upgrade
/// of an existing volume to the enforced backend, the plain `data/` dir is copied into the fresh
/// image. The two backends are DISTINCT on-disk locations, so a discarded failure would mount an
/// EMPTY volume over data that still exists elsewhere - the workload sees nothing, may recreate or
/// overwrite it, and nothing said the copy did not happen. Refusing costs a failed box start; not
/// refusing costs the dataset.
fn attach_quota_volumes(
    quota_specs: &[String],
    ext4_ok: bool,
    vdisk_work: &std::path::Path,
    ext4_handles: &mut Vec<crate::vdisk::Ext4Vdisk>,
    volumes: &mut Vec<Volume>,
) -> Result<(), Error> {
    for spec in quota_specs {
        let (name_v, dest, ro) = crate::volume::parse_named_spec(spec)?;
        let limit = crate::volume::size_limit(name_v).unwrap_or(0);
        let backend = crate::volume::volumes_dir()
            .join(name_v)
            .to_string_lossy()
            .into_owned();
        let img_existed = std::path::Path::new(&backend)
            .join(format!("kern-vdisk-{name_v}.img"))
            .exists();
        let source = if ext4_ok {
            match crate::vdisk::prepare(name_v, limit, true, Some(&backend), vdisk_work) {
                Some(h) => {
                    let m = h.mount.to_string_lossy().into_owned();
                    // First time this volume is upgraded to the enforced ext4 backend: seed the fresh
                    // image from the plain `data/` dir, so switching rootless→privileged doesn't hide
                    // the files already written to the volume (the enforced and unenforced backends are
                    // otherwise distinct on-disk locations).
                    if !img_existed {
                        let data = crate::volume::volumes_dir().join(name_v).join("data");
                        let has_data = data
                            .read_dir()
                            .map(|mut d| d.next().is_some())
                            .unwrap_or(false);
                        if has_data {
                            // NOT best-effort. This is the one-time seeding of a freshly created ext4
                            // image from the volume's plain `data/` dir when a quota'd volume is first
                            // upgraded to the enforced backend. The two backends are DISTINCT on-disk
                            // locations, so a discarded failure mounts an EMPTY volume over data that
                            // still exists elsewhere: the workload sees no data, may recreate or
                            // overwrite it, and nothing said the copy did not happen. Refusing costs a
                            // failed box start; not refusing costs the dataset.
                            let st = std::process::Command::new("cp")
                                .arg("-a")
                                .arg(format!("{}/.", data.display()))
                                .arg(&m)
                                .status()
                                .map_err(|e| {
                                    Error::Volume(format!(
                                        "seeding volume '{name_v}' into its quota'd backend: {e}"
                                    ))
                                })?;
                            if !st.success() {
                                return Err(Error::Volume(format!(
                                    "seeding volume '{name_v}' into its quota'd backend failed ({st}); the existing data is still in {} and the box was not started",
                                    data.display()
                                )));
                            }
                        }
                    }
                    ext4_handles.push(h);
                    m
                }
                None => quota_fallback(name_v)?,
            }
        } else {
            quota_fallback(name_v)?
        };
        volumes.push(Volume {
            source,
            target: dest,
            read_only: ro,
        });
    }
    Ok(())
}

/// Who keeps the box alive, decided once from the flags and the host.
struct Supervision {
    /// The parsed `--health-action`, validated before any host-side mount so a typo fails fast.
    health_action: HealthAction,
    /// In-process supervisor that dies with the host: `on-failure`, or a `restart` health action.
    restart: bool,
    /// A standalone persistent box on a host that HAS a `systemd --user` manager: it gets a unit and
    /// survives a reboot.
    systemd_supervises: bool,
    /// The in-process supervisor restarts on ANY exit (a pod member, or a persistent box on a host
    /// with no systemd manager).
    restart_always: bool,
    /// This process IS the foreground run systemd drives as the supervisor (`KERN_MANAGED=1`).
    managed: bool,
    /// A detached, persistent, non-pod box: the only shape that can take the systemd unit path.
    standalone_persistent: bool,
}

/// A detached box with a persistent restart policy and no pod: the one shape that may hand itself to
/// a systemd unit instead of running here. Read by `decide_supervision` and by the early id map,
/// which must not start work for a box this process may never run.
fn standalone_persistent(args: &BoxRunArgs) -> bool {
    args.detached && args.restart.persistent() && args.pod.is_none()
}

/// Decide the supervision arrangement, and refuse the one combination that would silently do nothing.
///
/// A POD MEMBER with `always`/`unless-stopped` is supervised IN-PROCESS for the stack's lifetime
/// (restart on ANY exit, including 0), NOT via a per-service systemd unit: a pod member needs the pod
/// holder's shared namespace, so a standalone unit that outlives the holder could not re-join it.
///
/// A STANDALONE persistent box normally takes the systemd path (survives reboot) - but ONLY where a
/// `systemd --user` manager actually exists. Where none does (WSL2 without systemd, a minimal
/// container, no user manager) it FALLS BACK to the same in-process supervisor: restart on any exit
/// for this process's lifetime, no reboot-survival. Without that fallback a systemd-less host could
/// not run `--restart always` AT ALL - the unit install just errored and the box never started.
///
/// The systemd probe runs ONLY for a standalone persistent box, so an ordinary box start pays no
/// socket connect for it.
fn decide_supervision(args: &BoxRunArgs) -> Result<Supervision, Error> {
    let health_action = parse_health_action(args.health_action)?;
    let restart =
        args.restart == RestartPolicy::OnFailure || health_action == HealthAction::Restart;
    let standalone_persistent = standalone_persistent(args);
    let systemd_present = standalone_persistent && kern_isolation::user_systemd_present();
    let (systemd_supervises, restart_always) = persistent_supervision(
        args.detached,
        args.restart.persistent(),
        args.pod.is_some(),
        systemd_present,
    );
    // When systemd (re-)starts a persistent box it runs THIS binary in the foreground with
    // `KERN_MANAGED=1`: that run skips the transient-scope re-exec (the box already lives in the
    // unit's own service cgroup) and registers itself so `kern ps`/`logs`/`stop` still see it.
    let managed = kern_common::env_flag("KERN_MANAGED");
    // `--restart always`/`unless-stopped` needs a SUPERVISOR, and the only two are systemd (detached
    // standalone) and the in-process loop (detached, incl. a pod member) - the FOREGROUND path runs
    // the box exactly once. Reject it here rather than start the box and silently drop the policy.
    // `managed` is exempt: that IS the foreground re-exec systemd itself drives as the supervisor, so
    // `persistent() && !detached` is expected and correct there.
    if args.restart.persistent() && !args.detached && !managed {
        return Err(Error::Usage(
            "--restart always/unless-stopped needs -d: a foreground box runs once, so nothing would \
             supervise the restarts (use -d and systemd or kern's supervisor takes over)",
        ));
    }
    Ok(Supervision {
        health_action,
        restart,
        systemd_supervises,
        restart_always,
        managed,
        standalone_persistent,
    })
}

/// Who the box runs as: `--user` / compose `user:` when the caller gave one, otherwise the image's
/// own `USER`. `Ok(None)` means neither asked, so the workload stays box root.
///
/// A spec that `resolve` cannot answer is an ERROR in BOTH cases. The image's own `USER` used to
/// fall back to box root with a note on stderr, so that "an odd image still starts". That is the
/// wrong shape of failure, for three reasons:
///
///  * **It fails open.** An image whose whole intent is to drop privilege ends up running as the
///    box's root instead, which is the opposite of what it asked for. `real.rs` already refuses to
///    exec rather than silently run a workload as in-box root when a drop cannot be honoured; this
///    path was the one place that decided the other way.
///  * **The note went to stderr**, ahead of the workload's own output, which is where a note is read
///    last or not at all. A field test on the `dev` branch reported the behaviour as "ran as 0:0,
///    not an error" and never mentioned the warning that was printed. That is the failure mode,
///    demonstrated rather than argued.
///  * **Docker refuses it** (`unable to find user X: no matching entries in passwd file`), and kern
///    reads its user spec by Docker's rules everywhere else on this path. Deviating only in the
///    failure case makes the compatible behaviour unpredictable.
///
/// The escape hatch is not removed, it is made explicit: `--user 0` runs as box root on purpose.
///
/// `resolve` is injected rather than called directly so the decision can be asserted without an
/// image on disk: the resolution rules themselves are `resolve_user`'s, and are tested there.
pub(crate) fn resolve_run_as(
    flag: Option<&str>,
    image_user: Option<&str>,
    resolve: &dyn Fn(&str) -> Option<(u32, u32)>,
) -> Result<Option<(u32, u32)>, Error> {
    // An empty `USER` in the image config means the image said nothing, not that it asked for "".
    let (spec, from_flag) = match flag {
        Some(u) => (Some(u), true),
        None => (image_user.filter(|u| !u.is_empty()), false),
    };
    let Some(u) = spec else {
        return Ok(None);
    };
    match resolve(u) {
        Some(pair) => Ok(Some(pair)),
        None if from_flag => Err(Error::Sandbox(format!(
            "--user '{u}': not a numeric UID[:GID] and no such account in the image's /etc/passwd"
        ))),
        None => Err(Error::Sandbox(format!(
            "the image requests user '{u}', which is not a numeric UID[:GID] and has no account in \
             the image's /etc/passwd (docker refuses this too). Pass `--user <uid[:gid]>` to choose \
             one, or `--user 0` to run as box root on purpose"
        ))),
    }
}

pub fn box_run(args: BoxRunArgs) -> Result<(), Error> {
    // The PARENT was not instrumented: `KERN_TIMING` covered only the child's setup, so the time
    // spent here was invisible and nobody could optimise it, because nobody could see it. The marks
    // below cost one `getenv` when the variable is unset.
    let mut pt = kern_isolation::PhaseTimer::new();
    // ⛔ BEFORE ANY TRUST-BEARING STATE IS WRITTEN, and at this altitude on purpose.
    //
    // MEASURED 2026-11-12: with `$XDG_RUNTIME_DIR/kern` created 0777 in advance, kern ADOPTED it,
    // filled it with `claims env instances logs runstats scratch waitexit`, and started the box.
    // That directory holds the records which decide a box's capabilities and seccomp posture, and
    // kern's own `-v` refusal calls a writer of it able to "forge another box's recorded
    // capability/seccomp posture and elevate its own `kern exec`".
    //
    // WHY NOT IN THE PLUMBING, where the first version put it: `runtime_subdir` is reached by
    // read-only verbs that treat a missing registry as an empty one (`if let Ok(..)`), and box start
    // itself does `registry::register(&inst).ok()`, because a box matters more than its bookkeeping.
    // A refusal down there was returned and DISCARDED by almost every caller: a guard whose error
    // nobody reads looks like a guard and is not one. Here it is one explicit, fatal decision, taken
    // where the state is about to be created.
    //
    // A WORLD-WRITABLE RUNTIME DIR IS NOT HYPOTHETICAL: on WSLg `XDG_RUNTIME_DIR` is
    // `/mnt/wslg/runtime-dir`, which Microsoft's session setup creates `drwxrwxrwx`. kern's own
    // `kern/` under it is 0700 and owned by the caller, which is the case this check passes.
    if let Err(why) = crate::registry::state_dir_is_private() {
        return Err(Error::Cli(why));
    }
    let name = BoxName::parse(args.name).map_err(Error::InvalidBox)?;
    // The caller's (an SDK's) "box started" fd, read and VALIDATED up front, BEFORE the box is forked.
    // CLOEXEC is deferred past the scope re-exec by `cloexec_started_fd` below (see both docstrings for
    // why the systemd-run re-exec forces the split); written once, at the terminal exit arm below.
    let started_fd = started_signal_fd();
    // 🔴 THE ALIVE ACK GOES HERE, NOT AT THE SPAWN, and the byte is the whole point of the position.
    // Its docstring says "as soon as it has accepted the descriptor, before any box setup begins", and
    // that was false by about 780 lines: the ack was written just before the fork, while the IMAGE is
    // resolved and PULLED far above it. So the longest phase of a cold start was the one the channel
    // could not describe.
    //
    // MEASURED, and found on a board rather than on a laptop: the first SDK call on a Raspberry Pi 5
    // took 38 s pulling `python:3.12-slim` for arm64 against 0.1 s warm, the caller's 30 s deadline
    // fired inside the pull, and the verdict came back `timeout` - "your code was slow" - for a box
    // whose code never ran. Reproduced deterministically on x86 with an empty `XDG_CACHE_HOME` and
    // `timeout_s=3`, on the released binary AND on this tree, so it was never the tag skew.
    //
    // Written ONCE: `alive_signal_fd` writes the byte as a side effect, so the value is carried down
    // to the spawn rather than asked for twice.
    let alive_fd = alive_signal_fd();
    // An INHERITED direct-cap-path marker (e.g. a nested `kern box` inside a box whose host-side
    // start chose the direct path) is meaningless here and would arm the fail-closed refusal on a
    // host that never chose it - scrub before any cap decision is read.
    kern_isolation::scrub_direct_marker();
    // Reject a name already held by a LIVE box - otherwise two boxes share a name and `stop`/`logs`/
    // `exec` become ambiguous (and a repeated `compose up` would silently stack duplicates). `name_taken`
    // checks ONLY this name's entry (not the whole registry), so start stays fast at scale; it prunes a
    // dead same-name entry, so a freed name is immediately reusable. ADVISORY fast-fail only - the
    // authoritative check runs inside `claim_name` below; skipped on the scoped inner re-run
    // (`KERN_SCOPE`), which already passed it in the outer process.
    if crate::global_env("KERN_SCOPE").is_none() && registry::name_taken(name.as_str()) {
        return Err(Error::AlreadyRunning(format!(
            "a box named '{}' is already running",
            name.as_str()
        )));
    }
    pt.mark("parent:name-check");
    // THE ID MAP STARTS HERE, before everything the rest of this function does, because that is the
    // window it runs in: the two setuid helpers were ~0.9 ms on the path to the fork (measured
    // 2026-11-20, `parent:idmap` 928 of 4036 us), and the scope decision, the volumes, the claim,
    // the image, the ports and the cgroup can all happen while they run. Only where the command
    // line already makes the range certain and the box will build its own namespace (a pod member
    // joins the pod's; a persistent detached box may hand itself to systemd and never run here).
    // Every other box maps in place exactly as before, and so does this one if the preparation
    // fails. A scope re-exec below abandons it before its `execve`. See
    // `prepare_id_mapped_userns_early`.
    if args.pod.is_none()
        && !standalone_persistent(&args)
        && (image_default_uid_range(&args) || uid_range_asked_by_args(&args))
    {
        kern_isolation::prepare_id_mapped_userns_early();
        pt.mark("parent:userns-early");
    }
    // FLEET LIMITS (env-configured, deployment-level). Checked only in the OUTER process (KERN_SCOPE
    // unset), like the name check: the scoped inner re-run is the SAME box, already counted.
    if crate::global_env("KERN_SCOPE").is_none() {
        fleet_gate_and_budget()?;
    }
    warn_if_ssh_lacks_a_uid_range(args.ssh_port);
    // (The effective command is resolved AFTER the image is pulled, so an `--image`'s Entrypoint/Cmd
    // can supply the default - see `resolve_image_command` below.)
    // Split `-v` into local (host/named) and network (nfs/smb/sshfs) specs. Local ones are parsed
    // (named auto-created); network ones are FUSE/GVFS-mounted to staging and bound in - foreground
    // only, so their unmount is bounded to this call (detached network teardown lands later).
    let (net_specs, local_specs): (Vec<String>, Vec<String>) = args
        .volumes
        .iter()
        .cloned()
        .partition(|s| crate::volume::is_network(s));
    if !net_specs.is_empty() && (args.detached || args.tty) {
        return Err(Error::Sandbox(
            "network volumes (nfs/smb/sshfs) need a plain foreground box (not `-d` or `-it` yet)"
                .to_string(),
        ));
    }
    // Pull out named volumes that carry a recorded quota - those get an ext4-loop backing (real disk
    // quota) in the mount section; the rest (host paths + non-quota named) parse normally here.
    let (quota_specs, plain_specs): (Vec<String>, Vec<String>) =
        local_specs.into_iter().partition(|s| {
            let src = s.split(':').next().unwrap_or("");
            crate::volume::is_named(src) && crate::volume::size_limit(src).is_some()
        });
    let mut volumes = parse_volumes(&plain_specs)?;
    // BEFORE the GPU binds join the list: only what the caller bound is a candidate.
    let idmap_binds =
        crate::commands::idmap_bind_candidates(&volumes, kern_isolation::is_initial_root());
    // A BUILD STEP'S SSH AGENT SOCKETS: binds like any other, and the only sockets a box takes (the
    // targets go to `setup_volumes`, which refuses a socket anywhere else).
    let socket_binds: Vec<String> = args
        .build_ssh_agents
        .iter()
        .map(|(_, target)| target.clone())
        .collect();
    for (source, target) in args.build_ssh_agents {
        volumes.push(Volume {
            source: source.clone(),
            target: target.clone(),
            read_only: false,
        });
    }

    // `--gpus`: ONE card, resolved from native discovery and mounted through the SAME `Volume`
    // list `-v` uses. There is no second mount path and no hook: a GPU grant is a set of binds,
    // and giving it its own machinery would mean two places that can disagree about what a bind
    // is. The resolver is pure and was tested without hardware in S1; this is the plumbing.
    //
    // EVERY REFUSAL NAMES ITS CAUSE AND STOPS. A box that was asked for a GPU and started without
    // one is the "runs and lies" outcome: the workload meets `CUDA_ERROR_NO_DEVICE` at its first
    // call and has no way to learn that the flag it passed did nothing.
    // `--device` is the CDI spelling of `--gpus`, resolved to the same index through the spec and
    // then built from discovery. The plan's rule is that CDI is an ALIAS: the spec says which card
    // a name means, and the mounts come from the discovery a test proves equivalent to it.
    // THE VARIABLES A CDI SPEC PUTS IN THE CONTAINER, applied once the box's environment is known.
    let mut cdi_env: Vec<String> = Vec::new();
    // `--device <host path>[:<box path>[:perms]]`, DOCKER'S HOST-NODE FORM: a bind of the node, which
    // is what compose `devices:` already becomes, and read-only when the permissions name no `w`.
    // It used to be refused with a pointer to `-v`; docker takes it, beside `--gpus` too (measured on
    // a Jetson: `--gpus all --device /dev/nvhost-gpu` runs CUDA under docker). A name that is not a
    // path stays CDI. A node the caller opens only through a group keeps the box's groups, the rule
    // a `--gpus` grant follows, because a box on the uid-range map would otherwise clear it.
    let mut device_groups: Vec<u32> = Vec::new();
    let mut cdi_names: Vec<&str> = Vec::new();
    for item in args
        .device
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !item.starts_with('/') {
            cdi_names.push(item);
            continue;
        }
        let mut parts = item.splitn(3, ':');
        let host = parts.next().unwrap_or(item);
        let second = parts.next();
        let (inbox, perms) = match second {
            Some(p) if p.starts_with('/') => (p, parts.next()),
            other => (host, other),
        };
        if !std::path::Path::new(host).exists() {
            return Err(Error::Cli(format!(
                "--device {host}: no such device on this host (a node is bound, never created)"
            )));
        }
        let ro = perms.is_some_and(|p| !p.contains('w'));
        volumes.extend(parse_volumes(&[format!(
            "{host}:{inbox}{}",
            if ro { ":ro" } else { "" }
        )])?);
        if let Some(g) = crate::gpu_grant::node_needs_a_group(std::path::Path::new(host)) {
            if !device_groups.contains(&g) {
                device_groups.push(g);
            }
        }
    }
    let cdi_device: Option<String> = (!cdi_names.is_empty()).then(|| cdi_names.join(","));
    let gpu_selection: Option<Result<crate::gpu_grant::GpuSelection, Error>> =
        match (args.gpus, cdi_device.as_deref()) {
            (Some(_), Some(_)) => Some(Err(Error::Cli(
                "--gpus and --device name the same thing two ways: pass one".to_string(),
            ))),
            // EVERY `--device` ON THE LINE, as docker and podman read them: repeated flags reach
            // here as one comma-separated list (see the parser), each name resolves to a card or,
            // for the spec's `all`, to every card. The alias claim is unchanged and is about the
            // MOUNTS: the same card reached either way produces the same nodes.
            (None, Some(reference)) => Some(
                crate::cdi::resolve_device_refs(std::path::Path::new("/"), reference)
                    .map(|resolved| {
                        // WHAT THE SPEC ASKED FOR THAT kern DOES NOT DO, before the box starts and
                        // on the `--plan` path as well, because this value is computed once for
                        // both. The nodes of a CDI device and of `--gpus` are the same set, which
                        // is what "alias" means here; the hooks are the part that is not, and
                        // saying nothing about them let the equality be read as a stronger claim
                        // than it is.
                        if let Some(msg) =
                            crate::cdi::describe_hooks_not_run(reference, &resolved.hooks_not_run)
                        {
                            eprintln!("kern: warning: {msg}");
                        }
                        cdi_env = resolved.env;
                        match resolved.indices {
                            Some(indices) => crate::gpu_grant::GpuSelection::These(indices),
                            None => crate::gpu_grant::GpuSelection::All,
                        }
                    })
                    .map_err(|(_, e)| {
                        use crate::cdi::DeviceRefError as D;
                        Error::Cli(match e {
                            D::NotQualified { given } if given.starts_with('/') => {
                                device_path_message(&given)
                            }
                            D::NotQualified { given } => {
                                format!(
                                "--device {given}: not a CDI name. Use --device nvidia.com/gpu=0"
                            )
                            }
                            // THE FOURTH SURFACE THAT HAD TO SAY IT. Measured on a WSL2 guest with
                            // an RTX 3060 on the Windows side: this arm answered
                            // "Found: none" and nothing else, so the one operator who most needs
                            // the cause got the shortest message. The sentence is appended ONLY
                            // when the host offers no kind at all, which is that case; when a spec
                            // IS there and offers something else, `found` already names the cause.
                            D::NoSuchKind { kind, found } if found.is_empty() => {
                                crate::gpu::with_foreign_shape(
                                    &format!(
                                        "--device: no CDI spec on this host offers {kind}. \
                                         Found: none"
                                    ),
                                    std::path::Path::new("/"),
                                )
                            }
                            D::NoSuchKind { kind, found } => format!(
                                "--device: no CDI spec on this host offers {kind}. Found: {}",
                                found.join(", ")
                            ),
                            D::NoSuchDevice { name, offered } => format!(
                                "--device: the spec offers no device {name:?}. It offers: {}",
                                offered.join(", ")
                            ),
                            D::UnknownUuid { uuid } => format!(
                        "--device: the spec names {uuid} and this host's driver reports no card \
                         with that UUID"
                    ),
                            D::Unreadable { path, why } => format!(
                                "--device: {} could not be read: {}",
                                path.display(),
                                why.describe()
                            ),
                            // THE NESTING RULE REACHING THE READER. A spec describes the host it
                            // was generated on, so inside a nested container its paths are wrong
                            // unless that runtime regenerated it. The message says which file made
                            // the claim and what to do, because the name being valid is exactly
                            // what makes this confusing: the spec is not corrupt, it is about
                            // somewhere else.
                            // A FORMAT THIS BUILD DOES NOT READ IS NOT A BROKEN FILE. Saying
                            // "bad line 1" about a valid JSON spec sends the reader looking for a
                            // typo; naming the format and the flag that does not need a spec at
                            // all is the answer they can act on.
                            D::JsonSpec { path } => format!(
                                "--device: {} is a JSON CDI spec and this build reads the YAML \
                                 form only. Regenerate it with `nvidia-ctk cdi generate \
                                 --format=yaml`, or use --gpus device=N, which reads this host's \
                                 own /dev and needs no spec",
                                path.display()
                            ),
                            D::DescribesAnotherHost { reference, path } => format!(
                                "--device {reference}: {} names that device and none of its \
                                 device nodes exists here, so the spec describes a different \
                                 host (a nested container sees the outer host's paths unless its \
                                 runtime regenerated the spec). Use --gpus device=N, which reads \
                                 this host's own /dev, or regenerate the spec here",
                                path.display()
                            ),
                        })
                    }),
            ),
            (Some(spec), None) => {
                if let Some(note) = crate::gpu_grant::capabilities_note(spec) {
                    eprintln!("kern: note: {note}");
                }
                if crate::gpu_grant::asks_for_no_gpu(spec) {
                    eprintln!("kern: note: {}", crate::gpu_grant::describe_no_gpu(spec));
                }
                crate::gpu_grant::selection_from_spec(std::path::Path::new("/"), spec)
                    .or_else(|e| {
                        wsl_unchecked_uuid(spec, e, |note| eprintln!("kern: note: {note}"))
                    })
                    .map_err(|e| {
                        match e {
                    crate::gpu_grant::GpuSpecError::Empty => Error::Cli(
                        "--gpus needs a value: a count like 2, a card like device=0, or all"
                            .to_string(),
                    ),
                    crate::gpu_grant::GpuSpecError::AllWithMore { given } => Error::Cli(format!(
                        "--gpus {given}: `all` and anything beside it name different things and \
                         only one can be true. Use --gpus all, or name the cards \
                         (--gpus device=0,1)"
                    )),
                    crate::gpu_grant::GpuSpecError::Duplicate { index } => Error::Cli(format!(
                        "--gpus names card {index} twice. Each card is granted once; if you meant \
                         two cards, name two (--gpus device=0,1)"
                    )),
                    crate::gpu_grant::GpuSpecError::ZeroIsAmbiguous => Error::Cli(
                        "--gpus 0 has two readings and is refused rather than guessed: docker \
                         reads it as NO gpus, and this project's own examples read it as card 0. \
                         For card 0 write --gpus device=0; for no gpu, pass no flag"
                            .to_string(),
                    ),
                    crate::gpu_grant::GpuSpecError::NotACount { given } => Error::Cli(format!(
                        "--gpus {given}: not a number of cards. A bare number is HOW MANY you \
                         want, as it is in docker: --gpus 2. For a particular card use \
                         --gpus device=0, and for every card --gpus all"
                    )),
                    crate::gpu_grant::GpuSpecError::NotAnIndex { given } => Error::Cli(format!(
                        "--gpus {given}: not a card index. Use --gpus device=0, \
                         --gpus device=0,1, --gpus all, or a count like --gpus 2"
                    )),
                    // A UUID IS A DOCUMENTED SHAPE, so the refusal is about this HOST and not
                    // about the grammar: Docker's reference takes `device_ids: ["GPU-ebc4a5d2"]`
                    // and so does this flag now. The message names what the driver does publish,
                    // because the two likely causes are the wrong machine and a card that moved.
                    crate::gpu_grant::GpuSpecError::UnknownUuid { given, known } => {
                        Error::Cli(if known.is_empty() {
                            format!(
                                "--gpus device={given}: this host's driver publishes no GPU UUID \
                                 at all, so there is nothing to match it against"
                            )
                        } else {
                            format!(
                                "--gpus device={given}: no card here carries that UUID. This host \
                                 has: {}",
                                known.join(", ")
                            )
                        })
                    }
                }
                    })
                    // `Result<Option<_>, _>` INTO `Option<Result<_, _>>`: a spec that asks for no card
                    // becomes the same `None` the no-flag case produces, so nothing downstream has to
                    // learn a fourth state.
                    .transpose()
            }
            (None, None) => None,
        };

    // The address of the granted card, for the box's `/proc/driver/nvidia/gpus` mask. It is read
    // from the SAME grant that produced the mounts, so the directory the box keeps and the node it
    // was given are two views of one decision rather than two lookups that could disagree.
    // NO GRANT IS A STATE, NOT AN ABSENCE OF ONE. A box that was handed no card may see no card in
    // the driver's enumeration either, and the default below is what says so: the earlier spelling
    // was an empty vector that the mask read as "leave the host's listing alone", so every box on
    // this host, GPU or not, read both cards' UUID and video BIOS.
    let mut gpu_enumeration = kern_isolation::GpuEnumeration::NoneGranted;
    // THE GRANT, CARRIED TO WHERE THE BOX'S IDENTITY IS KNOWN. It is resolved before the image
    // config, so `run_as` does not exist yet at this point, and the question "which nodes does this
    // box lose by not being the caller" cannot be answered without it.
    //
    // THE LIST USED TO BE COMPUTED HERE and that was the defect: it probed with a uid no account can
    // name, while a box started `--user N` runs as `subuid_base + N - 1`, which is an account an
    // operator can write an ACL for. Carrying the GRANT instead of a precomputed answer is what
    // lets the probe use the uid the box will really carry.
    let mut gpu_for_identity: Option<(crate::gpu_grant::GpuGrant, crate::gpu_grant::GpuSelection)> =
        None;
    // `NVIDIA_VISIBLE_DEVICES` as docker sets it for the `--gpus` spec (see
    // `crate::gpu_grant::visible_devices`), applied once the box's own environment is known.
    let mut gpu_visible: Option<String> = None;
    // The driver tools the grant bound at `/usr/bin`, by name, for the healthcheck warning below:
    // `None` is "no GPU grant", which is a different sentence from "granted, and this host has no
    // such tool".
    let mut granted_tools: Option<Vec<String>> = None;
    // WHERE THE GPU'S BINDS GO IN THE LIST, and the WSL2 grant they come from: the libraries land
    // in the IMAGE's library directory, which is known only once the image is resolved below, so
    // the binds are placed then, at this position, and the mount order is what it always was.
    let gpu_binds_at = volumes.len();
    let mut wsl_pending: Option<crate::gpu::WslGrant> = None;
    // Nodes the grant reaches only through a group, decided once the box's uid map is known.
    let mut gpu_groups_needed: Option<(Vec<u32>, Vec<std::path::PathBuf>)> = None;
    // `--mount`'s mounts, resolved from their FIELDS. They never pass through a `src:dst` string, so
    // a source containing a `:` (or, quoted, a `,`) arrives whole - which is the difference between
    // `--mount` and `-v` now, and the reason the cache under a `colon:cache` path can be mounted.
    for (source, target, read_only) in args.mounts {
        volumes.push(crate::commands::resolve_volume(
            source,
            target,
            *read_only,
            &format!("--mount src={source},dst={target}"),
        )?);
    }
    // A box "asked for DNS" if it named ANY of the three: a `search` line alone is still a request
    // to own the file, and owning it in a pod means not sharing the pod's.
    let dns_requested =
        !args.dns.is_empty() || !args.dns_search.is_empty() || !args.dns_options.is_empty();
    let mut inherited_nameservers: Vec<String> = Vec::new();
    // `--network container:<box>` joins THAT box's network namespace through the pod path (a pod
    // holder is "a process whose user and network namespaces a box enters"), and takes its name, its
    // hosts file and its resolvers, which is what a container in another's namespace has under Docker.
    let joined = match args.net_container {
        Some(target) => Some(join_box_network(target, &args)?),
        None => None,
    };
    // The pod this box is RECORDED under: its own `--pod`, or the pod of the box whose network it
    // joined (see `JoinedNet::pod`). A label only: `args.pod` still decides what the box enters.
    let pod_label: String = args
        .pod
        .map(str::to_string)
        .or_else(|| joined.as_ref().map(|j| j.pod.clone()))
        .unwrap_or_default();
    let pod_holder = match &joined {
        Some(j) => {
            if !dns_requested {
                inherited_nameservers.extend(j.nameservers.iter().cloned());
            }
            Some(j.pid1)
        }
        None => join_pod_and_bind_its_files(
            args.pod,
            name.as_str(),
            &mut volumes,
            dns_requested,
            &mut inherited_nameservers,
            !args.pod_bridges.is_empty(),
        )?,
    };
    let (ipc_from, shm_dir) = share_ipc(&args, &name, pod_holder, &pod_label)?;
    // `--env-file` first (K=V lines from a file), then `--env` on top (explicit wins).
    let mut env = parse_env_files(args.env_file)?;
    env.extend(parse_envs(args.env)?);
    point_the_box_at_the_egress_proxy(&args, &mut env)?;
    // Fold resource profiles (`vcpu:name` …) into the caps - explicit flags win - before capping.
    let mut ap = AppliedProfiles {
        memory: args.memory,
        cpus: args.cpus,
        cpuset: args.cpuset.map(str::to_string),
        ..Default::default()
    };
    apply_profile_list(args.profiles, args.config, &mut ap)?;
    let AppliedProfiles {
        memory,
        cpus,
        cpuset,
        nice,
        vgpio,
        vdisk,
    } = ap;
    // ⛔ A BOX GIVEN A GPU IS BOUNDED BY THE MACHINE, NOT BY THE SANDBOX DEFAULT, as `kern compose`
    // services are and as docker's are. 512 MiB is a sandbox's default for code nobody sized, and a
    // GPU workload is never that: MEASURED on a WSL2 guest, every CUDA context costs about 75 MiB of
    // host memory (18 contexts reached 1351 MiB) and a box asking only for `--gpus all` was
    // OOM-killed while the same program ran outside kern. The host's RAM keeps the cap a real number,
    // so a box that does exhaust memory is still killed against its own cgroup with kern's message;
    // `--memory` still sets any cap, and the sandbox SDKs pass their own.
    let gpu_asked = args.gpus.is_some() || cdi_device.is_some() || args.runtime_nvidia;
    let memory = match memory {
        None if gpu_asked => host_meminfo_bytes("MemTotal:"),
        other => other,
    };
    // `--nice` (an explicit flag) overrides a profile's `nice`.
    let nice: Option<i32> = args.nice.map(|n| n as i32).or(nice);
    // Flatten the resolved vGPIO profiles into the device/sysfs paths the box will expose.
    let mut vgpio_devs: Vec<String> = Vec::new();
    let mut vgpio_sysfs: Vec<String> = Vec::new();
    for vg in vgpio {
        vgpio_devs.extend(vg.devs);
        vgpio_sysfs.extend(vg.sysfs);
    }
    // Refused, as Docker refuses them, when they name more than this host has (see `check_cpus`).
    let cpus = check_cpus(cpus, cpu_source(args.cpus.is_some()))?;
    let cpuset = check_cpuset(cpuset, cpu_source(args.cpuset.is_some()))?;
    // `--show-config`: a dry run - print the resolved box configuration and exit BEFORE any host-side
    // mount or the systemd-scope re-exec, so nothing is created or torn down.
    if args.show_config {
        // The dry run refuses what the launch would, the grant included.
        if let Some(selection) = gpu_selection {
            decide_gpu_grant(selection?, args.gpus)?;
        }
        print_resolved_config(
            &args,
            name.as_str(),
            memory,
            cpus,
            cpuset.as_deref(),
            nice,
            &crate::commands::ResolvedGrants {
                devs: &vgpio_devs,
                sysfs: &vgpio_sysfs,
                vdisk: &vdisk,
            },
        );
        std::process::exit(0);
    }
    let Supervision {
        health_action,
        restart,
        systemd_supervises,
        restart_always,
        managed,
        standalone_persistent,
    } = decide_supervision(&args)?;
    // A `kern build` RUN step (`KERN_BUILD_STEP=1`) is a transient, first-party box run many times in
    // a row - the ~7ms transient-scope re-exec would dominate the build. Skip it (the best-effort
    // in-process cgroup in run_in_sandbox still applies caps; isolation is unchanged).
    let build_step = kern_common::env_flag("KERN_BUILD_STEP");
    // Robust resource caps: re-exec this whole invocation inside a transient systemd user scope
    // with memory + task limits (proper cgroup delegation). The scope's caps track the effective
    // memory/cpu so the outer scope never strangles a box that asked for more. No-op if already
    // scoped or if systemd --user isn't available - then the best-effort cgroup in run_in_sandbox
    // applies the same caps.
    if !managed && !build_step {
        reexec_in_scope_if_possible(ScopeReexec {
            memory,
            memory_swap_max: args.memory_swap_max,
            cpuset: cpuset.as_deref(),
            cpus,
            pids_max: args.pids_limit,
            allow_direct: true, // `kern box` has a supervisor → may take the direct kern.slice path
            die_with_parent: !args.detached && !args.tty, // a foreground box dies with its launcher
            allow_uncapped: args.allow_uncapped || kern_common::env_flag("KERN_ALLOW_UNCAPPED"),
        });
    }
    say_what_the_egress_filter_cannot_close(&args);
    // THE GPU GRANT IS DECIDED IN THE FINAL PROCESS, after the scope re-exec and still before the
    // image is pulled, so a request this host cannot meet is refused before any download. Decided
    // above the re-exec, it was decided twice: MEASURED on a Jetson, where an SSH session sits
    // outside the user manager and every box takes the scope, the parent opened and read the header
    // of each of the grant's libraries once before `systemd-run` and once after it.
    if let Some(selection) = gpu_selection {
        let o = decide_gpu_grant(selection?, args.gpus)?;
        gpu_enumeration = o.enumeration;
        gpu_for_identity = o.for_identity;
        gpu_visible = o.visible;
        granted_tools = o.tools;
        wsl_pending = o.wsl;
        gpu_groups_needed = o.groups_needed;
    }
    // Now in the FINAL process (the scope re-exec above, if taken, has already execve'd): mark the
    // started-fd CLOEXEC so the workload's execvp closes it. Fail-closed (a fd we cannot protect is
    // dropped, and the SDK falls back to its over-reporting heuristic); see `cloexec_started_fd`.
    let started_fd = cloexec_started_fd(started_fd);
    // A profile's `nice` set here is inherited by the forked box workload.
    if let Some(n) = nice {
        apply_nice(n);
    }

    // Close the start/start race on the name (the `name_taken` check at the top is advisory -
    // check-then-register): atomically CLAIM the name, in THIS process - i.e. after the scope
    // re-exec, so the `exec()` can't orphan a claim - and hold it until the box is registered
    // (dropped explicitly after `register`, or by RAII on any earlier error return; a fork
    // inheriting it never releases - the claim is pid-owned). `claim_name` itself re-checks the
    // registry UNDER its lock, so `Ok(None)` covers both a concurrent starter and an already-
    // running box. Two concurrent same-name starts now serialize: one wins, the other fails fast
    // here instead of both passing `name_taken` and both coming up as ambiguous twins.
    pt.mark("parent:config+volumes");
    // The fleet ceiling is enforced HERE, atomically with the name claim, closing the count-then-start
    // race that the advisory check in `fleet_gate_and_budget` cannot: `claim_name_capped` counts the
    // boxes in flight and refuses UNDER THE SAME lock it takes the claim under, so two concurrent starts
    // at `max-1` serialize instead of both passing. `KERN_MAX_CONCURRENT` is read unconditionally (not
    // gated on `KERN_SCOPE`) because this is the single point every box - direct or scope-re-exec'd -
    // passes exactly once. Cooperative, not a security boundary (see `fleet_gate_and_budget`).
    let name_claim = match registry::claim_name_capped(name.as_str(), fleet_max()) {
        Ok(registry::StartOutcome::Claimed(c)) => Some(c),
        Ok(registry::StartOutcome::NameBusy) => {
            return Err(Error::AlreadyRunning(format!(
                "a box named '{}' is already starting or running",
                name.as_str()
            )))
        }
        Ok(registry::StartOutcome::FleetFull { live, max }) => {
            return Err(fleet_limit_error(live, max))
        }
        // No usable runtime dir → the registry is equally unavailable; proceed unclaimed
        // (fail-open, exactly like `name_taken`).
        Err(_) => None,
    };
    pt.mark("parent:claim");

    // `--keep`: THE COMMAND LINE IS RECORDED HERE, AFTER THE NAME IS CLAIMED and before the box
    // runs. Before the box, because a box that failed to start is still one the operator will want
    // to start again after fixing what refused it. After the claim, because the record and the layer
    // belong to the name: MEASURED with 20 `kern start` of one kept box at once, writing it earlier
    // had the 19 LOSERS rewrite the winner's record and (re)create its directory on their way to
    // being refused, which answered one of them "no kept box" and another "cannot record this box:
    // No such file or directory". Past the claim, only the one process that owns the name touches
    // either. Written every time, so a box re-created with different flags is restarted with the NEW
    // ones; `created` is kept from the first time.
    //
    // `args_os`, not `args`: an argument is not required to be UTF-8, and `std::env::args` panics on
    // one that is not. The first element is this binary's path and is dropped, since `kern start`
    // re-runs the kern it is itself.
    // `--keep`: the layer is TAKEN here and the record is WRITTEN further down, just before the box
    // is launched. See the note at the write for why the two are at different points.
    let mut keep_record: Option<(std::path::PathBuf, Vec<std::ffi::OsString>, u64)> = None;
    if args.keep {
        if let Some(dir) = crate::keepbox::dir_of(name.as_str()) {
            // THE LAYER IS TAKEN BEFORE ANYTHING IS WRITTEN TO IT, because the name claim above does
            // not cover it: the registry and the layer live in different places, and two boxes
            // mounting one overlay upperdir is undefined behaviour by the kernel's own message. See
            // `keepbox::hold_layer` for the two measured ways a name claim lets that happen.
            crate::keepbox::hold_layer(&dir)?;
            let argv = kept_argv(std::env::args_os().skip(1).collect(), name.as_str());
            let previous = crate::keepbox::read(&dir);
            // A DIFFERENT IMAGE ON AN EXISTING LAYER IS REFUSED, because a kept layer is a DELTA and
            // a delta only means something on the base it was written against. MEASURED: `kern box
            // m1 --image alpine:3.19 --keep` then `kern box m1 --image debian:12 --keep` ran the
            // debian box with the alpine run's files live inside it, and with a real workload the
            // delta carries that image's `/etc`, `/usr/lib` and `/var/lib` over the new base - a
            // rootfs nobody can debug. Every other flag may change (that is what rewriting the
            // record is for); this one cannot, and the way to change it is to say so: `kern rm`.
            let now_runs = crate::keepbox::image_of(&argv);
            if let Some((old_argv, _)) = previous.as_ref() {
                let was = crate::keepbox::image_of(old_argv);
                if !was.is_empty() && !now_runs.is_empty() && was != now_runs {
                    return Err(Error::Sandbox(format!(
                        "kept box '{}' has a layer written against {was}, and this command would run \
                         {now_runs} on top of it: a kept layer is a delta, and a delta of one image \
                         is not valid on another. `kern rm {}` throws the layer away and `kern box \
                         {} --image {now_runs} --keep -- <cmd>` makes it again, or keep {was}",
                        name.as_str(),
                        name.as_str(),
                        name.as_str()
                    )));
                }
            }
            keep_record = Some((
                dir,
                argv,
                previous
                    .as_ref()
                    .map(|(_, m)| m.created)
                    .filter(|c| *c > 0)
                    .unwrap_or_else(registry::now_unix),
            ));
        }
    }

    // `--bind-rootfs` only makes sense for a real `--rootfs` directory: an `--image` must stay an
    // immutable, shareable overlay (the cache is read-only and shared across boxes), and a bind
    // can't be remounted read-only on the kernels where bind mode is even useful.
    if args.bind_rootfs {
        if args.image.is_some() {
            return Err(Error::Sandbox(
                "--bind-rootfs needs --rootfs; an --image stays an immutable overlay".to_string(),
            ));
        }
        if args.read_only {
            return Err(Error::Sandbox(
                "--bind-rootfs is writable-only - a read-only bind remount is denied on the \
                 kernels where it helps; drop --bind-rootfs to get a read-only overlay root"
                    .to_string(),
            ));
        }
    }

    // `--privileged` (relax seccomp so a NESTED `kern box` can create its namespaces) is honoured
    // ONLY rootless: as REAL host root the box's root maps to host root, where re-allowing `mount`
    // would re-open the host-privilege class (the core_pattern escape). Refuse loudly rather than
    // silently ignore - the user asked for nesting; tell them it isn't safe here and why.
    if args.privileged && unsafe { libc::geteuid() } == 0 {
        return Err(Error::Sandbox(
            "--privileged (nested box) is rootless-only: run kern as a non-root user. As real \
             root the box's root maps to host root, and relaxing mount/namespace syscalls there \
             would break containment. A nested box is safe precisely because a rootless userns \
             grants no host privilege."
                .to_string(),
        ));
    }

    // A user `--rootfs` becomes the box's ENTIRE root (overlay lower or `--bind-rootfs`): guard it
    // against the registry through the SAME chokepoint `--secret`/`--env-file` use, or `--rootfs
    // <runtime>/kern` would make the registry the box's filesystem - the most privileged exposure of
    // the lot.
    if let Some(r) = args.rootfs {
        crate::secret::guard_host_path(r, "--rootfs")?;
    }
    // `--overlay-lower` TOO, AND IT IS NOT INTERNAL JUST BECAUSE IT IS UNDOCUMENTED. The comment here
    // used to say "kern-generated, not user input", but the flag is parsed from the same argv as any
    // other: `kern box x --overlay-lower <runtime>/kern --overlay-lower <an image dir> -- /bin/sh`
    // stacks the registry into the box's root, which is exactly what the line above refuses for
    // `--rootfs`. Guarding every layer costs one `canonicalize` per layer on the build's RUN steps
    // and closes the flag that was left open beside the one that was closed.
    for layer in args.overlay_lower {
        crate::secret::guard_host_path(layer, "--overlay-lower")?;
    }
    // The lower/base rootfs: an explicit --rootfs, or pull --image into a local cache. An --image
    // also yields its OCI runtime config (Entrypoint/Cmd/Env/WorkingDir/User) - the defaults below.
    // `lower` is the root's layers, TOP first, one path each - a list up to the mount, never a
    // `:`-joined string (a host path may contain a `:`).
    let (lower, image_config): (Vec<String>, kern_oci::ImageConfig) =
        match (args.overlay_lower, args.rootfs, args.image) {
            // Build RUN step: the base's layers as the build resolved them, no image config.
            (ol, _, _) if !ol.is_empty() => (ol.to_vec(), kern_oci::ImageConfig::default()),
            (_, Some(r), _) => (vec![r.to_string()], kern_oci::ImageConfig::default()),
            // `--image` may be a pulled (flat) OR a locally-built (layered) image - resolve both. The
            // `--pull` policy rides all the way down to the one site that hits the network
            // (`pull_to_cache`); `scratch` and locally-built images short-circuit before that, so
            // `never` naturally passes them.
            (_, None, Some(img)) => resolve_image_depth(img, 0, args.pull)?,
            (_, None, None) => return Err(Error::Sandbox("need --rootfs or --image".to_string())),
        };
    // AN EMPTY NAMED VOLUME IS SEEDED FROM THE IMAGE, WHICH IS WHAT DOCKER DOES.
    //
    // Docker copies the image's content at the mount point into a named volume the first time that
    // volume is used while it is still empty; kern mounted an empty directory over the top, so the
    // service came up and found NOTHING where its image had put a default configuration, an initial
    // database, or a web root. It then failed with an error of its own making, which points at the
    // application and never at the mount: `postgres` re-initialises, `nginx` serves 403, and the
    // person debugging it has no reason to suspect kern.
    //
    // ONLY WHEN THE VOLUME IS EMPTY, so this costs nothing after first use and can never write over
    // data that is already there. That is Docker's rule too, and it is the whole reason the check is
    // on the directory rather than on a first-use marker: a volume created ahead of time is empty,
    // and one emptied by hand is empty again.
    // `--runtime nvidia`: WHAT THE BOX'S OWN `NVIDIA_VISIBLE_DEVICES` NAMES, as NVIDIA's runtime reads
    // it, which is why it is decided only now: the value is the image's `ENV` unless `-e` or an env
    // file set it, and the image is known only from here on. The grant itself is the one `--gpus`
    // takes, by the same function.
    if args.runtime_nvidia && args.gpus.is_none() && cdi_device.is_none() {
        let set_by_caller = env
            .iter()
            .rev()
            .find(|(k, _)| k == "NVIDIA_VISIBLE_DEVICES")
            .map(|(_, v)| v.clone());
        let set_by_image = image_config
            .env
            .iter()
            .rev()
            .find_map(|kv| kv.strip_prefix("NVIDIA_VISIBLE_DEVICES="))
            .map(str::to_string);
        let value = set_by_caller.or(set_by_image);
        match runtime_nvidia_selection(value.as_deref())? {
            Some(selection) => {
                let o = decide_gpu_grant(selection, None)?;
                gpu_enumeration = o.enumeration;
                gpu_for_identity = o.for_identity;
                granted_tools = o.tools;
                wsl_pending = o.wsl;
                gpu_groups_needed = o.groups_needed;
            }
            None => eprintln!(
                "kern: note: --runtime nvidia: NVIDIA_VISIBLE_DEVICES is {}, which NVIDIA's runtime \
                 reads as no GPU, so none was granted",
                value
                    .as_deref()
                    .map(|v| format!("{v:?}"))
                    .unwrap_or_else(|| "not set in the image or the box".to_string())
            ),
        }
    }
    // THE GPU'S BINDS, NOW THAT THE IMAGE IS KNOWN, at the position the grant had in the list. The
    // libraries go into the image's library directory, docker's rule (`box_library_dir`).
    if gpu_for_identity.is_some() || wsl_pending.is_some() {
        let lib_dir = crate::gpu_grant::box_library_dir(&lower);
        let binds = match (&gpu_for_identity, &wsl_pending) {
            // The group question was settled by the grant decision (and is checked against the
            // box's uid map below), so it is not asked a second time here.
            (Some((grant, selected)), _) => crate::gpu_grant::mount_plan_keeping_groups(
                grant,
                selected,
                &crate::gpu_grant::Caller::current(),
                Some(&lib_dir),
            )
            .map_err(|e| Error::Cli(crate::gpu_grant::describe_mount_plan_error(&e)))?,
            (None, Some(w)) => w.binds_into(&lib_dir),
            (None, None) => Vec::new(),
        };
        volumes.splice(
            gpu_binds_at..gpu_binds_at,
            binds.into_iter().map(|(source, target, read_only)| Volume {
                source,
                target,
                read_only,
            }),
        );
    }
    seed_empty_named_volumes(&lower, &volumes);
    // Resolve the effective command from the image config (docker semantics: Entrypoint + the user's
    // command, else the image's Cmd; a shell if nothing is set). `--ssh` with no command keeps the
    // box alive instead. Explicit `-- CMD` always wins over the image's Cmd.
    let cmd = resolve_image_command(
        args.command,
        args.ssh_port.is_some(),
        &image_config,
        args.entrypoint,
    );
    pt.mark("parent:image+command");
    // The image's Env are DEFAULTS: put them first, then the user's `--env`/`--env-file` on top so an
    // explicit variable overrides the image's.
    if !image_config.env.is_empty() {
        let mut merged = image_envs(&image_config.env);
        merged.extend(env);
        env = merged;
    }
    // THE GRANT'S VALUE REPLACES ANY OTHER, the image's `ENV` and `-e` included, which is what docker
    // does (measured: `-e NVIDIA_VISIBLE_DEVICES=xyz --gpus device=1` gives `1`, once).
    if let Some(visible) = gpu_visible {
        env.retain(|(k, _)| k != "NVIDIA_VISIBLE_DEVICES");
        env.push(("NVIDIA_VISIBLE_DEVICES".to_string(), visible));
    }
    // AND A CDI SPEC'S OWN, the same way: what docker and podman put in the container for
    // `--device nvidia.com/gpu=…` (measured: `NVIDIA_VISIBLE_DEVICES=void` from this host's spec).
    for kv in cdi_env {
        if let Some((k, v)) = kv.split_once('=') {
            env.retain(|(name, _)| name != k);
            env.push((k.to_string(), v.to_string()));
        }
    }

    // Host-side mounts happen HERE - AFTER the systemd-scope re-exec (above) and after every
    // fallible step (guards, pull), so each is done exactly once, in the process that also tears it
    // down, and a later `?` can't orphan one (the handles' `Drop` cleans up an error path; the
    // success path unmounts explicitly before `exit`). Network volumes: FUSE/GVFS mount → bind.
    let mut net_volumes: Vec<crate::volume::NetVolume> = Vec::new();
    for (idx, spec) in net_specs.iter().enumerate() {
        let (source, target, read_only, handle) = crate::volume::setup_network(spec, idx)?;
        volumes.push(Volume {
            source,
            target,
            read_only,
        });
        net_volumes.push(handle);
    }
    // vDisks: a plain foreground box that can reach loop devices (root/`disk`) gets an ext4-on-loop
    // image (real disk-backed quota + persistence); detached/`-it`/unprivileged → a `size=` tmpfs.
    let ext4_ok = !args.detached && !args.tty;
    let vdisk_work = scratch_dir().join(format!("vdisk-{}-{}", name.as_str(), std::process::id()));
    let mut ext4_handles: Vec<crate::vdisk::Ext4Vdisk> = Vec::new();
    // cgroup `io.max` lines for `--iops`/`--bandwidth` on the ext4-loop backend (applied in the box's
    // cgroup by `apply_limits` - best-effort, needs the `io` controller delegated).
    let mut vdisk_io_max: Vec<String> = Vec::new();
    let vdisks: Vec<kern_isolation::VdiskMount> = vdisk
        .into_iter()
        .map(|vd| {
            prepare_vdisk(
                vd,
                ext4_ok,
                &vdisk_work,
                &mut ext4_handles,
                &mut vdisk_io_max,
            )
        })
        .collect();
    // Quota'd named volumes: back them with an ext4-loop image (real disk quota + persistence) when
    // privileged; else bind the plain data dir and say the quota isn't enforced (never silently).
    attach_quota_volumes(
        &quota_specs,
        ext4_ok,
        &vdisk_work,
        &mut ext4_handles,
        &mut volumes,
    )?;

    // `--secret`: read the values on the host (files/stdin/inline) BEFORE the fork; the box writes
    // them into a RAM-backed `/run/secrets` tmpfs (mode 0400) that never touches the overlay upper.
    let mut secrets = crate::secret::parse_secrets(args.secrets, args.secret_mode)?;
    // The environment-sourced ones join the same list, so everything downstream sees one kind of
    // secret: a name and its bytes. Appended AFTER, and a name already delivered from a file is
    // refused rather than shadowed, because two sources for one `/run/secrets/<name>` is the file
    // saying two different things.
    for s in crate::secret::parse_secret_envs(args.secret_envs, args.secret_mode)? {
        if secrets.iter().any(|e| e.name == s.name) {
            return Err(Error::Sandbox(format!(
                "secret '{}' is given both a file and an environment source; only one can land at \
                 /run/secrets/{}",
                s.name, s.name
            )));
        }
        secrets.push(s);
    }

    // SECURITY: `--ssh` cannot mean anything with `--net`, and what it WOULD do is dangerous.
    // `--ssh <port>` publishes `127.0.0.1:<port>` → box `:22`. With `--net` the box has no network
    // namespace of its own, so "box `:22`" is the HOST's `:22`. On any host that runs sshd - every
    // board in a fleet, every server - the forwarder therefore lands on the HOST's sshd while kern
    // prints `ssh -p <port> … root@127.0.0.1` as the way into the box. Measured on 2026-07-31 with an
    // image that has no sshd at all: the banner on the published port was byte-identical to the
    // host's own (`SSH-2.0-OpenSSH_9.6p1`). On a host WITHOUT sshd it is no better: the box's own
    // sshd binds the host's `:22`, exposing the box to the whole network on the standard port.
    // Refuse, like `--egress-allow` above: a flag whose promise the network mode cannot keep.
    if args.share_net && args.ssh_port.is_some() {
        return Err(Error::Sandbox(
            "--ssh cannot be combined with --net: --ssh publishes the box's port 22, and with --net \
             the box has no network of its own, so port 22 is the HOST's. kern would hand you the \
             host's sshd (or expose the box's on the host's :22). Drop --net for an isolated network, \
             or use --pod for a shared network that is still not the host's."
                .to_string(),
        ));
    }
    // SECURITY, the general case behind `--ssh` above: `-p` publishes THE BOX'S port, and with `--net`
    // the box has no port of its own. The forwarder connects to `127.0.0.1:<box_port>` in the shared
    // (host) network, where kern cannot tell the box's listener from any other process on the machine.
    // If the box's service is not up - it crashed, it is still starting, it was never in the image -
    // the mapping quietly serves whatever host process owns that number, under the box's name and in
    // `kern ps`. That is not a warning-shaped problem: it is a claim kern cannot substantiate, so it
    // is refused, exactly as `--egress-allow` is refused for the same reason (it filters the box's OWN
    // network). The way to get outbound AND a published port is `--pod`, whose network is shared but
    // is not the host's, and where `-p` means the pod's port again.
    if args.share_net && !args.ports.is_empty() {
        return Err(Error::Sandbox(
            "-p cannot be combined with --net: with a shared network the box has no port of its own, \
             so kern cannot tell the box's listener from any other process on this host, and would \
             publish whichever one holds that number. Drop --net for an isolated network where -p is \
             the only way in, or use `kern pod create` + --pod for a shared network that is not the \
             host's (outbound works there, and -p means the pod's port)."
                .to_string(),
        ));
    }
    // `--ssh`: authorize a key (generate a throwaway keypair, or use `--ssh-key`) and publish the
    // in-box sshd on the host port (→ box `:22`) via the ordinary rootless forwarder. `eff_ports`
    // is the user's `-p` maps plus that SSH mapping.
    let (ssh, mut eff_ports, ssh_hint) =
        prepare_ssh(&name, args.ssh_port, args.ssh_key, args.ports)?;
    // THE HOST'S PUBLISH POLICY, APPLIED AT THE ONE CHOKE POINT. Everything downstream - the
    // preflight, the forwarders, the registry entry, `kern ps` - reads this list, so narrowing it
    // here means there is no second place where a port could still be bound wider than the operator
    // allowed. Named rather than silent: a spec that asked for something else is reported, because a
    // published port that answers somewhere other than where the file said is precisely the class of
    // difference this project refuses to ship.
    // NOT CONSULTED WHEN THERE IS NOTHING TO PUBLISH, and this is a measured cost rather than a
    // tidiness argument. `publish_policy` reads `kern.toml`, and it used to run on every box start
    // including the overwhelming majority that publish no port at all. Alternated against `main`,
    // 250 pairs per repeat, three repeats: +13, +33, +17 us on box start p50 - all three positive,
    // so unlike ordinary run-to-run spread this was real. A box with no `-p` cannot be affected by a
    // publish policy, so the read is skipped and the cost is paid only by the boxes the setting is
    // about.
    let policy = if eff_ports.is_empty() {
        None
    } else {
        match crate::commands::publish_policy() {
            Ok(p) => p,
            // FAIL CLOSED, AND SAY SO. kern cannot know what the operator meant, and the two wrong
            // answers are not symmetric: guessing "every interface" publishes ports the operator may
            // have spent a config file preventing, while guessing "loopback" costs reachability that a
            // single readable line restores. The box still starts, because refusing every box over an
            // unrelated typo elsewhere in `kern.toml` would be a bigger change than this setting owns.
            Err(e) => {
                eprintln!(
                "kern: warning: kern.toml could not be read ({e}); publishing on 127.0.0.1 until it \
                 parses, rather than assuming every interface"
            );
                Some(crate::ports::LOOPBACK_IP)
            }
        }
    };
    let moved = crate::commands::apply_publish_policy(&mut eff_ports, policy);
    if moved > 0 {
        eprintln!(
            "kern: note: {moved} published port(s) bound to loopback (127.0.0.1, ::1) by the host's \
             `[kern] publish_bind` policy, overriding what the spec asked for"
        );
    }
    // A PORT KERN CANNOT BIND IS MOVED RATHER THAN FATAL, unless the operator asked otherwise.
    // Rootless, the kernel refuses a bind below `net.ipv4.ip_unprivileged_port_start`, and 15 of the
    // 39 samples Docker itself ships publish such a port: `80` in fourteen of them. Refusing means
    // more than a third of Docker's own examples do not start here for a reason that is about the
    // machine and not about the file. Every move is printed with both numbers, so the reader is
    // never left looking for a service on a port it is not on.
    let floor = unprivileged_port_start_at("/proc/sys/net/ipv4/ip_unprivileged_port_start");
    match crate::commands::privileged_port_policy() {
        Ok(true) => {
            let moved = crate::commands::shift_privileged_ports(&mut eff_ports, floor);
            for (from, to) in &moved {
                eprintln!(
                    "kern: note: host port {from} needs a privilege kern lacks when rootless, so it \
                     is published on {to} instead (this host binds from {floor} upward; set `[kern] \
                     privileged_port = \"refuse\"` to fail instead of moving it)"
                );
            }
        }
        Ok(false) => {}
        Err(e) => eprintln!(
            "kern: warning: {e}; a privileged port is moved rather than refused, which is the default"
        ),
    }
    // THE IPv6 TWIN OF A DEFAULT BIND IS DROPPED WHERE ITS ADDRESS CANNOT BE BOUND, as Docker drops
    // it: a CI runner or a kernel booted with `ipv6.disable=1` would otherwise refuse every `-p
    // 8080:80`. Decided PER ADDRESS, because a host can have IPv6 and not `::1` (see
    // `address_is_bindable`), which is the twin a loopback policy asks for. An IPv6 address the spec
    // WROTE is kept, so that host refuses it by name. One probe per distinct address, and none when
    // there is no twin.
    drop_unbindable_twins(&mut eff_ports, kern_isolation::address_is_bindable);
    assign_picked_ports(&mut eff_ports)?;
    let ports: &[kern_isolation::PortMap] = &eff_ports;
    // Fail fast if a `-p` host port is already taken (by another box or any process): otherwise the
    // forwarder fails inside its fork - whose stderr a detached box swallows - and the box would
    // print "started" while nothing actually listens.
    // THE `ssh` LINE IS PRINTED ONLY ONCE THE PORTS ARE KNOWN FREE, and the keys made for a box that
    // cannot start are removed. It used to be printed first, so a taken port produced a ready-to-paste
    // command for a box that never ran, followed by the refusal, and left the keys behind.
    let preflight = kern_isolation::preflight_ports(ports);
    if preflight.is_err() && args.ssh_port.is_some() {
        forget_ssh_keys(&name);
    }
    if preflight.is_ok() {
        if let Some(h) = &ssh_hint {
            eprintln!("{h}");
        }
    }
    if let Err((hp, e)) = preflight {
        return Err(publish_refusal(hp, &e, ports));
    }
    // `--hostname`: validate before it reaches `sethostname`. `--tmpfs`: parse the Docker-style
    // specs (blocking a tmpfs over the hardened mounts). `--user`: parse UID[:GID].
    let hostname = match &joined {
        // The joined box's own name, as Docker gives it: a container in another's network namespace
        // answers to that namespace's hostname.
        Some(j) if !j.hostname.is_empty() => Some(j.hostname.clone()),
        _ => validate_hostname(args.hostname)?,
    };
    let tmpfs = parse_tmpfs(args.tmpfs)?;
    // `--user` wins; otherwise the image's `config.User`. Either can be NUMERIC (parses directly) or a
    // NAME - `--user memcache`, compose `user:`, or the image's own `USER memcache` - resolved against the
    // image's OWN `/etc/passwd`/`/etc/group`, the way Docker does (the rootfs is extracted pre-pivot). One
    // resolver closes the whole class: kern no longer runs a by-name user as box root, which broke every
    // image that declares a user by name and refuses to run as root (memcached, unprivileged nginx,
    // elasticsearch). The two halves differ ONLY in the miss case: an EXPLICIT `--user`/`user:` the image
    // can't resolve is an ERROR (the caller asked for it), while the image's OWN `USER` falls back to
    // box-root with an honest note (so an odd image still starts).
    // `user_or_image` is the shared half both arms need: a NUMERIC spec parses directly, a NAME resolves
    // against the image. The arms differ ONLY in the miss handler (below), which is the whole point.
    // THE IMAGE IS CONSULTED FIRST, INCLUDING FOR A NUMERIC SPEC, and it was consulted last.
    //
    // This tried `parse_user` first, which succeeds on any number, so a numeric `USER 1000` never
    // reached the image at all and took `gid = uid`. Docker resolves a numeric user against the
    // image's `/etc/passwd` exactly as it does a name, and falls back to the ROOT group when the
    // image has no entry for that uid.
    //
    // Measured on `quay.io/keycloak/keycloak:26.1`: it declares `USER 1000`, its passwd says
    // `keycloak:x:1000:0:`, and its own tree is `drwxrwxr-x root root` - writable by the owner and
    // by GROUP 0. Run with gid 1000 the process cannot write its own installation, Quarkus'
    // startup augmentation fails to write into its runner JAR, and `jdk.nio.zipfs` reports the
    // JAR as a READ-ONLY zip filesystem. The box then restart-loops on a
    // `ReadOnlyFileSystemException` that names nothing about permissions or uids.
    //
    // `resolve_user` answers for every spelling - `1000`, `1000:2000`, `keycloak`,
    // `keycloak:root` - so `parse_user` is only the fallback for a spec the image cannot resolve,
    // which is where the two arms below deliberately differ.
    let image_accounts = Accounts::Layers(&lower);
    let user_or_image = |u: &str| match resolve_user(u, &image_accounts) {
        Some(pair) => Some(pair),
        None => parse_user(Some(u)).ok().flatten(),
    };
    let run_as = resolve_run_as(
        args.run_as,
        image_config.user.as_deref(),
        &user_or_image as &dyn Fn(&str) -> Option<(u32, u32)>,
    )?;
    // THE GROUPS THAT USER IS IN, from the SAME spec `run_as` was resolved from and only when that
    // spec named no group. Docker and podman fill the supplementary set exactly there and nowhere
    // else (measured; see `supplementary_gids`), so an operator writing `--user 1000:1000`
    // still gets that pair and nothing added to it.
    let user_spec = args
        .run_as
        .filter(|u| !u.is_empty())
        .or(image_config.user.as_deref().filter(|u| !u.is_empty()));
    let mut extra_gids = match user_spec {
        Some(spec) => supplementary_gids(spec, &image_accounts),
        None => Vec::new(),
    };
    // `--group-add`, ON TOP of the user's own groups, as docker adds them.
    for g in
        super::imagecache::group_add_gids(args.group_add, &image_accounts).map_err(Error::Cli)?
    {
        if !extra_gids.contains(&g) {
            extra_gids.push(g);
        }
    }
    // HOME FOLLOWS THE USER, as a DEFAULT under both the image's own `Env` and the caller's `-e`:
    // it is only added when neither of those named it, so an explicit `HOME=` still wins. The box
    // keeps `/root` when it runs as box root, which is that uid's home in every image that has one.
    // See `user_home` for what a fixed `/root` cost a non-root workload.
    if let Some((uid, _)) = run_as {
        if uid != 0 && !env.iter().any(|(k, _)| k == "HOME") {
            env.insert(0, ("HOME".to_string(), user_home(uid, &image_accounts)));
        }
    }
    // COMPAT HEADS-UP (not a security check; not parsing the entrypoint - only the image's own declared
    // `User`). An OCI image that drops privilege to a non-root user (postgres/redis/nginx via `User` or
    // an entrypoint `setpriv`/`gosu`) needs uids beyond box-root. Two honest cases:
    //  - WITHOUT --uid-range (single-uid box): the drop's uid isn't mapped → the entrypoint's
    //    `chown`/`setuid` fails EINVAL. Tell the user to add --uid-range (which now makes these images
    //    work - the box root is world-traversable and the range maps the service uid).
    //  - WITH --uid-range but the image declares a numeric `User` >= the mapped range size: the drop is
    //    to a uid the range doesn't cover → still fails. Tell the user to widen /etc/subuid. We NEVER
    //    silently clamp the uid into range (that would run the service as a DIFFERENT uid than the image
    //    intends - a silent lie); we surface it and let the user fix the range.
    // An `--image` box gets the RANGE uid mapping by default, which is what `kern compose` has always
    // done for image services. Without it the official images fail in their entrypoint, not in kern:
    // postgres dies on `chown: /var/lib/postgresql/data: Invalid argument` and nginx on
    // `chown("/var/cache/nginx/client_temp", 101) failed`, because both declare USER root and drop
    // privilege INTERNALLY - so reading the image's USER is not enough to predict it.
    //
    // The same input reaching the two paths and behaving differently is the divergence class this
    // codebase treats as a defect. `--no-uid-range` opts out for anyone who wants the tighter
    // single-uid map; a `--rootfs` box is unaffected, exactly as in compose.
    let image_default_uid_range = image_default_uid_range(&args);

    // A non-root `--user` needs its uid mapped into the box's namespace, which the single-uid map
    // doesn't provide - so a non-zero `--user` (like `--ssh`) implies the uid/gid-range mapping.
    // `run_as` already folded in the image's own `USER`, which is why this has to be known BEFORE
    // the heads-up below: that message speaks about the map the box will get.
    let non_root_user = matches!(run_as, Some((u, _)) if u != 0);

    // THE GRANT MET THE BOX IDENTITY, which are the two facts this function resolves at opposite
    // ends of itself. A node reached only by the caller's uid (`Owner`, or an `ACL_USER` entry for
    // them) is NOT reached by a box running as a subordinate uid, so the mount succeeds and the
    // workload meets `CUDA_ERROR_NO_DEVICE` with nothing from kern to explain it.
    //
    // A WARNING AND NOT A REFUSAL. `--gpus --user nobody` works on every host whose nodes are
    // world-accessible, which is the common shape and what pentest case C1 measures, so refusing it
    // would break that shape to describe a rare one. The operator gets the node names, the cause
    // and the one flag that avoids it; the box still starts. `kern: warning:` is the prefix both
    // SDKs file as a runtime note rather than a failed start.
    // THE GRANT MEETS THE BOX IDENTITY, which this function resolves at opposite ends of itself.
    // A node reached only by the caller's uid (`Owner`, or an `ACL_USER` entry for them) is NOT
    // reached by a box running as a subordinate uid, so the mount succeeds and the workload meets
    // `CUDA_ERROR_NO_DEVICE` with nothing from kern to explain it.
    //
    // THE PROBE USES THE UID THE BOX WILL CARRY. On the ranged map, in-box uid N lands on
    // `subuid_base + N - 1`: measured, `--user nobody` (65534) runs as host uid 165533 with a base
    // of 100000. Probing with a uid no account can name instead would report a node carrying an ACL
    // for that subuid as lost, warning about a box that works.
    //
    // NO RANGE MEANS NO WARNING. A non-zero `--user` is not mappable on the single-uid map, and
    // kern promotes such a box to the ranged map; on a host with no `/etc/subuid` row at all the
    // identity itself cannot be assumed, so the box fails for a different reason and a note about
    // device nodes would be noise.
    // "NO RANGE" IS THE HOST'S ANSWER, NOT ITS `/etc/subuid` ROW ALONE: a Jetson with the row and
    // without `newuidmap` warned about nodes a box it cannot build would lose (measured).
    if let (true, Some((grant, selection)), Some((in_box_uid, _)), true) = (
        non_root_user,
        &gpu_for_identity,
        run_as,
        kern_isolation::id_range_available(),
    ) {
        let caller = crate::gpu_grant::Caller::current();
        let name = kern_isolation::username(caller.uid);
        let base = kern_isolation::sub_range("/etc/subuid", name.as_deref(), caller.uid)
            .map(|(start, _)| start);
        // `checked_add` rather than a bare sum: the row is operator-written and a base near
        // `u32::MAX` would otherwise wrap into a uid that means something else.
        let box_host_uid = match base {
            Some(start) if in_box_uid >= 1 => start.checked_add(in_box_uid - 1),
            // In-box uid 0 is the caller's own uid on both maps, so there is nothing to lose.
            Some(_) => Some(caller.uid),
            None => None,
        };
        if let Some(box_host_uid) = box_host_uid {
            let lost = crate::gpu_grant::uid_dependent_nodes(
                grant,
                selection,
                &caller,
                box_host_uid,
                gpu_groups_needed.is_some(),
            );
            if !lost.is_empty() {
                let names: Vec<String> = lost
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect();
                // NAME WHAT FAILS, NOT WHAT MIGHT. The first wording said "CUDA may fail inside
                // with no device", and on this host that is false: the compute nodes are `0666` and
                // only the DRM nodes are uid-gated, so `cuInit` works and a Vulkan or display
                // workload does not. Measured both ways with `--gpus device=0`: a default box opens
                // all three nodes read-write, and the same box `--user nobody` is refused on
                // exactly the two named here. A warning that overstates its own consequence teaches
                // a reader to skip the next one.
                eprintln!(
                    "kern: warning: this box runs as a non-root user (host uid {box_host_uid}), so \
                     {} of the granted GPU node(s) will NOT open inside it: {}. They are reachable \
                     only by your uid (their owner, or an ACL entry naming you) and the box's \
                     subordinate uid is neither. Compute on the card still works if its \
                     /dev/nvidia* nodes are world-accessible; anything needing a refused node \
                     (display, Vulkan, video encode) fails there. Run without --user, or without \
                     the image's own USER, to keep your uid, or give those nodes an `other` bit on \
                     the host.",
                    lost.len(),
                    names.join(", ")
                );
            }
        }
    }

    let declared_user = image_config
        .user
        .as_deref()
        .filter(|u| !u.is_empty() && *u != "0" && *u != "root");
    if let Some(u) = declared_user {
        // Warn ONLY when the box really will be single-uid. Checking just the flag and the image
        // default made this fire on `--image <declares USER 1000> --no-uid-range`, where the image's
        // own USER has already promoted the box to a range: it announced a single-uid map that did
        // not exist and advised re-running without a flag, which would have changed nothing. The
        // remaining true case is an explicit `--user 0` over an image that drops privilege itself.
        let will_be_single_uid =
            !args.uid_range && !image_default_uid_range && !non_root_user && ssh.is_none();
        if will_be_single_uid {
            eprintln!(
                "kern: heads-up: image runs as non-root user '{u}' - under kern's rootless model a \
                 single-uid box can't map that uid, so the entrypoint may fail (chown/setuid EINVAL). \
                 Re-run without --no-uid-range to map a subordinate uid range."
            );
        } else if let Ok(n) = u.split(':').next().unwrap_or(u).parse::<u32>() {
            // Numeric User declared AND --uid-range: warn only if it exceeds the range we can map.
            // (A name like `postgres` we can't resolve pre-pivot; the range covers the usual 0..65535.)
            let range = mapped_uid_count(); // best-effort: the caller's /etc/subuid range size
            if range != 0 && n >= range {
                eprintln!(
                    "kern: heads-up: image runs as uid {n}, but --uid-range maps only {range} uids \
                     (0..{}). The drop to {n} will fail; widen the caller's /etc/subuid allocation to \
                     cover it. kern will NOT remap it to a different uid.",
                    range - 1
                );
            }
        }
    }
    // `--security-profile <untrusted>`: apply the bundle as a BASE, so explicit flags and env override
    // it (the documented precedence). CRITICAL: seccomp is resolved into a VALUE carried in the spec,
    // NOT via `env::set_var` - that is `unsafe` (a data race on the un-locked `environ` in a
    // multi-threaded process) and a process-global side effect that would leak into a second box run in
    // the same process. cap-drop and read-only mutate LOCALS only. The profile still rides the replayed
    // argv into the scope re-exec, so the re-exec'd process re-derives the same posture from the flag.
    let seccomp_mode = resolve_seccomp_mode(
        crate::global_env("KERN_SECCOMP").as_deref(),
        args.security_profile,
    )?;
    let mut cap_drops = args.cap_drop.to_vec();
    let mut read_only = args.read_only;
    // The profile is for code nobody has read, so it also refuses a setuid gain, which a plain box
    // allows as docker does (`--security-opt no-new-privileges` asks for it on any box).
    let no_new_privs =
        args.no_new_privs || matches!(args.security_profile, Some(SecurityProfile::Untrusted));
    if let Some(SecurityProfile::Untrusted) = args.security_profile {
        // cap-drop ALL as a base; an explicit `--cap-add X` is re-added by `caps::resolve` (the adds are
        // subtracted from the drop mask, see `CapSpec`), so the profile is a floor, not a ceiling.
        if !cap_drops.iter().any(|d| d.eq_ignore_ascii_case("ALL")) {
            cap_drops.insert(0, "ALL".to_string());
        }
        read_only = true; // untrusted -> read-only root (there is no --no-read-only to override)
                          // Print the RESOLVED constituents (the ACTUAL seccomp mode, so an explicit KERN_SECCOMP shows as
                          // what it is): the macro is visible and never claims a posture it did not get.
        let sec = match seccomp_mode {
            kern_isolation::SeccompFilter::Allowlist => "allowlist",
            kern_isolation::SeccompFilter::AllowlistAudit => "allowlist-audit",
            kern_isolation::SeccompFilter::Denylist => "denylist",
        };
        // A surviving `--cap-add` wins over the profile's drop-all (adds are subtracted from the drop
        // mask). The line must SHOW it, held to the same "never advertise a posture it did not get"
        // standard as the seccomp value above - otherwise it reads `cap-drop=ALL` while the box keeps a
        // cap the operator re-added. `--cap-add ALL` is already refused at parse under the profile, so
        // these are specific caps that genuinely survive.
        let caps_line = if args.cap_add.is_empty() {
            "cap-drop=ALL".to_string()
        } else {
            format!("cap-drop=ALL, cap-add={}", args.cap_add.join(","))
        };
        // Announced on stderr (not TTY-gated): this is an HONESTY confirmation of the resolved posture
        // - "never advertise a posture it did not get" - and is asserted by the sandbox_run tests. An
        // SDK capturing the box's stderr must not mistake it for a box-start failure: the classifier
        // skips benign `kern:` banner/warning/note lines before its startup-failure heuristic.
        eprintln!(
            "kern: security-profile=untrusted: seccomp={sec}, {caps_line}, read-only=on, \
             no-new-privileges=on (Landlock and --require-limits untouched)"
        );
    }
    // `--cap-add`/`--cap-drop`: resolve names to a CapSpec (unknown name → error) layered on the
    // always-dropped dangerous baseline.
    let caps = crate::caps::resolve(args.cap_add, &cap_drops)?;

    // Always an overlay (image/rootfs = read-only lower, private upper takes writes).
    // `--read-only` then remounts that overlay read-only after pivot.
    // A JETSON GRANT'S SYSFS (the chip's identity), read-only beside any a vGPIO profile asked for.
    // AND A PCI CARD'S OWN SYSFS DIRECTORY, which NVML reads its PCI identity from: see
    // `gpu_grant::pci_sysfs_paths`. Only the cards this box was given.
    // The PCI card's sysfs goes into its OWN list, reproduced read-only with its links and the
    // bridges above it: see `kern_isolation::SandboxSpec::gpu_sysfs`.
    let mut gpu_sysfs: Vec<String> = Vec::new();
    if let Some((grant, selection)) = &gpu_for_identity {
        for p in &grant.sysfs {
            let p = p.to_string_lossy().into_owned();
            if !vgpio_sysfs.contains(&p) {
                vgpio_sysfs.push(p);
            }
        }
        let pci = crate::gpu_grant::pci_addresses_of(grant, selection)
            .map(|a| crate::gpu_grant::pci_sysfs_paths(std::path::Path::new("/"), &a))
            .unwrap_or_default();
        for r in pci {
            let p = std::path::Path::new("/")
                .join(r)
                .to_string_lossy()
                .into_owned();
            if !gpu_sysfs.contains(&p) {
                gpu_sysfs.push(p);
            }
        }
    }
    // THE BOX'S UID MAP, decided once, read by the spec and by the GPU group check below.
    let uid_range = if args.uid_range || ssh.is_some() || non_root_user {
        UidRange::Requested
    } else if image_default_uid_range {
        UidRange::ImageDefault
    } else {
        UidRange::Off
    };
    // A GPU NODE REACHED ONLY THROUGH A GROUP: the box KEEPS the caller's groups, on any map.
    //
    // Docker's NVIDIA runtime gives the container the node's group (`additionalGids`), whatever its
    // user. kern cleared the inherited set on the uid-range map, so on a Jetson (every node
    // `root:video 0660`) `cuInit` failed in every pod member, under `--uid-range` and under `--user`,
    // MEASURED once `uidmap` was installed. A first fix moved a standalone box to the single-uid map,
    // which cannot clear; a pod member shares the pod's map and was not helped. The gid itself cannot
    // be mapped into a range, so the inherited set is kept whole, which is what the single-uid map
    // already does, and the note says so where the box would otherwise have cleared it.
    let mut kept_for: Vec<u32> = gpu_groups_needed
        .as_ref()
        .map(|(gids, _)| gids.clone())
        .unwrap_or_default();
    for g in &device_groups {
        if !kept_for.contains(g) {
            kept_for.push(*g);
        }
    }
    let keep_groups = !kept_for.is_empty();
    if keep_groups {
        let would_clear = (!matches!(uid_range, UidRange::Off) || args.pod.is_some())
            && kern_isolation::id_range_available();
        if would_clear {
            let ids: Vec<String> = kept_for.iter().map(u32::to_string).collect();
            eprintln!(
                "kern: note: the granted device nodes open only through group(s) {}, so this box \
                 keeps the supplementary groups you are in, all of them, as docker's NVIDIA runtime \
                 adds the nodes' group to a container",
                ids.join(", ")
            );
        }
    }
    let (spec, scratch) = build_spec(BuildSpec {
        name: &name,
        lower,
        cmd,
        read_only, // profile-adjusted: `--security-profile=untrusted` forces read-only on
        seccomp_mode, // resolved above (explicit KERN_SECCOMP > profile > default), not from env here
        landlock_rw: args.landlock_rw.to_vec(),
        net_ips: args.net_ips.to_vec(),
        // THE BOXES SOMETHING REACHES FROM OUTSIDE get an address of their own: a published port, a
        // pod's peers, a compose service's peers (every service carries `--def-hash`, and only compose
        // writes it). An SDK cell or an MCP call has none of them and does not pay for one.
        box_addr: !args.share_net
            && (!ports.is_empty() || pod_holder.is_some() || !args.def_hash.is_empty()),
        pod_bridges: args.pod_bridges.clone(),
        apparmor: args.apparmor.map(|s| s.to_string()),
        volumes,
        env,
        // `--workdir` wins; otherwise the image's `config.WorkingDir`.
        workdir: args
            .workdir
            .map(str::to_string)
            .or_else(|| image_config.workdir.clone()),
        share_net: args.share_net,
        pod_holder,
        ipc_from,
        shm_dir,
        // AFTER `share_ipc`, which clears this box name's directories: made here, empty.
        etc_dir: registry::fresh_etc_dir(name.as_str()).map(|d| d.to_string_lossy().into_owned()),
        // `--ssh` and a non-root `--user` imply the uid/gid *range* mapping: sshd's privsep needs a
        // working `setgroups` (a single-uid map forbids it via `/proc/self/setgroups=deny`), and a
        // non-zero target uid must be mapped in. With the range (via `newgidmap`/`newuidmap`) both
        // work; if the helpers are absent the box falls back to single-uid. Those three are the
        // caller ASKING, so an unavailable range is reported; the per-image default is not.
        uid_range,
        bind_rootfs: args.bind_rootfs,
        privileged: args.privileged,
        require_limits: args.require_limits,
        allow_uncapped: args.allow_uncapped,
        // `--keep` RESOLVES INTO THE PERSISTENT UPPER HERE, once, so everything downstream - the
        // mount, the work-dir clearing, the registry record - sees one mechanism and cannot disagree
        // about where a box's writes go. An explicit `--overlay-upper` wins: a build step passes it.
        overlay_upper: args.overlay_upper.map(str::to_string).or_else(|| {
            args.keep
                .then(|| crate::keepbox::dir_of(name.as_str()))
                .flatten()
                .map(|d| d.to_string_lossy().into_owned())
        }),
        memory,
        shm_size: args.shm_size,
        memory_swap_max: args.memory_swap_max,
        cpus,
        cpuset,
        vgpio_devs,
        vgpio_sysfs,
        gpu_sysfs,
        gpu_enumeration,
        // A GPU GRANT REBUILDS THE BOX'S LOADER CACHE, as docker's and podman's NVIDIA hook does
        // (see `kern_isolation`'s `refresh_loader_cache` for the measurement and the confinement).
        refresh_ldcache: gpu_for_identity.is_some() || wsl_pending.is_some(),
        ldconfig_dirs: gpu_for_identity
            .as_ref()
            .filter(|(grant, _)| grant.at_host_paths)
            .map(|(grant, _)| {
                grant
                    .ldconfig_dirs
                    .iter()
                    .map(|d| d.to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default(),
        idmap_binds,
        socket_binds,
        no_new_privs,
        vdisks,
        secrets,
        ssh,
        hostname,
        tun: args.tun,
        init: args.init,
        tmpfs,
        run_as,
        extra_gids,
        keep_groups,
        pids_max: args.pids_limit,
        caps,
        io_max: vdisk_io_max,
        io_weight: args.io_weight,
        extra_hosts: {
            let mut h = joined.as_ref().map(|j| j.hosts.clone()).unwrap_or_default();
            h.extend(resolve_add_hosts(args.add_hosts, args.share_net));
            h
        },
        // The box's own servers win; the pod's are the FALLBACK for a box that only added a search
        // domain or an option. An empty result means neither existed, and the box then gets no
        // nameserver line at all, which is the same as it had before it asked.
        memory_low: args.memory_reservation,
        cpu_weight: args.cpu_weight,
        dns: if args.dns.is_empty() {
            inherited_nameservers
        } else {
            args.dns.to_vec()
        },
        dns_search: args.dns_search.to_vec(),
        dns_options: args.dns_options.to_vec(),
        ulimits: args.ulimits.to_vec(),
        sysctls: args.sysctls.to_vec(),
    })?;

    if args.tty && args.detached {
        return Err(Error::Sandbox(
            "-it can't combine with -d - a detached box has no terminal to attach".to_string(),
        ));
    }
    // `--restart always|unless-stopped` (detached): hand supervision to the user's systemd instead of
    // kern's in-process supervisor - the box then restarts on ANY exit and survives reboot, with no
    // kern daemon. The generated unit re-runs THIS invocation in the foreground; the pull+mount we
    // just did warmed the image cache, so systemd's start is fast. We tear down this launcher's
    // scratch (the managed run makes its own) and return. Not reached in the managed run itself
    // (the unit strips `-d`, so `args.detached` is false there).
    // A pod member is excluded (`args.pod.is_none()`): it takes the in-process `restart_always` path
    // instead, because a systemd unit that outlives the pod holder could not re-join its namespace. And
    // a systemd-LESS host (`!user_systemd_present()`) also falls through, to the in-process supervisor
    // below - so `--restart always` works there too, just without reboot-survival.
    if systemd_supervises {
        for h in &ext4_handles {
            h.teardown();
        }
        for h in &net_volumes {
            h.teardown();
        }
        cleanup_scratch(scratch.as_deref());
        let _ = std::fs::remove_dir_all(&vdisk_work);
        // Release the start-claim BEFORE `systemctl enable --now`: the unit's own `kern box` run
        // claims the same name, and this launcher (still alive) holding it would fail the unit's
        // FIRST start with 'already starting' - systemd would only succeed on the 1s restart retry,
        // making every `--restart` install flaky. From here the unit is the name's owner.
        drop(name_claim);
        return install_persistent_box(
            &name,
            args.restart,
            args.memory,
            args.memory_swap_max,
            cpus,
            args.pids_limit,
        );
    }
    // Each box records the named volumes it mounts (below, in the registry) BEFORE it mounts them, so
    // `kern volume rm` sees an in-use volume and refuses - race-free without holding an fd open on the
    // volume dir (which would disturb the sandbox's mount setup).
    let mounted_vols = mounted_named_volumes(args.volumes);
    if standalone_persistent && !systemd_supervises {
        // Fell through the systemd branch above because no `systemd --user` manager is reachable. The
        // box still runs and restarts on any exit (in-process, via `restart_always` above); it just does
        // not survive a reboot. Say so once, and name the way to get reboot-survival.
        eprintln!(
            "kern: note: no `systemd --user` manager here, so --restart is supervised in-process \
             (restarts on any exit while kern runs, but does NOT survive a reboot). For reboot-survival, \
             enable a systemd --user manager, or generate a unit with `kern compose <file> systemd`."
        );
    }
    // ONE HealthConfig FOR BOTH PATHS, built before the branch that chooses between them. It used to
    // be constructed inline for `run_detached` and field-by-field again for the foreground checker,
    // which is exactly how the same flag comes to mean two things depending on how the box was
    // started - the defect this branch exists to fix, in miniature.
    // THE IMAGE'S OWN `HEALTHCHECK` IS A DEFAULT, exactly as its `ENTRYPOINT` and `Cmd` are.
    //
    // Docker runs the check an image ships whether or not the compose file mentions one, and
    // `depends_on: {condition: service_healthy}` waits on precisely that. kern read only what the
    // caller passed, so a service built on an image with a `HEALTHCHECK` reported `HEALTH = "-"`
    // forever and a dependency waiting on it either hung or was let through against a service that
    // was not ready. `nginx`, `postgres`, `redis` and `traefik` images all ship one.
    //
    // A TYPED FLAG ALWAYS WINS, and every field falls back independently: a file that sets only
    // `interval:` keeps the image's command, which is what a partial override means.
    // ALL OR NOTHING, which is what Docker does and what the flags allow us to know.
    //
    // A caller who passes `--health-cmd` owns the whole check: their command with their (or kern's
    // default) numbers, and the image's is ignored - Compose's `healthcheck.test` REPLACES the
    // image's rather than merging with it. A caller who passes none gets the image's check entire.
    //
    // FIELD-BY-FIELD FALLBACK IS NOT EXPRESSIBLE HERE and pretending otherwise would be a guess: the
    // numeric flags carry kern's defaults already baked in (`--health-interval` is 30 whether or not
    // anyone typed it), so "did the caller choose this?" has no answer at this point. An all-or-
    // nothing rule needs only a question that can be answered.
    // THE IMAGE'S `STOPSIGNAL` IS A DEFAULT TOO, and for the same reason as its healthcheck: Docker
    // stops a container with the signal its image asked for. nginx wants `SIGQUIT` (a graceful
    // drain), apache wants `SIGWINCH`; sent `SIGTERM`, both cut live connections instead of
    // finishing them, which looks like a flaky proxy and never like a missing signal.
    //
    // AN EXPLICIT FLAG WINS EVEN WHEN IT NAMES `SIGTERM`, which is why the flag is an `Option`: with
    // the default folded in as a value, honouring the image would have meant overriding somebody's
    // deliberate choice, and keeping the flag would have meant never honouring the image.
    let stop_signal = resolve_stop_signal(args.stop_signal, image_config.stop_signal.as_deref());
    let flag_probe = flag_health_probe(args.health_cmd, args.health_cmd_argv);
    let img_health = image_health_defaults(image_config.healthcheck.as_ref(), flag_probe.as_ref());
    let health_cfg = HealthConfig {
        probe: flag_probe.or(img_health.probe),
        interval: img_health.interval.unwrap_or(args.health_interval),
        retries: img_health.retries.unwrap_or(args.health_retries),
        start_period: img_health.start_period.unwrap_or(args.health_start_period),
        // Same fallback shape as every other number here: the image's value when the caller named no
        // probe of their own, otherwise the flag (which compose sets from `healthcheck.start_interval`).
        // `0` on both sides means "nobody asked", and the steady interval governs from the first probe,
        // which is exactly what kern did before this field existed.
        start_interval: img_health
            .start_interval
            .unwrap_or(args.health_start_interval),
        timeout: img_health.timeout.unwrap_or(args.health_timeout),
        action: health_action,
    };
    // SAID ONCE, WHERE THE EFFECTIVE PROBE IS KNOWN. A warning and not a refusal: the file is valid,
    // the box runs, and the operator may well be about to bind the tool in. What it must not do is
    // run and report `unhealthy` with nothing naming the cause. See `health_probe_driver_tool` for
    // the measurement and for why the remedies below are the two that were RUN.
    if let Some(tool) = health_probe_driver_tool(health_cfg.probe.as_ref()) {
        if let Some(why) = health_tool_absence(&tool, granted_tools.as_deref()) {
            eprintln!(
                "kern: warning: box '{name}': the healthcheck runs `{tool}`, {why}. The probe can \
                 never pass, so this box stays `unhealthy` for its whole life and a compose \
                 `service_healthy` gate on it never opens.",
                name = name.as_str()
            );
        }
    }
    // ONE POLICY OBJECT, BUILT ONCE, and computed BEFORE the branch so the detached path and the
    // systemd-managed path cannot bound their logs differently. `LogCap::default()` is what every
    // box had before the flags existed, so an unset flag changes nothing.
    //
    // The box's own flag first, then `[kern] log_max_size` / `log_max_file`, then kern's default:
    // Docker's order (`--log-opt` over `daemon.json` over the built-in). A `kern.toml` that does not
    // parse leaves the built-in in force rather than failing a box over its log.
    let log_cap = crate::commands::boxlog::LogCap {
        streams: args.log_streams,
        ..crate::commands::boxlog::LogCap::resolve(
            args.log_max_size,
            args.log_max_file,
            !args.log_none,
        )
    };
    // THE RECORD IS WRITTEN HERE: past every argument-coherence refusal and immediately before the
    // box is launched.
    //
    // BEFORE THE LAUNCH, because a box that fails to START is still one the operator will want to
    // start again after fixing what refused it (a missing mount source, a uid map, a seccomp
    // filter): those are the runtime refusals, and they happen below this line.
    //
    // AFTER THE FLAG CHECKS, because a refusal about the COMMAND LINE can never be fixed by
    // replaying that same command line. MEASURED: `kern box bad1 --image alpine --keep -it -d`
    // failed on "-it can't combine with -d" - a refusal 600 lines after the record was written - and
    // left a `ps -a` row and a directory for a box that had never existed and could never start.
    if let Some((dir, argv, created)) = keep_record.as_ref() {
        let meta = crate::keepbox::Meta {
            created: *created,
            last_exit: None,
            // Not recorded: `kern ps -a` derives it from the argv (`keepbox::image_of`), so the row
            // and the replay read one source.
            image: String::new(),
            cwd: std::env::current_dir()
                .map(|d| d.to_string_lossy().into_owned())
                .unwrap_or_default(),
        };
        // A record that cannot be written is a `kern start` that would not work, so it is the box's
        // problem and not a note: the operator asked for a box they can start again.
        crate::keepbox::write(dir, argv, &meta).map_err(|e| {
            Error::Sandbox(format!(
                "--keep: cannot record this box so `kern start {}` can run it again ({}): {e}",
                name.as_str(),
                dir.display()
            ))
        })?;
    }
    if args.detached {
        let egress_plan = EgressPlan::from_args(&args)?;
        return run_detached(
            &name,
            args.rm,
            spec,
            scratch,
            ports,
            &mounted_vols,
            &pod_label,
            restart,
            restart_always,
            health_cfg,
            args.timeout,
            &registry::encode_labels(args.labels),
            stop_signal,
            args.stop_grace,
            args.restart_max,
            args.def_hash,
            log_cap,
            args.image.unwrap_or(""),
            args.gpus.unwrap_or(""),
            args.pod.filter(|_| args.stack_outbound),
            egress_plan,
        );
    }
    // Foreground/interactive: print the status panel - but only when stderr is a real terminal, so
    // it stays out of pipes, scripts and `kern logs`. stderr (not stdout) keeps the box's own
    // stdout clean. Printed once: when a systemd scope re-execs us, only the inner process (which
    // actually reaches here) prints.
    if !args.quiet && !managed {
        print_box_status(&args, cpus);
    }
    if args.tty {
        // Release the start-claim: `run_box_interactive` leaves via `process::exit` (raw-terminal
        // teardown), which skips Drop - holding it here would leak one stale claim file per `-it`
        // session. An interactive box never registers, so duplicate `-it` names stay allowed,
        // exactly as before the claim existed.
        drop(name_claim);
        return run_box_interactive(spec, scratch, ports, args.timeout);
    }
    // A persistent box (`--restart always`) is started by systemd in the foreground - systemd is the
    // supervisor. Send its output to the per-box log and register it so `kern ps`/`logs`/`stop` still
    // see it; below we re-register with PID 1 once it's up (so `kern exec` works) and unregister on exit.
    // Register EVERY foreground box (Docker-parity: `kern ps`/`stop`/`volume rm` all see it), and
    // unregister on exit below. Registering here - before the box binds its named volumes inside the
    // sandbox - makes `volume rm`'s in-use check race-free. A *managed* (persistent, systemd-unit) box
    // also redirects its stdio to a per-box log; a plain foreground box keeps its terminal. The entry
    // is removed on clean exit; a crash/kill leaves it, but `registry::list()` prunes it by start-time.
    // THE REGISTRY KEY, COMPUTED ONCE. The entry below, the health checker armed further down and the
    // teardown that clears its status must all agree on which pid the box is filed under. Reading
    // `std::process::id()` at each of the three sites made that agreement a coincidence; one binding
    // makes it structural.
    let launcher_pid = std::process::id() as i32;
    let mut reg_state = {
        let pid = launcher_pid;
        if managed {
            let log = registry::logs_dir()
                .ok()
                .map(|d| d.join(format!("{}-{}.log", name.as_str(), pid)));
            detach_stdio(log.as_deref(), log_cap);
            // `[kern] log_keep_ended`: a new log is being made, so the old ones are bounded now.
            let _ = registry::expire_ended_logs();
        }
        let (cap_drop_all, cap_drops, cap_adds) = registry::cap_fields(&spec.caps);
        let inst = registry::Instance {
            name: name.as_str().to_string(),
            pid,
            pid1_recorded: 0,
            pid1_starttime: 0,
            rootfs: spec.root.clone(),
            command: crate::registry::command_line(&spec.command),
            started: registry::now_unix(),
            starttime: registry::proc_starttime(pid),
            ports: ports_summary(ports),
            volumes: mounted_vols.clone(),
            pod: pod_label.clone(),
            workdir: spec.workdir.clone().unwrap_or_default(),
            run_as: spec.run_as,
            extra_gids: spec.extra_gids.clone(),
            egress: if args.egress_deny.is_empty() {
                args.egress_allow.join(",")
            } else {
                format!(
                    "{} deny {}",
                    args.egress_allow.join(","),
                    args.egress_deny.join(",")
                )
            },
            bridges: registry::encode_bridges(&spec.pod_bridges),
            log_driver: if log_cap.keep {
                String::new()
            } else {
                "none".to_string()
            },
            landlock_rw: spec.landlock_rw.join(","),
            labels: registry::encode_labels(args.labels),
            stop_signal,
            stop_grace: args.stop_grace,
            def_hash: args.def_hash.to_string(),
            memory_max: spec.memory_max,
            pids_max: spec.pids_max,
            cap_drop_all,
            cap_drops,
            cap_adds,
            // Record the box's ACTUAL posture from the spec that built it, so `exec` reproduces it
            // instead of guessing: `seccomp_mode` is what PID 1 installs, `cap_recorded` marks this as
            // a box whose capability profile IS known, and the record is well-formed by construction.
            seccomp_mode: spec.seccomp_mode,
            no_new_privs: spec.effective_no_new_privs(),
            keep_groups: spec.keep_groups,
            image: args.image.unwrap_or("").to_string(),
            gpus: args.gpus.unwrap_or("").to_string(),
            timeout_s: args.timeout,
            apparmor: spec.apparmor.clone().unwrap_or_default(),
            cap_recorded: true,
            aa_recorded: true,
            seccomp_recorded: true,
            posture_corrupt: false,
            // Resolved and recorded in the `on_started` callback below, once PID 1 exists and its
            // dedicated cgroup can be read. Empty here (and for a box with no dedicated cgroup).
            cgroup: String::new(),
            cgroup_id: None,
            orphaned: false,
        };
        let path = registry::register(&inst).ok();
        // RECORDED ALONGSIDE THE ENTRY, because `kern exec` cannot read it back from the box: an
        // image whose workload runs as a non-root user owns `/proc/<pid1>/environ` as that user's
        // mapped uid, and reading it needs `CAP_SYS_PTRACE` in the box's user namespace, which the
        // box has dropped. See `registry::set_box_env`.
        registry::set_box_env(&inst.name, inst.pid, &spec.env);
        crate::runstats::record_box(); // count this box start for kern top's box-start rate
        Some((inst, path))
    };
    // Registered → the registry entry guards the name from here on; release the start-claim
    // explicitly (this foreground path leaves via `process::exit`, which skips Drop). The detached
    // path (`run_detached` above) instead drops it on `return` - after the supervisor has
    // registered (readiness is signalled post-register, and `await_box_started` waits for it).
    drop(name_claim);
    // Foreground: run the box (the runtime forks `-p` forwarders before the unshare and tears them
    // down when the box exits). `--timeout N`: arm a watchdog that SIGKILLs the box's PID 1 after N
    // seconds. The watchdog MUST be forked here - BEFORE `run_in_sandbox_with` makes the box's pid
    // namespace - so it lives in the host (ancestor) pid namespace; on the path where that namespace
    // is unshared just before the fork (`fork_into_cgroup`'s fallback), a process forked after it
    // would land INSIDE the box's namespace, where a non-init member can't signal the ns-init. It learns the box's PID 1 over a pipe (written by `on_started`). Skipped for a
    // managed box - a persistent box is meant to stay up; a timeout would just fight systemd's restart.
    let timeout_wd = (args.timeout > 0 && !managed)
        .then(|| spawn_foreground_timeout(args.timeout))
        .flatten();
    // `--health-cmd` ON THE FOREGROUND PATH TOO. It used to be armed only in `run_detached`, so a box
    // started without `-d` accepted the flag and never evaluated it: `kern ps` showed an empty HEALTH
    // column, with no warning and exit 0. That is not a corner of the CLI - `--restart
    // always`/`unless-stopped` installs a systemd unit whose `ExecStart` strips `-d` (`Type=simple`,
    // systemd is the supervisor), so EVERY persistent box runs here. A `kern compose` stack carrying
    // `restart:` under `--no-pod` therefore gated on a status nobody computed, and
    // `depends_on: condition: service_healthy` timed out with `last status: 'none yet'` while the
    // service underneath was up. Reported against v0.8.0.
    //
    // FORKED HERE, BEFORE `run_in_sandbox_with`, for the same reason the timeout watchdog above is: a
    // process forked after the box's pid namespace is unshared lands INSIDE it, where it
    // becomes an un-reapable zombie on box exit and deadlocks the namespace teardown. The checker does
    // not need PID 1 at fork time - it re-reads `pid1` from the registry each round, which is also how
    // it follows a `--restart` - so there is nothing to wait for.
    //
    // Keyed by THIS process's pid, the same value the entry above was registered under, so
    // `set_health` and `kern ps` agree on where the status lives.
    let health_wd = health_cfg
        .into_owned()
        .and_then(|hc| spawn_health_checker(name.as_str().to_string(), launcher_pid, hc));
    // Egress filter: spawn BOTH helpers NOW, while box_run is still in the HOST pid namespace (before
    // `run_in_sandbox_with` makes the box's). Spawning them from the `on_started` callback instead
    // could land them in the BOX pid namespace (box_run's `pid_for_children` is the box pidns by then
    // whenever the namespace was unshared before the fork, `fork_into_cgroup`'s fallback), where a helper becomes an un-reapable zombie on box exit and deadlocks the pidns teardown:
    // the box "runs, filters, then never exits" until `--timeout`. The pump does not know the box init
    // pid yet; it is delivered over a pipe in the callback below. The guard is held for the box's
    // lifetime; dropping it (after the box exits) SIGKILLs and reaps both helpers. Fail-CLOSED: on any
    // failure the box simply has no outbound.
    let mut egress_pending = EgressPlan::from_args(&args)?
        .as_ref()
        .and_then(EgressPlan::arm);
    let mut egress_guard: Option<crate::egress::EgressFilter> = None;
    // Set by the PID-1 callback when the egress pump could not be confirmed listening. Checked
    // after the sandbox call returns, because the callback cannot fail the start by itself.
    let mut egress_failed: Option<String> = None;
    pt.mark("parent:setup->spawn");
    // GARBAGE COLLECTION, DELIBERATELY AFTER THE SPAWN. Reaping cgroups left by boxes whose
    // supervisor was killed has nothing to do with starting THIS box, and doing it first cost 193 us
    // on every start (measured with 61 entries in the slice, 7.4% of a 2.6 ms box). Here it overlaps
    // the workload rather than delaying it, and the slice is still swept once per box start.
    kern_isolation::sweep_orphans_off_hot_path();
    // THE READINESS PIPE ON THE FOREGROUND PATH, acked at the TOP of this function (see there) and
    // only handed on here. `-d` builds its own (the launcher blocks on it to print a truthful
    // "started"), and this path had no reader, so it passed `None`. An SDK is a reader: it needs to
    // tell "the workload was slow" from "kern never reached `execvp`", and those are the same overrun
    // without this fd.
    let mut held_nat = args
        .pod
        .filter(|_| args.stack_outbound)
        .and_then(|p| HeldNat::arm(p, name.as_str()));
    // THE WORKLOAD WAITS FOR ITS FILTER: armed after `HeldNat`, which `--egress-allow` never meets
    // (it refuses `--pod`), so the two never compete for the one gate a box has.
    let mut egress_gate = egress_pending.as_ref().and_then(|_| EgressGate::arm());
    let result = run_in_sandbox_with(
        &spec,
        alive_fd,
        |pid1| {
            feed_timeout_pid(timeout_wd, pid1);
            if let Some((inst, path)) = reg_state.as_mut() {
                inst.record_pid1(pid1);
                // Record the box's DEDICATED cgroup PATH and its `(dev, ino)` IDENTITY now that PID 1
                // exists: `list()` uses them to tell an ORPHANED box (supervisor dead, cgroup still
                // populated) from an exited one WITHOUT a live pid, and to make the reap identity-safe
                // against a recycled-pid path collision. `("", None)` (no dedicated cgroup) leaves
                // liveness on the supervisor pid, exactly as before.
                (inst.cgroup, inst.cgroup_id) = registry::box_cgroup_record(pid1);
                if path.is_some() {
                    // The callback is `FnOnce(i32) -> ()`, so there is no channel to propagate on;
                    // report instead of discarding. This re-registration is what records the box's
                    // PID 1, and `kern exec` opens `/proc/<pid1>/ns/*`: with a stale `pid1` of 0 it
                    // fails with "box is not running (its namespaces are gone)" about a box that is
                    // running perfectly well.
                    if let Err(e) = registry::register(inst) {
                        eprintln!(
                            "kern: warning: could not record the box's PID 1 in the registry: {e} -                              `kern exec` on this box will not find it"
                        );
                    }
                }
            }
            // The launcher turns the recorded message into the box's own error. Delivered means the
            // pump listens in the box: only then does the workload pass its gate.
            if let Some(e) = deliver_egress(&mut egress_pending, &mut egress_guard, pid1) {
                egress_failed = Some(e);
            } else if let Some(gate) = egress_gate.as_mut() {
                gate.release();
            }
            if let Some(nat) = held_nat.as_mut() {
                nat.release(pid1);
            }
            // No terminal on this path, so nothing to swap: see `run_in_sandbox_with`'s `on_started`.
            None
        },
        None,
        ports,
        // Foreground box: tie its lifetime to the launcher via PDEATHSIG, so a hard-killed launcher
        // (SIGKILL/OOM) doesn't orphan the box until `--timeout`. NOT for a managed box - systemd is
        // its supervisor (KillMode=mixed tears it down); a PDEATHSIG relative to systemd is pointless.
        !managed,
    );
    drop(held_nat);
    drop(egress_gate);
    pt.mark("box lifetime (spawn->exit)");
    // THE EGRESS PUMP NEVER CAME UP, so the box we just ran had no outbound access at all, not
    // even to the domains the caller allowed. PID 1 was SIGKILLed in the callback; report the
    // cause here rather than let this surface as the workload's own exit code, which would say
    // nothing about `--egress-allow` and leave the reader chasing a `Connection refused`.
    if let Some(msg) = egress_failed.take() {
        return Err(Error::Sandbox(msg));
    }
    cancel_foreground_timeout(timeout_wd);
    // The box has exited: stop the checker and drop its status. This path leaves via `process::exit`,
    // which skips Drop, so an unstopped checker would outlive the box as an orphan - the shape the
    // `--timeout` watchdog was once found leaking in.
    stop_health_checker(health_wd, name.as_str(), launcher_pid);
    // The box has exited: SIGKILL the egress helpers NOW (this foreground path leaves via
    // `process::exit`, which skips Drop, so an implicit drop would leak the proxy + pump).
    drop(egress_guard);
    // Tear down any ext4-loop vdisks (unmount + detach loop + remove ephemeral image) and network
    // volumes (fusermount/gio -u) now the box is gone; then the scratch (which holds the images) is
    // removed.
    for h in &ext4_handles {
        h.teardown();
    }
    for h in &net_volumes {
        h.teardown();
    }
    cleanup_scratch(scratch.as_deref());
    let _ = std::fs::remove_dir_all(&vdisk_work);
    if let Some((_, Some(path))) = &reg_state {
        leave_registry(path);
    }
    // THE ENVIRONMENT SIDECAR GOES WITH THE BOX. `set_box_env` writes `env/<name>-<pid>` for every
    // box so `kern exec` and the healthcheck can read an environment they cannot get from
    // `/proc/<pid1>/environ` (unreadable once the box drops privilege). Only `stop` dropped it, so a
    // box that simply EXITED - which is every foreground box, and every SDK call - left the file
    // behind forever. MEASURED on 2026-09-20: 4433 files and 13 MB in that directory with zero boxes
    // alive, in tmpfs, so resident memory that never returns.
    //
    // Here rather than beside `set_box_env`'s other callers, because this is the one place every
    // foreground box passes through on its way out, next to the `unregister` that drops the instance
    // file for the same reason. `prune` sweeps the directory too, for the box whose supervisor was
    // killed before reaching this line.
    if let Some((_, Some(_))) = &reg_state {
        registry::clear_box_env(name.as_str(), launcher_pid);
    }
    registry::clear_box_dirs(name.as_str());
    pt.mark("parent:teardown");
    // CLOSE THE PROFILE, naming what the marks above do NOT cover. Every phase here is a delta
    // between two marks, so the sum describes only the span from the first mark onwards: the
    // binary's own startup and the argv parse happen before this timer exists, and anything between
    // two marks that nobody labelled is invisible by construction. Measured on 2026-09-20 that
    // remainder was about 1140 us of a ~3930 us `--image` box, 29%, and larger than every labelled
    // phase except the id mapping. A reader summing the marks would have concluded the box was
    // 2790 us and gone looking for savings inside the wrong ones.
    //
    // The total comes from `runstats`' process-entry stamp, which `kern run` already measures its
    // setup against, rather than a second clock read here that would drift from it.
    pt.summary("parent:accounted", crate::runstats::since_start_us());
    // THE BOX'S LINE IN THE HISTORY, from what kern observed outside it: see `history.rs`. Here,
    // after teardown and before the exit code is handed back, because this is the one place every
    // foreground box (every SDK and MCP call) passes on its way out with its outcome known.
    // EVERY ENDING GETS ITS LINE, a box kern could not start included: it is the `not-started`
    // outcome (kern's own 125). Writing only on success consumed a stop's claim and then wrote
    // nothing, so a stopped box whose launcher failed afterwards left no line at all.
    let code = *result.as_ref().unwrap_or(&125);
    let ran_ms = crate::runstats::since_start_us()
        .map_or(0, |us| u64::try_from(us / 1000).unwrap_or(u64::MAX));
    crate::history::record_owner_end(
        name.as_str(),
        launcher_pid,
        &crate::history::Observed {
            code,
            signal: kern_isolation::box_workload_signal(),
            oom: kern_isolation::box_was_oom_killed(),
            timeout_s: args.timeout,
            ran_ms,
            image: args.image.unwrap_or(""),
            gpu: args.gpus.unwrap_or(""),
        },
    );
    match result {
        // Propagate the sandboxed command's exit code as kern's, like `docker run`. This is the
        // one place a non-0/1 exit code is produced - a deliberate terminal action.
        Ok(code) => {
            // Deterministic "the box STARTED" signal for a caller (an SDK) on the fd read + FD_CLOEXEC'd
            // up front: kern reaches this arm only when its sandbox setup SUCCEEDED and the command ran
            // (including a command whose own execvp failed → 126/127, a real exit of a BUILT box), so a
            // reader that gets the byte knows the exit code is the workload's own, not a box that never
            // started - without parsing kern's stderr, which a workload can forge. The `Err` arm never
            // writes, so its EOF is an unforgeable "did not start". EINTR-safe: a lost byte would read as
            // EOF and mislabel a healthy box as startup_failed.
            // 125 IS "THE BOX DID NOT START", AND THIS ARM USED TO CLAIM THE OPPOSITE. The docstring
            // above says kern reaches `Ok` only when setup SUCCEEDED, and that was not true: a setup
            // failure inside the box's own namespaces (a mount the kernel refuses, a uid map, seccomp)
            // is reported by the child as exit 125 and arrives here as `Ok(125)`, so the unforgeable
            // "started" byte was written for a box that never existed.
            //
            // MEASURED end to end with `-v <fifo>:/x`: kern wrote `[1, 0]` and exited 125, and the
            // Python SDK - correctly trusting a signal kern documents as unforgeable - used it to
            // ERASE its own `startup_failed` classification, handing the caller `fault=None`. An agent
            // branching on `fault` reads that as its own code failing. The same erasure hit
            // `mount(volume bind) failed: Not a directory`, so this was never about one flag.
            //
            // WHY 125 IS THE RIGHT DISCRIMINATOR AND COSTS NOTHING. It is kern's own convention for
            // box-not-started (`box_start_exit_code`), and Docker's. A workload that CHOSE to exit 125
            // now gets no byte either, and that is harmless: with no byte the SDK falls back to its
            // stderr heuristic, which requires one of kern's own markers, and a workload's own 125
            // carries none - so it is classified exactly as it is today, a normal non-zero result.
            // The enforcement byte is lost in this case too, which is correct: there was no box to cap.
            if let Some(fd) = started_fd.filter(|_| code != 125) {
                // FOUR bytes, written atomically (a pipe write of <= PIPE_BUF is all-or-nothing):
                //   byte 0 = `1`, the unchanged "box started" signal - an SDK that reads only ONE byte
                //           (every 0.1.x binding) still sees exactly `0x01` and is unaffected;
                //   byte 1 = the memory-cap ENFORCEMENT signal (0 undetermined, 1 enforced, 2 requested
                //           but not enforced), so a NEWER SDK can tell an OOM against a real ceiling from
                //           a plain kill where the cap never bound. An OLDER kern wrote one byte, so a
                //           newer SDK reads EOF for byte 1 and treats enforcement as undetermined;
                //   byte 2 = the OOM OUTCOME (1 = the kernel's OOM killer fired against this box's OWN
                //           cgroup, 0 = it did not, or nothing was read);
                //   byte 3 = the SIGNAL that terminated the workload, or 0 if it exited on its own.
                //
                // WHY BYTE 3, and it is the same defect one level down. kern propagates the workload's
                // status as `128 + N`, so a workload the kernel SIGKILLed and a workload that called
                // `exit(137)` both leave kern exiting 137 normally: the origin is erased by the very
                // convention that makes the code useful. MEASURED through the Python binding: a cell
                // doing `sys.exit(137)` was reported `fault = killed` (an external kill that never
                // happened), and `sys.exit(159)` was reported `escape_blocked`, which is a security
                // event a cell can fabricate in one line. The exit code is the right thing to propagate
                // and the wrong thing to classify from, so the classifier gets the signal itself.
                //
                // WHY BYTE 2 EXISTS, and it is a correctness fix rather than a convenience. Enforcement
                // is not an outcome: byte 1 says a ceiling was in force, which every `kern stop` of a
                // capped box also satisfies. An SDK that read `SIGKILL + cap enforced` as "OOM" was
                // MEASURED reporting `kern stop` during a cell as `oom`, sending an agent to retry with
                // more memory a kill that had nothing to do with memory. The only honest source is the
                // kernel's own counter for the box's own cgroup, which kern already latches
                // (`latch_box_oom`) and prints on stderr. STDERR IS NOT ENOUGH: the workload writes to
                // the same stream, so a binding keying off the sentence accepts a forgery about the
                // box's own death. This byte carries the same observation where the workload cannot
                // reach it, and each byte stays ONE fact - overloading byte 1 with a value 3 would make
                // "was the cap enforced" a question with two right answers.
                let buf = [
                    1u8,
                    kern_isolation::memory_cap_signal(),
                    u8::from(kern_isolation::box_was_oom_killed()),
                    kern_isolation::box_workload_signal(),
                ];
                loop {
                    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
                    if n < 0
                        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    break;
                }
                let _ = unsafe { libc::close(fd) };
            }
            // A BOX KILLED BY ITS OWN CAP MUST NOT VANISH IN SILENCE.
            //
            // 137 is `128 + SIGKILL` and SIGKILL has many senders, so on its own it tells an operator
            // nothing. The counter read here is the BOX's own cgroup, so an increment names this box
            // exactly rather than reporting that something in a shared subtree was killed. `None`
            // whenever the directory is gone or the box never had a dedicated one, and `None` prints
            // nothing rather than guessing.
            if code == 128 + libc::SIGKILL {
                {
                    if kern_isolation::box_was_oom_killed() {
                        eprintln!(
                            "kern: the workload was killed by the kernel's OOM killer against this \
                             box's own memory cap. Raise it with `--memory <size>` (or `memory = \
                             \"<size>\"` in a vcpu: profile) if the workload needs more. \
                             {UNIFIED_MEMORY_NOTE}."
                        );
                    }
                }
            }
            // `--rm`: leave no exit record. AFTER THE FACT AND BEST EFFORT, the same shape (and the
            // same function) `compose run --rm` already uses, because a foreground box may not have
            // written one at all and the command's status is the workload's either way. Scoped to
            // this box's pod AND its name, so a foreign record is never touched.
            if args.rm {
                registry::clear_waitexit_pod(
                    &pod_label,
                    std::slice::from_ref(&args.name.to_string()),
                );
            }
            // A kept box remembers how its last run ended, which is what `kern ps -a` shows for it.
            // Best effort: a code that could not be recorded costs a column, not the box.
            if args.keep {
                if let Some(dir) = crate::keepbox::dir_of(name.as_str()) {
                    crate::keepbox::set_exit(&dir, code);
                }
            }
            std::process::exit(code)
        }
        Err(e) => Err(Error::Setup(e.to_string())), // genuine sandbox-start failure → userns hint
    }
}

/// `kern run [--memory M] [--cpus N] [--] <cmd...>` - run a command under cgroup CPU/memory caps
/// WITHOUT a sandbox. The resource-governor verb: it governs *resources*, not isolation (that's
/// `box`). It replaces this process with the command - no fork, no namespaces, no seccomp - so it's
/// the leanest possible path: a transient capped cgroup + `exec`. The command's exit code becomes
/// kern's, exactly like a bare exec.
pub fn run(
    command: &[String],
    memory: Option<u64>,
    memory_swap_max: Option<u64>,
    cpus: Option<f64>,
    cpuset: Option<&str>,
    config: Option<&str>,
    landlock_rw: &[String],
) -> Result<(), Error> {
    use std::os::unix::process::CommandExt;
    // AN INHERITED DIRECT-CAP-PATH MARKER IS THIS PROCESS'S PARENT'S DECISION, NOT ITS OWN.
    //
    // The marker is an env var, so it survives into everything kern execs - including the workload,
    // and so into a `kern` the workload runs. This verb now READS it (`took_direct_cap_path()` below
    // decides whether to fork and which leaf to build), which is what makes an inherited one harmful:
    // `KERN_NO_SCOPE=1 kern run` returns from the decision site before the marker is ever written, so
    // an inherited `1` would make this claim a direct path it never chose and cap through `kern.slice`
    // in the one mode whose documented meaning is that it does not. `kern box` scrubs at its own entry
    // for the same reason; `run` did not need to until it started reading the value.
    kern_isolation::scrub_direct_marker();
    // A FAST-FAIL on the write-allowlist, so a typo costs a message instead of a systemd scope and a
    // re-exec. This check is a convenience and is deliberately NOT the security decision: it stats a
    // path here, and the rule is bound to an fd opened later, so the two could in principle be
    // different objects (`O_NOFOLLOW` rejects a path that BECAME a symlink, but accepts one swapped for
    // a different real directory). The authoritative check lives in `landlock::add_path`, which opens
    // once and stats and binds that same fd, and refuses on this path when a named grant cannot be
    // bound. Both messages name the path; this one simply arrives sooner.
    for p in landlock_rw {
        let md = std::fs::symlink_metadata(p).map_err(|e| {
            Error::Cli(format!(
                "--landlock-rw '{p}': {e}. The grant is bound to a path that must already exist; \
                 create it first, or name one that does."
            ))
        })?;
        if md.file_type().is_symlink() {
            return Err(Error::Cli(format!(
                "--landlock-rw '{p}' is a symlink. Landlock binds the grant with O_NOFOLLOW, so a \
                 symlinked path would grant nothing and the command would run confined to nothing. \
                 Name the target path instead."
            )));
        }
    }
    // THE COMBINATION THAT FAILS LATE, INSIDE THE DRIVER, AND NAMES NOTHING.
    //
    // Measured on 2026-11-12: `kern run -- python3 gpu_work.py` computes on the card, and the same
    // command with `--landlock-rw /tmp` dies with `cuInit` 304, an OS-call error. The behaviour is
    // right (a write allowlist that does not name a device node does not grant write access to it,
    // and `run` has no mount namespace, so it cannot hand out `/dev` the way a box does), and
    // nothing here widens it. What is new is that the prediction is made BEFORE the exec instead of
    // arriving from CUDA with no mention of the flag that caused it.
    //
    // A WARNING AND NOT A REFUSAL: a caller who confines a non-GPU command on a GPU host asked for
    // exactly this, and pays one line. A caller whose workload needs the card would otherwise pay
    // the afternoon.
    // Fold any leading resource-profile tokens (`vcpu:name` …) into the caps - explicit flags win -
    // and find where the real command begins.
    let (cpus_flag, cpuset_flag) = (cpus.is_some(), cpuset.is_some());
    let mut ap = AppliedProfiles {
        memory,
        cpus,
        cpuset: cpuset.map(str::to_string),
        ..Default::default()
    };
    let start = peel_run_profiles(command, config, &mut ap)?;
    let AppliedProfiles {
        memory,
        cpus,
        cpuset,
        nice,
        vgpio,
        vdisk,
    } = ap;
    let command = &command[start..];
    if command.is_empty() {
        return Err(Error::Usage(
            "run [--memory M] [--cpus N] [--cpuset-cpus L] [--config F] [vcpu:PROFILE] [--] <cmd...>",
        ));
    }
    // Both notices below are emitted on the FIRST pass only. `run` re-execs itself through
    // `systemd-run --user --scope` to get an enforced cap and this code runs again on the way back,
    // so an unguarded `eprintln!` prints twice: the vdisk one did, for as long as it existed, and
    // `KERN_NO_SCOPE=1` was the only way to see it once. Same guard as the four other
    // first-pass-only checks in this file. The env vars are NOT guarded: the second pass is the one
    // that execs the workload, so it needs them set.
    //
    // Short-circuited on the profile lists so `var_os` (which returns an owned `OsString`, i.e. an
    // allocation) is not called on the common `kern run -- cmd` with no profile attached. The first
    // version of this line was unconditional and put a getenv plus an allocation on every run for a
    // message that could not be printed.
    let first_pass =
        (!vgpio.is_empty() || !vdisk.is_empty()) && crate::global_env("KERN_SCOPE").is_none();
    // `run` has no sandbox, so a `vgpio:` profile can't confine devices - instead export it as env
    // (`KERN_VGPIO_NAME`/`_PINS`), so a cooperative workload can find its pins. To
    // actually *isolate* the peripherals, use `kern box vgpio:NAME …`.
    if !vgpio.is_empty() {
        let names: Vec<&str> = vgpio.iter().map(|v| v.name.as_str()).collect();
        let pins: Vec<String> = vgpio
            .iter()
            .flat_map(|v| v.pins.iter())
            .map(u32::to_string)
            .collect();
        crate::set_global_env("KERN_VGPIO_NAME", names.join(","));
        crate::set_global_env("KERN_VGPIO_PINS", pins.join(","));
        // Say it, for the same reason the vdisk line below exists. `run` treats the two the same way
        // (neither can confine without a mount namespace) and used to report only one of them, so a
        // vgpio profile attached here looked like a device grant and was cooperative metadata. A
        // grant that silently grants nothing is the worst shape this can take.
        if first_pass {
            eprintln!(
                "kern: vgpio profile(s) under `run` export KERN_VGPIO_NAME/_PINS for a cooperative \
                 workload and confine nothing: `run` has no mount namespace, so the process sees \
                 the host's own /dev. Use `kern box vgpio:NAME …` for the device grant."
            );
        }
    }
    // A `vdisk:` needs a mount namespace to isolate - `run` has none. Say so rather than pretend.
    if !vdisk.is_empty() && first_pass {
        eprintln!(
            "kern: vdisk profile(s) ignored by `run` (no mount namespace) - use `kern box vdisk:NAME …`"
        );
    }
    // The confinement COMMITMENT, and why a second channel here is not the second transport it looks
    // like.
    //
    // `--landlock-rw` reaches the post-re-exec pass as argv, which is verbatim today (`env::args()`,
    // replayed unchanged - it used to pass through a recorded post-translation copy while kern still
    // answered to `docker`) and stays correct only as long as nothing ever rewrites, normalises or
    // reorders it. That is an invariant of the code, not of the type: the day
    // it breaks, an argv that LOST the flag is indistinguishable from one that never carried it, and
    // the difference between those two is a confined workload and an unconfined one. No test can
    // separate them after the fact, because a clean run and a lost-flag run look identical downstream.
    //
    // So make them distinguishable BEFORE the exec. The env below carries the PREDICATE (a confinement
    // was requested); the argv carries the CONTENT (which paths). They are asymmetric on purpose: they
    // never assert the same fact, so they cannot disagree in a way that needs adjudicating. Predicate
    // present with content missing is the impossible state, it is the exact signature of a lost
    // transport, and it aborts. Losing both across the same `execve` takes two independent bugs
    // instead of one, which is the whole of what a belt buys.
    //
    // Checked only under `KERN_SCOPE`, because that is the sole situation in which an `execve` sat
    // between the parse that saw the flag and this one. Elsewhere there is no transport to lose.
    if kern_common::env_flag("KERN_SCOPE")
        && kern_common::env_flag(LANDLOCK_REQUIRED_ENV)
        && landlock_rw.is_empty()
    {
        return Err(Error::Cli(
            "--landlock-rw was requested before the scope re-exec and did not survive it. Refusing \
             to run the command unconfined. This is a kern bug, not a usage error: please report it \
             with the exact command line."
                .into(),
        ));
    }
    // Authored here in BOTH directions, so the value the second pass reads is always one this pass
    // wrote and never one a user happened to have exported into the environment.
    if landlock_rw.is_empty() {
        crate::unset_global_env(LANDLOCK_REQUIRED_ENV);
    } else {
        crate::set_global_env(LANDLOCK_REQUIRED_ENV, "1");
    }
    // Robust caps via a transient systemd user scope whose MemoryMax/CPUQuota track the caps; this
    // re-execs once and returns here under KERN_SCOPE. Where systemd --user isn't present it's a
    // no-op and the best-effort in-process cgroup below applies the same caps.
    let cpus = check_cpus(cpus, cpu_source(cpus_flag))?;
    let cpuset = check_cpuset(cpuset, cpu_source(cpuset_flag))?;
    // THE SCOPE IS 88% OF `kern run`, AND IT IS NOT BUYING WHAT ITS COMMENT SAID IT WAS.
    //
    // MEASURED on this desktop, the shipped extreme binary, 200 samples each, medians:
    //
    //     kern run -- /bin/true                    4.700 ms
    //     KERN_NO_SCOPE=1 kern run -- /bin/true    0.577 ms
    //     systemd-run --user --scope -- /bin/true  3.867 ms
    //     kern box --rootfs … -- true              2.354 ms   (direct kern.slice path)
    //
    // so the transient scope costs 4.12 ms of a 4.70 ms `kern run` and is the entire reason the
    // GOVERNOR verb is twice as slow as the verb that builds a whole container. `kern box` skips it
    // through `kern.slice` and this verb was excluded from that by one `false`.
    //
    // The reason recorded for the `false` was that `kern run` "exec()s in place, so there is no
    // supervisor to drop the RAII guard and `rmdir` the leaf". That was true of the code it was
    // written against and has not been true since the scope re-exec grew its fork+proxy: measured by
    // walking `/proc/<pid>/stat` from inside the workload, a `kern run` today is `bash -> kern -> sh`,
    // with the original kern resident for the whole run as a signal-forwarding proxy. The process the
    // comment said did not exist is the one waiting on the workload.
    //
    // So the direct path is granted, and the fork that makes it legitimate is performed HERE rather
    // than assumed: see `run_forked_under_direct_caps` below. It is granted ONLY together with that
    // fork - on any path that still `exec()`s in place, `took_direct_cap_path()` is false and the
    // scope stays exactly as it was.
    // BOUND ONCE, READ THREE TIMES, for the reason the `forking` note below gives: one decision,
    // not three that happen to agree. Nothing between the three sites writes it, and the refusal
    // added to this function made it a third reader of an expression already written out twice.
    let allow_uncapped = kern_common::env_flag("KERN_ALLOW_UNCAPPED");
    reexec_in_scope_if_possible(ScopeReexec {
        memory,
        memory_swap_max,
        cpuset: cpuset.as_deref(),
        cpus,
        pids_max: None,
        allow_direct: true, // `kern run` forks its workload below, so it can hold the guard and clean up
        die_with_parent: false,
        allow_uncapped,
    });
    // THE CUDA WRITE-ALLOWLIST WARNING, said once, by the process that runs the command. Before the
    // re-exec above it was printed twice, once by the launcher and once by its copy in the scope:
    // MEASURED on a Jetson Orin Nano, every remedy path came out doubled. And only where Landlock
    // exists: elsewhere the command is refused below for that reason, which is the line to read.
    if !landlock_rw.is_empty() && kern_isolation::landlock_abi().is_some() {
        if let Ok(grant) = crate::gpu_grant::resolve() {
            let missing = crate::gpu_grant::cuda_write_paths_outside_allowlist(&grant, landlock_rw);
            if let Some(msg) = crate::gpu_grant::describe_cuda_write_paths(&missing) {
                eprintln!("kern: warning: {msg}");
            }
        }
    }
    // TWO INDEPENDENT DECISIONS, AND CONFLATING THEM IS WHAT LEFT A LEAK ON THE HOSTS THAT HAD IT.
    //
    // `direct` answers "may this relocate into kern's delegated `kern.slice`", which needs a systemd
    // user manager. `run_should_fork` answers "must this process leave a supervisor behind to reap the
    // workload and remove its leaf", which does NOT. The first version of this change used `direct`
    // for both, so it forked on exactly the hosts that never leaked (there the leaf lives inside the
    // transient scope and systemd reaps the whole unit) and left the leaking hosts untouched.
    //
    // MEASURED by a later pass, 2026-09-09, same binary, two hosts, 200 sequential `kern run`:
    //
    //     Ubuntu, systemd user manager present    0 leaves -> 200 runs -> 0 leaves
    //     WSL2 Alpine, no user manager            2 leaves -> 200 runs -> 201 leaves
    //
    // and the second is the configuration of the WSL rootfs this project publishes, so it was the
    // documented Windows install path that accumulated one directory per invocation. The same host
    // also lost the OOM diagnostic: with no process outliving the workload, a run killed by its own
    // 512 MiB default printed the shell's bare `Killed`.
    let direct = kern_isolation::took_direct_cap_path();
    // NOT `!direct`. Under `KERN_SCOPE` the outer scope proxy is already the surviving process: it
    // waits, forwards signals, reports the OOM and propagates the code, and `--collect` removes the
    // cgroup. Under `KERN_MANAGED` / `KERN_BUILD_STEP` an ancestor owns the workload for the same
    // reason. Forking under any of them adds a third process to the chain and buys none of it, which
    // is exactly the question `outer_enforcer_present` already answers for the cap path.
    let outer_enforcer = kern_isolation::outer_enforcer_present();
    // BOUND ONCE, READ THREE TIMES, for the reason the note below gives about `forking`: one
    // decision, not three that happen to agree. Nothing between the three sites writes this
    // variable, and the refusal added to this function made it a third reader of an expression that
    // was already written out twice.
    let allow_uncapped = kern_common::env_flag("KERN_ALLOW_UNCAPPED");
    // BOUND ONCE, USED THREE TIMES, because it is one decision and not three that happen to agree.
    // `cap_built` is `true` here because the two later uses are both inside `cg.is_some()`, and the
    // first one is what MAKES the cgroup: if none is built, the fork re-asks with the real value and
    // stays a single process. Writing the expression out at each site is the duplicated-derived-
    // condition shape that has already cost this project a divergence.
    let forking = run_should_fork(outer_enforcer, true);
    let cg = kern_isolation::apply_cgroup_limits(
        direct, // allow_direct: the kern.slice relocation, and nothing else
        // `kern run`'s leaf is NOT a box leaf, on ANY path, and the name is what keeps it out of
        // `kern ps` and out of reach of the sweep's `cgroup.kill`. See `kern_isolation::CgroupLeaf`.
        // It was `kern-box-run-<pid>` before, which mattered most on the no-manager path: there the
        // leaf is built in the CALLER's own cgroup, which `kern ps` scans, and a live `kern run` was
        // reported as a box with no registry record that `kern stop` could not reach.
        kern_isolation::CgroupLeaf::Run,
        memory,
        memory_swap_max,
        cpuset.as_deref(),
        cpus,
        None,  // `kern run` has no --pids-limit; box's pids cap is applied in the sandbox
        &[],   // no vdisk io limits in `kern run`
        None,  // no --io-weight in `kern run`
        None, // no --memory-reservation in `kern run`: the soft knobs are box-shaped (compose sets them)
        None, // no --cpu-weight in `kern run`, same reason
        false, // `kern run` is a cooperative governor, never fail-closed (best-effort gate)
        // supervisor_forks_workload: the SAME value the fork below acts on, so the two cannot drift.
        // `true` keeps this process OUT of the capped leaf so a whole-box OOM cannot take the process
        // that has to report it; `false` puts it IN, which is required where it `exec()`s in place.
        // Getting it wrong is not cosmetic: `true` without the fork runs the workload in the UNCAPPED
        // parent, which is the failure `apply_limits` documents against this very parameter.
        forking,
    );
    // For its RESOURCE CAPS `kern run` is a cooperative governor, not an isolation boundary - so unlike
    // `kern box` it does NOT fail-closed when a cap can't be applied. But make the drop VISIBLE, not
    // silent: if the user asked for a cap, no outer scope is enforcing it (`KERN_SCOPE` unset), and we
    // couldn't apply it (`cg` None), say so rather than let the workload quietly exceed it.
    //
    // `--landlock-rw` is the one thing on this verb that does NOT follow this policy: it is a
    // confinement, not a limit, and it refuses instead of warning. See the block just before the exec.
    if cg.is_none()
        && (memory.is_some() || cpus.is_some())
        && crate::global_env("KERN_SCOPE").is_none()
    {
        // FAIL CLOSED ON THE DIRECT PATH, exactly as `run_in_sandbox` does, and for the identical
        // reason: when kern DELIBERATELY skipped the per-command systemd scope, the leaf it builds
        // itself is the sole enforcer, so a `None` here means the cap the caller asked for binds
        // NOWHERE. This verb governs resources and nothing else; accepting `--memory` and executing
        // the command anyway is the one outcome it must not produce.
        //
        // MEASURED, and this is why it is a refusal and not a louder warning. 2026-10-09 20:20 on the
        // maintainer's own desktop: `kern run --memory 16m -- sh -c 's=…; while :; do s=$s$s; done'`
        // (a test's deliberately unbounded doubler, whose only brake is the cap). The leaf could not
        // be created on that run, kern printed the warning below and executed the command, the shell
        // grew to 25.5 GB in the cgroup it had inherited from the terminal, and the HOST's OOM killer
        // took the largest process on the machine - the editor, with every session in it. The warning
        // was printed and read by nobody, because the thing that would have read it was killed.
        //
        // GATED ON `--memory`, NOT ON WHICH PATH KERN TOOK. The first version of this refusal asked
        // `took_direct_cap_path()`, mirroring the box, and the positive control killed it: on the
        // maintainer's own delegated desktop that predicate is FALSE for this verb, so the refusal
        // would not have fired on the very incident it was written for. The condition that matters
        // is not how kern tried, it is that the caller NAMED a memory cap and nothing is holding it.
        //
        // `--cpus` alone does not qualify: an uncapped share makes a command slow, and slow does not
        // take a machine down. Memory does. The refusal stays tied to the harm that was measured.
        //
        // AND THE KERNEL IS ASKED BEFORE REFUSING, the same correction `mandatory_caps_in_force`
        // carries on the box path: `apply_limits` returning `None` says KERN wrote no cap, not that
        // the command is uncapped. Inside an already-capped cgroup (a container, a scope with
        // `MemoryMax=`) the ceiling binds without kern writing a byte, and refusing there would
        // break a host where the cap demonstrably works. `None` as the directory because this verb
        // `exec()`s the workload in place when it has no leaf of its own, so this process IS the
        // subject and `/proc/self/cgroup` is the right chain.
        //
        // A bare `kern run` with no `--memory` keeps today's best-effort behaviour and its notice,
        // and `KERN_ALLOW_UNCAPPED=1` runs anyway for a caller who means it.
        // PROVEN, not "not disproven": the first version of this asked the warn-oriented helper,
        // whose documented default is that an unreadable or unmodelled cgroup counts as capped. On a
        // root container reporting `0::/` that default skipped the refusal entirely and the command
        // ran uncapped, which is the defect this whole block exists to stop (reported from such a
        // host, measured, same day).
        let memory_unheld =
            memory.is_some_and(|m| !kern_isolation::memory_cap_proven_at_or_below(m));
        if memory_unheld && !allow_uncapped {
            return Err(Error::Sandbox(format!(
                "--memory was requested and nothing here enforces it: kern could not place this \
                 command in a cgroup that carries the cap ({}), and no ancestor cgroup holds it to \
                 that ceiling either. Refusing to run UNCAPPED, because a command that outgrows the \
                 cap it asked for takes the HOST down with it - measured on 2026-10-09, a shell that \
                 should have died at 16 MiB reached 25.5 GB and the kernel's OOM killer took the \
                 largest process on the machine instead. `kern doctor` names the one local change \
                 that would make a cap bind here; KERN_ALLOW_UNCAPPED=1 says an uncapped run is \
                 intended and runs it.",
                kern_isolation::missing_manager_clause()
            )));
        }
        // AND THE WARNING ANSWERS THE SAME QUESTION THE REFUSAL JUST ANSWERED. Reaching this line
        // with `--memory` means the ceiling WAS proven - that is the only way past the refusal above
        // without the opt-out - so saying "runs UNCAPPED" here is kern contradicting itself about
        // one command. MEASURED inside a cgroup namespace whose root carries `memory.max` 67108864,
        // the shape `docker run -m 64m` produces: `kern run --memory 64m` correctly declined to
        // refuse and then printed "the command runs UNCAPPED" over a command the kernel holds to
        // exactly 64 MiB. kern wrote no cgroup of its own, which is what this branch tests, and that
        // is not the same fact as the command being uncapped.
        //
        // Reaching this line with `--memory` means the ceiling WAS proven (the refusal above is the
        // only other way out), so `memory_unheld` is false and only `--cpus` can still want the
        // warning: nothing here proves a CPU ceiling, and an unenforced share is worth saying.
        if memory_unheld || cpus.is_some() {
            // THE CAUSE THIS PATH ALREADY MEASURED, not a fixed clause. Reading
            // "cgroup delegation unavailable" on a host whose delegation works perfectly - the real
            // cause there was an `XDG_RUNTIME_DIR` pointing away from the live manager, which the
            // `--memory` refusal names exactly and this line did not.
            eprintln!(
                "kern: warning: requested resource cap(s) could not be enforced here - {} - the \
                 command runs UNCAPPED.",
                kern_isolation::missing_manager_clause()
            );
        }
    } else if kern_common::env_flag("KERN_SCOPE") {
        // The branch above stays quiet under a scope because the scope is ASSUMED to enforce the
        // caps it was given. systemd accepts `MemoryMax=`/`CPUQuota=` that the kernel cannot honour
        // and reports nothing, so verify the effective chain rather than trusting the assumption.
        // `None`: `kern run` exec()s the workload IN PLACE, so this process IS the box and
        // `/proc/self/cgroup` is the right chain to read. The box path passes the box's cgroup
        // explicitly because its supervisor sits in a sibling leaf; here there is no supervisor.
        kern_isolation::warn_unenforced_caps(None, memory, cpus, None);
    } else if memory.is_none()
        && cpus.is_none()
        && !kern_common::env_flag("KERN_QUIET")
        && !allow_uncapped
        && !kern_isolation::memory_cap_in_force_at_or_below(
            // THE WORKLOAD'S CGROUP, NOT THIS PROCESS'S, WHEREVER THE TWO DIFFER.
            //
            // `will_fork` puts this process OUTSIDE the capped leaf on purpose, so that a whole-box
            // OOM cannot take the process that has to report it. A self-read then answers about a
            // cgroup that is uncapped BY CONSTRUCTION, and this branch would print "no RAM ceiling"
            // over a workload holding the exact 512 MiB default. It is the same correction
            // `warn_unenforced_caps` already carries one branch up, and it is why that one takes a
            // directory at all. `None` where this process IS the workload, which is every path that
            // still `exec()`s in place.
            cg.as_ref()
                .filter(|_| forking)
                .map(kern_isolation::CgroupGuard::box_dir),
            SCOPE_MEMORY_MAX_BYTES,
        )
    {
        // THE DEFAULT CAP, WHICH NOBODY TYPED AND WHICH BOTH BRANCHES ABOVE ARE BLIND TO.
        //
        // A plain `kern run` is not uncapped: the scope it re-execs into carries `MemoryMax=512M`,
        // `MemorySwapMax=0` and `TasksMax=512`, so a workload over that ceiling is OOM-killed and told
        // why. `KERN_NO_SCOPE=1` skips that scope, and with it the default goes too. Both branches
        // above are gated on a REQUEST (`memory.is_some() || cpus.is_some()`), so the case where
        // nothing was typed said nothing at all.
        //
        // MEASURED on this host, allocating 800 MiB under a 512 MiB default:
        //
        //   kern run                       killed, rc 137, with the OOM message
        //   KERN_NO_SCOPE=1 kern run       ran to completion, rc 0, and stderr was EMPTY
        //
        // and the process landed in whatever cgroup the caller happened to sit in, which on that run
        // was an unrelated desktop application's scope, with `memory.max`, `memory.swap.max` and
        // `pids.max` all at their host values.
        //
        // `kern box` already closed this exact gap on its own path, and its comment states the rule
        // this branch is applying: memory and pids ALWAYS carry a default, so accepting a cap, default
        // or requested, and enforcing nothing is the one thing this codebase does not do quietly. The
        // rule was stated for boxes and `kern run` was left out of it.
        //
        // VERIFIED against the cgroup rather than inferred from `cg` or from the absence of an env
        // var, for the same reason the sandbox path does it that way: the question is whether a cap is
        // in force, and only the cgroup answers that.
        //
        // THE CAUSE IS NAMED, NOT ASSUMED, and it used to be assumed. This branch is reached whenever
        // nothing was typed and nothing binds, and `KERN_NO_SCOPE` is only ONE of the ways to get
        // here: a host with no systemd user manager whose own cgroup cannot take a capped child
        // reaches it too, and so does one where the controllers are not delegated. The single message
        // told all of them "unset KERN_NO_SCOPE to get the default back", which on those hosts names
        // a variable the user never set and a remedy that changes nothing. An instruction that cannot
        // work is worse than no instruction, because it ends the reader's search at the wrong place.
        if kern_common::env_flag("KERN_NO_SCOPE") {
            eprintln!(
                "kern: warning: KERN_NO_SCOPE skipped the systemd scope, and with it kern's DEFAULT \
                 memory cap - this command runs with no RAM ceiling and no OOM backstop, in the \
                 cgroup of whatever started it. Unset KERN_NO_SCOPE to get the default back, pass an \
                 explicit `--memory <size>` (which REFUSES to run rather than go uncapped here), \
                 or set KERN_ALLOW_UNCAPPED=1 to say the uncapped run is intended and silence this."
            );
        } else {
            // The cause, not "which part is missing". The `--cpus` warning beside this one and the
            // `--memory` refusal below both name what this host measured; reading all three
            // in one session and this was the only one still sending them to go and find out.
            eprintln!(
                "kern: warning: this host could not give the command a memory cgroup, so kern's \
                 DEFAULT memory cap is not in force - it runs with no RAM ceiling and no OOM \
                 backstop, in the cgroup of whatever started it: {}. `kern doctor` shows the \
                 delegation state; an explicit `--memory <size>` REFUSES to run rather than go \
                 uncapped here, and KERN_ALLOW_UNCAPPED=1 says the uncapped run is intended and \
                 silences this.",
                kern_isolation::missing_manager_clause()
            );
        }
    }
    // A `memory.high` ABOVE THE WORKLOAD, the same check `kern box` makes at its start and for the same
    // measured reason: past that limit the kernel throttles instead of OOM-killing, so a command that
    // should die at its cap stalls instead (Jetson Orin, 2026-10-03: 317 s against 0.06 s). The
    // workload's cgroup is the one the default-cap branch above reads, for the reason it gives: where
    // this process forks, it sits OUTSIDE the capped leaf. A warning and never a refusal here,
    // because `kern run` treats its caps as a cooperative governor (see the top of this block).
    if !kern_common::env_flag("KERN_QUIET") {
        if let Some(outer) = kern_isolation::outer_memory_high_for_box(
            cg.as_ref()
                .filter(|_| forking)
                .map(kern_isolation::CgroupGuard::box_dir),
        ) {
            eprintln!("{}", outer.note_for("command"));
        }
    }
    // THE FORK - and past this line, on every path, this process is the workload's.
    //
    // Where it forks, this call returns ONLY in the child, which is inside the capped leaf; the
    // parent stays behind proxying signals, reaps the workload, drops the guard (which `rmdir`s the
    // leaf) and exits with the workload's code, so it never reaches any of the code below. Where an
    // outer enforcer already supervises the workload, or where no cap could be built at all, it is a
    // no-op and this process is still the one that will `exec`.
    //
    // Everything below therefore runs exactly once, in the process that becomes the workload, which is
    // what the affinity, the `nice`, the throughput counter and above all the Landlock ruleset require:
    // a ruleset applied in the parent would confine the proxy and not the command.
    let cg = fork_workload_under_caps(outer_enforcer, cg);
    // On the scope path this process `exec()`s the workload IN PLACE, so there is no supervisor left to
    // reap it and drop the guard afterwards. The guard's Drop would `rmdir` the cgroup we're about to
    // exec into, which is non-empty (we're in it) → EBUSY → a no-op anyway. Forget it so the intent is
    // explicit: we do NOT tear down our own live cgroup here. (Same as the pre-guard behaviour - the
    // `run` cgroup outlives this call; it's removed when the systemd scope is collected.) On the direct
    // path `cg` is already `None`: the parent kept the guard, and forgetting a guard the CHILD holds
    // would be the leak, not the fix.
    std::mem::forget(cg);
    // Pin CPUs via affinity (works with no cgroup cpuset delegation), and apply a profile's `nice`.
    kern_isolation::set_cpu_affinity(cpuset.as_deref());
    if let Some(n) = nice {
        apply_nice(n);
    }
    // Bump the daemonless run-throughput counter (one atomic on a shared mmap) so `kern top` can show
    // live runs/sec - done here, in the final process that actually runs the workload (past any
    // scope re-exec), so each `kern run` counts exactly once. Best-effort: never fails the run.
    crate::runstats::record();
    // The write-allowlist, applied LAST: after the scope re-exec (a ruleset applied before it would be
    // inherited by `systemd-run`, which needs to write the user bus socket under /run/user/$UID that
    // HOST_AUTO_RW deliberately does not grant, and the scope would fail) and immediately before
    // `execve`, which the ruleset survives. Nothing of the workload has run at this point, so it never
    // holds a pre-opened writable fd to a denied path.
    //
    // This FAILS CLOSED, unlike every resource cap above it. That divergence is deliberate: a cap that
    // cannot be applied leaves the workload running without a limit, which `run` states plainly and
    // accepts because it is a cooperative governor. A confinement that cannot be applied leaves the
    // workload running with the operator's files reachable while the operator believes they are not.
    // The `vgpio` branch earlier in this function names that shape "the worst this can take"; refusing
    // is the only answer that keeps the flag's promise honest on a host where it cannot be kept.
    if !landlock_rw.is_empty() {
        match kern_isolation::landlock_confine_writes(landlock_rw) {
            Ok(true) => {}
            Ok(false) => return Err(Error::Cli(
                "--landlock-rw: this kernel has no Landlock (needs Linux 5.13+, and it must not \
                     be disabled at boot). Refusing to run the command unconfined - check with \
                     `kern doctor`."
                    .into(),
            )),
            Err(e) => {
                return Err(Error::Cli(format!(
                    "--landlock-rw: could not enforce the write allowlist ({e}). Refusing to run \
                     the command unconfined."
                )))
            }
        }
    }
    // exec() replaces this process with the command (which inherits the cgroup) and only returns on
    // failure - so a successful run propagates the command's own exit code as kern's.
    let err = std::process::Command::new(&command[0])
        .args(&command[1..])
        .exec();
    // `kern run` is the resource governor - there is NO sandbox here - so don't wrap this in the
    // "sandbox: …" error. Print a plain command-not-found message with a fitting hint and exit 127
    // (the conventional "command not found" code), mirroring the box path's exec-failure handling.
    eprintln!("kern: cannot run '{}': {err}", command[0]);
    eprintln!("hint: the command must exist and be executable (an absolute path, or on $PATH)");
    std::process::exit(127);
}

/// Why host port `hp` cannot be published, naming the holder when kern can see it: a kern box (from
/// the registry), a process of this user listening on it (from `/proc`), or neither, said as such.
/// One function for `kern box` and for `compose up`'s check before the first service starts.
pub(crate) fn publish_refusal(
    hp: u16,
    e: &std::io::Error,
    ports: &[kern_isolation::PortMap],
) -> Error {
    // Tell the two failures apart. `EACCES` on a port <1024 is NOT "in use": rootless kern lacks
    // CAP_NET_BIND_SERVICE, so the fix is a higher port - sending the user to `kern ps`/`kern stop`
    // would chase a phantom holder (the old message did). `EADDRINUSE` (or any other errno) IS the
    // taken-port case, where AlreadyRunning's "run `kern ps` … `kern stop`" hint fits.
    if e.raw_os_error() == Some(libc::EACCES) && hp < unprivileged_port_start() {
        let start = unprivileged_port_start();
        return Error::Sandbox(format!(
            "cannot publish port {hp}: this host lets an unprivileged process bind from {start} \
             upward (net.ipv4.ip_unprivileged_port_start) and kern is rootless, so it lacks the \
             CAP_NET_BIND_SERVICE a lower port needs. Publish it on a host port >={start} \
             instead (e.g. -p 8080:80), or have the machine's owner lower that sysctl"
        ));
    }
    // NAME THE HOLDER WHEN KERN CAN. The registry records every running box's published ports,
    // so "another box, or a non-kern process" is a shrug in the one case kern can answer: two
    // stacks competing for a port is the commonest way this fires, and "which one" is the whole
    // question. MEASURED on two projects publishing 18099: the message named the port and left
    // the reader to find the holder with `kern ps` and their own eyes.
    //
    // STILL A SHRUG WHEN IT HAS TO BE. A port held by something that is not a kern box - another
    // runtime, a dev server, systemd - is invisible from here, and claiming otherwise would be
    // worse than the shrug. The two cases get two different sentences.
    let holder = registry_holder(hp);
    // NOT A TAKEN PORT AT ALL: the host has no such address. Said as what it is, because "held by
    // something else, `ss -ltnp` names it" sent the reader after a process that does not exist.
    // MEASURED on a VPS whose loopback has IPv6 disabled: `-p [::1]:18202:80` answered exactly
    // that. Docker refuses the same spec there ("cannot assign requested address").
    if e.raw_os_error() == Some(libc::EADDRNOTAVAIL) {
        let asked: Vec<String> = ports
            .iter()
            .filter(|p| p.host == hp)
            .map(crate::ports::host_side)
            .collect();
        return Error::Sandbox(format!(
            "cannot publish {}: {e} - this host has no such address to listen on (an IPv6 \
             address where IPv6 is disabled on that interface, or an address of another \
             machine); publish it on an address the host has, or without an address",
            asked.join(", ")
        ));
    }
    Error::AlreadyRunning(match holder {
        Some(b) if b.pod.is_empty() => format!(
            "cannot publish host port {hp}: {e} - box '{}' is already publishing it. \
             `kern stop {}` frees it, or publish this one on another port",
            b.name, b.name
        ),
        Some(b) => format!(
            "cannot publish host port {hp}: {e} - service '{}' of stack '{}' is already \
             publishing it. Take that stack down, or publish this one on another port",
            crate::ui::display_box_name(&b.name, &b.pod),
            b.pod
        ),
        None => match local_listener(hp) {
            Some((pid, comm)) => format!(
                "cannot publish host port {hp}: {e} - no running kern box is publishing it: process \
                 {pid} ({comm}) is listening on it. Stop it, or publish this one on another port \
                 (`ss -ltnp | grep :{hp}` shows it)"
            ),
            None => format!(
                "cannot publish host port {hp}: {e} - and no running kern box is publishing it, \
                 so it is held by {}. `ss -ltnp | grep :{hp}` names it when it is visible",
                unseen_holder()
            ),
        },
    })
}

/// The running kern box publishing host port `hp`, read from the registry with the one parser of a
/// recorded port list.
fn registry_holder(hp: u16) -> Option<crate::registry::Instance> {
    crate::registry::list().into_iter().find(|b| {
        crate::ports::parse_display_list(&b.ports)
            .iter()
            .any(|m| m.host == hp)
    })
}

/// What holds a port when it is not a kern box and no process of this user listens on it.
fn unseen_holder() -> &'static str {
    let wsl = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .is_ok_and(|r| r.to_ascii_lowercase().contains("microsoft"));
    if wsl {
        "something kern cannot see from here: under WSL most often a Windows program (Docker \
         Desktop's com.docker.backend, a node.exe dev server, wslrelay), or another user's process"
    } else {
        "something else on this machine that kern cannot see (another user's process, another \
         runtime, a systemd unit)"
    }
}

/// Who holds host port `hp`, in a few words, for the stack-wide refusal.
fn holder_of(hp: u16, e: &std::io::Error) -> String {
    if e.raw_os_error() == Some(libc::EADDRNOTAVAIL) {
        return format!("not an address this host has ({e})");
    }
    if let Some(b) = registry_holder(hp) {
        return if b.pod.is_empty() {
            format!("kern box '{}'", b.name)
        } else {
            format!(
                "service '{}' of kern stack '{}'",
                crate::ui::display_box_name(&b.name, &b.pod),
                b.pod
            )
        };
    }
    match local_listener(hp) {
        Some((pid, comm)) => format!("{comm} (pid {pid})"),
        None => unseen_holder().to_string(),
    }
}

/// The process of this user listening on TCP port `port`, from `/proc/net/tcp{,6}` and the socket
/// links under `/proc/<pid>/fd`. `None` when the socket is not found or belongs to a process this
/// user cannot read, which is every process of another user and, under WSL, every Windows one.
fn local_listener(port: u16) -> Option<(u32, String)> {
    let want = format!(":{port:04X}");
    let mut inodes: Vec<String> = Vec::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(table) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            // local_address, rem_address, st (0A = LISTEN), ..., inode at index 9.
            if f.len() > 9 && f[1].ends_with(&want) && f[3] == "0A" && f[9] != "0" {
                inodes.push(format!("socket:[{}]", f[9]));
            }
        }
    }
    if inodes.is_empty() {
        return None;
    }
    let procs = std::fs::read_dir("/proc").ok()?;
    for entry in procs.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            if inodes.iter().any(|i| target.as_os_str() == i.as_str()) {
                let comm = std::fs::read_to_string(entry.path().join("comm"))
                    .map(|c| c.trim().to_string())
                    .unwrap_or_default();
                return Some((pid, comm));
            }
        }
    }
    None
}

/// `compose up`'s port check, BEFORE any service starts: every host port the stack publishes must
/// be free, except the ones a box of this same stack already publishes (an `up` on a running stack
/// recreates or keeps those). MEASURED on 2026-11-18: a port held by a dev server let the first
/// service start and refused the second, leaving the stack half up.
///
/// Privileged ports are left to the box's own path, which can move them under the publish policy;
/// so are the implicit IPv6 twins, which a box drops where they cannot bind.
pub(crate) fn preflight_stack_ports(
    boxes: &[crate::compose::ComposeBox],
    project: &str,
) -> Result<(), Error> {
    let floor = unprivileged_port_start();
    let own: Vec<u16> = crate::registry::list()
        .into_iter()
        .filter(|b| b.pod == project)
        .flat_map(|b| {
            crate::ports::parse_display_list(&b.ports)
                .into_iter()
                .map(|m| m.host)
        })
        .collect();
    // Every busy port of every service, so one run names them all: fixing them one `up` at a time
    // is what the reader was doing.
    let mut busy: Vec<(u16, bool, String, String)> = Vec::new();
    for b in boxes {
        let mut maps: Vec<kern_isolation::PortMap> = b
            .ports
            .iter()
            .filter_map(|spec| crate::ports::parse(spec))
            .flatten()
            .filter(|m| m.host != 0 && m.host >= floor && !own.contains(&m.host))
            .collect();
        drop_unbindable_twins(&mut maps, kern_isolation::address_is_bindable);
        for m in &maps {
            if busy
                .iter()
                .any(|(p, udp, _, _)| *p == m.host && *udp == m.udp)
            {
                continue;
            }
            if let Err((hp, e)) = kern_isolation::preflight_ports(std::slice::from_ref(m)) {
                busy.push((hp, m.udp, b.service_name().to_string(), holder_of(hp, &e)));
            }
        }
    }
    if busy.is_empty() {
        return Ok(());
    }
    let mut msg = format!(
        "{} host port(s) already in use, so no service was started:",
        busy.len()
    );
    for (port, udp, service, holder) in &busy {
        let proto = if *udp { "udp" } else { "tcp" };
        msg.push_str(&format!(
            "\n  {port}/{proto}  service {service}  held by {holder}"
        ));
    }
    msg.push_str(
        "\nfix one of: stop what holds them, or publish those services on other host ports in the \
         file (or in the variable the file reads them from). kern never moves a port by itself: the \
         address you open would answer nothing",
    );
    Err(Error::Compose(msg))
}

/// Give every mapping whose host port is 0 (`-p 80`, `-p ip::80`, `-p 0:80`, compose `"80"`) a port
/// the kernel picked, ONE NUMBER FOR A DEFAULT BIND'S TWO FAMILIES (the IPv4 map and its implicit
/// IPv6 twin with the same box port and protocol), as Docker does. Done before the preflight and the
/// registry, so `kern ps`, `kern port` and `compose port` read the real number.
fn assign_picked_ports(ports: &mut [kern_isolation::PortMap]) -> Result<(), Error> {
    for i in 0..ports.len() {
        let Some(p) = ports.get(i).copied() else {
            continue;
        };
        if p.host != 0 || p.implicit {
            continue;
        }
        let twins: Vec<usize> = (0..ports.len())
            .filter(|&j| {
                ports.get(j).is_some_and(|t| {
                    t.implicit && t.host == 0 && t.box_port == p.box_port && t.udp == p.udp
                })
            })
            .collect();
        let also: Vec<std::net::IpAddr> = twins
            .iter()
            .filter_map(|&j| ports.get(j).map(|t| t.bind))
            .collect();
        let picked = match p.host_pool {
            // A RANGE: its first free port, as Docker picks one, refused in Docker's words when the
            // whole range is taken.
            Some((start, end)) => kern_isolation::pick_port_in(p.bind, &also, p.udp, start, end)
                .ok_or_else(|| {
                    Error::Sandbox(format!(
                        "cannot publish box port {}: Bind for {}:{start}-{end} failed: port is \
                         already allocated (every port of the range is in use)",
                        p.box_port,
                        crate::ports::host_side(&kern_isolation::PortMap { host: 0, ..p })
                            .trim_end_matches(":0")
                    ))
                })?,
            None => kern_isolation::pick_free_port(p.bind, &also, p.udp).ok_or_else(|| {
                Error::Sandbox(format!(
                    "cannot publish box port {}: no free host port could be picked on {}",
                    p.box_port,
                    crate::ports::host_side(&kern_isolation::PortMap { host: 0, ..p })
                        .trim_end_matches(":0")
                ))
            })?,
        };
        for j in std::iter::once(i).chain(twins) {
            if let Some(m) = ports.get_mut(j) {
                m.host = picked;
            }
        }
    }
    Ok(())
}

/// Drop every IMPLICIT mapping (the IPv6 twin of a default bind) whose address `bindable` refuses,
/// asking once per distinct address and not at all when there is no twin. A written mapping is
/// always kept, so a host that cannot bind it refuses it by name.
fn drop_unbindable_twins(
    ports: &mut Vec<kern_isolation::PortMap>,
    bindable: impl Fn(std::net::IpAddr) -> bool,
) {
    if !ports.iter().any(|p| p.implicit) {
        return;
    }
    let mut probed: Vec<(std::net::IpAddr, bool)> = Vec::new();
    ports.retain(|p| {
        if !p.implicit {
            return true;
        }
        if let Some(&(_, ok)) = probed.iter().find(|(ip, _)| *ip == p.bind) {
            return ok;
        }
        let ok = bindable(p.bind);
        probed.push((p.bind, ok));
        ok
    });
}

/// What a box that joins another's network namespace takes from it.
struct JoinedNet {
    /// The target's PID 1, whose user and network namespaces the box enters.
    pid1: i32,
    /// The target's hostname, its `/etc/hosts` entries (`localhost` lines left to the box) and its
    /// resolvers: all three belong to the namespace, as under Docker.
    hostname: String,
    hosts: Vec<(String, String)>,
    nameservers: Vec<String>,
    /// The target's pod, which the joining box is RECORDED under (it does not enter the pod's
    /// namespace, it enters the target's). A `network_mode: service:X` service is a member of X's
    /// stack: recorded with no pod, `compose down` could not find its exit record and left it in
    /// `kern ps -a` (MEASURED: one `exit 137` row per run of a VPN-sidecar file, four after four runs).
    pod: String,
}

/// `--ipc shareable` / `--ipc container:<box>`: the IPC namespace to enter and the host directory to
/// bind at `/dev/shm`, as `(ipc_from, shm_dir)`; `(None, None)` for a box that keeps its own.
///
/// DOCKER'S RULES, MEASURED against Docker Compose v5 on one file: `ipc: "service:producer"` let the
/// consumer read what the producer wrote to `/dev/shm` when the producer was `ipc: shareable`, and
/// was refused with `non-shareable IPC (hint: use IpcMode:shareable for the donor container)` when it
/// was not. kern refused both by never applying `ipc:` at all.
///
/// ONE POD, BECAUSE ONE USER NAMESPACE. The donor's IPC namespace is owned by the user namespace it
/// was created in, and only a process with CAP_SYS_ADMIN there may enter it: the members of one pod
/// share the pod's (measured, in pod and bridge wiring), standalone boxes each have their own.
fn share_ipc(
    args: &BoxRunArgs,
    name: &BoxName,
    pod_holder: Option<i32>,
    pod_label: &str,
) -> Result<(Option<i32>, Option<String>), Error> {
    if !args
        .ipc
        .is_some_and(|m| m.eq_ignore_ascii_case("shareable"))
    {
        registry::clear_box_dirs(name.as_str());
    }
    let Some(mode) = args.ipc else {
        return Ok((None, None));
    };
    if mode.eq_ignore_ascii_case("shareable") {
        let dir = registry::shm_dir_of(name.as_str()).map_err(|e| {
            Error::Sandbox(format!("--ipc shareable: shared memory directory: {e}"))
        })?;
        // A directory left by a box of this name that is gone (a live box holds its name alone) is
        // stale: the new box starts with an empty store, as a new container does.
        registry::clear_box_dirs(name.as_str());
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::Sandbox(format!("--ipc shareable: {}: {e}", dir.display())))?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777));
        return Ok((None, Some(dir.to_string_lossy().into_owned())));
    }
    let Some(target) = mode.strip_prefix("container:") else {
        return Ok((None, None));
    };
    if pod_holder.is_none() {
        return Err(Error::Sandbox(format!(
            "--ipc container:{target} needs this box in the same pod as '{target}' (`--pod`, or \
             one compose stack): an IPC namespace can only be entered from the user namespace that \
             owns it, and a pod's members share one"
        )));
    }
    let donor = registry::find_ref(target).ok_or_else(|| {
        Error::Sandbox(format!(
            "--ipc container:{target}: no running box '{target}' (`kern ps` lists them); the box \
             whose IPC namespace this one joins must be up first"
        ))
    })?;
    if donor.pod != pod_label {
        return Err(Error::Sandbox(format!(
            "--ipc container:{target}: '{target}' is in pod '{}' and this box in '{pod_label}': an \
             IPC namespace is shared inside one pod",
            donor.pod
        )));
    }
    let pid1 = donor.live_pid1().ok_or_else(|| {
        Error::Sandbox(format!(
            "--ipc container:{target}: '{target}' has no running init"
        ))
    })?;
    let dir = registry::shm_dir_of(&donor.name)
        .map_err(|e| Error::Sandbox(format!("--ipc container:{target}: {e}")))?;
    if !dir.is_dir() {
        return Err(Error::Sandbox(format!(
            "--ipc container:{target}: non-shareable IPC (hint: start '{target}' with --ipc \
             shareable, compose `ipc: shareable`), as Docker answers the same file"
        )));
    }
    Ok((Some(pid1), Some(dir.to_string_lossy().into_owned())))
}

/// Resolve `--network container:<target>` to a running box and read what the joining box inherits.
///
/// REFUSED with what Docker refuses with it, because each is a contradiction rather than an option:
/// `-p` (a published port would be the TARGET's port under this box's name; Docker: "conflicting
/// options: port publishing and the container sharing the network namespace"), `--hostname` (the
/// name is the namespace's), `--pod` and `--net` (a second network), `--egress-allow` (the filter
/// owns a namespace this box does not).
///
/// The target's files are read through `/proc/<pid1>/root`, which is the target's own view and needs
/// no mount; one that cannot be read leaves that part empty rather than failing the box, because the
/// namespace itself is what was asked for.
fn join_box_network(target: &str, args: &BoxRunArgs) -> Result<JoinedNet, Error> {
    let conflict = if !args.ports.is_empty() || args.ssh_port.is_some() {
        Some("-p/--ssh: a published port would be the other box's, under this box's name")
    } else if args.hostname.is_some() {
        Some("--hostname: the name belongs to the network namespace being joined")
    } else if args.pod.is_some() || args.share_net {
        Some("--pod/--net: a box has one network")
    } else if !args.egress_allow.is_empty() {
        Some("--egress-allow: the filter needs a network namespace of the box's own")
    } else {
        None
    };
    if let Some(why) = conflict {
        return Err(Error::Sandbox(format!(
            "--network container:{target} cannot combine with {why} (Docker refuses the same pair)"
        )));
    }
    let found = registry::find_ref(target);
    let pod = found.as_ref().map(|i| i.pod.clone()).unwrap_or_default();
    let pid1 = found.and_then(|i| i.live_pid1()).ok_or_else(|| {
        Error::Sandbox(format!(
            "--network container:{target}: no running box '{target}' (`kern ps` lists them); \
                 the box whose network this one joins must be up first"
        ))
    })?;
    let read =
        |f: &str| std::fs::read_to_string(format!("/proc/{pid1}/root/etc/{f}")).unwrap_or_default();
    let hostname = read("hostname").trim().to_string();
    let hosts: Vec<(String, String)> = read("hosts")
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let ip = f.next()?;
            ip.parse::<std::net::IpAddr>()
                .ok()
                .filter(|a| !a.is_loopback())?;
            Some(
                f.map(|n| (n.to_string(), ip.to_string()))
                    .collect::<Vec<_>>(),
            )
        })
        .flatten()
        .collect();
    let nameservers: Vec<String> = read("resolv.conf")
        .lines()
        .filter_map(|l| l.strip_prefix("nameserver"))
        .map(|v| v.trim().to_string())
        .filter(|v| v.parse::<std::net::IpAddr>().is_ok())
        .collect();
    Ok(JoinedNet {
        pid1,
        hostname,
        hosts,
        nameservers,
        pod,
    })
}

/// Prepare `--ssh`: authorize a public key (from `--ssh-key`, or a freshly generated throwaway
/// ed25519 keypair kept in the runtime dir) and add the `host_port → box:22` mapping to the port set.
/// Prints the ready-to-paste `ssh` command. Returns `(None, ports.to_vec())` when `--ssh` is unset.
#[allow(clippy::type_complexity)]
fn prepare_ssh(
    name: &BoxName,
    ssh_port: Option<u16>,
    ssh_key: Option<&str>,
    ports: &[kern_isolation::PortMap],
) -> Result<
    (
        Option<kern_isolation::SshSetup>,
        Vec<kern_isolation::PortMap>,
        Option<String>,
    ),
    Error,
> {
    let Some(port) = ssh_port else {
        return Ok((None, ports.to_vec(), None));
    };
    // Don't silently shadow a user `-p` on the same host port, or a second box-side :22.
    if ports.iter().any(|m| m.host == port) {
        return Err(Error::Sandbox(format!(
            "--ssh {port} conflicts with a -p mapping on host port {port}"
        )));
    }

    let (authorized_key, hint_key) = match ssh_key {
        // `--ssh-key`: authorize the operator's own public key; nothing is generated.
        Some(path) => {
            let key = std::fs::read_to_string(path)
                .map_err(|e| Error::Sandbox(format!("--ssh-key '{path}': {e}")))?;
            // Validate the key TYPE token (first whitespace-delimited field), not a bare `ssh-`
            // substring - that wrongly rejected valid ECDSA keys (`ecdsa-sha2-nistp256`,
            // `sk-ecdsa-sha2-nistp256@openssh.com`), which contain no `ssh-`.
            let ktype = key.split_whitespace().next().unwrap_or("");
            let ok = ktype.starts_with("ssh-")
                || ktype.starts_with("ecdsa-")
                || ktype.starts_with("sk-ssh-")
                || ktype.starts_with("sk-ecdsa-");
            if !ok {
                return Err(Error::Sandbox(format!(
                    "--ssh-key '{path}' does not look like an OpenSSH public key"
                )));
            }
            (key, None)
        }
        // Generate a throwaway ed25519 keypair in the runtime dir; the private key path is printed
        // for `ssh -i`. Regenerated each launch (the box's authorized_keys is ephemeral anyway).
        None => {
            let dir = registry::ssh_dir()
                .map_err(|e| Error::Sandbox(format!("ssh key dir: {e}")))?
                .join(name.as_str());
            std::fs::create_dir_all(&dir)
                .map_err(|e| Error::Sandbox(format!("ssh key dir: {e}")))?;
            let key = dir.join("id");
            let _ = std::fs::remove_file(&key);
            let _ = std::fs::remove_file(dir.join("id.pub"));
            let ok = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-q", "-f"])
                .arg(&key)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                return Err(Error::Sandbox(
                    "--ssh: ssh-keygen failed on the host (install openssh-client) - or pass \
                     --ssh-key <pubkey>"
                        .to_string(),
                ));
            }
            let pub_key = std::fs::read_to_string(dir.join("id.pub"))
                .map_err(|e| Error::Sandbox(format!("--ssh: reading generated key: {e}")))?;
            (pub_key, Some(key.to_string_lossy().into_owned()))
        }
    };

    let mut eff = ports.to_vec();
    eff.push(kern_isolation::PortMap {
        bind: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        implicit: false,
        host: port,
        box_port: 22,
        udp: false,
        host_pool: None,
    }); // 127.0.0.1:<port> -> box :22
    let id = hint_key
        .map(|k| format!(" -i {}", super::shell_quote_single(&k)))
        .unwrap_or_default();
    // THE HOST KEY IS KERN'S, AND SO IS THE `known_hosts` THAT NAMES IT. The box used to generate a
    // fresh host key every launch while the hint said `StrictHostKeyChecking=accept-new`, which pins
    // the FIRST key it sees for `[127.0.0.1]:<port>` in the user's own `~/.ssh/known_hosts`. So the
    // printed command worked once: MEASURED, the second box on the same port answered `Host key for
    // [127.0.0.1]:2222 has changed ... Host key verification failed`, which is every rerun of a CI
    // job or a dev loop that relaunches its box. Generated here, the key is known before the box
    // starts: the hint points at a file holding exactly it and checks strictly, so it works on every
    // launch, refuses any other key, and never writes to the user's file.
    match host_key_for(name, port) {
        Some((private, known_hosts)) => {
            let hint = format!(
                "kern: ssh: ssh -p {port}{id} -o UserKnownHostsFile={} \
                 -o StrictHostKeyChecking=yes root@127.0.0.1",
                super::shell_quote_single(&known_hosts.to_string_lossy())
            );
            Ok((
                Some(kern_isolation::SshSetup {
                    authorized_key,
                    host_key: Some(private),
                }),
                eff,
                Some(hint),
            ))
        }
        // No `ssh-keygen` on the host (only reachable with `--ssh-key`): the box makes its own key,
        // which no client can know in advance, so the hint can only pin it on first sight.
        //
        // `accept-new` and not `UserKnownHostsFile=/dev/null`: a box started inside kern's WSL
        // distro is often reached with Windows' own ssh.exe, where `/dev/null` does not exist
        // (measured: `Host key verification failed`), and turning checking off wholesale teaches
        // the wrong habit. `accept-new` still refuses a CHANGED key; it needs OpenSSH 7.6 (2017).
        None => {
            let hint = format!(
                "kern: ssh: ssh -p {port}{id} -o StrictHostKeyChecking=accept-new root@127.0.0.1"
            );
            Ok((
                Some(kern_isolation::SshSetup {
                    authorized_key,
                    host_key: None,
                }),
                eff,
                Some(hint),
            ))
        }
    }
}

/// Remove the `--ssh` keys made for `name`, when its box could not start. Only kern's own files are
/// in that directory, and the name is a validated box name, so the path is never empty or `..`.
fn forget_ssh_keys(name: &BoxName) {
    if name.as_str().is_empty() {
        return;
    }
    if let Ok(dir) = registry::ssh_dir() {
        let mine = dir.join(name.as_str());
        if mine.starts_with(&dir) && mine != dir {
            let _ = std::fs::remove_dir_all(mine);
        }
    }
}

/// Generate the box's ed25519 host key on the host and write the `known_hosts` that names it, in the
/// box's ssh dir. Returns the PRIVATE key (it goes to the box, in memory; the file is removed) and
/// the `known_hosts` path. `None` when anything fails, which falls back to a key the box makes.
fn host_key_for(name: &BoxName, port: u16) -> Option<(String, std::path::PathBuf)> {
    let dir = registry::ssh_dir().ok()?.join(name.as_str());
    std::fs::create_dir_all(&dir).ok()?;
    let key = dir.join("hostkey");
    let _ = std::fs::remove_file(&key);
    let _ = std::fs::remove_file(dir.join("hostkey.pub"));
    let ok = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-C", "", "-f"])
        .arg(&key)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    let private = ok.then(|| std::fs::read_to_string(&key).ok()).flatten();
    let public = ok
        .then(|| std::fs::read_to_string(dir.join("hostkey.pub")).ok())
        .flatten();
    let _ = std::fs::remove_file(&key);
    let _ = std::fs::remove_file(dir.join("hostkey.pub"));
    let (private, public) = (private?, public?);
    let known_hosts = dir.join("known_hosts");
    std::fs::write(&known_hosts, known_hosts_line(port, &public)?).ok()?;
    Some((private, known_hosts))
}

/// The `known_hosts` line for a server on `127.0.0.1:<port>` with this public key (`<type> <base64>
/// [comment]`). OpenSSH writes a non-default port as `[host]:port` and port 22 as the bare host;
/// a line in the other form never matches. `None` for a key with no type and body.
fn known_hosts_line(port: u16, public: &str) -> Option<String> {
    let mut f = public.split_whitespace();
    let (kind, body) = (f.next()?, f.next()?);
    let host = if port == 22 {
        "127.0.0.1".to_string()
    } else {
        format!("[127.0.0.1]:{port}")
    };
    Some(format!("{host} {kind} {body}\n"))
}

/// WHOSE identity a `kern exec` command runs under.
///
/// The callers want different answers. `kern exec <box>` stays box root: it is the operator's way in,
/// and defaulting it to the workload would leave no way back to root. `kern compose <file> exec
/// <service>` is [`ExecAs::Workload`], because Docker's `compose exec` runs as the service's
/// configured user and a script that reads `whoami` must not get a different answer here.
/// `kern exec -u <spec>` names an account of the box.
#[derive(Clone, Copy, Debug)]
pub enum ExecAs<'a> {
    /// The workload's own uid/gid and groups, as the registry recorded them when the box started.
    Workload,
    /// `-u <user[:group]>`, each half a name or a number, resolved against the box's CURRENT
    /// `/etc/passwd` and `/etc/group`, which is where `docker exec --user` looks.
    User(&'a str),
}

/// `kern exec <name> [-u <user>] [--env K=V] [--workdir <dir>] [-- cmd...]` - run a command inside an
/// already-running box, joining its namespaces. Defaults to `/bin/sh`. Propagates the exit code. `who`
/// picks the identity; see [`ExecAs`].
pub fn exec(
    name: &str,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    tty: bool,
    who: ExecAs,
) -> Result<(), Error> {
    let name = BoxName::parse(name).map_err(Error::InvalidBox)?;
    let env = parse_envs(env)?;
    let cmd = default_if_empty(command);
    let inst = registry::find_ref(name.as_str())
        .ok_or_else(|| Error::NotRunning(format!("no running box named '{}'", name.as_str())))?;
    // A PAUSED box runs no task, so the exec'd process is placed in a frozen cgroup and never
    // scheduled: the command hung forever with no output and no way to tell why. `ps` has always
    // reported the box as `paused`, so the state was known - it just wasn't consulted here. An
    // operation that CANNOT succeed has to say so immediately, and name the way out.
    if registry::is_paused(inst.cgroup_pid()) {
        return Err(Error::Sandbox(format!(
            "box '{}' is paused, so an exec would never be scheduled - `kern unpause {}` first",
            name.as_str(),
            name.as_str()
        )));
    }
    // THE HOST SHAPE IS ANSWERED HERE, before anything forks, and deliberately AFTER the two errors
    // that need no scope to be reported: a box that does not exist and a box that is paused are
    // answered without paying a systemd round trip. Everything below this point is the command
    // actually running, which is the only case where the placement matters.
    //
    // On the host this suite runs on, and on every ordinary desktop, `inside_user_manager_tree()` is
    // true and this is four reads and no fork. It fires on the shapes where an exec is otherwise
    // IMPOSSIBLE, not merely slower.
    if exec_wants_scope(
        kern_isolation::inside_user_manager_tree(),
        kern_common::env_flag("KERN_SCOPE"),
        kern_common::env_flag("KERN_NO_SCOPE"),
        kern_isolation::user_systemd_present,
    ) {
        reexec_exec_in_bare_scope();
        // Returning means the scope could not be arranged after all - the manager went away between
        // the decision and the execve. Fall through: the placement refusal downstream then says so
        // in kern's own words, which is what the reader got before this path existed.
    }
    // PID 1 of the box. Older entries (or a race before the supervisor recorded it) → fall back
    // to the supervisor's sole child.
    let pid1 = match inst.live_pid1() {
        Some(p) => p,
        None => registry::box_init_under(inst.pid)
            .ok_or_else(|| Error::Sandbox("could not locate the box's main process".to_string()))?,
    };
    // THE IDENTITY BEFORE THE TERMINAL: a `-u` that names nobody is refused before a raw-mode tty
    // exists to be restored. `ExecAs::Workload` reads the SAME registry entry that gave us `pid1`, so a
    // box recreated under this name is entered as itself rather than as whoever held the name before.
    let recorded_env = registry::box_env(&inst.name, inst.pid);
    let identity = match who {
        ExecAs::Workload => ExecIdentity {
            run_as: inst.run_as,
            extra_gids: inst.extra_gids.clone(),
            home: None,
        },
        ExecAs::User(spec) => {
            exec_user_identity(spec, name.as_str(), pid1, inst.run_as, &recorded_env, &env)?
        }
    };

    // `-it`: allocate a PTY and (when our own stdin is a terminal) put it in raw mode + forward
    // window resizes, exactly like `kern box -it`. `exec_in_box` hands the slave to the exec'd
    // process as its controlling tty and pumps host stdio <-> master; we restore the terminal after.
    let pty = if tty {
        Some(crate::pty::open().map_err(|e| Error::Sandbox(format!("openpty: {e}")))?)
    } else {
        None
    };
    // The channel the box's own master comes back on. Only for `-it`, and a failure to make one is
    // simply the old behaviour: the host pty above is already open and already works.
    let pty_chan = pty.as_ref().and_then(|_| kern_isolation::fd_channel());
    let saved = pty
        .as_ref()
        .and_then(|p| crate::pty::raw_with_resize(p.master));

    // Warn (in `exec_in_box`) only if the user set an EXPLICIT cap on the box: on a rootless
    // scope-path host the exec can't join the box's cgroup, and a default box would otherwise warn
    // on every `kern exec`. `None` caps → the user asked for nothing to enforce → stay quiet.
    let box_has_explicit_caps = inst.memory_max.is_some() || inst.pids_max.is_some();
    // REFUSE rather than GUESS the box's capability posture: the gate lives inside `exec_posture`, which
    // returns the box's OWN (cap spec, seccomp filter) or refuses a record that predates the posture
    // fields / is corrupt - a caller can't rebuild a usable posture without passing that gate.
    let (box_caps, box_seccomp, box_aa, box_landlock) = inst.exec_posture()?;
    let box_nnp = inst.no_new_privs;
    // With no `-w`, start where the WORKLOAD starts, not at `/`. Docker's `exec` inherits the
    // container's WorkingDir and people lean on it: a compose service with `working_dir: /app` should
    // not need `-w /app` retyped on every exec. An explicit `-w` still wins, and a box with no workdir
    // (or an older registry entry, which carries no such field) keeps landing at `/`.
    let effective_workdir = workdir.or(Some(inst.workdir.as_str()).filter(|w| !w.is_empty()));
    // `--apparmor` parity: `box_aa` comes from the RECORDED exec posture (like caps + seccomp), NOT
    // from `/proc/<pid1>`, so an `--init` box (whose PID 1 reaper stays unconfined) re-enters the box's
    // ACTUAL profile instead of running the exec unconfined. `None` when the box ran with no profile.
    // THE BOX'S OWN ENVIRONMENT FIRST, THE CALLER'S `-e` ON TOP. `exec_in_box` applies what it read
    // from `/proc/<pid1>/environ` and then this list, so a `-e` the user typed still wins - and the
    // recorded environment covers the case that read cannot: an image whose workload runs as a
    // non-root user owns that file as a mapped uid kern cannot read. MEASURED on
    // `rabbitmq:3.12-management-alpine`: `kern exec` saw a bare `PATH` and could not find the
    // image's own binaries.
    let mut exec_env = recorded_env;
    // `-u`'S HOME, between the box's environment and the caller's `-e`: see `exec_user_home`.
    if let Some(home) = identity.home {
        exec_env.push(("HOME".to_string(), home));
    }
    exec_env.extend(env.iter().cloned());
    let result = exec_in_box(
        pid1,
        &cmd,
        &exec_env,
        effective_workdir,
        pty.as_ref().map(|p| p.slave),
        pty.as_ref().map(|p| p.master),
        None, // `kern exec` has no timeout
        box_has_explicit_caps,
        &box_caps,
        box_seccomp,
        box_nnp,
        box_aa.as_deref(),
        // RESOLVED HERE, BEFORE THE FORK, because the child may not read the environment. The default
        // is to refuse: a command that steps around the box's caps while the operator believes it is
        // capped is the escape the fail-closed exists to stop. `KERN_ALLOW_UNCAPPED` is the operator
        // saying otherwise, and it is the same variable, with the same documented meaning, that
        // `kern box` and `kern run` already read for exactly this condition. No new flag: the CLI
        // surface is frozen, and `kern exec` takes none of the cap flags anyway.
        if kern_common::env_flag("KERN_ALLOW_UNCAPPED") {
            kern_isolation::Unplaceable::ProceedWithWarning
        } else {
            kern_isolation::Unplaceable::Refuse
        },
        // `-it`: let the command take its terminal from the BOX's devpts, so `ttyname()` resolves it
        // inside the box. Built only when there IS a terminal; without it the host pty still works,
        // it just has no name in there.
        pty_chan.map(|(parent, child)| kern_isolation::PtyHandover {
            sock_child: child,
            sock_parent: parent,
            retarget: crate::pty::retarget_resize,
        }),
        identity.run_as,
        &identity.extra_gids,
        inst.keep_groups,
        &box_landlock,
    );

    if let Some(prev) = saved.as_ref() {
        crate::pty::restore(0, prev);
    }
    if let Some(p) = pty.as_ref() {
        unsafe { libc::close(p.master) };
    }
    match result {
        Ok(code) => {
            // A REFUSAL IS NOT A START. The child refused before running anything and exited 126, and
            // the parent's wait status for that is the one a command exiting 126 leaves: telling an SDK
            // "it started" here made the sandbox's refusal read as the code's own exit. Nothing is written
            // instead, which is what `kern box` writes for a box that never started.
            if !kern_isolation::exec_was_refused() {
                signal_exec_outcome();
            }
            std::process::exit(code)
        }
        Err(e) => Err(Error::Sandbox(e.to_string())),
    }
}

/// Who a `kern exec` command runs as: `None` is box root, with the caller's groups as they map in.
#[derive(Debug, Default)]
struct ExecIdentity {
    run_as: Option<(u32, u32)>,
    /// The supplementary groups, already narrowed to the ones the box can hold.
    extra_gids: Vec<u32>,
    /// HOME for the command, or `None` to keep the environment's: see [`exec_user_home`].
    home: Option<String>,
}

/// Resolve `kern exec -u <spec>` in the running box whose PID 1 is `pid1`, or refuse with the reason.
///
/// Against the box's CURRENT `/etc/passwd` and `/etc/group`, read ONCE through
/// `openat2(RESOLVE_IN_ROOT)` on its root (see [`Accounts::of_box_root`]), so a symlink the box planted
/// there resolves inside the box and never onto a host file. The rules are `kern box --user`'s (one
/// implementation, [`resolve_user`]): a bare user takes its passwd group, a numeric one not in passwd
/// takes group 0, and the supplementary groups come from `/etc/group` only when the spec names no
/// group.
///
/// THE ID MUST EXIST IN THE BOX'S USER NAMESPACE, and that is checked HERE rather than left to the
/// `setuid` in the child. A box with the single-uid map has root alone; asked for uid 1000 there,
/// the child failed closed with "could not drop to the box's own user", which names neither the uid
/// nor the reason. The kernel's rule is the map itself (an id outside every range cannot be set), so
/// reading the same map cannot disagree with it. An unreadable map is not a refusal: the child's own
/// fail-closed still stands behind it.
fn exec_user_identity(
    spec: &str,
    box_name: &str,
    pid1: i32,
    workload: Option<(u32, u32)>,
    recorded_env: &[(String, String)],
    caller_env: &[(String, String)],
) -> Result<ExecIdentity, Error> {
    use std::os::fd::AsFd;
    let refuse = |why: String| Error::Sandbox(format!("exec -u '{spec}': {why}"));
    let Some((user, group)) = split_user_spec(spec) else {
        return Err(refuse(
            "expected <user>[:<group>], each a name or a number".to_string(),
        ));
    };
    let root = crate::openat2::box_root_fd(pid1)
        .map_err(|e| refuse(format!("cannot open the root of box '{box_name}': {e}")))?;
    let accounts = Accounts::of_box_root(root.as_fd()).map_err(|e| {
        refuse(format!(
            "cannot read the account files of box '{box_name}': {e}"
        ))
    })?;
    drop(root);
    let Some((uid, gid)) = resolve_user(spec, &accounts) else {
        return Err(refuse(match group {
            Some(g) if resolve_user(user, &accounts).is_some() => {
                format!("no group '{g}' in the /etc/group of box '{box_name}'")
            }
            _ => format!("no user '{user}' in the /etc/passwd of box '{box_name}'"),
        }));
    };
    let id_map = |file: &str| {
        std::fs::read_to_string(format!("/proc/{pid1}/{file}"))
            .ok()
            .map(|t| id_map_ranges(&t))
    };
    let uid_ranges = id_map("uid_map");
    let gid_ranges = id_map("gid_map");
    // THE BOX'S OWN BOUNDING SET, not the posture recorded for it: `CapBnd: 0000000000000000` is
    // what `--cap-drop ALL` leaves, and it is the condition `range_buys_nothing` acts on. Read from
    // the subject rather than from kern's record, so a box whose record and whose reality disagree
    // is described by its reality. Unreadable or unparsable answers `false`, which keeps the
    // sentence that was there before rather than inventing a cause.
    let no_caps = std::fs::read_to_string(format!("/proc/{pid1}/status"))
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("CapBnd:"))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        })
        .is_some_and(|bnd| bnd == 0);
    for (kind, id, ranges) in [("uid", uid, &uid_ranges), ("gid", gid, &gid_ranges)] {
        let Some(ranges) = ranges else { continue };
        if !id_is_mapped(ranges, id) {
            return Err(refuse(format!(
                "{kind} {id} does not exist in box '{box_name}', {}",
                describe_id_map(kind, ranges, no_caps)
            )));
        }
    }
    // THE GROUPS THE BOX CAN HOLD. `setgroups` takes the whole list or nothing, and refuses it all for
    // one gid outside the map, so an unmapped entry would cost the mapped ones too. (On the single-uid
    // map only root gets this far, and `set_user` says nothing when that map refuses root's list.)
    let extra_gids: Vec<u32> = supplementary_gids(spec, &accounts)
        .into_iter()
        .filter(|g| gid_ranges.as_ref().is_none_or(|r| id_is_mapped(r, *g)))
        .collect();
    let workload_home = workload
        .filter(|(u, _)| *u != 0)
        .map(|(u, _)| user_home(u, &accounts));
    let home = exec_user_home(
        recorded_env,
        caller_env,
        workload_home.as_deref(),
        user_home(uid, &accounts),
    );
    Ok(ExecIdentity {
        run_as: Some((uid, gid)),
        extra_gids,
        home,
    })
}

/// The INSIDE ranges of a `/proc/<pid>/uid_map` or `gid_map`, as `(first, count)`. A line that does
/// not parse as three numbers is skipped, and so is one with a count of 0: the kernel writes no such
/// line, it maps nothing if it appears, and carrying it would make `describe_id_map` compute a last
/// id of `first - 1`.
fn id_map_ranges(text: &str) -> Vec<(u64, u64)> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace().map(str::parse::<u64>);
            match (f.next(), f.next(), f.next()) {
                (Some(Ok(inside)), Some(Ok(_)), Some(Ok(count))) if count > 0 => {
                    Some((inside, count))
                }
                _ => None,
            }
        })
        .collect()
}

/// Whether `id` falls inside one of `ranges`.
fn id_is_mapped(ranges: &[(u64, u64)], id: u32) -> bool {
    let id = u64::from(id);
    ranges
        .iter()
        .any(|&(first, count)| id >= first && id - first < count)
}

/// The end of the sentence that refuses an unmapped id: what the box DOES map, and for the single-id
/// map the reason it has nothing else.
///
/// `no_caps` IS THE THIRD CAUSE, AND IT WAS MISSING. A field report measured this: a box started
/// `--cap-drop ALL` maps uid 0 alone, because `imagecache::range_buys_nothing` drops the DEFAULT
/// range when the box holds no capabilities (the range exists so a box can `chown` to another uid,
/// which `--cap-drop ALL` refuses either way, and skipping it saves 985 us of a cold box). So the
/// reader was told two causes - `--no-uid-range`, or a host with no `/etc/subuid` entry - and
/// NEITHER was theirs: they check `/etc/subuid`, find it fine, check their command line, find no
/// `--no-uid-range`, and conclude the message is wrong.
///
/// `kern exec -u <non-root>` is what made it matter, and it arrived in this branch: it is a consumer
/// of the range that did not exist when that default was written, and it happens AFTER the box
/// started, so nothing can retrofit the map. The answer is to name the cause and the flag that asks
/// for the range anyway.
///
/// THE CAUSE IT NAMED IS NARROWER NOW. It said kern drops the range for a no-caps box "because the
/// range buys it nothing", and the range buys the `setgroups` clear, which that box then cannot do.
/// Since `range_buys_nothing` also requires the caller to carry no inherited supplementary group,
/// this branch is reachable only for a caller that has none, so the sentence has to say which of the
/// two conditions the reader is in rather than implying the capability set alone decided.
fn describe_id_map(kind: &str, ranges: &[(u64, u64)], no_caps: bool) -> String {
    if ranges == [(0, 1)] {
        if no_caps {
            return format!(
                "which maps {kind} 0 alone: it holds no capabilities (`--cap-drop ALL`, or \
                 `--security-profile untrusted`) AND the caller carries no supplementary group, so \
                 kern skipped the default sub-uid range, which would have bought this box nothing. \
                 Start it with `--uid-range` as well, which asks for the range in as many words, and \
                 `kern exec -u` then works"
            );
        }
        return format!(
            "which maps {kind} 0 alone: it was started with the single-uid map (`--no-uid-range`, \
             or a host with no subordinate range in /etc/subuid), and `--uid-range` gives a box the rest"
        );
    }
    let spans: Vec<String> = ranges
        .iter()
        .map(|&(first, count)| match count {
            1 => first.to_string(),
            _ => format!("{first}-{}", first + count - 1),
        })
        .collect();
    format!("which maps {kind}s {}", spans.join(", "))
}

/// The HOME a `kern exec -u` command gets, or `None` to keep the one its environment already has.
///
/// runc's rule, which `docker exec --user` inherits: HOME comes from the environment when it is set
/// there, and from the user's passwd entry when it is not. kern's recorded box environment holds one
/// HOME runc's would not: the one kern itself derived at start for a non-root workload
/// (`user_home`). That one belongs to the WORKLOAD's user, so a `-u` for someone else
/// re-derives it, and a HOME the image or the box's own `-e` set is kept, as Docker keeps
/// `Config.Env`. An image `ENV HOME` equal to the workload user's passwd home reads as kern's and is
/// re-derived too; for the workload's own user that changes nothing. The caller's `-e HOME=` wins
/// over all of it, so with one there is nothing to add.
///
/// Without this, `kern exec -u node` into a box whose workload is root ran with `HOME=/root`, a
/// directory node cannot write, and every tool that keeps state under `~` failed there.
fn exec_user_home(
    recorded: &[(String, String)],
    caller: &[(String, String)],
    workload_home: Option<&str>,
    passwd_home: String,
) -> Option<String> {
    if caller.iter().any(|(k, _)| k == "HOME") {
        return None;
    }
    match recorded.iter().rev().find(|(k, _)| k == "HOME") {
        Some((_, set)) if Some(set.as_str()) != workload_home => None,
        _ => Some(passwd_home),
    }
}

/// Hand an exec'd command's outcome to the caller's `KERN_STARTED_FD`, in the byte order `kern box`
/// writes at its teardown: the command ran (1), cap enforcement is not known on this path (0), whether
/// the OOM killer took it with its box, and the signal that ended it (0 for an exit of its own).
///
/// THE OUTCOME EXISTED AND ONLY A READER OF STDERR COULD HAVE IT. `memory.oom.group=1` makes an OOM
/// take the whole box, so a command run with `kern exec` dies with it; the exec path attributed that
/// and printed a sentence, and wrote nothing here. MEASURED through the SDK, resident sandbox,
/// `memory_mb=128`: `bytearray(400 << 20)` came back `killed` where a fresh box says `oom`, so an agent
/// does not try more memory, and a cell's own `sys.exit(137)` ALSO came back `killed`, a kill that never
/// happened, which `kern box`'s fourth byte had already ruled out for the one-shot path. Stderr is no
/// substitute: the workload writes to it too.
///
/// The workload cannot reach this descriptor: `kern exec` sheds inherited fds before the command runs
/// (measured: a caller's fd 7 is absent from the box's `/proc/self/fd`).
fn signal_exec_outcome() {
    let Some(fd) = started_signal_fd() else {
        return;
    };
    let buf = [
        1u8,
        0,
        u8::from(kern_isolation::exec_was_oom_killed()),
        kern_isolation::exec_workload_signal(),
    ];
    loop {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    let _ = unsafe { libc::close(fd) };
}

/// Foreground-launcher side of a detached start: block on the readiness pipe until the box `exec`s
/// (EOF = up) or signals failure (one byte → reap the supervisor and report why), then print the
/// "started" line. With no pipe it just announces. Retries the read on `EINTR` so a stray signal
/// isn't misread as a successful start.
#[allow(clippy::too_many_arguments)]
fn await_box_started(
    name: &BoxName,
    child: i32,
    rd: i32,
    wr: i32,
    have_pipe: bool,
    // The box is owned by a --restart supervisor (on-failure OR always) that RETRIES a failed start.
    // A failure byte from the FIRST attempt then does NOT mean the box is dead: reaping the supervisor
    // here would block until it gives up - FOREVER for `always` - and wedge `compose up`, which waits
    // on this launcher. So on a supervised box a first-attempt failure is reported, not awaited.
    supervised: bool,
    // The read end of the cap-notice pipe (see `run_detached`): what the supervisor could not say on
    // a stderr that is now the box's log. `None` when that pipe could not be created.
    notice_rd: Option<i32>,
    // The box waits at a gate its OWN supervisor releases ([`HeldNat`]), so `b'P'` is a step on the
    // way to the exec and not the end of the start: the read goes on to the EOF or failure byte,
    // and the start is reported as any other box's.
    self_gated: bool,
    // `--log-driver none`: the box keeps no log, so the next steps do not offer `kern logs`.
    keeps_log: bool,
    // The box publishes a TCP port: only then can it have a `.localhost` URL, and only then is the
    // registry read for it.
    publishes_tcp: bool,
) -> Result<(), Error> {
    // Assembled below, on whichever path resolves the start, and printed with the start line so the
    // launcher still makes ONE write per box (see that comment).
    let notices;
    if have_pipe {
        unsafe { libc::close(wr) };
        let mut byte = [0u8; 1];
        let n = loop {
            let r = unsafe { libc::read(rd, byte.as_mut_ptr().cast(), 1) };
            if r < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if r == 1 && self_gated && byte[0] == kern_isolation::READY_PREPARED {
                continue;
            }
            break r;
        };
        unsafe { libc::close(rd) };
        // DRAINED HERE, AND THE POSITION IS THE WHOLE CORRECTNESS ARGUMENT. The notices are written
        // before the box is forked, and the readiness pipe resolves at the box's `execvp` (or at its
        // failure byte), so by this line whatever the start had to say about its caps is already in
        // the pipe. Nothing waits for EOF - that read is non-blocking - so the channel cannot make a
        // launcher hang the way a held stderr did.
        notices = notice_rd.map(drain_cap_notices).unwrap_or_default();
        // PREPARED IS A SUCCESS, AND IT IS THE ONLY BYTE THAT IS.
        //
        // The pipe carries three states, one per shape: EOF means the workload exec'd, the byte
        // `b'x'` means setup failed, and `b'P'` means the box is fully set up and waiting on its
        // pre-exec gate. The third exists because a gated box CANNOT reach EOF on its own: under
        // `compose --no-pod` the workload waits for the gate, the gate is written by `up`, and `up`
        // waits for this launcher - a four-way wait that hung two runs in three before this byte
        // existed.
        //
        // Read as "any byte means failure" - which is what this did - a prepared box was reported as
        // a box that died before starting, complete with a log tail that did not exist. So the value
        // is checked, not just the count.
        if n > 0 && byte[0] == kern_isolation::READY_PREPARED {
            // A prepared box prints no start line here (`compose up` reports the stack), but a cap
            // notice is about the box and not about this launcher's shape, so it is still said.
            print_cap_notices(&notices);
            return Ok(());
        }
        if n > 0 && supervised {
            // Docker returns immediately for `-d --restart` on a box that trips its first start; the
            // supervisor keeps retrying in the background. Hand back so the caller (and `compose up`)
            // proceeds instead of hanging on a supervisor that may never exit.
            let n = name.as_str();
            print_cap_notices(&notices);
            eprintln!(
                "kern: box '{n}' failed its first start attempt; the --restart supervisor is \
                 retrying (see `kern logs {n}`)"
            );
            return Ok(());
        }
        if n > 0 {
            let mut st = 0i32;
            crate::eintr::waitpid(child, &mut st, 0);
            // NOT printed on this path, deliberately: the error below quotes the box's log, where
            // every notice also went, so saying them here would print the same sentence twice above a
            // message that already carries it.
            drop(notices);
            // The box's own error went to its per-box log (its stderr was detached there), so the
            // launcher only knows it died. `waitpid` above has reaped the supervisor, so the log is
            // now fully written - surface its tail inline. This turns the failure from an opaque
            // "run `kern logs`" round-trip into a reason the user (and a skip-graceful test) can act
            // on immediately, e.g. "unprivileged user namespaces are unavailable" on a locked host.
            // The log is named `<name>-<supervisor pid>.log`, and `child` IS that supervisor pid.
            let n = name.as_str();
            let reason = registry::logs_dir()
                .ok()
                .map(|d| d.join(format!("{n}-{child}.log")))
                .and_then(|p| read_log_reason(&p))
                // A reason that is only whitespace (or scrubs to nothing) is no reason: it printed
                // "exited before starting:" and then nothing (reported on WSL2 for a missing command).
                .filter(|r| r.lines().any(|l| !crate::ui::scrub(l).trim().is_empty()));
            return Err(Error::Sandbox(match reason {
                Some(r) => {
                    // The tail is the box's OWN log bytes rendered to the operator - scrub control
                    // sequences PER LINE (keep the newlines that make a multi-line tail readable, drop
                    // ESC/CR/…) so a box that printed `\e[2J` before dying can't clear or repaint the
                    // operator's terminal through this failure message. Same untrusted-text guard as
                    // the `ps` command column.
                    let safe: String = r
                        .lines()
                        .map(crate::ui::scrub)
                        .collect::<Vec<_>>()
                        .join("\n");
                    format!(
                        "box '{n}' exited before starting:\n{safe}\n(run `kern logs {n}` for the full log)"
                    )
                }
                None => {
                    format!("box '{n}' exited before starting - run `kern logs {n}` for the reason")
                }
            }));
        }
    } else {
        // No readiness pipe (fd exhaustion): the supervisor hasn't necessarily REGISTERED yet, and
        // the caller releases its name-claim right after we return - an unlucky concurrent
        // same-name start could slip into that gap. Wait (bounded, best-effort) for the entry to
        // appear so the claim's release contract - "after register" - holds on this path too.
        for _ in 0..20 {
            if registry::name_taken(name.as_str()) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // Same drain, after the same kind of wait: on this path the registry entry is the only signal
        // there is, so it stands in for the readiness pipe's resolution.
        notices = notice_rd.map(drain_cap_notices).unwrap_or_default();
    }
    let p = crate::ui::Palette::detect();
    let gl = crate::ui::Glyphs::detect();
    let n = name.as_str();
    // stderr, not stdout. A detached box writes its workload's output to its LOG, so nothing about
    // this line is data: it is a confirmation and a hint, addressed to a person. Putting it on stdout
    // means `kern box web -d … > file` captures a decorated sentence, and a caller reading stdout gets
    // prose where it expected either nothing or a machine-readable value. Interactively nothing
    // changes - stderr is the same terminal - and the box's name is an ARGUMENT the caller already
    // holds, so there is no identifier to print in its place (unlike `docker run -d`, which prints a
    // container id it generated).
    // ONE STRING, ONE WRITE, and that is not a style preference. `compose up` starts a level's
    // services in parallel, each as its own `kern box -d` process sharing this stderr. Two
    // `eprintln!`s here are several `write` calls each (`Stderr` is unbuffered, so every fragment of
    // the format goes out on its own), and nothing locks a descriptor ACROSS processes. MEASURED on a
    // two-service stack: `✔✔ started started ''kern-…-cli kern-…-srv''`, one unreadable line where
    // two boxes reported. Assembling first makes it a single `write`, which a pipe delivers atomically
    // under `PIPE_BUF` and a terminal delivers as one call; the worst case left is whole lines out of
    // order, which reads fine.
    // The cap notices go FIRST and in the same write: they are the condition under which this box is
    // running, so a reader scanning for the tick has already passed them, and a reader who only sees
    // the tick is the defect this channel exists to close.
    let logs_step = if keeps_log {
        format!("kern logs {n} {} ", gl.dot)
    } else {
        String::new()
    };
    // Started by `compose up`: the notices only, the stack's summary says the rest.
    let msg = if crate::global_env("KERN_COMPOSE_LAUNCH").is_some() {
        notices
    } else {
        // A published port gets a name on this machine too, as a compose service does.
        let url_line = publishes_tcp
            .then(|| crate::localrouter::box_url(n))
            .flatten()
            .map(|u| format!("  url: {u}\n"))
            .unwrap_or_default();
        format!(
            "{notices}{}{} started{} {}'{n}'{} {}[pid {child}, detached]{}\n{url_line}  {}next: kern ps {} {logs_step}kern stop {n}{}\n",
            p.g, gl.ok, p.z, p.b, p.z, p.d, p.z, p.d, gl.dot, p.z
        )
    };
    let _ = std::io::Write::write_all(&mut std::io::stderr(), msg.as_bytes());
    Ok(())
}

/// Read whatever the supervisor put in the cap-notice pipe and close it. Never blocks and never waits
/// for EOF: the write ends outlive this call by design (the supervisor keeps one until it forks the
/// first attempt), so waiting for one would hang the launcher - which is exactly the defect the first
/// version of this channel had when it was a `dup` of stderr instead of a pipe.
///
/// SCRUBBED AND BOUNDED, because this text is printed to the operator's terminal. kern is the only
/// writer today (the supervisor and the attempt it forks; the box's own copy is `FD_CLOEXEC` and is
/// shed before `execvp`), and that is a property of the code rather than of the kernel, so the bytes
/// are treated as untrusted anyway: control sequences are stripped per line, exactly as the failure
/// path already does with the log tail, and the total is capped so nothing can flood a terminal
/// through it. Each line keeps its newline so the result drops straight into the start-line write.
fn drain_cap_notices(fd: i32) -> String {
    // One read of a bounded buffer: the notices are a handful of sentences, and a cap well under the
    // 64 KiB pipe buffer means a single non-blocking read sees all of what kern wrote.
    const CAP: usize = 8 * 1024;
    let mut buf = vec![0u8; CAP];
    let mut filled = 0usize;
    // `O_NONBLOCK` on the read end only, set here rather than at creation so the supervisor's writes
    // keep their ordinary blocking semantics.
    unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
    while filled < CAP {
        let n = unsafe { libc::read(fd, buf[filled..].as_mut_ptr().cast(), CAP - filled) };
        if n > 0 {
            filled += n as usize;
            continue;
        }
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        break; // EAGAIN (nothing more pending) or EOF
    }
    unsafe { libc::close(fd) };
    let text = String::from_utf8_lossy(&buf[..filled]);
    let mut out = String::with_capacity(filled + 8);
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        out.push_str(&crate::ui::scrub(line));
        out.push('\n');
    }
    out
}

/// Print already-drained notices on the paths that have no start line to carry them.
fn print_cap_notices(notices: &str) {
    if notices.is_empty() {
        return;
    }
    let _ = std::io::Write::write_all(&mut std::io::stderr(), notices.as_bytes());
}

/// Leave the registry with the box's log complete: the log pump finishes first
/// ([`crate::commands::boxlog::finish_log_pump`]), so a `kern logs -f` that stops at the removal has
/// every line. The one way a box's supervisor leaves the registry at the end of its box.
fn leave_registry(path: &std::path::Path) {
    crate::commands::boxlog::finish_log_pump();
    registry::unregister(path);
}

/// Should a box that just exited `code` be started again? The whole restart policy, as a pure
/// function, so the rule is testable without forking anything.
///
/// `always`/`unless-stopped` restart on ANY exit including 0, uncapped: Docker's contract, kept up for
/// the stack's lifetime. `on-failure` restarts a non-zero exit within its budget.
///
/// AND 125 IS NEITHER, because it is not a workload exit at all: it is kern's own box-not-started code
/// (Docker's too), used as the discriminator elsewhere in this file. Under `always` it was restarted
/// forever, so a stack whose `up` died left its surviving boxes rebuilding a box that could not be
/// built. MEASURED by a later pass bringing up Immich: 26 iterations for one service, 15 for
/// another, each logging "never released: the launcher closed the pre-exec gate ... the workload did
/// not run". Docker does not restart a container it failed to create.
///
/// BOUNDED RATHER THAN FORBIDDEN, because not every 125 is permanent: a bind source that appears a
/// second later, a peer still writing the pod's network. It gets the same budget `on-failure` uses.
/// Can this box's pre-exec gate still release a retry? `None` when there is no gate to ask.
///
/// ASKED OF THE PIPE, NOT OF A MESSAGE, so it cannot be wrong about a box that is lying or about a
/// line kern itself wrote: the gate is one pipe per box, the launcher holds the only write end, and
/// the two states are distinguishable without reading a byte.
///
/// - `POLLIN`: a release byte is SITTING IN THE PIPE. The launcher released this box and the attempt
///   died before consuming it (its own setup failed - a bind source that was not there yet). A retry
///   will read that byte and run, so the budget is exactly right and this returns `true`.
/// - `POLLHUP` without `POLLIN`: the write end is gone and nothing is buffered. The launcher closed
///   the gate WITHOUT releasing this box, and no future attempt can ever be released, because the
///   process that would have written the byte has exited. Retrying is 10 refusals and a backoff that
///   reaches 30 s, which is what a later pass watched go round 26 times on Immich.
/// - Open, no data: the launcher is still working. Unchanged: the budget applies.
///
/// `poll` does not consume, so asking costs the pipe nothing and the retry still finds its byte.
/// Any error, an unusable descriptor, or no gate at all answers `None`, and the caller keeps the
/// behaviour it had before this question existed: refusing to restart on a guess would be the same
/// class of defect in the other direction.
fn gate_can_still_release() -> Option<bool> {
    let fd: libc::c_int = crate::global_env_str("KERN_GATE_FD")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if fd < 0 {
        return None;
    }
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live local `pollfd`, count 1, zero timeout: `poll` returns immediately and writes
    // only into `revents`.
    if unsafe { libc::poll(&mut pfd, 1, 0) } < 0 {
        return None;
    }
    if pfd.revents & libc::POLLNVAL != 0 {
        return None;
    }
    if pfd.revents & libc::POLLIN != 0 {
        return Some(true);
    }
    Some(pfd.revents & libc::POLLHUP == 0)
}

fn should_restart(
    code: i32,
    always: bool,
    on_failure: bool,
    attempt: u32,
    max_restarts: u32,
) -> bool {
    // A POLICY FIRST, THEN ITS BUDGET. The 125 rule was written to BOUND `always` (see the caller),
    // and it also made a box with NO policy retry ten times with a backoff of up to 30 s, while
    // `kern box -d` waited on the supervisor: a box whose setup failed hung the launcher for minutes
    // where the foreground answered 125 in 18 ms (reported, and present since the rule was added).
    // Docker does not retry a container it could not create unless a restart policy says so.
    if code == 125 {
        return (always || on_failure) && attempt <= max_restarts;
    }
    always || (on_failure && code != 0 && attempt <= max_restarts)
}

/// Supervisor loop: run the box and wait for it; with `--restart` (on-failure) re-run it on a
/// non-zero exit, up to a cap with a 1 s backoff so a perpetually-crashing box eventually gives up.
/// Each attempt is a FRESH child - `run_in_sandbox_with` unshares its *caller*, so it can't be
/// re-run in place (the second `unshare` would `EINVAL`); the supervisor stays un-namespaced and
/// just waits. Readiness is signalled only on the first attempt (the launcher already returned by
/// the time a restart happens). `inst` is re-registered with each attempt's box PID 1.
/// A box renamed while it ran is recorded under its NEW name: its exit record, its history line,
/// its kept layer's last exit and its `--rm` log removal. MEASURED before this: `kern rename a b`
/// on a running box, then its exit was listed by `ps -a` as `a`, `kern rm b` found nothing, and
/// a `--rm` box renamed so left its logs (which the rename had moved to `b`) in the store. The
/// registry entry, which `rename` rewrites, is still there at this point and names it.
fn adopt_current_name(inst: &mut registry::Instance) {
    if let Some(current) = registry::name_for_pid(inst.pid) {
        inst.name = current;
    }
}

#[allow(clippy::too_many_arguments)]
fn supervise_box(
    // `--rm`: skip the exit breadcrumb entirely. See `run_detached`.
    rm: bool,
    name: &BoxName,
    spec: &SandboxSpec,
    have_pipe: bool,
    wr: i32,
    ports: &[kern_isolation::PortMap],
    restart: Restart,
    inst: &mut registry::Instance,
    // See [`HeldNat`]: armed afresh for every attempt, because every attempt is a new namespace.
    outbound_pod: Option<&str>,
    // The egress filter, armed afresh for every attempt for the same reason (see [`EgressPlan`]).
    egress: Option<&EgressPlan>,
) {
    const DEFAULT_MAX_RESTARTS: u32 = 10;
    let max_restarts = if restart.max > 0 {
        restart.max
    } else {
        DEFAULT_MAX_RESTARTS
    };
    // `compose` hands a box that is a `depends_completed` target an exit KEY via env `KERN_EXIT_KEY`.
    // The key is `<pod>-<token>-<name>` - it encodes both the stack AND the `up` epoch, so recording
    // the final code under it can't collide with a same-named service in another stack, nor with the
    // SAME stack under a concurrent `up` (that run has a different token → a different filename). Absent
    // for a plain `kern box` - no sidecar is written. Read ONCE at start; the box's own workload can't
    // change our env.
    let exit_key = crate::global_env_str("KERN_EXIT_KEY")
        .ok()
        .filter(|k| !k.is_empty());
    // The box's log file, resolved here in the SUPERVISOR (whose pid names it) so the runner child
    // can append a diagnosis to it by path. See the pids message below for why by path and not by
    // writing to stderr.
    let log_path = registry::logs_dir()
        .ok()
        .map(|d| d.join(format!("{}-{}.log", name.as_str(), std::process::id())));
    let mut attempt = 0u32;
    // Whether any attempt reached its workload: what decides below whether `--rm` may take the
    // logs (a box that never started is explained to its launcher FROM its log).
    let mut ran_once = false;
    // ⛔ THE PRE-EXEC GATE IS A ONE-SHOT, AND A RESTART MUST NOT WAIT ON IT. The gate's write end
    // belongs to the LAUNCHER (`compose up`), which releases every box and then returns; a box the
    // supervisor restarts afterwards finds that descriptor at EOF and refuses to exec, forever.
    // MEASURED on Sentry's `install.sh`: a `restart: always` service whose workload exited once then
    // logged `never started (exit 125); retrying (7/10)` until its budget ran out, with `kern ps`
    // still showing it as `starting` - and the message blamed a launcher that had done its job.
    //
    // WHAT THE GATE IS FOR decides this: it holds the FIRST exec until the peer network exists. By
    // the time anything restarts, that network is built, so there is nothing left to wait for. The
    // variable is removed from THIS process's environment, which is what every forked attempt
    // inherits, so the change reaches the restart and nothing else.
    //
    // 🔴 BUT ONLY AFTER AN ATTEMPT THAT ACTUALLY RAN THE WORKLOAD, or this becomes a way to RUN a box
    // the launcher deliberately refused. MEASURED on published main with a
    // `service_completed_successfully` dependency whose service exits 1: the gate does its job and the
    // box logs "never released ... never started (exit 125)", and ONE SECOND LATER the restart, with
    // the gate removed, execs the workload anyway. The condition was enforced and then undone by the
    // recovery path.
    //
    // THE DISCRIMINATOR IS THE PREVIOUS EXIT, and 125 is exactly "no workload ran" (kern's
    // box-not-started convention, used as the discriminator elsewhere in this file). So the gate is
    // kept for a retry that follows a box which never started, and dropped only once a workload has
    // exited - which is the only case the paragraph above is about.
    //
    // KEEPING IT IS NOT A HANG, AND THE PIPE ITSELF SEPARATES THE TWO CASES, which is why this needs
    // no new channel and no stderr heuristic. Each box has its own gate pipe, and the supervisor's
    // read end stays open across forks (the child closes its own copy, post-fork). If the launcher
    // RELEASED this box and the box then failed its own setup - a missing bind source, the case the
    // budget exists for - that release byte was never consumed and is still in the pipe, so the retry
    // reads it and proceeds. If the launcher refused, there is no byte and the write end is gone, and
    // the restart decision at the bottom of this loop ends the box on the first refusal rather than
    // running a workload whose dependency failed.
    let mut gate_dropped = false;
    // The previous attempt's exit, `None` before the first. Only its equality with 125 is read.
    let mut last_code: Option<i32> = None;
    // The last attempt's verdict (signal, OOM) from the runner, and how long it ran: what the box's
    // line in the sandbox history is written from once no restart is left.
    // Declared unassigned: every attempt assigns both before the loop can end, and the compiler
    // holds that.
    let mut last_verdict: (u8, bool);
    let mut last_ran_ms: u64;
    let final_code = loop {
        let ready = if attempt == 0 {
            have_pipe.then_some(wr)
        } else {
            None
        };
        if attempt > 0 && !gate_dropped && last_code != Some(125) {
            // SAFETY: single-threaded supervisor between forks; no other thread can be reading the
            // environment here.
            crate::unset_global_env("KERN_GATE_FD");
            gate_dropped = true;
        }
        // Wall-clock this attempt so a box that stayed up counts as recovered (see the reset below).
        let started = std::time::Instant::now();
        // What `ps` reports as this box's state: running since now (see `registry::Attempt`).
        registry::set_box_attempt(
            &inst.name,
            inst.pid,
            registry::Attempt::Running {
                since_ms: registry::unix_ms(),
            },
        );
        // THE RUNNER'S VERDICT, CARRIED BACK. The signal that ended the workload and whether its own
        // cgroup OOM-killed it are latched in the RUNNER (it reaps the box), and the exit status that
        // reaches this supervisor carries neither: an OOM read `exit-137`, the same as a `kill -9`.
        // Two bytes over a pipe, written just before the runner exits; a runner killed before it
        // writes leaves the pipe empty and the code alone speaks, as before. CLOEXEC, so the box's
        // own exec never inherits either end.
        let mut latch = [-1i32; 2];
        let have_latch = unsafe { libc::pipe2(latch.as_mut_ptr(), libc::O_CLOEXEC) } == 0;
        let runner = unsafe { libc::fork() };
        if runner == 0 {
            // Filled by the callback below, which runs in THIS process: the supervisor never sees
            // it, which is why the diagnosis is written here rather than after the wait.
            #[allow(clippy::type_complexity)]
            let pids_baseline: std::cell::OnceCell<
                Option<(Option<u64>, std::path::PathBuf)>,
            > = std::cell::OnceCell::new();
            let mut held_nat = outbound_pod.and_then(|p| HeldNat::arm(p, name.as_str()));
            // HERE, IN THE RUNNER, BEFORE `run_in_sandbox_with`: the same place the foreground box
            // arms its filter, so the helpers are this runner's children in the HOST pid namespace
            // and never members of the box's (the placement `EgressPlan::arm` documents).
            let mut egress_pending = egress.and_then(EgressPlan::arm);
            let mut egress_guard: Option<crate::egress::EgressFilter> = None;
            // THE WORKLOAD WAITS FOR ITS FILTER here too, for every attempt, as on the foreground path:
            // the detached box had the same race (see `EgressGate`). After `HeldNat`, which a box with
            // `--egress-allow` never has (it refuses `--pod`), so the one gate is never contended.
            let mut egress_gate = egress_pending.as_ref().and_then(|_| EgressGate::arm());
            // The exec witness: whether this attempt's workload ran, for the restart decision below.
            kern_isolation::want_exec_witness();
            let code = match run_in_sandbox_with(
                spec,
                ready,
                |pid1| {
                    inst.record_pid1(pid1);
                    // Record the box's DEDICATED cgroup PATH and its `(dev, ino)` IDENTITY now that PID 1
                    // exists: `list()` uses them to recognise an ORPHANED box (this supervisor
                    // SIGKILL'd/OOM'd, PID 1 + `-p` forwarder still alive and holding the port) instead
                    // of dropping it, AND to make the reap identity-safe - the path's `<pid>` leaf
                    // recycles, so only the recorded inode tells a reap it is killing THIS box and not a
                    // later one that took the path. `("", None)` (a scope/ambient box with no
                    // `kern-box-*` leaf) leaves liveness on the supervisor pid, as before. Re-resolved on
                    // every `--restart` re-register, so it never goes stale.
                    (inst.cgroup, inst.cgroup_id) = registry::box_cgroup_record(pid1);
                    // OPENED WHILE THE BOX IS ALIVE, because the counter dies with the cgroup. The
                    // refusal count lives on the box's OWN leaf (that is where the limit is), and the
                    // leaf is torn down with the box, so a path read after the exit finds nothing -
                    // measured: the message never printed for a box that had just been refused forty
                    // forks. See `open_pids_events_fd`.
                    // THE ANCESTOR'S COUNTER, and a baseline the moment PID 1 exists.
                    //
                    // Not the box's own leaf: `pids.events` there is unreadable once the cgroup is
                    // torn down with the box, which is exactly when the answer is wanted (measured:
                    // an fd held open across the exit read back `None` for a box that had just been
                    // refused forty forks). The counter is HIERARCHICAL, so the parent slice records
                    // the same refusal and survives: measured on this host, `kern.slice` went
                    // `max 438 -> 439` for one box hitting its own cap, with its own `pids.max` unset.
                    pids_baseline
                        .set(
                            std::path::Path::new(&inst.cgroup)
                                .parent()
                                .map(std::path::Path::to_path_buf)
                                .map(|p| (kern_isolation::pids_denied_count_at(&p), p)),
                        )
                        .ok();
                    // If the box was `kern rename`d since the last (re)register, adopt its CURRENT
                    // on-disk name so a `--restart` re-register updates that entry instead of
                    // resurrecting the original name as a duplicate live entry.
                    if let Some(cur) = registry::name_for_pid(inst.pid) {
                        inst.name = cur;
                    }
                    // On a RESTART (attempt > 0), adopt any memory/pids cap a `kern update` wrote to the
                    // record while this box was up, and re-apply it to THIS attempt's FRESH cgroup, so the
                    // operator's change survives an in-process restart instead of snapping back to the
                    // box's original spec (Docker's `update` persists). `apply_limits` already wrote spec's
                    // caps to the new cgroup BEFORE this callback, so the override here lands last and
                    // wins; the record stays the source of truth, keeping `kern ps` and the kernel in step.
                    // Skipped on the FIRST start: an operator `kern update` cannot have run before the box
                    // exists, so the record can only hold the spec caps `apply_limits` just wrote - reading
                    // them back would be a wasted dir-scan per launch (an M-service `compose up` pays it M
                    // times). NB `--cpus` is applied live by `update` but NOT recorded, so it does not
                    // persist here; only memory/pids do. (The systemd-managed path rebuilds from spec.)
                    if attempt > 0 {
                        if let Some((mem, pids)) = registry::current_caps(inst.pid) {
                            inst.memory_max = mem;
                            inst.pids_max = pids;
                            // Write to the box's dedicated cgroup dir ALREADY resolved on the line above
                            // (`box_cgroup_record` uses `box_cgroup_dir`, caller-independent). NOT
                            // `registry::box_cgroup(pid1)`: that is caller-RELATIVE and returns None here,
                            // because this callback runs in the runner process that `apply_limits` moved
                            // INTO the box's cgroup - so the write would silently never happen and the
                            // kernel would keep the spec cap while the record showed the update (divergence).
                            if !inst.cgroup.is_empty() {
                                let cg = std::path::Path::new(&inst.cgroup);
                                if let Some(m) = mem {
                                    let _ = write_cgroup(cg, "memory.max", &m.to_string());
                                }
                                if let Some(p) = pids {
                                    let _ = write_cgroup(cg, "pids.max", &p.to_string());
                                }
                            }
                        }
                    }
                    // Same reason as the foreground path: no channel to propagate on, so report.
                    // A discarded failure here leaves the entry without this box's PID 1, which is
                    // what `kern exec` joins.
                    if let Err(e) = registry::register(inst) {
                        eprintln!(
                            "kern: warning: could not record the box's PID 1 in the registry: {e} -                              `kern exec` on this box will not find it"
                        );
                    }
                    if let Some(nat) = held_nat.as_mut() {
                        nat.release(pid1);
                    }
                    // THE PUMP NEVER CAME UP: PID 1 is already killed. Said in the box's log (this
                    // process's stderr is the log pump, alive while the box is), and, on the first
                    // attempt, as the readiness pipe's failure byte, so the launcher reports a box
                    // that did not start, with this line as the reason, rather than "started".
                    if let Some(e) = deliver_egress(&mut egress_pending, &mut egress_guard, pid1) {
                        eprintln!("kern: {e}");
                        if let Some(fd) = ready {
                            // SAFETY: the readiness pipe's write end, a valid descriptor here.
                            let _ = unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
                        }
                    } else if let Some(gate) = egress_gate.as_mut() {
                        gate.release();
                    }
                    // A detached box has no terminal at all, so there is never a master to swap.
                    None
                },
                None,  // detached boxes have no terminal to attach
                ports, // the runtime forks `-p` forwarders before unshare, kills them on box exit
                // Detached: the supervisor is the box's PERSISTENT owner (the launcher already
                // returned from `await_box_started`), so NEVER arm a launcher PDEATHSIG here - it
                // would kill the box the instant the launcher exits. Teardown stays with `kern stop`.
                false,
            ) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("kern: box failed to start: {e}");
                    127
                }
            };
            drop(held_nat);
            // This attempt is over: its proxy, pump and gate go now. The runner leaves through
            // `_exit`, which runs no destructor, so an implicit drop would leave them running, and a
            // `KERN_GATE_FD` left set would make the next attempt's gate refuse to arm.
            drop(egress_gate);
            drop(egress_guard);
            drop(egress_pending);
            // WHY IT DIED, WHEN THE CGROUP KNOWS. A box that hit its pids cap does not say so: the
            // kernel refuses the fork or the thread with `EAGAIN` and the workload reports whatever
            // it makes of that, which is rarely the truth. MEASURED on Sentry's ClickHouse under
            // kern's default cap of 512: it aborts with "Couldn't get 512 threads from global thread
            // pool: Not enough threads. Please make sure max_thread_pool_size is considerably bigger
            // than background_schedule_pool_size" - a sentence about ClickHouse's own settings,
            // produced by a limit kern applied and never mentioned, on a stack whose compose file
            // asks for no such cap.
            //
            // `pids.events`'s `max` counts exactly those refusals, so this claims only what the
            // kernel counted, and only on a failing exit: a box that ends cleanly having once been
            // throttled has nothing to explain.
            if code != 0 {
                if let Some(Some((before, dir))) = pids_baseline.get() {
                    let after = kern_isolation::pids_denied_count_at(dir);
                    if let (Some(a), Some(b)) = (before, after) {
                        if b > *a {
                            // WRITTEN TO THE LOG FILE BY PATH, NOT TO STDERR, and that is the whole
                            // difference between a diagnostic and a defect.
                            //
                            // By the time this runs the workload is gone and this process's stderr
                            // is the log PUMP's pipe, whose reader can be gone with it. `main` sets
                            // `SIGPIPE` to `SIG_DFL` (so `kern … | head` behaves like a Unix tool),
                            // so that write KILLS this process - and the supervisor then records
                            // `128 + 13 = 141` as the box's exit, replacing whatever the workload
                            // meant to say.
                            //
                            // MEASURED, and it was exactly this message: a box whose init does
                            // `trap 'exit 7' TERM` recorded 141 instead of 7, reproducibly at 28-way
                            // test parallelism and never below 8; with the message removed the suite
                            // passed 116/116 twice; an instrumented supervisor named the signal
                            // (`sig=13`, no core). The line goes where a reader looks for it -
                            // `kern logs` - and reaches it through the file rather than the pipe.
                            let line = format!(
                                "kern: box '{}': the kernel refused a fork or a thread because a \
                                 pids cap was reached while it ran ({} refusal(s) in kern's \
                                 cgroup). A box gets a pids cap it cannot exceed; raise it with \
                                 `--pids-limit <n>` (compose: `pids_limit:`) if the workload needs \
                                 more tasks - ClickHouse, a JVM and an Elasticsearch node all ask \
                                 for more than the default.\n",
                                name.as_str(),
                                b - a
                            );
                            if let Some(path) = log_path.as_deref() {
                                use std::io::Write;
                                if let Ok(mut f) =
                                    std::fs::OpenOptions::new().append(true).open(path)
                                {
                                    let _ = f.write_all(line.as_bytes());
                                }
                            }
                        }
                    }
                }
            }
            if have_latch {
                let verdict = [
                    kern_isolation::box_workload_signal(),
                    u8::from(kern_isolation::box_was_oom_killed()),
                    kern_isolation::box_workload_started(),
                ];
                // SAFETY: `latch[1]` is this process's own pipe end and `verdict` lives on this frame.
                let _ = unsafe { libc::write(latch[1], verdict.as_ptr().cast(), verdict.len()) };
            }
            unsafe { libc::_exit(code) };
        }
        if have_latch {
            // SAFETY: the supervisor's copy of the write end; the runner holds its own.
            unsafe { libc::close(latch[1]) };
        }
        // Supervisor: drop our readiness-pipe copy so the launcher sees EOF when the box exec()s.
        if attempt == 0 && have_pipe {
            unsafe { libc::close(wr) };
        }
        // And drop the cap-notice channel, for the neighbouring reason: the FIRST attempt is the one
        // whose notices a launcher is still there to read. Past it the launcher has returned, nothing
        // drains that pipe, and a `--restart` box would write its notices into a buffer until the
        // write blocked - inside the attempt, with the box not yet forked. The runner we just forked
        // keeps its own copy and closes it as soon as the start is past the notices
        // (`disarm_launcher_notice` in `run_in_sandbox_with`), so attempt 0 still reports in full.
        if attempt == 0 {
            kern_isolation::disarm_launcher_notice();
        }
        // A fatal signal must not cost the box its exit record: swallow the first one and keep waiting,
        // so this process lives long enough to reap the box and write the record below.
        //
        // MEASURED on an Arduino UNO Q (systemd 257): a DETACHED box past its `--memory` cap left NO
        // record at all - `kern ps -a` empty, `kern wait` answering "no exit record for one" - because
        // that manager's `OOMPolicy=stop` stops the scope on the OOM and its SIGTERM killed the
        // supervisor before it could write one. A Raspberry Pi 5 (252) and a Jetson (249) recorded 137
        // for the same box. The record a box leaves behind should not depend on the manager's version.
        //
        // It does NOT relay the signal inwards: the box is signalled directly (`kern stop` signals the
        // box's process group, which the runner and PID 1 are in), and relaying it was measured to
        // record 143 for an OOM-killed box - kern's own SIGTERM beating the kernel's `oom.group`
        // SIGKILL to the workload. `kern stop`'s phase-2 SIGKILL is uncatchable and unaffected, and a
        // second signal exits immediately - see `keep_waiting_through_signals`.
        kern_isolation::keep_waiting_through_signals();
        let mut st = 0i32;
        let code = if runner > 0 && crate::eintr::waitpid(runner, &mut st, 0) > 0 {
            if libc::WIFEXITED(st) {
                libc::WEXITSTATUS(st)
            } else if libc::WIFSIGNALED(st) {
                128 + libc::WTERMSIG(st)
            } else {
                1
            }
        } else {
            1 // fork or waitpid failed - treat as a failure, don't spin
        };
        // The runner has exited, so its end is closed and this read cannot block on it.
        last_verdict = (0, false);
        // The third byte: whether the workload was exec'd (0 unknown, 1 ran, 2 never started).
        let mut workload_started = 0u8;
        if have_latch {
            let mut v = [0u8; 3];
            // SAFETY: `latch[0]` is this process's read end, `v` lives on this frame.
            let n = unsafe { libc::read(latch[0], v.as_mut_ptr().cast(), v.len()) };
            if n >= 2 {
                last_verdict = (v[0], v[1] != 0);
            }
            if n == 3 {
                workload_started = v[2];
            }
            unsafe { libc::close(latch[0]) };
        }
        last_ran_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        // A box that stayed up past the stabilisation window counts as RECOVERED: clear the backoff
        // counter so a later, unrelated exit restarts promptly (1 s) instead of inheriting the escalated
        // 30 s from a crash loop that has long since healed - and, for `on-failure`, so the retry budget
        // measures CONSECUTIVE rapid failures (Docker's contract), not lifetime exits. 10 s matches
        // Docker's reset window. The `max_restarts` cap still bounds a genuine tight crash loop.
        if started.elapsed() >= std::time::Duration::from_secs(10) {
            attempt = 0;
        }
        // Saturating, not `+=`: `always` restarts forever, so `attempt` is unbounded; a `+= 1` would
        // panic on overflow in a debug build (the one exception to this codebase's panic-free rule) and
        // wrap in release. At one restart / 30 s the cap is ~4000 years, but the guarantee should not
        // depend on the build profile. Cost is identical.
        attempt = attempt.saturating_add(1);
        // A BOX THAT NEVER STARTED IS NOT A WORKLOAD THAT EXITED, and `always` is a promise about a
        // workload. 125 is kern's own box-not-started convention (and Docker's), used as the
        // discriminator elsewhere in this file; under `always` it was restarted forever, so a stack
        // whose `up` died left its surviving boxes rebuilding a box that could not be built. MEASURED
        // by a later pass bringing up Immich, 26 iterations for one service and 15 for
        // another, each logging "never released: the launcher closed the pre-exec gate without
        // releasing this box - the workload did not run"; reproduced here by pointing one service at
        // an image that cannot be pulled. Docker does not restart a container it could not create.
        //
        // BOUNDED, NOT FORBIDDEN, because not every 125 is permanent: a bind source that appears a
        // second later, a peer that is still writing the pod's network. So the same budget `on-failure`
        // uses applies, and when it runs out the box says why instead of stopping silently.
        // FROM THE EXEC WITNESS WHEN THERE IS ONE, and from the code only when there is not (the
        // first attempt, whose readiness pipe is the launcher's). 125 alone cannot tell a box that
        // could not be built from a workload that exits 125 on purpose, and the second was being
        // counted as the first (reported: `exit 125` from `sh -c` read as "never started").
        let never_started = match workload_started {
            1 => false,
            2 => true,
            _ => code == 125,
        };
        // 125 is "the box was not built", 126/127 "its command could not be executed": in all
        // three the launcher explains the failure FROM the log. A workload exiting 126 or 127 on
        // its own keeps its log too, which costs space and never a reason.
        ran_once |= !matches!(code, 125..=127);
        // AND ONE 125 IS PERMANENT, so it does not get a budget: the launcher closed this box's gate
        // without releasing it, and the process that would write that byte has exited. Asked only
        // when the gate is still in force for retries (`!gate_dropped`), because once it is dropped a
        // retry execs without it and the answer would be about a gate nobody consults.
        let gate_shut = never_started && !gate_dropped && gate_can_still_release() == Some(false);
        let restart_now = !gate_shut
            && should_restart(
                code,
                restart.always,
                restart.on_failure,
                attempt,
                max_restarts,
            );
        if gate_shut {
            eprintln!(
                "kern: box '{}' was never released and will not be retried: the launcher closed \
                 this box's pre-exec gate without releasing it, so no attempt can ever start. The \
                 reason is in the lines above this one",
                name.as_str()
            );
        } else if never_started && !restart_now && (restart.always || restart.on_failure) {
            // ONLY WHEN A POLICY RAN OUT. With no `--restart` there was ONE attempt and nothing to
            // give up on, and this said "never started 10 times in a row" after it (reported). The
            // count is the attempts actually made.
            eprintln!(
                "kern: box '{}' exited 125 {attempt} times in a row; not restarting it again. 125 is \
                 what a box that could not be built exits with, and a restart policy restarts a \
                 workload that ran: the reason is in the lines above this one",
                name.as_str()
            );
        }
        if restart_now {
            if never_started && workload_started == 0 {
                // NOT KNOWN WHICH: the first attempt's readiness pipe is the launcher's, so only the
                // code speaks, and 125 is both kern's "could not be built" and a workload's own
                // `exit 125`. Said as both rather than as the one it may not be. Later attempts
                // carry the exec witness and say which.
                eprintln!(
                    "kern: box '{}' exited 125 (the box could not be built, or its workload exits 125); \
                     retrying ({attempt}/{max_restarts})",
                    name.as_str()
                );
            } else if never_started {
                // NOT "(always)": that word promises forever, and this case is budgeted. The reader who
                // sees attempt 3 of 10 knows the loop ends, which is the whole difference from the log
                // a later pass watched go round 26 times.
                eprintln!(
                    "kern: box '{}' never started (exit 125); retrying ({attempt}/{max_restarts})",
                    name.as_str()
                );
            } else if restart.always {
                eprintln!(
                    "kern: box '{}' exited {code}; restarting (always)",
                    name.as_str()
                );
            } else {
                eprintln!(
                    "kern: box '{}' exited {code}; restarting ({attempt}/{max_restarts})",
                    name.as_str()
                );
            }
            // Exponential backoff, capped at 30 s: a service that never comes up settles at one attempt
            // every ~30 s instead of spinning at 1/s, bounding both the wasted work AND the restart-log
            // line rate (the detached box log is a fixed-size ring, but a slower rate is still better -
            // this is the same log-fill class already guarded elsewhere). Matches Docker's back-off
            // shape. `attempt` is >= 1 here (incremented above): 1, 2, 4, 8, 16, then 30 s thereafter.
            let backoff = (1u32 << attempt.saturating_sub(1).min(5)).min(30);
            // THE RUN THAT JUST ENDED IS RECORDED BEFORE THE BACKOFF, overwritten by the next one and
            // by the final one below. While the box is registered no reader shows it (`ps -a`
            // skips the record of a registered box); it is what a stop arriving between two runs reports, where
            // before it found no record and the service read as exit 0. MEASURED against Docker:
            // `up --abort-on-container-exit` on an `on-failure:3` service that exits 1 stops the
            // stack at the first exit, and the service's status is 1.
            if !rm && !never_started {
                adopt_current_name(inst);
                registry::set_box_exit(std::process::id() as i32, inst.starttime, code, inst);
            }
            registry::set_box_attempt(
                &inst.name,
                inst.pid,
                registry::Attempt::Restarting {
                    since_ms: registry::unix_ms(),
                    code,
                },
            );
            unsafe { libc::sleep(backoff) };
            // Read at the top of the next iteration to decide whether the pre-exec gate may be
            // dropped. See the block above the loop: dropping it after a box that NEVER STARTED
            // would exec a workload the launcher refused to release.
            last_code = Some(code);
            continue;
        }
        break code;
    };
    // Every record below is about the box as it is called NOW.
    adopt_current_name(inst);
    // The box has finished for good (no restart left). Record the final exit code for `kern wait`,
    // keyed `<name>-<pid>` (our own pid = the registered pid). Written LAST here, and this whole call
    // returns BEFORE the caller unregisters the instance file, so a `wait` that sees the box leave
    // `list()` finds the code. If compose is also waiting, record it under its stack+run-scoped key too.
    // `--rm` LEAVES NOTHING A LATER READER CAN FIND, which is what Docker's flag asks for: no `ps -a`
    // line, and a `kern wait` that starts after the box has gone finds no box. A wait ALREADY
    // waiting still gets the code, from a hidden record that expires (see
    // `registry::set_box_exit_removed`), as `docker wait` does. The compose exit key below is NOT
    // suppressed: it is a different record, scoped to a stack and read by `compose up`, and a
    // one-off's `--rm` must not make a stack lose a service's status.
    if rm {
        let log_key = format!("{}-{}", inst.name, std::process::id());
        registry::set_box_exit_removed(
            std::process::id() as i32,
            inst.starttime,
            final_code,
            ran_once.then_some(log_key.as_str()),
        );
    } else {
        registry::set_box_exit(std::process::id() as i32, inst.starttime, final_code, inst);
    }
    // A DETACHED BOX'S LINE IN THE HISTORY, from the last attempt: its run time measured here to the
    // millisecond, its signal and OOM verdict from the runner (see `latch`), its image, GPUs and
    // timeout from the record. A `kern stop` that ended it left a marker, and then the line says
    // `stopped` and is the only one.
    crate::history::record_owner_end(
        &inst.name,
        inst.pid,
        &crate::history::Observed {
            code: final_code,
            signal: last_verdict.0,
            oom: last_verdict.1,
            timeout_s: inst.timeout_s,
            ran_ms: last_ran_ms,
            image: &inst.image,
            gpu: &inst.gpus,
        },
    );
    if let Some(key) = &exit_key {
        registry::set_exit(key, final_code);
    }
    // `--rm` TAKES THE BOX'S LOGS WITH IT, as Docker removes a container's log with the container.
    // They were left in the log store (a tmpfs, in RAM) until a `kern prune`: MEASURED on a desktop,
    // 142 MiB of logs, all of boxes that had ended, one of them a `--rm` box. The pump may still
    // hold the active file open until its pipe closes; the unlinked file's space is freed then.
    // NOT FOR A BOX THAT NEVER STARTED: its launcher quotes the log's tail as the reason, after
    // this supervisor has exited, and taking it would leave "box failed to start" with no why.
    // Since 0.57.0 they go with the box's hidden record, after its follower's window (see
    // `registry::set_box_exit_removed`), and no reader but that follower sees them meanwhile.
    // A KEPT BOX REMEMBERS HOW ITS LAST RUN ENDED WHATEVER SHAPE THAT RUN HAD. The foreground arm
    // records it; this is the DETACHED one, and `-d` is the shape a kept box is most likely to have
    // (it is the attach-and-detach workflow the feature exists for). Without this the kept record
    // said "never ran" for ever, and `kern ps -a` printed the same box twice saying two different
    // things: `exit 137` in the transient exited section and "never ran" in the kept one, measured.
    // Best effort, like the records above: a code that could not be written costs a column.
    if let Some(dir) = crate::keepbox::dir_of(&inst.name) {
        if dir.is_dir() {
            crate::keepbox::set_exit(&dir, final_code);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_detached(
    name: &BoxName,
    // `--rm`: the supervisor writes no exit record at all. NOT WRITTEN rather than written and
    // deleted, because this box outlives the command that started it: there is no later moment in
    // the launcher at which to sweep, and a record that exists for a while is one `kern ps -a` can
    // report.
    rm: bool,
    spec: SandboxSpec,
    scratch: Option<PathBuf>,
    ports: &[kern_isolation::PortMap],
    volumes: &str,
    pod: &str,
    restart: bool,
    // Docker `always`/`unless-stopped` on a pod member: in-process supervisor, restart on ANY exit
    // (uncapped). Distinct from `restart` (on-failure). A standalone box uses the systemd path instead.
    restart_always: bool,
    health: HealthConfig,
    timeout: u64,
    // `--label k=v` metadata, comma-joined, recorded in the registry entry (see `Instance::labels`).
    labels: &str,
    // `--stop-signal` / `--stop-timeout`, recorded so a later `kern stop` (a different process) can
    // honour the shutdown contract the box was started with.
    stop_signal: i32,
    stop_grace: u64,
    // `--restart-max`: retry cap for the on-failure supervisor (0 = kern's default).
    restart_max: u32,
    // `--def-hash`: fingerprint of the compose definition, recorded for drift detection.
    def_hash: &str,
    // `--log-max-size` / `--log-max-file`, resolved by the caller so both detach paths share one.
    log_cap: crate::commands::boxlog::LogCap,
    // `--image` and `--gpus`, empty when absent: recorded in the registry so the box's line in the
    // sandbox history names them, whoever writes it.
    image: &str,
    gpus: &str,
    // The stack whose network NAT this box gets at its own gate ([`HeldNat`]); `None` for every
    // other box.
    outbound_pod: Option<&str>,
    // `--egress-allow` / `--egress-secret`, armed by the runner before every attempt.
    egress: Option<EgressPlan>,
) -> Result<(), Error> {
    // Readiness pipe: the read end stays in this foreground launcher; the write end travels down
    // to the box's PID 1 and is closed on a successful `execvp` (FD_CLOEXEC) → we read EOF = "the
    // box is up". If the box fails to set up or exec, it writes one byte first → we report a
    // truthful failure instead of a misleading "started". No sleep, no poll: the read returns the
    // instant the box is up or has failed, so the only added latency is the box's real start time.
    let mut fds = [0i32; 2];
    let have_pipe = unsafe { libc::pipe(fds.as_mut_ptr()) } == 0;
    let (rd, wr) = (fds[0], fds[1]);
    // A SECOND, SEPARATE PIPE, for the cap notices the box's own stderr cannot deliver.
    //
    // WHY A PIPE AND NOT THE LAUNCHER'S OWN STDERR. The first version of this handed the supervisor a
    // `dup` of fd 2 and let it write the notices there directly. It delivered them, and it also broke
    // every caller that waits for stderr to END: a duplicate of the launcher's stderr held open for
    // the box's whole life means the pipe behind it never reaches EOF, so `Command::output()` - the
    // Rust test harness, `compose up`, any script doing `kern box -d 2>&1 | cat` - blocks until the
    // box exits instead of returning when the launcher does. MEASURED: 18 integration tests stopped
    // returning, and `kern box -d -- sleep 60 2>&1 | cat` never printed EOF (exit 124 under
    // `timeout 8`). My own check had written stderr to a FILE, where holding a descriptor costs
    // nothing and the defect is invisible.
    //
    // This pipe is nobody's EOF: the launcher DRAINS it at a known point (after the readiness pipe has
    // resolved, so the notices are already written) and never waits on it, and the supervisor keeps
    // its own read end so a write can never raise SIGPIPE at a launcher that has already exited.
    // Both ends are `FD_CLOEXEC` so no exec on this path - least of all the box's own - inherits a
    // descriptor that writes to the operator's terminal.
    let mut nfds = [0i32; 2];
    let have_notice = unsafe { libc::pipe2(nfds.as_mut_ptr(), libc::O_CLOEXEC) } == 0;
    let (notice_rd, notice_wr) = (nfds[0], nfds[1]);

    let child = unsafe { libc::fork() };
    if child < 0 {
        if have_pipe {
            unsafe {
                libc::close(rd);
                libc::close(wr);
            }
        }
        if have_notice {
            unsafe {
                libc::close(notice_rd);
                libc::close(notice_wr);
            }
        }
        return Err(Error::Sandbox("fork for detach failed".to_string()));
    }
    if child > 0 {
        // The launcher reads the notices and never writes them, so its write end goes now: the
        // supervisor's copy is the only one that matters, and one fewer descriptor is one fewer way
        // for this process to hold anything open.
        if have_notice {
            unsafe { libc::close(notice_wr) };
        }
        return await_box_started(
            name,
            child,
            rd,
            wr,
            have_pipe,
            restart || restart_always,
            have_notice.then_some(notice_rd),
            outbound_pod.is_some(),
            log_cap.keep,
            ports.iter().any(|p| !p.udp),
        );
    }
    // ── Supervisor ──
    // SAFETY (fork): kern is single-threaded (std + libc only, no runtime threads), so running
    // ordinary Rust - allocation, registry writes - after fork is sound. If a future change ever
    // spawns a startup thread, this child must be reduced to async-signal-safe calls (or re-exec).
    if have_pipe {
        unsafe { libc::close(rd) };
    }
    unsafe { libc::setsid() };
    let pid = std::process::id() as i32;
    // THE CHANNEL FOR WHAT THE BOX'S OWN STDERR CANNOT DELIVER. From `detach_stdio` below onwards,
    // this process's fd 2 IS the box's log file, so every cap notice kern prints during the start -
    // "the `--memory` you asked for is not enforced here", "the box runs UNCAPPED" - lands in a file
    // the operator was never told to read, and the only thing on their terminal is the green tick.
    // MEASURED on an independent host (2026-10-08) and reproduced here: identical box, identical
    // flags, the notice on the terminal in the foreground and nowhere in sight detached.
    //
    // The notices are written into the pipe the launcher drains (see its creation above for why it is
    // a pipe and not a `dup` of the launcher's stderr), and the supervisor DISARMS it right after
    // forking the first attempt - see `supervise_box` - so a `--restart` box cannot keep filling a
    // pipe nobody is draining any more.
    if have_notice {
        kern_isolation::arm_launcher_notice(notice_wr);
    }
    // Send the box's stdout/stderr to a per-box log file (so `kern logs` can show it).
    let log = registry::logs_dir()
        .ok()
        .map(|d| d.join(format!("{}-{}.log", name.as_str(), pid)));
    detach_stdio(log.as_deref(), log_cap);
    // `[kern] log_keep_ended`: a new log is being made, so the old ones are bounded now. After the
    // log is open, so this box's own file is the youngest in the store and never a candidate.
    let _ = registry::expire_ended_logs();
    let (cap_drop_all, cap_drops, cap_adds) = registry::cap_fields(&spec.caps);
    let mut inst = registry::Instance {
        name: name.as_str().to_string(),
        pid,
        pid1_recorded: 0,
        pid1_starttime: 0,
        rootfs: spec.root.clone(),
        command: crate::registry::command_line(&spec.command),
        started: registry::now_unix(),
        starttime: registry::proc_starttime(pid),
        ports: ports_summary(ports),
        volumes: volumes.to_string(),
        pod: pod.to_string(),
        workdir: spec.workdir.clone().unwrap_or_default(),
        run_as: spec.run_as,
        extra_gids: spec.extra_gids.clone(),
        egress: match &egress {
            None => String::new(),
            Some(e) if e.deny.is_empty() => e.allow.join(","),
            Some(e) => format!("{} deny {}", e.allow.join(","), e.deny.join(",")),
        },
        bridges: registry::encode_bridges(&spec.pod_bridges),
        log_driver: if log_cap.keep {
            String::new()
        } else {
            "none".to_string()
        },
        landlock_rw: spec.landlock_rw.join(","),
        labels: labels.to_string(),
        stop_signal,
        stop_grace,
        def_hash: def_hash.to_string(),
        memory_max: spec.memory_max,
        pids_max: spec.pids_max,
        cap_drop_all,
        cap_drops,
        cap_adds,
        // Same recorded posture as the foreground path: `exec` reproduces the box's own filter and
        // reapplies its own caps, never a value re-derived from the exec caller's environment.
        seccomp_mode: spec.seccomp_mode,
        no_new_privs: spec.effective_no_new_privs(),
        keep_groups: spec.keep_groups,
        image: image.to_string(),
        gpus: gpus.to_string(),
        timeout_s: timeout,
        apparmor: spec.apparmor.clone().unwrap_or_default(),
        cap_recorded: true,
        aa_recorded: true,
        seccomp_recorded: true,
        posture_corrupt: false,
        // Resolved once PID 1 is known (in the `on_started` callback below), so `list()` can tell an
        // orphaned box (this supervisor SIGKILL'd, PID 1 + forwarder still live) from an exited one.
        cgroup: String::new(),
        cgroup_id: None,
        orphaned: false,
    };
    let path = registry::register(&inst).ok();
    // See the sibling site above: the box's environment is recorded here because `kern exec` cannot
    // read it back from a workload running as a non-root user.
    registry::set_box_env(&inst.name, inst.pid, &spec.env);
    crate::runstats::record_box(); // count this box start for kern top's box-start rate
                                   // `--health-cmd`: a sidecar process that periodically probes the box and records its health for
                                   // `kern ps`. Lives in this supervisor's process group, so it's reaped on stop with everything else.
    let health_pid = health
        .into_owned()
        .and_then(|hc| spawn_health_checker(name.as_str().to_string(), pid, hc));
    // `--timeout N`: a watchdog that auto-stops the box N seconds after it starts (registry/scratch
    // cleaned up like `kern stop`). Cancelled below if the box exits on its own first.
    let timeout_pid = (timeout > 0)
        .then(|| spawn_timeout_stop(name.as_str().to_string(), pid, timeout))
        .flatten();
    // Run the box (re-registering with its PID 1 so `kern exec` can find it), restarting it per
    // `--restart`. Blocks for the box's whole lifetime.
    supervise_box(
        rm,
        name,
        &spec,
        have_pipe,
        wr,
        ports,
        Restart {
            on_failure: restart,
            always: restart_always,
            max: restart_max,
        },
        &mut inst,
        outbound_pod,
        egress.as_ref(),
    );
    // The box has ended: its log pump drains and exits while the rest of the teardown runs.
    crate::commands::boxlog::release_log_pump();
    // Box is gone - cancel the sidecars and reap them (they're our children; setsid doesn't change
    // parentage) so we don't leave brief zombies behind before this supervisor exits.
    if let Some(tp) = timeout_pid {
        if signal_helper(tp, libc::SIGKILL) {
            crate::eintr::reap(tp);
        }
    }
    stop_health_checker(health_pid, name.as_str(), pid);
    if let Some(p) = path {
        leave_registry(&p);
    }
    registry::clear_box_dirs(name.as_str());
    cleanup_scratch(scratch.as_deref());
    unsafe { libc::_exit(0) };
}

/// `--restart always|unless-stopped` + `-d`: write and enable a systemd **user** unit that supervises
/// this box, so it restarts on any exit AND survives reboot - WITHOUT a kern daemon (systemd, already
/// running, is the supervisor). The unit re-runs THIS binary in the foreground with `KERN_MANAGED=1`
/// (which registers the box for `kern ps`/`logs`/`stop`); `enable --now` starts it immediately and
/// `enable-linger` makes it come up at boot without a login session. Resource caps (`--memory`,
/// `--cpus`, `--pids-limit`) are applied by systemd via the unit's own service cgroup.
fn install_persistent_box(
    name: &BoxName,
    policy: RestartPolicy,
    memory: Option<u64>,
    memory_swap_max: Option<u64>,
    cpus: Option<f64>,
    pids_max: Option<u64>,
) -> Result<(), Error> {
    let unit_name = unit_file_name(name.as_str());
    let self_exe = std::env::current_exe()
        .map_err(|e| Error::Sandbox(format!("cannot locate the kern binary: {e}")))?;
    // Rebuild the argv for the managed foreground run so systemd re-runs exactly this each start.
    // The DECIDED argv, for the same reason the scope re-exec uses it, and here the stakes are
    // higher: the typed form gets FROZEN into a unit file. A `docker run --restart …` would bake
    // docker syntax into a unit whose `ExecStart` names the resolved `kern` binary, so it would fail
    // at every boot, on a machine nobody is watching.
    let mut exec = vec![systemd_quote(&self_exe.to_string_lossy())];
    let mut it = crate::invocation_args().into_iter().peekable();
    let mut past_sep = false;
    while let Some(a) = it.next() {
        // Strip kern's own `-d`/`--restart` only among the flags BEFORE the `--` command separator.
        // After `--` the tokens are the box command and must be re-run verbatim (a `-d` there is the
        // workload's argument, not kern's). This can't distinguish a flag from an identical flag
        // *value* before `--` (e.g. `--workdir -d`), but the CLI already parsed those - only the
        // command portion, which we now copy untouched, actually matters for the managed re-run.
        if !past_sep {
            match a.as_str() {
                "-d" | "--detach" => continue,
                "--restart" => {
                    if it.peek().is_some_and(|v| RestartPolicy::parse(v).is_some()) {
                        it.next();
                    }
                    continue;
                }
                "--" => past_sep = true,
                _ => {}
            }
        }
        // A newline/CR would break out of the quoted `ExecStart` line and could inject a systemd
        // directive. It can't come from a normal shell, so reject it rather than emit a corrupt unit
        // (defence in depth - don't rely on systemd itself rejecting the malformed unit).
        if a.contains(['\n', '\r']) {
            return Err(Error::Sandbox(
                "a newline in the command isn't allowed with --restart always \
                 (it would corrupt the systemd unit)"
                    .to_string(),
            ));
        }
        exec.push(systemd_quote(&a));
    }
    // [Service] body. `Restart=always` + `RestartSec=1` for both persistent policies (the
    // stop-survival nuance between `always`/`unless-stopped` is handled by `kern stop` removing the
    // unit). Resource caps go here so systemd's service cgroup enforces them for the managed run.
    let mut svc = String::from("Type=simple\n");
    svc.push_str(&format!("ExecStart={}\n", exec.join(" ")));
    svc.push_str("Environment=KERN_MANAGED=1\n");
    svc.push_str("Restart=always\nRestartSec=1\n");
    // On stop/restart, SIGTERM the kern wrapper (MainPID) so it tears the box down gracefully, then
    // SIGKILL anything still in the cgroup after a bounded grace - otherwise a box whose init ignores
    // SIGTERM (PID 1 in its own namespace) would stall the whole 90s default `TimeoutStopSec`.
    svc.push_str("KillMode=mixed\nTimeoutStopSec=10\n");
    if let Some(m) = memory {
        // Mirror `--memory-swap-max` (default 0 = swap off) so the RAM cap is a hard total, instead
        // of silently pinning swap to 0 and negating a `--memory-swap-max` the user did pass.
        svc.push_str(&format!(
            "MemoryMax={m}\nMemorySwapMax={}\n",
            memory_swap_max.unwrap_or(0)
        ));
    }
    if let Some(c) = cpus {
        svc.push_str(&format!(
            "CPUQuota={}%\n",
            ((c * 100.0).round() as u64).max(1)
        ));
    }
    if let Some(p) = pids_max {
        svc.push_str(&format!("TasksMax={p}\n"));
    }
    // `StartLimitIntervalSec=0` DISABLES systemd's start-rate limiter. Without it the default
    // (`StartLimitBurst=5` in `StartLimitIntervalSec=10s`) makes systemd give up and leave the unit in
    // `failed` after 5 restarts in 10s - and with `RestartSec=1` a service that crashes immediately hits
    // that in ~5s, so `--restart always` would silently STOP restarting. That contradicts the contract
    // (`always`/`unless-stopped` = restart on ANY exit, indefinitely, Docker's semantics) and the exact
    // "extremely reliable, up for days/weeks" case this path exists for. `on-failure`'s retry CAP is the
    // in-process supervisor's job (this systemd unit is only ever written for a persistent policy), so
    // disabling the limit here never removes a wanted bound - it makes "always" actually mean always.
    let unit = format!(
        "[Unit]\nDescription=kern box {name}\n{MANAGED_MARKER}={name}\n\
         After=network-online.target\nStartLimitIntervalSec=0\n\n\
         [Service]\n{svc}\n[Install]\nWantedBy=default.target\n",
        name = name.as_str(),
    );
    let dir = user_systemd_dir()?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::Sandbox(format!("cannot create {}: {e}", dir.display())))?;
    let path = dir.join(&unit_name);
    std::fs::write(&path, unit)
        .map_err(|e| Error::Sandbox(format!("cannot write {}: {e}", path.display())))?;
    // `enable-linger` so it starts at boot without a login session (best-effort - needs the session
    // bus); `enable --now` enables + starts it. systemd auto-loads a freshly-written unit on `start`,
    // so we SKIP the ~150ms `daemon-reload` in the common path and only fall back to it if the first
    // enable fails (e.g. a stale cached view of a same-named unit).
    let _ = std::process::Command::new("loginctl")
        .arg("enable-linger")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if !systemctl_user(&["enable", "--now", &unit_name]) {
        systemctl_user(&["daemon-reload"]);
        if !systemctl_user(&["enable", "--now", &unit_name]) {
            // Don't leave a dangling unit if we couldn't start it.
            let _ = std::fs::remove_file(&path);
            systemctl_user(&["reset-failed", &unit_name]);
            systemctl_user(&["daemon-reload"]);
            return Err(Error::Sandbox(
                "systemctl --user enable failed - is a `systemd --user` manager available for this user?"
                    .into(),
            ));
        }
    }
    // Feedback-first: `enable --now` returns success once the start is *dispatched*, so verify the
    // service actually came up rather than printing a "started" that might be a lie (e.g. a bad
    // ExecStart, an image that exits immediately). `is-active` is true for active|activating.
    if !systemctl_user(&["is-active", "--quiet", &unit_name]) {
        return Err(Error::Sandbox(format!(
            "the box unit was installed but didn't start - check `systemctl --user status {unit_name}` \
             (then `kern stop {}` to remove it)",
            name.as_str(),
        )));
    }
    println!(
        "started '{}' (systemd-managed · restart={} · survives reboot)",
        name.as_str(),
        policy.as_str()
    );
    println!(
        "  stop:   kern stop {name}\n  \
           status: systemctl --user status {unit_name}\n  \
           logs:   kern logs {name}",
        name = name.as_str(),
    );
    Ok(())
}

/// Should `kern run` fork a supervisor for its workload, rather than `exec()` in place?
///
/// A pure function of the two facts that decide it, so all four combinations are asserted without a
/// cgroup filesystem. It is the single definition: the SAME value is passed to `apply_limits` as
/// `supervisor_forks_workload`, and the two disagreeing is a cap escape in one direction (this
/// process outside the leaf, and the workload exec'd in place there too) or a leak in the other.
///
/// `outer_enforcer` means kern's own scope proxy, a `--restart` unit or a build step already owns
/// this workload: it waits, reports and cleans up, so a second supervisor buys nothing.
/// `cap_built` means a capped leaf actually exists; with none there is nothing to be inside, nothing
/// to reap and nothing to remove.
pub(super) const fn run_should_fork(outer_enforcer: bool, cap_built: bool) -> bool {
    cap_built && !outer_enforcer
}

/// Fork the workload into the capped leaf and stay behind as its supervisor.
///
/// WHY A FORK IS REQUIRED AT ALL. A cgroup leaf kern created is a plain directory: the only thing
/// that can `rmdir` it is a kern process that outlives the workload, and `exec()`ing in place leaves
/// none. Where an outer enforcer exists that process already exists too (the scope proxy, and
/// `systemd-run --collect` on top of it), and this is a no-op. Where it does not - a host with no
/// systemd user manager, which is the configuration of the WSL rootfs this project publishes - there
/// was nothing, and a later pass measured 200 sequential `kern run` leaving 201 directories behind.
///
/// The fork buys three things on that host, not one: the leaf is removed, the workload's exit code
/// and signals are still propagated by a process that survives it, and an OOM kill is EXPLAINED
/// instead of surfacing as the shell's bare `Killed`.
///
/// WHERE IT FORKS, this returns in the CHILD only, with `None`: the guard belongs to the parent,
/// which is the process that removes the directory, and the parent never returns - it proxies, reaps,
/// drops the guard and exits with the workload's code. Where it does not fork it hands `cg` straight
/// back untouched, so those paths are byte-for-byte what they were, and a failed fork returns `None`
/// after saying so, because the command still runs and it will run uncapped.
///
/// COST: one `clone3` and one `waitpid`. The process TOPOLOGY does not change on the scope path -
/// `kern run` was already `caller -> kern -> workload` there, because that path's own fork+proxy put
/// a resident kern between them (verified by walking `/proc/<pid>/stat` from inside the workload).
fn fork_workload_under_caps(
    outer_enforcer: bool,
    cg: Option<kern_isolation::CgroupGuard>,
) -> Option<kern_isolation::CgroupGuard> {
    // NOT FORKING: stay a single process, and hand the guard BACK rather than drop it. The difference
    // is a cap escape. On those paths this process IS the workload and sits INSIDE the capped cgroup
    // (`supervisor_forks_workload` was false), so `CgroupGuard::drop` would move it back to `origin` -
    // out of its own memory ceiling, one line before the `execve`. The caller `mem::forget`s it for
    // exactly that reason.
    if !run_should_fork(outer_enforcer, cg.is_some()) {
        return cg;
    }
    let Some(guard) = cg else {
        // UNREACHABLE BY CONSTRUCTION: `run_should_fork` returned true, and its `cap_built` input was
        // `cg.is_some()`. Written as a branch rather than an `expect`, because this codebase does not
        // put a panic on a path it can express as a value, and `None` is the correct value anyway:
        // with no cap there is nothing to reap and nothing to remove.
        return None;
    };
    // The same invariant the scope path's fork asserts, for the same reason: the child runs Rust that
    // allocates (the `Command` argv, the Landlock ruleset) after the fork, which is safe only while
    // this process is single-threaded, since a lock held by another thread at fork time is copied
    // HELD into a child that will never see it released.
    debug_assert!(
        single_threaded(),
        "kern run's fork must stay single-threaded (no thread spawned before it)"
    );
    let (pid, placed) = kern_isolation::fork_workload_into_leaf(&guard);
    if pid < 0 {
        // The fork failed. Keeping the guard and exiting would be worse than continuing: `exec()` in
        // place still runs the command, and this process is NOT in the capped leaf (the supervisor
        // stays outside on this path), so the command would run uncapped. Say so, drop the guard so
        // the empty leaf does not survive us, and let the caller exec.
        eprintln!(
            "kern: warning: could not fork to place the command under its resource caps ({}) - the \
             command runs UNCAPPED.",
            std::io::Error::last_os_error()
        );
        drop(guard);
        return None;
    }
    if pid == 0 {
        // CHILD: this process becomes the workload.
        if !placed {
            // `kern run` is a cooperative GOVERNOR, not an isolation boundary, so this warns where
            // `kern box` refuses - the same split the `cg.is_none()` branch above already applies.
            // Written with one `write(2)` on a `const` slice rather than `eprintln!`: this is between
            // a fork and an exec, and the rule this codebase keeps there is that nothing allocates,
            // takes a lock or formats a string.
            const MSG: &[u8] = b"kern: warning: the command could not be placed in its cgroup, so \
                it runs outside the requested resource caps\n";
            unsafe { libc::write(2, MSG.as_ptr().cast(), MSG.len()) };
        }
        // The PARENT owns the guard. Leaking it here (rather than dropping it) is the point: `Drop`
        // would `rmdir` the leaf this very process is running in.
        std::mem::forget(guard);
        return None;
    }
    // PARENT: proxy the workload, then remove the leaf. `box_dir` is the workload's OWN cgroup, so the
    // OOM counter this reads is the workload's and not a shared ancestor's.
    //
    // AND THE SWEEP, HERE, BECAUSE THIS VERB HAD NOWHERE ELSE TO PUT IT. `kern run`'s leaf is removed
    // by the `drop` below on every ordinary exit, so the only way one is left behind is a parent that
    // died without running it - a SIGKILL, an OOM, a power cut. `kern box` self-heals that through
    // `sweep_orphans_off_hot_path`, called by its launcher AFTER the box is spawned; until now nothing
    // on the `run` path called it at all, so on a machine that only ever runs `kern run` those leaves
    // accumulated until a `kern box` or a `kern gc` came along. This process is about to block in
    // `waitpid` for the whole workload, so the work is free: it overlaps the run instead of preceding
    // it, which is the same reason the box path moved it off ITS start path (193 us with 61 entries,
    // measured). Passed as the overlap closure so it lands after the signal handlers are armed.
    let code = proxy_child_to_exit(pid, Some(guard.box_dir()), || {
        kern_isolation::sweep_orphans_off_hot_path();
    });
    // EXPLICIT, and it has to be, because `std::process::exit` does NOT run destructors: an implicit
    // drop at the end of this function would never happen. This is the `rmdir` that the systemd
    // `--collect` used to perform, and it is the whole justification for the direct path.
    drop(guard);
    std::process::exit(code);
}

/// Put this process in the transient scope `unit` with the `-p Key=Value` properties `props` (the
/// list built for `systemd-run`, `-p` included), asked of the manager over D-Bus from here
/// (`kern_isolation::sdbus`). `true` once this process runs in it: kern then goes on as the
/// re-executed kern would, `KERN_SCOPE` set and the scope's supervisor leaf prepared.
///
/// MEASURED on WSL Ubuntu with systemd, from a session outside the user's subtree, medians of 30:
/// `systemd-run --user --scope` 5.94 ms and then kern started again inside it, against 2.87 ms for
/// the same `StartTransientUnit` asked from the process. `false`, with nothing changed, on any
/// failure or any property it cannot type, and the caller takes `systemd-run` as before: the worst
/// this costs is the time the attempt took.
fn scope_natively(unit: &str, props: &[String]) -> bool {
    // The way back to `systemd-run` for every scope, for a host where this misbehaves and for an
    // A/B of the two with the same binary.
    if kern_common::env_flag("KERN_SCOPE_VIA_SYSTEMD_RUN") {
        return false;
    }
    let typed: Option<Vec<kern_isolation::sdbus::Prop>> = props
        .iter()
        .filter(|p| p.as_str() != "-p")
        .map(|p| kern_isolation::sdbus::prop_of(p))
        .collect();
    let Some(typed) = typed else {
        return false;
    };
    let runtime = kern_isolation::manager_env()
        .map(std::path::Path::to_path_buf)
        .or_else(|| crate::global_env("XDG_RUNTIME_DIR").map(std::path::PathBuf::from));
    let system = kern_isolation::systemd_scope_mode() == "--system";
    match kern_isolation::sdbus::start_scope_for_self(system, runtime.as_deref(), unit, &typed) {
        Ok(()) => {
            crate::set_global_env("KERN_SCOPE", "1");
            kern_isolation::prepare_delegated_scope();
            true
        }
        Err(e) => {
            if kern_common::env_flag("KERN_DEBUG_SCOPE") {
                eprintln!(
                    "kern: debug: scope over D-Bus not made ({}); systemd-run instead",
                    e.0
                );
            }
            false
        }
    }
}

/// Re-run this invocation inside a BARE transient user scope, so the command it is about to run can
/// be placed in the box's cgroup. Returns only if that could not be arranged, leaving the caller on
/// the path it was already taking.
///
/// WHY THIS EXISTS, and why the answer used to be a sentence instead of code. `kern exec` refused
/// outright on every host that runs kern outside the tree it delegates - a shell in `/init.scope`,
/// which is how WSL starts every terminal, and an ordinary `ssh` session on Ubuntu 24.04, Fedora 44,
/// Debian 13 and Rocky 10.2 alike. The refusal told the reader to re-enter with
/// `systemd-run --user --scope bash` and run kern in that shell, which works and keeps the caps
/// enforced. kern now does that for them, for one invocation, instead of asking.
///
/// ⛔ A BARE SCOPE, WITH NO RESOURCE PROPERTIES, and that is the difference from the box path.
/// `kern box` puts its caps ON the scope because there the scope IS the enforcement. An exec has no
/// caps of its own: it inherits the box's the moment it is placed in the box's cgroup, which is the
/// whole point of getting here. A `MemoryMax=` on this scope would cap the command at a number the
/// box never asked for, and the cap would not even be the box's.
///
/// The unit is named `kern-exec-<pid>.scope`: not `kern-box-*`, which the registry records as a
/// box's own cgroup, and ending in `<pid>.scope` so `sweep_orphan_boxes`, which reads the last `-`
/// field as a pid, never parses it as one. `--collect` reaps it when the command exits.
fn reexec_exec_in_bare_scope() {
    use std::os::unix::process::CommandExt;

    // Asked from this process first: no `systemd-run`, no second start (see `scope_natively`).
    if scope_natively(&format!("kern-exec-{}.scope", std::process::id()), &[]) {
        return;
    }
    let Ok(self_exe) = std::env::current_exe() else {
        return;
    };
    let args: Vec<String> = crate::invocation_args();
    let systemd_run = kern_isolation::trusted_helper("systemd-run")
        .unwrap_or_else(|| std::path::PathBuf::from("systemd-run"));
    let unit = format!("--unit=kern-exec-{}.scope", std::process::id());
    let mut cmd = std::process::Command::new(systemd_run);
    // The manager through `/run/user/<uid>` when `XDG_RUNTIME_DIR` points elsewhere, and the
    // caller's own runtime dir handed back to the re-executed kern (see `manager_env`).
    cmd.envs(kern_isolation::manager_envs())
        .arg(kern_isolation::systemd_scope_mode())
        .args(["--scope", "--quiet", "--collect"])
        .args(kern_isolation::scope_no_expand_arg())
        .args(kern_isolation::manager_setenv_args())
        .arg(&unit)
        .arg("--")
        .arg(self_exe)
        .args(&args)
        .env("KERN_SCOPE", "1");
    // The same TOCTOU floor the box path keeps, and for the same reason: `current_exe`,
    // `trusted_helper` and the arg building above are a gap in which a session teardown could take
    // the user manager with it. Re-probe ADJACENT to the execve, with no blocking I/O between. If it
    // vanished, return and let the caller refuse in kern's own words rather than replace kern with a
    // `systemd-run` that is about to fail and speak for it.
    if !kern_isolation::user_systemd_present() {
        return;
    }
    // REPLACE, not fork-and-wait. `kern exec` exits with the command's own status - that contract is
    // older than this path and `compose exec` depends on it - and `systemd-run --scope` propagates
    // the status of what it runs, so an `exec()` keeps it exactly. A proxy process in the middle
    // would also sit between a `-it` session and its terminal, which is a cost with no gain here.
    let _ = cmd.exec();
}

fn reexec_in_scope_if_possible(p: ScopeReexec) {
    use std::os::unix::process::CommandExt;

    let ScopeReexec {
        memory,
        memory_swap_max,
        cpuset,
        cpus,
        pids_max,
        allow_direct,
        die_with_parent,
        allow_uncapped,
    } = p;

    if kern_common::env_flag("KERN_SCOPE") {
        return; // already inside our scope
    }
    // Honest heads-up (a warning, NOT a refusal): the user asked for `--memory` but this kernel
    // doesn't expose the cgroup v2 `memory` controller to us, so the cap is accepted-but-never-bites.
    // True on Microsoft's DEFAULT WSL2 kernel and a stock Raspberry Pi OS (no `cgroup_enable=memory`)
    // - the SAME limitation Docker/Podman hit there; it's the environment, not kern. Isolation
    // (namespaces + seccomp) is unaffected - ONLY the resource cap is. Printed once, in the original
    // invocation (the scope re-exec returned above), and never on a normal host, where the controller
    // IS available up the tree so `memory_cap_enforceable()` is true.
    // A box ALWAYS carries a memory cap, the default 512 MiB when none is typed, so "the cap cannot
    // be enforced" is true of every box on such a host and not only of the ones that asked. Gating
    // this on the REQUEST left the common case silent: a default box on a host that does not
    // delegate the controller ran with unbounded RAM and said nothing, and a later pass
    // reported the limits as "soft" with no way to tell a degraded host from a degraded runtime.
    //
    // What kept it that way is a real objection: a line on every 2 ms box start is noise that trains
    // the reader to skip it. The resolution is that this is a HOST fact and not a box fact, so it is
    // stated once per host. An explicit request keeps its per-invocation warning, because asking for
    // `--memory 256m` and silently not getting it is a different failure from starting a default box.
    if !allow_uncapped
        && crate::global_env("KERN_BUILD_STEP").is_none()
        && !kern_isolation::memory_cap_enforceable()
    {
        let asked = memory.is_some() || memory_swap_max.is_some();
        if asked || claim_uncapped_host_notice() {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                let what = if asked { "--memory is" } else { "resource caps are" };
                eprintln!(
                    "kern: warning: {what} not enforced on this host - the kernel doesn't delegate \
                     the cgroup v2 `memory` controller (Microsoft's default WSL2 kernel, or Raspberry Pi \
                     OS without `cgroup_enable=memory`). The box still runs and stays isolated \
                     (namespaces + seccomp), but its RAM is UNCAPPED, including the 512M default. \
                     Fix on WSL: add `kernelCommandLine = cgroup_enable=memory cgroup_memory=1` under \
                     `[wsl2]` in `%UserProfile%\\.wslconfig`, then `wsl --shutdown`. Same limit as \
                     Docker/Podman here. `kern doctor` reports it every time; this line prints once."
                );
            });
        }
    }
    if kern_common::env_flag("KERN_NO_SCOPE") {
        // Opt-out fast path: skip the systemd transient scope (which costs a `systemd-run` spawn +
        // a D-Bus round-trip + a second kern re-exec). Resource caps then fall through to the
        // best-effort cgroup path (same as when no user systemd is present). For latency-critical
        // callers (e.g. an agent dev loop firing many short boxes) that accept best-effort instead of
        // hard-delegated caps.
        //
        // "Best-effort" can mean NONE, and it says so now. Measured on a Raspberry Pi 5 (2026-07-30):
        // the scope costs 13.7 ms of a 15.5 ms box there, so the opt-out looks like free speed, and it
        // is not. With it set, `--memory 256m` left `memory.max` at `max`, `--pids-limit 30` left
        // `pids.max` at `max`, and a workload 3x over its RAM cap exited 0 instead of 137: on that
        // board the scope IS the enforcement, because no delegated slice is available to write to.
        // kern printed nothing at all. Accepting a cap and not enforcing it is the one thing this
        // codebase refuses to do quietly, and this was the last place it still did.
        //
        // NO WARNING IS EMITTED HERE, and the reason is the whole of the defect above. This point is
        // BEFORE the box exists: `apply_limits` has not run, no `kern-box-*` cgroup has been created,
        // and whether the direct path will succeed is not yet known. The sentence this code used to
        // print, that the caller's own chain "is also the one the box will inherit, since the opt-out
        // skips the scope entirely", is simply false: the opt-out skips the SCOPE, not the direct
        // cgroup, and the box lands in a `kern-box-*` leaf of its own either way.
        //
        // MEASURED on x86_64 with `KERN_NO_SCOPE=1 --memory 256m`: this printed "accepted but NOT
        // enforced here - the box can exceed it" while the box's cgroup held `memory.max=268435456`
        // and a 400 MB load was killed with exit 137. A false red, from the same mistake as the one
        // it was meant to report: answering about the box from a vantage that is not the box.
        //
        // The Pi finding this block was written for is unchanged and still reported, one layer down,
        // where the answer is knowable: `kern box` warns from `real.rs` after `apply_limits`, against
        // the box's own cgroup, and `kern run` warns from its own `cg.is_none()` branch above. Both
        // now speak only about a cgroup that exists.
        return;
    }
    // Gate on a running user manager (so the exec can't strand us in a broken systemd-run). Probe ONCE
    // and reuse for `choose_direct_cap_path_given` just below - the two are adjacent (no exec/fork/I/O
    // between), so a second `connect()` on `systemd/private` could only return the same answer. The
    // pre-exec re-probe far below stays a FRESH call: it guards a different, later instant (post arg
    // building), which is the whole point of the TOCTOU floor.
    if !kern_isolation::user_systemd_present() {
        return;
    }
    // REUSE INVARIANT: `manager_present` is trusted below (`choose_direct_cap_path_given`) WITHOUT a
    // second probe. That is sound ONLY because nothing between this gate and that call execs, forks, or
    // blocks on I/O - so the manager cannot have died in between. If you add such a call here, this
    // `true` goes stale: drop it and pass a FRESH `kern_isolation::user_systemd_present()` instead.
    // (Nothing enforces this mechanically; the invariant lives in this comment - do not break it.)
    let manager_present = true; // established by the gate above; reused to avoid a redundant probe
                                // FAST PATH (box only): if kern's delegated `kern.slice` is usable, SKIP the per-box `systemd-run
                                // --scope` and let `apply_limits` cap DIRECTLY under it - ~4 ms less/box, same hard kernel caps; a
                                // downstream fail-closed refuses the box if the cap doesn't bite, so it never silently runs uncapped.
                                // `choose_direct_cap_path` is THE decision site: it also rules out an outer enforcer
                                // (KERN_MANAGED/KERN_BUILD_STEP - their ancestor already caps, and `apply_limits` wouldn't use
                                // kern.slice anyway) and RECORDS the decision, so the fail-closed refusal downstream fires only
                                // when this return was actually taken - never on the `exec()`-failed fall-through below, which
                                // keeps its historical best-effort behavior. NOT for `kern run` (`allow_direct=false`): it
                                // exec()s in place with no supervisor to run the guard's Drop, so without the scope's
                                // `--collect` its `kern.slice/kern-box-run-*` cgroup would leak forever.
    if allow_direct && kern_isolation::choose_direct_cap_path_given(manager_present) {
        return;
    }
    // FROM HERE THIS PROCESS IS REPLACED (every path below ends in an `execve`), so an id map started
    // early for it would be left to a process image that never asked for it: stop it now. The
    // re-executed kern starts its own.
    kern_isolation::abandon_id_mapped_userns_early();
    let Ok(self_exe) = std::env::current_exe() else {
        return;
    };
    // THE ARGV KERN RAN, NOT THE ONE IT WAS TYPED IN: a `kern-docker` invocation arrived in docker's
    // dialect, and replaying that hands the second pass a syntax kern's parser rejects (measured:
    // `kern run: unknown flag` on every shim box of a host that takes the scope). See
    // `crate::invocation_args`.
    let args: Vec<String> = crate::invocation_args();

    // The scope's memory cap tracks `--memory` (so the outer scope never caps a box below what it
    // asked for); `--cpus` maps to a CPUQuota, `--cpuset-cpus` to AllowedCPUs. Swap tracks
    // `--memory-swap-max` (default 0 = hard cap) and TasksMax stays default.
    let mem_prop = format!("MemoryMax={}", scope_memory_max(memory));
    let swap_prop = match memory_swap_max {
        Some(b) => format!("MemorySwapMax={b}"),
        None => SCOPE_SWAP_MAX.to_string(),
    };
    let tasks_prop = match pids_max {
        Some(n) => format!("TasksMax={n}"),
        None => SCOPE_TASKS_MAX.to_string(),
    };
    let mut props: Vec<String> = vec![
        "-p".into(),
        mem_prop,
        "-p".into(),
        swap_prop,
        "-p".into(),
        tasks_prop,
    ];
    if let Some(c) = cpus {
        props.push("-p".into());
        // Floor at 1% - a sub-1% `--cpus` would round to `CPUQuota=0%`, which systemd rejects,
        // silently dropping the whole scope (matches the persistent-unit path).
        props.push(format!("CPUQuota={}%", ((c * 100.0).round() as u64).max(1)));
    }
    // `cpuset` was checked against the host's online CPUs at the box/run entry (`check_cpuset`), so
    // it can't be an over-wide `0-9999` that systemd would reject with a raw "Failed to parse
    // AllowedCPUs", nor a CPU systemd would accept and not apply.
    if let Some(set) = cpuset {
        props.push("-p".into());
        props.push(format!("AllowedCPUs={set}"));
    }
    // Leave the OOM kill to the KERNEL, which kern has already told to take the whole box at once
    // (`memory.oom.group`). A newer manager's default `OOMPolicy=stop` answers that same kill by
    // stopping the unit - SIGKILL to the entire scope, including the supervisor that would have
    // recorded the box's exit code - so on systemd 257 an OOM-killed detached box left `kern wait` with
    // nothing to report, where 249 and 252 recorded 137. Gated on a PROBE, never on a version: an older
    // manager rejects the property and would fail `systemd-run` outright. See `scope_accepts_oom_policy`.
    if kern_isolation::scope_accepts_oom_policy() {
        props.push("-p".into());
        props.push("OOMPolicy=continue".into());
    }
    // The same scope, the same properties, asked from this process: kern goes on in it with no
    // `systemd-run` and no second start. A foreground box keeps its die-with-parent cascade with
    // nothing in between (launcher -> kern -> box), armed on this process as it was on the exec.
    if scope_natively(&format!("kern-box-{}.scope", std::process::id()), &props) {
        if die_with_parent {
            arm_pdeathsig();
        }
        return;
    }
    // Resolve `systemd-run` by trusted absolute path, NOT via `$PATH`: on a box start this spawn is on
    // the critical path, and a long user `$PATH` (cargo/nvm/local/…) makes the kernel try execve in each
    // dir until it finds it - several failed execves per box. The absolute path is one execve. (Same
    // trusted-bin policy as the id-map helpers.)
    let systemd_run = kern_isolation::trusted_helper("systemd-run")
        .unwrap_or_else(|| std::path::PathBuf::from("systemd-run"));
    // NAME the transient scope with kern's own prefix, instead of letting systemd pick
    // `run-p<pid>-i<id>.scope`. This is what makes a box on THIS path recoverable when its supervisor
    // is killed: the registry records a box's cgroup only when the path names a `kern-box-*` dir (see
    // `box_cgroup_dir`), deliberately, because on the scope path the box's cgroup can be a scope kern
    // did NOT create - `kern doctor` itself suggests `systemd-run --user --scope bash` to pay the
    // scope cost once, and every box started in that shell would share the shell's scope, so
    // recording it would let a later reap `cgroup.kill` the user's own session. Naming the scope
    // kern creates settles that by construction: an ambient scope is `run-*` and stays unrecorded, a
    // scope kern created is `kern-box-*` and is recorded with its `(dev, ino)` identity.
    //
    // MEASURED before this, on an Arduino UNO Q (rootless, user systemd, the scope path): SIGKILL a
    // box's supervisor and the box vanished from `kern ps` while four of its processes kept running,
    // with `kern stop <name>` answering "no running box". The direct-path host reaped the same box.
    //
    // The pid makes the unit unique per invocation, so a stale scope cannot make a later start fail
    // with "unit already exists"; `--collect` reaps the unit on exit regardless. The `.scope` suffix
    // is explicit rather than left to systemd, and it is also what keeps `sweep_orphan_boxes` off
    // this dir: that sweep reads the last `-` field as a pid, which `<pid>.scope` never parses as.
    let unit = format!("--unit=kern-box-{}.scope", std::process::id());
    let mut cmd = std::process::Command::new(systemd_run);
    cmd.envs(kern_isolation::manager_envs())
        .arg(kern_isolation::systemd_scope_mode()) // `--system` as root, else `--user`
        .args(["--scope", "--quiet", "--collect"])
        // NO `-p Delegate=yes` here, deliberately. kern DOES build a cgroup subtree inside this scope
        // (`prepare_delegated_scope`), which is what `Delegate=` is nominally for - but it does not need
        // the property: a user manager creates the scope's directory as the user, so it is already ours
        // to `mkdir` in (MEASURED `owner=1000` on systemd 249, 252 and 257, with the child cgroup, the
        // process move and the `cgroup.subtree_control` write all accepted without it).
        //
        // Asking for it anyway costs a box start: MEASURED per scope, `Delegate=yes` alone took a Jetson
        // Orin Nano (systemd 249) from 8 ms to 846 ms and an Arduino UNO Q (257) from 47 ms to 148 ms,
        // while the subtree kern actually builds costs ~2 ms on top of a bare scope. A 100x start-latency
        // regression to ask for permission already held is not a trade; the property stays off.
        .arg(&unit)
        .args(&props)
        // The caller's arguments verbatim: see `scope_no_expand_arg`.
        .args(kern_isolation::scope_no_expand_arg())
        // The box keeps the runtime dir of the world that started it while `systemd-run` reaches
        // the manager through `/run/user/<uid>` (see `manager_env`; `envs` below).
        .args(kern_isolation::manager_setenv_args())
        .arg("--")
        .arg(self_exe)
        .args(&args)
        .env("KERN_SCOPE", "1");
    // What `kern-docker` prints after the command (`docker run -d`: the container's name), which
    // this process will not live to print: the re-executed kern does. See `crate::PRINT_AFTER_ENV`.
    if let Some(text) = crate::invocation_print_after() {
        cmd.env(crate::PRINT_AFTER_ENV, text);
    }
    // Minimise the check-then-use window before the IRREVERSIBLE exec. The manager was probed earlier
    // in this function, but `current_exe`, `trusted_helper` and the arg building since then are a
    // gap in which the user manager could exit (a session teardown). Re-probe HERE, adjacent to the
    // execve with no blocking I/O between: a probe-then-exec TOCTOU cannot be zero, but this is its
    // floor. If the manager vanished, return to the best-effort in-process cgroup path rather than
    // `exec()` into a `systemd-run` that would then fail with no fallback - which would kill the box.
    // Building `cmd` above has no side effect (no spawn), so dropping it on this return is clean.
    if !kern_isolation::user_systemd_present() {
        return;
    }
    // A FOREGROUND box (die_with_parent) keeps the proven `exec()`. Its `PR_SET_PDEATHSIG(SIGKILL)`,
    // armed here and surviving the execve into `systemd-run`, drives the die-with-parent cascade
    // launcher -> systemd-run -> kern -> box that the SDK's per-request pattern relies on. The fork+proxy
    // fallback below CANNOT be used here: a systemd scope interposes on the process tree, and inserting a
    // proxy link between the launcher and `systemd-run` breaks that PDEATHSIG cascade (measured: the box
    // outlives its launcher). The sub-millisecond TOCTOU residual therefore stays on the foreground scope
    // path, where the launcher-death guarantee matters more than a race that does not occur in steady
    // state, and where the window is already at its floor (the re-probe above is adjacent to the exec).
    if die_with_parent {
        arm_pdeathsig();
        let _ = cmd.exec();
        return;
    }
    // DETACHED and `kern run` (no die-with-parent): FORK instead of exec, so a `systemd-run` that reaches
    // the manager and THEN fails - the sub-millisecond TOCTOU where the manager dies between the re-probe
    // above and here, or answers the probe but cannot create the scope - does not replace kern with no
    // way back and kill the box. The child execs `systemd-run`; the re-exec'd kern inside the scope
    // writes one byte to `KERN_SCOPE_READY_FD` from `main` the instant the scope is proven to exist. The
    // parent reads that pipe:
    //   - one byte => the scope was created and the box runs under `systemd-run` (our child) => become a
    //     transparent proxy: forward the catchable fatal signals to it, wait, and `exit` with its code (0
    //     for a detached box, whose re-exec'd kern forks the supervisor and returns so `systemd-run`
    //     exits at once; the workload's code for `kern run`). One thin resident process on the (already
    //     ~7-13 ms) scope path only, and there is no die-with-parent cascade to preserve here.
    //   - EOF => `systemd-run` died before the box started => reap it and RETURN, so `box_run`/`run`
    //     continue on the best-effort in-process cgroup path here instead of the box dying.
    // kern is single-threaded at box start (the pump/supervisor threads spawn later), so the fork plus
    // `Command::exec`'s argv/envp allocation in the child is safe here.
    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        // Cannot build the readiness pipe: keep the historical `exec()` (no fallback here, but no worse
        // than before this change). No PDEATHSIG: this path is `!die_with_parent`.
        let _ = cmd.exec();
        return;
    }
    let (read_fd, write_fd) = (pipe_fds[0], pipe_fds[1]);
    // The write end must survive the child's `execve` into `systemd-run` and reach the re-exec'd kern
    // (which writes the ready byte). Both ends are `O_CLOEXEC` from `pipe2`; the CHILD clears the flag on
    // the write end just before its exec (below), NOT here in the parent - so the parent never holds an
    // inheritable copy that some other `execve` between now and the fork could leak. The read end stays
    // CLOEXEC (the parent never execs). `systemd-run --scope` passes inherited fds through (verified).
    cmd.env("KERN_SCOPE_READY_FD", write_fd.to_string());

    // INVARIANT: kern is single-threaded here (the pump/supervisor threads spawn later, in
    // run_in_sandbox / run_detached), so the child may run `Command::exec`'s allocation after the fork
    // without an allocator-lock deadlock. A `thread::spawn` added before this point would break that;
    // the assert makes a regression fail a debug build instead of hanging a box on the scope path.
    debug_assert!(
        single_threaded(),
        "reexec fork must stay single-threaded (no thread spawned before it)"
    );
    match unsafe { libc::fork() } {
        -1 => {
            // Fork failed: close the pipe and keep the historical `exec()`.
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            let _ = cmd.exec();
        }
        0 => {
            // CHILD: exec `systemd-run`. Close the read end (only the parent reads), and clear the write
            // end's close-on-exec HERE - the last point before the execve, so the fd is inheritable in
            // the child alone. No PDEATHSIG on this path (`!die_with_parent`: detached / `kern run`).
            unsafe {
                libc::close(read_fd);
                libc::fcntl(write_fd, libc::F_SETFD, 0);
            }
            let _ = cmd.exec();
            // execve failed (systemd-run absent, etc.): close the write end so the parent reads EOF and
            // falls back, then exit without touching the box.
            unsafe {
                libc::close(write_fd);
                libc::_exit(127);
            }
        }
        child => {
            // PARENT (proxy): close the write end so our own read reaches EOF when the child chain closes
            // it, then proxy. No die-with-parent to preserve on this path (detached / `kern run`).
            unsafe { libc::close(write_fd) };
            scope_reexec_proxy(child, read_fd);
        }
    }
}

#[cfg(test)]
mod exec_user_tests {
    use super::{describe_id_map, exec_user_home, id_is_mapped, id_map_ranges};

    /// THE KERNEL'S RULE, READ FROM THE SAME MAP: an id is settable in the box when it falls inside an
    /// INSIDE range. Both shapes kern makes, plus the edges of each range and a line that is not
    /// three numbers.
    #[test]
    fn an_id_is_mapped_exactly_when_an_inside_range_holds_it() {
        let single = id_map_ranges("         0       1000          1\n");
        assert_eq!(single, vec![(0, 1)]);
        assert!(id_is_mapped(&single, 0));
        assert!(!id_is_mapped(&single, 1));
        assert!(
            !id_is_mapped(&single, 1000),
            "the OUTSIDE column is not the box's id"
        );

        let range = id_map_ranges("0 1000 1\n1 100000 65536\nnot a map line\n\n");
        assert_eq!(range, vec![(0, 1), (1, 65536)]);
        for id in [0, 1, 1000, 65534, 65536] {
            assert!(id_is_mapped(&range, id), "{id}");
        }
        assert!(!id_is_mapped(&range, 65537));
        assert!(!id_is_mapped(&range, u32::MAX));
        assert!(id_map_ranges("").is_empty());
        assert!(!id_is_mapped(&[], 0), "an empty map maps nothing");
        // A full-width range cannot overflow the check.
        assert!(id_is_mapped(&[(0, 4_294_967_295)], u32::MAX - 1));
    }

    /// The refusal says what the box DOES map, and for root alone, why and what gives it the rest.
    ///
    /// AND IT NAMES THE CAUSE THAT APPLIES. A field report measured the gap: a box started
    /// `--cap-drop ALL` maps uid 0 alone, and the sentence named `--no-uid-range` and a missing
    /// `/etc/subuid` entry, neither of which was the reader's. Both forms must still point at
    /// `--uid-range`, because that is the flag that fixes either one.
    #[test]
    fn the_refusal_names_what_the_box_maps() {
        let single = describe_id_map("uid", &[(0, 1)], false);
        assert!(single.contains("uid 0 alone"), "{single}");
        assert!(single.contains("--uid-range"), "{single}");
        assert!(
            single.contains("--no-uid-range") && single.contains("/etc/subuid"),
            "with capabilities, those are the two causes left: {single}"
        );
        assert!(
            !single.contains("--cap-drop"),
            "a box that HOLDS capabilities was not refused for dropping them: {single}"
        );

        let dropped = describe_id_map("uid", &[(0, 1)], true);
        assert!(dropped.contains("uid 0 alone"), "{dropped}");
        assert!(
            dropped.contains("--cap-drop ALL") && dropped.contains("--uid-range"),
            "the cause it can prove, and the flag that answers it: {dropped}"
        );
        assert!(
            dropped.contains("kern exec -u"),
            "the reader is here because of that command: {dropped}"
        );

        // A box that maps a range is described by the range, whatever its capabilities are: the
        // cause only exists for the single-id map.
        for no_caps in [false, true] {
            assert_eq!(
                describe_id_map("gid", &[(0, 1), (1, 65536)], no_caps),
                "which maps gids 0, 1-65536"
            );
        }
    }

    /// HOME follows the `-u` user unless the environment already set one that is not kern's own.
    #[test]
    fn exec_user_home_keeps_a_set_home_and_rederives_only_kerns() {
        let env = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        let node = "/home/node".to_string();
        // A root workload records no HOME: the user's passwd home.
        assert_eq!(
            exec_user_home(&env(&[]), &env(&[]), None, node.clone()),
            Some(node.clone())
        );
        // The image's `ENV HOME`, kept as Docker keeps `Config.Env`.
        assert_eq!(
            exec_user_home(&env(&[("HOME", "/app")]), &env(&[]), None, node.clone()),
            None
        );
        // kern's own HOME for a `--user node` workload, asked for root: re-derived.
        assert_eq!(
            exec_user_home(
                &env(&[("HOME", "/home/node")]),
                &env(&[]),
                Some("/home/node"),
                "/root".to_string()
            ),
            Some("/root".to_string())
        );
        // A non-root workload whose image set a HOME of its own: kept.
        assert_eq!(
            exec_user_home(
                &env(&[("HOME", "/srv")]),
                &env(&[]),
                Some("/home/node"),
                "/root".into()
            ),
            None
        );
        // The LAST recorded HOME is the one in force.
        assert_eq!(
            exec_user_home(
                &env(&[("HOME", "/app"), ("HOME", "/home/node")]),
                &env(&[]),
                Some("/home/node"),
                "/root".into()
            ),
            Some("/root".to_string())
        );
        // The caller's `-e HOME=` wins over everything, so nothing is added.
        assert_eq!(
            exec_user_home(&env(&[]), &env(&[("HOME", "/x")]), None, node),
            None
        );
    }
}

#[cfg(test)]
mod pod_dns_tests {
    use super::pod_nameservers;

    /// ONLY `nameserver` LINES, AND IN FILE ORDER.
    ///
    /// This is the fallback a pod member gets when it asked to change its `search` or `options` and
    /// nothing else: it must inherit the resolvers the rest of the stack is using, and nothing else
    /// from that file. Folding in a `search` line would emit it as an address, and `resolv.conf`
    /// silently skips a `nameserver` it cannot parse - so the box would end up with fewer working
    /// resolvers than the pod has, with nothing said anywhere.
    ///
    /// Order matters because glibc honours at most `MAXNS` (3) servers, top down: a reordering is a
    /// different resolver for anyone past the third line.
    #[test]
    fn pod_nameservers_reads_only_nameserver_lines_in_order() {
        let dir = std::env::temp_dir().join(format!("kern-resolv-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("resolv.conf");
        std::fs::write(
            &p,
            "# a comment\nsearch example.com\nnameserver 1.1.1.1\noptions ndots:2\nnameserver 9.9.9.9\n",
        )
        .expect("write");
        assert_eq!(
            pod_nameservers(&p),
            vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()]
        );

        // A file that names no resolver yields none, rather than something that looks like one.
        std::fs::write(&p, "search example.com\noptions ndots:2\n").expect("write");
        assert!(pod_nameservers(&p).is_empty());

        // A missing file is not an error here: a pod without outbound has no resolv.conf at all.
        assert!(pod_nameservers(&dir.join("nope")).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod image_defaults_tests {

    /// `restart: always` is a promise about a WORKLOAD, and a box that never started has none.
    ///
    /// MEASURED by a later pass on a real stack (Immich, one image that would not pull): the
    /// surviving services logged "never released: the launcher closed the pre-exec gate ... the
    /// workload did not run" and were restarted 26 and 15 times, unbounded, while `ps` showed them
    /// running. Reproduced here by pointing one service at an image that cannot be pulled.
    #[test]
    fn a_box_that_never_started_is_not_restarted_forever() {
        // 125 is kern's box-not-started code: budgeted even under `always`, and the budget ENDS.
        assert!(super::should_restart(125, true, false, 1, 10));
        assert!(super::should_restart(125, true, false, 10, 10));
        assert!(!super::should_restart(125, true, false, 11, 10));
        // ...and `on-failure` sees the same bound.
        assert!(!super::should_restart(125, false, true, 11, 10));
        // THE CONTROLS, or this would be "never restart anything". A workload that exits, for any
        // reason, keeps Docker's contract: `always` is uncapped, including a clean exit.
        assert!(super::should_restart(0, true, false, 9_999, 10));
        assert!(super::should_restart(1, true, false, 9_999, 10));
        assert!(super::should_restart(137, true, false, 9_999, 10));
        // `on-failure` restarts a failure within budget, never a success.
        assert!(super::should_restart(1, false, true, 10, 10));
        assert!(!super::should_restart(1, false, true, 11, 10));
        assert!(!super::should_restart(0, false, true, 1, 10));
        // and no policy means no restart at all, a box that never started included: it used to be
        // retried ten times, and `kern box -d` waited for every one of them.
        assert!(!super::should_restart(1, false, false, 1, 10));
        assert!(!super::should_restart(125, false, false, 1, 10));
    }

    /// The gate is asked whether a RETRY could still be released, and the pipe answers all four ways.
    ///
    /// WHY THIS TEST AND NOT A STACK: the state that separates "retry me" from "never" is whether a
    /// release byte is in the pipe, and in a real stack the losing case needs the box to die inside
    /// the window between the launcher's write and its own read - which is not a thing a test can
    /// arrange on demand. The pipe is the whole mechanism, so the pipe is what is falsified here.
    ///
    /// THE CONTROLS ARE THE POINT. Without the `POLLIN`-with-a-closed-writer row, "closed writer
    /// means never" would read as correct while silently discarding a box the launcher DID release.
    /// The gate of a box with `--egress-allow`: armed, it names its read end in `KERN_GATE_FD` for
    /// the box this process forks; released, that end reads ONE byte, which is the box's release;
    /// dropped unreleased (a pump that never listened, a launcher that died), it reads EOF, which
    /// the box's gate takes as refusal; and a launcher's gate already set is left alone. Read here
    /// from the descriptor the variable names, as the box reads it.
    #[test]
    fn the_egress_gate_releases_with_one_byte_and_refuses_with_eof() {
        let _g = crate::env_guard();
        crate::unset_global_env("KERN_GATE_FD");
        let read_named = || -> (isize, u8) {
            let fd: libc::c_int = crate::global_env_str("KERN_GATE_FD")
                .expect("an armed gate names its read end")
                .parse()
                .expect("a descriptor number");
            let mut b = [0u8; 1];
            // SAFETY: one byte into a local buffer from the descriptor the gate holds open.
            let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), 1) };
            (n, b[0])
        };
        let mut gate = EgressGate::arm().expect("no gate was set, so one is armed");
        gate.release();
        assert_eq!(read_named(), (1, 1), "a released gate holds one byte");
        gate.release();
        assert_eq!(
            read_named(),
            (0, 0),
            "released once: the write end is gone after it"
        );
        drop(gate);
        assert!(
            crate::global_env_str("KERN_GATE_FD").is_err(),
            "the gate's variable outlived it, and the next box would wait on a closed descriptor"
        );
        let unreleased = EgressGate::arm().expect("armed again");
        let fd: libc::c_int = crate::global_env_str("KERN_GATE_FD")
            .expect("named")
            .parse()
            .expect("a number");
        // SAFETY: a duplicate of the read end, so the read below outlives the gate's drop.
        let kept = unsafe { libc::dup(fd) };
        assert!(kept >= 0, "dup");
        let mut unreleased = unreleased;
        unreleased.write = None; // what its drop does first: the pump never said it listens
        let mut b = [9u8; 1];
        // SAFETY: one byte into a local buffer from a descriptor this test owns.
        let n = unsafe { libc::read(kept, b.as_mut_ptr().cast(), 1) };
        // SAFETY: the duplicate this test made.
        unsafe { libc::close(kept) };
        assert_eq!(
            n, 0,
            "an unreleased gate must read EOF, which refuses the box"
        );
        drop(unreleased);
        crate::set_global_env("KERN_GATE_FD", "7");
        assert!(
            EgressGate::arm().is_none(),
            "a launcher's gate is already set: that launcher releases this box"
        );
        assert_eq!(crate::global_env_str("KERN_GATE_FD").as_deref(), Ok("7"));
        crate::unset_global_env("KERN_GATE_FD");
    }

    #[test]
    fn gate_can_still_release_separates_a_pending_byte_from_a_shut_pipe() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        // Process-global env (`KERN_GATE_FD`) - serialize with every other env-mutating test.
        let _g = crate::env_guard();

        // `pipe2(O_CLOEXEC)` AND NOT `pipe()`, because this test's verdict is POLLHUP and POLLHUP is
        // a statement about the whole PROCESS TABLE, not about this thread.
        //
        // 🪤 MEASURED: with a bare `pipe()` this test failed 3 times in 20 runs of the binary under
        // load, always at the `Some(false)` below, always `Some(true)`. `Some(true)` with no POLLIN
        // means POLLHUP was ABSENT, which means the write end was still open somewhere - and it was:
        // sibling tests in this same binary spawn processes (`Command::new(self_exe)` in the compose
        // tests, `cp`, `systemctl`), so a fork between `pipe()` and `drop(wr)` hands the child an
        // inherited copy of the write end. Dropping our own copy then leaves the pipe with a living
        // writer, so the kernel is right and the test was wrong. `O_CLOEXEC` makes the inherited
        // copy vanish at the child's `execvp`, which is what line 4045 of this file already does
        // for the same reason. The production readiness pipe near line 3412 deliberately does NOT
        // set it: there the child is MEANT to inherit the write end.
        fn pipe() -> (OwnedFd, OwnedFd) {
            let mut fds = [0 as libc::c_int; 2];
            assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
        }
        fn ask(rd: &OwnedFd) -> Option<bool> {
            crate::set_global_env("KERN_GATE_FD", rd.as_raw_fd().to_string());
            super::gate_can_still_release()
        }
        fn release(wr: &OwnedFd) {
            let b = *b"r";
            assert_eq!(
                unsafe { libc::write(wr.as_raw_fd(), b.as_ptr().cast::<libc::c_void>(), 1) },
                1
            );
        }

        // Launcher alive, nothing sent yet: it may still release, so the budget applies.
        let (rd, wr) = pipe();
        assert_eq!(ask(&rd), Some(true));

        // Launcher alive and the byte is waiting: a retry reads it and runs.
        release(&wr);
        assert_eq!(ask(&rd), Some(true));

        // THE CONTROL THAT MATTERS: the launcher released this box and then EXITED. The byte is
        // still in the pipe, so this is a retry that can succeed, not a box that was refused.
        drop(wr);
        assert_eq!(ask(&rd), Some(true));

        // Released, consumed, writer gone: nothing left to read, so no retry can ever start.
        let mut byte = [0u8; 1];
        assert_eq!(
            unsafe { libc::read(rd.as_raw_fd(), byte.as_mut_ptr().cast::<libc::c_void>(), 1) },
            1
        );
        assert_eq!(ask(&rd), Some(false));

        // Refused outright: writer closed, nothing ever written. This is the dependency that failed.
        let (rd2, wr2) = pipe();
        drop(wr2);
        assert_eq!(ask(&rd2), Some(false));

        // No gate, or one that cannot be parsed or used: no opinion, and the caller keeps its budget.
        crate::unset_global_env("KERN_GATE_FD");
        assert_eq!(super::gate_can_still_release(), None);
        crate::set_global_env("KERN_GATE_FD", "not-a-number");
        assert_eq!(super::gate_can_still_release(), None);
        crate::set_global_env("KERN_GATE_FD", "-1");
        assert_eq!(super::gate_can_still_release(), None);
        // A descriptor that CANNOT be open answers `POLLNVAL`, which is not "refused".
        //
        // 🪤 NOT A NUMBER THAT LOOKS FREE. This was `987`, and a later pass caught it failing
        // 1 run in 12 at `--test-threads=16`: the tests are threads in ONE process, they open pipes
        // and files, and 987 is a descriptor a sibling is entitled to hold. The soft `RLIMIT_NOFILE`
        // is one past the highest fd this process may own, so no thread can make it valid, and the
        // case stops depending on what the rest of the suite happens to be doing.
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: one live local `rlimit`, filled by the kernel.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) }, 0);
        let impossible = libc::c_int::try_from(lim.rlim_cur).unwrap_or(libc::c_int::MAX);
        crate::set_global_env("KERN_GATE_FD", impossible.to_string());
        assert_eq!(super::gate_can_still_release(), None);
        crate::unset_global_env("KERN_GATE_FD");
    }
    use super::*;

    fn hc(test: &[&str]) -> kern_oci::ImageHealthcheck {
        kern_oci::ImageHealthcheck {
            test: test.iter().map(|s| (*s).to_string()).collect(),
            interval_ns: Some(30_000_000_000),
            timeout_ns: Some(5_000_000_000),
            start_period_ns: Some(2_000_000_000),
            start_interval_ns: None,
            retries: Some(4),
        }
    }

    /// ALL OR NOTHING, and each arm is a different reason. MEASURED end to end on a real box before
    /// this was extracted: with no flag the image's check runs (`healthy` when its file exists,
    /// `unhealthy` when it does not), and the same image on `main` reports `-`.
    #[test]
    fn the_image_health_is_a_default_the_flag_replaces_whole() {
        // No image check at all: nothing to contribute.
        assert_eq!(
            image_health_defaults(None, None),
            ImageHealthDefaults::default()
        );
        assert_eq!(
            image_health_defaults(None, Some(&shell_probe("curl -f /"))),
            ImageHealthDefaults::default()
        );

        // The image alone: its command AND its numbers.
        let d = image_health_defaults(Some(&hc(&["CMD-SHELL", "test -f /ready"])), None);
        assert_eq!(d.probe, Some(shell_probe("test -f /ready")));
        assert_eq!(
            (d.interval, d.timeout, d.start_period, d.retries),
            (Some(30), Some(5), Some(2), Some(4))
        );

        // THE FLAG REPLACES THE WHOLE CHECK, numbers included: Compose's `healthcheck.test` does not
        // merge with the image's, and half of each would be a check nobody wrote.
        assert_eq!(
            image_health_defaults(
                Some(&hc(&["CMD-SHELL", "test -f /ready"])),
                Some(&shell_probe("mine"))
            ),
            ImageHealthDefaults::default()
        );

        // `NONE` DISABLES, and must not leave its intervals behind to be applied to a check that
        // does not exist. A version that returned only `cmd: None` would set an interval on nothing.
        assert_eq!(
            image_health_defaults(Some(&hc(&["NONE"])), None),
            ImageHealthDefaults::default()
        );

        // THE IMAGE'S EXEC FORM SURVIVES AS AN EXEC FORM. It used to arrive here joined into a
        // string and leave wrapped in `/bin/sh -c`, which an image that has no shell - the very
        // reason it writes `CMD` rather than `CMD-SHELL` - fails on every single probe.
        let d = image_health_defaults(Some(&hc(&["CMD", "postgrest", "--ready"])), None);
        assert_eq!(
            d.probe,
            Some(kern_oci::HealthTest::Exec(vec![
                "postgrest".to_string(),
                "--ready".to_string()
            ]))
        );
    }

    /// The image's `StartInterval` must reach the checker, because reading only `Interval` is a 60x
    /// delay on a real image.
    ///
    /// MEASURED on Immich's postgres (`Interval 300s, StartPeriod 300s, StartInterval 5s`): Docker
    /// probes every 5 s and calls it healthy in about ten; kern waited the full 300 s for its FIRST
    /// probe and reported `starting` for five minutes, with every `depends_on: service_healthy`
    /// waiting behind it. A later pass sampled the process table at 0.1 s and saw the probe
    /// run once, at 300 s, and pass.
    #[test]
    fn an_images_start_interval_reaches_the_checker() {
        let mut h = hc(&["CMD-SHELL", "true"]);
        h.start_interval_ns = Some(5_000_000_000);
        let d = image_health_defaults(Some(&h), None);
        assert_eq!(d.start_interval, Some(5));
        // ...and an image that says nothing leaves it unset, which is "use the steady interval from
        // the first probe" - exactly what kern did before the field existed.
        let mut silent = hc(&["CMD-SHELL", "true"]);
        silent.start_interval_ns = None;
        assert_eq!(
            image_health_defaults(Some(&silent), None).start_interval,
            None
        );
        // THE CONTROL that the whole block is still all-or-nothing: a caller's own probe takes the
        // image's numbers away with it, this one included.
        let flag = kern_oci::HealthTest::Shell("mine".into());
        assert_eq!(
            image_health_defaults(Some(&h), Some(&flag)).start_interval,
            None
        );
    }

    /// THE CALLER'S FLAGS KEEP THEIR FORM TOO, and `--health-cmd-argv` is the one that needs no
    /// shell in the box.
    #[test]
    fn a_flag_probe_carries_the_form_the_caller_wrote() {
        assert_eq!(flag_health_probe(None, &[]), None);
        assert_eq!(
            flag_health_probe(Some("pg_isready -U app"), &[]),
            Some(shell_probe("pg_isready -U app"))
        );
        let argv = vec!["postgrest".to_string(), "--ready".to_string()];
        assert_eq!(
            flag_health_probe(None, &argv),
            Some(kern_oci::HealthTest::Exec(argv.clone()))
        );
        // The exec form runs WITHOUT a shell - that is the whole of the fix, so it is asserted on
        // the argv itself and not on the enum variant alone.
        let p = flag_health_probe(None, &argv).expect("a probe");
        assert_eq!(p.argv(), vec!["postgrest", "--ready"]);
        assert_eq!(
            shell_probe("x").argv(),
            vec!["/bin/sh".to_string(), "-c".to_string(), "x".to_string()]
        );
    }

    fn shell_probe(c: &str) -> kern_oci::HealthTest {
        kern_oci::HealthTest::Shell(c.to_string())
    }

    /// ⛔ A HEALTHCHECK ON `nvidia-smi` IS A BOX THAT CAN NEVER BE HEALTHY, and it used to be a box
    /// that never said so.
    ///
    /// MEASURED 2026-11-12: a compose service with `gpus: all` and
    /// `healthcheck: test: ["CMD", "nvidia-smi"]` (the shape NVIDIA's own guides print, and one that
    /// appears in field example lists verbatim) started, took both of this host's cards, and sat at
    /// `unhealthy` with no output naming the cause. Under docker the identical file is healthy,
    /// because its NVIDIA runtime injects the binary and kern binds no binaries. The cost is a
    /// `depends_on: {condition: service_healthy}` gate that never opens.
    ///
    /// THE PREDICATE IS THE RUNTIME'S, not a copy of the tool list: `kern-isolation` owns the five
    /// names `libnvidia-container` injects, and a surface that carried its own copy would be the
    /// recurring defect of this repo (one derived condition computed twice).
    #[test]
    fn a_health_probe_that_runs_a_driver_tool_is_named_and_an_ordinary_one_is_not() {
        // BOTH FORMS, because compose writes both: `["CMD", …]` reaches this as an exec probe and
        // `["CMD-SHELL", …]` as a shell string.
        assert_eq!(
            health_probe_driver_tool(Some(&kern_oci::HealthTest::Exec(vec![
                "nvidia-smi".to_string()
            ])))
            .as_deref(),
            Some("nvidia-smi")
        );
        assert_eq!(
            health_probe_driver_tool(Some(&shell_probe("nvidia-smi || exit 1"))).as_deref(),
            Some("nvidia-smi")
        );
        // WRAPPED IN A SHELL, which is why every token is scanned and not just the program: this is
        // the form a file uses when the check needs a pipe, and `sh` is not a driver tool.
        assert_eq!(
            health_probe_driver_tool(Some(&kern_oci::HealthTest::Exec(vec![
                "sh".to_string(),
                "-c".to_string(),
                "/usr/bin/nvidia-smi".to_string(),
            ])))
            .as_deref(),
            Some("/usr/bin/nvidia-smi"),
            "a path spelling is reported as the caller wrote it"
        );
        // ⛔ AND THE WARNING MUST NOT FIRE ON A CHECK THAT WORKS. `test -c /dev/nvidiactl` is the
        // remedy this warning recommends, so a predicate that flagged it would send the reader in a
        // circle; both were MEASURED in a granted box, where the node is present and the probe
        // passes, and in one started without `--gpus`, where it is absent and the probe fails.
        for ok in [
            "test -c /dev/nvidiactl",
            "pg_isready -U app",
            "curl -f http://localhost:8000/health",
            "python3 -c \"import torch; torch.cuda.init()\"",
            // Names that merely LOOK like the tool: the box's own wrapper is the workload's
            // business and a hint about grants would describe a cause that is not there.
            "my-nvidia-smi --json",
            "nvidia-smi-wrapper",
        ] {
            assert_eq!(
                health_probe_driver_tool(Some(&shell_probe(ok))),
                None,
                "a probe that can pass must stay silent: {ok}"
            );
        }
        // No probe at all is no warning: a box without a healthcheck has nothing to report.
        assert_eq!(health_probe_driver_tool(None), None);
    }

    /// `--runtime nvidia` READS `NVIDIA_VISIBLE_DEVICES` AS NVIDIA'S RUNTIME DOES: unset, empty, void
    /// and none grant nothing; all is every card; a list is those cards.
    #[test]
    fn the_nvidia_runtime_reads_the_visible_devices_value() {
        use crate::gpu_grant::GpuSelection;
        for none in [None, Some(""), Some("void"), Some("NONE"), Some("  ")] {
            assert!(
                matches!(runtime_nvidia_selection(none), Ok(None)),
                "{none:?}"
            );
        }
        assert!(matches!(
            runtime_nvidia_selection(Some("all")),
            Ok(Some(GpuSelection::All))
        ));
        assert!(matches!(
            runtime_nvidia_selection(Some("0,1")),
            Ok(Some(GpuSelection::These(ref v))) if v == &vec![0, 1]
        ));
        assert!(runtime_nvidia_selection(Some("abc")).is_err());
    }

    /// ⛔ THE WARNING FIRES ONLY WHERE THE PROBE STILL CANNOT PASS. A grant binds the driver tools
    /// at `/usr/bin` as docker does, so `nvidia-smi` in a granted box is silent; no grant, a host
    /// without the tool, and a path the grant does not use are the three that still speak, each with
    /// its own cause.
    #[test]
    fn a_driver_tool_healthcheck_warns_only_where_the_grant_did_not_bind_it() {
        let five: Vec<String> = kern_isolation::driver_tools()
            .iter()
            .map(|t| t.to_string())
            .collect();
        assert_eq!(health_tool_absence("nvidia-smi", Some(&five)), None);
        assert_eq!(
            health_tool_absence("/usr/bin/nvidia-smi", Some(&five)),
            None
        );
        let none = health_tool_absence("nvidia-smi", None).expect("no grant");
        assert!(
            none.contains("no GPU grant") && none.contains("--gpus"),
            "{none}"
        );
        let missing = health_tool_absence("nvidia-persistenced", Some(&["nvidia-smi".to_string()]))
            .expect("host lacks it");
        assert!(
            missing.contains("has no `nvidia-persistenced`"),
            "{missing}"
        );
        let path = health_tool_absence("/usr/local/bin/nvidia-smi", Some(&five)).expect("path");
        assert!(
            path.contains("/usr/bin/nvidia-smi, not at /usr/local/bin/nvidia-smi"),
            "{path}"
        );
        // And the names come from the binds, only those at /usr/bin and only the driver's.
        let binds = vec![
            (
                "/h/nvidia-smi".to_string(),
                "/usr/bin/nvidia-smi".to_string(),
                true,
            ),
            ("/h/x".to_string(), "/usr/bin/python3".to_string(), true),
            (
                "/dev/nvidia0".to_string(),
                "/dev/nvidia0".to_string(),
                false,
            ),
        ];
        assert_eq!(
            tools_bound_at_usr_bin(&binds),
            vec!["nvidia-smi".to_string()]
        );
    }

    /// A ZERO IS "UNSET", NOT "EVERY ZERO SECONDS". The OCI config writes 0 for a field the image
    /// omitted, and a zero interval would spin the checker in a loop.
    #[test]
    fn an_oci_duration_becomes_whole_seconds_and_a_zero_stays_absent() {
        assert_eq!(secs_from_nanos(None), None);
        assert_eq!(secs_from_nanos(Some(0)), None);
        assert_eq!(secs_from_nanos(Some(30_000_000_000)), Some(30));
        // ROUNDS UP: the coarser unit must never turn a real interval into no interval at all, which
        // is what truncating a sub-second value to 0 would do.
        assert_eq!(secs_from_nanos(Some(500_000_000)), Some(1));
        assert_eq!(secs_from_nanos(Some(1)), Some(1));
        assert_eq!(secs_from_nanos(Some(1_500_000_000)), Some(2));
    }

    /// THREE CONDITIONS, AND EACH EXCLUDES A DIFFERENT MISTAKE.
    ///
    /// Seeding writes image content, and its owner and mode, onto a directory: getting this
    /// predicate wrong once means filling somebody's bind mount, or overwriting live data.
    ///
    /// UNDER A ROOT THIS TEST OWNS. It used to build its fixture inside the real `volumes_dir()`,
    /// which is one directory for the whole user that every kern on the machine writes to, and then
    /// assert that a directory there was EMPTY. It went red twice with the predicate untouched, both
    /// times while other kern processes were running, and the writer was never identified. It was
    /// not reproducible under concurrent volume churn either, so the honest conclusion is not "the
    /// racer is X" but "nothing here should have been able to race at all": a test of a pure rule
    /// that shares state with the machine proves nothing when it is green.
    ///
    /// THE WIRING IS STILL ASSERTED, at the end, and it is a pure path computation that opens no
    /// file: `name_of_data_dir` must resolve against the REAL volumes directory, or this whole test
    /// would pass while production looked somewhere else.
    #[test]
    fn only_an_empty_named_volume_at_a_real_path_is_seeded() {
        let _g = crate::env_guard();
        let base = std::env::temp_dir().join(format!("kern-seedable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("volumes");
        let host_path = base.join("a-host-directory");
        let empty_named = root.join("kern-seed-probe").join("data");
        std::fs::create_dir_all(&empty_named).expect("mkdir volume data");
        std::fs::create_dir_all(&host_path).expect("mkdir host path");
        let v = |src: &std::path::Path, target: &str| Volume {
            source: src.to_string_lossy().into_owned(),
            target: target.to_string(),
            read_only: false,
        };
        let seedable =
            |src: &std::path::Path, target: &str| is_seedable_under(&root, &v(src, target));

        // NAMED, EMPTY, AND NOT THE ROOT: the only shape Docker seeds, and the only one kern does.
        assert!(
            seedable(&empty_named, "/etc/nginx"),
            "an empty named volume at a real target is the case seeding exists for"
        );
        // A BIND MOUNT of a host path: the caller's own directory, never kern's to fill.
        assert!(
            !seedable(&host_path, "/etc/nginx"),
            "a host path is not kern's to write image content into"
        );
        // A volume that already holds something: Docker seeds only an empty one, and this is the
        // only thing standing between seeding and overwriting live data.
        std::fs::write(empty_named.join("x"), b"1").expect("write");
        assert!(
            !seedable(&empty_named, "/etc/nginx"),
            "a volume that already holds data must never be seeded over"
        );
        std::fs::remove_file(empty_named.join("x")).expect("rm");
        assert!(
            seedable(&empty_named, "/etc/nginx"),
            "and emptying it makes it seedable again, so the condition is the CONTENT and not a \
             one-way flag"
        );
        // A volume over the ROOT has no "the image's content at the mount point" to copy.
        assert!(
            !seedable(&empty_named, "/"),
            "a volume over / has no mount point content"
        );
        assert!(
            !seedable(&empty_named, "///"),
            "and neither does a slash-only target"
        );
        // A DIRECTORY THAT IS NOT THERE answers false rather than true: `read_dir` fails, and the
        // safe reading of a failure is "do not write into it".
        assert!(
            !seedable(&root.join("kern-seed-probe").join("nope"), "/etc/nginx"),
            "a path that is not a volume's data directory is not seedable"
        );

        // THE WIRING, AND IT HAS TO BE A POSITIVE ASSERTION AGAINST THE REAL DIRECTORY.
        //
        // The refusal of a foreign root is NOT enough, and that was measured rather than assumed: a
        // mutation pointing production at `/` left this test green, because `/` refuses the fixture
        // for the same reason the correct root does. Only a volume under the REAL `volumes_dir()`
        // that production ACCEPTS pins which root production uses.
        //
        // WHICH PUTS ONE FIXTURE BACK IN A SHARED DIRECTORY, so it is built to survive a third party
        // instead of pretending there is none: the name carries this process's pid, so nothing can
        // collide with it by name, and the attempt is repeated because the failure this test
        // actually suffered was a directory that stopped being readable between its creation and its
        // reading. A broken predicate fails every attempt; a sweeper loses to the next one. The same
        // shape as the `prune` convergence loop in the integration suite, and for the same reason.
        let shared = crate::volume::volumes_dir()
            .join(format!("kern-seed-probe-{}", std::process::id()))
            .join("data");
        let mut wired = false;
        let mut why = String::from("never created");
        for _ in 0..8 {
            let _ = std::fs::remove_dir_all(&shared);
            if let Err(e) = std::fs::create_dir_all(&shared) {
                why = format!("could not create {}: {e}", shared.display());
                continue;
            }
            if is_seedable(&v(&shared, "/etc/nginx")) {
                wired = true;
                break;
            }
            why = match std::fs::read_dir(&shared) {
                Ok(d) => format!("the directory held {} entries", d.count()),
                Err(e) => format!("the directory could not be read: {e}"),
            };
        }
        let _ = std::fs::remove_dir_all(
            crate::volume::volumes_dir().join(format!("kern-seed-probe-{}", std::process::id())),
        );
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            wired,
            "an empty named volume under the REAL volumes directory must be seedable, or production \
             is resolving against some other root and every assertion above is about a directory it \
             never looks at. Last attempt: {why}"
        );
    }

    /// THE PRECEDENCE, asserted. MEASURED end to end before it was a function: an image declaring
    /// `SIGQUIT` delivers QUIT, the same box with `--stop-signal TERM` delivers TERM, and `main`
    /// delivers TERM in both cases.
    #[test]
    fn the_flag_beats_the_image_and_the_image_beats_the_default() {
        let r = resolve_stop_signal;
        // Nothing anywhere: the historic default.
        assert_eq!(r(None, None), libc::SIGTERM);
        // The image alone decides.
        assert_eq!(r(None, Some("SIGQUIT")), libc::SIGQUIT);
        // THE FLAG WINS EVEN WHEN IT NAMES THE DEFAULT. This is the arm the `Option` exists for: with
        // `SIGTERM` folded in as a value, this case and the one above are indistinguishable.
        assert_eq!(r(Some(libc::SIGTERM), Some("SIGQUIT")), libc::SIGTERM);
        assert_eq!(r(Some(libc::SIGINT), Some("SIGQUIT")), libc::SIGINT);
        // A name kern's table lacks leaves the box on the default rather than stopping it.
        assert_eq!(r(None, Some("SIGWINCH")), libc::SIGTERM);
        assert_eq!(r(None, Some("")), libc::SIGTERM);
    }

    /// AN IMAGE'S SIGNAL IS NOT A TYPO, so an unknown name must not stop the box.
    ///
    /// The flag is typed by the person running kern and an unknown name there is their mistake, to
    /// be refused before anything starts. `STOPSIGNAL` is written by whoever built the image, is
    /// read where there is no usage error to return, and a name kern's table lacks (nextcloud ships
    /// `SIGWINCH`, MEASURED) must leave the box running on `SIGTERM` as it did before.
    #[test]
    fn an_image_signal_kern_does_not_know_falls_back_instead_of_refusing() {
        assert_eq!(
            crate::cli::parse_signal_name("SIGQUIT"),
            Some(libc::SIGQUIT)
        );
        assert_eq!(crate::cli::parse_signal_name("QUIT"), Some(libc::SIGQUIT));
        assert_eq!(crate::cli::parse_signal_name("15"), Some(libc::SIGTERM));
        // Unknown to kern's table, and to any table: neither may panic or refuse.
        assert_eq!(crate::cli::parse_signal_name("SIGWINCH"), None);
        assert_eq!(crate::cli::parse_signal_name(""), None);
        assert_eq!(crate::cli::parse_signal_name("999"), None);
    }
}

#[cfg(test)]
mod ssh_hint_tests {
    /// The `known_hosts` line kern writes must be the form OpenSSH LOOKS UP, or the strict hint
    /// refuses the very key kern handed the box: `[127.0.0.1]:<port>` for a non-default port, the
    /// bare address for 22, and the key's type and body without its comment.
    #[test]
    fn the_known_hosts_line_is_the_form_ssh_looks_up() {
        let public = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKern alex@desk\n";
        assert_eq!(
            super::known_hosts_line(2222, public).as_deref(),
            Some("[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKern\n")
        );
        assert_eq!(
            super::known_hosts_line(22, public).as_deref(),
            Some("127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKern\n")
        );
        assert_eq!(super::known_hosts_line(2222, "ssh-ed25519\n"), None);
        assert_eq!(super::known_hosts_line(2222, ""), None);
    }
}

#[cfg(test)]
mod twin_tests {
    /// THE TWIN IS DECIDED BY ITS OWN ADDRESS. The shape of a VPS measured with IPv6 on `eth0` and
    /// none on `lo`: `::` binds and `::1` does not. A loopback policy's twin (`::1`) must go and the
    /// box must still start; the default's twin (`::`) must stay; a WRITTEN `[::1]` is never dropped
    /// (it is refused by name at the bind); and each address is asked about once.
    #[test]
    fn a_twin_goes_only_when_its_own_address_cannot_be_bound() {
        use std::net::{IpAddr, Ipv6Addr};
        let lo6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let any6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let asked = std::cell::RefCell::new(Vec::new());
        let vps = |ip: IpAddr| {
            asked.borrow_mut().push(ip);
            ip != lo6
        };
        let mut policy =
            crate::ports::parse_with_default("8000-8002:80-82", crate::ports::LOOPBACK_IP)
                .unwrap_or_default();
        policy.extend(crate::ports::parse("[::1]:9000:90").unwrap_or_default());
        super::drop_unbindable_twins(&mut policy, vps);
        assert!(
            policy.iter().all(|p| !p.implicit),
            "the ::1 twins must go on a host without ::1: {policy:?}"
        );
        assert!(
            policy.iter().any(|p| p.bind == lo6 && p.host == 9000),
            "a written [::1] is kept, for the bind to refuse by name: {policy:?}"
        );
        assert_eq!(asked.borrow().len(), 1, "one probe per distinct address");

        let mut default = crate::ports::parse("8080:80").unwrap_or_default();
        super::drop_unbindable_twins(&mut default, |ip| ip != lo6);
        assert!(
            default.iter().any(|p| p.bind == any6),
            "the [::] twin stays: {default:?}"
        );
    }
}

/// A `kern run` (or `kern container run`) command line as the `kern box` one it is
/// (`cli::run_to_box`, the parser's own translation), and any other as it was. A kept box records
/// the `box` form: `kern start` replays only that, and the image a later `--keep` run is checked
/// against is read from it. MEASURED before (0.57.0's `kern run`): `kern run --keep --name rk2
/// alpine:3.21 ...` could not be started again ("its record does not begin `box rk2`"), and `kern run
/// --keep --name rk2 debian:12` ran on the alpine layer, the check seeing no image in the record.
fn as_box_argv(argv: Vec<std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    let words: Option<Vec<&str>> = argv.iter().map(|a| a.to_str()).collect();
    let Some(mut words) = words else {
        return argv;
    };
    if words.first() == Some(&"container") && words.get(1) == Some(&"run") {
        words.remove(0);
    }
    if words.first() != Some(&"run") {
        return argv;
    }
    match crate::cli::run_to_box(&words) {
        Ok(boxed) => boxed.into_iter().map(std::ffi::OsString::from).collect(),
        Err(_) => argv,
    }
}

/// The command line a kept box records, as `box <name> <options...>`: `kern start` replays only a
/// record that begins that way (see `start_one_kept`), and `--name <name>` is Docker's spelling of
/// the same thing. MEASURED: `kern box --name web --image nginx:alpine -d --keep` recorded `box
/// --name web ...`, and `kern start web` refused it as "not a command line this box can be started
/// from", so a box kept that way could never start again. The name moves to position 1; everything
/// after the workload's `--` is the workload's and is left as it is.
fn kept_argv(argv: Vec<std::ffi::OsString>, name: &str) -> Vec<std::ffi::OsString> {
    let argv = as_box_argv(argv);
    if argv
        .get(1)
        .is_some_and(|a| a.as_os_str() == std::ffi::OsStr::new(name))
    {
        return argv;
    }
    let mut out: Vec<std::ffi::OsString> = Vec::with_capacity(argv.len() + 1);
    let mut it = argv.into_iter();
    if let Some(verb) = it.next() {
        out.push(verb);
    }
    out.push(std::ffi::OsString::from(name));
    let mut in_workload = false;
    while let Some(a) = it.next() {
        if !in_workload {
            if a.as_os_str() == "--" {
                in_workload = true;
            } else if a.as_os_str() == "--name" {
                it.next();
                continue;
            } else if a.to_str().is_some_and(|t| t.starts_with("--name=")) {
                continue;
            }
        }
        out.push(a);
    }
    out
}

/// The NAT of a box that joins a compose stack's bridge network, attached while the box waits at a
/// pre-exec gate: the shape `compose up` gives each of the stack's services (see
/// [`crate::pod::attach_box_outbound`]), for one box.
///
/// A HELPER FORKED BEFORE THE BOX'S `unshare`, like the `--timeout` watchdog, and for the same
/// reason plus one. The supervisor that forks the box first unshares its own user namespace (and,
/// on `fork_into_cgroup`'s fallback, the pid namespace), so from the PID-1 callback a `pasta` would be
/// spawned INSIDE the box's user namespace, and where the pid namespace is the box's too a thread
/// cannot be created at all: MEASURED, the first version
/// attached from the callback and the box's launcher died "failed to spawn thread: Invalid
/// argument". The helper stays in the host's namespaces, learns PID 1 over a pipe, attaches the NAT
/// and writes the release.
///
/// THE HELPER HOLDS THE ONLY WRITE END OF THE GATE. The supervisor drops its copy before it forks
/// the box, so a helper that dies, or never receives a PID 1, closes the gate and the box reads EOF
/// and refuses to exec: fail-closed, as a gate a launcher abandons is. A NAT that cannot be
/// attached is said and the box is released anyway, as a service is: it still reaches the stack.
pub(crate) struct HeldNat {
    helper: libc::pid_t,
    pid_write: Option<std::os::fd::OwnedFd>,
    // The gate's read end, named in `KERN_GATE_FD` for the box this process forks next; held until
    // the attempt is over so the number stays valid for the fork.
    _gate_read: std::os::fd::OwnedFd,
}

impl HeldNat {
    /// Arm the gate for the next box this process forks, with the NAT's state under the stack's own
    /// directory (which `compose down` removes). `None`, with the reason said, when it cannot be
    /// made; `None` in silence when a launcher's gate is already set, because then `compose up`
    /// started this box and is the one that wires it.
    pub(crate) fn arm(pod: &str, name: &str) -> Option<HeldNat> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        if crate::global_env_str("KERN_GATE_FD").is_ok() {
            return None;
        }
        let warn = |why: String| {
            eprintln!(
                "kern: warning: box '{name}': no outbound - {why}. The box reaches the stack's \
                 services; it cannot reach the internet"
            );
        };
        let dir = match crate::relayhold::stack_dir(pod) {
            Ok(d) => d.join("outbound").join(format!("box-{name}")),
            Err(e) => {
                warn(format!("the stack directory is unavailable ({e})"));
                return None;
            }
        };
        let pipe = || -> Option<(OwnedFd, OwnedFd)> {
            let mut fds = [-1i32; 2];
            // SAFETY: `fds` is a two-element array, which is what `pipe2` writes.
            if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
                return None;
            }
            // SAFETY: both descriptors were just returned by `pipe2` and are owned by nothing else.
            Some(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
        };
        let (Some((gate_read, gate_write)), Some((pid_read, pid_write))) = (pipe(), pipe()) else {
            warn(format!("no pipe ({})", std::io::Error::last_os_error()));
            return None;
        };
        // SAFETY: kern is single-threaded here (the box is not forked yet, and the helper threads of
        // a box start after it), which is the condition for running ordinary code in the child.
        let helper = unsafe { libc::fork() };
        if helper < 0 {
            warn(format!("no helper ({})", std::io::Error::last_os_error()));
            return None;
        }
        if helper == 0 {
            // HELPER, in the host's namespaces. Nothing of the supervisor's is kept but the two
            // pipe ends it works with and stdio: a held readiness pipe would make a launcher wait on
            // this process.
            let (pid_fd, gate_fd) = (pid_read.as_raw_fd(), gate_write.as_raw_fd());
            kern_isolation::shed_inherited_fds_keeping(&[pid_fd, gate_fd]);
            let mut buf = [0u8; 4];
            let mut got = 0usize;
            while got < buf.len() {
                let Some(rest) = buf.get_mut(got..) else {
                    break;
                };
                // SAFETY: a valid descriptor and the unread tail of a four-byte buffer.
                let n = unsafe { libc::read(pid_fd, rest.as_mut_ptr().cast(), rest.len()) };
                if n < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                let Ok(n) = usize::try_from(n) else {
                    // SAFETY: `_exit` in a forked child: no destructors of the parent's state run.
                    unsafe { libc::_exit(0) };
                };
                if n == 0 {
                    // No PID 1 came: the start failed before the box was forked, so nothing waits.
                    unsafe { libc::_exit(0) };
                }
                got += n;
            }
            let pid1 = i32::from_ne_bytes(buf);
            // NOT BEFORE THE BOX IS AT ITS GATE. PID 1 has just been forked and is still being
            // built: a change of credentials clears its `dumpable` flag, and while it is clear the
            // kernel refuses its `/proc/<pid>/ns/*` to everyone, its owner included; the box sets
            // it again just before it waits on the gate (see `kern-isolation`'s gate). `compose up`
            // attaches only after a box reports itself prepared; this helper cannot read that
            // report, so it waits until IT can open the namespace, and only then starts pasta.
            //
            // THE WAIT IS ON KERN'S OWN OPEN, NOT ON PASTA'S. A first version retried pasta for as
            // long as it said "Permission denied", and that refusal has a second source the window
            // does not explain: a security policy that confines pasta. MEASURED in an openSUSE
            // Leap 16 VM (SELinux enforcing, passt 2025-04): pasta is refused every namespace of an
            // unconfined process, so the retry spent its whole 5 s on every one-off and then
            // reported. kern is not confined there, so its open measures the window alone, and a
            // pasta refused after it is refused for good and is said at once. Bounded, so a box
            // that never reaches its gate cannot hold the helper.
            //
            // THE WINDOW ITSELF HAS NOT BEEN SEEN. Counted with a temporary probe on the desktop,
            // 30 one-offs on a two-service bridge stack (20 foreground, 10 detached): kern's own open
            // was refused 0 times. The wait costs one `open` when it is not needed and is kept as the
            // bound for a window the credential change makes possible, not as a measured need.
            let ns_user = format!("/proc/{pid1}/ns/user");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut pause = std::time::Duration::from_millis(1);
            while let Err(e) = std::fs::File::open(&ns_user) {
                if e.kind() != std::io::ErrorKind::PermissionDenied
                    || std::time::Instant::now() >= deadline
                {
                    break;
                }
                std::thread::sleep(pause);
                pause = (pause * 2).min(std::time::Duration::from_millis(50));
            }
            let attached = crate::pod::attach_box_outbound(&dir, pid1);
            if let Err(why) = attached {
                eprintln!(
                    "kern: warning: box '{name}': no outbound - {why}. The box starts, and reaches \
                     the stack's services; it cannot reach the internet"
                );
            }
            let byte = [1u8];
            loop {
                // SAFETY: a valid descriptor and a one-byte buffer.
                let r = unsafe { libc::write(gate_fd, byte.as_ptr().cast(), 1) };
                if r < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                break;
            }
            // SAFETY: `_exit` in a forked child: no destructors of the parent's state run.
            unsafe { libc::_exit(0) };
        }
        // SUPERVISOR: the gate's write end is the helper's alone, and so is the pid pipe's read end.
        drop(gate_write);
        drop(pid_read);
        crate::set_global_env("KERN_GATE_FD", gate_read.as_raw_fd().to_string());
        Some(HeldNat {
            helper,
            pid_write: Some(pid_write),
            _gate_read: gate_read,
        })
    }

    /// Hand PID 1 to the helper, which attaches the NAT and releases the box. Once.
    pub(crate) fn release(&mut self, pid1: i32) {
        let Some(w) = self.pid_write.take() else {
            return;
        };
        let p = pid1.to_ne_bytes();
        // SAFETY: a valid descriptor this struct owned and a four-byte buffer. A short or failed
        // write leaves the helper at EOF, which closes the gate: the box refuses, it does not run
        // unwired.
        let _ = unsafe {
            libc::write(
                std::os::fd::AsRawFd::as_raw_fd(&w),
                p.as_ptr().cast(),
                p.len(),
            )
        };
    }
}

/// The pre-exec gate of a box with `--egress-allow`: the workload is released once the filter's pump
/// listens in the box, and never before.
///
/// MEASURED ON A STOCK UBUNTU 24.04 (kern's AppArmor profile, nested KVM), where it did not hold:
/// the pump was told PID 1 right after the fork and the box went on to its `execvp` at once, so the
/// "PID 1 is killed before it reaches the workload" of the failure path was a race the box won. The
/// workload's `wget` met `127.0.0.1:3128` with nothing behind it (`Connection refused`), the box
/// exited, and the pump then found no `/proc/<pid1>/ns/net` and the launcher said the port "never
/// came up". On this desktop the box's setup outlasted the pump's start and the race was never lost.
///
/// THE GATE `HeldNat` AND COMPOSE USE: the box is built and confined, waits in one `read`, and a
/// byte releases it. This process holds the only write end once the box has shed its copy; one
/// that dies, or a pump that never listens (`release` is not called), leaves EOF, and EOF refuses.
pub(crate) struct EgressGate {
    write: Option<std::os::fd::OwnedFd>,
    _read: std::os::fd::OwnedFd,
}

impl EgressGate {
    /// Arm the gate for the box this process forks next. `None` when a launcher's gate is already
    /// set (that launcher releases this box) or no pipe can be made, and then the box runs as it
    /// did before this gate, its pump racing it.
    pub(crate) fn arm() -> Option<EgressGate> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        if crate::global_env_str("KERN_GATE_FD").is_ok() {
            return None;
        }
        let mut fds = [-1i32; 2];
        // SAFETY: `fds` is a two-element array, which is what `pipe2` writes.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            eprintln!(
                "kern: warning: --egress-allow: no gate for the box ({}); its workload may start \
                 before the filter listens",
                std::io::Error::last_os_error()
            );
            return None;
        }
        // SAFETY: two descriptors `pipe2` just returned, owned by nothing else.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // SAFETY: the supervisor is single-threaded here, between the helpers' spawn and the fork.
        crate::set_global_env("KERN_GATE_FD", read.as_raw_fd().to_string());
        Some(EgressGate {
            write: Some(write),
            _read: read,
        })
    }

    /// Release the workload: the pump has said it listens. Once.
    pub(crate) fn release(&mut self) {
        let Some(w) = self.write.take() else {
            return;
        };
        let byte = [1u8];
        loop {
            // SAFETY: a valid descriptor this struct owned and a one-byte buffer.
            let r = unsafe {
                libc::write(std::os::fd::AsRawFd::as_raw_fd(&w), byte.as_ptr().cast(), 1)
            };
            if r < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
    }
}

impl Drop for EgressGate {
    fn drop(&mut self) {
        self.write = None;
        crate::unset_global_env("KERN_GATE_FD");
    }
}

impl Drop for HeldNat {
    fn drop(&mut self) {
        // A helper still waiting for a PID 1 reads EOF here and leaves; one that has it is done by
        // the time the box has run.
        self.pid_write = None;
        crate::eintr::reap(self.helper);
        crate::unset_global_env("KERN_GATE_FD");
    }
}

/// What [`stack_network_join`] hands back: the pod to join, the bridge addresses, the hosts lines,
/// and whether the box gets the network's NAT (a bridge network the file does not mark internal).
pub(crate) type StackJoin = (
    Option<String>,
    Vec<kern_isolation::BridgeAttach>,
    Vec<(String, String)>,
    bool,
);

/// `kern box --network <name>` onto a compose STACK: Docker's one-off that talks to a running stack,
/// `docker run --network <project>_<network>`.
///
/// The name is the stack's pod, or `<project>_<network>` (Docker's network name); the second form
/// is read as the pod plus one of its networks. On a stack in one pod nothing more is needed: the
/// box joins the pod and its hosts file. On a stack on a BRIDGE the box takes the next free address
/// on that network's bridge, reserved against a concurrent one-off, and every name on that network
/// (services, aliases, box names) is added to its hosts file, as a container on that network
/// resolves them. Anything else is passed through, and the join reports it.
pub(crate) fn stack_network_join(
    pod: Option<String>,
    mut pod_bridges: Vec<kern_isolation::BridgeAttach>,
    mut add_hosts: Vec<(String, String)>,
) -> Result<StackJoin, Error> {
    let Some(name) = pod.as_deref().filter(|_| pod_bridges.is_empty()) else {
        return Ok((pod, pod_bridges, add_hosts, false));
    };
    // A name that cannot name a pod is left to the join, which refuses it as a name: nothing here
    // turns it into a path first.
    if crate::pod::validate_join_name(name).is_err() {
        return Ok((pod, pod_bridges, add_hosts, false));
    }
    let (stack, network): (String, Option<String>) = if crate::pod::holder_pid(name).is_some() {
        (name.to_string(), None)
    } else {
        match name.rmatch_indices('_').find_map(|(i, _)| {
            let p = name.get(..i)?;
            let n = name.get(i + 1..)?;
            (!p.is_empty()
                && !n.is_empty()
                && crate::pod::validate_join_name(p).is_ok()
                && crate::pod::holder_pid(p).is_some())
            .then(|| (p.to_string(), n.to_string()))
        }) {
            Some((p, n)) => (p, Some(n)),
            None => return Ok((pod, pod_bridges, add_hosts, false)),
        }
    };
    let nets = crate::pod::bridge_networks(&stack);
    if nets.is_empty() {
        // One namespace for the whole stack: the pod IS every network of it.
        return Ok((Some(stack), pod_bridges, add_hosts, false));
    }
    let chosen = match &network {
        Some(n) => nets.iter().find(|x| &x.network == n).ok_or_else(|| {
            Error::Sandbox(format!(
                "stack '{stack}' has no network '{n}'; its networks are: {}",
                nets.iter()
                    .map(|x| format!("{stack}_{}", x.network))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?,
        None => nets
            .iter()
            .find(|x| x.network == "default")
            .or(nets.first())
            .ok_or_else(|| Error::Sandbox(format!("stack '{stack}' records no network")))?,
    };
    let Some((first, _)) = chosen.hosts.first() else {
        return Err(Error::Sandbox(format!(
            "network '{}' of stack '{stack}' has no member, so its addresses are not known",
            chosen.network
        )));
    };
    let prefix = u32::from(chosen.prefix.min(30));
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let base = u32::from(*first) & mask;
    let broadcast = base | !mask;
    let mut used: std::collections::HashSet<u32> =
        chosen.hosts.iter().map(|(ip, _)| u32::from(*ip)).collect();
    for i in crate::registry::list() {
        for a in crate::registry::recorded_bridge_addrs(&i.bridges) {
            used.insert(u32::from(a));
        }
    }
    // `.1` is the bridge's own address, the members' gateway.
    let free = (base.saturating_add(2)..broadcast)
        .filter(|a| !used.contains(a))
        .map(std::net::Ipv4Addr::from)
        .find(|ip| crate::pod::lease_bridge_addr(&stack, chosen.bridge, *ip))
        .ok_or_else(|| {
            Error::Sandbox(format!(
                "network '{}' of stack '{stack}' has no free address left",
                chosen.network
            ))
        })?;
    pod_bridges.push(kern_isolation::BridgeAttach {
        ip: free,
        prefix: chosen.prefix,
        bridge: chosen.bridge,
    });
    for (ip, n) in &chosen.hosts {
        if !add_hosts.iter().any(|(h, _)| h == n) {
            add_hosts.push((n.clone(), ip.to_string()));
        }
    }
    // EGRESS AS ITS SERVICES HAVE IT. Every service on a bridge gets its own NAT (the holder's
    // namespace is no member's), so a box joining the network later needs its own too. MEASURED
    // before this: `kern box --network kcu_default` reached the stack's services by name and had no
    // default route and no `resolv.conf`, where Docker's one-off on the same network reaches the
    // internet. A network the file marks `internal: true` gets none, as its services got none.
    let nat = !chosen.internal;
    Ok((Some(stack), pod_bridges, add_hosts, nat))
}

#[cfg(test)]
mod kept_record_tests {
    use super::{as_box_argv, kept_argv};

    fn os(v: &[&str]) -> Vec<std::ffi::OsString> {
        v.iter().map(std::ffi::OsString::from).collect()
    }

    /// A kept box's record is the `box <name>` command line whatever verb made it: `kern run` and
    /// `kern container run` are translated (the image named, so a later `--keep` run is checked
    /// against it, and `kern start` can replay it), and `kern box` is left as it was.
    #[test]
    fn a_kept_run_records_the_box_it_is() {
        let run = kept_argv(
            os(&[
                "run",
                "--keep",
                "--name",
                "rk",
                "-l",
                "a=b",
                "alpine:3.21",
                "sh",
                "-c",
                "x",
            ]),
            "rk",
        );
        assert_eq!(
            run,
            os(&[
                "box",
                "rk",
                "--keep",
                "-l",
                "a=b",
                "--image",
                "alpine:3.21",
                "--",
                "sh",
                "-c",
                "x"
            ])
        );
        assert_eq!(crate::keepbox::image_of(&run), "alpine:3.21");
        assert_eq!(crate::keepbox::workload_of(&run), "sh -c x");
        assert_eq!(
            as_box_argv(os(&["container", "run", "--keep", "alpine"])),
            os(&["box", "--keep", "--image", "alpine"])
        );
        let boxed = os(&["box", "rk", "--image", "alpine", "--keep", "--", "true"]);
        assert_eq!(as_box_argv(boxed.clone()), boxed);
    }
}
