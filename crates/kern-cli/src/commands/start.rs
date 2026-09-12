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
pub fn box_plan(name: &str, profiles: &[String], config: Option<&str>) -> Result<(), Error> {
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
    let holder = crate::pod::holder_pid(pod).ok_or_else(|| {
        Error::Sandbox(format!(
            "no running pod '{pod}' - create it first with `kern pod create {pod}`"
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
    // reviewer found in the relay wiring, arriving by a different door.
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
fn point_the_box_at_the_egress_proxy(
    args: &BoxRunArgs,
    env: &mut Vec<(String, String)>,
) -> Result<(), Error> {
    if args.egress_allow.is_empty() {
        return Ok(());
    }
    if args.detached {
        return Err(Error::Sandbox(
            "--egress-allow is foreground-only for now (the filter's lifetime is tied to the box); \
             drop -d"
                .to_string(),
        ));
    }
    if args.share_net || args.pod.is_some() {
        return Err(Error::Sandbox(
            "--egress-allow filters the box's OWN isolated network, so it can't combine with --net \
             (host network) or --pod (shared pod network)"
                .to_string(),
        ));
    }
    eprintln!(
        "kern: note: --egress-allow gives the box outbound to the listed domains only (over an HTTP \
         CONNECT/forward proxy; the box's isolated netns has no other route). It resolves and pins the \
         dialed host, refuses non-public resolved IPs (SSRF), and tunnels only ports 80/443. The one \
         hole it can't close is domain fronting on a SHARED CDN (SNI != CONNECT host); see \
         docs/EGRESS.md. For a fully hostile workload prefer a microVM with a real firewall."
    );
    let proxy = format!("http://127.0.0.1:{EGRESS_PROXY_PORT}");
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        env.push((k.to_string(), proxy.clone()));
    }
    Ok(())
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
fn seed_empty_named_volumes(lower: &str, volumes: &[Volume]) {
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
    let lower = lower.to_string();
    let owned: Vec<(String, String)> = seedable
        .iter()
        .map(|v| (v.source.clone(), v.target.clone()))
        .collect();
    let seed = move |_ranged: bool| {
        seed_now(&lower, &owned);
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
fn seed_now(lower: &str, volumes: &[(String, String)]) {
    let chain: Vec<String> = lower.split(':').map(str::to_string).collect();
    for (source, target) in volumes {
        let src = std::path::Path::new(source);
        let rel = target.trim_start_matches('/');
        if chain.len() >= 2 {
            let _ = crate::commands::merged_view_extract(
                &chain,
                crate::commands::Extract::Contents(rel),
                src,
            );
        } else {
            let from = std::path::Path::new(&chain[0]).join(rel);
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
        let from = std::path::Path::new(&chain[0]).join(rel);
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
    let standalone_persistent = args.detached && args.restart.persistent() && args.pod.is_none();
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
/// image on disk: the resolution rules themselves are `resolve_image_user`'s, and are tested there.
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
    let name = BoxName::parse(args.name).map_err(Error::InvalidBox)?;
    // The caller's (an SDK's) "box started" fd, read and VALIDATED up front, BEFORE the box is forked.
    // CLOEXEC is deferred past the scope re-exec by `cloexec_started_fd` below (see both docstrings for
    // why the systemd-run re-exec forces the split); written once, at the terminal exit arm below.
    let started_fd = started_signal_fd();
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
    if std::env::var_os("KERN_SCOPE").is_none() && registry::name_taken(name.as_str()) {
        return Err(Error::AlreadyRunning(format!(
            "a box named '{}' is already running",
            name.as_str()
        )));
    }
    pt.mark("parent:name-check");
    // FLEET LIMITS (env-configured, deployment-level). Checked only in the OUTER process (KERN_SCOPE
    // unset), like the name check: the scoped inner re-run is the SAME box, already counted.
    if std::env::var_os("KERN_SCOPE").is_none() {
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
    // A box "asked for DNS" if it named ANY of the three: a `search` line alone is still a request
    // to own the file, and owning it in a pod means not sharing the pod's.
    let dns_requested =
        !args.dns.is_empty() || !args.dns_search.is_empty() || !args.dns_options.is_empty();
    let mut inherited_nameservers: Vec<String> = Vec::new();
    let pod_holder = join_pod_and_bind_its_files(
        args.pod,
        name.as_str(),
        &mut volumes,
        dns_requested,
        &mut inherited_nameservers,
        args.pod_bridge.is_some(),
    )?;
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
    // `--nice` (an explicit flag) overrides a profile's `nice`.
    let nice: Option<i32> = args.nice.map(|n| n as i32).or(nice);
    // Flatten the resolved vGPIO profiles into the device/sysfs paths the box will expose.
    let mut vgpio_devs: Vec<String> = Vec::new();
    let mut vgpio_sysfs: Vec<String> = Vec::new();
    for vg in vgpio {
        vgpio_devs.extend(vg.devs);
        vgpio_sysfs.extend(vg.sysfs);
    }
    let cpus = clamp_cpus(cpus);
    // Clamp the pin list to the host CPUs too (flag OR profile), so an over-wide `0-9999` becomes the
    // valid subset instead of aborting the box with systemd's raw "Failed to parse AllowedCPUs".
    // Refuses outright when NOTHING in the list exists here: see `clamp_cpuset`.
    let cpuset = clamp_cpuset(cpuset)?;
    // `--show-config`: a dry run - print the resolved box configuration and exit BEFORE any host-side
    // mount or the systemd-scope re-exec, so nothing is created or torn down.
    if args.show_config {
        print_resolved_config(&args, name.as_str(), memory, cpus, cpuset.as_deref(), nice);
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
    // the lot. (An INTERNAL build lower, `overlay_lower`, is kern-generated and is not user input.)
    if let Some(r) = args.rootfs {
        crate::secret::guard_host_path(r, "--rootfs")?;
    }
    // The lower/base rootfs: an explicit --rootfs, or pull --image into a local cache. An --image
    // also yields its OCI runtime config (Entrypoint/Cmd/Env/WorkingDir/User) - the defaults below.
    let (lower, image_config) = match (args.overlay_lower, args.rootfs, args.image) {
        // Build RUN step: an explicit (possibly colon-joined multi-) lower, no image config.
        (Some(ol), _, _) => (ol.to_string(), kern_oci::ImageConfig::default()),
        (None, Some(r), _) => (r.to_string(), kern_oci::ImageConfig::default()),
        // `--image` may be a pulled (flat) OR a locally-built (layered) image - resolve both. The
        // `--pull` policy rides all the way down to the one site that hits the network (`pull_to_cache`);
        // `scratch` and locally-built images short-circuit before that, so `never` naturally passes them.
        (None, None, Some(img)) => resolve_image_depth(img, 0, args.pull)?,
        (None, None, None) => return Err(Error::Sandbox("need --rootfs or --image".to_string())),
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
        let mut merged = parse_envs(&image_config.env)?;
        merged.extend(env);
        env = merged;
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
    let (ssh, mut eff_ports) = prepare_ssh(&name, args.ssh_port, args.ssh_key, args.ports)?;
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
            "kern: note: {moved} published port(s) bound to 127.0.0.1 by the host's \
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
    let ports: &[kern_isolation::PortMap] = &eff_ports;
    // Fail fast if a `-p` host port is already taken (by another box or any process): otherwise the
    // forwarder fails inside its fork - whose stderr a detached box swallows - and the box would
    // print "started" while nothing actually listens.
    if let Err((hp, e)) = kern_isolation::preflight_ports(ports) {
        // Tell the two failures apart. `EACCES` on a port <1024 is NOT "in use": rootless kern lacks
        // CAP_NET_BIND_SERVICE, so the fix is a higher port - sending the user to `kern ps`/`kern stop`
        // would chase a phantom holder (the old message did). `EADDRINUSE` (or any other errno) IS the
        // taken-port case, where AlreadyRunning's "run `kern ps` … `kern stop`" hint fits.
        if e.raw_os_error() == Some(libc::EACCES) && hp < unprivileged_port_start() {
            let start = unprivileged_port_start();
            return Err(Error::Sandbox(format!(
                "cannot publish port {hp}: this host lets an unprivileged process bind from {start} \
                 upward (net.ipv4.ip_unprivileged_port_start) and kern is rootless, so it lacks the \
                 CAP_NET_BIND_SERVICE a lower port needs. Publish it on a host port >={start} \
                 instead (e.g. -p 8080:80), or have the machine's owner lower that sysctl"
            )));
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
        let holder = crate::registry::list().into_iter().find(|b| {
            b.ports
                .split(',')
                .filter_map(|p| p.split("->").next())
                .filter_map(|a| a.rsplit(':').next())
                .any(|p| p.trim().parse::<u16>() == Ok(hp))
        });
        return Err(Error::AlreadyRunning(match holder {
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
            None => format!(
                "cannot publish host port {hp}: {e} - and no running kern box is publishing it, so \
                 it is held by something else on this machine (another runtime, a dev server, a \
                 systemd unit). `ss -ltnp | grep :{hp}` names it"
            ),
        }));
    }
    // `--hostname`: validate before it reaches `sethostname`. `--tmpfs`: parse the Docker-style
    // specs (blocking a tmpfs over the hardened mounts). `--user`: parse UID[:GID].
    let hostname = validate_hostname(args.hostname)?;
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
    // `resolve_image_user` answers for every spelling - `1000`, `1000:2000`, `keycloak`,
    // `keycloak:root` - so `parse_user` is only the fallback for a spec the image cannot resolve,
    // which is where the two arms below deliberately differ.
    let user_or_image = |u: &str| match resolve_image_user(u, &lower) {
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
    // else (measured; see `image_supplementary_gids`), so an operator writing `--user 1000:1000`
    // still gets that pair and nothing added to it.
    let user_spec = args
        .run_as
        .filter(|u| !u.is_empty())
        .or(image_config.user.as_deref().filter(|u| !u.is_empty()));
    let extra_gids = match user_spec {
        Some(spec) => image_supplementary_gids(spec, &lower),
        None => Vec::new(),
    };
    // HOME FOLLOWS THE USER, as a DEFAULT under both the image's own `Env` and the caller's `-e`:
    // it is only added when neither of those named it, so an explicit `HOME=` still wins. The box
    // keeps `/root` when it runs as box root, which is that uid's home in every image that has one.
    // See `image_user_home` for what a fixed `/root` cost a non-root workload.
    if let Some((uid, _)) = run_as {
        if uid != 0 && !env.iter().any(|(k, _)| k == "HOME") {
            env.insert(0, ("HOME".to_string(), image_user_home(uid, &lower)));
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
        std::env::var_os("KERN_SECCOMP").as_deref(),
        args.security_profile,
    )?;
    let mut cap_drops = args.cap_drop.to_vec();
    let mut read_only = args.read_only;
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
            "kern: security-profile=untrusted: seccomp={sec}, {caps_line}, read-only=on \
             (Landlock and --require-limits untouched)"
        );
    }
    // `--cap-add`/`--cap-drop`: resolve names to a CapSpec (unknown name → error) layered on the
    // always-dropped dangerous baseline.
    let caps = crate::caps::resolve(args.cap_add, &cap_drops)?;

    // Always an overlay (image/rootfs = read-only lower, private upper takes writes).
    // `--read-only` then remounts that overlay read-only after pivot.
    let (spec, scratch) = build_spec(BuildSpec {
        name: &name,
        lower,
        cmd,
        read_only, // profile-adjusted: `--security-profile=untrusted` forces read-only on
        seccomp_mode, // resolved above (explicit KERN_SECCOMP > profile > default), not from env here
        landlock_rw: args.landlock_rw.to_vec(),
        net_ips: args.net_ips.to_vec(),
        pod_bridge: args.pod_bridge.clone(),
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
        // `--ssh` and a non-root `--user` imply the uid/gid *range* mapping: sshd's privsep needs a
        // working `setgroups` (a single-uid map forbids it via `/proc/self/setgroups=deny`), and a
        // non-zero target uid must be mapped in. With the range (via `newgidmap`/`newuidmap`) both
        // work; if the helpers are absent the box falls back to single-uid. Those three are the
        // caller ASKING, so an unavailable range is reported; the per-image default is not.
        uid_range: if args.uid_range || ssh.is_some() || non_root_user {
            UidRange::Requested
        } else if image_default_uid_range {
            UidRange::ImageDefault
        } else {
            UidRange::Off
        },
        bind_rootfs: args.bind_rootfs,
        privileged: args.privileged,
        require_limits: args.require_limits,
        allow_uncapped: args.allow_uncapped,
        overlay_upper: args.overlay_upper.map(str::to_string),
        memory,
        shm_size: args.shm_size,
        memory_swap_max: args.memory_swap_max,
        cpus,
        cpuset,
        vgpio_devs,
        vgpio_sysfs,
        vdisks,
        secrets,
        ssh,
        hostname,
        tun: args.tun,
        init: args.init,
        tmpfs,
        run_as,
        extra_gids,
        pids_max: args.pids_limit,
        caps,
        io_max: vdisk_io_max,
        io_weight: args.io_weight,
        extra_hosts: resolve_add_hosts(args.add_hosts, args.share_net),
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
        timeout: img_health.timeout.unwrap_or(args.health_timeout),
        action: health_action,
    };
    // ONE POLICY OBJECT, BUILT ONCE, and computed BEFORE the branch so the detached path and the
    // systemd-managed path cannot bound their logs differently. `LogCap::default()` is what every
    // box had before the flags existed, so an unset flag changes nothing.
    let log_cap = crate::commands::boxlog::LogCap {
        max_bytes: args
            .log_max_size
            .unwrap_or(crate::commands::boxlog::BOX_LOG_MAX_BYTES),
        files: args.log_max_file.unwrap_or(2),
    };
    if args.detached {
        return run_detached(
            &name,
            spec,
            scratch,
            ports,
            &mounted_vols,
            args.pod.unwrap_or(""),
            restart,
            restart_always,
            health_cfg,
            args.timeout,
            &args.labels.join(","),
            stop_signal,
            args.stop_grace,
            args.restart_max,
            args.def_hash,
            log_cap,
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
        }
        let (cap_drop_all, cap_drops, cap_adds) = registry::cap_fields(&spec.caps);
        let inst = registry::Instance {
            name: name.as_str().to_string(),
            pid,
            pid1_recorded: 0,
            pid1_starttime: 0,
            rootfs: spec.root.clone(),
            command: spec.command.join(" "),
            started: registry::now_unix(),
            starttime: registry::proc_starttime(pid),
            ports: ports_summary(ports),
            volumes: mounted_vols.clone(),
            pod: args.pod.unwrap_or("").to_string(),
            workdir: spec.workdir.clone().unwrap_or_default(),
            run_as: spec.run_as,
            extra_gids: spec.extra_gids.clone(),
            egress: args.egress_allow.join(","),
            landlock_rw: spec.landlock_rw.join(","),
            labels: args.labels.join(","),
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
    // seconds. The watchdog MUST be forked here - BEFORE `run_in_sandbox_with` does its
    // `unshare(CLONE_NEWPID)` - so it lives in the host (ancestor) pid namespace; a process forked
    // after the unshare would land INSIDE the box's namespace, where a non-init member can't signal
    // the ns-init. It learns the box's PID 1 over a pipe (written by `on_started`). Skipped for a
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
    // process forked after the `unshare(CLONE_NEWPID)` lands INSIDE the box's pid namespace, where it
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
    // `run_in_sandbox_with` does `unshare(CLONE_NEWPID)`). Spawning them from the `on_started` callback
    // instead would land them in the BOX pid namespace (box_run's `pid_for_children` is the box pidns by
    // then), where a helper becomes an un-reapable zombie on box exit and deadlocks the pidns teardown:
    // the box "runs, filters, then never exits" until `--timeout`. The pump does not know the box init
    // pid yet; it is delivered over a pipe in the callback below. The guard is held for the box's
    // lifetime; dropping it (after the box exits) SIGKILLs and reaps both helpers. Fail-CLOSED: on any
    // failure the box simply has no outbound.
    let mut egress_pending: Option<crate::egress::EgressPending> = None;
    if !args.egress_allow.is_empty() {
        match crate::egress::spawn(args.egress_allow, EGRESS_PROXY_PORT) {
            Ok(p) => egress_pending = Some(p),
            Err(e) => eprintln!(
                "kern: warning: egress filter failed to start ({e}); the box has NO outbound"
            ),
        }
    }
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
    // THE READINESS PIPE ON THE FOREGROUND PATH, when a caller asked for it with `KERN_ALIVE_FD`.
    // `-d` builds its own (the launcher blocks on it to print a truthful "started"), and this path had
    // no reader, so it passed `None`. An SDK is a reader: it needs to tell "the workload was slow" from
    // "kern never reached `execvp`", and those are the same overrun without this fd. See
    // `alive_signal_fd`. `None` when unset or unusable, which is byte-for-byte the old behaviour.
    let alive_fd = alive_signal_fd();
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
            if let Some(p) = egress_pending.take() {
                match p.deliver(pid1) {
                    Ok(g) => egress_guard = Some(g),
                    Err(e) => {
                        // The in-box proxy port never came up, so this box has NO outbound access,
                        // not even to the domains the caller allowed. Kill it here rather than let the
                        // workload run against a dead proxy and fail with a `Connection refused` that
                        // names neither the cause nor the flag: PID 1 is signalled before it reaches
                        // the workload's exec, and the launcher turns the recorded message into the
                        // box's own error.
                        unsafe { libc::kill(pid1, libc::SIGKILL) };
                        egress_failed = Some(e);
                    }
                }
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
        registry::unregister(path);
    }
    pt.mark("parent:teardown");
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
                             \"<size>\"` in a vcpu: profile) if the workload needs more. On a device \
                             with unified memory, GPU allocations count against the same cap."
                        );
                    }
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
    // Fold any leading resource-profile tokens (`vcpu:name` …) into the caps - explicit flags win -
    // and find where the real command begins.
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
        (!vgpio.is_empty() || !vdisk.is_empty()) && std::env::var_os("KERN_SCOPE").is_none();
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
        std::env::set_var("KERN_VGPIO_NAME", names.join(","));
        std::env::set_var("KERN_VGPIO_PINS", pins.join(","));
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
    // `--landlock-rw` reaches the post-re-exec pass as argv, which is verbatim today
    // (`shim::effective_args` returns `env::args()`) and stays correct only as long as nothing ever
    // rewrites, normalises or reorders it. That is an invariant of the code, not of the type: the day
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
        std::env::remove_var(LANDLOCK_REQUIRED_ENV);
    } else {
        std::env::set_var(LANDLOCK_REQUIRED_ENV, "1");
    }
    // Robust caps via a transient systemd user scope whose MemoryMax/CPUQuota track the caps; this
    // re-execs once and returns here under KERN_SCOPE. Where systemd --user isn't present it's a
    // no-op and the best-effort in-process cgroup below applies the same caps.
    let cpus = clamp_cpus(cpus);
    let cpuset = clamp_cpuset(cpuset)?;
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
    reexec_in_scope_if_possible(ScopeReexec {
        memory,
        memory_swap_max,
        cpuset: cpuset.as_deref(),
        cpus,
        pids_max: None,
        allow_direct: true, // `kern run` forks its workload below, so it can hold the guard and clean up
        die_with_parent: false,
        allow_uncapped: kern_common::env_flag("KERN_ALLOW_UNCAPPED"),
    });
    // TWO INDEPENDENT DECISIONS, AND CONFLATING THEM IS WHAT LEFT A LEAK ON THE HOSTS THAT HAD IT.
    //
    // `direct` answers "may this relocate into kern's delegated `kern.slice`", which needs a systemd
    // user manager. `run_should_fork` answers "must this process leave a supervisor behind to reap the
    // workload and remove its leaf", which does NOT. The first version of this change used `direct`
    // for both, so it forked on exactly the hosts that never leaked (there the leaf lives inside the
    // transient scope and systemd reaps the whole unit) and left the leaking hosts untouched.
    //
    // MEASURED by an outside reviewer, 2026-09-09, same binary, two hosts, 200 sequential `kern run`:
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
        && std::env::var_os("KERN_SCOPE").is_none()
    {
        eprintln!(
            "kern: warning: requested resource cap(s) could not be enforced on this host (cgroup \
             delegation unavailable) - the command runs UNCAPPED."
        );
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
        && !kern_common::env_flag("KERN_ALLOW_UNCAPPED")
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
                 explicit `--memory <size>` (applied best-effort on this path), or set \
                 KERN_ALLOW_UNCAPPED=1 to say the uncapped run is intended and silence this."
            );
        } else {
            eprintln!(
                "kern: warning: this host could not give the command a memory cgroup, so kern's \
                 DEFAULT memory cap is not in force - it runs with no RAM ceiling and no OOM \
                 backstop, in the cgroup of whatever started it. `kern doctor` reports which part is \
                 missing; an explicit `--memory <size>` is applied best-effort on this path, and \
                 KERN_ALLOW_UNCAPPED=1 says the uncapped run is intended and silences this."
            );
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
    ),
    Error,
> {
    let Some(port) = ssh_port else {
        return Ok((None, ports.to_vec()));
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
        bind_ip: 0x7f00_0001,
        host: port,
        box_port: 22,
        udp: false,
    }); // 127.0.0.1:<port> -> box :22
    let id = hint_key.map(|k| format!(" -i {k}")).unwrap_or_default();
    // `accept-new`, and no known-hosts override at all. The line used to read
    // `-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null`, which is two problems in one
    // hint. It is not portable: a box started inside kern's WSL distro is most often reached with
    // Windows' own ssh.exe, where the null device is `NUL` and `/dev/null` is a path that does not
    // exist, so the printed command fails verbatim on the platform kern ships a bridge for
    // (measured: `Host key verification failed`, then it worked with `NUL`). And it teaches the
    // reader to switch host-key checking off wholesale to silence one first-connection prompt.
    // `accept-new` pins the key on first sight and still refuses a CHANGED one, which is the part
    // worth keeping; it needs OpenSSH 7.6 (2017), older than any Windows that ships ssh.exe.
    eprintln!("kern: ssh: ssh -p {port}{id} -o StrictHostKeyChecking=accept-new root@127.0.0.1");
    Ok((Some(kern_isolation::SshSetup { authorized_key }), eff))
}

/// `kern exec <name> [--env K=V] [--workdir <dir>] [-- cmd...]` - run a command inside an
/// already-running box, joining its namespaces. Defaults to `/bin/sh`. Propagates the exit code.
///
/// `as_workload` picks WHOSE identity the command runs under, and the two callers want opposite
/// answers. `kern exec <box>` stays box-root: it is the operator's way in, and with no `--user` flag
/// on a frozen CLI surface, defaulting it to the workload would leave no way back to root at all.
/// `kern compose <file> exec <service>` passes `true`, because Docker's `compose exec` runs as the
/// service's configured user and a script that reads `whoami` must not get a different answer here.
/// The escape hatch needs no new flag and already exists: a compose service IS a box with a name, so
/// `kern exec <that name>` is the root way in.
pub fn exec(
    name: &str,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    tty: bool,
    as_workload: bool,
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
    // PID 1 of the box. Older entries (or a race before the supervisor recorded it) → fall back
    // to the supervisor's sole child.
    let pid1 = match inst.live_pid1() {
        Some(p) => p,
        None => registry::box_init_under(inst.pid)
            .ok_or_else(|| Error::Sandbox("could not locate the box's main process".to_string()))?,
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
    let (box_caps, box_seccomp, box_aa) = inst.exec_posture()?;
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
    let mut exec_env = registry::box_env(&inst.name, inst.pid);
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
        // WHOSE IDENTITY: see `as_workload` on this function. `kern exec` stays box-root; compose's
        // `exec` re-enters as the service's own uid/gid, read from the SAME registry entry that gave
        // us `pid1`, so a box recreated under this name is entered as itself rather than as whoever
        // held the name before.
        if as_workload { inst.run_as } else { None },
        if as_workload { &inst.extra_gids } else { &[] },
    );

    if let Some(prev) = saved.as_ref() {
        crate::pty::restore(0, prev);
    }
    if let Some(p) = pty.as_ref() {
        unsafe { libc::close(p.master) };
    }
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => Err(Error::Sandbox(e.to_string())),
    }
}

/// Foreground-launcher side of a detached start: block on the readiness pipe until the box `exec`s
/// (EOF = up) or signals failure (one byte → reap the supervisor and report why), then print the
/// "started" line. With no pipe it just announces. Retries the read on `EINTR` so a stray signal
/// isn't misread as a successful start.
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
) -> Result<(), Error> {
    if have_pipe {
        unsafe { libc::close(wr) };
        let mut byte = [0u8; 1];
        let n = loop {
            let r = unsafe { libc::read(rd, byte.as_mut_ptr().cast(), 1) };
            if r < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break r;
        };
        unsafe { libc::close(rd) };
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
            return Ok(());
        }
        if n > 0 && supervised {
            // Docker returns immediately for `-d --restart` on a box that trips its first start; the
            // supervisor keeps retrying in the background. Hand back so the caller (and `compose up`)
            // proceeds instead of hanging on a supervisor that may never exit.
            let n = name.as_str();
            eprintln!(
                "kern: box '{n}' failed its first start attempt; the --restart supervisor is \
                 retrying (see `kern logs {n}`)"
            );
            return Ok(());
        }
        if n > 0 {
            let mut st = 0i32;
            crate::eintr::waitpid(child, &mut st, 0);
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
                .and_then(|p| read_log_reason(&p));
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
    let msg = format!(
        "{}{} started{} {}'{n}'{} {}[pid {child}, detached]{}\n  {}next: kern ps {} kern logs {n} {} kern stop {n}{}\n",
        p.g, gl.ok, p.z, p.b, p.z, p.d, p.z, p.d, gl.dot, gl.dot, p.z
    );
    let _ = std::io::Write::write_all(&mut std::io::stderr(), msg.as_bytes());
    Ok(())
}

/// Supervisor loop: run the box and wait for it; with `--restart` (on-failure) re-run it on a
/// non-zero exit, up to a cap with a 1 s backoff so a perpetually-crashing box eventually gives up.
/// Each attempt is a FRESH child - `run_in_sandbox_with` unshares its *caller*, so it can't be
/// re-run in place (the second `unshare` would `EINVAL`); the supervisor stays un-namespaced and
/// just waits. Readiness is signalled only on the first attempt (the launcher already returned by
/// the time a restart happens). `inst` is re-registered with each attempt's box PID 1.
fn supervise_box(
    name: &BoxName,
    spec: &SandboxSpec,
    have_pipe: bool,
    wr: i32,
    ports: &[kern_isolation::PortMap],
    restart: Restart,
    inst: &mut registry::Instance,
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
    let exit_key = std::env::var("KERN_EXIT_KEY")
        .ok()
        .filter(|k| !k.is_empty());
    // The box's log file, resolved here in the SUPERVISOR (whose pid names it) so the runner child
    // can append a diagnosis to it by path. See the pids message below for why by path and not by
    // writing to stderr.
    let log_path = registry::logs_dir()
        .ok()
        .map(|d| d.join(format!("{}-{}.log", name.as_str(), std::process::id())));
    let mut attempt = 0u32;
    let final_code = loop {
        let ready = if attempt == 0 {
            have_pipe.then_some(wr)
        } else {
            None
        };
        // Wall-clock this attempt so a box that stayed up counts as recovered (see the reset below).
        let started = std::time::Instant::now();
        let runner = unsafe { libc::fork() };
        if runner == 0 {
            // Filled by the callback below, which runs in THIS process: the supervisor never sees
            // it, which is why the diagnosis is written here rather than after the wait.
            #[allow(clippy::type_complexity)]
            let pids_baseline: std::cell::OnceCell<
                Option<(Option<u64>, std::path::PathBuf)>,
            > = std::cell::OnceCell::new();
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
            unsafe { libc::_exit(code) };
        }
        // Supervisor: drop our readiness-pipe copy so the launcher sees EOF when the box exec()s.
        if attempt == 0 && have_pipe {
            unsafe { libc::close(wr) };
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
        // `always`/`unless-stopped`: restart on ANY exit (including 0), uncapped - Docker's contract,
        // kept up for the stack's lifetime. `on-failure`: only a non-zero exit, capped at max_restarts.
        let restart_now = if restart.always {
            true
        } else {
            restart.on_failure && code != 0 && attempt <= max_restarts
        };
        if restart_now {
            if restart.always {
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
            unsafe { libc::sleep(backoff) };
            continue;
        }
        break code;
    };
    // The box has finished for good (no restart left). Record the final exit code for `kern wait`,
    // keyed `<name>-<pid>` (our own pid = the registered pid). Written LAST here, and this whole call
    // returns BEFORE the caller unregisters the instance file, so a `wait` that sees the box leave
    // `list()` finds the code. If compose is also waiting, record it under its stack+run-scoped key too.
    registry::set_box_exit(
        std::process::id() as i32,
        inst.starttime,
        final_code,
        &inst.name,
        &inst.pod,
        &inst.command,
    );
    if let Some(key) = &exit_key {
        registry::set_exit(key, final_code);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_detached(
    name: &BoxName,
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
) -> Result<(), Error> {
    // Readiness pipe: the read end stays in this foreground launcher; the write end travels down
    // to the box's PID 1 and is closed on a successful `execvp` (FD_CLOEXEC) → we read EOF = "the
    // box is up". If the box fails to set up or exec, it writes one byte first → we report a
    // truthful failure instead of a misleading "started". No sleep, no poll: the read returns the
    // instant the box is up or has failed, so the only added latency is the box's real start time.
    let mut fds = [0i32; 2];
    let have_pipe = unsafe { libc::pipe(fds.as_mut_ptr()) } == 0;
    let (rd, wr) = (fds[0], fds[1]);

    let child = unsafe { libc::fork() };
    if child < 0 {
        if have_pipe {
            unsafe {
                libc::close(rd);
                libc::close(wr);
            }
        }
        return Err(Error::Sandbox("fork for detach failed".to_string()));
    }
    if child > 0 {
        return await_box_started(name, child, rd, wr, have_pipe, restart || restart_always);
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
    // Send the box's stdout/stderr to a per-box log file (so `kern logs` can show it).
    let log = registry::logs_dir()
        .ok()
        .map(|d| d.join(format!("{}-{}.log", name.as_str(), pid)));
    detach_stdio(log.as_deref(), log_cap);
    let (cap_drop_all, cap_drops, cap_adds) = registry::cap_fields(&spec.caps);
    let mut inst = registry::Instance {
        name: name.as_str().to_string(),
        pid,
        pid1_recorded: 0,
        pid1_starttime: 0,
        rootfs: spec.root.clone(),
        command: spec.command.join(" "),
        started: registry::now_unix(),
        starttime: registry::proc_starttime(pid),
        ports: ports_summary(ports),
        volumes: volumes.to_string(),
        pod: pod.to_string(),
        workdir: spec.workdir.clone().unwrap_or_default(),
        run_as: spec.run_as,
        extra_gids: spec.extra_gids.clone(),
        egress: String::new(), // --egress-allow is foreground-only; a detached box never carries it
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
    );
    // Box is gone - cancel the sidecars and reap them (they're our children; setsid doesn't change
    // parentage) so we don't leave brief zombies behind before this supervisor exits.
    if let Some(tp) = timeout_pid {
        if signal_helper(tp, libc::SIGKILL) {
            crate::eintr::reap(tp);
        }
    }
    stop_health_checker(health_pid, name.as_str(), pid);
    if let Some(p) = path {
        registry::unregister(&p);
    }
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
    let mut it = crate::shim::effective_args().into_iter().peekable();
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
/// was nothing, and a reviewer measured 200 sequential `kern run` leaving 201 directories behind.
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
    // delegate the controller ran with unbounded RAM and said nothing, and an outside tester
    // reported the limits as "soft" with no way to tell a degraded host from a degraded runtime.
    //
    // What kept it that way is a real objection: a line on every 2 ms box start is noise that trains
    // the reader to skip it. The resolution is that this is a HOST fact and not a box fact, so it is
    // stated once per host. An explicit request keeps its per-invocation warning, because asking for
    // `--memory 256m` and silently not getting it is a different failure from starting a default box.
    if !allow_uncapped
        && std::env::var_os("KERN_BUILD_STEP").is_none()
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
    let Ok(self_exe) = std::env::current_exe() else {
        return;
    };
    // The DECIDED argv, not the typed one: a `docker …` invocation has already been translated into
    // kern's dialect here, and replaying the original would hand the second pass docker syntax that
    // kern's own parser rejects. `current_exe()` above resolves a symlink, so the shim cannot
    // re-identify itself on the far side and cannot translate again.
    let args: Vec<String> = crate::shim::effective_args();

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
    // `cpuset` is already clamped to the host CPUs at the box/run entry (`clamp_cpuset`), so it can't
    // be an over-wide `0-9999` that systemd would reject with a raw "Failed to parse AllowedCPUs".
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
    cmd.arg(kern_isolation::systemd_scope_mode()) // `--system` as root, else `--user`
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
        .arg("--")
        .arg(self_exe)
        .args(&args)
        .env("KERN_SCOPE", "1")
        // `args` is already kern's dialect (see `shim::effective_args`), so the child must NOT
        // translate again. It would otherwise re-enter the shim whenever the binary it re-execs is
        // itself named `docker` (a COPY rather than a symlink) and reject `box …` as "no kern
        // equivalent". Not folded into KERN_SCOPE: a user can set that one by hand to opt out of the
        // scope path, and it would then be claiming something about the argv that isn't true.
        .env(crate::shim::DIALECT_ENV, "1");
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
    use super::*;

    fn hc(test: &[&str]) -> kern_oci::ImageHealthcheck {
        kern_oci::ImageHealthcheck {
            test: test.iter().map(|s| (*s).to_string()).collect(),
            interval_ns: Some(30_000_000_000),
            timeout_ns: Some(5_000_000_000),
            start_period_ns: Some(2_000_000_000),
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
