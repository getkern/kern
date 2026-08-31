//! Housekeeping verbs: `version`, `help`, `examples`, `prune`, `gc`, `bench`, `update`, `events`,
//! `uninstall`.
//!
//! What maintains the installation rather than running a workload. Split out of `commands/mod.rs`
//! for size; the parent keeps the box lifecycle these read, reached through `use super::*`.

use super::*;

pub fn version() -> Result<(), Error> {
    println!("kern {}", kern_common::VERSION);
    Ok(())
}

pub fn help() -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    println!("{}", crate::ui::logo(&p));
    println!("{}", help_text(&p));
    Ok(())
}

/// The full reference as a STRING, so `kern <verb> --help` can serve a slice of the very same text.
///
/// `kern volume --help` used to print this whole page, and so did `pod`, `config`, `compose`,
/// `image` and `top`: six out of six subcommands answered the universal `<tool> <verb> --help`
/// habit with a 160-line wall in which the reader has to find their verb. Writing a second help
/// text per verb is the obvious fix and the wrong one, because two texts describing one parser
/// drift, which is the defect class this project keeps paying for. So there is still exactly one
/// text and [`help_for`] filters it.
fn help_text(p: &crate::ui::Palette) -> String {
    let (b, c, d, z) = (p.b, p.c, p.d, p.z);
    // The compose sub-verbs come from COMPOSE_VERBS, so help cannot describe a set of verbs the
    // parser does not accept, nor omit one it does.
    let cv = compose_verbs_help();
    format!(
        "\
  {b}kern {ver}{z}{d}: a fast, rootless sandbox & virtual resource runtime{z}

{b}USAGE:{z}
    kern <COMMAND> [ARGS]

{b}COMMANDS:{z}
  {d}Essentials{z}
    {c}box{z} <name> (--rootfs <dir>|--image <ref>) [opts] [-- CMD...]   Run CMD in a sandbox
    {c}box{z} <name> [PROFILE…] --plan                                   Preview the isolation sequence + device grants
    {c}run{z} [--memory M] [--cpus N] [vcpu:PROFILE] [--] CMD...         Run CMD under CPU/mem caps (no sandbox)
    {c}run{z} --landlock-rw <path> [--] CMD...                           Confine CMD's writes to <path> (kernel LSM, no sandbox)
    {c}exec{z} <name> [-it] [--env K=V] [-w <dir>] [--] [CMD...]         Run CMD in a running box
    {c}ps{z} [-a] [--json] [-q] [--filter name=|status=|id=|label=] [--format T] List boxes (-a also lists recently-exited: transient, gc-reaped, no name hold)
    {c}logs{z} <name> [--tail N] [-f|--follow]                           Show a box's output
    {c}stop{z} <name>... | --all                                         Stop box(es), or all

  {d}Images{z}
    {c}search{z} <query> [--json]                                        Search Docker Hub for images
    {c}pull{z} <image>                                                   Fetch an image into the cache (`--image` uses it)
    {c}pull{z} <image> --dest <dir> [--platform os/arch]                 Extract a rootfs instead, for `--rootfs`
    {c}push{z} <local-ref> [as <remote-ref>]                             Publish a cached image to a registry
    {c}tag{z} <src> <dst>                                                Give a cached image a second name
    {c}commit{z} <box> <image>                                           Snapshot a running box's fs into a reusable image (warm start)
    {c}build{z} -t <name> [-f Dockerfile] [--build-arg K=V] [ctx]        Build a local image from a Dockerfile
    {c}images{z} [--json]                                                List pulled (cached) images
    {c}rmi{z} <image>...                                                 Remove cached images (frees unshared layers)
    {c}save{z} <image> [-o file]                                         Export an image to a tar (docker load-compatible)
    {c}load{z} [-i file]                                                 Import an image from a tar (docker save format)
    {c}builds{z} [<tag>] [--status S] [-n N] [--json]                    List past builds (build history)
    {c}build{z} logs|inspect|rm|prune <id>                               Inspect/manage build-history records

  {d}Manage boxes{z}
    {c}top{z}                                                            Interactive task manager (TUI)
    {c}stats{z} [--json] [name...]                                       Per-box memory + CPU
    {c}inspect{z} <name> [--json]                                        Full detail for one box
    {c}attach{z} <name>                                                  Stream a box's output live (Ctrl-C detaches)
    {c}cp{z} <box>:<src> <dst> | <src> <box>:<dst>                       Copy a file host<->box
    {c}pause{z} <name>... | --all                                        Freeze box(es) (cgroup freezer)
    {c}unpause{z} <name>... | --all                                      Thaw frozen box(es)
    {c}kill{z} <name>... | killall                                       Stop box(es) (alias of stop)
    {c}rename{z} <old> <new>                                             Give a running box a new name
    {c}update{z} <box> [--memory M] [--cpus N] [--pids-limit P]          Change a running box's caps live (needs delegated cgroup)
    {c}wait{z} <box>...                                                  Wait for box(es) to exit and print the code; one that already exited answers at once
    {c}diff{z} <box> [--json]                                            List filesystem changes vs the image (C/D)
    {c}events{z}                                                         Stream box start/die/rename events (Ctrl-C; best-effort)
    {c}prune{z}                                                          Remove a stopped box's leftovers: logs, health, and the recorded exit code
    {c}gc{z} [--images]                                                  Cleanup: prune + scratch + build layers. --images DELETES every cached image
    {c}recover{z}                                                        Reclaim orphaned scratch of dead boxes (also done by gc)
    {c}history{z} [-n N]                                                 Recently-run boxes

  {d}Multi-box{z}
    {c}compose{z} <file> [{cv}] Run a stack (kern TOML or docker-compose.yml)
    {c}up{z} [--no-pod] / {c}down{z}                                          Bring up / tear down the compose file in this dir
    {c}pod{z} create <name> [--no-outbound] [--uid-range] / pod ls [--json] / pod rm <name>  Shared-network pod (boxes reach each other by name)

  {d}Config & storage{z}
    {c}config{z} [list [--json]|edit|setup|probe|clear]                  List resource profiles; manage kern.toml
    {c}config add{z} <kind:name> [--flags]                              Create a profile (vcpu/vgpio/vdisk), CLI twin of `kern top`
    {c}config rm{z} <kind:name>                                         Delete a profile
    {c}validate{z} [path]                                                Check a kern.toml
    {c}uninstall{z} [--yes] [--keep-images]                              Remove everything kern created (lists it first)
    {c}examples{z}                                                       Print an example kern.toml
    {c}volume{z} <create|rm|edit|prune> / <ls|inspect> [--json]           Manage named volumes
    {c}login{z} [registry] [--username U] / {c}logout{z} [registry]         Registry credentials (private pulls)

  {d}Diagnostics{z}
    {c}doctor{z}                                                         Preflight: will boxes run here?
    {c}probe{z}                                                          Host resources you can put in kern.toml
    {c}info{z}                                                           Runtime + host snapshot
    {c}bench{z} (--image <ref>|--rootfs <dir>) [--bind-rootfs] [-n N]     Time box start→exit latency
    {c}completions{z} <bash|zsh|fish>                                    Print a shell-completion script

{b}OPTIONS for box:{z}
    --rootfs <dir>      Root filesystem to enter
    --image <ref>       OCI image to pull and run (e.g. alpine, alpine:3.19)
    --pull missing|never|always  missing = default (pull only when absent); never = fail if not
                        already cached (no network pull); always = force a fresh pull (atomic swap;
                        a locally-built image is used as-is)
    -d, --detach        Run in the background (track with `kern ps`)
    --read-only         Read-only root (default is a writable overlay)
    -v, --volume S:D[:ro]   Mount into the box (repeatable). S = a host path, a named volume
                        (auto-created; see `kern volume`), or nfs://|smb://|sshfs:// URL
    -e, --env K=V       Set an environment variable (repeatable)
    -w, --workdir <dir> Working directory inside the box
        --entrypoint <a> Replace the image's ENTRYPOINT (repeat for an exec-form list;
                         `--entrypoint \"\"` clears it). Discards the image's CMD, as docker does
    -m, --memory <size> Hard memory cap (e.g. 512m, 1g; default 512m)
    --cpus <n>          CPU cap in cores (e.g. 1.5, 2; default uncapped)
    --cpuset-cpus <list>  Pin to specific CPUs (e.g. 0-3, 0,2,4; default no pinning)
    --memory-swap-max <size>  Swap allowance → cgroup-v2 memory.swap.max (default 0 = swap off)
    -it, -t, -i         Allocate an interactive PTY (shells/REPLs); foreground only
    -p, --publish H:B   Publish box port B on host port H ([ip:]H:B[/tcp|/udp]; a port RANGE
                        like 8000-8010:8000-8010 works; binds 127.0.0.1 by default, use
                        0.0.0.0:H:B to expose on all interfaces; repeatable)
    --add-host N:IP     Add an /etc/hosts entry N → IP in the box; IP may be `host-gateway`
                        (the host's address, to reach a service on the host); repeatable
    --secret SPEC       Deliver a secret as /run/secrets/NAME (mode 0400): SRC[:NAME] (file),
                        NAME=- (from stdin), or NAME=value (inline - the value lands in argv, so
                        it is readable by any user via `ps`: use a file or stdin for a real one);
                        repeatable
    --ssh PORT          Run an in-box sshd, published on host PORT (→ box :22); prints the ssh
                        command (auto-generates a keypair). Needs openssh in the image
    --ssh-key FILE      Authorize this public key instead of generating a throwaway keypair
    --restart           Restart a detached box if it exits non-zero (on-failure)
    --health-cmd <cmd>  Shell command probed in the box; sets ps HEALTH (exit 0 = healthy)
    --health-interval N Seconds between health checks (default 30)
    --health-retries N  Consecutive failures before a box is unhealthy (default 3)
    --health-start-period N  Grace period where failures keep it starting (default 0)
    --health-timeout N  Kill a single check that exceeds N seconds (default 0 = none)
    --health-action A   On unhealthy: restart | stop | none (default none)
    --net [host|none]   Share the host network (bare/host); none = isolated (default)
    --network <mode>    host = share host net (= --net); none = isolated (default)
    --pod <name>        Join a shared-network pod (reach peers by name; see `kern pod`)
    --egress-allow d,d  Restrict outbound to an allowlist of domains via a filtering proxy (foreground-only)
    --hostname <name>   Set the box's hostname (default: the box name)
    --tun               Expose /dev/net/tun in the box (WireGuard / userspace VPN)
    --init              Run a built-in reaping init as PID 1 (no zombies; forwards SIGTERM)
    --pids-limit <N>    Cap the box's process count (pids.max), fork-bomb containment
    --io-weight <N>     cgroup-v2 io.weight, relative I/O priority (1-10000; best-effort)
    --nice <n>          Scheduling niceness for the box workload (-20 high … 19 low)
    --env-file <file>   Load K=V lines from a file into the box env (repeatable; --env wins)
    --config <path>     Use this kern.toml for resource-profile tokens (vcpu:/vgpio:/vdisk:)
    --show-config       Print the resolved box configuration and exit (a dry run)
    -q, --quiet         Suppress the foreground status line
    --verbose           Expand the status line into the full isolation panel
    --tmpfs <path[:sz]> Mount a fresh tmpfs at path in the box (e.g. /tmp:64m; repeatable)
    -u, --user <u[:g]>  Run the box command as this uid[:gid] (numeric; needs the id mapped)
    --cap-add <CAP>     Keep a capability kern would otherwise drop (e.g. NET_ADMIN, or ALL); repeatable
    --cap-drop <CAP>    Drop an extra capability (e.g. NET_RAW, or ALL); repeatable
    --no-uid-range      Use the single-uid map (an --image box maps a uid RANGE by default)
    --stop-signal <s>   Signal sent before the SIGKILL on stop (name or number; default SIGTERM)
    --stop-timeout <n>  Seconds the workload gets to exit before the SIGKILL (default 10; skipped if its init has no handler for the signal)
    --timeout <n>       Auto-stop: SIGTERM at n seconds, SIGKILL 2 seconds later (so n+2 worst case)
    --restart-max <n>   How many times --restart retries before giving up (default 10)
    --ulimit <n=s[:h]>  Set a resource limit (e.g. nofile=1024:2048); rootless can only LOWER; repeatable
    --sysctl <k=v>      Set a namespaced kernel knob (e.g. net.core.somaxconn=1024); repeatable
    -l, --label <k=v>   Attach metadata, selectable with `ps --filter label=`; repeatable
    --landlock-rw <path> Confine writes to these paths with the Landlock LSM; root stays read+exec (repeatable)
                        Also valid on `run`, where it is the only real confinement: it needs no
                        namespace. There it grants ONLY these paths (plus /dev/null and friends),
                        refuses if the kernel has no Landlock, and implies no-new-privs (no sudo)
    --uid-range         Map a sub-uid/gid range (needed for apt/dpkg, www-data); default maps
                        only the caller (faster + more isolated)
    --bind-rootfs       Bind --rootfs directly instead of an overlay, faster on kernels with a
                        slow overlayfs, but the source is mutable & shared (no per-box isolation)
    --privileged        Relax seccomp so a NESTED `kern box` (docker-in-docker style) can start,
                        rootless-only; still blocks kexec/modules/bpf/io_uring (unlike Docker)
    --require-limits    Refuse to start unless the memory and pids caps (incl. their defaults) are
                        actually enforced (the OOM/fork-bomb backstop); cpu/cpuset stay best-effort,
                        as on the scope path. Default warns and runs uncapped
    --allow-uncapped    Accept running uncapped silently where no cgroup is delegated (nested CI);
                        mutually exclusive with --require-limits
    --security-profile <untrusted>  Opt-in hardening bundle (seccomp allowlist + cap-drop ALL +
                        read-only), applied as a base explicit flags override; prints its constituents
    --apparmor <profile>  Enter a pre-loaded AppArmor profile on exec (Docker's --security-opt
                        apparmor=), layered over seccomp; a missing/unloaded profile fails closed
    --plan              Preview the isolation sequence and any device grants, without running

{b}OPTIONS for run:{z}
    -m, --memory <SIZE>     RAM ceiling for the process (e.g. 512m, 2g)
    --memory-swap-max <S>   cgroup v2 swap allowance (NOT Docker's mem+swap total; 0 = no swap)
    --cpus <N>              CPU quota, fractional allowed (0.5 = half a core)
    --cpuset-cpus <LIST>    Pin to these CPUs (e.g. 0-3,8); a CPU that does not exist is dropped
    --config <PATH>         kern.toml to resolve `vcpu:`/`vgpio:`/`vdisk:` profiles against
    --landlock-rw <PATH>    Confine the process's WRITES to PATH (kernel LSM, needs no namespace);
                            everything else stays readable and executable. Repeatable. Refuses to
                            run if this kernel has no Landlock, and implies no-new-privs (no sudo)
    {d}`run` caps a process on the HOST: no image, no namespaces, no sandbox - except --landlock-rw,{z}
    {d}which is a real kernel-enforced write boundary. For full isolation use `box`.{z}

{b}OPTIONS:{z}
    -V, --version  Print version
    -h, --help     Print this help

{d}Docs & issues: {z}{c}https://github.com/getkern/kern{z}",
        ver = kern_common::VERSION
    )
}

/// `kern <verb> --help`: the lines of the full reference that describe THAT verb.
///
/// What it selects, in order:
///   1. every `COMMANDS:` line whose first coloured token is the verb, so `box <name> …` and
///      `box <name> … --plan` both come out for `box` while `ps` does not match `push`;
///   2. the verb's own `OPTIONS for <verb>:` block, if the reference carries one;
///   3. a pointer to `kern --help`, because a filtered page must say it is filtered.
///
/// Falls back to the whole reference when nothing matched. A verb this cannot find is a verb the
/// COMMANDS section does not document, and answering that with an empty page would hide the real
/// defect; `every_verb_has_its_own_help` fails on it instead.
pub fn help_for(verb: &str) -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    let full = help_text(&p);
    // Colour codes sit between the indent and the verb, so matching is done on the line with the
    // escapes REMOVED. Comparing against the raw line would silently stop matching the day the
    // palette changes, and it would stop matching in the direction that looks like success.
    //
    // This is `strip_ansi` and NOT `scrub`-then-`replace`, which is what it was and which was broken
    // in exactly the configuration nobody tests in: `scrub` deletes the ESC byte first, so the
    // `[1m` tail survives and the subsequent `replace(p.b, …)` searches for a sequence that is no
    // longer there. Every match then failed and the filter fell back to the whole reference. With
    // stdout captured the palette is empty and the bug is invisible, which is why the test that
    // covers this saw 75 lines while a terminal saw 161. It is also five allocations per line
    // against one.
    let plain = |s: &str| -> String { strip_ansi(s) };
    let mut out: Vec<String> = Vec::new();
    let mut in_commands = false;
    let mut in_verb_options = false;
    for line in full.lines() {
        let flat = plain(line);
        let trimmed = flat.trim_start();
        if flat.contains("COMMANDS:") {
            in_commands = true;
            continue;
        }
        if trimmed.starts_with("OPTIONS for ") {
            // "OPTIONS for box:" → "box"
            let which = trimmed
                .trim_start_matches("OPTIONS for ")
                .trim_end_matches(':')
                .trim();
            in_verb_options = which == verb;
            in_commands = false;
            if in_verb_options {
                out.push(line.to_string());
            }
            continue;
        }
        if trimmed.starts_with("OPTIONS:") {
            in_commands = false;
            in_verb_options = false;
            continue;
        }
        if in_verb_options {
            out.push(line.to_string());
            continue;
        }
        if in_commands && trimmed.split_whitespace().next() == Some(verb) {
            out.push(line.to_string());
        }
    }
    if out.is_empty() {
        println!("{}", crate::ui::logo(&p));
        println!("{full}");
        return Ok(());
    }
    println!(
        "{b}kern {verb}{z}{d} - from the full reference ({z}{c}kern --help{z}{d} for everything){z}",
        b = p.b,
        z = p.z,
        d = p.d,
        c = p.c
    );
    for line in &out {
        println!("{line}");
    }
    Ok(())
}

/// `kern prune` - garbage-collect leftover `logs/` and `health/` sidecar files from boxes that are
/// no longer running (a detached box's captured log outlives it). Live boxes are never touched.
/// Reports what it reclaimed (feedback-first: an explicit "nothing to prune" rather than silence).
pub fn prune() -> Result<(), Error> {
    let (removed, freed) = registry::prune();
    let p = crate::ui::Palette::detect();
    if removed == 0 {
        println!("{}nothing to prune{}", p.d, p.z);
    } else {
        let files = if removed == 1 { "file" } else { "files" };
        println!(
            "{}pruned{} {removed} {files}, freed {}",
            p.g,
            p.z,
            human_bytes(freed)
        );
    }
    Ok(())
}

pub fn gc(images: bool) -> Result<(), Error> {
    prune()?;
    // Sweep orphaned build layers: a `kern build` that changes a RUN/COPY leaves its old layer dirs
    // in `L/`, referenced by no image. Delete any `L/<key>` (+ `.ok`) not named in a `<tag>.layers`
    // manifest - bounds the layer cache without nuking the shared, still-referenced layers.
    let (n, freed) = sweep_orphan_layers(&cache_dir());
    if n > 0 {
        let p = crate::ui::Palette::detect();
        println!(
            "{}swept{} {n} orphaned build layer{}, freed {}",
            p.g,
            p.z,
            if n == 1 { "" } else { "s" },
            human_bytes(freed)
        );
    }
    // Reclaim orphaned box scratch too (the piece `recover` used to own alone) so `gc` is the single
    // full local cleanup and crashed-box overlay dirs don't accumulate unnoticed.
    let (rec, rfreed) = sweep_orphan_scratch();
    if rec > 0 {
        let p = crate::ui::Palette::detect();
        println!(
            "{}recovered{} {rec} orphaned box scratch dir{}, freed {}",
            p.g,
            p.z,
            if rec == 1 { "" } else { "s" },
            human_bytes(rfreed)
        );
    }
    // Retired/staging image dirs left by `--pull always` (`<ref>.old-*` / `<ref>.pull-*`). Removed
    // ONLY when no box is running: a live box may still hold a retired dir's inodes via its overlay
    // mount (overlayfs opens lower files on demand), so deleting one under a running box would yank it.
    let retired = sweep_retired_images();
    if retired > 0 {
        let p = crate::ui::Palette::detect();
        println!(
            "{}removed{} {retired} stale --pull-always image dir{}",
            p.g,
            p.z,
            if retired == 1 { "" } else { "s" }
        );
    }
    // Reap `kern wait` exit sidecars of boxes whose supervisor is gone and were never waited on.
    let waited = registry::sweep_waitexit_dead();
    if waited > 0 {
        let p = crate::ui::Palette::detect();
        println!(
            "{}removed{} {waited} stale wait-exit record{}",
            p.g,
            p.z,
            if waited == 1 { "" } else { "s" }
        );
    }
    // Reap ORPHANED boxes: a detached box whose SUPERVISOR was SIGKILL'd/OOM'd, but whose PID 1 and
    // `-p` forwarder outlived it - still running, still holding the host port. `list()` now surfaces
    // these as `orphaned` (they used to vanish from the registry while alive); `gc` SIGKILLs each one's
    // recorded cgroup at once (`cgroup.kill`) and drops its record, so a burst of crashed supervisors
    // does not leak ports and processes until the next explicit `kern stop`.
    let orphans = registry::list()
        .into_iter()
        .filter(|b| b.orphaned)
        .filter(registry::reap_orphan)
        .count();
    if orphans > 0 {
        let p = crate::ui::Palette::detect();
        println!(
            "{}reaped{} {orphans} orphaned box{} (supervisor died, cgroup still live)",
            p.g,
            p.z,
            if orphans == 1 { "" } else { "es" }
        );
    }
    // Reap orphaned box CGROUP dirs under kern.slice too (the direct-cap path leaves an empty
    // `kern-box-*` cgroup when a box is SIGKILL'd; normally the next box start sweeps it, but `gc`
    // should too so they don't linger between bursts).
    let boxc = kern_isolation::gc_orphan_box_cgroups();
    if boxc > 0 {
        let p = crate::ui::Palette::detect();
        println!(
            "{}reaped{} {boxc} orphaned box cgroup{}",
            p.g,
            p.z,
            if boxc == 1 { "" } else { "s" }
        );
    }
    if images {
        let p = crate::ui::Palette::detect();
        let cache = cache_dir();
        let freed = dir_size(&cache);
        if freed == 0 {
            println!("{}no cached images{}", p.d, p.z);
        } else if let Err(e) = remove_tree_forced(&cache) {
            // A FAILURE, not a note. This printed to stderr and returned Ok, so `kern gc --images &&
            // echo cleaned` printed "cleaned" over an untouched cache: the caller had no way to tell.
            return Err(Error::Sandbox(format!(
                "could not clear the image cache: {e}"
            )));
        } else {
            println!(
                "{}reclaimed{} the image cache, freed {}",
                p.g,
                p.z,
                human_bytes(freed)
            );
        }
    }
    Ok(())
}

/// `kern bench [--rootfs R] [-n N]` - measure end-to-end box start→exit latency by running N throwaway
/// boxes (each `/bin/true`, foreground) and timing them, then reporting min/median/avg/max +
/// boxes/sec. This is the real user-facing number (it spawns `kern box` just like you would), so it's
/// the honest figure to quote. Needs a `--rootfs` with a `/bin/true` (any busybox/distro rootfs).
pub fn bench(
    rootfs: Option<&str>,
    image: Option<&str>,
    bind_rootfs: bool,
    count: u32,
) -> Result<(), Error> {
    // `--image` resolves through the SAME cache path `kern box --image` uses, so benching an image
    // measures the box a user would actually run, and a second copy of the pull logic never appears
    // here. Before this, bench was the only verb needing a filesystem that did not accept an image:
    // the one command the README asks a newcomer to run was the one needing two commands first.
    // Bench measures the box a user would actually run, so it spawns the SAME command they would:
    // `--rootfs <dir>` or `--image <ref>`, passed through verbatim. Resolving an image to a directory
    // here would have been wrong twice: a locally built image resolves to a COLON-JOINED layer chain
    // that `--rootfs` does not accept, and the timing would stop describing the command being quoted.
    let (flag, value) = match (rootfs, image) {
        (Some(_), Some(_)) => {
            return Err(Error::Usage(
                "bench takes --rootfs <dir> OR --image <ref>, not both",
            ))
        }
        (Some(r), None) => {
            if !std::path::Path::new(r).is_dir() {
                return Err(Error::Sandbox(format!("--rootfs '{r}' is not a directory")));
            }
            ("--rootfs", r)
        }
        (None, Some(img)) => {
            // Warm the cache BEFORE timing: a first-run pull is network time, not box-start time,
            // and folding it into the first sample would inflate max and slander the number.
            resolve_image(img)?;
            ("--image", img)
        }
        (None, None) => {
            return Err(Error::Usage(
                "bench needs --image <ref> (e.g. kern bench --image alpine) or --rootfs <dir>",
            ))
        }
    };
    let self_exe =
        std::env::current_exe().map_err(|e| Error::Sandbox(format!("locating kern: {e}")))?;
    let one = |name: &str| -> Option<std::time::Duration> {
        let t0 = std::time::Instant::now();
        let mut cmd = std::process::Command::new(&self_exe);
        cmd.args(["box", name, flag, value]);
        // Passed through to the box rather than resolved here, for the same reason `--rootfs` and
        // `--image` are: bench must spawn the command it quotes, or it stops describing it.
        if bind_rootfs {
            cmd.arg("--bind-rootfs");
        }
        let ok = cmd
            .args(["--", "/bin/true"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        ok.then(|| t0.elapsed())
    };
    // Warm-up (image/overlay caches, first scope) - discarded.
    let pid = std::process::id();
    if one(&format!("bench-{pid}-warm")).is_none() {
        return Err(Error::Sandbox(
            "bench box failed to run - does the rootfs have /bin/true? (try a busybox/distro rootfs)"
                .into(),
        ));
    }
    let mut times: Vec<std::time::Duration> = Vec::with_capacity(count as usize);
    for i in 0..count {
        if let Some(d) = one(&format!("bench-{pid}-{i}")) {
            times.push(d);
        }
    }
    if times.is_empty() {
        return Err(Error::Sandbox("no bench runs succeeded".into()));
    }
    times.sort();
    let ms = |d: std::time::Duration| d.as_secs_f64() * 1000.0;
    let sum: f64 = times.iter().map(|d| ms(*d)).sum();
    let avg = sum / times.len() as f64;
    let p = crate::ui::Palette::detect();
    // The header names the exact box that was timed, `--bind-rootfs` included: on a host where the
    // overlay mount IS the cost, the two paths differ by more than the rest of box start put
    // together, so a header that omits it leaves two very different numbers looking identical.
    println!(
        "{b}kern bench{z}  {} runs, {} {value}{}",
        times.len(),
        flag,
        if bind_rootfs { " --bind-rootfs" } else { "" },
        b = p.b,
        z = p.z
    );
    println!(
        "  min {:.1} ms · median {:.1} ms · avg {:.1} ms · max {:.1} ms",
        ms(times[0]),
        ms(times[times.len() / 2]),
        avg,
        ms(times[times.len() - 1])
    );
    println!(
        "  {g}{:.0} boxes/sec{z} (serial)",
        1000.0 / avg,
        g = p.g,
        z = p.z
    );
    Ok(())
}

/// `kern update <box> [--memory M] [--cpus N] [--pids-limit P]` - change a RUNNING box's cgroup v2
/// caps in place (Docker `update`), no restart. Writes `memory.max`/`cpu.max`/`pids.max` straight into
/// the box's delegated cgroup and records the memory/pids caps back in the registry; each knob is
/// best-effort where its controller isn't delegated (the same policy as box start). At least one knob
/// is required. Note: lowering `--memory` below live usage can trigger the OOM killer inside the box,
/// exactly as `docker update` does.
///
/// Across a RESTART: an in-process-supervised box (`--restart on-failure`, or an `always` pod member)
/// re-reads the recorded **memory/pids** caps on each restart and re-applies them, so those PERSIST
/// (Docker parity). `--cpus` is applied live but is NOT recorded (the `Instance` has no cpu field), so a
/// cpu change does NOT survive an in-process restart - the box comes back on the spec's cpu quota. A
/// systemd-managed box (a standalone `--restart always`/`unless-stopped`) is instead rebuilt from its
/// original spec by the unit's re-exec, and its OUTER scope also caps it: RAISING a cap above the outer
/// one takes effect only after that rebuild, LOWERING always bites.
pub fn update(
    name: &str,
    memory: Option<u64>,
    cpus: Option<f64>,
    pids: Option<u64>,
) -> Result<(), Error> {
    if memory.is_none() && cpus.is_none() && pids.is_none() {
        return Err(Error::Usage(
            "update <box> [--memory M] [--cpus N] [--pids-limit P] (at least one)",
        ));
    }
    let Some(inst) = registry::find_ref(name) else {
        return Err(Error::NotRunning(format!("no running box named '{name}'")));
    };
    let Some(cg) = registry::box_cgroup(inst.cgroup_pid()) else {
        return Err(Error::Sandbox(format!(
            "box '{}' has no dedicated cgroup - caps are not enforced on this host, nothing to update",
            inst.name
        )));
    };
    // Best-effort PER KNOB: apply each independently so one controller that isn't delegated doesn't
    // discard the knobs that DID take effect. Collect what applied vs what failed, and record back
    // ONLY the caps that actually stuck (so `ps`/`inspect` never show a cap that silently failed).
    let mut applied: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    let (mut mem_ok, mut pids_ok) = (None, None);
    if let Some(m) = memory {
        match write_cgroup(&cg, "memory.max", &m.to_string()) {
            Ok(()) => {
                applied.push(format!("memory={}", human_bytes(m)));
                mem_ok = Some(m);
            }
            Err(why) => failed.push(why),
        }
    }
    if let Some(c) = cpus {
        // cores → quota µs (clamped to ≥1); period fixed. Matches the box-start rendering.
        let quota = (c * CPU_PERIOD_US as f64).round().max(1.0) as u64;
        match write_cgroup(&cg, "cpu.max", &format!("{quota} {CPU_PERIOD_US}")) {
            Ok(()) => applied.push(format!("cpus={c}")),
            Err(why) => failed.push(why),
        }
    }
    if let Some(p) = pids {
        // Docker parity: `--pids-limit 0` means UNLIMITED (`pids.max = max`), NOT "forbid every fork".
        let (val, label) = if p == 0 {
            ("max".to_string(), "pids=unlimited".to_string())
        } else {
            (p.to_string(), format!("pids={p}"))
        };
        match write_cgroup(&cg, "pids.max", &val) {
            Ok(()) => {
                applied.push(label);
                // Record a real cap; "unlimited" (0) isn't stored, so `ps`/`inspect` don't show a `0`.
                if p != 0 {
                    pids_ok = Some(p);
                }
            }
            Err(why) => failed.push(why),
        }
    }
    if mem_ok.is_some() || pids_ok.is_some() {
        registry::update_caps(&inst.name, inst.pid, mem_ok, pids_ok);
    }
    if !applied.is_empty() {
        let pal = crate::ui::Palette::detect();
        println!(
            "{}updated{} {}: {}",
            pal.g,
            pal.z,
            inst.name,
            applied.join(", ")
        );
    }
    for why in &failed {
        eprintln!("kern: update {}: {why}", inst.name);
    }
    if applied.is_empty() {
        // Every requested knob failed - surface an error, not a silent success.
        return Err(Error::Sandbox(format!(
            "update {}: no cap could be applied",
            inst.name
        )));
    }
    Ok(())
}

/// `kern events` - stream box lifecycle events (Docker `events`), best-effort. kern is DAEMONLESS, so
/// there is no authoritative event bus: this OBSERVES the registry by polling `list()` every 500 ms
/// and emits `start` when a box appears, `die` when it leaves, and `rename` when a live box's name
/// changes. A box that both starts AND ends inside one 500 ms gap can be missed - it is a convenience
/// monitor, not a guaranteed audit log. Boxes already running when `events` starts are NOT replayed
/// (only NEW transitions are shown), matching `docker events`. Runs until interrupted (Ctrl-C).
pub fn events() -> Result<(), Error> {
    use std::collections::HashMap;
    // Key on (pid, starttime), NOT pid alone: if a box dies and a NEW box reuses its pid within one
    // poll gap, the differing start-time makes them distinct keys -> a correct `die`+`start`, never a
    // fabricated `rename`. A genuine rename keeps (pid, starttime) and only the name changes.
    let snapshot = || -> HashMap<(i32, u64), String> {
        registry::list()
            .into_iter()
            .map(|b| ((b.pid, b.starttime), b.name))
            .collect()
    };
    let mut seen = snapshot();
    loop {
        unsafe { libc::usleep(500_000) }; // 500 ms poll - no daemon, negligible cost
        let now = snapshot();
        for (key, name) in &now {
            match seen.get(key) {
                None => emit_event("start", name, key.0, None),
                Some(old) if old != name => emit_event("rename", name, key.0, Some(old)),
                _ => {}
            }
        }
        for (key, name) in &seen {
            if !now.contains_key(key) {
                emit_event("die", name, key.0, None);
            }
        }
        seen = now;
    }
}

/// `kern uninstall [--yes] [--keep-images]` - remove everything kern created on this host.
///
/// A **dry run by default**: it prints the exact paths, their sizes, and which of them are data the
/// user made, then stops. `--yes` performs it. There was no uninstall at all before this, on any
/// platform, and the paths involved held 5.5 GB on the machine where that was noticed - so the verb
/// that removes them has to say what it is about to do before it does it.
///
/// It only touches paths kern OWNS, each taken from the function that creates it rather than written
/// out here, so a future change to a location cannot leave this deleting the wrong tree. Notably it
/// does **not** touch `/var/lib/kern`: kern-public never creates it (the only mentions in the source
/// are a synthetic path in `--plan` output and an example inside the generated starter config), and a
/// `[[disk]]` a user pointed there is their data in their location.
pub fn uninstall(yes: bool, keep_images: bool) -> Result<(), Error> {
    let p = crate::ui::Palette::detect();

    // A running box means live processes, mounts and cgroups. Removing the tree under them would leave
    // a box whose rootfs is gone: refuse and name the fix rather than half-succeeding.
    let live = registry::list();
    if !live.is_empty() {
        let names: Vec<&str> = live.iter().map(|i| i.name.as_str()).collect();
        return Err(Error::Sandbox(format!(
            "{} box(es) still running ({}) - stop them first: kern stop --all",
            live.len(),
            names.join(", ")
        )));
    }

    let mut items: Vec<Removable> = Vec::new();
    let mut push = |path: PathBuf, what: &'static str, is_user_data: bool| {
        if path.exists() {
            let bytes = dir_bytes(&path);
            let is_symlink = std::fs::symlink_metadata(&path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            items.push(Removable {
                path,
                what,
                is_user_data,
                is_symlink,
                bytes,
            });
        }
    };

    // The image cache, and the build layer cache inside it. Refetchable, so `--keep-images` can spare
    // it: reinstalling with a warm cache is the common case and re-downloading gigabytes is not.
    if !keep_images {
        if let Some(dir) = cache_dir().parent() {
            push(dir.to_path_buf(), "image + layer cache", false);
        }
    }
    // Named volumes are user DATA: whatever a `-v name:/dst` wrote lives here.
    let vols = crate::volume::volumes_dir();
    let vol_count = std::fs::read_dir(&vols)
        .map(|rd| rd.flatten().filter(|e| e.path().is_dir()).count())
        .unwrap_or(0);
    push(vols, "named volumes (YOUR DATA)", true);
    // The config, and the backup `config setup --force` leaves next to it - but ONLY the one at kern's
    // OWN default location.
    //
    // `active_path()` returns the `KERN_CONFIG` override when set, and that path is a file the USER chose,
    // in a directory kern does not own: uninstall listed `/some/shared/dir/my-own-kern.toml` as
    // "kern.toml (YOUR DATA)" and would have deleted it. Owning a path because its name matches is the
    // inference this verb exists to avoid, and here it reached outside kern entirely. Measured with
    // KERN_CONFIG pointing at a hand-written file.
    let owned_cfg = crate::config::default_path();
    let active_cfg = crate::config::active_path();
    let overridden = match (&owned_cfg, &active_cfg) {
        (Some(o), Some(a)) => o != a,
        _ => active_cfg.is_some(),
    };
    if let Some(cfg) = owned_cfg {
        push(cfg.with_extension("toml.bak"), "config backup", true);
        push(cfg, "kern.toml (YOUR DATA)", true);
    }
    // Runtime state: the registry, logs, claims. Skipped when EMPTY, because any kern invocation
    // recreates the tree - including this one, which reads the registry to check for running boxes.
    // Listing a 0 B directory made "nothing to remove" unreachable on a clean host, which is the one
    // case where that sentence is the whole answer.
    if let Ok(rt) = registry::dir() {
        if let Some(parent) = rt.parent() {
            if dir_bytes(parent) > 0 {
                push(
                    parent.to_path_buf(),
                    "runtime state (registry, logs)",
                    false,
                );
            }
        }
    }
    // Units generated by `--restart always`. Left behind, they would try to start a box whose binary
    // is gone at the next login.
    if let Some(h) = std::env::var_os("HOME") {
        let unitdir = PathBuf::from(&h).join(".config/systemd/user");
        if let Ok(rd) = std::fs::read_dir(&unitdir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.starts_with("kern-") && n.ends_with(".service") {
                    push(e.path(), "systemd unit from --restart", false);
                }
            }
        }
    }
    // The binary itself, only when it is the one running AND sits in a known install location.
    if let (Some(exe), Some(h)) = (std::env::current_exe().ok(), std::env::var_os("HOME")) {
        if is_installed_binary(&exe, std::path::Path::new(&h)) {
            push(exe, "the kern binary", false);
        }
    }

    if items.is_empty() {
        println!("nothing to remove - kern has created no state on this host.");
        return Ok(());
    }

    let total: u64 = items.iter().map(|i| i.bytes).sum();
    let data: u64 = items
        .iter()
        .filter(|i| i.is_user_data)
        .map(|i| i.bytes)
        .sum();
    println!(
        "{b}{}{z} would be removed:",
        if yes { "removing" } else { "this" },
        b = p.b,
        z = p.z
    );
    for i in &items {
        let mark = if i.is_user_data { p.y } else { p.d };
        // A symlink prints "symlink" where the size goes. Printing 0 B was worse than printing nothing:
        // it answered the reader's question ("is there anything there?") with a confident no.
        let size = if i.is_symlink {
            "symlink".to_string()
        } else {
            human_bytes(i.bytes)
        };
        println!(
            "  {mark}{:>9}{z}  {}  {d}{}{z}",
            size,
            i.path.display(),
            i.what,
            z = p.z,
            d = p.d
        );
        if i.is_symlink {
            println!(
                "  {d}           the link is removed; whatever it points at is left alone{z}",
                d = p.d,
                z = p.z
            );
        }
    }
    println!(
        "  {d}{:>9}   total, of which {} is data you made{z}",
        human_bytes(total),
        human_bytes(data),
        d = p.d,
        z = p.z
    );
    if vol_count > 0 {
        println!(
            "  {y}{vol_count} named volume(s) will be destroyed - `kern volume ls` lists them{z}",
            y = p.y,
            z = p.z
        );
    }
    if keep_images {
        println!(
            "  {d}the image cache is kept (--keep-images){z}",
            d = p.d,
            z = p.z
        );
    }

    if !yes {
        println!();
        println!(
            "{d}nothing was removed. pass --yes to do it{z}",
            d = p.d,
            z = p.z
        );
        if in_wsl() && items.iter().any(|i| i.what == "the kern binary") {
            println!(
                "{d}inside WSL: this removes kern from the distro only. kern.exe and your PATH entry are on the Windows side - uninstall.ps1 removes those.{z}",
                d = p.d,
                z = p.z
            );
        }
        if overridden {
            if let Some(a) = &active_cfg {
                println!(
                    "{d}KERN_CONFIG points at {} - that is your file in your location, so it is NOT removed{z}",
                    a.display(),
                    d = p.d,
                    z = p.z
                );
            }
        }
        println!(
            "{d}not touched: /var/lib/kern and any [[disk]] path in your config - kern never created those{z}",
            d = p.d,
            z = p.z
        );
        return Ok(());
    }

    // Remove the binary LAST: on Linux an unlinked running executable keeps working, but doing it
    // first would leave the rest behind if anything after it failed.
    items.sort_by_key(|i| i.what == "the kern binary");
    let (mut done, mut failed) = (0usize, Vec::new());
    for i in &items {
        let r = if i.path.is_dir() {
            std::fs::remove_dir_all(&i.path)
        } else {
            std::fs::remove_file(&i.path)
        };
        match r {
            Ok(()) => done += 1,
            Err(e) => failed.push(format!("{}: {e}", i.path.display())),
        }
    }
    println!();
    if failed.is_empty() {
        println!(
            "{g}removed {done} item(s), {}{z}",
            human_bytes(total),
            g = p.g,
            z = p.z
        );
    } else {
        println!(
            "{y}removed {done} item(s); {} could not be removed:{z}",
            failed.len(),
            y = p.y,
            z = p.z
        );
        for f in &failed {
            println!("  {f}");
        }
    }
    println!(
        "{d}the transient kern.slice cgroup disappears on its own; nothing else is left.{z}",
        d = p.d,
        z = p.z
    );
    Ok(())
}

/// `kern examples` - print a commented example `kern.toml` to stdout (redirect it into
/// `~/.config/kern/kern.toml` to get started).
pub fn examples() -> Result<(), Error> {
    print!("{EXAMPLE_KERN_TOML}");
    Ok(())
}
