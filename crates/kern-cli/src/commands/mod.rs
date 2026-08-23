//! Subcommand implementations. One responsibility per function; the roadmap splits each verb
//! (box/run/pull/compose) into its own module here as the surface grows.

use crate::error::Error;
use crate::registry;
use crate::sandbox::SandboxCtx;
use kern_common::{json_str, BoxName};
use kern_isolation::{
    exec_in_box, run_in_sandbox_with, MountMode, OverlayDirs, SandboxSpec, UidRange, Volume,
};
use std::io::IsTerminal;
use std::path::PathBuf;

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
    {d}`run` caps a process on the HOST: no image, no namespaces, no sandbox. For isolation use `box`.{z}

{b}OPTIONS:{z}
    -V, --version  Print version
    -h, --help     Print this help

{d}Docs & issues: {z}{c}https://github.com/getkern/kern{z}",
        ver = kern_common::VERSION
    )
}

/// A copy of `s` with ANSI escape sequences and control characters removed.
///
/// One pass, one allocation, and it does not need to know the palette: a CSI sequence is `ESC [`
/// followed by parameter/intermediate bytes and terminated by a final byte in `@`..`~`, and any
/// other `ESC x` form is two bytes. Anything a palette can produce is covered, so this cannot go
/// stale when a colour is added.
///
/// Deliberately not `ui::scrub`: scrub DELETES the ESC and leaves the `[1m` tail as printable text,
/// which is right for its job (an error message must not repaint a terminal, and what remains is
/// inert) and wrong for matching, where the residue is indistinguishable from content.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            match it.next() {
                // CSI (`ESC [ … final`) and OSC (`ESC ] … BEL/ST`): consume up to the terminator.
                // Every colour kern emits is a CSI SGR, so this is the branch that matters.
                Some('[') => {
                    for n in it.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&n) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    for n in it.by_ref() {
                        // BEL, or the ST introducer whose ESC was already eaten by this loop.
                        if n == '\u{7}' || n == '\\' {
                            break;
                        }
                    }
                }
                // Charset designation (`ESC ( B`, `ESC ) 0`, …): one intermediate, one final. Nothing
                // in kern emits these; they are handled because leaving the final byte behind turns
                // an escape into a stray letter that reads as content, which is the failure mode this
                // whole function exists to avoid.
                Some('(') | Some(')') | Some('*') | Some('+') | Some('#') => {
                    let _ = it.next();
                }
                // Any other two-byte form (`ESC 7`, `ESC =`, …) is fully consumed by the `next()`
                // above. Out of scope, and stated rather than assumed: a form not listed here loses
                // its ESC and keeps its payload.
                Some(_) | None => {}
            }
            continue;
        }
        if !c.is_control() {
            out.push(c);
        }
    }
    out
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

/// Bare `kern`: a short, friendly banner - the logo, the tagline, and the handful of commands most
/// people reach for first. The full command + flag reference is `kern --help`.
pub fn banner() -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    let (b, c, d, z) = (p.b, p.c, p.d, p.z);
    println!("{}", crate::ui::logo(&p));
    println!(
        "\
  {b}kern {ver}{z}{d}: a fast, rootless sandbox & virtual resource runtime{z}

    {b}kern box{z} <name> --image alpine -- sh   {d}run a command in a sandbox{z}
    {b}kern box{z} app --image alpine vcpu:big -- sh  {d}attach a resource profile (make one: {z}{b}kern config{z}{d}){z}
    {b}kern run{z} --memory 512m -- <cmd>         {d}govern a command's CPU/memory (no sandbox){z}
    {b}kern ps{z} {d}·{z} {b}logs{z} {d}·{z} {b}exec{z} {d}·{z} {b}stop{z}            {d}manage running boxes{z}
    {b}kern pull{z} {d}·{z} {b}build{z} {d}·{z} {b}push{z} {d}·{z} {b}images{z}       {d}work with OCI images{z}
    {b}kern compose{z} stack.yml                  {d}bring up a stack (docker-compose.yml too){z}

  {b}kern --help{z} {d}all commands{z} {d}·{z} {b}kern top{z} {d}live TUI{z} {d}·{z} {b}kern doctor{z} {d}check this host{z}
  {d}{z}{c}https://github.com/getkern/kern{z}",
        ver = kern_common::VERSION
    );
    Ok(())
}

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
            Err(e) => println!("  vcpu:{n}: cannot attach: {e}"),
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
            Err(e) => println!("  vgpio:{n}: cannot attach: {e}"),
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
            Err(e) => println!("  vdisk:{n}: cannot attach: {e}"),
        }
    }
    Ok(())
}

/// `--restart [policy]` - what to do when a detached box exits. `no` (default) leaves it dead;
/// `on-failure` re-runs it on a non-zero exit via kern's own in-process supervisor (dies with the
/// host); `always`/`unless-stopped` hand supervision to the user's **systemd** (a generated
/// `~/.config/systemd/user/kern-<name>.service` + linger) so the box restarts on ANY exit AND
/// survives reboot - all WITHOUT a kern daemon. Exception: a `--pod` MEMBER with `always`/
/// `unless-stopped` is supervised in-process for the stack's lifetime instead (it needs the pod
/// holder's shared namespace, which a standalone systemd unit could not re-join).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestartPolicy {
    #[default]
    No,
    OnFailure,
    Always,
    UnlessStopped,
}

impl RestartPolicy {
    /// Parse a `--restart` value; `None` if unrecognized (so a bare `--restart` can fall back to
    /// `on-failure` without swallowing the next token).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "no" => Some(Self::No),
            "on-failure" => Some(Self::OnFailure),
            "always" => Some(Self::Always),
            "unless-stopped" => Some(Self::UnlessStopped),
            _ => None,
        }
    }

    /// Human name (matches the CLI value + Docker's).
    fn as_str(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::OnFailure => "on-failure",
            Self::Always => "always",
            Self::UnlessStopped => "unless-stopped",
        }
    }

    /// Does this policy persist across reboot (→ hand off to a systemd user unit)?
    fn persistent(self) -> bool {
        matches!(self, Self::Always | Self::UnlessStopped)
    }
}

/// `--pull <policy>` - when an `--image` names a registry ref, decide whether to hit the network.
/// `Missing` (Docker's default) pulls only when the image is not already cached; `Never` fails closed
/// if it is not local (never touches the network); `Always` forces a fresh pull with an atomic cache
/// swap. A locally-built (`.layers`/`.base`) or `scratch` image is used as-is under every policy -
/// kern has nothing to re-pull for it, so those resolve before the network decision is ever reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PullPolicy {
    #[default]
    Missing,
    Never,
    Always,
}

/// `--security-profile <name>`: a named bundle of opt-in hardening applied as a BASE that explicit
/// flags override. A CLOSED set (one value today); a registry stays premature until a second profile
/// and an external request exist. The resolved constituents are printed (at start and by `--plan`), so
/// the macro is visible and a future change to a constituent surfaces rather than shifting silently.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecurityProfile {
    /// `untrusted`: seccomp ALLOWLIST + `--cap-drop ALL` + `--read-only`, for running code nobody has
    /// read. Explicit flags/env override it (`--cap-add X`, `KERN_SECCOMP=...`). Deliberately does NOT
    /// touch Landlock (a write-allowlist needs the workload's real paths, which a profile cannot guess:
    /// build it from a `--landlock-rw` audit run) and does NOT set `--require-limits` (which would break
    /// a host with no cgroup delegation, exactly what an opt-in hardening profile must not do).
    Untrusted,
}

impl SecurityProfile {
    /// Parse the flag value; `None` on an unknown name so the caller emits a usage error naming the set.
    pub fn parse(v: &str) -> Option<Self> {
        match v {
            "untrusted" => Some(Self::Untrusted),
            _ => None,
        }
    }
}

/// Resolve the box's seccomp mode WITHOUT touching the process environment. Precedence, explicit first:
/// a non-empty `KERN_SECCOMP` (a valid token parses as [`kern_isolation::SeccompFilter::parse`] does),
/// then the security profile, then the default (allowlist). Pure and total: the caller passes the env
/// value read once, so there is no `env::set_var` - which is a data race on the un-locked `environ` in a
/// multi-threaded process and a process-global side effect that would leak into a later box in the same
/// process. Unlike `from_env`, a SET-but-unrecognised (or non-UTF-8) value is a FAIL-LOUD usage error,
/// not a silent fall to the default: a malformed security control must stop, never downgrade a profile
/// silently. Only an ABSENT or EMPTY value falls through to the profile, then the default.
fn resolve_seccomp_mode(
    env: Option<&std::ffi::OsStr>,
    profile: Option<SecurityProfile>,
) -> Result<kern_isolation::SeccompFilter, Error> {
    use kern_isolation::SeccompFilter;
    if let Some(v) = env {
        if !v.is_empty() {
            // A SET-but-unrecognised value is a FAIL-LOUD usage error, not a silent fall to the
            // default. Silently defaulting would let a typo (`allowlist-audi`) downgrade a
            // `--security-profile untrusted` box from the allowlist to the denylist while the box
            // still advertises `untrusted`: the label would lie. A malformed security control must stop.
            return match v.to_str().and_then(SeccompFilter::parse) {
                Some(f) => Ok(f),
                None => Err(Error::Usage(
                    "KERN_SECCOMP: unrecognised value (expected `denylist`, `allowlist`, or \
                     `allowlist-audit`)",
                )),
            };
        }
    }
    Ok(match profile {
        Some(SecurityProfile::Untrusted) => SeccompFilter::Allowlist,
        None => SeccompFilter::default(),
    })
}

/// Arguments for [`box_run`]. A struct (not a long parameter list) keeps the call site readable
/// as box options grow (`-v`, `--env`, `--workdir`, `--net`).
pub struct BoxRunArgs<'a> {
    pub name: &'a str,
    pub rootfs: Option<&'a str>,
    pub image: Option<&'a str>,
    /// `--pull <missing|never|always>`: registry-image fetch policy (see [`PullPolicy`]).
    pub pull: PullPolicy,
    pub command: &'a [String],
    pub detached: bool,
    pub read_only: bool,
    pub volumes: &'a [String],
    pub env: &'a [String],
    /// `--egress-allow d1,d2`: outbound network restricted to these domains (+ subdomains) via a
    /// kern-run filtering proxy; empty = the default (no outbound unless `--net`/`--pod`).
    pub egress_allow: &'a [String],
    /// `--landlock-rw <path>` (repeatable): a Landlock (LSM) write-allowlist; the box root is read+exec
    /// and writes are confined to these paths (+ box scratch dirs). Empty = no Landlock. Each path must
    /// EXIST at box start (typically a `-v` volume or a dir the image ships): the box root is read-only
    /// under Landlock, so the workload cannot `mkdir` a missing allowlist dir, and a path absent at start
    /// is skipped (fail-safe, so the box is only ever MORE confined, never less).
    pub landlock_rw: &'a [String],
    /// `--apparmor <profile>`: a pre-loaded AppArmor profile the box enters on exec, or None.
    pub apparmor: Option<&'a str>,
    pub workdir: Option<&'a str>,
    pub share_net: bool,
    /// `--pod <name>`: join this pod's shared network (created by `kern pod create`).
    pub pod: Option<&'a str>,
    pub uid_range: bool,
    /// `--no-uid-range`: opt OUT of the range mapping an `--image` box gets by default.
    pub no_uid_range: bool,
    pub bind_rootfs: bool,
    /// `--privileged`: relax the seccomp filter to allow a NESTED `kern box` (rootless-only; see
    /// [`kern_isolation::SandboxSpec::privileged`]).
    pub privileged: bool,
    /// `--require-limits`: refuse to start (non-zero exit) if a resource cap cannot be enforced here,
    /// instead of running best-effort UNCAPPED (see [`kern_isolation::SandboxSpec::require_limits`]).
    pub require_limits: bool,
    /// `--allow-uncapped`: accept running uncapped silently on a host with no cgroup delegation (see
    /// [`kern_isolation::SandboxSpec::allow_uncapped`]). Mutually exclusive with `require_limits`.
    pub allow_uncapped: bool,
    /// `--security-profile <untrusted>`: opt-in hardening bundle applied as a base (see
    /// [`SecurityProfile`]). `None` = no profile.
    pub security_profile: Option<SecurityProfile>,
    /// INTERNAL (build): explicit colon-joined overlay lower dir(s), used instead of `--rootfs`/
    /// `--image` and paired with `overlay_upper` to run a build's RUN step against the base.
    pub overlay_lower: Option<&'a str>,
    /// INTERNAL (build): a persistent overlay upper (the build layer) instead of ephemeral scratch.
    pub overlay_upper: Option<&'a str>,
    /// `--memory`/`-m`: hard memory ceiling in bytes (default cap if `None`).
    pub memory: Option<u64>,
    /// `--memory-swap-max`: swap allowance in bytes → `memory.swap.max` (`None` → `0`, swap off).
    pub memory_swap_max: Option<u64>,
    /// `--cpus`: CPU cap in cores, K8s semantics (uncapped if `None`).
    pub cpus: Option<f64>,
    /// `--cpuset-cpus`: pin to specific CPUs (e.g. `"0-3"`; `None` → no pinning).
    pub cpuset: Option<&'a str>,
    /// `-it`/`-t`: allocate a PTY so the box gets an interactive controlling terminal.
    pub tty: bool,
    /// `-p host:box` (repeatable): publish a box TCP port on a host port.
    pub ports: &'a [kern_isolation::PortMap],
    /// `--secret SRC[:NAME]` / `NAME=value` / `NAME=-` (repeatable): deliver a secret as
    /// `/run/secrets/NAME` (mode 0400) without it hitting the image or the workload env.
    pub secrets: &'a [String],
    /// `--ssh PORT`: run an in-box sshd and publish it on host `PORT` (→ box `:22`). `None` → no SSH.
    pub ssh_port: Option<u16>,
    /// `--ssh-key FILE`: authorize this public key file instead of generating a throwaway keypair.
    pub ssh_key: Option<&'a str>,
    /// `--hostname NAME`: the box's UTS hostname (default: the box name).
    pub hostname: Option<&'a str>,
    /// `--tun`: expose `/dev/net/tun` in the box (WireGuard / userspace VPN).
    pub tun: bool,
    /// `--init`: run a built-in reaping init as box PID 1 (no zombies; forwards SIGTERM/SIGINT).
    pub init: bool,
    /// `--pids-limit N`: cap the box's task count (`pids.max`) - fork-bomb containment.
    pub pids_limit: Option<u64>,
    /// `--tmpfs PATH[:size]` (repeatable): mount a fresh tmpfs at PATH inside the box.
    pub tmpfs: &'a [String],
    /// `--ulimit` limits, pre-resolved to `(RLIMIT_*, soft, hard)` by the CLI.
    pub ulimits: &'a [(i32, u64, u64)],
    /// `--sysctl KEY=VALUE` pairs, applied inside the box's namespaces.
    pub sysctls: &'a [(String, String)],
    /// `--label k=v` metadata (repeatable). Descriptive only: it does not change how the box runs,
    /// but it is recorded in the registry so `kern ps --filter label=` and `kern inspect` can use it.
    pub labels: &'a [String],
    /// `--restart-max <n>`: retry cap for the on-failure supervisor (0 = kern's default).
    pub restart_max: u32,
    /// `--stop-signal <name|num>`: signal sent before the SIGKILL (default SIGTERM).
    pub stop_signal: i32,
    /// `--stop-timeout <secs>`: grace given to the workload before the SIGKILL.
    pub stop_grace: u64,
    /// `--def-hash <hex>`: fingerprint of the compose definition this box comes from, recorded so a
    /// later `up` can tell whether the file still describes the running service.
    pub def_hash: &'a str,
    /// `--user UID[:GID]`: drop to this uid/gid inside the box before the command runs.
    pub run_as: Option<&'a str>,
    /// `--cap-add CAP` (repeatable): keep a capability kern would otherwise drop (or `ALL`).
    pub cap_add: &'a [String],
    /// `--cap-drop CAP` (repeatable): drop an extra capability (or `ALL`).
    pub cap_drop: &'a [String],
    /// `--restart [policy]`: what to do when the detached box exits (see [`RestartPolicy`]).
    pub restart: RestartPolicy,
    /// `--health-cmd <cmd>`: shell command run periodically in the box (exit 0 = healthy).
    pub health_cmd: Option<&'a str>,
    /// `--health-interval <sec>`: seconds between health checks.
    pub health_interval: u64,
    /// `--health-retries <n>`: consecutive failures before "unhealthy".
    pub health_retries: u32,
    /// `--health-start-period <sec>`: grace period where a failing check keeps "starting".
    pub health_start_period: u64,
    /// `--health-timeout <sec>`: kill a single check that exceeds this (0 = no timeout).
    pub health_timeout: u64,
    /// `--health-action <restart|stop|none>`: what to do when a box turns unhealthy.
    pub health_action: Option<&'a str>,
    /// `--env-file <file>` (repeatable): read `K=V` lines into the box environment.
    pub env_file: &'a [String],
    /// `--timeout <sec>`: auto-stop the box after this many seconds (0 = no timeout).
    pub timeout: u64,
    /// `--nice <n>`: scheduling niceness for the box workload.
    pub nice: Option<i64>,
    /// `--io-weight <n>`: cgroup v2 `io.weight` (relative I/O priority).
    pub io_weight: Option<u64>,
    /// `--config <path>`: a specific `kern.toml` for this invocation.
    pub config: Option<&'a str>,
    /// `--show-config`: print the resolved box configuration and exit.
    pub show_config: bool,
    /// `--quiet`: suppress the foreground status panel.
    pub quiet: bool,
    /// `--verbose`: expand the one-line summary into the full isolation posture panel.
    pub verbose: bool,
    /// Resource-profile tokens (`vcpu:name` …) applied to the box's caps.
    pub profiles: &'a [String],
    /// `--add-host NAME:IP` extra `/etc/hosts` entries; the IP may be the keyword `host-gateway`
    /// (resolved to the host's reachable address at build time).
    pub add_hosts: &'a [(String, String)],
}

/// Resolve `--add-host` entries: the `host-gateway` keyword becomes the host's reachable address -
/// `127.0.0.1` when the box shares the host network, else the host's primary (default-route) IPv4 (the
/// address a box with egress uses to reach the host). Other values pass through verbatim.
fn resolve_add_hosts(raw: &[(String, String)], share_net: bool) -> Vec<(String, String)> {
    let gateway = || -> String {
        if share_net {
            return "127.0.0.1".to_string();
        }
        host_primary_ipv4().unwrap_or_else(|| "127.0.0.1".to_string())
    };
    raw.iter()
        .map(|(name, ip)| {
            let ip = if ip.eq_ignore_ascii_case("host-gateway") {
                gateway() // resolved lazily, only for host-gateway entries
            } else {
                ip.clone()
            };
            (name.clone(), ip)
        })
        .collect()
}

/// The host's primary IPv4 (the source address the default route would use), found by `connect()`ing a
/// UDP socket to a public address - no packet is sent; the kernel just picks the route's source IP. So
/// it works offline as long as a default route exists. `None` if there's no usable route.
fn host_primary_ipv4() -> Option<String> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:53").ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => {
            Some(v4.to_string())
        }
        _ => None,
    }
}

/// The host's online CPU count (`processor` lines in `/proc/cpuinfo`), floored at 1. Memoized - the
/// single reader, so a box passing BOTH `--cpus` and `--cpuset-cpus` reads `/proc/cpuinfo` once, not
/// twice. (Counts online CPUs on purpose: `available_parallelism()` respects kern's own affinity mask
/// and would undercount the `0..host` pin range if kern were itself pinned.)
fn host_cpu_count() -> usize {
    use std::sync::OnceLock;
    static N: OnceLock<usize> = OnceLock::new();
    *N.get_or_init(|| {
        std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.lines().filter(|l| l.starts_with("processor")).count())
            .ok()
            .filter(|&n| n > 0)
            .unwrap_or(1)
    })
}

/// Clamp a `--cpus` request to the host's physical CPU count (from `/proc/cpuinfo`), so the cap
/// is consistent across the systemd scope AND the in-namespace cgroup. The warning fires once - in
/// the original process, before the scope re-exec (which sets `KERN_SCOPE`) runs the parse again.
fn clamp_cpus(cpus: Option<f64>) -> Option<f64> {
    let c = cpus?;
    let host = host_cpu_count() as f64;
    if c > host {
        if std::env::var_os("KERN_SCOPE").is_none() {
            eprintln!(
                "kern: --cpus {c} exceeds the {host:.0} available CPUs - clamping to {host:.0}"
            );
        }
        return Some(host);
    }
    Some(c)
}

/// Clamp a `--cpuset-cpus` list to the host's CPU range (`0..host`), so an over-wide pin (`0-9999` on
/// a 4-CPU box) becomes the valid subset (`0-3`) instead of a raw `systemd`/kernel "Failed to parse
/// AllowedCPUs" that aborts the box start. Each range/single is intersected with `[0, host-1]`;
/// out-of-range items are dropped. Warns once, like `clamp_cpus`.
///
/// A list in which NOTHING exists on this host is REFUSED rather than passed through. It used to be
/// passed through, on the reasoning that "the backend rejects an all-invalid pin loudly rather than
/// us silently running unpinned". Measured on a 28-CPU machine, that reasoning was false for the
/// values people actually mistype: `--cpuset-cpus 28` (one past the end) reached systemd, which
/// accepted it, applied nothing, printed nothing, and exited 0 with the process free to use all 28
/// CPUs. Only absurd values (`999999`) overflow systemd's parser and fail loudly, so the fallback
/// worked precisely where it was not needed and failed on the off-by-one. A resource cap that cannot
/// be applied must not silently become no cap, the same fail-closed rule `--user` follows.
///
/// Refusing rather than clamping is deliberate here and differs from [`clamp_cpus`]. Clamping
/// `--cpus 999` to 28 moves TOWARD the request (you wanted a lot, you get the most there is), while
/// clamping `--cpuset-cpus 28` to `0-27` INVERTS it: the caller asked to be confined to one CPU and
/// would be handed the whole machine. There is no safe subset to pick, so the caller is told.
fn clamp_cpuset(set: Option<String>) -> Result<Option<String>, Error> {
    let Some(s) = set else {
        return Ok(None);
    };
    let host = host_cpu_count(); // >= 1 by construction, so `host - 1` cannot underflow
    let max = host - 1;
    let mut out: Vec<String> = Vec::new();
    // Distinguishes "every item parsed and every item was out of range" (refuse) from "an item did
    // not parse at all" (leave it to the backend, since the CLI validator already vetted the form
    // and a parser disagreement here is our bug, not the caller's).
    let mut parsed_any = false;
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((a, b)) => {
                let (Ok(a), Ok(b)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>()) else {
                    return Ok(Some(s)); // unparseable - leave it (the CLI boundary vetted the form)
                };
                parsed_any = true;
                let (lo, hi) = (a.min(b), a.max(b));
                if lo > max {
                    continue; // wholly above the host range → drop
                }
                let hi = hi.min(max);
                out.push(if lo == hi {
                    lo.to_string()
                } else {
                    format!("{lo}-{hi}")
                });
            }
            None => match part.parse::<usize>() {
                Ok(n) if n <= max => {
                    parsed_any = true;
                    out.push(n.to_string());
                }
                Ok(_) => parsed_any = true, // single CPU out of range → drop
                Err(_) => return Ok(Some(s)),
            },
        }
    }
    if out.is_empty() {
        if parsed_any {
            let range = if max == 0 {
                "0".to_string()
            } else {
                format!("0-{max}")
            };
            return Err(Error::Cli(format!(
                "--cpuset-cpus {s}: this machine has {host} CPU(s), numbered {range}, so none of \
                 the CPUs you asked for exist. Refusing rather than starting with no pin at all."
            )));
        }
        return Ok(Some(s));
    }
    let clamped = out.join(",");
    if clamped != s && std::env::var_os("KERN_SCOPE").is_none() {
        eprintln!(
            "kern: --cpuset-cpus {s} exceeds the {host} available CPUs - clamping to {clamped}"
        );
    }
    Ok(Some(clamped))
}

/// `kern box <name> (--rootfs <dir> | --image <ref>) [-d] [-v ...] [--env ...] [-- cmd...]` - run
/// a command in a real sandbox: a fresh user + PID + (net) + UTS + IPC + mount namespace, the
/// rootfs pivoted in, seccomp-filtered, cgroup-capped. `--image` pulls an OCI image (cached).
/// Defaults to `/bin/sh`. Foreground propagates the exit code; `-d` detaches (track via `kern ps`).
/// Enforce deployment-level FLEET limits from the environment before a box starts.
///
///  * `KERN_MAX_CONCURRENT=N`: a COOPERATIVE ceiling on the number of running boxes. Refuses the N+1th
///    box so a runaway (an agent spawning `box fn` in a loop) can't exhaust the host. Counts LIVE boxes
///    via the registry, which prunes dead entries on read, so a crashed box frees its slot. First-party
///    and cooperative (a caller can unset the env): NOT a security boundary. The check HERE is a fast-
///    fail advisory; the AUTHORITATIVE count is race-free - `claim_name_capped` re-counts and refuses
///    under the same lock it takes the name claim under (see `box_run`), so a parallel burst
///    (`kern compose up`, `xargs -P kern box`) can no longer overshoot N. For a HARD bound on total
///    fleet RESOURCES (not box count) use `KERN_FLEET_PIDS_MAX` / `KERN_FLEET_MEMORY_MAX` below
///    (cgroup-enforced on the shared slice, so the kernel caps the SUM no matter how boxes are started).
///  * `KERN_FLEET_MEMORY_MAX` / `KERN_FLEET_PIDS_MAX`: a REAL, kernel-enforced budget on kern's shared
///    `kern.slice`, bounding the SUM of all boxes' memory / pids. This is the hard backstop the counter
///    lacks: even past the cooperative ceiling, the kernel caps total fleet memory. Best-effort (needs
///    systemd-user delegation); engages once the slice exists (from the first box onward).
///
/// Returns an error only for the max-concurrent refusal; the budget is best-effort and never fails a box.
/// `KERN_MAX_CONCURRENT` parsed to a ceiling, or `None` (unset/unparseable). The single reader, shared
/// by the advisory fast-fail here and the authoritative under-lock check in `box_run`, so the env key
/// and its parse rule live once.
fn fleet_max() -> Option<usize> {
    std::env::var("KERN_MAX_CONCURRENT")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
}

/// The one refusal message for the fleet ceiling, shared by both checks so the wording can't drift.
fn fleet_limit_error(live: usize, max: usize) -> Error {
    Error::Sandbox(format!(
        "fleet limit reached: {live} box(es) already running (KERN_MAX_CONCURRENT={max}); \
         stop one, or raise/unset the limit"
    ))
}

fn fleet_gate_and_budget() -> Result<(), Error> {
    if let Some(max) = fleet_max() {
        let live = registry::list().len(); // prunes dead entries as a side effect (crash-safe count)
        if live >= max {
            return Err(fleet_limit_error(live, max));
        }
    }
    let mem = std::env::var("KERN_FLEET_MEMORY_MAX")
        .ok()
        .and_then(|v| kern_common::parse_binary_size(v.trim()));
    let pids = std::env::var("KERN_FLEET_PIDS_MAX")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    if mem.is_some() || pids.is_some() {
        kern_isolation::set_fleet_caps(mem, pids);
        // The fleet SUM cap lives on kern's delegated `kern.slice` and only bounds boxes that actually
        // run INSIDE it (the direct-cap path). Where kern falls back to per-box systemd scopes (the
        // common ROOTLESS case: verified on Jetson/Pi5, boxes land in `app.slice/run-*.scope`), the boxes
        // are NOT under kern.slice, so the SUM is unbounded even though `set_fleet_caps` wrote the limit.
        // Do NOT silently no-op a security-relevant cap: warn once (same posture as the `--memory`
        // not-enforced warning). Per-box `--memory`/`--pids` still enforce; those are the reliable knob.
        if !kern_isolation::choose_direct_cap_path() {
            static ONCE: std::sync::Once = std::sync::Once::new();
            ONCE.call_once(|| {
                eprintln!(
                    "kern: warning: KERN_FLEET_MEMORY_MAX / KERN_FLEET_PIDS_MAX bound the SUM across boxes \
                     ONLY when boxes share kern's delegated kern.slice, which this host does not use (boxes \
                     run in per-box systemd scopes). The fleet SUM is NOT enforced here; per-box \
                     --memory / --pids still are. For a hard fleet bound, run kern as root, or cap each box."
                );
            });
        }
    }
    Ok(())
}

/// The supervision decision for a detached box: `(use_systemd_unit, in_process_restart_always)`, from
/// its flags and whether a `systemd --user` manager exists. A STANDALONE persistent box
/// (`always`/`unless-stopped`, detached, no pod) is supervised by a systemd unit where a manager exists
/// (survives reboot), and FALLS BACK to the in-process supervisor where none does (restart on any exit
/// for this process's lifetime, no reboot-survival) - without which a systemd-less host (WSL2 without
/// systemd, a minimal container) could not run `--restart always` at all. A pod member ALWAYS uses the
/// in-process supervisor (it needs the holder's namespace, which a standalone unit could not re-join).
/// Pure, so the systemd-absent fallback is testable without a live systemd.
fn persistent_supervision(
    detached: bool,
    persistent: bool,
    has_pod: bool,
    systemd_present: bool,
) -> (bool, bool) {
    let standalone = detached && persistent && !has_pod;
    let use_systemd = standalone && systemd_present;
    let restart_always = persistent && (has_pod || (standalone && !use_systemd));
    (use_systemd, restart_always)
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
    // `--ssh` PREFLIGHT: sshd's privilege separation calls `setgroups()`, which a single-uid userns
    // forbids (`/proc/self/setgroups=deny`). It works only with a real uid RANGE via newuidmap/subuid.
    // On a host without those (common on edge boards), `--ssh` would leave a listening port whose auth
    // silently closes with a confusing "Connection closed" - so say it up front instead of at handshake.
    if args.ssh_port.is_some() {
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
    // `--pod <name>`: join the pod's shared user+net namespace (created by `kern pod create`). Resolve
    // its live holder PID, register this box in the pod's shared `/etc/hosts` (so peers resolve it by
    // name), and bind that hosts file read-only over the box's `/etc/hosts`.
    let pod_holder = match args.pod {
        Some(pod) => {
            let holder = crate::pod::holder_pid(pod).ok_or_else(|| {
                Error::Sandbox(format!(
                    "no running pod '{pod}' - create it first with `kern pod create {pod}`"
                ))
            })?;
            crate::pod::add_member(pod, name.as_str())?;
            // Bind the pod's shared hosts over /etc/hosts. RW (not `:ro`): a read-only remount of a
            // bind is refused inside the pod's single-uid user ns (EPERM), and pod members are
            // co-trusted anyway (they already share the user+net ns).
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
            let rp = crate::pod::resolv_path(pod);
            if rp.exists() {
                volumes.push(kern_isolation::Volume {
                    source: symlink_free(rp),
                    target: "/etc/resolv.conf".to_string(),
                    read_only: false,
                });
            }
            Some(holder)
        }
        None => None,
    };
    // `--env-file` first (K=V lines from a file), then `--env` on top (explicit wins).
    let mut env = parse_env_files(args.env_file)?;
    env.extend(parse_envs(args.env)?);
    // `--egress-allow <domains>`: an outbound domain allowlist. The box keeps its default ISOLATED netns
    // (no route out, a real kernel boundary), and its ONLY egress is a kern-run filtering proxy started
    // once the box's netns exists (in the `on_started` callback below). Point the box's proxy env at it.
    // See egress.rs and docs/EGRESS.md for the enforcement model and its honest limits.
    const EGRESS_PROXY_PORT: u16 = 3128;
    if !args.egress_allow.is_empty() {
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
    }
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
    // Validate `--health-action` up front (before any host-side mount) so a typo fails fast. A
    // `restart` action implies the on-failure restart policy (that's how it re-runs the box).
    let health_action = parse_health_action(args.health_action)?;
    // In-process supervisor (dies with the host): `on-failure` - or a `restart` health action.
    let restart =
        args.restart == RestartPolicy::OnFailure || health_action == HealthAction::Restart;
    // A POD MEMBER with `always`/`unless-stopped` is supervised IN-PROCESS for the stack's lifetime
    // (restart on ANY exit, including 0), NOT via a per-service systemd unit: a pod member needs the
    // pod holder's shared namespace, so a standalone unit that outlives the holder could not re-join it.
    // A STANDALONE persistent box normally takes the systemd path below (survives reboot) - but ONLY
    // where a `systemd --user` manager actually exists. Where none does (WSL2 without systemd, a minimal
    // container, no user manager) it FALLS BACK to the same in-process supervisor: restart on any exit
    // for this process's lifetime, no reboot-survival. Without this fallback a systemd-less host could
    // not run `--restart always` AT ALL - the unit install just errored and the box never started.
    let standalone_persistent = args.detached && args.restart.persistent() && args.pod.is_none();
    // Probe `systemd --user` ONLY for a standalone persistent box (avoid a socket connect on every box
    // start). `persistent_supervision` decides systemd-unit vs in-process from that single bool.
    let systemd_present = standalone_persistent && kern_isolation::user_systemd_present();
    let (systemd_supervises, restart_always) = persistent_supervision(
        args.detached,
        args.restart.persistent(),
        args.pod.is_some(),
        systemd_present,
    );
    // When systemd (re-)starts a persistent box, it runs THIS binary in the foreground with
    // `KERN_MANAGED=1`: skip the transient-scope re-exec (the box already lives in the unit's own
    // service cgroup) and register the foreground run so `kern ps`/`logs`/`stop` still see it.
    let managed = kern_common::env_flag("KERN_MANAGED");
    // `--restart always`/`unless-stopped` needs a SUPERVISOR, and the only two are systemd (detached
    // standalone, the branch below) and the in-process loop (detached, incl. a pod member) - the
    // FOREGROUND path runs the box exactly once. Reject it here rather than start the box and silently
    // drop the policy. `managed` is exempt: that IS the foreground re-exec systemd itself drives as the
    // supervisor (`KERN_MANAGED=1`), so `persistent() && !detached` is expected and correct there.
    if args.restart.persistent() && !args.detached && !managed {
        return Err(Error::Usage(
            "--restart always/unless-stopped needs -d: a foreground box runs once, so nothing would \
             supervise the restarts (use -d and systemd or kern's supervisor takes over)",
        ));
    }
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
        unsafe { libc::setpriority(libc::PRIO_PROCESS as _, 0, n) };
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
    // Resolve the effective command from the image config (docker semantics: Entrypoint + the user's
    // command, else the image's Cmd; a shell if nothing is set). `--ssh` with no command keeps the
    // box alive instead. Explicit `-- CMD` always wins over the image's Cmd.
    let cmd = resolve_image_command(args.command, args.ssh_port.is_some(), &image_config);
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
    for spec in &quota_specs {
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
            match crate::vdisk::prepare(name_v, limit, true, Some(&backend), &vdisk_work) {
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

    // `--secret`: read the values on the host (files/stdin/inline) BEFORE the fork; the box writes
    // them into a RAM-backed `/run/secrets` tmpfs (mode 0400) that never touches the overlay upper.
    let secrets = crate::secret::parse_secrets(args.secrets)?;

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
    let (ssh, eff_ports) = prepare_ssh(&name, args.ssh_port, args.ssh_key, args.ports)?;
    let ports: &[kern_isolation::PortMap] = &eff_ports;
    // Fail fast if a `-p` host port is already taken (by another box or any process): otherwise the
    // forwarder fails inside its fork - whose stderr a detached box swallows - and the box would
    // print "started" while nothing actually listens.
    if let Err((hp, e)) = kern_isolation::preflight_ports(ports) {
        // Tell the two failures apart. `EACCES` on a port <1024 is NOT "in use": rootless kern lacks
        // CAP_NET_BIND_SERVICE, so the fix is a higher port - sending the user to `kern ps`/`kern stop`
        // would chase a phantom holder (the old message did). `EADDRINUSE` (or any other errno) IS the
        // taken-port case, where AlreadyRunning's "run `kern ps` … `kern stop`" hint fits.
        if e.raw_os_error() == Some(libc::EACCES) && hp < 1024 {
            return Err(Error::Sandbox(format!(
                "cannot publish port {hp}: a port below 1024 needs a privilege kern lacks when rootless \
                 (CAP_NET_BIND_SERVICE) - publish it on a host port >=1024 instead (e.g. -p 8080:80)"
            )));
        }
        return Err(Error::AlreadyRunning(format!(
            "cannot publish host port {hp}: {e} - already in use (another box, or a non-kern process)"
        )));
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
    let user_or_image = |u: &str| match parse_user(Some(u)) {
        Ok(parsed) => parsed, // numeric (uid or uid:gid)
        Err(_) => resolve_image_user(u, &lower),
    };
    let run_as = match args.run_as {
        // Explicit `--user`/compose `user:`: a name the image can't resolve is an ERROR (caller asked).
        Some(u) => Some(user_or_image(u).ok_or_else(|| {
            Error::Sandbox(format!(
                "--user '{u}': not a numeric UID[:GID] and no such account in the image's /etc/passwd"
            ))
        })?),
        // The image's OWN `USER`: a name it can't resolve falls back to box-root with an honest note.
        None => match image_config.user.as_deref().filter(|u| !u.is_empty()) {
            None => None,
            Some(u) => user_or_image(u).or_else(|| {
                eprintln!(
                    "kern: image requests user '{u}' but it is not in the image's /etc/passwd - \
                     running as box root (pass --user <uid[:gid]> to drop privilege)"
                );
                None
            }),
        },
    };
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
        pids_max: args.pids_limit,
        caps,
        io_max: vdisk_io_max,
        io_weight: args.io_weight,
        extra_hosts: resolve_add_hosts(args.add_hosts, args.share_net),
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
            HealthConfig {
                cmd: args.health_cmd,
                interval: args.health_interval,
                retries: args.health_retries,
                start_period: args.health_start_period,
                timeout: args.health_timeout,
                action: health_action,
            },
            args.timeout,
            &args.labels.join(","),
            args.stop_signal,
            args.stop_grace,
            args.restart_max,
            args.def_hash,
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
    let mut reg_state = {
        let pid = std::process::id() as i32;
        if managed {
            let log = registry::logs_dir()
                .ok()
                .map(|d| d.join(format!("{}-{}.log", name.as_str(), pid)));
            detach_stdio(log.as_deref());
        }
        let (cap_drop_all, cap_drops, cap_adds) = registry::cap_fields(&spec.caps);
        let inst = registry::Instance {
            name: name.as_str().to_string(),
            pid,
            pid1: 0,
            rootfs: spec.root.clone(),
            command: spec.command.join(" "),
            started: registry::now_unix(),
            starttime: registry::proc_starttime(pid),
            ports: ports_summary(ports),
            volumes: mounted_vols.clone(),
            pod: args.pod.unwrap_or("").to_string(),
            workdir: spec.workdir.clone().unwrap_or_default(),
            egress: args.egress_allow.join(","),
            landlock_rw: spec.landlock_rw.join(","),
            labels: args.labels.join(","),
            stop_signal: args.stop_signal,
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
    pt.mark("parent:setup->spawn");
    let result = run_in_sandbox_with(
        &spec,
        None,
        |pid1| {
            feed_timeout_pid(timeout_wd, pid1);
            if let Some((inst, path)) = reg_state.as_mut() {
                inst.pid1 = pid1;
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
                egress_guard = Some(p.deliver(pid1));
            }
        },
        None,
        ports,
        // Foreground box: tie its lifetime to the launcher via PDEATHSIG, so a hard-killed launcher
        // (SIGKILL/OOM) doesn't orphan the box until `--timeout`. NOT for a managed box - systemd is
        // its supervisor (KillMode=mixed tears it down); a PDEATHSIG relative to systemd is pointless.
        !managed,
    );
    pt.mark("box lifetime (spawn->exit)");
    cancel_foreground_timeout(timeout_wd);
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
            if let Some(fd) = started_fd {
                // TWO bytes, written atomically (a pipe write of <= PIPE_BUF is all-or-nothing):
                //   byte 0 = `1`, the unchanged "box started" signal - an SDK that reads only ONE byte
                //           (every 0.1.x binding) still sees exactly `0x01` and is unaffected;
                //   byte 1 = the memory-cap ENFORCEMENT signal (0 undetermined, 1 enforced, 2 requested
                //           but not enforced), so a NEWER SDK can tell an OOM against a real ceiling from
                //           a plain kill where the cap never bound. An OLDER kern wrote one byte, so a
                //           newer SDK reads EOF for byte 1 and treats enforcement as undetermined.
                let buf = [1u8, kern_isolation::memory_cap_signal()];
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
            std::process::exit(code)
        }
        Err(e) => Err(Error::Setup(e.to_string())), // genuine sandbox-start failure → userns hint
    }
}

/// The `KERN_STARTED_FD` write end an SDK passes to receive the unforgeable "box started" byte, or
/// `None`. VALIDATES the fd (`> 2`, never stdin/stdout/stderr, and a live descriptor) but does NOT set
/// FD_CLOEXEC - that is deferred to [`cloexec_started_fd`], called AFTER the `systemd-run --scope`
/// re-exec. A CLOEXEC fd is DROPPED by that re-exec (a plain one is inherited), so marking it here
/// would lose the channel on every host that takes the scope path. Called ONCE, EARLY in `box_run`
/// (before the box is forked). Fail-closed: a fd we cannot even stat is dropped (`None`), since no
/// signal beats a forgeable one. Mirrors [`ready_fd_to_signal`]'s `> 2` discipline.
fn started_signal_fd() -> Option<i32> {
    let fd = std::env::var("KERN_STARTED_FD")
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()?;
    if fd <= 2 {
        return None;
    }
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return None;
    }
    Some(fd)
}

/// Mark the started-fd **FD_CLOEXEC** in the FINAL process - after the `systemd-run --scope` re-exec,
/// which inherits a plain fd but drops a CLOEXEC one. From here the box's execvp closes it, so the
/// workload can never inherit or write it (a byte it wrote would spoof or suppress the signal).
/// Fail-closed: a fd we cannot protect is dropped (`None`), so the SDK reads EOF and falls back to its
/// stderr heuristic (which only ever over-reports a failure, never masks one) rather than trusting a
/// descriptor the workload might reach.
fn cloexec_started_fd(fd: Option<i32>) -> Option<i32> {
    let fd = fd?;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return None;
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return None;
    }
    Some(fd)
}

/// Print the `kern box` status panel (aligned isolation + resource posture, actionable warnings)
/// to stderr - but ONLY when stderr is a terminal, so pipes/scripts/`kern logs` stay clean. `cpus`
/// is the already-clamped value, so the panel shows the cap that's actually enforced.
fn print_box_status(args: &BoxRunArgs, cpus: Option<f64>) {
    if !std::io::stderr().is_terminal() {
        return;
    }
    let (source, cmd) = display_source_cmd(args);
    let status = crate::ui::BoxStatus {
        name: args.name,
        source,
        cmd: &cmd,
        read_only: args.read_only,
        bind_rootfs: args.bind_rootfs,
        share_net: args.share_net,
        memory: args.memory,
        cpus,
        volumes: args.volumes.len(),
        tty: args.tty,
        seccomp_syscalls: kern_isolation::denied_syscall_count(nesting_active(args.privileged)),
    };
    let p = crate::ui::Palette::detect_stderr();
    let gl = crate::ui::Glyphs::detect();
    // Concise by default - a beginner running `kern box … -- cmd` wants their command's output, not a
    // six-line posture panel. One line ("▸ box 'x' · alpine  ✔ isolated"); `--verbose` expands it to
    // the full panel (with the once-per-session wordmark, which would only be noise on the one-liner).
    if !args.verbose {
        eprint!("{}", crate::ui::box_line(&status, &p, &gl));
        return;
    }
    let w = crate::ui::term_width(libc::STDERR_FILENO);
    if first_box_of_session() {
        eprintln!("{}\n", crate::ui::logo(&p));
    }
    eprint!("{}", crate::ui::box_banner(&status, &p, &gl, w));
}

/// Render an optional value for `--show-config`: the value, or `-` when absent.
fn or_dash<T: std::fmt::Display>(o: Option<T>) -> String {
    o.map_or_else(|| "-".to_string(), |v| v.to_string())
}

/// The box's display source (`--image`, else `--rootfs`) and effective command (defaults to
/// `/bin/sh` when none is given, like docker's COMMAND column). Shared by the status panel and the
/// `--show-config` dry run so the two can't drift.
fn display_source_cmd<'a>(args: &'a BoxRunArgs) -> (&'a str, String) {
    let source = args.image.or(args.rootfs).unwrap_or("");
    let cmd = if args.command.is_empty() {
        "/bin/sh".to_string()
    } else {
        args.command.join(" ")
    };
    (source, cmd)
}

/// Does kern turn the subordinate uid range on for this box BY DEFAULT, because it is an OCI image
/// box? The single statement of that rule on the box side: the real run and the `--show-config` dry
/// run both call it, so the dry run cannot report a range the box will not get, or miss one it will.
/// It reported `uid_range: false` for every image box for exactly as long as this was written twice.
fn image_default_uid_range(args: &BoxRunArgs) -> bool {
    args.image.is_some() && !args.no_uid_range
}

/// `--show-config`: print the resolved box configuration (after profiles, clamps and flag merges) to
/// stdout as plain `key: value` lines, then the caller exits. A dry run - unlike the status panel it
/// always prints (it's the whole point of the command) and goes to stdout so it can be captured.
fn print_resolved_config(
    args: &BoxRunArgs,
    name: &str,
    memory: Option<u64>,
    cpus: Option<f64>,
    cpuset: Option<&str>,
    nice: Option<i32>,
) {
    let (source, cmd) = display_source_cmd(args);
    println!("name: {name}");
    println!("source: {source}");
    println!("command: {cmd}");
    println!("read_only: {}", args.read_only);
    println!("bind_rootfs: {}", args.bind_rootfs);
    println!("share_net: {}", args.share_net);
    println!("memory: {}", or_dash(memory));
    println!("memory_swap_max: {}", or_dash(args.memory_swap_max));
    println!("cpus: {}", or_dash(cpus));
    println!("cpuset: {}", cpuset.unwrap_or("-"));
    println!("pids_limit: {}", or_dash(args.pids_limit));
    println!("nice: {}", or_dash(nice));
    println!("io_weight: {}", or_dash(args.io_weight));
    println!("volumes: {}", args.volumes.len());
    println!("ports: {}", args.ports.len());
    println!("secrets: {}", args.secrets.len());
    println!("cap_add: {}", args.cap_add.join(","));
    println!("cap_drop: {}", args.cap_drop.join(","));
    println!("hostname: {}", args.hostname.unwrap_or("-"));
    println!("user: {}", args.run_as.unwrap_or("-"));
    // The effective uid-range rule the box will actually apply (mirror of `box_run`): explicit
    // --uid-range, OR --ssh, OR a non-root --user (its uid must be mapped in). Derived the same way
    // here so the dry run can't report a different value than the box uses.
    let non_root_user = parse_user(args.run_as)
        .ok()
        .flatten()
        .is_some_and(|(u, _)| u != 0);
    // Report the range AND where it came from. The bare boolean stays a bare boolean (scripts parse
    // these lines), so the provenance is its own key: a caller can see that kern, not they, turned it
    // on, which is the difference between a default one may opt out of and a request one asked for.
    // The dry run runs before the image is resolved, so an image that declares a non-root USER can
    // still promote this to `request` at run time; `image-default` is a floor, never a ceiling.
    let asked = args.uid_range || args.ssh_port.is_some() || non_root_user;
    let by_image = image_default_uid_range(args);
    println!("uid_range: {}", asked || by_image);
    println!(
        "uid_range_source: {}",
        match (asked, by_image) {
            (true, _) => "request",
            (false, true) => "image-default",
            (false, false) => "-",
        }
    );
    println!("tun: {}", args.tun);
    println!("tty: {}", args.tty);
    println!("detached: {}", args.detached);
    println!(
        "timeout: {}",
        or_dash((args.timeout != 0).then_some(args.timeout))
    );
    println!(
        "seccomp_denied_syscalls: {}",
        kern_isolation::denied_syscall_count(nesting_active(args.privileged))
    );
    println!("privileged: {}", nesting_active(args.privileged));
}

/// Whether a `--privileged` request will ACTUALLY relax seccomp for nesting: only rootless (as real
/// host root the flag is refused earlier, but keep the display honest if that path is ever reached).
fn nesting_active(privileged: bool) -> bool {
    privileged && unsafe { libc::geteuid() } != 0
}

/// True the first time a foreground box runs in this login session, recording a marker under
/// `$XDG_RUNTIME_DIR` (tmpfs → cleared on logout, so "once per session") so the wordmark prints
/// once and not before every box. Best-effort: with no runtime dir (can't track) it returns false,
/// better to skip the logo than to reprint it every time. A lost race (two boxes at once) just
/// prints the logo twice, which is harmless.
fn first_box_of_session() -> bool {
    let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") else {
        return false;
    };
    let marker = std::path::Path::new(&dir).join("kern").join(".greeted");
    if marker.exists() {
        return false;
    }
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&marker, b"").is_ok()
}

/// Foreground `-it`: allocate a PTY, hand its slave to the box as a controlling terminal, put the
/// host terminal in raw mode, and let `run_in_sandbox_with` pump bytes between them until the box
/// exits - then restore the terminal and propagate the exit code.
fn run_box_interactive(
    mut spec: SandboxSpec,
    scratch: Option<PathBuf>,
    ports: &[kern_isolation::PortMap],
    timeout: u64,
) -> Result<(), Error> {
    let pty = crate::pty::open().map_err(|e| Error::Sandbox(format!("openpty: {e}")))?;
    spec.tty_slave = Some(pty.slave);
    let saved = crate::pty::raw_with_resize(pty.master);
    // `--timeout N`: same host-namespace watchdog as the non-tty path (forked here, before the
    // unshare), so a hung interactive session is force-stopped after N seconds.
    let timeout_wd = (timeout > 0)
        .then(|| spawn_foreground_timeout(timeout))
        .flatten();
    let result = run_in_sandbox_with(
        &spec,
        None,
        |pid1| feed_timeout_pid(timeout_wd, pid1),
        Some(pty.master),
        ports,
        // `-it`: leave the box tied to the controlling terminal/session, not to a launcher PDEATHSIG -
        // the terminal owns the session and the pty pump already ends the box when the tty closes.
        false,
    );
    cancel_foreground_timeout(timeout_wd);
    if let Some(ref prev) = saved {
        crate::pty::restore(0, prev);
    }
    unsafe { libc::close(pty.master) };
    cleanup_scratch(scratch.as_deref());
    match result {
        Ok(code) => std::process::exit(code),
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
) -> Result<(), Error> {
    use std::os::unix::process::CommandExt;
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
    // Robust caps via a transient systemd user scope whose MemoryMax/CPUQuota track the caps; this
    // re-execs once and returns here under KERN_SCOPE. Where systemd --user isn't present it's a
    // no-op and the best-effort in-process cgroup below applies the same caps.
    let cpus = clamp_cpus(cpus);
    let cpuset = clamp_cpuset(cpuset)?;
    // `kern run` exec()s in place (no supervisor to reap the cgroup) → `false`: it must use the systemd
    // `--scope --collect` path (which auto-removes the cgroup on exit), never the direct kern.slice path.
    reexec_in_scope_if_possible(ScopeReexec {
        memory,
        memory_swap_max,
        cpuset: cpuset.as_deref(),
        cpus,
        pids_max: None,
        allow_direct: false, // `kern run` execs the workload in place - no box to tie to the launcher
        die_with_parent: false,
        allow_uncapped: kern_common::env_flag("KERN_ALLOW_UNCAPPED"),
    });
    let cg = kern_isolation::apply_cgroup_limits(
        false, // allow_direct: `kern run` exec()s in place (no supervisor) → never relocate into kern.slice
        "run",
        memory,
        memory_swap_max,
        cpuset.as_deref(),
        cpus,
        None,  // `kern run` has no --pids-limit; box's pids cap is applied in the sandbox
        &[],   // no vdisk io limits in `kern run`
        None,  // no --io-weight in `kern run`
        false, // `kern run` is a cooperative governor, never fail-closed (best-effort gate)
    );
    // `kern run` is a cooperative GOVERNOR, not an isolation boundary - so unlike `kern box` it does NOT
    // fail-closed when a cap can't be applied. But make the drop VISIBLE, not silent: if the user asked
    // for a cap, no outer scope is enforcing it (`KERN_SCOPE` unset), and we couldn't apply it (`cg` None),
    // say so rather than let the workload quietly exceed it (there is no isolation here; only the limit).
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
        kern_isolation::warn_unenforced_caps(memory, cpus, None);
    }
    // `kern run` exec()s the workload IN PLACE - there is no supervisor left to reap it and drop the
    // guard afterwards. The guard's Drop would `rmdir` the cgroup we're about to exec into, which is
    // non-empty (we're in it) → EBUSY → a no-op anyway. Forget it so the intent is explicit: we do NOT
    // tear down our own live cgroup here. (Same as the pre-guard behaviour - the `run` cgroup outlives
    // this call; it's removed when the whole systemd scope / caller lifecycle is collected.)
    std::mem::forget(cg);
    // Pin CPUs via affinity (works with no cgroup cpuset delegation), and apply a profile's `nice`.
    kern_isolation::set_cpu_affinity(cpuset.as_deref());
    if let Some(n) = nice {
        unsafe { libc::setpriority(libc::PRIO_PROCESS as _, 0, n) };
    }
    // Bump the daemonless run-throughput counter (one atomic on a shared mmap) so `kern top` can show
    // live runs/sec - done here, in the final process that actually runs the workload (past any
    // scope re-exec), so each `kern run` counts exactly once. Best-effort: never fails the run.
    crate::runstats::record();
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

/// The effective resources a set of resource profiles contributes. `memory`/`cpus`/`cpuset`/`nice`
/// are pre-seeded from the CLI flags and a `vcpu:` fills only the ones left unset (explicit flags
/// win); `vgpio`/`vdisk` accumulate the resolved device/disk profiles the caller then applies.
#[derive(Default)]
struct AppliedProfiles {
    memory: Option<u64>,
    cpus: Option<f64>,
    cpuset: Option<String>,
    nice: Option<i32>,
    vgpio: Vec<crate::config::ResolvedVgpio>,
    vdisk: Vec<crate::config::ResolvedVdisk>,
}

/// Resolve resource-profile tokens (`vcpu:`/`vgpio:`/`vdisk:`) into `out`. Shared by `run` and `box`;
/// `kern.toml` (the `--config` path, else the default / `KERN_CONFIG`) is loaded once, lazily.
fn apply_profile_list(
    profiles: &[String],
    config: Option<&str>,
    out: &mut AppliedProfiles,
) -> Result<(), Error> {
    use crate::config::ProfileRef;
    if profiles.is_empty() {
        return Ok(());
    }
    let cfg = crate::config::load(config).map_err(Error::Config)?;
    // Multiple `vcpu:` profiles on one box do NOT merge: the FIRST to set each field wins (documented),
    // so a second `vcpu:` is a silent no-op on every field the first already set. That is almost always a
    // typo, so name it - which profile is in force, which are ignored - rather than pick one quietly.
    // Only `vcpu:` needs this: `vgpio:`/`vdisk:` STACK (each adds its own devices/disks), so several are
    // legitimate. Runs once, on the warning path only, so its allocations never touch a normal start.
    let vcpu_names: Vec<&str> = profiles
        .iter()
        .filter_map(|t| match crate::config::classify(t) {
            Some(ProfileRef::Vcpu(n)) => Some(n),
            _ => None,
        })
        .collect();
    if vcpu_names.len() > 1 {
        let all = vcpu_names
            .iter()
            .map(|n| format!("vcpu:{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "kern: warning: {} vcpu: profiles given ({all}); only the first (vcpu:{}) sets each cap it \
             defines - the others are ignored on any field it already set (first-wins). Merge them into \
             one profile with `extends` if you meant to layer them.",
            vcpu_names.len(),
            vcpu_names[0]
        );
    }
    for tok in profiles {
        match crate::config::classify(tok) {
            Some(ProfileRef::Vcpu(name)) => {
                let r = crate::config::resolve_vcpu(&cfg, name).map_err(Error::Config)?;
                out.memory = out.memory.or(r.memory);
                out.cpus = out.cpus.or(r.cpus);
                out.cpuset = out.cpuset.take().or(r.cpuset);
                out.nice = out.nice.or(r.nice);
            }
            Some(ProfileRef::Vgpio(name)) => {
                out.vgpio
                    .push(crate::config::resolve_vgpio(&cfg, name).map_err(Error::Config)?);
            }
            Some(ProfileRef::Vdisk(name)) => {
                out.vdisk
                    .push(crate::config::resolve_vdisk(&cfg, name).map_err(Error::Config)?);
            }
            None => {} // not a profile token - ignored (callers pass only classified tokens)
        }
    }
    Ok(())
}

/// For `run`: peel the leading profile tokens from `command` (plus a `--` separator the parser keeps
/// after the first non-flag token), resolve them into `out`, and return where the real command
/// starts.
fn peel_run_profiles(
    command: &[String],
    config: Option<&str>,
    out: &mut AppliedProfiles,
) -> Result<usize, Error> {
    // A LEADING `--` means the command was explicitly delimited (`kern run -- vcpu:heavy prog`): the
    // `--` end-of-options contract says the following tokens are the literal command, so we must NOT
    // peel a `vcpu:`/`vgpio:`/`vdisk:`-looking token as a profile. Skip the `--` and stop. (Matches the
    // `box` path, which never re-classifies past `--`.)
    if command.first().map(String::as_str) == Some("--") {
        return Ok(1);
    }
    let mut i = 0;
    while i < command.len() && crate::config::classify(&command[i]).is_some() {
        i += 1;
    }
    let profiles = command[..i].to_vec();
    if command.get(i).map(String::as_str) == Some("--") {
        i += 1;
    }
    apply_profile_list(&profiles, config, out)?;
    Ok(i)
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

/// A quota'd named volume couldn't get its ext4-loop backing (unprivileged, or `-d`/`-it`): bind the
/// plain data dir and say the quota isn't enforced - never silently.
fn quota_fallback(name: &str) -> Result<String, Error> {
    eprintln!(
        "kern: volume '{name}' has a quota but it isn't enforced here - the ext4-loop backend needs \
         a plain foreground box as root (or `disk` group); mounted as a plain directory. Note the \
         enforced (ext4 image) and unenforced (data dir) backends hold data separately."
    );
    crate::volume::resolve_named(name)
}

/// Turn a resolved vDisk into a box mount. Rootless (the default): a `size=`-capped `tmpfs` - the box
/// gets a real size quota with no privilege (RAM-backed, ephemeral). `iops`/`bandwidth`/`persistent`
/// need a disk-backed ext4-on-loop backend (root); rather than silently drop them, we say so. (The
/// ext4-loop backend is the next increment; the tmpfs path means a `vdisk:` profile always works.)
fn prepare_vdisk(
    vd: crate::config::ResolvedVdisk,
    ext4_ok: bool,
    work: &std::path::Path,
    handles: &mut Vec<crate::vdisk::Ext4Vdisk>,
    io_max: &mut Vec<String>,
) -> kern_isolation::VdiskMount {
    // Preferred: a real ext4-on-loop disk (needs privilege). Only for a plain foreground box, where
    // the handle's teardown is bounded to `box_run`. `prepare` returns `None` unprivileged → tmpfs.
    if ext4_ok {
        if let Some(size) = vd.size {
            if let Some(h) = crate::vdisk::prepare(
                &vd.name,
                size,
                vd.persistent,
                vd.backend_dir.as_deref(),
                work,
            ) {
                // `--iops`/`--bandwidth` → a cgroup `io.max` line for the loop device backing this
                // vdisk (`MAJ:MIN riops=… wiops=… rbps=… wbps=…`). The box's `apply_limits` writes it;
                // it takes effect only where the `io` controller is delegated (else a no-op, reported).
                if vd.iops.is_some() || vd.bandwidth.is_some() {
                    match h.loop_dev_num() {
                        Some((maj, min)) => {
                            io_max.push(io_max_line(maj, min, vd.iops, vd.bandwidth))
                        }
                        None => eprintln!(
                            "kern: vdisk:{} - could not resolve the loop device for iops/bandwidth",
                            vd.name
                        ),
                    }
                }
                let host_dir = h.mount.to_string_lossy().into_owned();
                handles.push(h);
                return kern_isolation::VdiskMount {
                    name: vd.name,
                    size: vd.size,
                    host_dir: Some(host_dir),
                };
            }
        }
    }
    // `backend = "disk:<pool>"` is an explicit request for a DISK, and this is the path where it did
    // not happen. Until now it only got a message if the profile ALSO set `iops`/`bandwidth`/
    // `persistent`, or asked for >= 1 GiB - so the ordinary case (a disk pool, a modest size) was told
    // nothing at all and got RAM. Found on a root VPS on 2026-08-01: `backend = "disk:pool"`,
    // `size = "64m"`, `mkfs.ext4` present, `/dev/loop-control` writable, and `df` inside the box said
    // `tmpfs`, because the box was `--detach`ed. Name the reason, since the two are fixed differently.
    if vd.backend_dir.is_some() {
        let why = if !ext4_ok {
            "the ext4-loop backend is only used for a FOREGROUND box (its teardown is bounded to the \
             box's run); drop -d / -it to get the disk-backed quota"
        } else {
            "the ext4-loop backend needs privilege: root (or the `disk` group) for /dev/loop-control, \
             plus mkfs.ext4 - see `kern doctor`"
        };
        eprintln!(
            "kern: vdisk:{} asked for a disk backend but is RAM-backed (tmpfs) here: {}. The size cap \
             is still enforced; the data is EPHEMERAL and counts against the box's memory.",
            vd.name, why
        );
    }
    // Rootless fallback: a size-capped tmpfs. Be honest about what it can't do.
    if vd.iops.is_some() || vd.bandwidth.is_some() || vd.persistent {
        eprintln!(
            "kern: vdisk:{} - iops/bandwidth/persistent need the ext4-loop backend (root, foreground \
             box); the rootless tmpfs backend applies only the size cap",
            vd.name
        );
    }
    // The tmpfs is RAM-backed, so `size` counts against RAM (correctly charged to the box's memory
    // cgroup - a write past `--memory` OOM-kills the box, exit 137; verified) AND its data is
    // EPHEMERAL - gone when the box exits. Say both, so a large scratch isn't mistaken for a disk.
    if vd.size.is_some_and(|b| b >= 1 << 30) {
        eprintln!(
            "kern: vdisk:{} is RAM-backed (tmpfs) rootless - its data is EPHEMERAL (gone when the box \
             exits) and its size counts against RAM; pair a large vdisk with --memory (or run a \
             foreground box as root for the persistent ext4 backend)",
            vd.name
        );
    }
    kern_isolation::VdiskMount {
        name: vd.name,
        size: vd.size,
        host_dir: None,
    }
}

/// Build a cgroup v2 `io.max` line for a device: `MAJ:MIN` + read/write IOPS (from `--iops`) and
/// read/write bytes-per-second (from `--bandwidth`), applied symmetrically to reads and writes.
fn io_max_line(maj: u32, min: u32, iops: Option<u64>, bandwidth: Option<u64>) -> String {
    let mut s = format!("{maj}:{min}");
    if let Some(n) = iops {
        s.push_str(&format!(" riops={n} wiops={n}"));
    }
    if let Some(b) = bandwidth {
        s.push_str(&format!(" rbps={b} wbps={b}"));
    }
    s
}

/// Parsed inputs for [`build_spec`].
struct BuildSpec<'a> {
    name: &'a BoxName,
    lower: String,
    cmd: Vec<String>,
    read_only: bool,
    landlock_rw: Vec<String>,
    apparmor: Option<String>,
    volumes: Vec<Volume>,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    share_net: bool,
    /// `--pod`: the pod holder PID whose user+net ns this box joins (`None` = its own).
    pod_holder: Option<i32>,
    uid_range: UidRange,
    bind_rootfs: bool,
    /// `--privileged`: relax seccomp for a nested `kern box` (rootless-only).
    privileged: bool,
    /// `--require-limits`: fail-closed if a resource cap cannot be enforced (else best-effort uncapped).
    require_limits: bool,
    /// `--allow-uncapped`: accept running uncapped silently (no best-effort notice). XOR require_limits.
    allow_uncapped: bool,
    /// The box's seccomp filter, RESOLVED by the caller (explicit `KERN_SECCOMP` > profile > default)
    /// into a value, not read from the environment here - see [`resolve_seccomp_mode`].
    seccomp_mode: kern_isolation::SeccompFilter,
    /// INTERNAL (build): a persistent overlay upper dir; overlays `lower` and keeps writes there.
    overlay_upper: Option<String>,
    memory: Option<u64>,
    memory_swap_max: Option<u64>,
    cpus: Option<f64>,
    cpuset: Option<String>,
    vgpio_devs: Vec<String>,
    vgpio_sysfs: Vec<String>,
    vdisks: Vec<kern_isolation::VdiskMount>,
    secrets: Vec<(String, Vec<u8>)>,
    ssh: Option<kern_isolation::SshSetup>,
    hostname: Option<String>,
    tun: bool,
    init: bool,
    tmpfs: Vec<(String, String)>,
    run_as: Option<(u32, u32)>,
    pids_max: Option<u64>,
    caps: kern_isolation::CapSpec,
    io_max: Vec<String>,
    io_weight: Option<u64>,
    /// `--add-host NAME:IP` entries (`host-gateway` already resolved to a concrete address).
    extra_hosts: Vec<(String, String)>,
    /// `--ulimit`, pre-resolved to `(RLIMIT_*, soft, hard)`.
    ulimits: Vec<(i32, u64, u64)>,
    /// `--sysctl KEY=VALUE`, applied inside the box's namespaces.
    sysctls: Vec<(String, String)>,
}

/// Build the sandbox spec. **Always an overlay** (the image/rootfs is the read-only lower; a
/// private upper takes writes) over a scratch tree under the runtime dir, removed after the box
/// exits. `--read-only` then remounts that overlay read-only.
///
/// Why overlay even for `--read-only` (rather than a plain bind + remount-ro): on some kernels a
/// **bind** mount cannot be remounted read-only inside a user namespace (e.g. Android-kernel
/// boards return EPERM - the bind inherits a lock from a host mount the child userns doesn't own),
/// whereas an **overlay** has its own superblock created in the namespace and *can* be remounted
/// read-only. Using overlay for both modes makes `--read-only` work everywhere and keeps the
/// image immutable (writes, when allowed, only ever hit the discarded upper).
///
/// When `--net` shares the host network, the host's `/etc/resolv.conf` is copied into the upper
/// so DNS works out of the box.
/// Resolve the resource-cap posture from the two flags and their env fallbacks, in ONE place, and
/// reject the contradiction on the RESOLVED values rather than on the raw flags. This is what catches
/// the mixed forms a flag-only parse check misses: `--require-limits` paired with `KERN_ALLOW_UNCAPPED`
/// (or `--allow-uncapped` with `KERN_REQUIRE_LIMITS`). `require`/`allow` are `flag || env`, so an env
/// can only ENABLE, never override an explicit flag - the safe direction for a fail-closed control.
/// Pure and total: it reads no environment itself (the caller passes the two resolved env booleans),
/// so it unit-tests every combination without touching the process state.
fn resolve_limit_policy(
    require_flag: bool,
    require_env: bool,
    allow_flag: bool,
    allow_env: bool,
) -> Result<(bool, bool), Error> {
    let require = require_flag || require_env;
    let allow = allow_flag || allow_env;
    if require && allow {
        return Err(Error::Usage(
            "--require-limits and --allow-uncapped are mutually exclusive (one refuses an \
             unenforceable cap, the other accepts it); this also holds when either is set through \
             KERN_REQUIRE_LIMITS or KERN_ALLOW_UNCAPPED",
        ));
    }
    Ok((require, allow))
}

fn build_spec(b: BuildSpec) -> Result<(SandboxSpec, Option<PathBuf>), Error> {
    // Hostname: `--hostname` wins, else the box name (the box's own UTS namespace, so it's private).
    let hostname = b
        .hostname
        .clone()
        .unwrap_or_else(|| b.name.as_str().to_string());

    // `--bind-rootfs`: skip the overlay and bind the rootfs directly. On kernels with a slow
    // overlayfs mount (some Android-kernel boards: ~31 ms for an overlay vs ~8 ms for a bind) this
    // is the difference between winning and losing on raw start. The trade-off - accepted by the
    // explicit flag - is that the source is mutable and shared: writes land in the rootfs dir and
    // boxes sharing one rootfs are not isolated from each other. There is no overlay scratch.
    //
    // Unlike the overlay path, we deliberately do NOT inject `/etc/resolv.conf` here even with
    // `--net`: that would be a host-side, privileged write into the user-supplied rootfs, and a
    // symlink there (e.g. `/etc/resolv.conf -> ../../host/file`) would make it clobber a file
    // *outside* the rootfs. A bind-mode box uses whatever `/etc/resolv.conf` its rootfs already
    // ships (`--net` still gives outbound networking; add a resolv.conf to the rootfs if needed).
    // The rootfs strategy is the ONLY thing that differs between bind and overlay: pick
    // `(root, mode, overlay, cleanup)` here, then build the one shared SandboxSpec below (its ~27
    // other fields were duplicated field-for-field in both branches - a silent-drift hazard).
    let (root, mode, overlay, eph): (String, MountMode, Option<OverlayDirs>, Option<PathBuf>) = if b
        .bind_rootfs
    {
        (b.lower, MountMode::Bind, None, None)
    } else {
        // The writable overlay upper. Normally an ephemeral scratch (discarded on exit). For a `kern
        // build` RUN step (`overlay_upper` set) the UPPER persists in the build tree so successive RUN/
        // COPY steps accumulate into it (the "diff" layer). overlayfs requires upperdir and workdir to be
        // on the SAME filesystem, so in build mode BOTH live under the build tree (work is cleared each
        // step - overlay wants a fresh workdir); only `merged` (a bare mountpoint) stays ephemeral.
        let eph = scratch_dir().join(format!("{}-{}", b.name.as_str(), std::process::id()));
        // Create the ephemeral parent once (0700) so the per-leaf creates below (`upper`/`work`/`merged`,
        // all under `eph` in the common case) are a single bare mkdir each instead of each re-walking
        // and re-stat-ing the shared parent chain - a few fewer serial pre-fork syscalls per box.
        own_only_dir(&eph).map_err(|e| Error::Sandbox(format!("overlay scratch: {e}")))?;
        let merged = eph.join("merged");
        let (upper, work) = match &b.overlay_upper {
            Some(dir) => {
                let root = PathBuf::from(dir);
                let w = root.join("work");
                // overlayfs REQUIRES an empty workdir, so this is a precondition, not tidying. Left
                // discarded, a refused removal surfaced later as a bare `mount: invalid argument` with
                // no way to connect it to the leftover directory that caused it.
                match std::fs::remove_dir_all(&w) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(Error::Sandbox(format!(
                            "overlay work dir {}: cannot clear it, and overlayfs requires it empty: {e}",
                            w.display()
                        )))
                    }
                }
                (build_upper_dir(&root), w)
            }
            None => (eph.join("upper"), eph.join("work")),
        };
        own_only_dir(&upper).map_err(|e| Error::Sandbox(format!("overlay upper: {e}")))?;
        // overlayfs presents the merged root's mode as the UPPER dir's mode. The upper is 0700 (own-only)
        // by default, which makes the box's `/` un-traversable by ANY dropped, cap-less non-root uid →
        // exec/read fails EACCES on `/` itself (the first path component). A `--user` uid hits this, but
        // so does the far more common case: an OCI image whose ENTRYPOINT drops privilege internally
        // (postgres/redis/mysql/nginx `setpriv`/`gosu` to a service uid) - there is no `--user`, yet the
        // workload still ends up non-root and needs a world-traversable `/`. So give the box a normal
        // 0755 root (exactly like a real rootfs) whenever privilege MIGHT be dropped: an explicit
        // non-root `--user`, OR a `--uid-range` box (which exists precisely to run such images). This is
        // the fix for the "official images don't start" gap. It's safe: the HOST scratch dir is still
        // 0700 (no other host user can enter), and root=0755 is the norm for every real filesystem -
        // it's the in-box view only, and the box's isolation is the namespace, not the root's mode.
        //
        // A POD MEMBER (`pod_holder` set) gets the same treatment: it joins a shared user namespace that
        // may map a subordinate uid range (`pod create --uid-range`), and its image may drop privilege to
        // a service uid - but the box's own `uid_range` flag is false there (the range lives on the pod
        // holder, not this box), so it must be included explicitly or postgres/redis/… in a pod hit the
        // exact EACCES-on-`/` gap this whole block fixes. Harmless for a single-uid pod (no other uid to
        // traverse). Found via a live python+postgres pod stack: the entrypoint's `gosu postgres` drop
        // could not traverse the 0700 `/`, so every PATH lookup failed "not found".
        let root_traversable = matches!(b.run_as, Some((u, _)) if u != 0)
            || b.uid_range.is_on()
            || b.pod_holder.is_some();
        if root_traversable {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&upper, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| Error::Sandbox(format!("overlay upper perms: {e}")))?;
        }
        for d in [&work, &merged] {
            std::fs::create_dir_all(d).map_err(|e| Error::Sandbox(format!("scratch dir: {e}")))?;
        }
        // With `--net` sharing the host network, copy the host's resolv.conf into the upper so DNS
        // resolves inside the box. A private copy → the box can't touch the host's file, and it's
        // removed with the scratch. (Best-effort: no host resolv.conf → IPs still work.)
        if b.share_net {
            if let Ok(conf) = std::fs::read("/etc/resolv.conf") {
                let etc = upper.join("etc");
                // Best-effort, and now audible. A box whose `resolv.conf` could not be written still
                // runs and still reaches every literal IP, so this must not fail the box - but silence
                // turned "DNS does not resolve in here" into a symptom with no stated cause.
                let placed = std::fs::create_dir_all(&etc)
                    .and_then(|()| std::fs::write(etc.join("resolv.conf"), conf));
                if let Err(e) = placed {
                    eprintln!(
                        "kern: warning: could not place /etc/resolv.conf in the box: {e} -                          name resolution will not work inside it (literal IPs still do)"
                    );
                }
            }
        }
        (
            merged.to_string_lossy().into_owned(),
            MountMode::Overlay,
            Some(OverlayDirs {
                lower: b.lower,
                upper: upper.to_string_lossy().into_owned(),
                work: work.to_string_lossy().into_owned(),
            }),
            // Clean up work/merged (and, when the upper is ephemeral, the upper too) after the box
            // exits; a build's persistent upper lives outside `eph`, owned by the build driver.
            Some(eph),
        )
    };

    // Resolve the cap posture from flags + env in ONE place, and reject the contradiction on the
    // RESOLVED values (so `--require-limits` + `KERN_ALLOW_UNCAPPED`, and every other mix, is caught -
    // a flag-only parse check would miss the env combinations).
    let (require_limits, allow_uncapped) = resolve_limit_policy(
        b.require_limits,
        kern_common::env_flag("KERN_REQUIRE_LIMITS"),
        b.allow_uncapped,
        kern_common::env_flag("KERN_ALLOW_UNCAPPED"),
    )?;

    let spec = SandboxSpec {
        root,
        mode,
        overlay,
        read_only: b.read_only,
        landlock_rw: b.landlock_rw,
        apparmor: b.apparmor,
        command: b.cmd,
        hostname,
        volumes: b.volumes,
        env: b.env,
        workdir: b.workdir,
        share_net: b.share_net,
        pod_holder: b.pod_holder,
        uid_range: b.uid_range,
        memory_max: b.memory,
        memory_swap_max: b.memory_swap_max,
        cpuset: b.cpuset,
        cpus: b.cpus,
        tty_slave: None,
        vgpio_devs: b.vgpio_devs,
        vgpio_sysfs: b.vgpio_sysfs,
        vdisks: b.vdisks,
        secrets: b.secrets,
        ssh: b.ssh,
        tun: b.tun,
        init: b.init,
        tmpfs: b.tmpfs,
        run_as: b.run_as,
        pids_max: b.pids_max,
        caps: b.caps,
        io_max: b.io_max,
        io_weight: b.io_weight,
        extra_hosts: b.extra_hosts,
        ulimits: b.ulimits,
        sysctls: b.sysctls,
        privileged: b.privileged,
        // Resolved above (flag || env, contradiction rejected). `--require-limits`/`KERN_REQUIRE_LIMITS`
        // fail-closed; `--allow-uncapped`/`KERN_ALLOW_UNCAPPED` accept-uncapped; mutually exclusive.
        require_limits,
        allow_uncapped,
        // The seccomp filter, RESOLVED ONCE by the caller (`resolve_seccomp_mode`: explicit
        // `KERN_SECCOMP` > `--security-profile` > default) into `b.seccomp_mode` - a value, never a
        // re-read of the environment here. PID 1 installs it and the instance record carries it, so
        // `kern exec` reproduces the box's filter (a profile-set allowlist reproduces as allowlist, not
        // as the wider denylist). Single point of resolution for the box's whole lifetime.
        seccomp_mode: b.seccomp_mode,
    };
    // Audit mode is a validation aid, deliberately LESS confined than the shipped denylist (its
    // log-and-run default lets clone3/io_uring RUN instead of returning ENOSYS). Warn loudly, once per
    // box, so it can never be mistaken for a production posture on an operator who set the env by habit.
    if spec.seccomp_mode == kern_isolation::SeccompFilter::AllowlistAudit {
        eprintln!(
            "kern: warning: KERN_SECCOMP=allowlist-audit is a VALIDATION mode - it records the syscalls a \
             real allowlist would refuse but LETS THEM RUN (clone3, io_uring, and every other \
             ENOSYS-denied call), so the box is LESS confined than the default allowlist. The kill set \
             still kills; do NOT use this as a production posture."
        );
    }
    Ok((spec, eph))
}

/// Parse `-v src:dst[:ro]` specs into [`Volume`]s. The target must be absolute; the source is a
/// volume name, an absolute path, or a `./`-style path relative to the current directory, and must
/// exist on the host. A trailing `:ro` (or `:rw`) sets the mode.
fn parse_volumes(specs: &[String]) -> Result<Vec<Volume>, Error> {
    let mut out = Vec::with_capacity(specs.len());
    for s in specs {
        let parts: Vec<&str> = s.split(':').collect();
        let (source, target, read_only) = match parts.as_slice() {
            [src, dst] => (*src, *dst, false),
            [src, dst, "ro"] => (*src, *dst, true),
            [src, dst, "rw"] => (*src, *dst, false),
            _ => {
                return Err(Error::Sandbox(format!(
                    "bad -v '{s}' (expected src:dst[:ro])"
                )))
            }
        };
        // The target is always an absolute, `.`/`..`-free, NUL-free path inside the box.
        if !target.starts_with('/') {
            return Err(Error::Sandbox(format!("-v '{s}': target must be absolute")));
        }
        if target.contains('\0') {
            return Err(Error::Sandbox(format!("-v '{s}': target has a NUL byte")));
        }
        if target.split('/').any(|c| c == "." || c == "..") {
            return Err(Error::Sandbox(format!(
                "-v '{s}': target must not contain '.' or '..'"
            )));
        }
        // Refuse to shadow the box's own essential mounts: a `-v` exactly over `/`, `/proc`, `/sys` or
        // `/dev` would hide the sandbox's isolation setup (masked proc/sys, minimal dev). A SUBPATH
        // (e.g. `/dev/foo`, `/data`) is fine - only these exact roots are protected. Normalize the way
        // the mount actually resolves it (`open_in_root` splits on '/' and drops empty components), so
        // a leading-double-slash target like `//dev` - which trims to a non-matching string but still
        // resolves to `/dev` at mount time - can't slip past this guard.
        let comps: Vec<&str> = target.split('/').filter(|c| !c.is_empty()).collect();
        if comps.is_empty() || matches!(comps.as_slice(), ["proc"] | ["sys"] | ["dev"]) {
            let shown = if comps.is_empty() {
                "/".to_string()
            } else {
                format!("/{}", comps.join("/"))
            };
            return Err(Error::Sandbox(format!(
                "-v '{s}': cannot mount over {shown} (a box essential mount)"
            )));
        }
        // A NAMED volume resolves to its data dir (auto-created on first use); a PATH is
        // canonicalized symlink-free, so a missing source is rejected here rather than as an opaque
        // post-fork mount failure. `canonicalize` resolves a relative path (`.`, `./src`,
        // `../shared`) against the current directory, which is what makes `-v .:/app` work. No
        // containment guard on purpose: unlike compose, which confines binds under the project dir,
        // a direct CLI invocation can already name any absolute path, so resolving a relative one
        // grants nothing new and refusing `../shared:/x` would only break a legitimate call.
        // `volume::classify` owns the name-or-path decision so this site cannot disagree with it.
        let source = match crate::volume::classify(source) {
            crate::volume::SourceKind::Named => crate::volume::resolve_named(source)?,
            crate::volume::SourceKind::Path => {
                let canon = std::fs::canonicalize(source)
                    .map_err(|e| Error::Sandbox(format!("-v '{s}': source {source}: {e}")))?;
                // A box that can WRITE the kern registry can forge a PEER box's recorded capability/
                // seccomp posture and elevate that peer's `kern exec` (proven, adversarial review).
                // Refuse to bind a trust-bearing registry dir - or a parent that contains one - into
                // any box. Named volumes resolve in the SIBLING branch above and are unaffected.
                if crate::registry::path_overlaps_trusted_state(&canon) {
                    return Err(Error::Sandbox(format!(
                        "-v '{s}': refusing to mount the kern registry ({}) into a box - a box able \
                         to write it could forge another box's recorded capability/seccomp posture \
                         and elevate its own `kern exec`",
                        canon.display()
                    )));
                }
                canon.to_string_lossy().into_owned()
            }
            crate::volume::SourceKind::Neither => {
                return Err(Error::Sandbox(format!(
                    "-v '{s}': source must be a volume name or a path (absolute, or ./ or ../)"
                )))
            }
        };
        out.push(Volume {
            source,
            target: target.to_string(),
            read_only,
        });
    }
    Ok(out)
}

/// The command a box/exec runs when none is given.
const DEFAULT_SHELL: &str = "/bin/sh";

/// `command` if non-empty, else a one-element argv of [`DEFAULT_SHELL`].
fn default_if_empty(command: &[String]) -> Vec<String> {
    if command.is_empty() {
        vec![DEFAULT_SHELL.to_string()]
    } else {
        command.to_vec()
    }
}

/// Resolve the box's effective command from the user's `-- CMD` and the image's OCI config, docker-
/// style: the image `Entrypoint` is prepended to either the user's command or (if none) the image's
/// `Cmd`; a shell is the fallback when nothing is set anywhere. `--ssh` with no command keeps the box
/// alive instead (the sshd is a child of PID 1, which would otherwise exit). For `--rootfs` the
/// config is empty, so this reduces to the user's command or a shell - the prior behaviour.
fn resolve_image_command(
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
fn write_image_config(path: &std::path::Path, c: &kern_oci::ImageConfig) -> std::io::Result<()> {
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
fn read_image_config(path: &std::path::Path) -> kern_oci::ImageConfig {
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

/// Parse `--env K=V` specs. The value may contain `=`; the key may not be empty.
fn parse_envs(specs: &[String]) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::with_capacity(specs.len());
    for s in specs {
        match s.split_once('=') {
            Some((k, v)) if !k.is_empty() => out.push((k.to_string(), v.to_string())),
            _ => return Err(Error::Sandbox(format!("bad --env '{s}' (expected K=V)"))),
        }
    }
    Ok(out)
}

/// Parse `--env-file PATH` files: one `K=V` per line, `#`-comment and blank lines skipped, surrounding
/// whitespace on the key trimmed. Later files (and `--env`) override earlier keys by list order.
fn parse_env_files(paths: &[String]) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::new();
    for p in paths {
        // Route through the ONE guarded host-file reader: `--env-file` delivers a file's K=V lines into
        // the box's env, so `--env-file <runtime>/kern/instances/<peer>` would inject a peer's posture
        // record (`capdropall=`, `seccompmode=`, …) - the same class `--secret` and `-v` are guarded for.
        let bytes = crate::secret::read_host_file_for_box(p, "--env-file")?;
        let body = String::from_utf8(bytes)
            .map_err(|_| Error::Sandbox(format!("--env-file '{p}' is not valid UTF-8")))?;
        for (n, raw) in body.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.split_once('=') {
                Some((k, v)) if !k.trim().is_empty() => {
                    out.push((k.trim().to_string(), v.to_string()))
                }
                _ => {
                    return Err(Error::Sandbox(format!(
                        "bad line {} in --env-file '{p}' (expected K=V): {line}",
                        n + 1
                    )))
                }
            }
        }
    }
    Ok(out)
}

/// Validate a `--hostname` before it reaches `sethostname`: a DNS-label-ish name (letters/digits/`.`/
/// `-`, no leading/trailing `-`/`.`, ≤ 64, no `/` or NUL). `None` → keep the default (the box name).
fn validate_hostname(h: Option<&str>) -> Result<Option<String>, Error> {
    let Some(h) = h else { return Ok(None) };
    let ok = !h.is_empty()
        && h.len() <= 64
        && !h.starts_with(['-', '.'])
        && !h.ends_with(['-', '.'])
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    if ok {
        Ok(Some(h.to_string()))
    } else {
        Err(Error::Sandbox(format!(
            "invalid --hostname '{h}' (letters/digits/-/. only, no leading/trailing -/., ≤64)"
        )))
    }
}

/// Parse `--tmpfs PATH[:size]` specs into `(path, size)` - `size` a tmpfs `size=` token (`"64m"`),
/// empty for the kernel default. The path must be absolute, `.`/`..`/NUL-free, and not shadow a
/// hardened mount (`/proc`, `/sys`, `/dev`). A bad size (not digits + optional k/m/g/t) is rejected.
fn parse_tmpfs(specs: &[String]) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::with_capacity(specs.len());
    for s in specs {
        let (path, size) = match s.split_once(':') {
            Some((p, sz)) => (p, sz),
            None => (s.as_str(), ""),
        };
        if !path.starts_with('/')
            || path.contains('\0')
            || path.split('/').any(|c| c == "." || c == "..")
        {
            return Err(Error::Sandbox(format!(
                "--tmpfs '{s}': path must be absolute, without '.'/'..'/NUL"
            )));
        }
        // Normalize like the mount resolves it (drop empty components) so a leading-double-slash path
        // (`//proc`) can't slip past. Block the hardened roots AND anything under them: the first real
        // path component being proc/sys/dev is the test.
        let first = path.split('/').find(|c| !c.is_empty());
        if matches!(first, Some("proc") | Some("sys") | Some("dev")) {
            return Err(Error::Sandbox(format!(
                "--tmpfs '{path}' is refused (it would shadow the sandbox's hardened /proc, /sys or /dev)"
            )));
        }
        if !size.is_empty() {
            let core = size
                .strip_suffix(['k', 'm', 'g', 't', 'K', 'M', 'G', 'T'])
                .unwrap_or(size);
            if core.is_empty() || !core.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Sandbox(format!(
                    "--tmpfs '{s}': bad size '{size}' (digits + optional k/m/g/t, e.g. 64m)"
                )));
            }
        }
        out.push((path.to_string(), size.to_ascii_lowercase()));
    }
    Ok(out)
}

/// Parse `--user UID[:GID]` into `(uid, gid)` (a bare `UID` uses `UID` for the gid too). Numeric only
/// - a user namespace maps ids, not names. `None` → keep the box's namespace root.
fn parse_user(spec: Option<&str>) -> Result<Option<(u32, u32)>, Error> {
    let Some(s) = spec else { return Ok(None) };
    let bad = || Error::Sandbox(format!("--user '{s}': expected UID or UID:GID (numeric)"));
    let (uid, gid) = match s.split_once(':') {
        Some((u, g)) => (
            u.parse::<u32>().map_err(|_| bad())?,
            g.parse::<u32>().map_err(|_| bad())?,
        ),
        None => {
            let u = s.parse::<u32>().map_err(|_| bad())?;
            (u, u)
        }
    };
    Ok(Some((uid, gid)))
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
fn image_account_entry(lower: &str, file: &str, name: &str) -> Option<Vec<String>> {
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
fn resolve_image_user(spec: &str, lower: &str) -> Option<(u32, u32)> {
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

#[cfg(test)]
mod image_user_resolution_tests {
    use super::*;

    /// A box's `config.User` given by NAME (e.g. memcached's `USER memcache`) must resolve to the image's
    /// own uid/gid the way Docker does - reading the rootfs's `/etc/passwd`/`/etc/group` - not silently
    /// run as box root. This is the fix for the class that killed memcached, unprivileged nginx, etc.
    #[test]
    fn resolves_user_name_uid_gid_group_and_numerics_from_the_image() {
        let root = std::env::temp_dir().join(format!("kern-usr-{}", std::process::id()));
        let etc = root.join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/sh\nmemcache:x:11211:11211:Memcached:/:/sbin/nologin\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("group"),
            "root:x:0:\nstaff:x:50:\nmemcache:x:11211:\n",
        )
        .unwrap();
        let lower = root.to_string_lossy();

        // bare NAME -> uid AND its passwd primary gid (Docker's rule).
        assert_eq!(resolve_image_user("memcache", &lower), Some((11211, 11211)));
        // NAME:groupname -> uid from passwd, gid from group (overrides the passwd gid).
        assert_eq!(
            resolve_image_user("memcache:staff", &lower),
            Some((11211, 50))
        );
        // NAME:numericgid, and a fully-numeric spec, both parse without the files.
        assert_eq!(resolve_image_user("memcache:99", &lower), Some((11211, 99)));
        assert_eq!(resolve_image_user("root", &lower), Some((0, 0)));
        assert_eq!(resolve_image_user("1000:1000", &lower), Some((1000, 1000)));
        // A name the image does NOT define -> None, so the caller keeps box-root with an honest note.
        assert_eq!(resolve_image_user("ghost", &lower), None);
        assert_eq!(resolve_image_user("memcache:nogroup", &lower), None);
        // No account files at all (a scratch image) -> None, never a wrong uid.
        let empty = std::env::temp_dir().join(format!("kern-usr-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(
            resolve_image_user("memcache", &empty.to_string_lossy()),
            None
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&empty);
    }

    /// The lookup walks an overlay `top:…:base` chain and the TOP-most layer that carries the file wins,
    /// the way the merged rootfs would present it.
    #[test]
    fn top_layer_of_an_overlay_chain_wins() {
        let base = std::env::temp_dir().join(format!("kern-usr-base-{}", std::process::id()));
        let top = std::env::temp_dir().join(format!("kern-usr-top-{}", std::process::id()));
        std::fs::create_dir_all(base.join("etc")).unwrap();
        std::fs::create_dir_all(top.join("etc")).unwrap();
        std::fs::write(base.join("etc/passwd"), "app:x:1000:1000::/:/bin/sh\n").unwrap();
        std::fs::write(top.join("etc/passwd"), "app:x:2000:2000::/:/bin/sh\n").unwrap();
        // chain is "top:base"; top's entry (2000) is authoritative.
        let chain = format!("{}:{}", top.to_string_lossy(), base.to_string_lossy());
        assert_eq!(resolve_image_user("app", &chain), Some((2000, 2000)));

        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&top);
    }

    /// A hostile image whose account file is a symlink OUT of the rootfs must NOT resolve against host
    /// paths - `image_account_field` reads pre-pivot on the host, so an unconfined read would follow the
    /// link. Confinement returns `None` (caller keeps box-root), even though the escape target defines the
    /// name.
    #[test]
    fn a_passwd_symlink_escaping_the_rootfs_does_not_resolve() {
        let root = std::env::temp_dir().join(format!("kern-usr-esc-{}", std::process::id()));
        let outside =
            std::env::temp_dir().join(format!("kern-usr-esc-target-{}", std::process::id()));
        std::fs::create_dir_all(root.join("etc")).unwrap();
        // The victim account lives OUTSIDE the rootfs; the image's /etc/passwd is a symlink to it.
        std::fs::write(&outside, "victim:x:1234:1234::/:/bin/sh\n").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("etc/passwd")).unwrap();
        // Unconfined this would return Some((1234, 1234)); confined it must be None.
        assert_eq!(resolve_image_user("victim", &root.to_string_lossy()), None);

        // An IN-rootfs symlink (a real distro layout) still resolves - its target stays under the layer.
        std::fs::remove_file(root.join("etc/passwd")).unwrap();
        std::fs::write(root.join("etc/passwd.real"), "app:x:777:777::/:/bin/sh\n").unwrap();
        std::os::unix::fs::symlink("passwd.real", root.join("etc/passwd")).unwrap();
        assert_eq!(
            resolve_image_user("app", &root.to_string_lossy()),
            Some((777, 777))
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&outside);
    }
}

/// `kern exec <name> [--env K=V] [--workdir <dir>] [-- cmd...]` - run a command inside an
/// already-running box, joining its namespaces. Defaults to `/bin/sh`. Propagates the exit code.
pub fn exec(
    name: &str,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
    tty: bool,
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
    let pid1 = if inst.pid1 > 0 {
        inst.pid1
    } else {
        registry::child_of(inst.pid)
            .ok_or_else(|| Error::Sandbox("could not locate the box's main process".to_string()))?
    };

    // `-it`: allocate a PTY and (when our own stdin is a terminal) put it in raw mode + forward
    // window resizes, exactly like `kern box -it`. `exec_in_box` hands the slave to the exec'd
    // process as its controlling tty and pumps host stdio <-> master; we restore the terminal after.
    let pty = if tty {
        Some(crate::pty::open().map_err(|e| Error::Sandbox(format!("openpty: {e}")))?)
    } else {
        None
    };
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
    let result = exec_in_box(
        pid1,
        &cmd,
        &env,
        effective_workdir,
        pty.as_ref().map(|p| p.slave),
        pty.as_ref().map(|p| p.master),
        None, // `kern exec` has no timeout
        box_has_explicit_caps,
        &box_caps,
        box_seccomp,
        box_aa.as_deref(),
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

// Subuid/subgid range resolution and the trusted id-map helper lookup are the ONE authoritative
// implementation in kern-isolation (`sub_range` / `trusted_helper` / `username`), reused here so the
// cleanup path can't drift from the box-start path.

/// Remove a box's writable scratch tree (best-effort), with a ranged fallback for subuid-owned files.
fn cleanup_scratch(scratch: Option<&std::path::Path>) {
    if let Some(s) = scratch {
        if std::fs::remove_dir_all(s).is_ok() || !s.exists() {
            return;
        }
        // remove_dir_all failed and the dir is still there: a `--uid-range` box (or a pod member) can
        // leave files owned by SUBORDINATE uids (an image that dropped to e.g. uid 472 → host subuid
        // 100471) that we - as the plain host user, outside any userns - can't unlink (they sit under
        // subuid-owned dirs). Retry inside a `newuidmap`-mapped user namespace where those subuids map
        // back to ns-root, so the remove succeeds. This is what `podman unshare rm` does for the same
        // reason. Best-effort: if the range isn't available, we've already tried the plain remove.
        //
        // TOCTOU (the ranged remove is PRIVILEGED - subuids map to ns-root - and descends a tree a box
        // wrote): a box process surviving teardown could plant a symlink mid-descent to steer the
        // recursive remove outside the scratch tree. Two layers close it: (1) `remove_dir_all` is
        // no-follow at every level (openat+O_NOFOLLOW since Rust 1.26; our MSRV is 1.82, so guaranteed,
        // not toolchain-luck); (2) BEFORE removing, we re-open the target under kern's scratch-root with
        // `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` - a kernel-level check that no component is a
        // symlink or escapes the root. If that open is refused, we do NOT run the ranged remove.
        if !scratch_path_is_confined(s) {
            return;
        }
        remove_dir_all_ranged(s);
    }
}

/// True iff `dir` opens cleanly under kern's scratch-root with `openat2(RESOLVE_BENEATH |
/// RESOLVE_NO_SYMLINKS)` - i.e. every path component stays beneath the root and none is a symlink.
/// Kernel-enforced (Linux 5.6+ for openat2 / 5.3 for the resolve flags); if openat2 is unavailable the
/// no-follow `remove_dir_all` + the canonicalized parent check are the fallback confinement.
fn scratch_path_is_confined(dir: &std::path::Path) -> bool {
    const SYS_OPENAT2: libc::c_long = 437;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let root = scratch_dir();
    let Ok(root_c) = std::ffi::CString::new(root.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    let root_fd = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return false;
    }
    // The path RELATIVE to the scratch root (RESOLVE_BENEATH interprets it from root_fd).
    let rel = dir.strip_prefix(&root).unwrap_or(dir);
    let Ok(rel_c) = std::ffi::CString::new(rel.as_os_str().as_encoded_bytes()) else {
        unsafe { libc::close(root_fd) };
        return false;
    };
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
    };
    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            root_fd,
            rel_c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    unsafe { libc::close(root_fd) };
    if fd >= 0 {
        unsafe { libc::close(fd as libc::c_int) };
        true // confined: no symlink component, stays beneath the scratch root
    } else {
        // ENOSYS (no openat2) → fall back to the no-follow remove + canonical-parent check (still safe
        // on our MSRV); any other error (ELOOP/EXDEV = a symlink/escape component) → refuse.
        std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS)
    }
}

/// Remove `dir` from inside a user namespace mapped to the caller's full subordinate range, so files
/// owned by subordinate uids (left by a `--uid-range` / pod box whose workload dropped privilege) are
/// unlinkable (they appear owned by ns-root under the map). Forks a child that unshares a user ns and
/// blocks; the parent maps it with `newuidmap`/`newgidmap`; the child then `remove_dir_all`s as ns-root.
fn remove_dir_all_ranged(dir: &std::path::Path) {
    let (uid, gid) = (unsafe { libc::getuid() }, unsafe { libc::getgid() });
    // Resolve the range + trusted helpers via the ONE authoritative kern-isolation impl (same as the
    // box-start path), so cleanup can't drift; no allocation → give up.
    let name = kern_isolation::username(uid);
    let (Some(newuidmap), Some(newgidmap)) = (
        kern_isolation::trusted_helper("newuidmap"),
        kern_isolation::trusted_helper("newgidmap"),
    ) else {
        return;
    };
    let (Some((sub_uid, uc)), Some((sub_gid, gc))) = (
        kern_isolation::sub_range("/etc/subuid", name.as_deref(), uid),
        kern_isolation::sub_range("/etc/subgid", name.as_deref(), gid),
    ) else {
        return;
    };
    let mut c2p = [0i32; 2];
    let mut p2c = [0i32; 2];
    if unsafe { libc::pipe(c2p.as_mut_ptr()) } != 0 || unsafe { libc::pipe(p2c.as_mut_ptr()) } != 0
    {
        return;
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return;
    }
    if pid == 0 {
        unsafe {
            libc::close(c2p[0]);
            libc::close(p2c[1])
        };
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
            unsafe { libc::_exit(1) };
        }
        let _ = unsafe { libc::write(c2p[1], b"1".as_ptr().cast(), 1) };
        let mut b = [0u8; 1];
        let _ = unsafe { libc::read(p2c[0], b.as_mut_ptr().cast(), 1) };
        // ns-root over the whole range now: the subuid-owned files map to ids we own here → removable.
        let _ = std::fs::remove_dir_all(dir);
        unsafe { libc::_exit(0) };
    }
    unsafe {
        libc::close(c2p[1]);
        libc::close(p2c[0])
    };
    let mut b = [0u8; 1];
    let _ = unsafe { libc::read(c2p[0], b.as_mut_ptr().cast(), 1) };
    let map = |bin: &std::path::Path, own: u32, sub: u32, count: u32| {
        let _ = std::process::Command::new(bin)
            .args([
                pid.to_string(),
                "0".into(),
                own.to_string(),
                "1".into(),
                "1".into(),
                sub.to_string(),
                count.to_string(),
            ])
            .status();
    };
    map(&newuidmap, uid, sub_uid, uc);
    map(&newgidmap, gid, sub_gid, gc);
    let _ = unsafe { libc::write(p2c[1], b"1".as_ptr().cast(), 1) };
    let mut st = 0;
    crate::eintr::waitpid(pid, &mut st, 0);
}

/// Fork a health-checker for a detached box: every `interval` s it runs `health_cmd` (via
/// `/bin/sh -c`) inside the box and records `healthy`/`unhealthy` in the registry health sidecar
/// (shown by `kern ps`). It re-reads the box's PID 1 each round, so it follows `--restart`s.
/// Returns the checker's pid.
fn spawn_health_checker(name: String, pid: i32, hc: OwnedHealth) -> i32 {
    let child = unsafe { libc::fork() };
    if child != 0 {
        return child;
    }
    // CHILD: shed inherited fds (the detached box's readiness pipe would otherwise hang `box -d`),
    // then quiet stdio so probe output doesn't land in the box log.
    kern_isolation::shed_inherited_fds(-1);
    detach_stdio(None);
    registry::set_health(&name, pid, "starting");
    let probe = ["/bin/sh".to_string(), "-c".to_string(), hc.cmd];
    let mut elapsed = 0u64; // seconds since the checker started
    let mut fails = 0u32; // consecutive failures
    let mut acted = false; // acted on the *current* unhealthy episode (reset when healthy again)
    let mut first = true;
    loop {
        // The FIRST probe runs after a short fixed delay, NOT after a full `interval`: a dependent box
        // gated on `service_healthy` should start as soon as the dependency is actually ready, not wait
        // a whole interval for the first check. A service that boots in 50 ms was being held ~1 s just
        // because `interval: 1s` slept before the first probe - a needless bottleneck in a `depends_on:
        // condition: service_healthy` stack. Subsequent probes use the real interval.
        if first {
            unsafe { libc::usleep(100_000) }; // 100 ms - let the process exec before the first probe
            first = false;
        } else {
            unsafe { libc::sleep(hc.interval as libc::c_uint) };
            elapsed = elapsed.saturating_add(hc.interval);
        }
        // The box may have been `kern rename`d since we started: resolve its CURRENT name by pid so we
        // follow the rename instead of writing health under (and looking up) the stale original name.
        // `name_for_pid` is a readdir + filename match (no per-entry file reads), far cheaper than a
        // `list()`. Then `find(cur)` opens ONLY this box's entry - a full `list()` per interval per
        // checker would be O(N²) steady-state across N checkers.
        let cur = registry::name_for_pid(pid).unwrap_or_else(|| name.clone());
        let entry = registry::find(&cur);
        let pid1 = entry.as_ref().map(|b| b.pid1).unwrap_or(0);
        let status = if pid1 > 0 {
            // Probe under the box's RECORDED seccomp mode, read from the same entry as `pid1`, so the
            // probe's filter matches PID 1 by construction - not by the assumption that the checker's
            // environment still equals the box's creation environment.
            let mode = entry.as_ref().map(|b| b.seccomp_mode).unwrap_or_default();
            let ok = run_probe(pid1, &probe, hc.timeout, mode);
            if ok {
                fails = 0;
                acted = false;
                "healthy"
            } else {
                fails = fails.saturating_add(1);
                // During the start-period grace, a failure keeps the box "starting" (Docker
                // semantics - a slow-booting service isn't flapped to unhealthy). After it, a box is
                // "unhealthy" only once `retries` checks have failed in a row; until then hold
                // "starting" so a single blip doesn't trip an orchestrator.
                if elapsed <= hc.start_period || fails < hc.retries {
                    "starting"
                } else {
                    "unhealthy"
                }
            }
        } else {
            "starting"
        };
        registry::set_health(&cur, pid, status);
        // `--health-action`: when the box first turns unhealthy, act once (not every interval).
        if status == "unhealthy" && !acted {
            acted = true;
            match hc.action {
                HealthAction::None => {}
                // Restart: kill box PID 1 so the supervisor's on-failure policy re-runs it. Signal
                // via a pidfd taken now, so a pid recycled during a restart gap can't be the victim
                // (the registry-supplied `pid1` could be stale between the box exiting and the
                // supervisor re-registering the new one). Falls back to `kill` on kernels < 5.3.
                HealthAction::Restart => {
                    if pid1 > 0 {
                        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid1, 0) as i32 };
                        unsafe { signal_box(pidfd, pid1, libc::SIGKILL) };
                        if pidfd >= 0 {
                            unsafe { libc::close(pidfd) };
                        }
                    }
                }
                // Stop: tear the whole box down (a detached stopper that has escaped this checker's
                // process group, so the group-kill can't cut its own cleanup short), then exit - the
                // box is going away, so there's nothing left to check.
                HealthAction::Stop => {
                    spawn_detached_stop(name.clone());
                    unsafe { libc::_exit(0) };
                }
            }
        }
    }
}

/// Fork a child that has left the caller's process group (`setsid`), with inherited fds shed and
/// stdio detached - the common prologue of the detached stop/timeout helpers. Returns the child pid
/// to the parent and `None` to the child (which then runs its body and `_exit`s). Escaping the group
/// matters because these children call `stop()`, which group-kills the box; an in-group caller would
/// otherwise be cut down mid-cleanup.
fn fork_detached() -> Option<i32> {
    let child = unsafe { libc::fork() };
    if child != 0 {
        return Some(child);
    }
    unsafe { libc::setsid() };
    kern_isolation::shed_inherited_fds(-1);
    detach_stdio(None);
    None
}

fn spawn_detached_stop(name: String) {
    if fork_detached().is_some() {
        return;
    }
    let _ = stop(std::slice::from_ref(&name), false);
    unsafe { libc::_exit(0) };
}

/// Fork a watchdog for a **foreground** `--timeout N`, returning `(watchdog_pid, write_fd)`. The
/// watchdog is created in the caller's (host) pid namespace - it MUST be forked before the box's
/// `unshare(CLONE_NEWPID)`, so it is an *ancestor* of the box and can therefore signal the box's
/// ns-init (a same-namespace member cannot). It blocks reading the box's PID 1 from the returned
/// pipe (written by `on_started`); once it has it, it waits for that box to EXIT with `secs` as a
/// cap, and only if the cap is reached does it SIGTERM and - after a 2 s grace - SIGKILL the box's
/// PID 1, tearing down the whole namespace. If the pipe closes before a pid arrives (the box never
/// started and the caller cancels), the read returns 0 and the watchdog just exits.
///
/// Waiting for the exit rather than sleeping the deadline out is what stops this process outliving
/// the box it guards: see `wait_for_box_exit`.
/// Returns `None` if the pipe/fork failed (the box simply runs without a timeout).
fn spawn_foreground_timeout(secs: u64) -> Option<(i32, i32)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    let (rd, wr) = (fds[0], fds[1]);
    let child = unsafe { libc::fork() };
    if child < 0 {
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        return None;
    }
    if child > 0 {
        // Parent keeps the write end. Mark it close-on-exec so the box's exec'd command doesn't
        // inherit a live host pipe fd (the parent's own `on_started` write is unaffected - CLOEXEC
        // only fires on exec).
        unsafe {
            libc::close(rd);
            libc::fcntl(wr, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        return Some((child, wr));
    }
    // CHILD (host-ns watchdog): escape our parent's group/session, drop the write end, quiet stdio.
    unsafe {
        libc::setsid();
        libc::close(wr);
    }
    kern_isolation::shed_inherited_fds(rd);
    detach_stdio(None);
    let mut buf = [0u8; 4];
    let mut got = 0usize;
    while got < buf.len() {
        let n = unsafe { libc::read(rd, buf[got..].as_mut_ptr().cast(), buf.len() - got) };
        if n <= 0 {
            unsafe { libc::_exit(0) }; // pipe closed before a pid arrived - box already gone
        }
        got += n as usize;
    }
    let pid1 = i32::from_ne_bytes(buf);
    // Pin the target with a pidfd taken NOW, while the box is still alive: a pidfd refers to that
    // exact process for its whole life, so the delayed signals below can never land on a reused pid
    // (if the box exits during the sleep, the signal just fails with ESRCH). Fall back to plain
    // `kill(pid1)` only on a kernel too old for pidfd (< 5.3) - the target boards are 5.15+.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid1, 0) as i32 };
    unsafe {
        // WAIT FOR THE BOX TO EXIT, with `secs` as a CAP - do not sleep `secs` out. A pidfd becomes
        // readable the instant the process it pins terminates, so the common case (the box finishes
        // early) wakes us at once and we exit with nothing to enforce.
        //
        // This used to be a bare `sleep(secs)`, and `cancel_foreground_timeout` was the only thing
        // that stopped it: the supervisor closes our pipe, SIGKILLs us and reaps us when the box
        // exits normally. That covers a normal exit and NOTHING else. `kern stop` kills the
        // supervisor, so the supervisor never runs its own cleanup, and this watchdog was left
        // sleeping out the remainder of the deadline: 884 KB and a pid, for 24 h with the SDK's
        // 86405 s default. Measured: `kern box difftest --timeout 300` then `kern stop difftest`
        // reported success and left this process behind for the remaining 298 seconds, and running
        // the two SDK teardown tests repeatedly accumulated 14 of them.
        //
        // Waiting on the pidfd fixes every one of those paths at once, because it keys on the fact
        // that actually matters (the box is gone) instead of on the supervisor's cooperation.
        //
        // Note it deliberately does NOT key on our pipe reaching EOF. The supervisor dying is not
        // the same event as the box dying: SIGKILL the supervisor and the box's pid 1 is orphaned
        // but keeps running, and enforcing the deadline on exactly that box is this watchdog's
        // reason to exist. The pidfd stays readable-on-exit whoever dies first, so the safety net
        // is kept while the leak goes away.
        if wait_for_box_exit(pidfd, secs.saturating_mul(1000)) {
            libc::_exit(0); // the box is already gone: nothing to signal, nothing to leave behind
        }
        signal_box(pidfd, pid1, libc::SIGTERM);
        // Same again for the grace period: a box that dies on the SIGTERM must not hold us here for
        // the full 2 s, and one that ignores it gets exactly the 2 s it used to get.
        wait_for_box_exit(pidfd, 2000);
        signal_box(pidfd, pid1, libc::SIGKILL);
        libc::_exit(0);
    }
}

/// CLOCK_MONOTONIC in milliseconds, or `None` if the clock cannot be read.
///
/// SAFETY: async-signal-safe (`clock_gettime` is on the POSIX list), so it is callable from the
/// post-fork watchdog child, which must not touch the allocator or any libc lock.
unsafe fn monotonic_ms() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
        return None;
    }
    Some((ts.tv_sec as u64).saturating_mul(1000) + (ts.tv_nsec as u64) / 1_000_000)
}

/// Block until the process pinned by `pidfd` exits, or until `ms` milliseconds have passed.
/// Returns true **only** when it was observed to exit.
///
/// Every failure mode degrades to "sleep the deadline out and report no exit", which is precisely
/// the behaviour this replaces, so the caller's SIGTERM/SIGKILL can never fire EARLY on a live box:
///
///   * no pidfd at all (kernel < 5.3, or `pidfd_open` refused) -> sleep, exactly as before;
///   * the clock cannot be read -> sleep, rather than loop on an unbounded deadline;
///   * `POLLERR`/`POLLNVAL` (an fd we cannot wait on) -> sleep out what is left of the deadline;
///   * `EINTR` -> retry, bounded by the absolute deadline, so a signal cannot shorten it.
///
/// SAFETY: async-signal-safe - `poll`, `clock_gettime` and `sleep` only, no allocation.
unsafe fn wait_for_box_exit(pidfd: i32, ms: u64) -> bool {
    // `sleep` takes whole seconds: round UP, so a sub-second deadline is never truncated to zero.
    let sleep_out = |left: u64| {
        if left > 0 {
            libc::sleep(left.div_ceil(1000) as libc::c_uint);
        }
    };
    if pidfd < 0 {
        sleep_out(ms);
        return false;
    }
    let Some(start) = monotonic_ms() else {
        sleep_out(ms);
        return false;
    };
    let deadline = start.saturating_add(ms);
    let mut pfd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let Some(now) = monotonic_ms() else {
            sleep_out(ms);
            return false;
        };
        if now >= deadline {
            return false;
        }
        let left = deadline - now;
        // poll(2) takes an `int` of milliseconds. A deadline past ~24.8 days would overflow it, so
        // it is waited out in chunks rather than clamped to -1, which would mean "forever" and would
        // silently disarm the timeout.
        let chunk = if left > i32::MAX as u64 {
            i32::MAX
        } else {
            left as i32
        };
        pfd.revents = 0;
        let r = libc::poll(&mut pfd, 1, chunk);
        if r > 0 {
            if pfd.revents & libc::POLLIN != 0 {
                return true; // the pidfd fired: the box has terminated
            }
            // An fd we cannot wait on. Serve out the rest of the deadline the old way instead of
            // returning false immediately, which would SIGTERM a box that still has time left.
            let rest = monotonic_ms().map_or(0, |n| deadline.saturating_sub(n));
            sleep_out(rest);
            return false;
        }
        // r == 0: this chunk expired, the loop re-checks the deadline.
        // r < 0: EINTR or another error; the deadline check at the top bounds the retry.
    }
}

/// Send `sig` to the box's PID 1: via its `pidfd` when we have one (reuse-proof), else plain `kill`.
/// SAFETY: async-signal-safe - only raw syscalls, called from the post-fork watchdog child.
unsafe fn signal_box(pidfd: i32, pid1: i32, sig: i32) {
    if pidfd >= 0 {
        libc::syscall(libc::SYS_pidfd_send_signal, pidfd, sig, 0, 0);
    } else {
        libc::kill(pid1, sig);
    }
}

/// Tear a box down for `kern stop`: SIGKILL its **PID-namespace init** (`pid1`) directly, then sweep
/// the supervisor's process group. Returns whether the box was **confirmed** gone.
///
/// The kernel destroys the *entire* pid namespace the instant its PID 1 dies, so no workload - not
/// even a `while True: pass` that ignores SIGTERM - can survive, and `setsid` can't dodge it (it moves
/// the session/process group, not the pid namespace). Signalling `pid1` is also what makes this reach
/// a **foreground** box: its init is not in the caller's process group, so the historical `kill(-pid)`
/// alone missed it (there's no group whose id is a non-leader supervisor's pid → a harmless ESRCH).
/// We keep the group sweep too: for a **detached** box (supervisor `setsid`-ed, pgid == pid) it reaps
/// the supervisor and any stray helpers exactly as before, and it's the only reachable target for an
/// old registry entry that never recorded `pid1`.
///
/// The pidfd is taken while the box is still alive, so both the signal and the exit-confirmation are
/// reuse-proof: a `pidfd` polls readable precisely when its process terminates (even before it's
/// reaped), which side-steps the zombie window a bare `kill(pid, 0)` probe would trip on.
/// Docker's shutdown contract: send `stop_signal` first, give the workload
/// `grace_ms` to exit on its own, then SIGKILL whatever is left.
///
/// MILLISECONDS, not seconds. What reaches here is the time LEFT until a deadline shared by the
/// whole stack, and rounding that down to a whole second threw away up to 999 ms of a grace the
/// caller asked for: MEASURED, `--stop-timeout 3` gave a 2.5 s flush only 2019 ms and SIGKILLed it
/// (Docker's `stop -t 3` let the same workload finish in 2799 ms and exit 5).
///
/// This is not politeness. A hard SIGKILL means redis loses everything since its last save and
/// postgres does crash recovery on the NEXT start, on every single `stop`. The graceful phase is what
/// lets a stateful service flush and close. `grace_ms == 0` keeps the old behaviour (straight to
/// SIGKILL) for callers that want the box gone now.
///
/// The wait is a bounded poll on the pidfd, so a workload that exits immediately costs one syscall,
/// not the whole grace. A workload that IGNORES the signal costs exactly `grace_ms` and then dies:
/// the kernel tears down the pid namespace with its PID 1, so nothing survives the SIGKILL.
/// Can `sig` actually terminate this box's init, or would the grace period be a guaranteed wait for
/// nothing?
///
/// A PID-namespace init is special: the kernel DISCARDS any signal it has no handler for, so the
/// default "terminate" action does not apply to it. A box whose command is an ordinary program that
/// installs no handler (`sleep`, and most binaries) therefore cannot be stopped by SIGTERM at all,
/// and the graceful phase becomes a full wait for an event that can never happen.
///
/// MEASURED: `kern stop` on a `sleep` box took 9013 ms, against 2 ms before the graceful phase
/// existed, because it always waited the whole 10 s and only then sent SIGKILL. A box whose init
/// DOES trap the signal (a shell with `trap`, or any real service) is unaffected and still gets its
/// full grace.
///
/// `SigCgt` in `/proc/<pid>/status` is the caught-signal mask, one bit per signal, signal `n` at bit
/// `n-1`. Unreadable, unparsable, or absent means we do NOT know: assume it IS caught, so an unknown
/// stays on the patient path rather than being killed early. Guessing wrong in that direction costs
/// a wait; guessing wrong the other way would cut a real shutdown short.
fn init_catches_signal(pid1: i32, sig: i32) -> bool {
    if pid1 <= 0 || !(1..=64).contains(&sig) {
        return true;
    }
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid1}/status")) else {
        return true;
    };
    let Some(mask) = status
        .lines()
        .find_map(|l| l.strip_prefix("SigCgt:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
    else {
        return true;
    };
    mask & (1u64 << (sig - 1)) != 0
}

/// The `/proc/<pid>/stat` line, or `None` if the process is gone (or was never a pid).
fn proc_stat(pid: i32) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()
}

/// A pid's single-letter run state (`R`, `S`, `T`, `Z`, ...), or `None` if it is gone.
fn proc_state(pid: i32) -> Option<char> {
    let stat = proc_stat(pid)?;
    registry::stat_field(&stat, 3)?.chars().next()
}

/// A pid's parent, or `None` when it cannot be read (already reaped, or a process we may not look
/// at).
fn parent_of(pid: i32) -> Option<i32> {
    let stat = proc_stat(pid)?;
    registry::stat_field(&stat, 4)?.parse().ok()
}

/// The exit status of a **zombie we are not the parent of**, decoded the way `waitpid(2)` reports it.
///
/// `stop` needs the box init's real exit code and cannot `wait4` for it: that init's parent is the
/// supervisor, not us. Field 52 of `/proc/<pid>/stat` (`exit_code`, since Linux 3.5) carries exactly
/// the status `waitpid` would return, and it is populated for the whole zombie window - between the
/// init's death and the supervisor reaping it.
///
/// The window is NARROW and it is a real race: the init's parent is woken by the same event our
/// pidfd poll waits on, and reading this unguarded was right in 15 runs out of 20. `ReaperHold` is
/// what makes the window ours; this function only reads what is there.
///
/// Anything unexpected - not a zombie yet, unreadable, a status that is neither an exit nor a
/// signal - returns `None`, so the caller falls back instead of recording a guess.
fn zombie_exit_code(pid: i32) -> Option<i32> {
    let stat = proc_stat(pid)?;
    if registry::stat_field(&stat, 3) != Some("Z") {
        return None;
    }
    let status: i32 = registry::stat_field(&stat, 52)?.parse().ok()?;
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Some(128 + libc::WTERMSIG(status))
    } else {
        None
    }
}

/// Hold the box init's REAPER still, so the init's exit status survives long enough to be read.
///
/// MEASURED: without this, `kern stop` on a workload that traps the signal and exits 7 recorded the
/// real code in 15 runs out of 20 and fell back to 137 in the other 5. The init's parent is woken by
/// the very event our pidfd poll waits on, and when it reaps first the status is gone from /proc
/// before we can read it. A 75%-correct exit code is a worse contract than a consistently wrong one,
/// so the race is removed rather than won: SIGSTOP cannot be caught, and a stopped parent cannot
/// `wait4`.
///
/// TAKE IT BEFORE SIGNALLING. `stop` signals the box's process GROUP, which the runner is in, and a
/// dead runner is not a reaper we can hold - the init reparents to the user's systemd, which reaps
/// it at once. Held first, the runner takes that signal as PENDING (SIGSTOP wins) and dies from it
/// the moment we let go, so the end state is the same as if it had never been held.
///
/// The init itself is never stopped - it is a different process - so its shutdown handler runs
/// normally and the grace means what it says.
///
/// ONLY the box's RUNNER is ever held - the intermediate the supervisor forks, which no shell has a
/// job for. Two other things can be an init's parent and neither may be touched. The user's systemd
/// manager inherits an orphaned init, and trusting `PPid` blindly would SIGSTOP the process manager
/// of the whole session. A FOREGROUND box's parent is the user's own `kern box` process: stopping it
/// would print `Stopped` in their terminal for the length of the grace, and a `stop` interrupted mid
/// hold would leave that box frozen and looking alive - a worse outcome than the exit code this
/// buys, and a foreground box reports its code directly to its caller anyway. Both cases fall back
/// to the unguarded read.
///
/// The release is a `Drop`, which a SIGKILL of `kern stop` itself skips, so the caller takes this
/// hold only for a box whose dedicated cgroup makes that survivable - see the call site. VERIFIED in
/// both directions: with a cgroup, `kern stop` killed mid-grace leaves the box ORPHANED in `kern ps`
/// and the next `kern stop` reaps it whole ("reaped via cgroup.kill", no stopped process and no
/// stray left); with no cgroup and no hold, the runner dies with the group and the init reparents
/// and reaps itself, which is the behaviour that existed before this type and is left intact.
struct ReaperHold(Option<i32>);

impl ReaperHold {
    /// Hold this box's reaper, or hold nothing when it is not ours to hold.
    ///
    /// Returning before the target is ACTUALLY stopped would lose the race it exists to remove:
    /// `kill` only queues the signal, and the group SIGTERM that follows is number 15 against
    /// SIGSTOP's 19 - the kernel delivers the lower-numbered one first, so a reaper still running
    /// with both pending dies instead of stopping. MEASURED at 25 correct out of 30 without this
    /// wait, and 30 out of 30 with it. The wait is a few tens of microseconds (the target is blocked
    /// in `wait4`, so it stops as soon as it is scheduled) and bounded, because a hold that never
    /// lands must not turn a stop into a hang.
    fn new(supervisor: i32, pid1: i32) -> Self {
        let Some(reaper) = parent_of(pid1) else {
            return Self(None);
        };
        if reaper <= 1 || parent_of(reaper) != Some(supervisor) {
            return Self(None);
        }
        if unsafe { libc::kill(reaper, libc::SIGSTOP) } != 0 {
            return Self(None);
        }
        let held = Self(Some(reaper));
        for _ in 0..200 {
            match proc_state(reaper) {
                Some('T') => break,
                // Gone while we waited: nothing to hold, and nothing to release.
                None => return Self(None),
                _ => {
                    unsafe { libc::usleep(50) };
                }
            }
        }
        // Re-check the relationship now that the target cannot run: between reading `PPid` and the
        // signal landing, that pid could have died and been reused by an unrelated process of this
        // user, and the check above would have cleared a process we then stopped. It is a narrow
        // window and the damage would be small (a stop-and-continue), but it is closed for free -
        // a reused pid is no longer the init's parent, and dropping `held` here resumes it at once.
        if parent_of(pid1) != Some(reaper) {
            return Self(None);
        }
        held
    }
}

impl Drop for ReaperHold {
    /// Let it go, on every path. It resumes into whatever arrived while it was stopped - `stop`
    /// signals the box's process group, which it is in - so it finishes exactly as it would have
    /// without the hold. A reaper left stopped would never tear its cgroup, forwarders and scratch
    /// dir down, so this is a `Drop` and not a call at the end of the happy path.
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            unsafe { libc::kill(pid, libc::SIGCONT) };
        }
    }
}

/// What a teardown did, and the box's real exit code when it could be observed.
///
/// `stop` is the box's LAST owner: its group signal kills the supervisor, which therefore never
/// reaches the `set_box_exit` it writes on a normal exit. Whatever this carries is the only exit code
/// the box will ever have. A flat `bool` here is what made every clean `kern stop` record `exit 137`:
/// the constant was written when the teardown was ALWAYS a SIGKILL, and it did not follow the
/// graceful phase in.
///
/// The distinction is deliberately NOT "which branch ran" but "what did we read". A box can reach
/// any branch already dead - `stop` signals the group before it gets here - so branch identity is a
/// bad witness, while the unreaped status is the fact itself: it reads 137 exactly when the init
/// really was SIGKILLed, and 7 when the workload trapped the signal and exited 7.
enum Teardown {
    /// The box is gone. `Some(code)` is the init's real status, read from its unreaped zombie;
    /// `None` means we tore it down without ever observing one.
    Gone(Option<i32>),
    /// The signal went out, the box was not confirmed gone in time.
    Unconfirmed,
}

impl Teardown {
    /// Whether the box is confirmed gone.
    fn confirmed(&self) -> bool {
        matches!(self, Teardown::Gone(_))
    }

    /// The code to record for `kern wait` / `kern ps -a`. A teardown whose status we could not read
    /// falls back to 137, the historical value, rather than inventing a `0` nobody measured.
    fn exit_code(&self) -> i32 {
        match self {
            Teardown::Gone(Some(code)) => *code,
            _ => 137,
        }
    }
}

/// How long `stop` may still wait on THIS box: its own `--stop-timeout`, minus the time already
/// spent since the signal went out, in MILLISECONDS.
///
/// Every box is signalled in phase 1, so a box's grace runs from THERE, not from the moment the
/// teardown loop reaches it. That is what keeps a stack converging - an N-service stop costs
/// max(grace), never the sum - and it is also why the remainder must be measured per box rather than
/// against one deadline shared by the stack: a shared `max(grace)` hands every member the LONGEST
/// grace configured anywhere in the file. MEASURED on a two-service stack, one asking 4 s and one
/// asking 1 s, both hanging in their handler: the 1 s service was killed at 5154 ms. Its own
/// `stop_grace_period` is an upper bound, and it was exceeded five times over. With this it is
/// killed as soon as its own second is spent, and the stack still finishes in max(grace).
///
/// Milliseconds, not seconds: rounding the remainder down to a whole second silently spent up to
/// 999 ms of a grace the caller asked for (`--stop-timeout 3` gave a 2.5 s flush only 2019 ms and
/// SIGKILLed it mid-write, where Docker's `stop -t 3` let it finish in 2799 ms and exit 5).
///
/// A box configured with no grace at all gets zero, which is the straight-to-SIGKILL path.
///
/// The bound this gives is one-sided, and deliberately so: a member is never SIGKILLed BEFORE its own
/// grace, and can be killed later than it if a longer-grace member is torn down first, because the
/// loop is sequential. Killing it exactly on its own second regardless of order would need concurrent
/// waits; the stack total is max(grace) either way, and erring late costs a wait where erring early
/// would cut a real shutdown short.
fn remaining_grace_ms(own_grace_secs: u64, since_signal: std::time::Duration) -> u64 {
    let own = own_grace_secs.saturating_mul(1000);
    let spent = u64::try_from(since_signal.as_millis()).unwrap_or(u64::MAX);
    own.saturating_sub(spent)
}

fn kill_box_graceful(pid: i32, pid1: i32, stop_signal: i32, grace_ms: u64) -> Teardown {
    // The init may ALREADY be gone: `stop` signals the supervisor's process group before it reaches
    // here, and a box init that sits in that group takes that signal too, so it can be an unreaped
    // zombie on arrival. Read its status now, while /proc still has it. Without this the graceful
    // phase is skipped for a reason that looks right and is not: a zombie's `SigCgt` is cleared, so
    // `init_catches_signal` reports "cannot catch it" for a workload that caught it and exited 7.
    let already = zombie_exit_code(pid1);
    let pidfd = if pid1 > 0 {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid1, 0) as i32 };
        // Skip the graceful phase entirely when the init provably cannot receive the signal: see
        // `init_catches_signal`. This is the difference between `kern stop` returning in 2 ms and in
        // 9 s for the most ordinary box there is. Already dead is the same case: nothing to wait for.
        let graceful = grace_ms > 0 && already.is_none() && init_catches_signal(pid1, stop_signal);
        if graceful {
            // Graceful phase: the configured signal to the box init, and to the supervisor's group so
            // a foreground box's helpers hear it too.
            unsafe { signal_box(fd, pid1, stop_signal) };
            if pid > 1 {
                unsafe { libc::kill(-pid, stop_signal) };
            }
            if fd >= 0 {
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // Exited within the grace: nothing left to kill, and we say so without the SIGKILL.
                let ms = grace_ms.min(i32::MAX as u64) as i32;
                if crate::eintr::poll(std::slice::from_mut(&mut pfd), ms) > 0 {
                    unsafe { libc::close(fd) };
                    // Read the status HERE, first thing, while the reaper is still held: once it is
                    // released and reaps, the box's real exit code is gone for good.
                    return Teardown::Gone(zombie_exit_code(pid1));
                }
            }
        }
        unsafe { signal_box(fd, pid1, libc::SIGKILL) };
        fd
    } else {
        if grace_ms > 0 && pid > 1 {
            unsafe { libc::kill(-pid, stop_signal) };
            std::thread::sleep(std::time::Duration::from_millis(grace_ms.min(60_000)));
        }
        -1
    };
    // Never let a corrupt/degenerate `pid <= 1` turn the group sweep into `kill(-1)` (SIGKILL every
    // process the user owns) or `kill(0)` (our own group): it's only meaningful for a real supervisor.
    if pid > 1 {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    if pidfd >= 0 {
        // Wait (bounded) for the init to actually exit - POLLIN fires on termination.
        let mut pfd = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = crate::eintr::poll(std::slice::from_mut(&mut pfd), 1000);
        unsafe { libc::close(pidfd) };
        if ready > 0 {
            // Read it again now that it is definitely dead: our SIGKILL leaves a status of 137, and
            // an init that had already exited on its own leaves the code it chose. `already` wins -
            // it was read before we signalled, so it cannot be our own SIGKILL overwriting a real
            // exit code (a zombie's status is fixed, but the pre-signal read needs no reasoning).
            Teardown::Gone(already.or_else(|| zombie_exit_code(pid1)))
        } else {
            Teardown::Unconfirmed
        }
    } else {
        // No pidfd (pid1 unrecorded, or a kernel < 5.3): best-effort probe on the recorded pids. The
        // signal still went out via `signal_box`/the group sweep; we just can't confirm as precisely.
        let probe = if pid1 > 0 { pid1 } else { pid };
        for _ in 0..100 {
            if unsafe { libc::kill(probe, 0) } != 0 {
                return Teardown::Gone(already); // ESRCH - the target is gone
            }
            unsafe { libc::usleep(10_000) };
        }
        Teardown::Unconfirmed
    }
}

/// Hand the box's PID 1 to a foreground `--timeout` watchdog over its pipe (from `on_started`, in the
/// host-ns parent). No-op when no timeout is armed.
fn feed_timeout_pid(wd: Option<(i32, i32)>, pid1: i32) {
    if let Some((_, wfd)) = wd {
        let p = pid1.to_ne_bytes();
        unsafe { libc::write(wfd, p.as_ptr().cast(), p.len()) };
    }
}

/// Cancel a foreground `--timeout` watchdog once the box has exited: close our pipe end (so a
/// still-blocked watchdog reads EOF and gives up), then SIGKILL and reap it. Reaping before we return
/// means the watchdog's pid can't be reused, and closing/killing a still-sleeping one stops it before
/// it can signal. No-op when no timeout is armed.
fn cancel_foreground_timeout(wd: Option<(i32, i32)>) {
    if let Some((wd_pid, wfd)) = wd {
        unsafe {
            libc::close(wfd);
            libc::kill(wd_pid, libc::SIGKILL);
            crate::eintr::reap(wd_pid);
        }
    }
}

/// Fork a watchdog for a **detached** `--timeout N`: after N seconds it stops the box by name (the
/// same teardown as `kern stop`, so the registry/scratch are cleaned up and a `--restart` policy
/// can't resurrect it). It first checks the box is still the same instance (name + supervisor pid),
/// so a box that already exited on its own isn't "stopped" a second time. Returns its pid so the
/// supervisor can cancel it once the box exits normally.
fn spawn_timeout_stop(name: String, sup_pid: i32, secs: u64) -> i32 {
    if let Some(child) = fork_detached() {
        return child;
    }
    // Wait for the SUPERVISOR to exit, with `secs` as a cap, rather than sleeping `secs` out.
    //
    // This is the detached twin of the foreground watchdog above, and it kept the bare `sleep` that
    // one shed: `kern box x -d --timeout N` followed by `kern stop x` left this process asleep for
    // the remainder of N, reparented to init, 884 KB and a pid per stopped box. Measured on this
    // tree before the change: `--timeout 20`, stop after one second, and the process was still
    // there at t=15 s and gone at t=20, exactly the deadline. `strace` showed it going straight
    // from `setsid` to `clock_nanosleep(25s)`, with no `pidfd_open` anywhere.
    //
    // Keying on the supervisor loses nothing here, unlike in the foreground watchdog, and the guard
    // below is why: this one only ever acts `if registry::pair_alive(&name, sup_pid)`, so a dead
    // supervisor already meant "do nothing". Waiting on its exit reaches that same decision without
    // holding a process for the deadline. The pidfd also pins that exact supervisor, so a pid
    // recycled during the wait cannot make the pair-probe match a different box.
    //
    // The pidfd is opened AFTER `fork_detached`, never before: that helper runs `close_range(3, ..)`
    // in the child, which would close an fd taken by the parent.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, sup_pid, 0) as i32 };
    let supervisor_gone = unsafe { wait_for_box_exit(pidfd, secs.saturating_mul(1000)) };
    if pidfd >= 0 {
        unsafe { libc::close(pidfd) };
    }
    if supervisor_gone {
        unsafe { libc::_exit(0) }; // nothing left to stop, and the pair-probe would say so too
    }
    // Exact (name,pid)-PAIR probe: a by-name `find` would test the pid against whichever same-name
    // entry readdir yields first - a duplicate entry (fail-open unclaimed start / pre-claim kern)
    // could shadow the tracked box and the timeout would silently never fire.
    if registry::pair_alive(&name, sup_pid) {
        let _ = stop(std::slice::from_ref(&name), false);
    }
    unsafe { libc::_exit(0) };
}

/// Run one health probe inside the box and report whether it succeeded (exit 0). Forks a child that
/// `exec_in_box`es the probe (so the checker itself stays on the host); `timeout` > 0 is enforced
/// inside `exec_in_box`, which SIGKILLs the whole in-box probe group on expiry (→ non-zero) so a hung
/// check neither stalls the checker nor leaks a live process into the box each interval.
fn run_probe(
    pid1: i32,
    probe: &[String],
    timeout: u64,
    seccomp_mode: kern_isolation::SeccompFilter,
) -> bool {
    let to = (timeout > 0).then_some(timeout);
    let probe_pid = unsafe { libc::fork() };
    if probe_pid == 0 {
        // A health probe never warns about the scope-path cap gap (it runs every interval). It keeps
        // the dangerous BASELINE drop (`CapSpec::default()`), unchanged from before this parameter
        // existed: a probe is not `kern exec`, and matching it to a box's `--cap-drop ALL` could break
        // a check that needs a baseline cap. Reapplying the box's own spec to the probe is a separate,
        // separately-validated follow-up; this increment fixes the `kern exec` contract only.
        //
        // The seccomp mode is the box's RECORDED mode (read from its registry entry by the caller), so
        // the probe installs the SAME filter as PID 1 by construction - not by assuming the checker's
        // environment still equals the box's creation environment.
        let code = exec_in_box(
            pid1,
            probe,
            &[],
            None,
            None,
            None,
            to,
            false,
            &kern_isolation::CapSpec::default(),
            seccomp_mode,
            // A health probe is kern's OWN command (the `--health-cmd`), run to decide liveness, not
            // the workload proper: keep it at the baseline (no box AppArmor), consistent with its
            // baseline caps above, so a confining profile can't wedge the very check kern uses to
            // decide health. Caveat, stated plainly: the probe target is a binary in the box's
            // workload-writable rootfs, so a workload that overwrites it gets one AppArmor-unconfined
            // (still seccomp- and namespace-confined) run per interval. A deliberate, documented
            // tradeoff, the same one taken for the probe's baseline caps; applying the profile here is
            // the separately-tracked follow-up.
            None,
        )
        .unwrap_or(1);
        unsafe { libc::_exit(code) };
    }
    if probe_pid <= 0 {
        return false;
    }
    let mut st = 0i32;
    if crate::eintr::waitpid(probe_pid, &mut st, 0) <= 0 {
        return false;
    }
    libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
}

/// Human-readable summary of `-p` mappings for `kern ps`, always showing the bind address so the
/// exposure is visible at a glance (e.g. `127.0.0.1:8080->80, 0.0.0.0:443->443`).
/// Comma-joined **named volumes** a box mounts (from its `-v name:/dst` specs) - recorded in the
/// registry so `kern volume rm` can refuse to delete a volume still in use. Host paths and network
/// URLs are skipped (only named volumes matter here).
fn mounted_named_volumes(specs: &[String]) -> String {
    let mut names: Vec<String> = specs
        .iter()
        .filter(|s| !crate::volume::is_network(s))
        .filter_map(|s| {
            let src = s.split(':').next().unwrap_or("");
            crate::volume::is_named(src).then(|| src.to_string())
        })
        .collect();
    names.sort();
    names.dedup();
    names.join(",")
}

fn ports_summary(ports: &[kern_isolation::PortMap]) -> String {
    ports
        .iter()
        .map(crate::ports::fmt)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Read the last `max` bytes of `path`, trimmed, or `None` if the file is missing/empty. Used to
/// surface a failed detached box's reason inline (the box logged it to its own stderr sink). Reads
/// the whole file - a box that "exited before starting" has only a few lines - and keeps the tail
/// lossily so non-UTF-8 output can't hide the reason.
fn read_log_tail(path: &std::path::Path, max: usize) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let start = data.len().saturating_sub(max);
    let tail = String::from_utf8_lossy(&data[start..]);
    let t = tail.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Read the box log's failure REASON, polling briefly for the asynchronous log pump to flush it.
/// A detached box's stdout/stderr is drained by a separate pump process, so the supervisor's
/// "kern: box failed to start: <reason>" line (printed to its pumped stderr AFTER the readiness
/// failure byte is already on the wire) can lag the byte. A single read here races the pump and
/// catches only the earlier lines - e.g. the benign "requested resource cap(s) could not be
/// enforced" notice - leaving `await_box_started` to surface a warning instead of the cause. Poll
/// up to ~1s for the supervisor's failure marker to land; fall back to whatever is there on timeout.
/// Only ever called on the (rare) start-failure path, so the bounded wait never touches a good start.
fn read_log_reason(path: &std::path::Path) -> Option<String> {
    // Bounded post-failure poll. NOT a start timeout: the box has ALREADY failed here (the launcher
    // received the readiness FAILURE byte, and that read itself has no deadline, so a slow board never
    // false-fails). This only waits for the async log pump to flush the supervisor's failure REASON
    // into the file. 3 s is generous even for a slow board's pump; on timeout we return whatever is
    // present, so the worst case is a less-detailed message, never a wrong verdict.
    for _ in 0..150 {
        let tail = read_log_tail(path, 1024);
        if tail
            .as_deref()
            .is_some_and(|t| t.contains("box failed to start") || t.contains("user namespaces"))
        {
            return tail;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    read_log_tail(path, 1024)
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
    println!(
        "{}{} started{} {}'{n}'{} {}[pid {child}, detached]{}",
        p.g, gl.ok, p.z, p.b, p.z, p.d, p.z
    );
    println!(
        "  {}next: kern ps {} kern logs {n} {} kern stop {n}{}",
        p.d, gl.dot, gl.dot, p.z
    );
    Ok(())
}

/// The on-failure restart contract for one box: whether to retry at all, and how many times.
/// Grouped so the supervisor keeps a readable signature as the contract grows.
#[derive(Debug, Clone, Copy)]
struct Restart {
    /// `--restart` (on-failure). `false` = run once, never retry.
    on_failure: bool,
    /// Docker `always`/`unless-stopped` on a POD MEMBER: restart on ANY exit (including 0), uncapped,
    /// via THIS in-process supervisor (it dies with the stack). A STANDALONE always/unless-stopped box
    /// takes the systemd path instead; a pod member cannot, as it needs the pod holder's namespace.
    always: bool,
    /// `--restart-max` / compose `on-failure:N`. 0 = kern's built-in cap. Not applied when `always`.
    max: u32,
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
            let code = match run_in_sandbox_with(
                spec,
                ready,
                |pid1| {
                    inst.pid1 = pid1;
                    // Record the box's DEDICATED cgroup PATH and its `(dev, ino)` IDENTITY now that PID 1
                    // exists: `list()` uses them to recognise an ORPHANED box (this supervisor
                    // SIGKILL'd/OOM'd, PID 1 + `-p` forwarder still alive and holding the port) instead
                    // of dropping it, AND to make the reap identity-safe - the path's `<pid>` leaf
                    // recycles, so only the recorded inode tells a reap it is killing THIS box and not a
                    // later one that took the path. `("", None)` (a scope/ambient box with no
                    // `kern-box-*` leaf) leaves liveness on the supervisor pid, as before. Re-resolved on
                    // every `--restart` re-register, so it never goes stale.
                    (inst.cgroup, inst.cgroup_id) = registry::box_cgroup_record(pid1);
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

/// What to do when a box's health check turns it "unhealthy" (`--health-action`).
#[derive(Clone, Copy, PartialEq)]
enum HealthAction {
    /// Record the status only (Docker's default) - an orchestrator decides what to do.
    None,
    /// Kill the box so the supervisor restarts it (implies the on-failure restart policy).
    Restart,
    /// Stop the box entirely (no restart).
    Stop,
}

/// Parse `--health-action <restart|stop|none>` (default `none`).
fn parse_health_action(s: Option<&str>) -> Result<HealthAction, Error> {
    match s {
        None | Some("none") => Ok(HealthAction::None),
        Some("restart") => Ok(HealthAction::Restart),
        Some("stop") => Ok(HealthAction::Stop),
        Some(o) => Err(Error::Sandbox(format!(
            "invalid --health-action '{o}' (expected restart, stop or none)"
        ))),
    }
}

/// The health-check policy for a detached box (`--health-*`).
struct HealthConfig<'a> {
    cmd: Option<&'a str>,
    interval: u64,
    retries: u32,
    start_period: u64,
    timeout: u64,
    action: HealthAction,
}

/// Owned health policy handed to the forked checker (it outlives `box_run`'s borrowed args).
struct OwnedHealth {
    cmd: String,
    interval: u64,
    retries: u32,
    start_period: u64,
    timeout: u64,
    action: HealthAction,
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
    detach_stdio(log.as_deref());
    let (cap_drop_all, cap_drops, cap_adds) = registry::cap_fields(&spec.caps);
    let mut inst = registry::Instance {
        name: name.as_str().to_string(),
        pid,
        pid1: 0,
        rootfs: spec.root.clone(),
        command: spec.command.join(" "),
        started: registry::now_unix(),
        starttime: registry::proc_starttime(pid),
        ports: ports_summary(ports),
        volumes: volumes.to_string(),
        pod: pod.to_string(),
        workdir: spec.workdir.clone().unwrap_or_default(),
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
    crate::runstats::record_box(); // count this box start for kern top's box-start rate
                                   // `--health-cmd`: a sidecar process that periodically probes the box and records its health for
                                   // `kern ps`. Lives in this supervisor's process group, so it's reaped on stop with everything else.
    let health_pid = health.cmd.map(|hc| {
        spawn_health_checker(
            name.as_str().to_string(),
            pid,
            OwnedHealth {
                cmd: hc.to_string(),
                interval: health.interval,
                retries: health.retries,
                start_period: health.start_period,
                timeout: health.timeout,
                action: health.action,
            },
        )
    });
    // `--timeout N`: a watchdog that auto-stops the box N seconds after it starts (registry/scratch
    // cleaned up like `kern stop`). Cancelled below if the box exits on its own first.
    let timeout_pid =
        (timeout > 0).then(|| spawn_timeout_stop(name.as_str().to_string(), pid, timeout));
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
        unsafe {
            libc::kill(tp, libc::SIGKILL);
            crate::eintr::reap(tp);
        }
    }
    if let Some(hp) = health_pid {
        unsafe {
            libc::kill(hp, libc::SIGTERM);
            crate::eintr::reap(hp);
        }
        registry::clear_health(name.as_str(), pid);
    }
    if let Some(p) = path {
        registry::unregister(&p);
    }
    cleanup_scratch(scratch.as_deref());
    unsafe { libc::_exit(0) };
}

/// The user's systemd unit directory (`$XDG_CONFIG_HOME/systemd/user`, else `~/.config/systemd/user`).
fn user_systemd_dir() -> Result<PathBuf, Error> {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME") {
        if !x.is_empty() {
            return Ok(PathBuf::from(x).join("systemd/user"));
        }
    }
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or_else(|| {
            Error::Sandbox("HOME not set - cannot locate the systemd user dir".into())
        })?;
    Ok(PathBuf::from(home).join(".config/systemd/user"))
}

/// Run `systemctl --user <args>` quietly; `true` on success. Used for the persistent-box unit.
fn systemctl_user(args: &[&str]) -> bool {
    std::process::Command::new("systemctl")
        .arg("--user")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Quote one argv element for a systemd `ExecStart=` line: wrap in double quotes and escape the
/// characters systemd would otherwise act on - `"`/`\` (C-escapes), `$` (env expansion → `$$`), and
/// `%` (specifier → `%%`). Keeps arbitrary box names/commands/paths intact when systemd re-runs us.
fn systemd_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    for c in arg.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '$' => out.push_str("$$"),
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
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

/// Memory + task ceilings for a sandbox scope. `MemorySwapMax=0` makes `MemoryMax` a HARD total
/// cap - without it, a workload over the RAM cap just swaps (on a host with swap) instead of OOM.
/// In BYTES, because the scope's ceiling is the box's cap plus `SCOPE_SUPERVISOR_HEADROOM` (kern's own
/// supervisor lives in the scope, in its own leaf, and must not eat into what the workload asked for).
const SCOPE_MEMORY_MAX_BYTES: u64 = 512 * 1024 * 1024;
const SCOPE_SWAP_MAX: &str = "MemorySwapMax=0";
const SCOPE_TASKS_MAX: &str = "TasksMax=512";

/// Where the "this host cannot enforce resource caps" notice records that it has been shown.
///
/// Persistent user data, so it survives a reboot: the host property it records does too, since it
/// comes from the kernel command line. Mirrors [`crate::volume::volumes_dir`] and
/// [`crate::builds::builds_dir`] rather than inventing a fourth location rule.
fn uncapped_notice_path() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(x).join("kern").join("uncapped-notice");
    }
    if let Some(h) = std::env::var_os("HOME") {
        return PathBuf::from(h).join(".local/share/kern/uncapped-notice");
    }
    PathBuf::from(format!("/tmp/kern-uncapped-notice-{}", unsafe {
        libc::getuid()
    }))
}

/// True the first time this host is told its resource caps are not enforceable, false afterwards.
///
/// `create_new` is `O_CREAT|O_EXCL`, so two boxes starting at the same instant race in the kernel
/// and exactly one of them prints. A `Once` alone would not do: it is per PROCESS, and every box is
/// a new process, which is precisely how this ends up on every line.
///
/// FAILURE MODES, each decided rather than left to chance:
///   * marker already there  -> `AlreadyExists` -> false. The steady state, one `openat` that fails.
///   * parent dir missing    -> created, then retried once. A first run has no `~/.local/share/kern`.
///   * cannot create at all  -> TRUE, every time. A read-only HOME with no writable `/tmp` is rare;
///     an unbounded box is worth a repeated line more than it is worth silence, so this fails loud.
///   * host later fixed      -> the marker is stale and the notice stays quiet, which is correct:
///     `memory_cap_enforceable()` is checked FIRST, so a host that now enforces never reaches here.
fn claim_uncapped_host_notice() -> bool {
    claim_notice_at(&uncapped_notice_path())
}

/// Testable core of [`claim_uncapped_host_notice`]. Split for the same reason `config::load_impl` is:
/// the wrapper reads `XDG_DATA_HOME`/`HOME`, and a test that set those would be mutating
/// process-global state under a parallel test runner.
fn claim_notice_at(path: &std::path::Path) -> bool {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    match opts.open(path) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_) => {
            if let Some(parent) = path.parent() {
                if std::fs::create_dir_all(parent).is_err() {
                    return true;
                }
            }
            match opts.open(path) {
                Ok(_) => true,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
                Err(_) => true,
            }
        }
    }
}

/// If a systemd user manager is available and we aren't already inside a kern scope, re-exec
/// the whole `kern` invocation under `systemd-run --user --scope` with cgroup caps, so the
/// sandbox (and any fork bomb in it) is hard-limited. This replaces the process on success; on
/// any failure it returns and the caller falls back to the best-effort cgroup path.
/// Parameters for [`reexec_in_scope_if_possible`], grouped into one value (the caps plus the three
/// posture bits) so the call is a single argument rather than an 8-wide positional list.
struct ScopeReexec<'a> {
    memory: Option<u64>,
    memory_swap_max: Option<u64>,
    cpuset: Option<&'a str>,
    cpus: Option<f64>,
    pids_max: Option<u64>,
    /// `kern box` (has a supervisor to hold the RAII guard) may take the direct kern.slice path;
    /// `kern run` (execs in place) must not, so it uses the systemd `--scope --collect` path.
    allow_direct: bool,
    /// A FOREGROUND box dies with its launcher (arm PDEATHSIG across the exec into systemd-run).
    die_with_parent: bool,
    /// `--allow-uncapped`/`KERN_ALLOW_UNCAPPED`: suppress the once-per-host "not enforced" notice.
    allow_uncapped: bool,
}

/// The ceiling the per-box SCOPE gets, in bytes: the box's own `--memory` (or the default) plus kern's
/// supervisor headroom.
///
/// The scope holds kern's bookkeeping AND the box; the box itself is capped at EXACTLY what was asked
/// for, by the inner `kern-box-*` child (see `prepare_delegated_scope`). The two ceilings must not be
/// equal: charges are counted at every level, so an equal outer one is reached FIRST - by exactly the
/// supervisor's share - and the box would be killed by the scope's OOM, which takes the supervisor with
/// it and loses the exit code. A pure function so that arithmetic is checked on every run, including
/// the `saturating_add`: a `--memory` near `u64::MAX` must not wrap the scope's ceiling down to a tiny
/// number and make every box OOM instantly.
fn scope_memory_max(memory: Option<u64>) -> u64 {
    memory
        .unwrap_or(SCOPE_MEMORY_MAX_BYTES)
        .saturating_add(kern_isolation::SCOPE_SUPERVISOR_HEADROOM)
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
        // Same function the other unenforceable-cap paths use, so the rule has one definition.
        kern_isolation::warn_unenforced_caps(memory, cpus, pids_max);
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

/// Arm `PR_SET_PDEATHSIG(SIGKILL)`: SIGKILL this process when its parent dies - the die-with-parent
/// link for a foreground box. Survives a non-setuid `execve`.
fn arm_pdeathsig() {
    unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        );
    }
}

/// The scope re-exec parent (proxy). Blocks on `read_fd` until the re-exec'd kern signals the scope is
/// up (one byte) or the child chain closes the pipe (EOF = `systemd-run` failed before the box started).
/// On a byte: forward the catchable fatal signals to `child` (`systemd-run`), wait for it, and `exit`
/// with its code - never returns. On EOF: reap `child` and RETURN, so the caller falls back.
fn scope_reexec_proxy(child: libc::pid_t, read_fd: i32) {
    let mut byte = [0u8; 1];
    let n = loop {
        let r = unsafe { libc::read(read_fd, byte.as_mut_ptr().cast(), 1) };
        if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break r;
    };
    unsafe { libc::close(read_fd) };
    if n <= 0 {
        // `systemd-run` died before the scope existed. Reap the child, then fall back.
        reap(child);
        return;
    }
    // The scope is up and the box runs under `systemd-run` (our child). Forward the catchable fatal
    // signals so Ctrl-C and a SIGTERM reach `systemd-run` (which relays them to the box) and the proxy
    // does not die first and orphan the wait. This path is `!die_with_parent` (detached / `kern run`):
    // there is no PDEATHSIG, and an uncatchable proxy SIGKILL simply leaves `systemd-run` and the box
    // running - correct for a detached box, and matching `kern run`'s no-die-with-launcher contract.
    SCOPE_PROXY_CHILD.store(child, std::sync::atomic::Ordering::SeqCst);
    // Install via `sigaction` (the codebase convention, not `signal`): explicit persistent-handler
    // semantics with no SysV one-shot reset, `SA_RESTART` so the `waitpid` below resumes instead of
    // failing with EINTR, and an `sa_mask` blocking the sibling fatal signals so one forward cannot
    // interrupt another mid-`kill`.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = scope_proxy_forward as extern "C" fn(libc::c_int) as libc::sighandler_t;
        act.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut act.sa_mask);
        for &sig in &[libc::SIGINT, libc::SIGTERM, libc::SIGQUIT, libc::SIGHUP] {
            libc::sigaddset(&mut act.sa_mask, sig);
        }
        for &sig in &[libc::SIGINT, libc::SIGTERM, libc::SIGQUIT, libc::SIGHUP] {
            libc::sigaction(sig, &act, std::ptr::null_mut());
        }
    }
    let status = reap(child);
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    };
    std::process::exit(code);
}

/// `waitpid` a child to completion, retrying on `EINTR`; returns the raw status (0 on a wait error, so
/// a caller reading it as "exited 0" degrades safe).
fn reap(child: libc::pid_t) -> libc::c_int {
    let mut status: libc::c_int = 0;
    loop {
        let w = unsafe { libc::waitpid(child, &mut status, 0) };
        if w < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }
    status
}

/// The `systemd-run` child pid, for the async-signal-safe forwarding handler in the scope proxy.
static SCOPE_PROXY_CHILD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Async-signal-safe: relay a catchable fatal signal from the proxy to `systemd-run` (`kill` and an
/// atomic load are both async-signal-safe).
extern "C" fn scope_proxy_forward(sig: libc::c_int) {
    let child = SCOPE_PROXY_CHILD.load(std::sync::atomic::Ordering::SeqCst);
    if child > 0 {
        unsafe { libc::kill(child, sig) };
    }
}

/// The fd `main` should write the scope-readiness byte to, resolved from the environment. Returns
/// `Some(fd)` ONLY for a legitimate scope re-exec: `KERN_SCOPE` must be set (the outer parent sets both
/// it and `KERN_SCOPE_READY_FD` on the `systemd-run` command, so they always arrive together), AND the
/// value must be a real, NON-STANDARD descriptor (> 2). This refuses a `KERN_SCOPE_READY_FD` planted in
/// the environment by a caller without the matching re-exec, so kern never writes a stray byte to or
/// closes its own std streams (0/1/2), or an arbitrary descriptor, on an env var's say-so.
pub(crate) fn ready_fd_to_signal(scope_set: bool, val: Option<&std::ffi::OsStr>) -> Option<i32> {
    if !scope_set {
        return None;
    }
    let fd = val?.to_str()?.trim().parse::<i32>().ok()?;
    (fd > 2).then_some(fd)
}

/// Per-file cap on a box's captured log. A single-generation ring (`<log>` + `<log>.1`) keeps at most
/// `2 * BOX_LOG_MAX_BYTES` on disk. The runtime dir is a small tmpfs (systemd default `size=` = 10% of
/// RAM), so an unbounded writer would otherwise fill it and break the user session (no more sockets or
/// state creatable in `/run/user/<uid>`). Docker solved the same class with `--log-opt max-size`.
const BOX_LOG_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Max bytes moved per `splice` in the pump: large enough to amortise the syscall across a flood, small
/// enough that one call can't monopolise the pump or overshoot the rotation boundary by much.
const PUMP_SPLICE_CHUNK: usize = 1 << 20;

/// Open `path` for log writing (`O_WRONLY|O_CREAT|O_CLOEXEC`, mode 0600), with `O_APPEND` iff `append`.
/// Returns the fd, or `-1` on error. The capped pump opens WITHOUT `O_APPEND` - it is the sole writer and
/// drives the offset itself via `splice`, whose interaction with `O_APPEND` is not guaranteed across
/// kernels - while the uncapped `open_log_direct` fallback opens WITH `O_APPEND` because the box writes
/// to it directly and its two inherited stdio streams stay ordered only through the append flag.
fn open_log(path: &std::path::Path, append: bool) -> i32 {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return -1;
    };
    let flags =
        libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC | if append { libc::O_APPEND } else { 0 };
    unsafe { libc::open(c.as_ptr(), flags, 0o600) }
}

/// Move up to `want` bytes from pipe `rd` into `sink` with `splice(2)` - a ZERO-COPY pipe->file move (no
/// userspace buffer, no `read`+`write` pair), so draining even a gigabyte-per-second flood costs syscall
/// overhead only. Returns bytes moved (`Ok(0)` = EOF) or `Err(errno)`.
fn splice_once(rd: i32, sink: i32, want: usize) -> Result<usize, i32> {
    let moved = unsafe {
        libc::splice(
            rd,
            std::ptr::null_mut(),
            sink,
            std::ptr::null_mut(),
            want,
            libc::SPLICE_F_MOVE,
        )
    };
    if moved >= 0 {
        Ok(moved as usize)
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }
}

/// A size-capped, single-generation-rotating append log. `write` never blocks the caller on a full disk
/// (`ENOSPC` drops the chunk) and never grows the active file past `max` (rotation renames it to
/// `<path>.1` and starts fresh), so total on-disk use is bounded at `2 * max`.
struct CappedLog {
    fd: i32,
    path: std::path::PathBuf,
    written: u64,
    max: u64,
}

impl CappedLog {
    fn open(path: &std::path::Path, max: u64) -> Option<Self> {
        let fd = open_log(path, false);
        if fd < 0 {
            return None;
        }
        // Non-append (the pump is the sole writer and drives the offset via `splice`). Seek to end so a
        // pre-existing log is appended to, not overwritten, and count from its size so the cap bounds the
        // FILE, not this session's bytes. `lseek(SEEK_END)` returns the new offset (= size); 0 for fresh.
        let end = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
        let written = if end > 0 { end as u64 } else { 0 };
        Some(Self {
            fd,
            path: path.to_path_buf(),
            written,
            max,
        })
    }

    /// Rename the active file to `<path>.1` (one generation kept, overwriting a previous `.1`) and reopen
    /// a fresh empty file. The rename is atomic, so a reader never sees the path missing. On failure the
    /// old fd is kept and `written` stays at the cap, so the next `write` retries rather than overflowing.
    fn rotate(&mut self) {
        let mut old = self.path.clone().into_os_string();
        old.push(".1");
        if std::fs::rename(&self.path, &old).is_err() {
            return; // keep the old fd; never grow past the cap
        }
        let fd = open_log(&self.path, false);
        if fd >= 0 {
            unsafe { libc::close(self.fd) };
            self.fd = fd;
            self.written = 0;
        }
    }

    fn write(&mut self, mut buf: &[u8]) {
        while !buf.is_empty() {
            if self.written >= self.max {
                self.rotate();
                if self.written >= self.max {
                    return; // rotation failed (rename/open) - drop rather than spin or overflow the cap
                }
            }
            let room = (self.max - self.written) as usize;
            let chunk = &buf[..buf.len().min(room)];
            let n = unsafe { libc::write(self.fd, chunk.as_ptr().cast(), chunk.len()) };
            if n < 0 {
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINTR) => continue,
                    // Disk full: drop the chunk and force a rotation next round (freeing `.1`'s space).
                    // The workload must NEVER block or die because its log is full - the log is
                    // diagnostics, not part of the workload's contract.
                    Some(libc::ENOSPC) => {
                        self.written = self.max;
                        return;
                    }
                    _ => return,
                }
            }
            self.written += n as u64;
            buf = &buf[n as usize..];
        }
    }
}

impl Drop for CappedLog {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

/// Drain the pipe `rd` into a byte-capped rotating log at `path` until EOF. Runs in the forked pump
/// child. Uses `splice(2)` (ZERO-COPY pipe->file) so draining a flood costs syscall overhead only, not
/// the two userspace memcpies of a `read`+`write` loop - the CPU that would otherwise burn OUTSIDE the
/// box's cgroup cap. Falls back to `read`+`write` permanently if the filesystem refuses `splice`
/// (`EINVAL`); drains to `/dev/null` (still zero-copy) when there is no log or the disk is full, so the
/// box NEVER blocks on a full pipe.
fn pump_capped_log(rd: i32, path: &std::path::Path) {
    let mut log = CappedLog::open(path, BOX_LOG_MAX_BYTES);
    // A /dev/null sink for the no-log case and disk-full overflow: the pipe must still be drained.
    let void = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    let mut use_splice = true;
    let mut scratch = [0u8; 64 * 1024]; // read+write fallback buffer (splice-unsupported fs)
    loop {
        // Choose this round's sink and how much may go to it. `to_log` distinguishes the real log (count
        // toward the cap) from the /dev/null shed (do not).
        let (sink, want, to_log) = match log.as_mut() {
            Some(l) => {
                if l.written >= l.max {
                    l.rotate();
                }
                let room = l.max.saturating_sub(l.written);
                if room == 0 {
                    (void, PUMP_SPLICE_CHUNK, false) // rotation could not free room -> shed this round
                } else {
                    (l.fd, room.min(PUMP_SPLICE_CHUNK as u64) as usize, true)
                }
            }
            None => (void, PUMP_SPLICE_CHUNK, false),
        };
        if sink < 0 {
            break; // neither a log nor /dev/null could be opened - nothing to drain into
        }
        if use_splice {
            match splice_once(rd, sink, want) {
                Ok(0) => break, // EOF: every write end (workload + supervisor) is closed
                Ok(n) => {
                    if to_log {
                        if let Some(l) = log.as_mut() {
                            l.written += n as u64;
                        }
                    }
                }
                Err(libc::EINTR) => {}
                // Disk full: force a rotation next round (freeing `.1`'s space), shedding meanwhile.
                Err(libc::ENOSPC) | Err(libc::EDQUOT) => {
                    if let Some(l) = log.as_mut() {
                        l.written = l.max;
                    }
                }
                // This kernel/filesystem cannot splice this pipe->fd pair: fall back permanently.
                Err(libc::EINVAL) => use_splice = false,
                Err(_) => break, // an unexpected splice error - stop draining
            }
        } else {
            let n = unsafe { libc::read(rd, scratch.as_mut_ptr().cast(), scratch.len()) };
            if n > 0 {
                match log.as_mut() {
                    Some(l) => l.write(&scratch[..n as usize]),
                    None => {
                        let _ = unsafe { libc::write(void, scratch.as_ptr().cast(), n as usize) };
                    }
                }
            } else if n == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
            {
                break; // EOF (n == 0) or a real read error; EINTR falls through and retries
            }
        }
    }
    if void >= 0 {
        unsafe { libc::close(void) };
    }
}

/// Interpose a byte-capped pump between the workload's stdout/stderr and the on-disk log. Creates a
/// pipe, forks a child that drains the read end into a [`CappedLog`], and returns the WRITE end for the
/// caller to `dup2` onto fd 1/2 - so a detached box that writes without bound (`yes`, a crash loop)
/// cannot fill the tmpfs runtime dir and break the user session. `None` if the pipe or fork fails - the
/// caller then falls back to writing the log directly (uncapped, but never lost).
///
/// # Safety
/// Runs during stdio detachment, before any namespace/seccomp setup, and forks. Single-threaded here, so
/// running Rust code in the child (no exec) is sound. The child sheds every inherited fd except the pipe
/// read end - crucially the readiness-pipe write end, which held here would stop the launcher from ever
/// seeing EOF and hang `kern box -d`.
unsafe fn start_log_pump(path: &std::path::Path) -> Option<i32> {
    let mut fds = [0i32; 2];
    if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
        return None;
    }
    let (rd, wr) = (fds[0], fds[1]);
    // Enlarge the pipe buffer to `PUMP_SPLICE_CHUNK` (default is 64 KiB = 16 pages). `splice` moves at
    // most what the pipe holds, so a bigger buffer means one `splice` drains up to 1 MiB instead of
    // 64 KiB - ~16x fewer syscalls under a flood, and fewer `write` wake-ups for the box. Best-effort:
    // capped by `/proc/sys/fs/pipe-max-size`, and a failure just leaves the default size (still correct).
    libc::fcntl(rd, libc::F_SETPIPE_SZ, PUMP_SPLICE_CHUNK as libc::c_int);
    let pid = libc::fork();
    if pid < 0 {
        libc::close(rd);
        libc::close(wr);
        return None;
    }
    if pid == 0 {
        // DETACH the pump from the parent's stdio FIRST. The pump is forked before `detach_stdio`
        // redirects fd 1/2 onto this pipe, so it inherits the LAUNCHER's stdout/stderr - and holding
        // that write end open would block a `kern box -d` whose stdout is a pipe (a test harness, a
        // script doing `$(kern box -d …)`) in `wait`/`output` until the BOX exits, breaking the
        // "detached returns immediately" contract. Point 0/1/2 at /dev/null so the pump holds no
        // inherited stream; it reads `rd` and writes only its own (later-opened) log fd.
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            if devnull > 2 {
                libc::close(devnull);
            }
        }
        // Shed every OTHER inherited fd except the read end - most importantly the readiness-pipe write
        // end, which held here would stop the launcher from ever seeing EOF and hang `kern box -d`.
        kern_isolation::shed_inherited_fds(rd);
        pump_capped_log(rd, path);
        libc::_exit(0);
    }
    libc::close(rd); // the parent keeps only the write end (dup2'd onto 1/2 by the caller, then closed)
    Some(wr)
}

/// Open the box log for direct (uncapped) append - the fallback when the capped pump can't start.
fn open_log_direct(path: &std::path::Path) -> Option<i32> {
    let fd = open_log(path, true);
    (fd >= 0).then_some(fd)
}

/// Detach stdio: stdin from `/dev/null`; stdout/stderr into the box's size-capped `log` (via a pump
/// child, so an unbounded writer can't fill the tmpfs runtime dir), or `/dev/null` if no log path. So a
/// detached box neither holds nor spams the terminal, its output is captured, and its log cannot DoS the
/// user session. If the pump can't start, the log is written directly (uncapped) rather than lost.
fn detach_stdio(log: Option<&std::path::Path>) {
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            libc::dup2(null, 0);
        }
        let sink = log
            .and_then(|p| start_log_pump(p).or_else(|| open_log_direct(p)))
            .unwrap_or(null);
        if sink >= 0 {
            libc::dup2(sink, 1);
            libc::dup2(sink, 2);
        }
        // Close the source fd once it's duplicated onto 1/2 - unless it IS `null` (closed below) or a
        // std stream.
        if sink > 2 && sink != null {
            libc::close(sink);
        }
        if null > 2 {
            libc::close(null);
        }
    }
}

/// True if the LIVE box `b` satisfies every `--filter` (AND semantics). Keys are pre-validated by
/// [`ps`]. `name` is a substring match (like `docker ps --filter name=`), `id` is an exact host-pid
/// match, `status` is running/paused/orphaned. `status=exited`/`dead` is answered by [`exited_matches`]
/// against the `waitexit` breadcrumb, not here, so a live box correctly fails those.
fn ps_matches(b: &registry::Instance, filters: &[(String, String)]) -> bool {
    filters.iter().all(|(k, v)| match k.as_str() {
        "name" => b.name.contains(v.as_str()),
        // Exact pod match - the grouping key `compose ps` scopes on. Exact, not substring: two stacks
        // whose pod names share a prefix must never be listed as one.
        "pod" => b.pod == *v,
        // `label=k=v` matches an exact pair; `label=k` matches the key whatever its value - the two
        // forms Docker supports. Matching is over the comma-joined field, so a bare key must not be
        // satisfied by a mere substring of another key (`app` must not match `apple=1`): compare the
        // key segment up to its `=`.
        "label" => b.labels.split(',').filter(|l| !l.is_empty()).any(|l| {
            l == v.as_str()
                || (!v.contains('=') && l.split_once('=').map(|(k, _)| k) == Some(v.as_str()))
        }),
        "id" => b.pid.to_string() == *v,
        // Mirror `box_status`'s priority so the filter never drifts from the STATUS column: orphaned
        // wins, and a `running`/`paused` query must therefore EXCLUDE an orphaned box (its supervisor
        // is dead - it is not simply running).
        "status" => match v.as_str() {
            "orphaned" => b.orphaned,
            "running" => !b.orphaned && !registry::is_paused(b.cgroup_pid()),
            "paused" => !b.orphaned && registry::is_paused(b.cgroup_pid()),
            _ => false,
        },
        _ => false, // unreachable: keys are validated in `ps` before this runs (fail closed anyway)
    })
}

/// The `ps_matches` twin for an EXITED box (`kern ps -a`). Same filter keys, but an exited box has no
/// live cgroup to read `paused`/`orphaned` from and did not keep its `labels`: a `status=running`
/// query therefore correctly excludes it, and `label=` matches nothing. Only `status=exited` accepts
/// it - kern has no `dead` state, so `status=dead` matches nothing (Docker's `dead` is a failed
/// removal kern cannot produce).
fn exited_matches(e: &registry::ExitedBox, filters: &[(String, String)]) -> bool {
    filters.iter().all(|(k, v)| match k.as_str() {
        "name" => e.name.contains(v.as_str()),
        "pod" => e.pod == *v,
        "id" => e.pid.to_string() == *v,
        "status" => v == "exited",
        _ => false,
    })
}

/// One box's display status: `paused` (frozen by `kern pause`), else its health-check verdict, else
/// `empty` when no health check is configured. The single source of truth for `ps`'s HEALTH column,
/// `ps --format {{.Status}}`, and `--filter status=` - so they never drift on what "paused" means.
fn box_status(b: &registry::Instance, empty: &str) -> String {
    // ORPHANED wins over every other status: the supervisor is dead but the box's PID 1 / `-p` forwarder
    // are still running (and still holding the host port). Surfacing it is the whole point - the box used
    // to vanish from `ps` here - and `kern stop <name>` reaps it via `cgroup.kill`.
    if b.orphaned {
        return "orphaned".to_string();
    }
    if registry::is_paused(b.cgroup_pid()) {
        return "paused".to_string();
    }
    let h = registry::health_of(&b.name, b.pid);
    if h.is_empty() {
        empty.to_string()
    } else {
        h
    }
}

/// Append `s` to `out`, turning the two-char escapes `\t`/`\n` into a tab / newline (the docker
/// `--format` convention); any other backslash is kept verbatim. Pure.
fn push_unescaped(out: &mut String, s: &str) {
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.peek() {
                Some('t') => {
                    out.push('\t');
                    it.next();
                }
                Some('n') => {
                    out.push('\n');
                    it.next();
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
}

/// The fields `ps --format` reads, so ONE template renderer serves both a live [`registry::Instance`]
/// and an exited [`registry::ExitedBox`] (Docker's `ps -a --format`). An exited box has no live
/// rootfs/ports left to report; those render empty rather than as a stale value.
trait PsRow {
    fn ps_name(&self) -> &str;
    fn ps_pid(&self) -> i32;
    fn ps_image(&self) -> String;
    fn ps_command(&self) -> String;
    fn ps_ports(&self) -> &str;
    fn ps_pod(&self) -> &str;
    fn ps_running_for(&self, now: u64) -> String;
    fn ps_status(&self) -> String;
}

impl PsRow for registry::Instance {
    fn ps_name(&self) -> &str {
        &self.name
    }
    fn ps_pid(&self) -> i32 {
        self.pid
    }
    fn ps_image(&self) -> String {
        crate::ui::scrub(&self.rootfs)
    }
    fn ps_command(&self) -> String {
        crate::ui::scrub(&self.command)
    }
    fn ps_ports(&self) -> &str {
        &self.ports
    }
    fn ps_pod(&self) -> &str {
        &self.pod
    }
    fn ps_running_for(&self, now: u64) -> String {
        fmt_uptime(now.saturating_sub(self.started))
    }
    fn ps_status(&self) -> String {
        box_status(self, "running")
    }
}

impl PsRow for registry::ExitedBox {
    fn ps_name(&self) -> &str {
        &self.name
    }
    fn ps_pid(&self) -> i32 {
        self.pid
    }
    fn ps_image(&self) -> String {
        String::new()
    }
    fn ps_command(&self) -> String {
        crate::ui::scrub(&self.command)
    }
    fn ps_ports(&self) -> &str {
        ""
    }
    fn ps_pod(&self) -> &str {
        &self.pod
    }
    fn ps_running_for(&self, _now: u64) -> String {
        format!("{} ago", fmt_uptime(self.exited_ago))
    }
    fn ps_status(&self) -> String {
        format!("exited ({})", self.code)
    }
}

/// Render one box through a `ps --format` template: the `{{.Field}}` placeholders below, plus `\t`/`\n`
/// in literal text. A Go-template with logic (ranges/conditionals/functions) is NOT supported: an
/// unterminated `{{` or an unknown token is a hard error (use `--json` for arbitrary shaping). Validated
/// fields (name/pod/ports/status) are borrowed straight in; the UNTRUSTED command/rootfs are
/// control-scrubbed first so a crafted box argv or `--rootfs` can't inject ANSI escapes into the
/// terminal (the same guard the `ps` table, `images`, and `--json` already apply).
fn render_ps_format<R: PsRow>(tmpl: &str, b: &R, now: u64) -> Result<String, Error> {
    let mut out = String::with_capacity(tmpl.len());
    let mut rest = tmpl;
    while let Some(open) = rest.find("{{") {
        push_unescaped(&mut out, &rest[..open]);
        let after = &rest[open + 2..];
        let close = after
            .find("}}")
            .ok_or(Error::Usage("ps --format: unterminated `{{`"))?;
        match after[..close].trim() {
            ".Names" | ".Name" => out.push_str(b.ps_name()),
            ".ID" | ".Pid" => out.push_str(&b.ps_pid().to_string()),
            ".Image" | ".Rootfs" => out.push_str(&b.ps_image()),
            ".Command" => out.push_str(&b.ps_command()),
            ".Ports" => out.push_str(b.ps_ports()),
            ".Pod" => out.push_str(b.ps_pod()),
            ".RunningFor" => out.push_str(&b.ps_running_for(now)),
            ".Status" => out.push_str(&b.ps_status()),
            _ => {
                return Err(Error::Usage(
                    "ps --format: unsupported token (supported: {{.Names}} {{.Pid}} {{.Image}} \
                     {{.Command}} {{.Ports}} {{.Pod}} {{.Status}} {{.RunningFor}}; use --json for more)",
                ))
            }
        }
        rest = &after[close + 2..];
    }
    push_unescaped(&mut out, rest);
    Ok(out)
}

#[cfg(test)]
mod scope_ceiling_tests {
    use super::*;

    /// The scope's ceiling is always ABOVE the box's own, and never wraps.
    ///
    /// Equal ceilings would silently undo the reason the box has an inner cgroup at all: the outer one
    /// is reached first, by the supervisor's share, so the box dies of the SCOPE's OOM - which kills
    /// the supervisor too and leaves `kern wait` with nothing to report. That was the measured defect
    /// on all three ARM boards. A `--memory` near `u64::MAX` must saturate, not wrap: wrapping would
    /// hand systemd a tiny `MemoryMax` and OOM every box instantly.
    #[test]
    fn the_scope_ceiling_is_above_the_boxs_own_and_saturates() {
        let head = kern_isolation::SCOPE_SUPERVISOR_HEADROOM;
        assert!(head > 0, "a zero headroom is the equal-ceilings bug");
        for asked in [1, 4096, 64 * 1024 * 1024, 8 * 1024 * 1024 * 1024] {
            assert_eq!(
                scope_memory_max(Some(asked)),
                asked + head,
                "the scope must clear the box's own cap by exactly the headroom"
            );
        }
        assert_eq!(
            scope_memory_max(None),
            SCOPE_MEMORY_MAX_BYTES + head,
            "a box with no --memory takes the default cap, plus the same headroom"
        );
        assert_eq!(
            scope_memory_max(Some(u64::MAX)),
            u64::MAX,
            "an absurd --memory must saturate at the ceiling, never wrap to a tiny one"
        );
        assert!(
            scope_memory_max(Some(u64::MAX - 1)) >= u64::MAX - 1,
            "saturation must never LOWER the ceiling below what was asked"
        );
    }
}

#[cfg(test)]
mod strip_ansi_tests {
    /// `strip_ansi` must remove the whole escape sequence, not just its ESC byte.
    ///
    /// This is the test that was missing, and its absence cost a shipped feature. `kern <verb>
    /// --help` filters the reference by matching on de-coloured lines; the first implementation
    /// called `ui::scrub` and then `replace`d the palette strings, but scrub removes the ESC first,
    /// so `[1m` survived as printable text and every `replace` searched for a sequence that was no
    /// longer present. Nothing matched, the filter fell back to the full 161-line page, and a
    /// terminal user got exactly the wall the feature existed to remove.
    ///
    /// The integration test could not see it: `Command::output()` captures stdout, stdout is then
    /// not a tty, the palette is empty, and with an empty palette the broken code is correct. So the
    /// assertion lives here, on the function, with the colour codes written out.
    #[test]
    fn strip_ansi_removes_whole_sequences_not_just_the_escape_byte() {
        let e = '\u{1b}';
        let cases: [(String, &str); 6] = [
            (format!("{e}[1mOPTIONS for box:{e}[0m"), "OPTIONS for box:"),
            (format!("    {e}[36mbox{e}[0m <name>"), "    box <name>"),
            (format!("{e}[38;5;208mtruecolor{e}[0m"), "truecolor"),
            ("no escapes at all".to_string(), "no escapes at all"),
            (format!("{e}(Bplain"), "plain"),
            ("tab\there".to_string(), "tabhere"),
        ];
        for (input, want) in cases {
            let got = super::strip_ansi(&input);
            assert_eq!(
                got, want,
                "strip_ansi({input:?}) gave {got:?}; a leftover `[1m` is indistinguishable from \
                 content and makes every match fail"
            );
            assert!(
                !got.contains('['),
                "strip_ansi left a `[` behind in {got:?}: the sequence was cut at the ESC only"
            );
        }
    }
}

#[cfg(test)]
mod ps_exited_tests {
    use super::*;

    fn dead(name: &str, code: i32, pod: &str) -> registry::ExitedBox {
        registry::ExitedBox {
            name: name.to_string(),
            pid: 42,
            starttime: 1000,
            code,
            pod: pod.to_string(),
            command: "python app.py".to_string(),
            exited_ago: 5,
        }
    }

    /// An exited box renders through the SAME `--format` engine as a live one: `.Status` is
    /// `exited (<code>)` and `.RunningFor` is "how long ago", so `kern ps -a --format` is complete.
    #[test]
    fn exited_box_renders_through_ps_format() {
        let e = dead("web", 7, "stack");
        assert_eq!(
            render_ps_format("{{.Names}} {{.Status}} {{.Pod}} {{.RunningFor}}", &e, 0).unwrap(),
            "web exited (7) stack 5s ago"
        );
        // No live rootfs/ports on a dead box - they render empty, not a stale value.
        assert_eq!(
            render_ps_format("[{{.Image}}{{.Ports}}]", &e, 0).unwrap(),
            "[]"
        );
    }

    /// The exited filter mirrors `ps_matches`: `status=exited|dead` accept it, `status=running`
    /// rejects it, `name` is a substring, `pod` is exact, and `label=` (not retained) matches nothing.
    #[test]
    fn exited_matches_honours_the_filter_keys() {
        let e = dead("mystack-db", 1, "mystack");
        assert!(exited_matches(&e, &[("status".into(), "exited".into())]));
        // kern has no `dead` state, so `status=dead` matches nothing (like `created`/`running`).
        assert!(!exited_matches(&e, &[("status".into(), "dead".into())]));
        assert!(!exited_matches(&e, &[("status".into(), "running".into())]));
        assert!(exited_matches(&e, &[("pod".into(), "mystack".into())]));
        assert!(!exited_matches(&e, &[("pod".into(), "mystac".into())]));
        assert!(exited_matches(&e, &[("name".into(), "db".into())]));
        assert!(exited_matches(&e, &[("id".into(), "42".into())]));
        assert!(!exited_matches(&e, &[("label".into(), "k=v".into())]));
        // AND semantics: one non-matching clause fails the whole filter.
        assert!(!exited_matches(
            &e,
            &[
                ("pod".into(), "mystack".into()),
                ("name".into(), "web".into())
            ]
        ));
    }
}

#[cfg(test)]
mod seccomp_resolution_tests {
    use super::{resolve_seccomp_mode, SecurityProfile};
    use crate::error::Error;
    use kern_isolation::SeccompFilter;
    use std::ffi::OsStr;

    fn ok(env: Option<&OsStr>, p: Option<SecurityProfile>) -> SeccompFilter {
        resolve_seccomp_mode(env, p).expect("resolve should succeed")
    }

    #[test]
    fn explicit_env_wins_then_profile_then_default_no_env_mutation() {
        // No env, no profile: the shipped default is the ALLOWLIST (deny-by-default). Pinned to the
        // concrete variant, not `SeccompFilter::default()`, so an accidental flip of the default is
        // caught here instead of passing tautologically.
        assert_eq!(ok(None, None), SeccompFilter::Allowlist);
        // Profile untrusted, no env: allowlist.
        assert_eq!(
            ok(None, Some(SecurityProfile::Untrusted)),
            SeccompFilter::Allowlist
        );
        // Explicit env WINS over the profile, even to weaken it (the documented precedence).
        assert_eq!(
            ok(
                Some(OsStr::new("denylist")),
                Some(SecurityProfile::Untrusted)
            ),
            SeccompFilter::Denylist
        );
        // Explicit `allowlist-audit` (LESS strict than the profile's allowlist: it logs-and-runs) also
        // wins - "explicit wins" is unconditional, by design.
        assert_eq!(
            ok(
                Some(OsStr::new("allowlist-audit")),
                Some(SecurityProfile::Untrusted)
            ),
            SeccompFilter::AllowlistAudit
        );
        assert_eq!(
            ok(Some(OsStr::new("allowlist")), None),
            SeccompFilter::Allowlist
        );
        // Exported-but-blank counts as unset, so it falls through to the profile.
        assert_eq!(
            ok(Some(OsStr::new("")), Some(SecurityProfile::Untrusted)),
            SeccompFilter::Allowlist
        );
    }

    #[test]
    fn a_malformed_explicit_value_fails_loud_it_does_not_downgrade_the_profile() {
        // A SET-but-unrecognised `KERN_SECCOMP` is a usage error, NOT a silent fall to the default that
        // would downgrade a `--security-profile untrusted` box from allowlist to denylist while it still
        // advertises `untrusted`. With and without the profile, the outcome is an error naming the var.
        for p in [None, Some(SecurityProfile::Untrusted)] {
            let err = resolve_seccomp_mode(Some(OsStr::new("allowlist-audi")), p).unwrap_err();
            assert!(
                matches!(&err, Error::Usage(m) if m.contains("KERN_SECCOMP")),
                "a typo'd KERN_SECCOMP must be a usage error naming the var, got {err:?}"
            );
        }
        assert!(resolve_seccomp_mode(Some(OsStr::new("bogus")), None).is_err());
    }

    #[test]
    fn a_non_utf8_value_fails_loud_it_does_not_silently_default() {
        // A non-UTF-8 `KERN_SECCOMP` cannot be a valid token, so it must be a usage error, NOT a silent
        // fall to the default that (under `--security-profile untrusted`) would downgrade the box while
        // it still advertises `untrusted`. `to_str()` returns None for invalid UTF-8, and the fail-loud
        // branch catches it exactly like a typo'd ASCII value - same class, verified here.
        use std::os::unix::ffi::OsStrExt;
        let bad = OsStr::from_bytes(b"\xff\xfe\x00nope"); // invalid UTF-8, non-empty
        for p in [None, Some(SecurityProfile::Untrusted)] {
            let err = resolve_seccomp_mode(Some(bad), p).unwrap_err();
            assert!(
                matches!(&err, Error::Usage(m) if m.contains("KERN_SECCOMP")),
                "a non-UTF-8 KERN_SECCOMP must be a usage error, got {err:?}"
            );
        }
    }
}

#[cfg(test)]
mod limit_policy_tests {
    use super::resolve_limit_policy;
    use crate::error::Error;

    #[test]
    fn require_and_allow_resolve_from_flag_or_env_and_conflict_on_resolved_values() {
        // Neither: best-effort, no conflict.
        assert_eq!(
            resolve_limit_policy(false, false, false, false).ok(),
            Some((false, false))
        );
        // require via flag; via env; both - all resolve to (true, false).
        assert_eq!(
            resolve_limit_policy(true, false, false, false).ok(),
            Some((true, false))
        );
        assert_eq!(
            resolve_limit_policy(false, true, false, false).ok(),
            Some((true, false))
        );
        assert_eq!(
            resolve_limit_policy(true, true, false, false).ok(),
            Some((true, false))
        );
        // allow via flag; via env.
        assert_eq!(
            resolve_limit_policy(false, false, true, false).ok(),
            Some((false, true))
        );
        assert_eq!(
            resolve_limit_policy(false, false, false, true).ok(),
            Some((false, true))
        );

        // The four contradictory combinations a flag-only parse check would MISS: flag+flag,
        // flag(require)+env(allow), env(require)+flag(allow), env+env. Every one must be rejected.
        for (rf, re, af, ae) in [
            (true, false, true, false),
            (true, false, false, true),
            (false, true, true, false),
            (false, true, false, true),
        ] {
            let err = resolve_limit_policy(rf, re, af, ae).unwrap_err();
            assert!(
                matches!(&err, Error::Usage(m)
                    if m.contains("mutually exclusive") && m.contains("KERN_")),
                "combination ({rf},{re},{af},{ae}) must be a usage error naming the env vars, got {err:?}"
            );
        }
    }
}

#[cfg(test)]
mod scope_ready_fd_tests {
    use super::ready_fd_to_signal;
    use std::ffi::OsStr;

    #[test]
    fn honours_a_real_fd_only_as_the_genuine_scope_reexec() {
        // A legitimate scope re-exec: KERN_SCOPE set + a real non-std fd.
        assert_eq!(ready_fd_to_signal(true, Some(OsStr::new("7"))), Some(7));
        assert_eq!(ready_fd_to_signal(true, Some(OsStr::new("  9 "))), Some(9));
        // trimmed
    }

    #[test]
    fn refuses_the_marker_without_the_scope_reexec() {
        // KERN_SCOPE NOT set: a `KERN_SCOPE_READY_FD` planted in the environment by any caller is
        // ignored, so kern never writes to / closes an fd on an env var's say-so alone.
        assert_eq!(ready_fd_to_signal(false, Some(OsStr::new("7"))), None);
        assert_eq!(ready_fd_to_signal(false, Some(OsStr::new("1"))), None);
        assert_eq!(ready_fd_to_signal(false, None), None);
    }

    #[test]
    fn never_touches_the_std_streams_or_a_malformed_value() {
        // fds 0/1/2 (stdin/stdout/stderr) are refused even under a genuine re-exec: writing a stray byte
        // to or closing kern's own std streams would corrupt its output. Malformed / out-of-range values
        // are refused too, never defaulting to some fd.
        for bad in [
            "0",
            "1",
            "2",
            "-1",
            "abc",
            "",
            "  ",
            "99999999999999999999",
            "7x",
            "0x7",
        ] {
            assert_eq!(
                ready_fd_to_signal(true, Some(OsStr::new(bad))),
                None,
                "value {bad:?} must not resolve to a signalable fd"
            );
        }
        // non-UTF-8 value: refused, not a panic.
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(
            ready_fd_to_signal(true, Some(OsStr::from_bytes(b"\xff\x37"))),
            None
        );
        assert_eq!(ready_fd_to_signal(true, None), None);
    }
}

#[cfg(test)]
mod uncapped_notice_tests {
    /// The uncapped-host notice fires exactly ONCE per host, and keeps firing when it cannot record
    /// that it fired.
    ///
    /// A `Once` is per PROCESS and every box is a new process, so the per-process guard alone put
    /// this line on every single box start. That noise is why the warning was gated on an explicit
    /// `--memory` instead, which in turn left a DEFAULT box on a non-delegating host running with
    /// unbounded RAM in silence. The marker is what lets the notice be both quiet and honest.
    #[test]
    fn the_uncapped_host_notice_is_claimed_once() {
        let dir = std::env::temp_dir().join(format!("kern-notice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("uncapped-notice");

        // First call creates the parent chain and claims it; every later call declines.
        assert!(
            super::claim_notice_at(&path),
            "the first call did not claim the notice, so a host would never be told"
        );
        assert!(
            path.exists(),
            "the marker was not written, so the claim cannot be remembered across processes"
        );
        for i in 0..5 {
            assert!(
                !super::claim_notice_at(&path),
                "call {} claimed the notice again: the line would repeat on every box start",
                i + 2
            );
        }

        // Unwritable location: fail LOUD. An unbounded box is worth a repeated line more than it is
        // worth silence, so a path that can never be created must keep returning true.
        let refused = std::path::Path::new("/proc/self/cannot-create-here/marker");
        assert!(
            super::claim_notice_at(refused) && super::claim_notice_at(refused),
            "an unwritable marker silenced the notice instead of repeating it"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod ps_format_tests {
    use super::push_unescaped;

    #[test]
    fn unescape_t_n_and_keep_others() {
        let mut o = String::new();
        push_unescaped(&mut o, "a\\tb\\nc");
        assert_eq!(o, "a\tb\nc");
        let mut o = String::new();
        push_unescaped(&mut o, "plain text");
        assert_eq!(o, "plain text");
        let mut o = String::new();
        push_unescaped(&mut o, "trailing\\");
        assert_eq!(o, "trailing\\");
        let mut o = String::new();
        push_unescaped(&mut o, "\\x kept");
        assert_eq!(o, "\\x kept");
    }
}

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

/// A JSON number field, or `null` when the value is absent (`stats`/`inspect`). One definition so the
/// two emitters render a missing metric the same way.
fn json_num(v: Option<u64>) -> String {
    v.map_or_else(|| "null".to_string(), |n| n.to_string())
}

/// Human-readable byte size - the shared [`kern_common::fmt_bytes`] convention (`ps`/`stats` columns).
pub(crate) fn human_bytes(b: u64) -> String {
    kern_common::fmt_bytes(b)
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
fn sweep_retired_images() -> usize {
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

/// `remove_dir_all` that can also delete an extracted OCI image.
///
/// An image ships directories with their original modes, and real images ship read-only ones: alpine's
/// `/proc` is `r-xr-xr-x`, amazonlinux adds `/root`, `/boot` and `/sbin`. Unlinking a child needs WRITE
/// on its parent directory, so `std::fs::remove_dir_all` stops at the first of them with EACCES, and so
/// does `rm -rf`, which leaves the tree too - but `rm` REPORTS it and exits 1. kern's defect was the
/// other half: it printed to stderr and returned Ok, so `kern gc --images && echo cleaned` printed
/// "cleaned" over an untouched cache while `rm -rf ... && echo cleaned` prints nothing. An earlier
/// version of this comment claimed `rm` exits 0, measured by reading `$?` after a pipe - which reads
/// the exit of `head`, not of `rm`. The rule against that is written down in this project, and it was
/// broken in the act of producing the false claim. 62 such directories sat in this machine's cache,
/// which is why `kern gc --images` had never actually cleared it.
///
/// Also called by `doctor` on overlayfs workdirs, a different shape of tree entirely: their
/// `work/work` is mode 000, created by uid 0 inside a user namespace that maps to the caller's
/// real uid, so the chmod reaches it. The paragraph above describes only the OCI-image caller.
///
/// We own these directories, so the fix is to restore write permission on the way down and then remove.
/// Only ever applied to a path kern created inside its own cache, and only to DIRECTORIES: file modes
/// are irrelevant to unlinking and are left alone. Symlinks are unlinked, never followed, so a link
/// pointing out of the tree cannot lead the chmod anywhere.
pub(crate) fn remove_tree_forced(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    // Every failure names the path AND why. "Permission denied" on its own sent me hunting through 3 GB
    // of cache for the one directory that blocked it: it was owned by uid 100999, a subuid left by a
    // layer built with `--uid-range`. An unprivileged user cannot chmod what it does not own, so that
    // case is genuinely unremovable from here, and the message says so rather than leaving it to be
    // discovered.
    let annotate = |e: std::io::Error, at: &std::path::Path| -> std::io::Error {
        let me = unsafe { libc::getuid() };
        let owner = std::fs::symlink_metadata(at).map(|m| m.uid()).ok();
        let why = match owner {
            Some(u) if u != me => format!(
                "{} is owned by uid {u}, not you - a layer built with --uid-range leaves subuid-owned files that an unprivileged user cannot remove",
                at.display()
            ),
            _ => at.display().to_string(),
        };
        std::io::Error::new(e.kind(), format!("{e} at {why}"))
    };
    let md = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(annotate(e, path)),
    };
    if !md.is_dir() {
        return std::fs::remove_file(path).map_err(|e| annotate(e, path));
    }
    // u+rwx on this directory first, or its own entries cannot be listed or unlinked. An extracted OCI
    // image ships read-only directories with their original modes (alpine's `/proc` is r-xr-xr-x;
    // amazonlinux adds `/root`, `/boot`, `/sbin`), and unlinking a child needs WRITE on its parent, so
    // `std::fs::remove_dir_all` stops at the first one with EACCES. So does `rm -rf`, which leaves the
    // tree, but `rm` reports it and exits 1; kern's defect was printing to stderr and returning Ok.
    // 62 such directories sat in this machine's cache, which is why
    // `kern gc --images` had never actually cleared it.
    let mode = md.permissions().mode();
    if mode & 0o700 != 0o700 {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o700));
    }
    for entry in std::fs::read_dir(path).map_err(|e| annotate(e, path))? {
        let entry = entry.map_err(|e| annotate(e, path))?;
        remove_tree_forced(&entry.path())?;
    }
    std::fs::remove_dir(path).map_err(|e| annotate(e, path))
}

/// Delete build-layer dirs in `L/` not referenced by any `<tag>.layers` manifest. Returns
/// `(count, bytes_freed)`. Only touches `L/<32hex>` entries, never a pulled/built image itself.
fn sweep_orphan_layers(cache: &std::path::Path) -> (usize, u64) {
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

/// Sweep orphaned overlay scratch: `<scratch>/<name>-<pid>/` dirs whose box is no longer live.
/// Returns `(dirs_removed, bytes_freed)`. Shared by `recover` (its whole job) and `gc` (folded in so
/// `gc` is the ONE full local cleanup - previously only `recover` reclaimed scratch, and it was easy
/// to miss, so crashed-box overlay dirs quietly piled up).
fn sweep_orphan_scratch() -> (u32, u64) {
    // `registry::list()` already prunes entries whose process is dead on read; call it to get the
    // set of *live* boxes and to trigger that cleanup.
    let live = registry::list();
    let live_scratch: std::collections::HashSet<String> =
        live.iter().map(|b| b.rootfs.clone()).collect();
    let mut recovered = 0u32;
    let mut freed = 0u64;
    let scratch = scratch_dir();
    if let Ok(entries) = std::fs::read_dir(&scratch) {
        for e in entries.flatten() {
            let path = e.path();
            let merged = path.join("merged");
            // A live box's `rootfs` is its `.../merged` dir; if none matches, this scratch is orphaned.
            if !live_scratch.contains(&merged.to_string_lossy().into_owned()) && path.is_dir() {
                freed += dir_size(&path);
                // Use the chmod-then-remove force cleaner: an overlay leaves a mode-000 `work/work`
                // dir that plain `remove_dir_all` can't traverse (Permission denied) - the bug that made
                // recover a silent no-op while orphans piled up. `gc`/`prune` already use this helper.
                remove_build_tree(&path);
                if !path.exists() {
                    recovered += 1;
                }
            }
        }
    }
    (recovered, freed)
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

/// cgroup v2 CPU period (µs) for `cpu.max` (`cpu.max = "<quota> <period>"`, cores = quota/period).
/// Matches the value the isolation layer uses at box start so a live update stays consistent.
const CPU_PERIOD_US: u64 = 100_000;

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

/// Write one cgroup v2 control file for [`update`]. On failure returns a short reason string. The
/// delegation hint is appended ONLY for the delegation-shaped errnos (EACCES/EPERM/ENOENT/ENODEV); a
/// value the kernel rejects (e.g. EINVAL) is left to speak for itself rather than misattributed to
/// delegation.
fn write_cgroup(cg: &std::path::Path, file: &str, val: &str) -> Result<(), String> {
    std::fs::write(cg.join(file), val).map_err(|e| {
        let delegation = matches!(
            e.raw_os_error(),
            Some(libc::EACCES | libc::EPERM | libc::ENOENT | libc::ENODEV)
        );
        let ctrl = file.split('.').next().unwrap_or(file);
        if delegation {
            format!("{file}: {e} (the {ctrl} controller may not be delegated here)")
        } else {
            format!("{file}: {e}")
        }
    })
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

/// Bounds for [`walk_diff`] against a box that fills its own overlay upper to exhaust the host `kern
/// diff` process. `DIFF_MAX_DEPTH` caps recursion (a box can't stack-overflow the walker); paths are
/// already ~PATH_MAX-bounded, so this is generous belt-and-suspenders. `DIFF_MAX_ENTRIES` caps the
/// collected output against an inode-bomb upper (millions of files) that would otherwise OOM the Vec.
const DIFF_MAX_DEPTH: usize = 4096;
const DIFF_MAX_ENTRIES: usize = 1_000_000;

/// Recursively classify overlay-upper entries into Docker `diff` markers, appending `(marker, in-box
/// absolute path)`. A whiteout (a char device with rdev 0:0) is a deletion `D`; every other entry
/// present in the upper is a change `C` (a changed dir is also recursed). Best-effort: an unreadable
/// subdir is skipped rather than aborting the whole diff. `metadata()` on a `DirEntry` does NOT follow
/// symlinks, so a whiteout or a symlink is classified by its own type, never its target's. Each
/// directory's fd is released (the `ReadDir` is dropped) BEFORE recursing, so open fds don't grow with
/// depth - otherwise a deep tree hits EMFILE and the diff silently truncates.
fn walk_diff(
    root: &std::path::Path,
    dir: &std::path::Path,
    depth: usize,
    out: &mut Vec<(char, String)>,
) {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    if depth > DIFF_MAX_DEPTH || out.len() >= DIFF_MAX_ENTRIES {
        return;
    }
    let mut subdirs: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if out.len() >= DIFF_MAX_ENTRIES {
                break;
            }
            let path = e.path();
            let Ok(md) = e.metadata() else { continue };
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let inbox = format!("/{}", rel.to_string_lossy());
            let ft = md.file_type();
            if ft.is_char_device() && md.rdev() == 0 {
                out.push(('D', inbox)); // overlayfs whiteout = deleted in the box
            } else if ft.is_dir() {
                out.push(('C', inbox));
                subdirs.push(path); // defer: recurse AFTER this dir's fd is released below
            } else {
                out.push(('C', inbox));
            }
        }
    } // `rd` dropped here -> this level's directory fd is freed before we descend
    for sub in subdirs {
        walk_diff(root, &sub, depth + 1, out);
    }
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

/// Print one `kern events` line: `<unix-seconds> box <action> <name> (pid <pid>)`, with `from <old>`
/// appended for a rename. Unix seconds (not a localized clock) keeps it timezone-unambiguous and
/// dependency-free.
fn emit_event(action: &str, name: &str, pid: i32, from: Option<&str>) {
    let t = registry::now_unix();
    match from {
        Some(old) => println!("{t} box {action} {name} (pid {pid}, from {old})"),
        None => println!("{t} box {action} {name} (pid {pid})"),
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

/// `kern images [--json]` - list OCI images pulled into the local cache. Each completed pull leaves
/// a `<sanitized>.ok` sentinel whose *content* is the original image ref, next to the `<sanitized>/`
/// rootfs dir - so we recover the real name, the on-disk size, and when it was pulled.
/// One cached OCI image as shown by `kern images` and the `kern top` Images tab.
pub(crate) struct ImageEntry {
    /// The original ref (`repository:tag`), recovered from the `.ok` sentinel's content.
    pub name: String,
    /// On-disk size in bytes (0 for an empty build - a valid image that added no files).
    pub size: u64,
    /// When it was pulled/built (unix seconds).
    pub pulled: u64,
    /// The image can't be assembled: a multi-layer build whose `.layers` manifest names an `L/` layer
    /// dir that is GONE (swept/deleted), or a sentinel with no payload at all. It would FAIL to run, so
    /// callers show a distinct `dangling` marker rather than a misleading `0 B` (which reads as "empty").
    pub dangling: bool,
}

/// On-disk `(size_bytes, dangling)` of cached image `<stem>`, computed in ONE pass - a flat pulled
/// image (`<stem>/`) or single-diff build (`<stem>.diff/`) is sized by its dir and never dangles; a
/// multi-layer build sums its referenced `L/<key>` dirs AND dangles if any is missing (a present but
/// 0-byte layer is a valid EMPTY build, not dangling); a sentinel with no payload at all dangles. Both
/// `kern images` and the build-history record read this, so size and health can't drift, and each
/// manifest/layer is stat'd once. The layer cache is `<cache>/L` (== [`layer_cache_dir`] when `cache`
/// is [`cache_dir`]), derived from the arg so it stays consistent with the entry and is testable.
fn image_stat(cache: &std::path::Path, stem: &str) -> (u64, bool) {
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

/// The cached OCI images, sorted by name - the SINGLE source for both `kern images` and the `kern top`
/// Images tab, so the CLI and TUI can never drift on which images exist, their sizes, or their health.
pub(crate) fn image_entries() -> Vec<ImageEntry> {
    let cache = cache_dir();
    let mut rows: Vec<ImageEntry> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&cache) {
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) != Some("ok") {
                continue; // skip the `<name>/` dirs, `.lock` files, `scratch/`
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()).map(String::from) else {
                continue;
            };
            // Shown with its implied tag, so every row is a reference you can paste straight back
            // into `--image` or `rmi`. The sentinel records the ref as first written (`alpine` from
            // a pull, `alpine:latest` from a load), and listing the two spellings side by side made
            // one image look like two.
            let name = std::fs::read_to_string(&path)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(|s| kern_oci::normalize_ref(&s))
                .unwrap_or_else(|| stem.clone());
            let (size, dangling) = image_stat(&cache, &stem);
            let pulled = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            rows.push(ImageEntry {
                name,
                size,
                pulled,
                dangling,
            });
        }
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    rows
}

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

/// A stem is a real [`sanitize_ref`] token only when it's non-empty and every byte is `[A-Za-z0-9_-]`.
/// Delete paths gate on this so a **planted** `.ok` filename can never steer a removal outside the
/// cache: e.g. a file literally named `...ok` has `Path::file_stem() == ".."`, which unchecked would
/// make `cache.join(stem)` resolve to the cache's PARENT - `is_safe_stem` rejects it (`.` isn't allowed).
fn is_safe_stem(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The on-disk artifacts of cached image `<stem>`: the flat rootfs dir, a single-diff dir, and the
/// `.layers`/`.base`/`.image`/`.ok`/`.lock` sidecars. ONE place owns this list so every remover (`rmi`,
/// untag, temp-stage drop) deletes the SAME set and can't drift - a leaked `.base`/`.image` would
/// otherwise linger and misclassify a later same-name pull. Best-effort; a missing artifact is fine.
/// `stem` MUST already be a [`sanitize_ref`] token (see [`is_safe_stem`]) - never raw user input.
fn drop_image_artifacts(cache: &std::path::Path, stem: &str) {
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
fn force_remove_dir_all(path: &std::path::Path) {
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
fn remove_image(cache: &std::path::Path, want: &str) -> Option<u64> {
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

/// Reclaim orphaned build layers (`L/` dirs referenced by no image). Safe and non-destructive: every
/// tagged image is kept; only dangling layers are freed. Invoked from the `kern top` Images tab (`p`);
/// the CLI equivalent is `kern gc` (which also prunes dead-box sidecars).
pub(crate) fn image_prune() -> Result<(), Error> {
    let (n, freed) = sweep_orphan_layers(&cache_dir());
    let p = crate::ui::Palette::detect();
    if n == 0 {
        println!("{}nothing to prune - no orphaned layers{}", p.d, p.z);
    } else {
        println!(
            "{}pruned{} {n} orphaned layer{}, freed {}",
            p.g,
            p.z,
            if n == 1 { "" } else { "s" },
            human_bytes(freed)
        );
    }
    Ok(())
}

/// One build record as a JSON object - the single emitter for both `kern builds --json` (an array of
/// these) and `kern build inspect --json` (one of these), so the two can't drift on fields or escaping.
fn build_json(r: &crate::builds::Record) -> String {
    format!(
        "{{\"id\":{},\"tag\":{},\"status\":{},\"duration_ms\":{},\"started\":{},\"size_bytes\":{},\"warnings\":{},\"dockerfile\":{},\"context\":{},\"error\":{}}}",
        json_str(&r.id),
        json_str(&r.tag),
        json_str(r.status.label()),
        r.duration_ms,
        r.started,
        r.size,
        r.warnings,
        json_str(&r.dockerfile),
        json_str(&r.context),
        json_str(&r.error),
    )
}

/// Compact build duration for the `kern builds` table (`ms` / `s` / `m` `s`).
fn fmt_dur(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{}m{}s", ms / 60_000, (ms % 60_000) / 1000)
    }
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
        Some(s) => Some(
            crate::builds::Status::from_label(s)
                .ok_or(Error::Usage("build --status ok|warn|failed|interrupted"))?,
        ),
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
                r.status.label().to_string()
            };
            let status = format!("{sc}{:<11}{}", label, p.z);
            println!(
                "{id} {:<tw$} {status} {:>8} {:>9}  {}",
                truncate(&r.tag, tw),
                fmt_dur(r.duration_ms),
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
        println!("  status     {}", r.status.label());
        println!("  duration   {}", fmt_dur(r.duration_ms));
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

/// On-disk size of cached image `<stem>` - the size half of [`image_stat`]. Used by the build-history
/// record (which needs only the size, not the health flag).
fn image_size(cache: &std::path::Path, stem: &str) -> u64 {
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
fn dir_size_cached(dir: &std::path::Path, stamp_of: &std::path::Path) -> u64 {
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

fn dir_size(dir: &std::path::Path) -> u64 {
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

/// Compact relative age for a duration in seconds (`s`/`m`/`h`/`d`).
fn fmt_age(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86_399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
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

/// Prepare an **untrusted** string for a terminal table: first strip control/escape characters
/// (so a crafted registry name/description or cached image ref can't inject ANSI sequences into the
/// user's terminal), then truncate to at most `max` characters with an `…`.
fn truncate(s: &str, max: usize) -> String {
    let clean = crate::ui::scrub(s); // single definition of "strip terminal escapes"
    if clean.chars().count() <= max {
        return clean;
    }
    let mut t: String = clean.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
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

/// The byte slice of the last `n` lines of `content` (each line keeps its trailing `\n`). A single
/// trailing newline is not counted as an extra empty line, so `tail_lines(b"a\nb\n", 1) == b"b\n"`.
/// Zero-copy: returns a subslice of `content`. `n == 0` yields an empty slice; fewer than `n` lines
/// present yields all of `content`.
fn tail_lines(content: &[u8], n: usize) -> &[u8] {
    if n == 0 {
        return &[];
    }
    // Ignore one trailing newline so the final line is not read as an empty line after it.
    let scan_end = match content.last() {
        Some(b'\n') => content.len() - 1,
        _ => content.len(),
    };
    let mut seen = 0usize;
    let mut i = scan_end;
    while i > 0 {
        i -= 1;
        if content[i] == b'\n' {
            seen += 1;
            if seen == n {
                return &content[i + 1..];
            }
        }
    }
    content
}

/// Read only the last `n` lines of an already-open log `f`, seeking backward in bounded chunks so a
/// small `--tail` off a huge detached-box log costs O(bytes shown) plus one chunk, never a full slurp.
/// (A `--tail` larger than the file simply degrades to a single linear pass, like `read_to_end`.) Line
/// semantics match [`tail_lines`] (each line keeps its `\n`; a single trailing newline is not an extra
/// empty line). Leaves `f`'s cursor mid-file; the caller re-seeks to EOF for `--follow`.
fn tail_file(f: &mut std::fs::File, n: usize) -> Result<Vec<u8>, Error> {
    use std::io::{Read, Seek, SeekFrom};
    let map = |e: std::io::Error| Error::Sandbox(format!("reading log: {e}"));
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut pos = f.seek(SeekFrom::End(0)).map_err(map)?;
    const CHUNK: u64 = 8192;
    // Chunks are read high-offset first; collect them reversed and stitch ONCE at the end. Prepending
    // into one growing buffer would recopy it (and re-scan it for newlines) every iteration - O(size^2)
    // on a pathological `--tail 999999999`; here it stays O(bytes read). Newlines counted incrementally.
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut newlines = 0usize;
    // Walk backward a chunk at a time until the window holds more than `n` newlines (so the n-th line
    // from the end is fully captured - see the `> n` proof in `tail_lines`) or we reach the start of
    // the file (fewer than `n` lines exist -> return them all).
    while pos > 0 {
        let read_len = CHUNK.min(pos);
        pos -= read_len;
        let mut chunk = vec![0u8; read_len as usize];
        f.seek(SeekFrom::Start(pos)).map_err(map)?;
        f.read_exact(&mut chunk).map_err(map)?;
        newlines += chunk.iter().filter(|&&b| b == b'\n').count();
        chunks.push(chunk);
        if newlines > n {
            break;
        }
    }
    // Stitch the chunks back into file order (they were pushed EOF-first).
    let total: usize = chunks.iter().map(Vec::len).sum();
    let mut buf = Vec::with_capacity(total);
    for chunk in chunks.iter().rev() {
        buf.extend_from_slice(chunk);
    }
    Ok(tail_lines(&buf, n).to_vec())
}

/// Stream new appends of an already-open log `f` (from its current read offset) to stdout, polling
/// every 200 ms until the box `(name, pid)` leaves the registry. Panic-free; a stdout write error
/// (a closed pipe) ends the follow quietly. Shared by `kern attach` and `kern logs -f`.
fn follow_log(mut f: std::fs::File, name: &str, pid: i32) -> Result<(), Error> {
    use std::io::{Read, Write};
    let mut buf = [0u8; 8192];
    let stdout = std::io::stdout();
    loop {
        // Drain whatever is currently appended.
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(k) => {
                    let mut lock = stdout.lock();
                    if lock.write_all(&buf[..k]).is_err() {
                        return Ok(());
                    }
                    let _ = lock.flush();
                }
                Err(_) => break,
            }
        }
        // Exact (name,pid) pair: a duplicate same-name entry must not make a live box read as exited.
        if !registry::pair_alive(name, pid) {
            return Ok(());
        }
        unsafe { libc::usleep(200_000) }; // 200 ms - cheap follow poll
    }
}

#[cfg(test)]
mod image_size_is_memoised {
    use super::{dir_size, dir_size_cached};

    /// `kern images` walked every byte of the cache on every call: 43 ms on a 2.6 GB cache of 53
    /// images, for a number that cannot have changed, since an extracted image is immutable once its
    /// `.ok` sentinel is written. Memoised against that sentinel's mtime it is 2.2 ms.
    ///
    /// The test asserts the two things that make the cache safe rather than merely fast: it returns
    /// the SAME value as the walk, and a changed stamp makes it recompute instead of serving a stale
    /// total. A cache that is only checked for speed is how a wrong size ships.
    #[test]
    fn memoised_size_matches_the_walk_and_reacts_to_a_new_stamp() {
        let root = std::env::temp_dir().join(format!("kern-sz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("img");
        std::fs::create_dir_all(dir.join("sub")).expect("mkdir");
        std::fs::write(dir.join("a"), vec![0u8; 1000]).expect("write");
        std::fs::write(dir.join("sub/b"), vec![0u8; 2000]).expect("write");
        let stamp = root.join("img.ok");
        std::fs::write(&stamp, b"ref").expect("stamp");

        let walked = dir_size(&dir);
        assert_eq!(walked, 3000, "the walk itself must be right first");
        assert_eq!(
            dir_size_cached(&dir, &stamp),
            walked,
            "cold read matches the walk"
        );
        assert_eq!(
            dir_size_cached(&dir, &stamp),
            walked,
            "warm read matches too"
        );

        // Grow the tree WITHOUT touching the stamp file: the cache is entitled to keep serving the old
        // total. This is the INVARIANT the function documents - nothing writes into an image
        // directory after its sentinel exists - and the test pins it rather than pretending the cache
        // can detect a change it is not keyed on.
        std::fs::write(dir.join("c"), vec![0u8; 500]).expect("write");
        assert_eq!(
            dir_size_cached(&dir, &stamp),
            walked,
            "same stamp, same answer: the cache is keyed on the stamp, not on a guess"
        );

        // A sentinel rewritten to a DIFFERENT LENGTH inside the same second must still invalidate:
        // mtime alone left `kern rmi x && kern pull x` able to serve the old image's size.
        std::fs::write(&stamp, b"a-longer-reference").expect("restamp same second");
        assert_eq!(
            dir_size_cached(&dir, &stamp),
            3500,
            "a sentinel of a different size must force a recompute even within one second"
        );

        // Rewrite the stamp, as a re-pull does, and the size must be recomputed.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(&stamp, b"ref2").expect("restamp");
        assert_eq!(
            dir_size_cached(&dir, &stamp),
            3500,
            "a new stamp must force a recompute"
        );

        let _ = super::remove_tree_forced(&root);
    }
}

#[cfg(test)]
mod gc_clears_read_only_image_dirs {
    use super::remove_tree_forced;

    /// An extracted OCI image ships read-only directories with their original modes, and unlinking a
    /// child needs WRITE on its parent, so `std::fs::remove_dir_all` stops at the first one with
    /// EACCES. `rm -rf` leaves the tree too, but reports it and exits 1. That is why `kern gc --images` had never cleared
    /// a cache containing alpine (whose `/proc` is `r-xr-xr-x`): 62 such directories sat in the one on
    /// this machine. Asserted BOTH ways, so the test cannot pass for the wrong reason if the fix is
    /// reverted: the standard call must FAIL on this fixture first.
    #[test]
    fn forced_removal_deletes_what_remove_dir_all_cannot() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("kern-rtf-{}", std::process::id()));
        let _ = super::remove_tree_forced(&root);
        let ro = root.join("img/proc");
        std::fs::create_dir_all(&ro).expect("mkdir");
        std::fs::write(ro.join("kmsg"), b"x").expect("write");
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).expect("chmod");

        assert!(
            std::fs::remove_dir_all(root.join("img")).is_err(),
            "remove_dir_all unexpectedly succeeded - the fixture no longer reproduces the bug"
        );

        remove_tree_forced(&root).expect("forced removal");
        assert!(!root.exists(), "the tree must be gone");
    }
}

#[cfg(test)]
mod logs_tail_tests {
    use super::tail_lines;

    #[test]
    fn tail_lines_counts_and_boundaries() {
        assert_eq!(tail_lines(b"a\nb\nc\n", 2), b"b\nc\n");
        assert_eq!(tail_lines(b"a\nb\nc\n", 1), b"c\n");
        assert_eq!(tail_lines(b"a\nb\nc", 2), b"b\nc"); // no trailing newline
        assert_eq!(tail_lines(b"a\nb\nc\n", 5), b"a\nb\nc\n"); // fewer lines than n
        assert_eq!(tail_lines(b"only\n", 3), b"only\n");
    }

    #[test]
    fn tail_lines_edge_cases() {
        assert_eq!(tail_lines(b"", 3), b"");
        assert_eq!(tail_lines(b"a\nb\n", 0), b"");
        assert_eq!(tail_lines(b"no newline", 1), b"no newline");
        assert_eq!(tail_lines(b"x\n", 1), b"x\n");
    }

    // The bounded backward-seek reader must return exactly what `tail_lines` would over the whole
    // file, including across multiple 8 KiB chunks, without a trailing newline, and on an empty file.
    #[test]
    fn tail_file_matches_tail_lines() {
        use super::tail_file;
        let path = std::env::temp_dir().join(format!("kern-tailfile-{}", std::process::id()));
        let check = |content: &[u8], n: usize| {
            std::fs::write(&path, content).unwrap();
            let mut f = std::fs::File::open(&path).unwrap();
            assert_eq!(
                tail_file(&mut f, n).unwrap(),
                tail_lines(content, n),
                "len={} n={n}",
                content.len()
            );
        };
        // Multi-chunk (> 8192 B) so the backward loop runs several iterations, trailing newline.
        let mut big = Vec::new();
        for i in 0..5000 {
            big.extend_from_slice(format!("line {i}\n").as_bytes());
        }
        for &n in &[0usize, 1, 3, 50, 5000, 9999, usize::MAX] {
            check(&big, n);
        }
        // Multi-chunk WITHOUT a trailing newline (the `> n` trailing-nl edge across chunk seams).
        let mut big_no_nl = big.clone();
        assert_eq!(big_no_nl.pop(), Some(b'\n'));
        for &n in &[1usize, 3, 5000, usize::MAX] {
            check(&big_no_nl, n);
        }
        check(
            &{
                let mut e = vec![b'x'; 8191];
                e.push(b'\n');
                e
            },
            1,
        ); // exactly one CHUNK (8192 B): last backward read lands on pos == 0
        check(b"\n\n\n", 2); // only newlines
        check(b"\n\n\n", usize::MAX);
        check(b"alpha\nbeta\ngamma", 2); // single chunk, no trailing nl
        check(b"", 3); // empty
        check(b"solo", 1); // one line, no newline
        let _ = std::fs::remove_file(&path);
    }
}

/// The current contents of a box's newest log, for the `kern top` log overlay (`Enter`). `None` if the
/// box has produced no log yet; errors are swallowed (the TUI shows an empty pane rather than blowing
/// up mid-frame).
pub(crate) fn box_log_tail(name: &str) -> Option<String> {
    let path = newest_log(name).ok().flatten()?;
    std::fs::read_to_string(path).ok()
}

/// The newest `<name>-<pid>.log` under the logs dir, or `None` if the box has produced no log.
fn newest_log(name: &str) -> Result<Option<PathBuf>, Error> {
    let dir = registry::logs_dir().map_err(|e| Error::Sandbox(format!("logs dir: {e}")))?;
    let prefix = format!("{name}-");
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let fname = e.file_name();
            let fname = fname.to_string_lossy();
            // Require exactly `<name>-<digits>.log`: strip the prefix and `.log`, then the middle must
            // be an all-digit PID. A bare `starts_with(prefix)` would let box `foo` match `foo-bar`'s
            // log file `foo-bar-<pid>.log` (box names may legally contain '-'), leaking another box's
            // output through `kern logs`/`attach`.
            let is_ours = fname
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(".log"))
                .is_some_and(|mid| !mid.is_empty() && mid.bytes().all(|b| b.is_ascii_digit()));
            if is_ours {
                if let Ok(mtime) = e.metadata().and_then(|m| m.modified()) {
                    if newest.as_ref().is_none_or(|(t, _)| mtime > *t) {
                        newest = Some((mtime, e.path()));
                    }
                }
            }
        }
    }
    Ok(newest.map(|(_, p)| p))
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

/// Uptime as `Xh YYm` / `Xm YYs` / `Xs` (matches the `kern top` style).
pub(crate) fn fmt_uptime(s: u64) -> String {
    if s >= 3600 {
        format!("{}h {:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
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

/// One thing `kern uninstall` would remove: where it is, how big, and whether it is user DATA.
struct Removable {
    path: PathBuf,
    what: &'static str,
    /// Data the user made (named volumes, a hand-written config) as opposed to a cache kern can
    /// refetch. The plan lists these separately because losing them is not the same as losing bytes
    /// that a `pull` restores.
    is_user_data: bool,
    bytes: u64,
    /// The path itself is a symlink. `dir_bytes` deliberately does not follow one, so the size reads 0 and
    /// the plan claimed there was nothing there while a real tree sat on the other side. Removing the link
    /// is still the right act (following it would delete outside what kern owns), but reporting 0 B is not:
    /// it tells the reader the cache is empty when it is merely elsewhere.
    is_symlink: bool,
}

/// Recursive DISK USAGE of a tree, following no symlinks. Best-effort: an unreadable subtree
/// contributes 0 rather than aborting the plan, because this number exists to inform a decision.
///
/// Two details, both measured on a real cache of 85302 files:
///
/// - **Each inode counts once.** 4434 of those files were hardlinks, which the layer store creates for
///   blobs shared between images. Summing `len()` per directory entry reported **5.22 GiB** where
///   removing the tree actually freed **3.38 GiB**: a 55% overstatement on the one figure a reader uses
///   to decide whether this is worth doing.
/// - **Allocated blocks, not apparent length.** `du` agrees with allocation, and on 85k mostly-small
///   files the rounding is not noise (it added 0.26 GiB here). It also makes a sparse file count as what
///   it occupies rather than what it claims.
///
/// Two limits it has by construction, and does not hide:
///
/// - **Copy-on-write.** On btrfs or ZFS, blocks whose extents are shared with a snapshot are not freed by
///   removing the file, so on those filesystems this is an upper bound rather than a measurement.
/// - **Per item, not per plan.** Each row's size stands on its own, which is what a reader comparing rows
///   wants; the consequence is that an inode hardlinked ACROSS two rows is counted in both, so the total
///   can overstate. Within a row (the layer store, where sharing actually happens) it cannot.
fn dir_bytes(p: &std::path::Path) -> u64 {
    let mut seen = std::collections::HashSet::new();
    disk_usage(p, &mut seen)
}

fn disk_usage(p: &std::path::Path, seen: &mut std::collections::HashSet<(u64, u64)>) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let Ok(md) = std::fs::symlink_metadata(p) else {
        return 0;
    };
    if md.file_type().is_symlink() {
        return 0;
    }
    // A hardlink already counted contributes nothing more: the blocks are the same blocks.
    if md.nlink() > 1 && !seen.insert((md.dev(), md.ino())) {
        return 0;
    }
    let own = md.blocks() * 512;
    if !md.is_dir() {
        return own;
    }
    let Ok(rd) = std::fs::read_dir(p) else {
        return own;
    };
    own + rd
        .flatten()
        .map(|e| disk_usage(&e.path(), seen))
        .sum::<u64>()
}

/// Are we the kern inside a WSL2 distro? `WSL_DISTRO_NAME` is set by WSL for every process it starts;
/// the osrelease check catches a process that inherited a stripped environment.
///
/// It matters to `uninstall` alone: on Windows the pieces a user sees (`kern.exe`, the PATH entry) live
/// OUTSIDE this filesystem, so removing the Linux binary from in here leaves a shim pointing at a distro
/// with no kern. Recoverable - the shim says how - but not something to discover afterwards.
fn in_wsl() -> bool {
    if std::env::var_os("WSL_DISTRO_NAME").is_some() {
        return true;
    }
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| {
            let s = s.to_ascii_lowercase();
            s.contains("microsoft") || s.contains("wsl")
        })
        .unwrap_or(false)
}

/// Is `exe` a kern that an installer put where an installer puts it? Only then is deleting it this
/// verb's business: a kern built in a source tree, or one somebody dropped in `/opt`, is not.
///
/// Compares FILE IDENTITY, `(st_dev, st_ino)`, not path strings. `current_exe()` resolves symlinks, so a
/// packaged install where `/usr/bin/kern` is a symlink into `/usr/lib/kern/` reports the resolved target,
/// which matches none of the candidate paths as text: string comparison refused to remove a perfectly
/// legitimate install. Measured, with `~/.local/bin/kern` symlinked at a copy elsewhere. Identity also
/// absorbs the harmless spellings that broke the string form: a trailing slash, `bin/../bin`, `~`.
///
/// A build output in a source tree still answers false, because no candidate path points at it.
fn is_installed_binary(exe: &std::path::Path, home: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(me) = std::fs::metadata(exe) else {
        return false;
    };
    [
        home.join(".local/bin/kern"),
        PathBuf::from("/usr/local/bin/kern"),
        PathBuf::from("/usr/bin/kern"),
    ]
    .iter()
    .any(|cand| {
        std::fs::metadata(cand)
            .map(|c| c.dev() == me.dev() && c.ino() == me.ino())
            .unwrap_or(false)
    })
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

/// `kern save <image> [-o file]` - export a cached image to a `docker load`-compatible tar (offline /
/// air-gapped transfer). Materializes the image to one rootfs (like `push`), then writes the archive.
/// Normalise an image ref to a `repo:tag` that `docker load` accepts: append `:latest` when the ref
/// carries no tag. A registry port (`localhost:5000/img`) is not a tag - only a `:` in the LAST path
/// component (after the final `/`) counts, so `localhost:5000/app` → `localhost:5000/app:latest`.
fn ensure_repo_tag(image: &str) -> String {
    let last = image.rsplit('/').next().unwrap_or(image);
    if last.contains(':') {
        image.to_string()
    } else {
        format!("{image}:latest")
    }
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

/// The write-end fd of the freeze file, published for the signal handler while a commit holds a box
/// frozen. `-1` when no commit is freezing. A signal that would kill the commit process (and so skip the
/// `FreezeGuard::drop` thaw) is caught, the box is thawed via this fd with an async-signal-safe raw
/// `write`, and the signal is re-raised with its default disposition.
static FREEZE_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Async-signal-safe: thaw the frozen box (raw `write` of "0") then re-raise `sig` so the process still
/// dies as the signal intends. Installed with `SA_RESETHAND`, so the disposition is already reset to
/// `SIG_DFL` on entry and the re-raise takes the default action. Only `write` and `raise` are used here,
/// both on POSIX's async-signal-safe list (`signal()` is NOT guaranteed to be, so it is avoided).
extern "C" fn thaw_on_fatal_signal(sig: i32) {
    let fd = FREEZE_FD.load(std::sync::atomic::Ordering::SeqCst);
    if fd >= 0 {
        unsafe { libc::write(fd, b"0".as_ptr() as *const libc::c_void, 1) };
    }
    unsafe { libc::raise(sig) };
}

/// RAII cgroup-freezer guard: freezes a box's cgroup on construction and thaws it on drop. Used by
/// `commit` to stop the workload for the duration of the rootfs snapshot (a frozen cgroup runs no task,
/// so no file can be swapped mid-copy). `thaw_path` is `Some` ONLY when this guard is the one that
/// transitioned the cgroup 0 -> 1; if the box has no dedicated cgroup, the write fails, or the box was
/// ALREADY frozen (the user ran `kern pause`), it is `None` and drop leaves the freeze state untouched,
/// so committing a paused box never silently un-pauses it.
///
/// Drop alone is NOT a sufficient safety net: SIGINT (Ctrl-C), SIGTERM, `process::exit`, and
/// `panic = "abort"` all skip destructors, which would leave the box frozen forever. So while WE hold the
/// freeze, SIGINT/SIGTERM/SIGHUP are trapped by [`thaw_on_fatal_signal`] (which thaws and re-raises), and
/// `kern stop`/`kern unpause` thaw a box they find frozen, giving a recovery path even for SIGKILL/OOM
/// that no handler can catch. The freeze is never a state you can only leave if a destructor ran.
struct FreezeGuard {
    thaw_path: Option<std::path::PathBuf>,
    freeze_fd: i32,
    old_handlers: Vec<(i32, libc::sigaction)>,
}

impl FreezeGuard {
    const TRAP: [i32; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

    fn freeze(box_pid: i32) -> FreezeGuard {
        let none = || FreezeGuard {
            thaw_path: None,
            freeze_fd: -1,
            old_handlers: Vec::new(),
        };
        let Some(cg) = registry::box_cgroup(box_pid) else {
            return none();
        };
        let freeze = cg.join("cgroup.freeze");
        // Preserve a pre-existing freeze: if the box is already paused, snapshot under it and do NOT thaw
        // on drop (that would un-pause a box the user deliberately paused). NOTE: `cgroup.freeze` has no
        // compare-and-swap, so a `kern pause` racing in the window between this read and our write below
        // could be undone by our drop-thaw. The window is tiny (a pause landing during an active commit)
        // and the consequence is a resumed box, not a security boundary crossing; a lossless fix isn't
        // possible with a plain cgroup file, so this is a documented known window rather than a guarantee.
        let already_frozen = std::fs::read_to_string(&freeze)
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        if already_frozen {
            return none();
        }
        if std::fs::write(&freeze, "1").is_err() {
            return none();
        }
        // The freeze is asynchronous; wait (bounded) until the cgroup reports `frozen 1` so the snapshot
        // starts only once every task is actually stopped. If it never settles within the budget, warn
        // and proceed rather than block commit forever, so the operator knows the TOCTOU protection did
        // not fully engage for this snapshot.
        let events = cg.join("cgroup.events");
        let mut settled = false;
        for _ in 0..200 {
            match std::fs::read_to_string(&events) {
                Ok(s) if s.lines().any(|l| l.trim() == "frozen 1") => {
                    settled = true;
                    break;
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }
        if !settled {
            eprintln!(
                "kern: warning: box did not report 'frozen' within 1s; the commit snapshot proceeds \
                 WITHOUT the freeze, so a concurrent write could race it"
            );
        }
        // Arm the signal-safe thaw: publish an fd to the freeze file and trap the interactive/kill signals
        // that would otherwise skip Drop and strand the box frozen.
        let mut freeze_fd = -1;
        let mut old_handlers = Vec::new();
        let cpath = std::ffi::CString::new(freeze.as_os_str().as_encoded_bytes()).ok();
        if let Some(cp) = cpath {
            freeze_fd = unsafe { libc::open(cp.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
            if freeze_fd >= 0 {
                FREEZE_FD.store(freeze_fd, std::sync::atomic::Ordering::SeqCst);
                for &sig in &Self::TRAP {
                    unsafe {
                        let mut new: libc::sigaction = std::mem::zeroed();
                        new.sa_sigaction = thaw_on_fatal_signal as extern "C" fn(libc::c_int)
                            as libc::sighandler_t;
                        libc::sigemptyset(&mut new.sa_mask);
                        // SA_RESETHAND: the kernel resets the handler to SIG_DFL before invoking it, so the
                        // handler's re-raise dies by default action without any (non-async-signal-safe)
                        // signal() call. Restore-via-sigaction on Drop covers the normal path.
                        new.sa_flags = libc::SA_RESETHAND;
                        let mut old: libc::sigaction = std::mem::zeroed();
                        if libc::sigaction(sig, &new, &mut old) == 0 {
                            old_handlers.push((sig, old));
                        }
                    }
                }
            }
        }
        FreezeGuard {
            thaw_path: Some(freeze),
            freeze_fd,
            old_handlers,
        }
    }
}

impl Drop for FreezeGuard {
    fn drop(&mut self) {
        // Restore the original signal handlers and stop publishing the fd BEFORE the normal thaw.
        for (sig, old) in &self.old_handlers {
            unsafe { libc::sigaction(*sig, old, std::ptr::null_mut()) };
        }
        if self.freeze_fd >= 0 {
            FREEZE_FD.store(-1, std::sync::atomic::Ordering::SeqCst);
        }
        if let Some(p) = &self.thaw_path {
            let _ = std::fs::write(p, "0");
        }
        if self.freeze_fd >= 0 {
            unsafe { libc::close(self.freeze_fd) };
        }
    }
}

/// The mount points inside a box's mount namespace, box-root-relative (e.g. `/proc`, `/dev`, `/dev/shm`,
/// `/sys/fs/cgroup`, and every `-v` volume / workspace / secret), EXCLUDING the root `/` itself. Read
/// from `/proc/<pid1>/mountinfo` (field 5 is the mount point). Used by `commit` to skip everything that
/// is not the image's own filesystem. `mountinfo` octal-escapes space/tab/newline/backslash in the path.
fn box_mount_points(pid1: i32) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    let Ok(body) = std::fs::read_to_string(format!("/proc/{pid1}/mountinfo")) else {
        return set;
    };
    for line in body.lines() {
        // Fields up to the optional-fields marker are fixed; the mount point is field 5 (index 4).
        if let Some(mp) = line.split_whitespace().nth(4) {
            let unescaped = unescape_mountinfo(mp);
            if unescaped != "/" {
                set.insert(unescaped);
            }
        }
    }
    set
}

/// Decode `mountinfo`'s octal escapes (`\040` space, `\011` tab, `\012` newline, `\134` backslash).
fn unescape_mountinfo(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let code = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(code as char);
            i += 4;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// Recursively copy a box's merged rootfs at `src_root` into `dst_root`, skipping the box-root-relative
/// paths in `skip` (its nested mounts: pseudo-fs, bind volumes, secrets). The overlay is read through
/// `/proc/<pid1>/root`, so the kernel has already resolved whiteouts/opaque dirs; a plain recursive copy
/// captures the merged view. Symlinks are copied verbatim (NEVER followed), directories are recreated
/// with their mode, regular files are copied with their permission bits; devices / fifos / sockets are
/// skipped (not image content). Descent is via `read_dir`, so a symlinked directory is copied as a link
/// and never traversed into: a box-planted symlink cannot steer the copy outside the box root.
fn copy_rootfs_snapshot(
    src_root: &std::path::Path,
    dst_root: &std::path::Path,
    skip: &std::collections::HashSet<String>,
) -> Result<(), Error> {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    std::fs::create_dir_all(dst_root).map_err(|e| Error::Sandbox(format!("commit mkdir: {e}")))?;
    // Each frame: (source dir, destination dir, box-root-relative path of the source dir).
    let mut stack = vec![(
        src_root.to_path_buf(),
        dst_root.to_path_buf(),
        "/".to_string(),
    )];
    while let Some((sdir, ddir, rel)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&sdir) else {
            continue;
        };
        for ent in entries.flatten() {
            let name = ent.file_name();
            let child_rel = if rel == "/" {
                format!("/{}", name.to_string_lossy())
            } else {
                format!("{rel}/{}", name.to_string_lossy())
            };
            if skip.contains(&child_rel) {
                continue; // a nested mount: proc/sys/dev/shm, a -v volume, workspace, or a secret
            }
            let sp = ent.path();
            let dp = ddir.join(&name);
            let Ok(md) = std::fs::symlink_metadata(&sp) else {
                continue;
            };
            let ft = md.file_type();
            let mode = md.mode() & 0o7777;
            if ft.is_symlink() {
                if let Ok(target) = std::fs::read_link(&sp) {
                    let _ = symlink(&target, &dp);
                }
            } else if ft.is_dir() {
                let _ = std::fs::create_dir(&dp);
                let _ = std::fs::set_permissions(&dp, std::fs::Permissions::from_mode(mode));
                stack.push((sp, dp, child_rel));
            } else if ft.is_file() && std::fs::copy(&sp, &dp).is_ok() {
                let _ = std::fs::set_permissions(&dp, std::fs::Permissions::from_mode(mode));
            }
        }
    }
    Ok(())
}

/// Copy from an image's KERNEL-MERGED overlay view into `out_dir`, honouring overlay opaque/whiteout
/// semantics so a file DELETED in an upper layer (`rm -rf dir && mkdir dir` → an OPAQUE directory, or a
/// per-file `.wh.` whiteout) can never resurface. This is the ONE correct reader for a ≥2-layer image:
/// a hand-rolled top-first / bottom-up `cp -a` of the RAW layer dirs ignores the opaque xattr and leaks
/// the deleted file (a real confidentiality bug - a secret `rm`'d in a build step reappearing in a
/// `COPY --from` or a pushed image). Letting the KERNEL present the merged view is the only way that
/// honours opaque + whiteout + redirect_dir + metacopy - the kernel is the authority, not our code.
///
/// HOW (no box, no `newuidmap`, no pseudo-fs, no external `cp`/`tar`): open an fd on `out_dir` (the copy
/// DESTINATION) FIRST - on the host, before any namespace work - then fork a child that
///   1. `unshare(CLONE_NEWUSER | CLONE_NEWNS)` and writes a SINGLE-UID self map (`0 <euid> 1`) - this
///      alone grants CAP_SYS_ADMIN *inside the new userns*, enough to mount an overlay, WITHOUT the
///      setuid `newuidmap` helper (that's only needed to map a *range* of subuids). No `/etc/subuid`.
///   2. mounts the `chain` as a READ-ONLY overlay (`MS_RDONLY|MS_NODEV|MS_NOSUID`) on a private temp
///      mountpoint. No `/proc`, `/dev`, `/sys` is mounted - so the merged view contains ONLY the image's
///      files (the disk-filling `/proc/<pid>` copy of a box-based approach is not even representable).
///   3. resolves every source path with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` rooted at the
///      mount - so the untrusted `src_rel` is confined BY CONSTRUCTION: a `..` is kernel-clamped to the
///      mount root, and an in-image symlink with an absolute target (`/app -> /etc`) resolves inside the
///      IMAGE's `/etc`, never the host's. (Both `..`-escape and in-image-absolute-symlink-escape were
///      verified to read host files with a naive `cp`; `RESOLVE_IN_ROOT` closes both - `cp`'s
///      `--no-dereference` only guards the FINAL component, not parent components, so it is NOT enough.)
///   4. copies with an in-process recursive copier (regular files via `copy_file_range` + read/write
///      fallback, directories recursively, symlinks verbatim) into the pre-opened `out_fd` - no external
///      binary, so it works even on a `scratch`/distroless image. `src_rel = None` copies the whole
///      rootfs (push squash); `Some(p)` copies that one path by basename (a `COPY --from`).
///
/// On `_exit` the child's mount+user namespaces die, unmounting the overlay BY CONSTRUCTION (no umount
/// bookkeeping, no leaked mount holding deleted lower files). Only called for a ≥2-layer chain (where
/// cross-layer opaque is possible); a single-layer/flat image is already merged and copied directly.
fn merged_view_extract(
    chain: &[String],
    src_rel: Option<&str>,
    out_dir: &std::path::Path,
) -> Result<(), Error> {
    // `chain` is ALREADY top-first (the caller split `resolve_image`'s `top:…:base` on ':'), and
    // overlayfs `lowerdir=` shadows left-to-right (leftmost wins) - so we join it AS-IS (no reverse).
    // Getting this order wrong silently defeats the opaque (base would shadow top), re-leaking the
    // deleted file. The RO mount needs only lowerdir. The opts CString outlives the fork.
    let lower = chain.join(":"); // top:…:base, order-preserving
    let opts = cstring(&format!("lowerdir={lower}"))?;
    // Defence-in-depth (the kernel `openat2(RESOLVE_IN_ROOT)` already confines every component): reject a
    // `..` path COMPONENT up front with a clear error. `None` = whole-rootfs push.
    if let Some(p) = src_rel {
        if p.trim_start_matches('/').split('/').any(|c| c == "..") {
            return Err(Error::Build(format!(
                "COPY --from source '{p}' contains a '..' component (refused)"
            )));
        }
    }
    // Open the DESTINATION as an fd on the host, BEFORE any namespace work. It stays valid in the child
    // (an fd isn't re-resolved), giving it a handle to the out dir to copy INTO without ever naming a
    // host path - the only host object reachable from the confined child.
    let out_fd = {
        use std::os::unix::io::IntoRawFd;
        std::fs::File::open(out_dir)
            .map_err(|e| Error::Oci(format!("merged-view: open out dir: {e}")))?
            .into_raw_fd()
    };
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    // FORK SAFETY: the child allocates (the copier uses `format!`/`CString`), which is only safe after
    // `fork()` when no OTHER thread could hold the allocator lock - i.e. the process is single-threaded.
    // `kern build`/`push` run on a synchronous single-threaded `main` (background threads live only in the
    // run/box paths), so this holds today. Enforce it as a HARD runtime check (not a debug_assert, which
    // vanishes in release - the fork-safety it guards would then be unprotected exactly in production): a
    // future worker-pool/pre-fork thread gets a clean error here instead of a rare malloc deadlock.
    if !single_threaded() {
        unsafe { libc::close(out_fd) };
        return Err(Error::Oci(
            "merged-view: refusing to fork in a multi-threaded process (fork-safety)".into(),
        ));
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe { libc::close(out_fd) };
        return Err(Error::Oci("merged-view: fork failed".into()));
    }
    if pid == 0 {
        // ---- CHILD: sets up the ns/mount and copies; never returns (always `_exit`). ----
        merged_view_child(&opts, out_fd, src_rel, euid, egid);
    }
    // ---- PARENT: close our copy of the out fd, reap the child, map its exit code to a precise error. ----
    unsafe { libc::close(out_fd) };
    let mut status = 0i32;
    if crate::eintr::waitpid(pid, &mut status, 0) < 0 {
        return Err(Error::Oci("merged-view: waitpid failed".into()));
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        return Ok(());
    }
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    // 107 = openat2 ENOSYS (kernel < 5.6); 108 = the source path doesn't exist in the MERGED view (e.g.
    // an opaque dir correctly hid it); 120 = the tree is nested past MERGED_COPY_MAX_DEPTH. Each gets a
    // precise message; everything else is a generic extract failure with the stage code for diagnosis.
    match code {
        107 => Err(Error::Oci(
            "reading the image's merged view needs openat2 (Linux 5.6+); this kernel is older"
                .into(),
        )),
        108 => Err(Error::Build(
            "COPY --from source does not exist in the stage's final filesystem".into(),
        )),
        120 => Err(Error::Build(
            "COPY --from source tree is nested too deeply (refused)".into(),
        )),
        _ => Err(Error::Oci(format!(
            "reading the image's merged overlay view failed (extract stage {code})"
        ))),
    }
}

/// The forked child of [`merged_view_extract`]. Sets up the namespaces + RO overlay mount, opens the
/// merged view as a dirfd, resolves the source path CONFINED to it via `openat2(RESOLVE_IN_ROOT)`, then
/// copies it into the pre-opened `out_fd` with an in-process recursive copier - NO chroot, NO `/proc`,
/// NO external `cp`/`tar` (so it works even on a `scratch`/distroless image with no binaries). Each
/// failure `_exit`s a distinct code so the parent can pinpoint the stage.
///
/// The child is the only thread in this process after fork (a `kern build` is single-threaded here), so
/// the copier may allocate; the map-writing that precedes it stays allocation-free out of habit and to
/// keep it robust if that ever changes.
fn merged_view_child(
    opts: &std::ffi::CStr,
    out_fd: libc::c_int,
    src_rel: Option<&str>,
    euid: libc::uid_t,
    egid: libc::gid_t,
) -> ! {
    unsafe {
        // 1. New user + mount namespace.
        if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
            libc::_exit(101);
        }
        // Single-uid self map: `deny` setgroups (required before writing gid_map unprivileged), then
        // `0 <euid> 1` / `0 <egid> 1`. Grants CAP_SYS_ADMIN in the new userns with no `newuidmap` helper.
        if !write_proc_self(b"/proc/self/setgroups\0", b"deny")
            || !write_proc_self_map(b"/proc/self/uid_map\0", euid)
            || !write_proc_self_map(b"/proc/self/gid_map\0", egid)
        {
            libc::_exit(102);
        }
        // Make our mount namespace private so the overlay mount can't propagate back to the host.
        if libc::mount(
            c"none".as_ptr(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) != 0
        {
            libc::_exit(103);
        }
        // 2. Mount the merged view RO on a private mountpoint (relative to CWD at fork time).
        let mnt = c".kern-merged";
        libc::mkdir(mnt.as_ptr(), 0o700);
        if libc::mount(
            c"overlay".as_ptr(),
            mnt.as_ptr(),
            c"overlay".as_ptr(),
            (libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID) as libc::c_ulong,
            opts.as_ptr() as *const libc::c_void,
        ) != 0
        {
            libc::_exit(104);
        }
        // 3. Open the merged view as a dirfd - the ROOT for all confined source resolution.
        let root_fd = libc::open(mnt.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        if root_fd < 0 {
            libc::_exit(105);
        }
        // 4. Copy. `None` = whole rootfs (push): copy the root dir itself INTO out_fd. `Some(p)` = a
        // single COPY --from path, resolved confined and copied by basename into out_fd.
        let code = match src_rel {
            None => copy_confined_tree(root_fd, ".", out_fd, None, 0),
            Some(p) => {
                let rel = p.trim_start_matches('/');
                // The basename becomes the destination entry name (Docker's `COPY --from x/y .` → `./y`).
                let name = std::path::Path::new(rel)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned());
                copy_confined_tree(root_fd, rel, out_fd, name.as_deref(), 0)
            }
        };
        libc::_exit(code);
    }
}

/// Recursively copy `src_rel` (resolved CONFINED under `root_fd` via `openat2(RESOLVE_IN_ROOT)`) into
/// `dst_fd`. `dst_name` is the destination entry name (COPY --from: the source's basename); `None` means
/// copy the CONTENTS of a directory `src_rel` into `dst_fd` (the whole-rootfs push case, `src_rel="."`).
/// Returns 0 on success or a small non-zero code identifying the failing operation. Preserves regular
/// files (via `copy_file_range` with a read/write fallback), directories (recursive), and symlinks
/// (verbatim, never dereferenced - matching `cp -a`); best-effort mode/owner/mtime; device/fifo are
/// skipped gracefully (rootless can't `mknod`, and they don't appear in a COPY --from binary/tree).
/// Maximum directory nesting the copier will descend. A hostile ≥2-layer image can author an arbitrarily
/// deep tree (`a/a/a/…`); without a cap the recursion would overflow the child's native stack (SIGSEGV,
/// an uncontrolled abort). This bound is far above any real image's depth, so it only ever trips on an
/// adversarial tree, where it returns a clean error code instead of crashing.
const MERGED_COPY_MAX_DEPTH: u32 = 256;

unsafe fn copy_confined_tree(
    root_fd: libc::c_int,
    src_rel: &str,
    dst_fd: libc::c_int,
    dst_name: Option<&str>,
    depth: u32,
) -> i32 {
    if depth > MERGED_COPY_MAX_DEPTH {
        return 120; // too deep - refuse rather than overflow the stack (parent surfaces a clean error)
    }
    // Resolve the source CONFINED to root_fd: `openat2(RESOLVE_IN_ROOT)` clamps `..` to root_fd and
    // reinterprets absolute in-image symlinks relative to it; `RESOLVE_NO_MAGICLINKS` blocks /proc-style
    // magic-link escapes. First open O_PATH|O_NOFOLLOW to classify the entry WITHOUT following a final
    // symlink; then reopen readable with a SECOND openat2 (files/dirs) - reopening an O_PATH fd readable
    // needs /proc (absent here), so a fresh confined openat2 is the clean way.
    let sfd = openat2_in_root(root_fd, src_rel, libc::O_PATH | libc::O_NOFOLLOW);
    if sfd < 0 {
        // The adapter returns `-errno`. ENOSYS → kernel < 5.6 (no openat2): 107 (parent maps to a precise
        // hint). ENOENT / RESOLVE refusal → 108 (a confined "no such file" - e.g. an opaque dir correctly
        // hid the source).
        return if sfd == -libc::ENOSYS { 107 } else { 108 };
    }
    let mut st: libc::stat = std::mem::zeroed();
    if libc::fstatat(sfd, c"".as_ptr(), &mut st, libc::AT_EMPTY_PATH) != 0 {
        libc::close(sfd);
        return 109;
    }
    match st.st_mode & libc::S_IFMT {
        // Read the symlink target straight off the O_PATH classify fd (AT_EMPTY_PATH) - confined by the
        // same openat2 that opened it, so no bare `readlinkat(root_fd, path)` re-resolution is needed.
        libc::S_IFLNK => {
            let rc = copy_one_symlink(sfd, dst_fd, dst_name);
            libc::close(sfd);
            rc
        }
        libc::S_IFDIR => {
            libc::close(sfd); // reopened readable inside copy_one_dir via a fresh confined openat2
            copy_one_dir(root_fd, src_rel, dst_fd, dst_name, &st, depth)
        }
        libc::S_IFREG => {
            libc::close(sfd);
            copy_one_file(root_fd, src_rel, dst_fd, dst_name, &st)
        }
        _ => {
            libc::close(sfd);
            0 // device/fifo/socket: skip (rootless can't recreate; absent in a COPY --from tree)
        }
    }
}

/// Thin `c_int`-returning adapter over the shared [`crate::openat2::openat2_in_root`] confinement
/// primitive, for the post-fork copier which speaks raw fds + numeric exit codes (not `io::Result`).
/// Returns the fd, or `-errno` so the caller can distinguish `ENOSYS` (pre-5.6 kernel) from `ENOENT`.
fn openat2_in_root(root_fd: libc::c_int, path: &str, flags: libc::c_int) -> libc::c_int {
    match crate::openat2::openat2_in_root(root_fd, path, flags, 0) {
        Ok(fd) => fd,
        Err(e) => -e.raw_os_error().unwrap_or(libc::EINVAL),
    }
}

/// Copy a symlink SOURCE verbatim (read its target off the already-confined O_PATH `src_fd`, recreate
/// with `symlinkat`). Never dereferenced - identical to `cp -a`, and reads nothing at the target. Reading
/// via `readlinkat(src_fd, "", AT_EMPTY_PATH)` keeps confinement BY CONSTRUCTION: `src_fd` came from
/// `openat2(RESOLVE_IN_ROOT)`, so there is no bare path re-resolution that could follow a symlinked parent.
unsafe fn copy_one_symlink(
    src_fd: libc::c_int,
    dst_fd: libc::c_int,
    dst_name: Option<&str>,
) -> i32 {
    let Some(name) = dst_name else { return 0 }; // a symlink has no "contents" to splat into a dir
    let mut buf = [0u8; libc::PATH_MAX as usize];
    let n = libc::readlinkat(
        src_fd,
        c"".as_ptr(),
        buf.as_mut_ptr() as *mut libc::c_char,
        buf.len() - 1,
    );
    if n < 0 {
        return 110;
    }
    buf[n as usize] = 0;
    let Ok(name_c) = std::ffi::CString::new(name) else {
        return 111;
    };
    if libc::symlinkat(buf.as_ptr() as *const libc::c_char, dst_fd, name_c.as_ptr()) != 0 {
        return 112;
    }
    0
}

/// Copy a directory: create it in `dst_fd` (or reuse `dst_fd` when `dst_name` is `None` - the whole-
/// rootfs push copies contents in place), then recurse. The source is reopened readable via a fresh
/// confined `openat2` (O_DIRECTORY); each child recurses via its path under the merged root, so every
/// component stays confined by `RESOLVE_IN_ROOT`.
unsafe fn copy_one_dir(
    root_fd: libc::c_int,
    src_rel: &str,
    dst_fd: libc::c_int,
    dst_name: Option<&str>,
    st: &libc::stat,
    depth: u32,
) -> i32 {
    // Destination dir fd: a freshly-created subdir, or `dst_fd` itself (contents-in-place).
    let child_dst = match dst_name {
        Some(name) => {
            let Ok(name_c) = std::ffi::CString::new(name) else {
                return 111;
            };
            libc::mkdirat(dst_fd, name_c.as_ptr(), st.st_mode & 0o7777);
            let fd = libc::openat(
                dst_fd,
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            );
            if fd < 0 {
                return 113;
            }
            fd
        }
        None => libc::dup(dst_fd),
    };
    // Reopen the source dir readable (confined). `.` resolves to the merged root itself for the push case.
    let src_read = openat2_in_root(root_fd, src_rel, libc::O_RDONLY | libc::O_DIRECTORY);
    if src_read < 0 {
        libc::close(child_dst);
        return 114;
    }
    let dirp = libc::fdopendir(src_read);
    if dirp.is_null() {
        libc::close(src_read);
        libc::close(child_dst);
        return 115;
    }
    let mut rc = 0;
    loop {
        let ent = libc::readdir(dirp);
        if ent.is_null() {
            break;
        }
        let name_ptr = (*ent).d_name.as_ptr();
        // Skip "." and "..".
        let b0 = *name_ptr as u8;
        let b1 = *name_ptr.add(1) as u8;
        if b0 == b'.' && (b1 == 0 || (b1 == b'.' && *name_ptr.add(2) as u8 == 0)) {
            continue;
        }
        let name_bytes = std::ffi::CStr::from_ptr(name_ptr).to_bytes();
        let Ok(child_name) = std::str::from_utf8(name_bytes) else {
            rc = 116;
            break;
        };
        // Child path under the merged root: `src_rel/child` (or just `child` when src_rel is ".").
        let child_rel = if src_rel == "." {
            child_name.to_string()
        } else {
            format!("{src_rel}/{child_name}")
        };
        let child_rc =
            copy_confined_tree(root_fd, &child_rel, child_dst, Some(child_name), depth + 1);
        if child_rc != 0 {
            rc = child_rc;
            break;
        }
    }
    libc::closedir(dirp); // also closes src_read
                          // Best-effort preserve dir mode/owner AFTER populating, so it isn't undone.
    if let Some(name) = dst_name {
        if let Ok(name_c) = std::ffi::CString::new(name) {
            libc::fchmodat(dst_fd, name_c.as_ptr(), st.st_mode & 0o7777, 0);
            libc::fchownat(
                dst_fd,
                name_c.as_ptr(),
                st.st_uid,
                st.st_gid,
                libc::AT_SYMLINK_NOFOLLOW,
            );
        }
    }
    libc::close(child_dst);
    rc
}

/// Copy a regular file: reopen the source readable (confined), create the dest, copy bytes with
/// `copy_file_range` (reflink/fast path) falling back to read/write, then preserve owner/mtime.
unsafe fn copy_one_file(
    root_fd: libc::c_int,
    src_rel: &str,
    dst_fd: libc::c_int,
    dst_name: Option<&str>,
    st: &libc::stat,
) -> i32 {
    let Some(name) = dst_name else { return 0 };
    let Ok(name_c) = std::ffi::CString::new(name) else {
        return 111;
    };
    let rfd = openat2_in_root(root_fd, src_rel, libc::O_RDONLY | libc::O_NOFOLLOW);
    if rfd < 0 {
        return 117;
    }
    let dfd = libc::openat(
        dst_fd,
        name_c.as_ptr(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW,
        (st.st_mode & 0o7777) as libc::c_uint,
    );
    if dfd < 0 {
        libc::close(rfd);
        return 118;
    }
    // copy_file_range (kernel reflink/fast copy); fall back to read/write on ENOSYS/EXDEV/short copy.
    let mut remaining = st.st_size as usize;
    let mut ok = true;
    while remaining > 0 {
        let n = libc::copy_file_range(
            rfd,
            std::ptr::null_mut(),
            dfd,
            std::ptr::null_mut(),
            remaining,
            0,
        );
        if n > 0 {
            remaining -= n as usize;
        } else if n == 0 {
            break; // EOF
        } else {
            ok = false;
            break;
        }
    }
    if !ok {
        // read/write fallback from the start.
        libc::lseek(rfd, 0, libc::SEEK_SET);
        libc::ftruncate(dfd, 0);
        let mut buf = [0u8; 1 << 16];
        loop {
            let r = libc::read(rfd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
            if r < 0 {
                libc::close(rfd);
                libc::close(dfd);
                return 119;
            }
            if r == 0 {
                break;
            }
            let mut off = 0isize;
            while off < r {
                let w = libc::write(
                    dfd,
                    buf.as_ptr().offset(off) as *const libc::c_void,
                    (r - off) as usize,
                );
                if w <= 0 {
                    libc::close(rfd);
                    libc::close(dfd);
                    return 119;
                }
                off += w;
            }
        }
    }
    // Carry `user.*` xattrs (application metadata, harmless) - best-effort, BEFORE owner/mtime. We do
    // NOT carry `security.capability`: file-capabilities are a privilege channel exactly like setuid, and
    // the source image is UNTRUSTED (a hostile `COPY --from`/push base could ship `/bin/sh` with
    // `cap_setuid+ep` → escalation in the copied/published image, and file-caps bypass the box's
    // MS_NOSUID unlike setuid). kern's model grants no file-caps at runtime, so dropping them removes an
    // injection vector without losing anything usable - the same call kern makes for setuid (stripped at
    // push). `system.*`/`trusted.*` are skipped too (need privilege, not ours to propagate).
    copy_xattrs(rfd, dfd);
    // Preserve owner + mtime best-effort (mode was set at create time).
    libc::fchown(dfd, st.st_uid, st.st_gid);
    let times = [
        libc::timespec {
            tv_sec: st.st_atime,
            tv_nsec: st.st_atime_nsec,
        },
        libc::timespec {
            tv_sec: st.st_mtime,
            tv_nsec: st.st_mtime_nsec,
        },
    ];
    libc::futimens(dfd, times.as_ptr());
    libc::close(rfd);
    libc::close(dfd);
    0
}

/// Copy the `user.*` extended attributes from `src_fd` to `dst_fd`, best-effort. Carries ONLY `user.*`
/// (application metadata, no privilege). Deliberately NOT `security.capability`: file-capabilities are a
/// privilege channel like setuid, and the source image is untrusted - blindly propagating an attacker's
/// `cap_setuid+ep` would inject an escalation into the copied/pushed image (worse than setuid: caps
/// bypass MS_NOSUID). `system.*`/`trusted.*` need privilege we don't have. Failures are ignored (xattrs
/// are best-effort like `cp --preserve=all`; a filesystem without xattr support must not fail the copy).
unsafe fn copy_xattrs(src_fd: libc::c_int, dst_fd: libc::c_int) {
    // List the source's xattr names into a buffer. `flistxattr(_, NULL, 0)` returns the needed size.
    let need = libc::flistxattr(src_fd, std::ptr::null_mut(), 0);
    if need <= 0 {
        return; // no xattrs (0) or not supported (<0)
    }
    let mut names = vec![0u8; need as usize];
    let got = libc::flistxattr(src_fd, names.as_mut_ptr() as *mut libc::c_char, names.len());
    if got <= 0 {
        return;
    }
    let mut val = vec![0u8; 4096];
    // Names are a NUL-separated, NUL-terminated list.
    for name in names[..got as usize]
        .split(|&b| b == 0)
        .filter(|n| !n.is_empty())
    {
        // Carry ONLY `user.*`. NOT `security.capability` (privilege channel - an untrusted image's caps
        // would be injected into the output; kern uses no runtime file-caps), NOT `system.*`/`trusted.*`
        // (need privilege, not ours to move).
        if !name.starts_with(b"user.") {
            continue;
        }
        let Ok(name_c) = std::ffi::CString::new(name) else {
            continue;
        };
        let vlen = libc::fgetxattr(
            src_fd,
            name_c.as_ptr(),
            val.as_mut_ptr() as *mut libc::c_void,
            val.len(),
        );
        if vlen < 0 {
            continue;
        }
        libc::fsetxattr(
            dst_fd,
            name_c.as_ptr(),
            val.as_ptr() as *const libc::c_void,
            vlen as usize,
            0,
        );
    }
}

/// `write(open(path), val)` - async-signal-safe (no allocation). `true` on full write.
unsafe fn write_proc_self(path: &[u8], val: &[u8]) -> bool {
    let fd = libc::open(path.as_ptr() as *const libc::c_char, libc::O_WRONLY);
    if fd < 0 {
        return false;
    }
    let n = libc::write(fd, val.as_ptr() as *const libc::c_void, val.len());
    libc::close(fd);
    n == val.len() as isize
}

/// Write a single-uid map line `0 <id> 1` to `path` (uid_map/gid_map), async-signal-safe. Formats the
/// number into a stack buffer (no allocation) to stay fork-safe.
unsafe fn write_proc_self_map(path: &[u8], id: u32) -> bool {
    let mut buf = [0u8; 32];
    let mut i = 0;
    buf[i] = b'0';
    i += 1;
    buf[i] = b' ';
    i += 1;
    let mut digits = [0u8; 10];
    let mut d = 0;
    let mut v = id;
    if v == 0 {
        digits[d] = b'0';
        d += 1;
    }
    while v > 0 {
        digits[d] = b'0' + (v % 10) as u8;
        v /= 10;
        d += 1;
    }
    while d > 0 {
        d -= 1;
        buf[i] = digits[d];
        i += 1;
    }
    buf[i] = b' ';
    i += 1;
    buf[i] = b'1';
    i += 1;
    write_proc_self(path, &buf[..i])
}

/// `CString` from a `&str`, mapping interior-NUL to an OCI error (a path/opt with a NUL is invalid).
fn cstring(s: &str) -> Result<std::ffi::CString, Error> {
    std::ffi::CString::new(s).map_err(|_| Error::Oci("merged-view: NUL in path".into()))
}

/// `true` if this process has exactly one thread - read from `/proc/self/stat`'s `num_threads` field.
/// Guards the fork-safety invariant of [`merged_view_extract`] via a HARD runtime check (it returns an
/// error if false - NOT a debug_assert, which would vanish in release where the guard matters most).
/// Best effort: if `/proc` is unreadable we assume single-threaded (don't refuse a legitimate run).
fn single_threaded() -> bool {
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return true;
    };
    // Fields after the (possibly space/paren-bearing) comm are space-separated; num_threads is field 20
    // (1-indexed), i.e. the 18th field AFTER the closing ')'. Parse from the last ')' to avoid comm spaces.
    let Some(rest) = stat.rsplit_once(')').map(|(_, r)| r.trim_start()) else {
        return true;
    };
    rest.split_whitespace()
        .nth(17) // state(1) … num_threads is the 18th token after comm
        .and_then(|n| n.parse::<i64>().ok())
        .map(|n| n <= 1)
        .unwrap_or(true)
}

/// Materialize an image reference to `(rootfs_dir, config, cleanup)`. `cleanup` is `Some(tmp)` when we
/// created a temporary squashed rootfs (layered image) that the caller must remove; `None` when the
/// rootfs is the persistent flat cache dir (do NOT delete it). Errors if the image isn't cached.
fn materialize_image(
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

/// Rewrite each service's RELATIVE bind-mount source to an absolute path under the compose file's
/// directory (Docker's rule), so kern's `-v` - which wants an absolute path or a named volume -
/// accepts the common `./dir:/dst` / `.:/app` compose form. A source that is already absolute (`/…`),
/// or a bare NAME (a named volume, no `/` and no leading `.`), is left untouched. The resolved path is
/// CONFINED under the compose dir (canonicalize + starts_with, same traversal guard as a build
/// context) so a `../../../etc:/x` can't escape the project tree.
fn resolve_relative_binds(
    boxes: &mut [crate::compose::ComposeBox],
    file: &str,
) -> Result<(), Error> {
    let base = std::fs::canonicalize(compose_dir(file))
        .map_err(|e| Error::Compose(format!("resolving compose dir: {e}")))?;

    for b in boxes.iter_mut() {
        for v in b.volumes.iter_mut() {
            // Split `src:dst[:opts]`. The source is the first segment; dst/opts follow.
            let (src, rest) = match v.split_once(':') {
                Some((s, r)) => (s, r),
                None => continue, // malformed spec - let `kern box` report it precisely
            };
            // Classify the source. A leading `/` is absolute (left as-is). A bare NAME with no `/` is a
            // named volume (left as-is; the box validates it). ANYTHING ELSE containing `/` is a
            // relative PATH and must be confined - not just the `./`/`../` forms: a source like
            // `foo/../../../etc` is relative but doesn't start with `./`, and the old check let it skip
            // the guard (the box's name-validator caught it as a backstop, but defense-in-depth wants
            // the compose layer to confine every relative path itself). (Hacker-mode audit, MEDIUM.)
            // `.` and `..` are relative PATHS with no slash in them, so the "no slash means named
            // volume" rule sent the single most common bind in existence (`.:/app`, mount the project
            // root) to the volume-name validator, which refused it. Docker resolves both against the
            // project directory. Anything else without a slash really is a named volume.
            let is_dot = src == "." || src == "..";
            if !is_dot && (src.starts_with('/') || !src.contains('/')) {
                continue;
            }
            // Docker CREATES a missing relative bind source. Refusing broke the most ordinary
            // workflow there is: clone a repo whose compose file says `./data:/var/lib/mysql`, and
            // `up` failed because `./data` does not exist yet. We create it too, but SAY SO - Docker
            // creating directories silently is how a typo'd path becomes an empty mount nobody
            // notices. Only under the compose directory, and only for a path that is relative, so the
            // traversal guard below still decides what is allowed.
            let target = base.join(src);
            // Containment is checked LEXICALLY first, BEFORE creating anything: `canonicalize` needs
            // the path to exist, so a `../x` source would otherwise have its directory created and
            // only then be refused - a filesystem side effect outside the project, caused by the very
            // input we are about to reject.
            // Walk the components keeping a depth counter: a `..` at depth 0 would step above the
            // project, so `try_fold` short-circuits to `None` and that IS the escape.
            let escapes = src
                .split('/')
                .try_fold(0i32, |depth, seg| match seg {
                    "" | "." => Some(depth),
                    ".." => (depth > 0).then_some(depth - 1),
                    _ => Some(depth + 1),
                })
                .is_none();
            if escapes {
                return Err(Error::Compose(format!(
                    "service '{}': bind source '{src}' escapes the compose directory (refused)",
                    b.name
                )));
            }
            if !target.exists() {
                std::fs::create_dir_all(&target).map_err(|e| {
                    Error::Compose(format!(
                        "service '{}': bind source '{src}' does not exist and could not be created: {e}",
                        b.name
                    ))
                })?;
                eprintln!(
                    "kern compose: service '{}': created missing bind source '{src}'",
                    b.name
                );
            }
            let abs = std::fs::canonicalize(&target).map_err(|e| {
                Error::Compose(format!("service '{}': bind source '{src}': {e}", b.name))
            })?;
            if !abs.starts_with(&base) {
                return Err(Error::Compose(format!(
                    "service '{}': bind source '{src}' escapes the compose directory (refused)",
                    b.name
                )));
            }
            *v = format!("{}:{rest}", abs.to_string_lossy());
        }
        // Compose `secrets:` map to `--secret <file>:<name>`; `<file>` came from a top-level `file: ./x`
        // and is relative → resolve against the compose dir, same traversal guard as a bind.
        for s in b.secrets.iter_mut() {
            let Some((file, nm)) = s.split_once(':') else {
                continue;
            };
            if file.starts_with('/') {
                continue; // already absolute
            }
            let abs = std::fs::canonicalize(base.join(file)).map_err(|e| {
                Error::Compose(format!("service '{}': secret file '{file}': {e}", b.name))
            })?;
            if !abs.starts_with(&base) {
                return Err(Error::Compose(format!(
                    "service '{}': secret file '{file}' escapes the compose directory (refused)",
                    b.name
                )));
            }
            *s = format!("{}:{nm}", abs.to_string_lossy());
        }
    }
    Ok(())
}

/// Walk a squashed rootfs and honour any OCI whiteout marker that survived the merge: `.wh.<name>`
/// deletes its sibling `<name>` (and itself), `.wh..wh..opq` clears its directory's contents. In
/// kern's model the chain has none (see the invariant at the call site), so this is a no-op belt -
/// but if a future layer format leaves whiteouts, this keeps a deleted file from being republished.
/// Best-effort, non-following (never descends a symlink), depth-first.
fn strip_whiteout_markers(root: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        let ft = match e.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if name == ".wh..wh..opq" {
            // Opaque dir marker: drop it (its "hide everything below" is already reflected in the
            // merged view we squashed; the marker itself must not ship).
            let _ = std::fs::remove_file(e.path());
            continue;
        }
        if let Some(victim) = name.strip_prefix(".wh.") {
            // Whiteout: remove the shadowed sibling (if it somehow got copied) and the marker.
            if !victim.is_empty() && !victim.contains('/') {
                let sib = root.join(victim);
                if sib.is_dir() {
                    let _ = std::fs::remove_dir_all(&sib);
                } else {
                    let _ = std::fs::remove_file(&sib);
                }
            }
            let _ = std::fs::remove_file(e.path());
            continue;
        }
        // Recurse into real subdirectories (not symlinks - no-follow).
        if ft.is_dir() {
            strip_whiteout_markers(&e.path());
        }
    }
}

/// Resolve `--image <ref>` to an overlay `(lowerdir, config)`. A pulled (flat) image is a single
/// cache dir. A locally-built (**layered**) image - marked by a `<ref>.base` sidecar - is its
/// `<ref>.diff` layer stacked over its base, resolved RECURSIVELY (the base may itself be layered)
/// and re-pulled if the base was pruned, so layered images are prune-safe. The returned `lowerdir`
/// may be a colon-joined chain (top layer first, exactly overlayfs's ordering).
fn resolve_image(image: &str) -> Result<(String, kern_oci::ImageConfig), Error> {
    resolve_image_depth(image, 0, PullPolicy::Missing)
}

fn resolve_image_depth(
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
fn cache_entry_complete(cache: &std::path::Path, safe: &str) -> bool {
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
fn pull_to_cache(
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
fn cache_dir() -> PathBuf {
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
fn layer_cache_dir() -> PathBuf {
    cache_dir().join("L")
}

/// A 128-bit FNV-1a cache key (32 hex) over `prev-key` then `repr` - the chained key that makes a
/// layer's identity depend on everything before it, so a change busts that layer and all after it.
/// Non-crypto: this is a LOCAL, first-party cache, and a collision only mis-reuses the user's OWN
/// layer (2^-128); it is never a trust boundary.
fn layer_key(prev: &str, repr: &str) -> String {
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
fn content_hash(
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
fn layer_cached(lc: &std::path::Path, key: &str) -> bool {
    lc.join(format!("{key}.ok")).exists()
}

/// Commit a freshly-built layer's content dir into the layer cache under `key` (atomic rename +
/// completion sentinel). A concurrent build that produced the same key first simply wins the race.
fn commit_layer(content: &std::path::Path, lc: &std::path::Path, key: &str) -> Result<(), Error> {
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
fn chain_has_dir(chain: &[String], rel: &str) -> bool {
    if rel.is_empty() {
        return true;
    }
    chain.iter().rev().any(|d| {
        std::fs::symlink_metadata(std::path::Path::new(d).join(rel))
            .map(|m| m.is_dir())
            .unwrap_or(false)
    })
}

/// Create `dir` (and parents) private to this user (mode 0700). Mitigates a local-user symlink/
/// clobber attack on a predictable cache path: another user can't pre-create or enter it.
/// Size of the caller's subordinate-uid range from `/etc/subuid` (box uids 1..count map here, so the
/// box can use uids 0..count-1). `0` if there's no allocation (single-uid only). Best-effort, matching
/// how `newuidmap` resolves the row - a name match wins, else a numeric-uid row. Used only to warn (F1)
/// when an image's declared uid exceeds what `--uid-range` can map; never to clamp.
/// Size of the caller's `/etc/subuid` range (box uids 0..count usable), or 0 if none. Delegates to the
/// ONE authoritative parser in kern-isolation (`sub_range`: `count>1`, name-row-wins) so the box path,
/// the cleanup path, and this F1 warning can't drift apart.
fn mapped_uid_count() -> u32 {
    let uid = unsafe { libc::getuid() };
    let name = kern_isolation::username(uid);
    kern_isolation::sub_range("/etc/subuid", name.as_deref(), uid)
        .map(|(_start, count)| count)
        .unwrap_or(0)
}

fn own_only_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// A filesystem-safe directory name for an image reference.
fn sanitize_ref(image: &str) -> String {
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
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Arguments for [`build`] (`kern build`).
pub struct BuildArgs<'a> {
    /// `-t <name[:tag]>`: the local image name to store the result under. Required.
    pub tag: Option<&'a str>,
    /// `-f <file>`: the Dockerfile path. `None` → `<context>/Dockerfile`.
    pub file: Option<&'a str>,
    /// The build context directory (default `.`) - the root COPY/ADD sources resolve against.
    pub context: &'a str,
    /// `--build-arg K=V` (repeatable): values for `ARG` substitution.
    pub build_args: &'a [String],
    /// `--quiet`: suppress per-step progress.
    pub quiet: bool,
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
        error: String::new(),
    };
    let _ = crate::builds::write(&rec);
    let capture = crate::builds::Capture::start(&id);
    for w in &warns {
        if !args.quiet {
            eprintln!("warning: {w}");
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
            rec.status.label(),
            rec.duration_ms,
            rec.tag
        ),
    );
    result
}

/// Execute a MULTI-STAGE build. Each stage is built in order via the ordinary single-stage `build_run`
/// under an internal temp tag (`.stage-<pid>-<idx>`), so every stage reuses the proven, byte-identical
/// single-stage path (RUN batching, layer cache, config handling). Only the LAST stage is built under
/// the user's real `tag`; the temp stage images are dropped at the end.
///
/// `COPY --from=<stage>` (the multi-stage feature) is made safe by REUSE, not by a hand-rolled overlay
/// mount: the source stage is materialized to a single merged rootfs dir (`materialize_image`, which
/// already resolves the overlay chain + whiteouts correctly), and the copy runs through the SAME
/// `copy_into_rootfs` guards as a context COPY - it canonicalizes the source under the stage rootfs and
/// rejects any `..`/symlink escape, so `COPY --from=build /etc/../../host` fails exactly like a hostile
/// context COPY. The `--from` COPY is rewritten to a plain COPY whose "context" is that merged rootfs.
///
/// Non-final stages build under an internal tag prefixed with [`STAGE_TAG_PREFIX`]; that prefix is the
/// single source of truth for both creating those tags and suppressing their "built …" line
/// ([`announce_built`]). A leading `.` never appears in a user ref, so the two can't collide.
const STAGE_TAG_PREFIX: &str = ".stage-";

/// Print the "built '<tag>'" success line - UNLESS `tag` is an internal multi-stage stage tag (prefixed
/// [`STAGE_TAG_PREFIX`]), which the user shouldn't see. Single-sourced so the create/suppress contract
/// can't drift.
fn announce_built(tag: &str) {
    if !tag.starts_with(STAGE_TAG_PREFIX) {
        println!("built '{tag}'");
        println!("  run: kern box myapp --image {tag}");
    }
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
            eprintln!("  [cached · multi-stage image unchanged]");
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

/// A stage's rewritten instruction list plus the two flags that pick its build context.
struct StagePrep {
    stage_instrs: Vec<crate::dockerfile::Instr>,
    /// The stage pulled from ≥1 source stage (files grafted into the sub-context `subctx`).
    pulled_from_stage: bool,
    /// The stage has ≥1 plain `COPY` from the real build context.
    stage_uses_context: bool,
}

/// Rewrite a stage's instruction slice, turning every `COPY --from=<stage|image>` into a plain COPY
/// whose source is the referenced stage's built rootfs - OR, for an external `--from=<image>`, the
/// image's pulled rootfs (`resolve_image`, the same path `FROM`/`--image` use). Files are grafted into
/// `subctx` through the SAME confine guards as a context COPY (`copy_from_stage_chain`), so an external
/// image's `srcs` can't `..`/symlink-escape its rootfs any more than a stage's can. Each distinct
/// source stage/image is resolved AT MOST ONCE (perf) so the caller sees a straight `?`.
fn prepare_stage(
    slice: &[crate::dockerfile::Instr],
    stage_tags: &[String],
    stage_names: &[Option<String>],
    si: usize,
    subctx: &std::path::Path,
) -> Result<StagePrep, Error> {
    use crate::dockerfile::{resolve_from, CopyFrom, Instr};
    let mut stage_instrs: Vec<Instr> = Vec::with_capacity(slice.len());
    let mut stage_uses_context = false;
    let mut pulled_from_stage = false;
    // Resolve each SOURCE STAGE's overlay chain at most once per stage. We copy files DIRECTLY from the
    // chain (no full-rootfs squash) - the squash only happens as a fallback for a directory source,
    // inside copy_from_stage_chain. Caching the chain dedups N `COPY --from=X`.
    let mut chains: std::collections::HashMap<usize, Vec<String>> =
        std::collections::HashMap::new();
    // Same idea for external `COPY --from=<image>`: pull+resolve each distinct image AT MOST ONCE.
    let mut image_chains: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut build = || -> Result<(), Error> {
        for ins in slice {
            match ins {
                Instr::Copy {
                    srcs,
                    dst,
                    from: Some(cf),
                    chmod,
                } => {
                    // Resolve the source's overlay chain (top-first list of layer dirs), pulling an
                    // external image on demand. A build STAGE takes precedence over an image of the same
                    // spelling - already decided by the parser, which only emits `CopyFrom::Image` when
                    // the token names NO earlier stage. Both paths feed the SAME confined copy helper
                    // (`copy_from_stage_chain` → single-layer `starts_with` guard, or ≥2-layer
                    // `merged_view_extract` with `openat2(RESOLVE_IN_ROOT)`), so an external image's
                    // `srcs` are confined to its rootfs exactly like a stage's - no `..`/symlink escape.
                    let (chain, label): (Vec<String>, String) = match cf {
                        CopyFrom::Stage(fref) => {
                            let src_idx = resolve_from(fref, stage_names, si).ok_or_else(|| {
                                Error::Build(format!(
                                    "COPY --from='{fref}' does not name an earlier stage"
                                ))
                            })?;
                            if let std::collections::hash_map::Entry::Vacant(slot) =
                                chains.entry(src_idx)
                            {
                                // The chain is `top:...:base`; split into a top-first Vec of layer dirs.
                                let (lower, _cfg) = resolve_image(&stage_tags[src_idx])?;
                                slot.insert(lower.split(':').map(str::to_string).collect());
                            }
                            (chains[&src_idx].clone(), stage_tags[src_idx].clone())
                        }
                        CopyFrom::Image(img) => {
                            if let std::collections::hash_map::Entry::Vacant(slot) =
                                image_chains.entry(img.clone())
                            {
                                // Pull (if not cached) + resolve the external image's overlay chain -
                                // the SAME path `FROM`/`--image` use (`resolve_image` → `pull_to_cache`).
                                // Runs synchronously on the single-threaded build main, so the confined
                                // copy that follows keeps the fork-safety invariant.
                                let (lower, _cfg) = resolve_image(img)?;
                                slot.insert(lower.split(':').map(str::to_string).collect());
                            }
                            (image_chains[img].clone(), img.clone())
                        }
                    };
                    if !pulled_from_stage {
                        let _ = std::fs::create_dir_all(subctx);
                        pulled_from_stage = true;
                    }
                    for s in srcs {
                        copy_from_stage_chain(&chain, s, subctx, &label)?;
                    }
                    // Rewrite to a plain COPY from the sub-context (same dst-side guards downstream).
                    let names: Vec<String> = srcs
                        .iter()
                        .map(|s| {
                            std::path::Path::new(s.trim_end_matches('/'))
                                .file_name()
                                .map(|b| b.to_string_lossy().into_owned())
                                .unwrap_or_else(|| s.clone())
                        })
                        .collect();
                    stage_instrs.push(Instr::Copy {
                        srcs: names,
                        dst: dst.clone(),
                        from: None,
                        chmod: chmod.clone(),
                    });
                }
                // A context COPY (from: None) - the stage references the real build context.
                Instr::Copy { .. } => {
                    stage_uses_context = true;
                    stage_instrs.push(ins.clone());
                }
                other => stage_instrs.push(other.clone()),
            }
        }
        Ok(())
    };
    // The chain-copy owns no temp squash dir (the dir-source fallback inside copy_from_stage_chain
    // cleans up its own squash), so there's nothing to reap here.
    build()?;
    Ok(StagePrep {
        stage_instrs,
        pulled_from_stage,
        stage_uses_context,
    })
}

/// Copy `src_rel` OUT of a source stage's overlay `chain` (top-first list of layer dirs) into `dest`,
/// honouring overlay opaque/whiteout semantics so a file DELETED in a build step never resurfaces.
///
/// For a ≥2-layer chain this reads from the KERNEL-MERGED view ([`merged_view_extract`]) - the ONLY
/// correct reader: a top-first walk of the RAW layers leaks a file whose PARENT directory was made
/// OPAQUE in an upper layer (`rm -rf dir && mkdir dir`), because the walk finds the file in a lower
/// layer that the opaque was meant to hide. (Verified live: a secret `rm`'d in a build step reappeared
/// via `COPY --from`.) The merged view also confines an untrusted `src_rel` by CONSTRUCTION
/// (`openat2(RESOLVE_IN_ROOT)`), so a `..`-escape and an in-image absolute-symlink-escape are both
/// closed - see the primitive's doc. A single-layer chain has no cross-layer opaque possible, so it's
/// copied directly (host-side canonicalize + `starts_with` confine).
fn copy_from_stage_chain(
    chain: &[String],
    src_rel: &str,
    dest: &std::path::Path,
    _stage_tag: &str,
) -> Result<(), Error> {
    if chain.len() >= 2 {
        // ≥2 stacked layers → cross-layer opaque is possible → read the kernel-merged view (which also
        // handles file AND directory sources uniformly, confining `src_rel` via `openat2(RESOLVE_IN_ROOT)`).
        return merged_view_extract(chain, Some(src_rel), dest);
    }
    // Exactly one layer: it IS its own merged rootfs (no cross-layer opaque to honour). Copy directly
    // through the shared single-rootfs confine helper (canonicalize + `starts_with`, `cp -a` no-follow).
    copy_from_stage_rootfs(std::path::Path::new(&chain[0]), src_rel, dest)
}

/// Copy `src_rel` OUT of a single source rootfs `src_rootfs` into `dest`, confined to it (canonicalize +
/// `starts_with`, the same escape guard a context COPY uses) with a no-follow `cp -a`. Used for a
/// SINGLE-layer `COPY --from` chain (a ≥2-layer chain goes through [`merged_view_extract`] instead,
/// which honours cross-layer opaque).
fn copy_from_stage_rootfs(
    src_rootfs: &std::path::Path,
    src_rel: &str,
    dest: &std::path::Path,
) -> Result<(), Error> {
    let clean = src_rel.trim_start_matches('/');
    // Canonicalize the ROOT too, so the confinement check compares canonical-vs-canonical. Without
    // this, a `src_rootfs` reached through a symlinked component (e.g. a cache dir under a symlinked
    // $HOME) would make `canonicalize(src)` resolve past the raw prefix and FALSE-reject a legitimate
    // copy. Security is unchanged: a src that symlinks OUT of the image still resolves outside `root`
    // and is rejected.
    let root = std::fs::canonicalize(src_rootfs).map_err(|e| {
        Error::Build(format!(
            "COPY --from source rootfs '{}': {e}",
            src_rootfs.display()
        ))
    })?;
    let src = std::fs::canonicalize(root.join(clean))
        .map_err(|e| Error::Build(format!("COPY --from source '{src_rel}': {e}")))?;
    if !src.starts_with(&root) {
        return Err(Error::Build(format!(
            "COPY --from source '{src_rel}' escapes the source stage"
        )));
    }
    let name = src
        .file_name()
        .ok_or(Error::Build("COPY --from source has no file name".into()))?;
    let target = dest.join(name);
    // `cp -a --` no-follow, preserving modes - same tool/flags as the rest of the builder.
    let ok = std::process::Command::new("cp")
        .arg("-a")
        .arg("--reflink=auto") // CoW clone on btrfs/xfs (near-free); plain copy elsewhere
        .arg("--")
        .arg(&src)
        .arg(&target)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        return Err(Error::Build(format!(
            "COPY --from could not copy '{src_rel}'"
        )));
    }
    Ok(())
}

/// Overlay `from`'s entries onto `into` (used to graft stage-copied files onto a build sub-context).
/// Each entry may be a file OR a directory, so we can't use `copy_tree` (which assumes a dir); a plain
/// `cp -a --` on the entry path handles both.
fn merge_context(from: &std::path::Path, into: &std::path::Path) -> Result<(), Error> {
    for e in std::fs::read_dir(from).map_err(|e| Error::Build(e.to_string()))? {
        let e = e.map_err(|e| Error::Build(e.to_string()))?;
        let dst = into.join(e.file_name());
        let _ = std::fs::remove_dir_all(&dst);
        let _ = std::fs::remove_file(&dst);
        let ok = std::process::Command::new("cp")
            .arg("-a")
            .arg("--reflink=auto") // CoW clone on btrfs/xfs (near-free); plain copy elsewhere
            .arg("--")
            .arg(e.path())
            .arg(&dst)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return Err(Error::Build(format!(
                "grafting '{}' into the build context failed",
                e.file_name().to_string_lossy()
            )));
        }
    }
    Ok(())
}

/// Remove a cached image (all sidecar forms) by ref - used to drop the internal temp stage images a
/// multi-stage build creates. Best-effort.
fn drop_cached_image(image: &str) -> Result<(), Error> {
    // `sanitize_ref` yields an `is_safe_stem` token, so this shares the single artifact-remover with
    // `rmi` (they can't drift on which sidecars make up an image).
    drop_image_artifacts(&cache_dir(), &sanitize_ref(image));
    Ok(())
}

/// A flat-build cache HIT: `tag` holds a flat image (its `<safe>` rootfs dir exists) whose stored
/// content key matches `key`. Shared by the single-stage and multi-stage build paths so they can't
/// drift on the suffix or the `is_dir` guard.
fn flat_cache_hit(tag: &str, key: &str) -> bool {
    let cache = cache_dir();
    let safe = sanitize_ref(tag);
    cache.join(&safe).is_dir()
        && std::fs::read_to_string(cache.join(format!("{safe}.flatkey")))
            .ok()
            .as_deref()
            == Some(key)
}

/// Record a flat-build content key on `tag` so the next identical build hits [`flat_cache_hit`].
fn write_flat_key(tag: &str, key: &str) {
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
fn flat_image_key(
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

/// The build body - separated so [`build`] can always clean up the work tree, success or error.
///
/// Prefers a **layered** build: the base stays a shared read-only overlay lower, and RUN/COPY writes
/// accumulate in a persistent upper (the diff) - so the base is **never copied** (closing the
/// base-copy bottleneck). The image is stored as its diff + a `<tag>.base` marker, and
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
        eprintln!("[1/{total}] FROM {base_ref}");
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
    let layered = std::env::var_os("KERN_BUILD_FLAT").is_none()
        && probe_overlay(&self_exe, &base_lower, work)
        && probe_opaque_honored();
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
            eprintln!("  [layered · base shared, no copy]");
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
            eprintln!("  [cached · flat image unchanged]");
        }
        announce_built(tag);
        return Ok(());
    }
    // A real flat build (cache miss) - now note the base copy (slower than layered).
    if !quiet {
        eprintln!("  [flat · unprivileged overlay unavailable, copying the base]");
    }
    let write_dir = work.join("rootfs");
    copy_tree(std::path::Path::new(&base_lower), &write_dir)?;
    // DNS for RUN: seed the host resolv.conf into the copied rootfs so apk/apt resolve; stripped
    // before finalize (if we created it) so the host's DNS servers aren't baked into the image.
    let seeded_resolv = seed_resolv_conf(&write_dir);

    let announce = |s: usize, what: String| {
        if !quiet {
            eprintln!("[{s}/{total}] {what}");
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
    // Strip the resolv.conf we seeded so host DNS isn't baked in; leave a base's own untouched.
    if seeded_resolv {
        let _ = std::fs::remove_file(write_dir.join("etc/resolv.conf"));
    }

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

/// The local filename an `ADD <url>` downloads to: the URL's last path segment minus any
/// query/fragment. SANITIZED - a URL ending in `/..` or `/.`, an empty segment (bare host), or a
/// segment bearing a path separator / NUL would let `dir.join(name)` escape the scratch dir (and feed
/// `..` into the copy as a source), so those fall back to a fixed safe name. Pure, so it's unit-tested.
fn add_url_basename(url: &str) -> &str {
    let tail = url.rsplit('/').next().unwrap_or("");
    let name = tail.split(['?', '#']).next().unwrap_or("");
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        "download"
    } else {
        name
    }
}

/// Fetch `url` into `dir` for a Dockerfile `ADD <url> <dst>`, returning the basename written. HTTPS
/// only (`--proto '=https'`, incl. redirects) - an `http://` URL is refused rather than silently
/// downgrading build integrity - via `curl`, matching kern's dependency-free (curl/tar/cp) posture. When `checksum`
/// (`<algo>:<hex>`) is given it's verified and a mismatch fails the build.
fn fetch_add_url(
    url: &str,
    checksum: Option<&str>,
    dir: &std::path::Path,
) -> Result<String, Error> {
    if !url.starts_with("https://") {
        return Err(Error::Sandbox(format!(
            "ADD {url}: only https:// URLs are fetched (http is refused; download over TLS or vendor \
             the file and COPY it)"
        )));
    }
    // Fresh scratch dir to download into (owned by the caller's `work`); it holds only this file.
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).map_err(|e| Error::Sandbox(format!("ADD download dir: {e}")))?;
    let name = add_url_basename(url);
    let out = dir.join(name);
    // HTTPS only, on the initial request AND across redirects (`--proto-redir`), so a 302 can't
    // silently downgrade the fetch to cleartext http.
    let status = std::process::Command::new("curl")
        .args([
            "-fSL",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "20",
            "-o",
        ])
        .arg(&out)
        .arg(url)
        .status()
        .map_err(|e| Error::Sandbox(format!("ADD {url}: curl: {e}")))?;
    if !status.success() {
        return Err(Error::Sandbox(format!("ADD {url}: download failed")));
    }
    if let Some(cs) = checksum {
        verify_download_checksum(&out, cs)?;
    }
    Ok(name.to_string())
}

/// Apply a Dockerfile `--chmod=<octal>` to a file the build just CREATED (an ADD-url download or a
/// COPY-heredoc body), so `ADD --chmod=755 <url> /bin/tool` lands executable (the download-and-run
/// pattern) - curl/`std::fs::write` create it 0644 otherwise. `None` = no flag, leave the mode as-is.
/// The octal is parsed leniently (`755`, `0755`, `0o755`); a non-octal mode is a clear error.
fn apply_chmod(path: &std::path::Path, mode: Option<&str>) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let Some(mode) = mode else { return Ok(()) };
    let cleaned = mode.trim().trim_start_matches("0o");
    let bits = u32::from_str_radix(cleaned, 8).map_err(|_| {
        Error::Sandbox(format!(
            "--chmod: invalid mode '{mode}' (use an octal mode like 755 or 0644)"
        ))
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits))
        .map_err(|e| Error::Sandbox(format!("--chmod {mode}: {e}")))
}

/// Apply a context/`--from` COPY's `--chmod=<octal>` to everything just copied at `target`: the file,
/// or a directory AND its whole subtree - Docker's `--chmod` is recursive. `None` = no flag, leave the
/// copied modes as-is. Symlinks are SKIPPED (never chmod THROUGH a symlink - the same no-follow
/// invariant the `cp -a`/`copy_dir_filtered` copy upholds, so a `leak -> /host` in the context can't be
/// used to chmod a host file). Directories are chmod'd AFTER their children so a restrictive mode
/// (e.g. 0644) on the dir can't block our own descent.
fn apply_chmod_tree(target: &std::path::Path, mode: Option<&str>) -> Result<(), Error> {
    let Some(mode) = mode else { return Ok(()) };
    let cleaned = mode.trim().trim_start_matches("0o");
    let bits = u32::from_str_radix(cleaned, 8).map_err(|_| {
        Error::Sandbox(format!(
            "--chmod: invalid mode '{mode}' (use an octal mode like 755 or 0644)"
        ))
    })?;
    chmod_tree_bits(target, bits);
    Ok(())
}

fn chmod_tree_bits(path: &std::path::Path, bits: u32) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(md) = std::fs::symlink_metadata(path) else {
        return;
    };
    if md.file_type().is_symlink() {
        return; // never follow/chmod a symlink
    }
    if md.is_dir() {
        if let Ok(rd) = std::fs::read_dir(path) {
            for e in rd.flatten() {
                chmod_tree_bits(&e.path(), bits);
            }
        }
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits));
}

/// Write an inline `COPY <<heredoc` body to a scratch file `dir/f` (a fresh dir), so the same
/// confined `copy_into_rootfs` path that a real COPY uses places it at the destination. Returns the
/// scratch dir ready with the single file `f`.
fn write_inline_file(dir: &std::path::Path, content: &str) -> Result<(), Error> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).map_err(|e| Error::Sandbox(format!("inline COPY dir: {e}")))?;
    std::fs::write(dir.join("f"), content)
        .map_err(|e| Error::Sandbox(format!("inline COPY write: {e}")))?;
    Ok(())
}

/// Verify a downloaded file against a BuildKit `--checksum=<algo>:<hex>` using coreutils
/// `sha{256,384,512}sum`. A malformed spec, unsupported algorithm, or digest mismatch fails the build.
fn verify_download_checksum(path: &std::path::Path, checksum: &str) -> Result<(), Error> {
    let (algo, want) = checksum.split_once(':').ok_or_else(|| {
        Error::Sandbox(format!(
            "ADD --checksum must be '<algo>:<hex>' (e.g. sha256:…), got '{checksum}'"
        ))
    })?;
    let tool = match algo {
        "sha256" => "sha256sum",
        "sha384" => "sha384sum",
        "sha512" => "sha512sum",
        other => {
            return Err(Error::Sandbox(format!(
                "ADD --checksum: unsupported algorithm '{other}' (use sha256/sha384/sha512)"
            )))
        }
    };
    let out = std::process::Command::new(tool)
        .arg("--")
        .arg(path)
        .output()
        .map_err(|e| Error::Sandbox(format!("ADD --checksum: {tool}: {e}")))?;
    if !out.status.success() {
        return Err(Error::Sandbox(format!("ADD --checksum: {tool} failed")));
    }
    let got = String::from_utf8_lossy(&out.stdout);
    let got = got.split_whitespace().next().unwrap_or("");
    if !got.eq_ignore_ascii_case(want) {
        return Err(Error::Sandbox(format!(
            "ADD checksum mismatch: expected {algo}:{want}, got {algo}:{got}"
        )));
    }
    Ok(())
}

/// Max bytes of the overlay `lowerdir=` chain - the mount-options buffer is ~one page (4 KiB); this
/// leaves headroom for `upperdir=`/`workdir=` so a long build/image chain fails with our clear error
/// instead of a cryptic kernel `EINVAL`.
const MAX_LOWERDIR_BYTES: usize = 3500;

/// Join an overlay lower `chain` (base first) into a `lowerdir=` string (TOP layer first, base last).
fn chain_lower(chain: &[String]) -> String {
    chain.iter().rev().cloned().collect::<Vec<_>>().join(":")
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
            eprintln!("[{s}/{total}] {what}");
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

/// The persistent overlay upper dir under a `kern build` work/`--overlay-upper` root - the ONE place
/// this layout convention lives, shared by [`build_run`] (writes COPY/WORKDIR here) and [`build_spec`]
/// (mounts it as the RUN box's overlay upperdir) so the two can't silently desync.
fn build_upper_dir(overlay_root: &std::path::Path) -> PathBuf {
    overlay_root.join("upper")
}

/// Remove a build work tree. overlayfs leaves its workdir's inner `work/` at mode `000`, which a
/// plain `remove_dir_all` can't traverse (→ a leaked `.build-*` dir on disk). We own every entry, so
/// chmod each directory back to `0700` before recursing, then remove.
fn remove_build_tree(path: &std::path::Path) {
    fn chmod_dirs(p: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    chmod_dirs(&e.path());
                }
            }
        }
    }
    chmod_dirs(path);
    let _ = std::fs::remove_dir_all(path);
}

/// Probe whether an unprivileged overlay with a persistent upper actually mounts on this kernel (a
/// tiny `true`-box over `base_lower`). Decides layered-vs-flat build up front. Best-effort; any
/// failure → `false` → the flat copy path.
/// `true` if this kernel HONOURS an overlay opaque directory in a rootless (single-uid userns) mount -
/// i.e. after `rm -rf dir && mkdir dir` on a dir that lives in a lower layer, the lower's files are
/// hidden from the merged view. Tested once, in-process (fork + `unshare(CLONE_NEWUSER|NEWNS)` +
/// single-uid self-map + a throwaway 2-dir overlay), so it needs no `newuidmap` and mirrors exactly what
/// a build layer does. Returns `true` on a modern kernel (a sub-ms check); `false` on a kernel that
/// silently omits the opaque (measured: tegra 5.15) - where the caller must NOT build layered, or a
/// deleted file would leak into a `COPY --from`/push. Best-effort: if the probe itself can't run
/// (no unpriv userns at all - but then `probe_overlay` already said no), we return `false` (fail-closed).
fn probe_opaque_honored() -> bool {
    let tmp = cache_dir().join(format!(".opaque-probe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    // lower/dir/secret + empty upper/work + a merge target. If mkdir fails we can't probe → fail-closed.
    let mk = |p: &std::path::Path| std::fs::create_dir_all(p).is_ok();
    if !(mk(&tmp.join("lower/dir"))
        && mk(&tmp.join("up"))
        && mk(&tmp.join("wk"))
        && mk(&tmp.join("mg")))
    {
        remove_build_tree(&tmp);
        return false;
    }
    if std::fs::write(tmp.join("lower/dir/secret"), b"x").is_err() {
        remove_build_tree(&tmp);
        return false;
    }
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };
    // The child does the ns/mount/rm and _exits 0 iff the opaque IS honoured (secret hidden). Any failure
    // (mount error, opaque not honoured, secret still visible) → non-zero → fail-closed.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        remove_build_tree(&tmp);
        return false;
    }
    if pid == 0 {
        unsafe { probe_opaque_child(&tmp, euid, egid) };
    }
    let mut status = 0i32;
    let waited = crate::eintr::waitpid(pid, &mut status, 0);
    remove_build_tree(&tmp);
    waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

/// Child of [`probe_opaque_honored`]: mount a RW overlay (lower has `dir/secret`), `rm -rf dir && mkdir
/// dir` in the merged view, then re-open the merged view read-only and check `dir/secret` is GONE (the
/// opaque was honoured). `_exit(0)` iff hidden; any other path `_exit`s non-zero. Async-signal-safe until
/// the `system()` - acceptable here (single-threaded at fork, like `merged_view_child`).
unsafe fn probe_opaque_child(tmp: &std::path::Path, euid: libc::uid_t, egid: libc::gid_t) -> ! {
    let cs = |p: String| std::ffi::CString::new(p).unwrap();
    if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
        libc::_exit(11);
    }
    if !write_proc_self(b"/proc/self/setgroups\0", b"deny")
        || !write_proc_self_map(b"/proc/self/uid_map\0", euid)
        || !write_proc_self_map(b"/proc/self/gid_map\0", egid)
    {
        libc::_exit(12);
    }
    libc::mount(
        c"none".as_ptr(),
        c"/".as_ptr(),
        std::ptr::null(),
        libc::MS_REC | libc::MS_PRIVATE,
        std::ptr::null(),
    );
    let d = tmp.to_string_lossy();
    let opts = cs(format!("lowerdir={d}/lower,upperdir={d}/up,workdir={d}/wk"));
    let mg = cs(format!("{d}/mg"));
    if libc::mount(
        c"overlay".as_ptr(),
        mg.as_ptr(),
        c"overlay".as_ptr(),
        0,
        opts.as_ptr() as *const libc::c_void,
    ) != 0
    {
        libc::_exit(13);
    }
    // Reproduce EXACTLY what a build does - and the leak that only shows on RE-MOUNT. A build RUN does
    // `rm -rf dir && mkdir dir` in the live overlay (which every kernel honours in the LIVE view), then
    // `commit_layer` saves the UPPER as a standalone layer, and later the merged-view RE-MOUNTS
    // upper-as-lower. The leak is that some kernels (tegra 5.15) honour the opaque live but DON'T
    // persist it into the upper (no opaque xattr / whiteout written) - so on re-mount the lower's file
    // resurfaces. So: do the rm in the live mount, then RE-MOUNT `up:lower` read-only (as the merged
    // view would) and check the secret is STILL hidden. Only if it stays hidden across the re-mount is
    // the opaque truly persisted → layered is safe.
    // stderr silenced ({{…}} 2>/dev/null): this is an internal PROBE - only its exit status matters
    // (drives the layered-vs-flat decision). On a filesystem where the overlay `rm` can't fully remove
    // the dir (WSL's 9p/overlay: "rm: can't remove …: I/O error"), the probe correctly falls back to a
    // flat build; leaking that rm's diagnostic to the user's build output just looks alarming.
    let script = cs(format!(
        "{{ rm -rf {d}/mg/dir && mkdir {d}/mg/dir && \
           umount {d}/mg && \
           mount -t overlay overlay -o lowerdir={d}/up:{d}/lower,ro {d}/mg && \
           test ! -e {d}/mg/dir/secret; }} 2>/dev/null"
    ));
    let ret = libc::system(script.as_ptr());
    // system() returns the shell's wait-status; 0 exit == opaque persisted (secret gone after re-mount).
    if ret == 0 {
        libc::_exit(0);
    }
    libc::_exit(14);
}

fn probe_overlay(self_exe: &std::path::Path, base_lower: &str, work: &std::path::Path) -> bool {
    let probe = work.join(".probe");
    let ok = std::process::Command::new(self_exe)
        .env("KERN_BUILD_STEP", "1") // no transient scope for the throwaway probe box
        .arg("box")
        .arg(format!("_probe-{}", std::process::id()))
        .arg("--overlay-lower")
        .arg(base_lower)
        .arg("--overlay-upper")
        .arg(&probe)
        .arg("--quiet")
        .arg("--")
        .arg("true")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    remove_build_tree(&probe); // the probe leaves a mode-000 overlay workdir too
    ok
}

/// Run one `RUN` step inside a `kern box` with host networking, so writes persist to the build layer
/// and the command can fetch packages. **Layered:** overlay `base_lower` with the persistent upper
/// under `work` (no base copy). **Flat:** bind-mount the copied `write_dir`. Reuses the full box
/// isolation rather than a second sandbox path; a non-zero exit fails the build.
#[allow(clippy::too_many_arguments)]
fn run_build_step(
    self_exe: &std::path::Path,
    layered: bool,
    base_lower: &str,
    work: &std::path::Path,
    write_dir: &std::path::Path,
    config: &kern_oci::ImageConfig,
    argv: &[String],
    step: usize,
) -> Result<(), Error> {
    let mut cmd = std::process::Command::new(self_exe);
    cmd.env("KERN_BUILD_STEP", "1"); // skip the transient systemd-scope re-exec (build boxes are hot)
    cmd.arg("box")
        .arg(format!("_build-{}-{step}", std::process::id()));
    if layered {
        cmd.arg("--overlay-lower")
            .arg(base_lower)
            .arg("--overlay-upper")
            .arg(work);
    } else {
        cmd.arg("--rootfs").arg(write_dir).arg("--bind-rootfs");
    }
    cmd.arg("--net").arg("--uid-range").arg("--quiet");
    for e in &config.env {
        cmd.arg("--env").arg(e);
    }
    if let Some(w) = &config.workdir {
        cmd.arg("--workdir").arg(w);
    }
    cmd.arg("--");
    for a in argv {
        cmd.arg(a);
    }
    let status = cmd
        .status()
        .map_err(|e| Error::Sandbox(format!("RUN: cannot start kern box: {e}")))?;
    if !status.success() {
        // For a batched RUN this prints the combined `&&` chain; the box inherited stdio, so the
        // failing sub-step's own stderr already appeared above - enough to see which step failed.
        return Err(Error::Sandbox(format!(
            "RUN failed (exit {}): {}",
            status.code().unwrap_or(-1),
            display_run(argv)
        )));
    }
    Ok(())
}

/// `cp -a src/. dst` - copy the CONTENTS of `src` into the existing `dst`, preserving symlinks,
/// modes and timestamps (used to make a mutable copy of the pulled base rootfs).
fn copy_tree(src: &std::path::Path, dst: &std::path::Path) -> Result<(), Error> {
    std::fs::create_dir_all(dst).map_err(|e| Error::Sandbox(format!("build rootfs: {e}")))?;
    let ok = std::process::Command::new("cp")
        .arg("-a")
        .arg("--reflink=auto") // copy-on-write clone on btrfs/xfs (near-free); plain copy elsewhere
        .arg("--") // paths are absolute, but stop cp treating any of them as a flag
        .arg(format!("{}/.", src.display()))
        .arg(dst)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(Error::Sandbox(
            "copying the base rootfs failed (is `cp` available?)".into(),
        ))
    }
}

/// Whether a COPY/ADD source token carries a glob metacharacter Docker expands (`*`, `?`, `[`).
fn has_glob_meta(s: &str) -> bool {
    s.bytes().any(|b| b == b'*' || b == b'?' || b == b'[')
}

/// `filepath.Match`-style match of ONE path component (never spans `/`, like Docker's COPY glob):
/// `*` = any run, `?` = one char, `[set]`/`[!set]` = a class (with `a-z` ranges). Patterns are short.
fn glob_match_component(pat: &[u8], name: &[u8]) -> bool {
    if pat.is_empty() {
        return name.is_empty();
    }
    match pat[0] {
        b'*' => {
            glob_match_component(&pat[1..], name)
                || (!name.is_empty() && glob_match_component(pat, &name[1..]))
        }
        b'?' => !name.is_empty() && glob_match_component(&pat[1..], &name[1..]),
        b'[' => {
            if name.is_empty() {
                return false;
            }
            let neg = pat.get(1) == Some(&b'!');
            let mut i = if neg { 2 } else { 1 };
            let start = i;
            let mut hit = false;
            while i < pat.len() && (pat[i] != b']' || i == start) {
                if i + 2 < pat.len() && pat[i + 1] == b'-' && pat[i + 2] != b']' {
                    if name[0] >= pat[i] && name[0] <= pat[i + 2] {
                        hit = true;
                    }
                    i += 3;
                } else {
                    if pat[i] == name[0] {
                        hit = true;
                    }
                    i += 1;
                }
            }
            if i >= pat.len() {
                return false; // unterminated class → no match
            }
            (hit != neg) && glob_match_component(&pat[i + 1..], &name[1..])
        }
        c => !name.is_empty() && name[0] == c && glob_match_component(&pat[1..], &name[1..]),
    }
}

/// Expand a COPY source pattern (context-relative, `/`-separated) into matching relative paths, one
/// component at a time (Docker matches `filepath.Match` per component). A component with no glob meta
/// is taken literally. Sorted; empty if nothing matched.
fn glob_expand_ctx(ctx: &std::path::Path, pattern: &str) -> Vec<String> {
    let comps: Vec<&str> = pattern
        .trim_start_matches("./")
        .split('/')
        .filter(|c| !c.is_empty())
        .collect();
    let mut cur = vec![String::new()];
    for comp in comps {
        let mut next = Vec::new();
        for base in &cur {
            let base_dir = if base.is_empty() {
                ctx.to_path_buf()
            } else {
                ctx.join(base)
            };
            if has_glob_meta(comp) {
                if let Ok(rd) = std::fs::read_dir(&base_dir) {
                    for e in rd.flatten() {
                        let nm = e.file_name();
                        let nm = nm.to_string_lossy();
                        if glob_match_component(comp.as_bytes(), nm.as_bytes()) {
                            next.push(if base.is_empty() {
                                nm.into_owned()
                            } else {
                                format!("{base}/{nm}")
                            });
                        }
                    }
                }
            } else {
                let cand = if base.is_empty() {
                    comp.to_string()
                } else {
                    format!("{base}/{comp}")
                };
                if ctx.join(&cand).symlink_metadata().is_ok() {
                    next.push(cand);
                }
            }
        }
        cur = next;
    }
    cur.sort();
    cur
}

/// Expand any glob sources in a context COPY/ADD `srcs` list against `ctx`; literal sources pass
/// through unchanged. Errors if a glob matches nothing (Docker: "no source files were specified").
fn expand_copy_srcs(ctx: &std::path::Path, srcs: &[String]) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    for s in srcs {
        if has_glob_meta(s) {
            let m = glob_expand_ctx(ctx, s);
            if m.is_empty() {
                return Err(Error::Sandbox(format!("COPY: no source files match '{s}'")));
            }
            out.extend(m);
        } else {
            out.push(s.clone());
        }
    }
    Ok(out)
}

/// Copy `src_rel` (relative to the build context) into the build `rootfs` at `dst`, refusing to
/// escape the context (source) or traverse a symlinked component of the image (destination). A
/// relative `dst` (e.g. `COPY x .`) resolves against the current `workdir` (Docker semantics).
/// Drop the `.` and empty segments a path join creates, leaving `..` ALONE.
///
/// `..` is deliberately kept: `sanitize_rootfs_rel` refuses it, and resolving it here would quietly
/// turn a rejected escape into an accepted write.
fn collapse_dot_segments(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

fn copy_into_rootfs(
    ctx: &std::path::Path,
    src_rel: &str,
    rootfs: &std::path::Path,
    dst: &str,
    workdir: Option<&str>,
    chain: &[String],
    chmod: Option<&str>,
) -> Result<(), Error> {
    // Source must resolve to a real path INSIDE the context (no `../`, no symlink pointing out).
    let src = std::fs::canonicalize(ctx.join(src_rel))
        .map_err(|e| Error::Sandbox(format!("COPY source '{src_rel}': {e}")))?;
    if !src.starts_with(ctx) {
        return Err(Error::Sandbox(format!(
            "COPY source '{src_rel}' escapes the build context"
        )));
    }
    // A relative destination is taken against the current WORKDIR (default `/`).
    let dst_abs = if dst.starts_with('/') {
        dst.to_string()
    } else {
        format!("{}/{}", workdir.unwrap_or("/").trim_end_matches('/'), dst)
    };
    // Then the `.` segments that join just created are dropped. `WORKDIR /app` + `COPY . .` builds
    // `/app/.`, and `cp` fails trying to create a directory literally named `.` - which broke the
    // single most common shape an application Dockerfile has. `COPY . /app` and `COPY main.py .`
    // both worked, which is why it survived: only a DIRECTORY source with a relative dot
    // destination under a non-root WORKDIR hits it.
    let dst_abs = collapse_dot_segments(&dst_abs);
    // Destination resolution (Docker semantics, verified against `docker build`):
    //   - a FILE into a directory dest keeps its basename → `dst/<file>`.
    //   - a DIRECTORY source has its CONTENTS copied into dest (`COPY dir /d/` → `/d/<contents>`,
    //     NEVER `/d/dir`); the `cp -a src/.` below fills `dst` directly, so a dir targets `dst` itself.
    //   - a FILE to a non-dir dest is a rename → `dst`.
    // `rootfs` is this unit's fresh (empty) layer, so a dir that exists only in a LOWER layer is found
    // via `chain` (the cached-layer build); the flat build passes an empty chain.
    let dst_clean = dst_abs.trim_start_matches('/');
    let dst_is_dir =
        dst.ends_with('/') || rootfs.join(dst_clean).is_dir() || chain_has_dir(chain, dst_clean);
    let target_rel = if dst_is_dir && !src.is_dir() {
        let base = src
            .file_name()
            .ok_or(Error::Sandbox("COPY source has no file name".into()))?;
        format!(
            "{}/{}",
            dst_clean.trim_end_matches('/'),
            base.to_string_lossy()
        )
    } else {
        dst_clean.trim_end_matches('/').to_string()
    };
    // Reject `..` (and re-strip any leading `/` the dir-branch reintroduced): a `..` component is a
    // real directory, so `whiteout_dir_symlink_free` (symlinks only) waves it through, and
    // `rootfs.join(..)` / `cp` would then escape the rootfs to write anywhere on the host.
    let target_rel = sanitize_rootfs_rel(dst, &target_rel)?;
    // No symlinked component in the target's parent may lead out of the rootfs (image could plant
    // `dst -> /host`). Then create the parents as REAL dirs and copy.
    let parent_rel = std::path::Path::new(&target_rel)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !kern_oci::whiteout_dir_symlink_free(&rootfs.to_string_lossy(), &parent_rel) {
        return Err(Error::Sandbox(format!(
            "COPY dest '{dst}' crosses a symlink in the image"
        )));
    }
    let target = rootfs.join(&target_rel);
    if let Some(p) = target.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    // If the target itself is an existing symlink, unlink it so we don't copy THROUGH it out of the
    // rootfs (COPY overwrites the name, following Docker).
    if let Ok(m) = std::fs::symlink_metadata(&target) {
        if m.file_type().is_symlink() {
            let _ = std::fs::remove_file(&target);
        }
    }
    // When the build context carries a `.dockerignore`/`.kernignore`, a directory COPY must skip the
    // excluded paths (so `COPY . /app` doesn't bake `.git`/secrets). The filter needs re-include
    // (`!`) and last-match-wins semantics that `cp`/`tar --exclude` can't express, so a directory copy
    // with an ignore file present goes through a no-follow Rust walk instead of `cp -a`. With NO ignore
    // file (the common case) the fast `cp -a` path below is unchanged.
    if src.is_dir() {
        if let Some(ig) = crate::dockerignore::DockerIgnore::load(ctx) {
            let _ = std::fs::create_dir_all(&target);
            // Match ignore paths relative to the CANONICAL context root: `src` is already canonicalized,
            // so a symlinked context path (e.g. `/tmp` -> `/private/tmp`, or a symlinked project dir)
            // would otherwise make `strip_prefix` fail and silently disable filtering - a fail-OPEN
            // that would leak the very secrets the ignore file exists to keep out. Falls back to raw
            // `ctx` only if canonicalize fails (then the walk fails CLOSED on any un-strippable entry).
            let ctx_root = std::fs::canonicalize(ctx).unwrap_or_else(|_| ctx.to_path_buf());
            copy_dir_filtered(&src, &target, &ctx_root, &ig)
                .map_err(|e| Error::Sandbox(format!("COPY '{src_rel}' → '{dst}': {e}")))?;
            return apply_chmod_tree(&target, chmod);
        }
    }
    let arg = if src.is_dir() {
        let _ = std::fs::create_dir_all(&target);
        format!("{}/.", src.display())
    } else {
        src.to_string_lossy().into_owned()
    };
    // SECURITY INVARIANT (do not break): `cp -a` implies `--no-dereference` - it PRESERVES symlinks in
    // the copied tree rather than following them. This is load-bearing for the build-context confinement
    // (the "duale-di-Z2" note in `resolve_builds`): the COPY source root is confined by canonicalize +
    // starts_with, and because the recursive descent here does NOT follow inner symlinks, a symlink
    // buried in the context lands in the image verbatim (dangling in the pivoted rootfs) and its host
    // target is never read at build time. If this `cp -a` is ever replaced (e.g. a Rust `walkdir` copy
    // for portability), that replacement MUST be no-follow too, or a `leak -> /host/secret` inside a
    // build context would leak the host file into the image. Verified live: it does not, today.
    let ok = std::process::Command::new("cp")
        .arg("-a")
        .arg("--") // src/target are absolute, but never let cp parse them as flags
        .arg(&arg)
        .arg(&target)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        apply_chmod_tree(&target, chmod)
    } else {
        Err(Error::Sandbox(format!("COPY '{src_rel}' → '{dst}' failed")))
    }
}

/// Recursively copy directory `src` into `target`, SKIPPING paths the context's ignore rules exclude
/// (matched relative to `ctx`, the context root). NO-FOLLOW - the same confinement invariant as the
/// `cp -a` path: a symlink is recreated as a symlink, never traversed, so a `leak -> /host/secret` in
/// the context lands dangling in the image and its host target is never read. File MODE is preserved
/// (an executable script stays executable). Non-regular entries (fifo/socket/device - which don't
/// belong in a build context) are skipped.
fn copy_dir_filtered(
    src: &std::path::Path,
    target: &std::path::Path,
    ctx: &std::path::Path,
    ig: &crate::dockerignore::DockerIgnore,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let md = std::fs::symlink_metadata(&path)?;
        let ft = md.file_type();
        // The path RELATIVE TO THE CONTEXT ROOT drives ignore matching (dockerignore is context-
        // relative). If it can't be made relative (shouldn't happen - `src` and `ctx` are both
        // canonical), fail CLOSED (skip) rather than copy an un-vetted file.
        let Ok(rel) = path.strip_prefix(ctx) else {
            continue;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        let dest = target.join(entry.file_name());
        if ft.is_dir() {
            // Prune a wholly-excluded subtree only when no `!` rule could re-include a descendant.
            if ig.can_prune_dir(&rel) {
                continue;
            }
            std::fs::create_dir_all(&dest)?;
            copy_dir_filtered(&path, &dest, ctx, ig)?;
        } else if ig.excluded(&rel) {
            continue;
        } else if ft.is_symlink() {
            // Recreate the symlink verbatim - NEVER follow it (a `leak -> /host/secret` in the context
            // must land dangling, its target never read at build time).
            let link = std::fs::read_link(&path)?;
            let _ = std::fs::remove_file(&dest);
            std::os::unix::fs::symlink(&link, &dest)?;
        } else if ft.is_file() {
            // Unlink any pre-existing dest first, so a symlink planted at that path (e.g. by the base
            // image) can't make `fs::copy` write THROUGH it out of the rootfs - stricter than `cp -a`.
            let _ = std::fs::remove_file(&dest);
            std::fs::copy(&path, &dest)?;
            std::fs::set_permissions(
                &dest,
                std::fs::Permissions::from_mode(md.permissions().mode()),
            )?;
        }
    }
    Ok(())
}

/// Set (replace or append) `K=V` in an image-config env list.
fn set_config_env(env: &mut Vec<String>, k: &str, v: &str) {
    let prefix = format!("{k}=");
    let entry = format!("{k}={v}");
    match env.iter_mut().find(|e| e.starts_with(&prefix)) {
        Some(e) => *e = entry,
        None => env.push(entry),
    }
}

/// Apply a CMD or ENTRYPOINT instruction to the image config - the ONE place the Docker rule
/// "ENTRYPOINT resets an inherited base CMD unless this Dockerfile set its own CMD" lives, so the
/// flat and layer-cached build loops can't drift. Config-only: neither touches the filesystem.
/// `cmd_seen` records whether THIS Dockerfile has set a CMD.
fn apply_cmd_entrypoint(
    config: &mut kern_oci::ImageConfig,
    ins: &crate::dockerfile::Instr,
    cmd_seen: &mut bool,
) {
    use crate::dockerfile::Instr;
    match ins {
        Instr::Cmd(a) => {
            config.cmd = a.clone();
            *cmd_seen = true;
        }
        Instr::Entrypoint(a) => {
            config.entrypoint = a.clone();
            if !*cmd_seen {
                config.cmd.clear();
            }
        }
        _ => {}
    }
}

/// Resolve a `WORKDIR` operand: absolute stays as-is, relative joins onto the previous workdir
/// (default `/`), matching Docker.
fn resolve_workdir(prev: Option<&str>, d: &str) -> String {
    if d.starts_with('/') {
        d.to_string()
    } else {
        format!("{}/{}", prev.unwrap_or("/").trim_end_matches('/'), d)
    }
}

/// Turn an in-image path into a rootfs-relative one that CANNOT escape: strip leading `/`, then
/// reject any `..` component. `..` is a real directory, so the symlink-only
/// [`kern_oci::whiteout_dir_symlink_free`] guard doesn't catch it; without this a `COPY`/`WORKDIR`
/// dest of `../../etc/…` would let `cp`/`create_dir_all` write outside the rootfs onto the host.
fn sanitize_rootfs_rel(orig: &str, rel: &str) -> Result<String, Error> {
    let rel = rel.trim_start_matches('/');
    if std::path::Path::new(rel)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::Build(format!(
            "'{orig}' escapes the image rootfs (`..`)"
        )));
    }
    Ok(rel.to_string())
}

/// `mkdir -p` a workdir inside the rootfs, refusing a `..` escape or a symlinked component that
/// leads out.
fn mkdir_in_rootfs(rootfs: &std::path::Path, dir: &str) -> Result<(), Error> {
    let rel = sanitize_rootfs_rel(dir, dir)?;
    if !kern_oci::whiteout_dir_symlink_free(&rootfs.to_string_lossy(), &rel) {
        return Err(Error::Sandbox(format!(
            "WORKDIR '{dir}' crosses a symlink in the image"
        )));
    }
    let _ = std::fs::create_dir_all(rootfs.join(&rel));
    Ok(())
}

/// Seed `/etc/resolv.conf` in the build rootfs from the host so RUN steps can resolve DNS over the
/// shared network namespace. Returns `true` if it CREATED the file (the base had none) so the caller
/// can remove it before finalizing - we don't want the host's DNS servers baked into the image
/// (Docker provides resolv.conf only at runtime). Best-effort; a base that ships its own is left be.
fn seed_resolv_conf(rootfs: &std::path::Path) -> bool {
    let dst = rootfs.join("etc/resolv.conf");
    if dst.exists() {
        return false; // base image already has one - leave it, don't touch/remove it
    }
    if let Ok(rc) = std::fs::read("/etc/resolv.conf") {
        let _ = std::fs::create_dir_all(rootfs.join("etc"));
        if std::fs::write(&dst, rc).is_ok() {
            return true;
        }
    }
    false
}

/// The shell script of a shell-form RUN (`["/bin/sh","-c",<script>]`), or `None` for an exec-form
/// RUN - only shell-form RUNs are safe to batch into one box.
fn run_shell_script(argv: &[String]) -> Option<&str> {
    match argv {
        [sh, dashc, s] if sh == "/bin/sh" && dashc == "-c" => Some(s),
        _ => None,
    }
}

/// Single-quote a string for POSIX sh (`'` → `'\''`), so an arbitrary RUN script can be embedded in
/// the batched command without the outer shell reinterpreting it.
fn shell_quote_single(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Combine consecutive shell-form RUN scripts into one box command: each original script runs in its
/// own `/bin/sh -c '<script>'` subshell (exact per-RUN semantics + cwd reset), chained with `&&` so
/// the batch fails at the first failing step. A single script needs no re-wrap.
fn combine_run_scripts(scripts: &[&str]) -> Vec<String> {
    debug_assert!(!scripts.is_empty(), "combine_run_scripts needs ≥1 script");
    if scripts.len() == 1 {
        return vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            scripts[0].to_string(),
        ];
    }
    let combined = scripts
        .iter()
        .map(|s| format!("/bin/sh -c {}", shell_quote_single(s)))
        .collect::<Vec<_>>()
        .join(" && ");
    vec!["/bin/sh".to_string(), "-c".to_string(), combined]
}

/// Human-readable form of a RUN/CMD argv for progress lines: unwrap the `sh -c "…"` shell form.
fn display_run(argv: &[String]) -> String {
    // Unwrap OUR shell-form wrapper (`/bin/sh -c <s>`); an exec-form the user wrote prints in full.
    match run_shell_script(argv) {
        Some(s) => s.to_string(),
        None => argv.join(" "),
    }
}

/// Per-box writable overlay scratch (upper/work) - placed on **tmpfs** where possible
/// (`$XDG_RUNTIME_DIR` → `/run/user/<uid>`, both tmpfs), else `/tmp`. tmpfs makes the create /
/// overlay-mount / cleanup RAM-fast and keeps the writable layer ephemeral; its pages count
/// against the box's memory cap. Created mode 0700 by the caller.
fn scratch_dir() -> PathBuf {
    crate::registry::assert_registry_child("scratch"); // classification chokepoint (see registry.rs)
                                                       // An explicit XDG_RUNTIME_DIR always wins - it is the documented override.
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(x).join("kern/scratch");
    }
    let uid = unsafe { libc::getuid() };
    // The scratch holds each box's overlay upper/work - and the kernel refuses an overlay UPPER
    // that itself lives on overlayfs. On a normal host `/run/user/<uid>` (tmpfs) or `/tmp` is fine;
    // when kern runs INSIDE a Docker/CI container BOTH sit on the container's overlay rootfs, so
    // probe the candidates and take the first non-overlay one. `/dev/shm` is a real tmpfs even
    // inside Docker (size-capped - last resort, announced on stderr so an ENOSPC later isn't a
    // mystery). If everything is overlayfs, fall through to /tmp and let the mount fail with the
    // actionable nested-overlay error from kern-isolation.
    let run = PathBuf::from(format!("/run/user/{uid}"));
    let mut cands: Vec<(PathBuf, &str)> = Vec::new();
    if run.is_dir() {
        cands.push((run.join("kern/scratch"), "run"));
    }
    cands.push((PathBuf::from(format!("/tmp/kern-{uid}/scratch")), "tmp"));
    cands.push((PathBuf::from(format!("/dev/shm/kern-{uid}/scratch")), "shm"));
    for (cand, kind) in &cands {
        if fs_magic_of(cand) != Some(OVERLAYFS_SUPER_MAGIC) {
            if *kind == "shm" && !kern_common::env_flag("KERN_QUIET") {
                static ONCE: std::sync::Once = std::sync::Once::new();
                ONCE.call_once(|| {
                    eprintln!(
                        "kern: note: /run and /tmp are on overlayfs (container?) - using the \
                         size-capped /dev/shm for box scratch; set XDG_RUNTIME_DIR to a tmpfs/disk \
                         path for full capacity"
                    );
                });
            }
            return cand.clone();
        }
    }
    PathBuf::from(format!("/tmp/kern-{uid}/scratch"))
}

const OVERLAYFS_SUPER_MAGIC: i64 = 0x794c7630;

/// Filesystem magic (`statfs.f_type`) of `p`'s deepest EXISTING ancestor - the path itself usually
/// doesn't exist yet (the scratch is created later). `None` only if nothing up to `/` can be stat'd.
fn fs_magic_of(p: &std::path::Path) -> Option<i64> {
    let mut cur = p;
    loop {
        if let Ok(c) = std::ffi::CString::new(cur.as_os_str().as_encoded_bytes()) {
            let mut st: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0 {
                return Some(st.f_type as i64);
            }
        }
        cur = cur.parent()?;
    }
}

/// `kern stop <name>... | --all` - stop running box(es): SIGKILL each target supervisor's process
/// group (tearing down the box's PID namespace), drop its registry entry, and remove its writable
/// scratch. Stops every name in `names` (a name may match more than one box if names ever collide),
/// or - with `all` - every running box. A requested name that isn't running is reported on stderr
/// (never silently ignored); the command succeeds as long as at least one box was stopped.
/// The running boxes matching a list of user refs - each a box NAME or (fallback) its `kern ps`
/// supervisor PID. NAME WINS GLOBALLY: `!live_names.contains(n)` gates the pid branch, so an all-digit
/// box name is never shadowed by a coincidental pid, and `stop 79` can't hit both a box named "79" and
/// a different pid-79 box. Shared by `stop` and `pause`/`unpause` (the multi-target live commands).
fn boxes_matching_refs(
    running: Vec<registry::Instance>,
    refs: &[String],
) -> Vec<registry::Instance> {
    let live_names = live_name_set(&running);
    running
        .into_iter()
        .filter(|b| refs.iter().any(|n| ref_matches(b, n, &live_names)))
        .collect()
}

/// The set of live box names, for the NAME-wins gate. A `HashSet` (not a `Vec`) so `ref_matches`'
/// membership test is O(1): it's called for every (box × ref) pair, so a `Vec::contains` scan would
/// make selection O(N²) in the box count when stopping/pausing many refs.
fn live_name_set(running: &[registry::Instance]) -> std::collections::HashSet<String> {
    running.iter().map(|b| b.name.clone()).collect()
}

/// Does ref `n` select box `b`? A ref matches by NAME (always), else - only when no live box bears
/// that exact name (NAME wins globally) - by its PID or by its POD name. Matching a pod name selects
/// every member of that pod, so `kern stop <pod>` / `kern pause <pod>` act on the whole group.
fn ref_matches(
    b: &registry::Instance,
    n: &str,
    live_names: &std::collections::HashSet<String>,
) -> bool {
    n == b.name
        // `HashSet<String>::contains(&str)` via Borrow - O(1), no per-call allocation.
        || (!live_names.contains(n)
            // The pod branch guards against an EMPTY ref: a standalone box has `pod == ""`, so an
            // empty `n` would otherwise sweep every standalone box. A pid parses only when non-empty.
            && (n.parse::<i32>().ok() == Some(b.pid) || (!n.is_empty() && n == b.pod)))
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

/// The systemd unit file name for a persistent box - the naming convention lives here only.
fn unit_file_name(name: &str) -> String {
    format!("kern-{name}.service")
}

/// The `X-` key kern stamps into every unit IT writes for a persistent box. systemd ignores unknown
/// `X-` keys and preserves them, which makes this a free, machine-readable claim of ownership.
const MANAGED_MARKER: &str = "X-KernManagedBox";

/// Is this unit file one kern wrote for a persistent box, and therefore one kern may DELETE?
///
/// The name is not evidence. `stop --all` used to treat every `kern-*.service` in the user's unit
/// directory as its own and remove it, so a unit the user wrote by hand - including the one
/// `kern compose … systemd` tells them to write, which is named exactly that way - was deleted by an
/// unrelated `kern stop --all`. Deleting a file kern never created, outside kern's own state
/// directories, is not a cleanup; it is data loss.
///
/// Ownership is therefore asserted POSITIVELY, by two marks, and anything else is left alone:
///
/// * [`MANAGED_MARKER`], stamped by every unit kern writes from now on;
/// * `Description=kern box <name>`, which every unit kern wrote BEFORE the marker existed carries,
///   so an already-installed persistent box keeps being cleaned up across the upgrade.
///
/// Fail-safe by construction: a file that cannot be read, or is too large to be one of ours, is NOT
/// ours. The read is bounded because this runs over every candidate in a directory kern does not own.
fn is_kern_managed_unit(path: &std::path::Path) -> bool {
    use std::io::Read;
    // A kern unit is a few hundred bytes. 64 KiB is far above any of ours and far below a file worth
    // paging in; a truncated read can only ever make the answer "not ours", which is the safe one.
    const MAX: usize = 64 * 1024;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = Vec::new();
    if f.by_ref().take(MAX as u64).read_to_end(&mut buf).is_err() {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&buf) else {
        return false;
    };
    text.lines().any(|l| {
        let l = l.trim();
        l.starts_with(MANAGED_MARKER) || l.starts_with("Description=kern box ")
    })
}

/// Path of the systemd user unit for a persistent box named `name` (if the user's systemd dir is
/// resolvable). Existence of this file is what marks a box as systemd-managed. Returns `None` for a
/// name that isn't a valid box name - `kern stop <name>` takes raw, unvalidated names, and a `../`
/// one must never let `stop_managed_unit`'s `remove_file` escape the systemd user dir.
fn managed_unit_path(name: &str) -> Option<PathBuf> {
    BoxName::parse(name).ok()?;
    user_systemd_dir()
        .ok()
        .map(|d| d.join(unit_file_name(name)))
}

/// If `name` is a persistent (systemd-managed) box, stop + disable its unit and remove the unit file
/// so it neither restarts nor returns at reboot. Returns `true` if a unit was found and torn down.
fn stop_managed_unit(name: &str) -> bool {
    let Some(path) = managed_unit_path(name) else {
        return false;
    };
    // Last line of defence, deliberately duplicated with the callers' filter: this function DELETES,
    // and a future caller that forgets to filter must not be able to remove a stranger's unit.
    if !is_kern_managed_unit(&path) {
        return false;
    }
    let unit = unit_file_name(name);
    systemctl_user(&["disable", "--now", &unit]);
    // Clear any lingering `failed` state so the removed unit doesn't leave a ghost in `systemctl
    // --user status`; then delete the unit file and reload so systemd forgets it entirely.
    systemctl_user(&["reset-failed", &unit]);
    let _ = std::fs::remove_file(&path);
    systemctl_user(&["daemon-reload"]);
    true
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

/// Remove the overlay scratch behind a box, derived from its merge path
/// (`<cache>/scratch/<name>-<pid>/merged`).
fn cleanup_box_scratch(rootfs: &str) {
    let p = std::path::Path::new(rootfs);
    if p.file_name().is_none_or(|n| n != "merged") {
        return;
    }
    let Some(scratch) = p.parent() else { return };
    // CONFINEMENT (the ranged fallback below runs a privileged newuidmap'd remove_dir_all, so the path
    // must be provably ours): require `scratch`'s parent to be kern's own scratch root - not a weak
    // `.contains("/scratch/")` (which `/tmp/scratch/../../etc` would pass). Canonicalize both sides so
    // no `..`/symlink in the registry-derived rootfs can steer the remove outside kern's scratch tree.
    let root = scratch_dir();
    let canon_root = std::fs::canonicalize(&root).unwrap_or(root);
    let parent_ok = scratch.parent().is_some_and(|par| {
        std::fs::canonicalize(par)
            .map(|c| c == canon_root)
            .unwrap_or(false)
    });
    if !parent_ok {
        return;
    }
    // Route through cleanup_scratch's ranged fallback: a `--uid-range`/pod box whose image dropped
    // privilege leaves subordinate-uid-owned files (e.g. grafana's /var/lib/grafana owned by subuid
    // 100471) that a plain remove_dir_all can't unlink from the host - the fallback retries inside a
    // newuidmap'd user ns where they're removable.
    cleanup_scratch(Some(scratch));
}

/// How long `compose up` waits for a `depends_healthy` / `depends_completed` condition before it
/// gives up and aborts the bring-up. Docker's default `--wait` has no ceiling; we cap it so a stuck
/// dependency fails loudly instead of hanging a scripted `up` forever. Generous enough for a cold
/// database (postgres init + first health pass is a few seconds).
const COMPOSE_CONDITION_TIMEOUT_SECS: u64 = 120;

/// The exit-sidecar key for a box: `<pod>-<token>-<name>`. `<pod>` namespaces by STACK (two stacks
/// with a `db` don't collide - review 1b); `<token>` namespaces by this `up`'s RUN (two concurrent
/// `up`s of the SAME stack own separate files, so one's clear/write can't clobber the other's real
/// completion - review round 2, the round-1 "token only inside the file" left the filename shared).
/// `compose_pod_name(file)` is stable per compose file even for a `--no-pod` stack (no live pod), so
/// the prefix is well-defined in both modes. `compose down` doesn't know the `up`'s token, so it reaps
/// each box's sidecar by `exit_key_prefix(pod)` ++ `-<name>` (pod-prefix AND name-suffix) - NOT a
/// blind pod prefix, which would wipe a concurrent same-stack run's in-flight files.
fn exit_key(pod: &str, token: &str, name: &str) -> String {
    format!("{pod}-{token}-{name}")
}

/// The `<pod>-` prefix shared by every exit key of a stack - the LEADING anchor for `compose down`'s
/// reap; the box name (`-<name>`) is the trailing anchor, so together they bracket any token.
fn exit_key_prefix(pod: &str) -> String {
    format!("{pod}-")
}

/// Resolve every service's compose `build:` into a built image via `kern build`, mutating the box's
/// `image` to the built tag. See the call site for the four hardenings; this enforces them.
fn resolve_builds(
    boxes: &mut [crate::compose::ComposeBox],
    file: &str,
    self_exe: &std::path::Path,
) -> Result<(), Error> {
    // The directory that a `build.context` is confined under: the compose file's parent (canonical).
    let compose_dir = compose_dir(file);
    let base = std::fs::canonicalize(&compose_dir).map_err(|e| {
        Error::Compose(format!(
            "resolving compose dir '{}': {e}",
            compose_dir.display()
        ))
    })?;

    for b in boxes.iter_mut() {
        let Some(bd) = b.build.clone() else { continue };
        // Guard 1 - CONFINE context under the compose dir. Canonicalize `base/context` and require the
        // result stays beneath `base`, so a `context: ../../../etc` in a third-party compose can't
        // escape the project tree. (Same traversal class as image/volume/pod names in the saga.)
        // NOTE (duale-di-Z2): confining the context ROOT here is not enough on its own - `kern build`
        // then DESCENDS the context (COPY). That descent is itself confined: `copy_into_rootfs`
        // canonicalizes each COPY source and requires `starts_with(ctx)` (a source symlink pointing out
        // is rejected), and `cp -a` PRESERVES inner symlinks rather than following them (so a symlink
        // buried in the tree lands in the image verbatim - dangling inside the pivoted rootfs - never
        // read at build time). Verified live: a `leak -> /host/secret` inside the context does not leak
        // the host file into the image. So root-confine here + no-follow descent in build = closed.
        let ctx_abs = std::fs::canonicalize(base.join(&bd.context)).map_err(|e| {
            Error::Compose(format!(
                "service '{}': build context '{}': {e}",
                b.name, bd.context
            ))
        })?;
        if !ctx_abs.starts_with(&base) {
            return Err(Error::Compose(format!(
                "service '{}': build context '{}' escapes the compose directory (refused)",
                b.name, bd.context
            )));
        }
        // Guard 1 (dockerfile) - if given, confine it under the CONTEXT (Docker resolves `dockerfile`
        // relative to the context). Reject an escaping dockerfile path.
        let dfile = match &bd.dockerfile {
            Some(df) => {
                let df_abs = std::fs::canonicalize(ctx_abs.join(df)).map_err(|e| {
                    Error::Compose(format!("service '{}': dockerfile '{df}': {e}", b.name))
                })?;
                if !df_abs.starts_with(&ctx_abs) {
                    return Err(Error::Compose(format!(
                        "service '{}': dockerfile '{df}' escapes the build context (refused)",
                        b.name
                    )));
                }
                Some(df_abs)
            }
            None => None,
        };

        // Guard 4 - `image:` + `build:` = build AND tag as `image`; `build:` alone → synthesized tag.
        // Either way the box RUNS the freshly built image, never a stale registry one.
        let tag = b
            .image
            .clone()
            .unwrap_or_else(|| format!("kern-compose-{}:latest", b.name));

        eprintln!("→ building '{}' from {}", b.name, bd.context);
        let mut cmd = std::process::Command::new(self_exe);
        cmd.arg("build").arg("-t").arg(&tag);
        if let Some(df) = &dfile {
            cmd.arg("-f").arg(df);
        }
        for a in &bd.args {
            cmd.arg("--build-arg").arg(a); // already ${VAR}-interpolated by the parser (guard 2)
        }
        cmd.arg(&ctx_abs);
        // Guard 3 - a build failure fails the whole `up` with a linked, service-named message.
        let status = cmd.status().map_err(|e| {
            Error::Compose(format!("service '{}': running `kern build`: {e}", b.name))
        })?;
        if !status.success() {
            return Err(Error::Compose(format!(
                "service '{}': build failed - run `kern build -t {tag} {}` to see why",
                b.name,
                ctx_abs.display()
            )));
        }
        b.image = Some(tag);
    }
    Ok(())
}

/// Reject conditional dependencies that can NEVER be satisfied, at bring-up time rather than after a
/// two-minute timeout (adversarial-review 2d). `topo_order` (called before this) already rejects
/// cycles and unknown deps; this adds the one statically-impossible case:
///   * `depends_healthy` on a box with no `health_cmd` - it can never report healthy.
///
/// NOTE on `depends_completed` + `restart`: the review suggested rejecting it, but in kern's compose
/// `restart = true` means ON-FAILURE (a bare `--restart`), NOT always-respawn - the supervisor re-runs
/// the box ONLY on a non-zero exit. So a `depends_completed` target that exits 0 completes normally,
/// and one that keeps failing crash-loops to the restart cap and then records its final non-zero exit,
/// which fails the wait cleanly. `restart = true` + `depends_completed` is therefore COHERENT, not
/// impossible - we must NOT reject it. (Were compose ever to gain an `always`/`unless-stopped` policy,
/// THAT would be the never-completes case to reject here.)
fn validate_conditions(boxes: &[crate::compose::ComposeBox]) -> Result<(), Error> {
    let find = |n: &str| boxes.iter().find(|x| x.name == n);
    for b in boxes {
        for dep in &b.depends_healthy {
            if find(dep).is_some_and(|x| x.health_cmd.is_none()) {
                return Err(Error::Compose(format!(
                    "box '{}' waits for '{dep}' to be healthy, but '{dep}' declares no `health_cmd` \
                     (add one, or use `depends_on`/`depends_completed`)",
                    b.name
                )));
            }
        }
    }
    Ok(())
}

/// Block until every conditional dependency of `b` is satisfied, or fail with a precise reason.
/// `depends_healthy[dep]` waits until `dep`'s health check reports `healthy`; `depends_completed[dep]`
/// waits until `dep` has run to completion (exit 0), keyed by `pod`+`token` so a same-named service in
/// another stack, or a previous run's sidecar, can't satisfy it. Driven off the registry sidecars the
/// box machinery already writes - no IPC of our own. Polled at 100 ms so a fast dep adds only a
/// sub-100 ms tail, not Docker's whole-second-per-health-interval granularity.
///
/// A dependency that DIES before satisfying its condition aborts immediately (adversarial-review 2a) -
/// we don't burn the full timeout on an already-decided outcome. The registry's liveness (a dep no
/// longer in `list()` and with no completion recorded) is the death signal.
fn wait_for_conditions(
    b: &crate::compose::ComposeBox,
    pod: &str,
    token: &str,
) -> Result<(), Error> {
    use std::time::{Duration, Instant};
    if b.depends_healthy.is_empty() && b.depends_completed.is_empty() {
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_secs(COMPOSE_CONDITION_TIMEOUT_SECS);
    let key_of = |dep: &str| exit_key(pod, token, dep);

    // `depends_healthy`: poll each dep's health sidecar until healthy. Abort on unhealthy, on the dep
    // dying, or on timeout.
    for dep in &b.depends_healthy {
        eprintln!(
            "  ⋯ waiting for '{dep}' to become healthy (for '{}')",
            b.name
        );
        loop {
            let status = current_health(dep);
            if status == "healthy" {
                break;
            }
            if status == "unhealthy" {
                return Err(Error::Compose(format!(
                    "box '{}': dependency '{dep}' is unhealthy (its health check keeps failing)",
                    b.name
                )));
            }
            // Dead before healthy - decided; don't wait out the timeout. Prefer the POSITIVE death
            // signal (a written exit sidecar) over the prune-timing one (absence from `list()`): a box
            // targeted by a `depends_completed` writes its exit on death, so a completion sidecar for
            // this dep is proof it's gone. Fall back to registry liveness for a dep that ISN'T a
            // completion target (no sidecar), where absence-from-`list()` is the only death signal -
            // there the timeout backstops the ≤1-poll prune lag (review 2a).
            let died = registry::exit_of(&key_of(dep)).is_some() || !is_box_alive(dep);
            if died {
                return Err(Error::Compose(format!(
                    "box '{}': dependency '{dep}' exited before becoming healthy - run `kern logs \
                     {dep}` for the reason (a crash, or e.g. a port already bound by a pod peer)",
                    b.name
                )));
            }
            if Instant::now() >= deadline {
                return Err(Error::Compose(format!(
                    "box '{}': timed out after {COMPOSE_CONDITION_TIMEOUT_SECS}s waiting for '{dep}' \
                     to become healthy (last status: '{}')",
                    b.name,
                    if status.is_empty() { "none yet" } else { &status }
                )));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // `depends_completed`: poll each dep's stack+run-scoped exit sidecar until it completes; require 0.
    for dep in &b.depends_completed {
        eprintln!("  ⋯ waiting for '{dep}' to complete (for '{}')", b.name);
        loop {
            if let Some(code) = registry::exit_of(&key_of(dep)) {
                if code == 0 {
                    break;
                }
                return Err(Error::Compose(format!(
                    "box '{}': dependency '{dep}' did not complete successfully (exit {code}) - \
                     run `kern logs {dep}` for the reason",
                    b.name
                )));
            }
            if Instant::now() >= deadline {
                return Err(Error::Compose(format!(
                    "box '{}': timed out after {COMPOSE_CONDITION_TIMEOUT_SECS}s waiting for '{dep}' \
                     to complete",
                    b.name
                )));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Ok(())
}

/// A running box's current health status by NAME (`healthy`/`unhealthy`/`starting`/empty). The
/// sidecar is keyed `name-pid`, so resolve the pid via the registry first; a box that has already
/// left the registry reads as empty (which the caller treats as "not yet healthy").
fn current_health(name: &str) -> String {
    registry::find(name)
        .map(|i| registry::health_of(name, i.pid))
        .unwrap_or_default()
}

/// Is a box with this name currently in the registry (i.e. still running)? `list()` prunes dead
/// entries, so presence == alive. Used to fail a `depends_healthy` wait fast when the dep has died.
fn is_box_alive(name: &str) -> bool {
    registry::name_taken(name)
}

/// What `kern compose <file> <verb>` should do. One enum instead of a `down: bool` so every verb is
/// exhaustively handled at the dispatch (a new verb cannot be silently forgotten by the compiler).
///
/// kern's model differs from Docker's in one way that shapes these semantics: a kern box is
/// EPHEMERAL - there is no "created but stopped" state to restart into. So `Stop` ends the boxes and
/// keeps the pod (the shared network), and `Start` launches whatever is not currently running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposeAction {
    /// Bring the whole stack up (create the pod, build, launch in dependency order).
    Up,
    /// Stop every service AND tear the pod down.
    Down,
    /// Stop every service, KEEP the pod - so `start` can re-join the same shared network.
    Stop,
    /// Launch the services that are not currently running (the rest are left untouched).
    Start,
    /// `Stop` followed by a full `Up`.
    Restart,
    /// List this stack's boxes.
    Ps,
    /// Print this stack's logs (`--tail N`, and `-f` for a single service).
    Logs,
    /// Only run the `build:` directives; start nothing.
    Build,
    /// Only fetch each service's `image:`; start nothing.
    Pull,
    /// Parse, interpolate and validate, then print the resolved services. No side effects.
    Config,
    /// Print a systemd unit for this stack on stdout. Installs nothing: kern is daemonless, so the
    /// one thing it cannot do for itself is come back after a reboot, and where that unit belongs is
    /// a decision about the user's machine. No side effects.
    Systemd,
}

/// Every compose sub-verb, in the order the help prints them. THE list: `from_verb`, the help line
/// and the usage error all read it, so a verb cannot work while being absent from what the CLI tells
/// you about itself. `systemd` shipped exactly that way, working but undocumented in both, because
/// the same list was written out three times by hand.
pub const COMPOSE_VERBS: &[(&str, ComposeAction)] = &[
    ("up", ComposeAction::Up),
    ("down", ComposeAction::Down),
    ("stop", ComposeAction::Stop),
    ("start", ComposeAction::Start),
    ("restart", ComposeAction::Restart),
    ("ps", ComposeAction::Ps),
    ("logs", ComposeAction::Logs),
    ("build", ComposeAction::Build),
    ("pull", ComposeAction::Pull),
    ("config", ComposeAction::Config),
    ("systemd", ComposeAction::Systemd),
];

/// The `up|down|…` fragment both help sites print, built from [`COMPOSE_VERBS`] so it cannot drift.
pub fn compose_verbs_help() -> String {
    COMPOSE_VERBS
        .iter()
        .map(|(v, _)| *v)
        .collect::<Vec<_>>()
        .join("|")
}

impl ComposeAction {
    /// Parse a compose sub-verb. `None` for an unknown word, so the caller can report it with the
    /// full list rather than guessing.
    pub fn from_verb(v: &str) -> Option<Self> {
        COMPOSE_VERBS
            .iter()
            .find_map(|(name, a)| (*name == v).then_some(*a))
    }
}

/// Stop every service of a stack and reap its exit sidecars. Shared by `down`, `stop` and `restart`
/// so the (subtle) sidecar-reaping rule below lives in exactly one place. Returns the service names.
///
/// Sidecar keys are `<pod>-<token>-<name>`; a teardown does not know the `up`'s token, so it clears
/// `<pod>-*-<name>` per box it stopped - NOT a blind `<pod>-*`, which would wipe a concurrent
/// same-stack run's OTHER boxes. Each `remove_file` is atomic and ENOENT-safe, so two concurrent
/// teardowns just no-op over each other.
///
/// One race remains for pure name-scoping: `down A` stops A's `migrate`, a concurrent `up B`
/// re-creates a `migrate` box, then A's reap would delete B's fresh sidecar. Closed BY CONSTRUCTION:
/// a box's sidecars are reaped ONLY if that box is no longer alive.
fn stop_stack(boxes: &[crate::compose::ComposeBox], pod: &str) -> Vec<String> {
    let names: Vec<String> = boxes.iter().map(|b| b.name.clone()).collect();
    let _ = stop(&names, false); // best-effort - some may already be gone
    for n in &names {
        if !is_box_alive(n) {
            registry::clear_exit_matching(&exit_key_prefix(pod), &format!("-{n}"));
        }
    }
    names
}

/// Fingerprint of everything that DEFINES a box, so `up` can tell a running service apart from the
/// file that describes it now.
///
/// The input is the exact argv `push_box_flags` builds plus the command: that argv IS the definition,
/// so anything that would produce a different box produces a different hash, and anything that would
/// not (comments, key order inside a mapping, a field kern ignores) does not. Deriving it from the
/// argv instead of from the YAML text is what keeps it from firing on cosmetic edits.
///
/// FNV-1a 64: deterministic, allocation-free over the input, no dependency. This is an
/// equality check between two runs of the SAME binary, not a security boundary - collisions here
/// would mean a missed recreate, not a trust decision, and no adversary chooses the input.
fn definition_hash(b: &crate::compose::ComposeBox) -> String {
    let mut cmd = std::process::Command::new("kern");
    b.push_box_flags(&mut cmd);
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |bytes: &[u8]| {
        for byte in bytes {
            h ^= u64::from(*byte);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    for a in cmd.get_args() {
        eat(a.as_encoded_bytes());
        eat(&[0]); // separator: `["ab","c"]` must not hash like `["a","bc"]`
    }
    for c in &b.command {
        eat(c.as_bytes());
        eat(&[0]);
    }
    format!("{h:016x}")
}

/// What `up` must do with a service that is ALREADY running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reconcile {
    /// Running and still matches the file: leave it alone.
    UpToDate,
    /// Running but the file changed since: stop it so the launch loop recreates it.
    Recreate,
}

/// Decide, for one running service, whether the file still describes it.
///
/// A box registered by an older kern (or started outside compose) carries no fingerprint. Treating
/// that as "changed" would recreate it on every `up` forever; treating it as "up to date" is the
/// conservative choice and costs at most one missed recreate, after which the box carries a
/// fingerprint and behaves normally.
fn reconcile_decision(running: &registry::Instance, want: &str) -> Reconcile {
    if running.def_hash.is_empty() || running.def_hash == want {
        Reconcile::UpToDate
    } else {
        Reconcile::Recreate
    }
}

/// Reject, BEFORE anything starts, the conflicts a shared network namespace makes inevitable.
///
/// A pod is one net ns, so several properties that read as per-service in the file are in fact
/// pod-global. Each produces either a CONFLICT (two services declare incompatible values, and which
/// one wins depends on start order) or a silent INHERITANCE (one declares, all receive). This checks
/// the first kind; the second is announced at bring-up.
///
/// The generalisation matters more than any single case: the internal-port clash was found only
/// because a reviewer's premise was tested, and it is one member of a class, not a special case.
///
/// The gate lives HERE, not at the call sites. It used to be written at each of them, and they drifted
/// exactly as that always ends: `up` gated it, `systemd` ran it ungated, and `config` (the verb whose
/// whole job is answering "will this come up?") did not run it at all, so a stack that `up` refused
/// was reported clean by the dry run. One statement of the rule, three callers that cannot restate it
/// differently.
///
/// Not gated on `use_pod`'s third term (`any(!b.net)`) on purpose: services on the HOST network share
/// the host's namespace, so their internal ports collide just as surely. `use_pod` answers "create a
/// pod?", this answers "can these ports coexist?" - different questions that happen to share two terms.
fn check_pod_global_conflicts(
    boxes: &[crate::compose::ComposeBox],
    no_pod: bool,
) -> Result<(), Error> {
    // `--no-pod` gives each service its own namespace, and a lone service shares with nobody.
    if no_pod || boxes.len() < 2 {
        return Ok(());
    }
    let short = |b: &crate::compose::ComposeBox| b.name.clone();

    // 1. INTERNAL ports. Two services listening on the same box port share one namespace: one binds,
    //    the other dies with EADDRINUSE. Common by default, not by accident - every framework has one
    //    canonical port (Node 3000, Flask 5000, Spring 8080), so two services of the same stack
    //    routinely want the same one even when their PUBLISHED ports differ.
    let mut seen: std::collections::HashMap<(u16, bool), String> = std::collections::HashMap::new();
    for b in boxes {
        // A declared `port` counts exactly like a published mapping's container port, and is the only
        // way an INTERNAL-only service (reached by name, publishing nothing) becomes visible here at
        // all. Derived from `ports:` alone, this check saw only the services that publish, so the
        // stack it protected was the smaller half of the stack. Declared ports are TCP.
        // Three sources, ONE space: `port:` (declared, injected as PORT), `expose:` (declared,
        // the Compose spelling) and the mappings from `ports:` (published). They are all the same
        // statement, "this service binds this port in the pod namespace", and have to be compared
        // together or the check protects only the source it happened to look at.
        let declared = b.port.map(|p| (p, false));
        for (port, udp) in
            declared
                .into_iter()
                .chain(b.expose.iter().copied())
                .chain(b.ports.iter().flat_map(|spec| {
                    crate::ports::parse(spec) // malformed: the per-box path reports it precisely
                        .unwrap_or_default()
                        .into_iter()
                        .map(|m| (m.box_port, m.udp))
                }))
        {
            if let Some(other) = seen.insert((port, udp), short(b)) {
                if other != b.name {
                    let proto = if udp { "udp" } else { "tcp" };
                    return Err(Error::Compose(format!(
                        "services '{}' and '{}' both listen on container port {port}/{proto}. Services \
                         in a stack share ONE network namespace (like a Kubernetes pod), so only one \
                         can bind it: declare a different internal port with `port:` on one of them \
                         (kern passes it as PORT, which most images read), or run with --no-pod.",
                        other,
                        short(b)
                    )));
                }
            }
        }
    }

    // 2. `net.*` sysctls set to DIFFERENT values by different services. The knob belongs to the
    //    namespace, so the last service to start wins and the file does not say which that is.
    let mut sys: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new();
    for b in boxes {
        for kv in b.sysctls.iter().filter(|s| s.starts_with("net.")) {
            let (k, v) = kv.split_once('=').unwrap_or((kv.as_str(), ""));
            if let Some((prev_v, prev_svc)) = sys.get(k) {
                if prev_v != v {
                    return Err(Error::Compose(format!(
                        "services '{prev_svc}' and '{}' set sysctl '{k}' to different values \
                         ('{prev_v}' and '{v}'). `net.*` knobs belong to the pod's shared network \
                         namespace, so the last service to start would decide: set one value, or \
                         run with --no-pod.",
                        short(b)
                    )));
                }
            } else {
                sys.insert(k.to_string(), (v.to_string(), short(b)));
            }
        }
    }

    // 3. An `extra_hosts` entry that shadows a SERVICE name. Both write the pod's /etc/hosts, so the
    //    winner is decided by write order - and a service silently resolving to somewhere else is the
    //    worst kind of wrong.
    let names: std::collections::HashSet<&str> = boxes.iter().map(|b| b.name.as_str()).collect();
    for b in boxes {
        for host in b.add_host.iter().filter_map(|h| h.split(':').next()) {
            // Service names are project-scoped by now; `extra_hosts` carries what the file wrote, so
            // compare against both spellings.
            let clashes = names.contains(host)
                || boxes
                    .iter()
                    .any(|o| o.net_aliases.iter().any(|a| a == host));
            if clashes {
                return Err(Error::Compose(format!(
                    "service '{}': extra_hosts entry '{host}' has the same name as a service in this \
                     stack. Both write the pod's shared /etc/hosts, so which one resolves would depend \
                     on start order: rename one of them.",
                    short(b)
                )));
            }
        }
    }
    Ok(())
}

/// Best-effort WARNING for two pod services whose IMAGES expose the same container port even though
/// NEITHER declares it in the compose file - the implicit-EXPOSE case `check_pod_global_conflicts`
/// cannot see (two `nginx` default to :80, two `node` apps to :3000). A pod shares one network
/// namespace, so if both actually bind it the second dies with EADDRINUSE at runtime, with an obscure
/// error and no compose-time hint. This is deliberately SOFT: an image's `ExposedPorts` is a hint, not
/// a guaranteed bind (an nginx reconfigured off :80 will not collide), so it warns, never refuses.
/// Cache-only via [`PullPolicy::Never`]: it never pulls just to warn, so an uncached service is
/// skipped (and warned about, if it collides, once its image is present - e.g. the second `up`).
fn warn_image_expose_collisions(boxes: &[crate::compose::ComposeBox], no_pod: bool) {
    if no_pod || boxes.len() < 2 {
        return;
    }
    let mut seen: std::collections::HashMap<(u16, bool), String> = std::collections::HashMap::new();
    for b in boxes {
        let Some(image) = b.image.as_deref() else {
            continue; // a `--rootfs`/`build`-only service has no image config to read
        };
        let Ok((_, cfg)) = resolve_image_depth(image, 0, PullPolicy::Never) else {
            continue; // not cached: do not pull just to warn
        };
        for (port, udp) in cfg.exposed_ports {
            if let Some(other) = seen.insert((port, udp), b.name.clone()) {
                if other != b.name {
                    let proto = if udp { "udp" } else { "tcp" };
                    eprintln!(
                        "kern: warning: the images of '{other}' and '{}' both EXPOSE {port}/{proto}; a \
                         stack shares ONE network namespace, so if both bind it the second fails at \
                         runtime with EADDRINUSE. If they really serve the same port, give one a \
                         different internal port (its own config, or `port:`), or run with --no-pod.",
                        b.name
                    );
                }
            }
        }
    }
}

/// How long to watch a freshly-launched stack for an IMMEDIATE death. Not "how long a service takes
/// to start": a service is not required to be READY here, only to still exist. This covers a failed
/// `execve`, a failed bind, a permission error and a missing file, which is the entire class `up` can
/// honestly speak about.
///
/// MEASURED, not chosen. A service that fails at once (`exit 3`, a missing binary, a failed exec) is
/// observably gone 0.7 ms after its box returns. This window is two orders of magnitude above that,
/// which leaves room for a board an order of magnitude slower than the desktop it was measured on.
///
/// It was 500 ms, justified by a comment stating the window "adds a fixed 500 ms to a bring-up that
/// already takes seconds". The bring-up measures ~40 ms: the window WAS the cost of `compose up`,
/// twelve times the work it was watching over. `compose up` of four services went from 540 ms to
/// ~190, and a stack with a failing service now reports in milliseconds instead of half a second.
const BRING_UP_SETTLE_MS: u64 = 150;

/// Watch the freshly-started services and return AS SOON AS one is gone, or when `ms` elapses.
///
/// The window used to be a flat sleep, so a stack whose service died instantly still took the whole
/// window to say so. Watching costs one cheap liveness check per service per tick and turns the
/// failure path from "always the full window" into "as fast as the failure happened", while a stack
/// that stays up pays exactly what it paid before.
fn watch_for_early_death(boxes: &[crate::compose::ComposeBox], ms: u64) {
    // 10 ms: far below the window, far above the cost of one liveness check per service, so the
    // watch adds no measurable work to a stack that stays up.
    const TICK_MS: u64 = 10;
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(ms);
    loop {
        if boxes.iter().any(|b| !is_box_alive(&b.name)) {
            return; // one is gone: the caller's registry pass decides whether that was legitimate
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return;
        }
        let left = deadline.saturating_duration_since(now);
        std::thread::sleep(left.min(std::time::Duration::from_millis(TICK_MS)));
    }
}

/// Names of the services that are gone after the settle window, in file order.
///
/// A service counts as legitimately finished when its exit sidecar records 0 - that is the same
/// signal `depends_completed` waits on, so a one-shot task that did its job is not reported as a
/// failure. Anything else that is no longer in the registry died, and `up` must say so.
///
/// One watch for the whole stack, then one registry read per service to classify what is gone.
fn settle_and_collect_dead(
    boxes: &[crate::compose::ComposeBox],
    pod: &str,
    token: &str,
) -> Vec<String> {
    watch_for_early_death(boxes, BRING_UP_SETTLE_MS);
    boxes
        .iter()
        .filter(|b| {
            if is_box_alive(&b.name) {
                return false;
            }
            // Gone: legitimate only if it recorded a clean completion.
            registry::exit_of(&exit_key(pod, token, &b.name)) != Some(0)
        })
        .map(|b| {
            b.name
                .strip_prefix(&format!("{pod}-"))
                .unwrap_or(&b.name)
                .to_string()
        })
        .collect()
}

/// The compose file's own directory - Docker's "project directory", which anchors `.env`, relative
/// bind sources and `build.context`. A bare filename (`docker-compose.yml`, no parent) means the
/// current directory, so the empty parent is mapped to `.` rather than to the filesystem root.
fn compose_dir(file: &str) -> std::path::PathBuf {
    std::path::Path::new(file)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Every mapping seen so far for ONE `(host port, protocol)` pair - the bucket that makes the
/// collision check linear instead of pairwise. `wildcard` is the service that bound `0.0.0.0` on this
/// pair (it subsumes every address, so anything else here conflicts with it); `specific` maps each
/// concrete bind address to its owner, and `first_specific` remembers one of them so a later wildcard
/// can name a counterpart in O(1).
#[derive(Default)]
struct PortSlot<'a> {
    wildcard: Option<&'a str>,
    first_specific: Option<&'a str>,
    specific: std::collections::HashMap<u32, &'a str>,
}

/// Pre-flight for `compose up`: reject two published mappings that would fight for the SAME host port.
///
/// Reuses the verified spec parser ([`crate::ports::parse`]) so range/`ip:host:box`/`/udp` forms are
/// interpreted exactly as at box-start. Two mappings conflict when they share protocol and host port
/// AND their bind addresses overlap - identical, or either bound to `0.0.0.0` (`bind_ip == 0`), which
/// subsumes any specific address.
///
/// LINEAR in the number of published mappings, by bucketing on `(host, udp)` and hashing the bind
/// address inside each bucket. The obvious pairwise form is quadratic, and that is NOT academic here:
/// a single `-p` may expand to 1024 ports (`ports::MAX_RANGE`), so a perfectly legal
/// 40-service stack of ranges reaches ~41k mappings and measured **10.5 s** of pure comparison before
/// a single box started (10/20/40 services = 0.7/2.7/10.5 s, textbook x4-per-doubling). Bucketing
/// makes the same file ~40 ms.
///
/// Panic-free (`Result` throughout); an unparseable spec is left for the per-box path to report, not
/// silently treated as a conflict.
///
/// On the protocol dimension: the compose parser (`ports_value`) already STRIPS the `/tcp` suffix and
/// drops non-TCP entries with a warning, so specs arriving here are always TCP today. Bucketing on
/// `(host, udp)` anyway keeps this faithful to `ports::parse`'s contract - the day kern publishes UDP,
/// a `udp/8080` and a `tcp/8080` won't be conflated into a bogus conflict.
fn check_port_collisions(boxes: &[crate::compose::ComposeBox]) -> Result<(), Error> {
    let mut slots: std::collections::HashMap<(u16, bool), PortSlot> =
        std::collections::HashMap::new();
    for b in boxes {
        let name = b.name.as_str();
        for spec in &b.ports {
            let Some(pms) = crate::ports::parse(spec) else {
                continue;
            };
            for pm in pms {
                let slot = slots.entry((pm.host, pm.udp)).or_default();
                // Who (if anyone) already holds an address overlapping this one on this port+proto.
                let prior = match slot.wildcard {
                    Some(w) => Some(w), // 0.0.0.0 is already taken: everything here conflicts
                    None if pm.bind_ip == 0 => slot.first_specific, // we ARE the wildcard
                    None => slot.specific.get(&pm.bind_ip).copied(), // exact same address
                };
                if let Some(other) = prior {
                    let proto = if pm.udp { "udp" } else { "tcp" };
                    let who = if other == name {
                        format!(
                            "service '{name}' publishes host port {}/{proto} more than once",
                            pm.host
                        )
                    } else {
                        format!(
                            "services '{other}' and '{name}' both publish host port {}/{proto}",
                            pm.host
                        )
                    };
                    return Err(Error::Compose(format!(
                        "{who}. Only one process can bind a host port; give each a distinct one."
                    )));
                }
                if pm.bind_ip == 0 {
                    slot.wildcard = Some(name);
                } else {
                    slot.specific.insert(pm.bind_ip, name);
                    slot.first_specific.get_or_insert(name);
                }
            }
        }
    }
    Ok(())
}

/// Everything `compose` needs for the verbs that do NOT start anything, grouped so the extracted
/// dispatch keeps a readable signature instead of eight positional arguments.
struct TerminalOpts<'a> {
    pod: &'a str,
    file: &'a str,
    tail: Option<usize>,
    follow: bool,
    /// `-a/--all` for `ps`: also list the stack's recently-exited services.
    all: bool,
    services: &'a [String],
    /// Needed by the read-only verbs too: `config` and `systemd` answer questions ABOUT a bring-up,
    /// so they have to know whether that bring-up would share a namespace.
    no_pod: bool,
}

/// Run the compose verbs that never launch a box, and report whether one ran.
///
/// `Ok(true)` means the verb was terminal and the command is done; `Ok(false)`
/// means the caller must continue to the bring-up (`up`, `start`, and `restart` after it has
/// stopped the stack). Extracted from `compose`, which had grown past 500 lines: the split is
/// exactly the boundary between "answers a question about the stack" and "changes it".
fn run_terminal_verb(
    action: ComposeAction,
    boxes: &mut [crate::compose::ComposeBox],
    o: &TerminalOpts<'_>,
) -> Result<bool, Error> {
    let (pod, file, tail, follow, all, services, no_pod) =
        (o.pod, o.file, o.tail, o.follow, o.all, o.services, o.no_pod);
    let selected =
        |b: &crate::compose::ComposeBox| services.is_empty() || services.contains(&b.name);

    match action {
        // Read-only / terminal verbs: each returns, so the bring-up below is reached ONLY by the
        // verbs that actually start something (Up, Start, Restart).
        ComposeAction::Systemd => {
            // The SAME validation `config` runs, before emitting anything: a unit generated from a
            // file that cannot come up would fail at boot, on a machine nobody is watching, which is
            // the worst possible moment to discover a broken graph. Then the unit, on stdout only.
            crate::compose::topo_levels(boxes).map_err(Error::Compose)?;
            validate_conditions(boxes)?;
            check_port_collisions(boxes)?;
            check_pod_global_conflicts(boxes, no_pod)?;
            crate::systemd::print_unit(file, pod)?;
            return Ok(true);
        }
        ComposeAction::Config => {
            // Parse + interpolate + validate, then print what kern actually resolved - the answer to
            // "is my file what I think it is" WITHOUT starting anything. Validation runs first so a
            // broken graph is reported here rather than at the next `up`.
            crate::compose::topo_levels(boxes).map_err(Error::Compose)?;
            validate_conditions(boxes)?;
            check_port_collisions(boxes)?;
            // The pod-global conflicts too: `config` is the verb you run to find out whether the file
            // will come up, so every rejection `up` performs has to be reachable from here. Reporting
            // a clean dry run for a stack that `up` then refuses is worse than not having the verb.
            check_pod_global_conflicts(boxes, no_pod)?;
            // Validate every published spec HERE, with the same parser the box uses. `config` is the
            // verb people run to check a file, so a typo must surface without starting anything (as
            // `docker compose config` does) instead of failing one box at bring-up. ALL bad specs are
            // reported together: fixing them one error per run is a poor loop.
            let bad: Vec<String> = boxes
                .iter()
                .flat_map(|b| {
                    b.ports
                        .iter()
                        .filter(|spec| crate::ports::parse(spec).is_none())
                        .map(move |spec| format!("  {}: invalid port '{spec}'", b.name))
                })
                .collect();
            if !bad.is_empty() {
                return Err(Error::Compose(format!(
                    "{} invalid port spec(s) - expected [ip:]host:box[/tcp|/udp], ports 1-65535:\n{}",
                    bad.len(),
                    bad.join("\n")
                )));
            }
            println!("compose config: {} service(s) in {file}", boxes.len());
            // `config` reports the FILE, so it prints service names as written, not the
            // project-scoped box names the runtime uses.
            let short = |n: &str| n.strip_prefix(&format!("{pod}-")).unwrap_or(n).to_string();
            for b in boxes.iter().filter(|b| selected(b)) {
                let src = b
                    .image
                    .as_deref()
                    .or(b.rootfs.as_deref())
                    .unwrap_or("(build)");
                println!("  {}  image={src}", short(&b.name));
                if !b.ports.is_empty() {
                    println!("    ports: {}", b.ports.join(", "));
                }
                // The v-profiles, because `config` answers "what did kern understand" and a profile
                // changes every cap the box runs under. Shown as the TOKENS the box will receive, so
                // the line can be copied onto a `kern box` command and behave the same; the file they
                // resolve against is named too, since a profile that is not in it is the one failure
                // this preview can warn about before anything starts.
                let tokens = b.profile_tokens();
                if !tokens.is_empty() {
                    println!("    profiles: {}", tokens.join(" "));
                    if let Some(c) = &b.config {
                        println!("      defined in: {c}");
                    }
                }
                // `config` answers "what did kern understand", so it must show a declared `port:`:
                // it is what the pod preflight reserves AND what the service receives as `PORT`, so
                // hiding it would leave the one command that exists to explain the file silent about
                // a field that changes both. Named as what it does, not just as its number.
                if let Some(p) = b.port {
                    println!("    port: {p} (reserved in the pod, passed as PORT={p})");
                }
                if !b.expose.is_empty() {
                    let list: Vec<String> = b
                        .expose
                        .iter()
                        .map(|(n, udp)| format!("{n}/{}", if *udp { "udp" } else { "tcp" }))
                        .collect();
                    println!("    expose: {} (reserved in the pod)", list.join(", "));
                }
                let deps: Vec<String> = b.all_deps().into_iter().map(short).collect();
                if !deps.is_empty() {
                    println!("    depends_on: {}", deps.join(", "));
                }
            }
            return Ok(true);
        }
        ComposeAction::Ps => {
            // Reuse `kern ps` itself, scoped to this stack's pod - one renderer, so the compose view
            // can never drift from `kern ps` (same columns, same status rules, same --json). `-a`
            // threads straight through, so `compose ps -a` shows the stack's recently-exited services;
            // the phantom worry (a PRIOR run of the same pod name) is closed at the source by `down`
            // reaping its own boxes' sidecars precisely (see `ComposeAction::Down`).
            let rc = ps(
                false,
                false,
                all,
                &[("pod".to_string(), pod.to_string())],
                None,
            );
            // Without `-a`, a running-only view cannot answer "which service died?" - point AT the
            // answer when the file defines more services than are up, instead of leaving the user to
            // know that the pod name is the stack name.
            if !all {
                let defined = boxes.len();
                let running = registry::list().iter().filter(|b| b.pod == pod).count();
                if running < defined {
                    let p = crate::ui::Palette::detect();
                    println!(
                        "{d}{running}/{defined} services running - exited: kern compose … ps -a{z}",
                        d = p.d,
                        z = p.z
                    );
                }
            }
            return rc.map(|()| true);
        }
        ComposeAction::Logs => {
            let wanted: Vec<&str> = boxes
                .iter()
                .filter(|b| selected(b))
                .map(|b| b.name.as_str())
                .collect();
            // `-f` on several services would need one blocking reader each; rather than interleave
            // them badly, require a single service and say exactly how to ask for it.
            if follow && wanted.len() != 1 {
                return Err(Error::Compose(format!(
                    "compose logs -f follows ONE service at a time; name it (e.g. `compose {file} logs -f {}`)",
                    wanted.first().copied().unwrap_or("<service>")
                )));
            }
            for (i, name) in wanted.iter().enumerate() {
                if wanted.len() > 1 {
                    if i > 0 {
                        println!();
                    }
                    println!("=== {name} ===");
                }
                // A service that never started (or already exited) has no log: report it and keep
                // going, so one missing service can't hide the others' output.
                if let Err(e) = logs(name, tail, follow) {
                    eprintln!("compose logs: {name}: {e}");
                }
            }
            return Ok(true);
        }
        ComposeAction::Pull => {
            let mut n = 0usize;
            for b in boxes.iter().filter(|b| selected(b)) {
                if let Some(img) = b.image.as_deref() {
                    pull(img, None, None)?;
                    n += 1;
                }
            }
            println!("compose pull: {n} image(s) up to date");
            return Ok(true);
        }
        ComposeAction::Build => {
            let self_exe = std::env::current_exe()
                .map_err(|e| Error::Compose(format!("locating kern: {e}")))?;
            resolve_builds(boxes, file, &self_exe)?;
            println!("compose build: done");
            return Ok(true);
        }
        ComposeAction::Down => {
            let names = stop_stack(boxes, pod);
            // Reap THIS stack's `waitexit` sidecars (by pod + our own service names), including services
            // that had ALREADY exited before `down` - a live-only capture would miss exactly those. So
            // `compose ps -a` is empty after a `down` (matching Docker), while `compose stop` (which does
            // not call this) leaves the exited services visible.
            registry::clear_waitexit_pod(pod, &names);
            // Tear the pod down QUIETLY (we just stopped the members, so `pod::remove`'s "members keep
            // running" note would contradict this). Only claim it was removed if one existed - a
            // `--no-pod` stack has none.
            let (pod_existed, _) = crate::pod::teardown(pod);
            if pod_existed {
                println!(
                    "compose down: {} box(es) stopped, pod '{pod}' removed",
                    names.len()
                );
            } else {
                println!("compose down: {} box(es) stopped", names.len());
            }
            return Ok(true);
        }
        ComposeAction::Stop => {
            // `stop` touches ONLY this file's services and never tears the pod down itself; `down`
            // removes the pod unconditionally. The distinction is real when the pod has members that
            // are NOT in this file (someone ran `kern box --pod <same>`): those keep running and the
            // pod with them. With no such member the pod still goes, because `kern stop` collapses a
            // pod once its LAST member exits (a deliberate, documented invariant - see `stop`); a
            // later `compose start` recreates it and services reach each other by name again.
            let names = stop_stack(boxes, pod);
            let pod_alive = crate::pod::holder_pid(pod).is_some();
            println!(
                "compose stop: {} box(es) stopped, pod '{pod}' {}",
                names.len(),
                if pod_alive {
                    "still up (other members remain)"
                } else {
                    "gone with its last member (`start` recreates it)"
                }
            );
            return Ok(true);
        }
        // `restart` = stop everything, then fall through to the full bring-up below.
        ComposeAction::Restart => {
            let names = stop_stack(boxes, pod);
            println!(
                "compose restart: {} box(es) stopped, restarting",
                names.len()
            );
        }
        ComposeAction::Up | ComposeAction::Start => {}
    }
    Ok(false)
}
/// `kern compose <file>` - bring up a stack of boxes (detached) in `depends_on` order. Each
/// service is launched via a fresh `kern box -d` subprocess, so it gets its own scope + registry
/// entry; track the stack with `kern ps`.
pub struct ComposeOpts<'a> {
    /// One or more compose files, merged left-to-right (`-f base.yml -f override.yml`).
    pub files: &'a [String],
    pub action: ComposeAction,
    pub no_pod: bool,
    pub tail: Option<usize>,
    pub follow: bool,
    /// `-a/--all` for `ps`: also list the stack's recently-exited services.
    pub all: bool,
    pub services: &'a [String],
    /// `-p/--project-name`: overrides the pod name normally derived from the file's directory.
    pub project: Option<&'a str>,
    /// `--env-file`: the interpolation table, instead of the project `.env`.
    pub env_file: Option<&'a str>,
    /// `--profile` (repeatable): profiles to activate, like `COMPOSE_PROFILES`.
    pub profiles: &'a [String],
}

pub fn compose(o: ComposeOpts<'_>) -> Result<(), Error> {
    let ComposeOpts {
        files,
        action,
        no_pod,
        tail,
        follow,
        all,
        services,
        project,
        env_file,
        profiles,
    } = o;
    // `--profile` is DEFINED by Docker as equivalent to `COMPOSE_PROFILES`, so it is applied by
    // exporting that variable once here, at the CLI boundary, before any parsing. One assignment in a
    // one-shot process, never from library code - the parser keeps reading a single source of truth.
    if !profiles.is_empty() {
        let mut all: Vec<String> = std::env::var("COMPOSE_PROFILES")
            .ok()
            .into_iter()
            .flat_map(|v| v.split(',').map(str::to_string).collect::<Vec<_>>())
            .filter(|p| !p.is_empty())
            .collect();
        all.extend(profiles.iter().cloned());
        std::env::set_var("COMPOSE_PROFILES", all.join(","));
    }
    // The FIRST file names the project (pod, relative paths, `.env` location), as in Docker.
    let file = files
        .first()
        .map(String::as_str)
        .ok_or_else(|| Error::Compose("compose needs at least one file".to_string()))?;
    let text = std::fs::read_to_string(file)
        .map_err(|e| Error::Compose(format!("reading {file}: {e}")))?;
    // Docker loads a `.env` sitting next to the compose file and uses it for `${VAR}` interpolation.
    // Without this, every real project (nearly all ship one) silently substituted EMPTY: a
    // `"${PORT}:80"` became `":80"` and a `${POSTGRES_PASSWORD}` became blank, with only a warning.
    // Absent/unreadable `.env` → an empty table, i.e. exactly the previous behaviour.
    // `--env-file` REPLACES the project `.env` (Docker's rule), and is required to exist when named:
    // a typo'd path must not silently fall back to no interpolation at all.
    let dotenv = match env_file {
        Some(p) => crate::compose::parse_dotenv(
            &std::fs::read_to_string(p)
                .map_err(|e| Error::Compose(format!("--env-file {p}: {e}")))?,
        ),
        None => std::fs::read_to_string(compose_dir(file).join(".env"))
            .map(|t| crate::compose::parse_dotenv(&t))
            .unwrap_or_default(),
    };
    let mut boxes = crate::compose::parse_with_env(&text, &dotenv).map_err(Error::Compose)?;
    // Merge every additional `-f`, left to right (see `merge_stacks` for the exact rules).
    for extra in &files[1..] {
        let t = std::fs::read_to_string(extra)
            .map_err(|e| Error::Compose(format!("reading {extra}: {e}")))?;
        let over = crate::compose::parse_override(&t, &dotenv).map_err(Error::Compose)?;
        boxes = crate::compose::merge_stacks(boxes, over);
    }
    // Per-service validation, on the MERGED stack and UNCONDITIONALLY. Merged, because an override
    // legitimately carries no `image:` and only the result must be runnable. Unconditional, because
    // these are per-service facts that do not depend on how many files stated them: gated on
    // `files.len() > 1`, the single-file case skipped them entirely, which left a lone YAML stack
    // unchecked (the TOML parser refuses "nothing to run" itself, the YAML front end defers it here)
    // and let a `port:`/`PORT=` contradiction through in the common one-file case.
    crate::compose::validate_runnable(&boxes).map_err(Error::Compose)?;
    // The stack's pod is named after the compose file (Docker's project-name idea) - one shared
    // network so services reach each other by name.
    let pod = match project {
        Some(p) => p.to_string(),
        None => compose_pod_name(file),
    };

    // PROJECT-SCOPED BOX NAMES. Docker names a container `<project>-<service>`; kern used the bare
    // service name, and box names are global, so two projects that both have a `db` (or `web`, or
    // `api` - the most common names there are) could not coexist: the second `up` failed with
    // "a box named 'db' is already running".
    //
    // The rename happens HERE, once, right after parsing: `depends_on` lists are rewritten with it, so
    // everything downstream (topological order, conditional waits, exit sidecars, health lookups,
    // liveness) keeps working on one consistent set of names without knowing about projects at all.
    // The bare service name is registered as a pod ALIAS below, so peers still reach each other as
    // `db` inside the stack - the name that appears in the compose file is the name that resolves.
    let service_names: Vec<String> = boxes.iter().map(|b| b.name.clone()).collect();
    let scoped = |svc: &str| format!("{pod}-{svc}");
    // Each service's BOX name: Docker's `container_name:` verbatim when set (so `docker exec <name>`
    // ports 1:1 to `kern exec <name>`), else the project-scoped `<pod>-<service>`. Built ONCE so the
    // box's own name and every `depends_on` edge that names a service map to the SAME box name.
    let box_name_of: std::collections::HashMap<String, String> = boxes
        .iter()
        .map(|b| {
            (
                b.name.clone(),
                b.container_name.clone().unwrap_or_else(|| scoped(&b.name)),
            )
        })
        .collect();
    let box_name = |svc: &str| box_name_of.get(svc).cloned().unwrap_or_else(|| scoped(svc));
    for b in boxes.iter_mut() {
        // The service name must survive as an alias: it is what peers connect to inside the pod,
        // regardless of what the box itself is named (a `container_name` does not change the DNS).
        let svc = b.name.clone();
        if !b.net_aliases.contains(&svc) {
            b.net_aliases.push(svc.clone());
        }
        for d in b
            .depends_on
            .iter_mut()
            .chain(b.depends_healthy.iter_mut())
            .chain(b.depends_completed.iter_mut())
        {
            *d = box_name(d);
        }
        b.name = box_name(&svc);
    }
    // Selectors from the command line name SERVICES; map them onto the boxes they now identify.
    let services: Vec<String> = services
        .iter()
        .map(|s| {
            if service_names.iter().any(|n| n == s) {
                box_name(s)
            } else {
                s.clone()
            }
        })
        .collect();
    let services = &services[..];

    // A `--filter`/service selection narrows the read-only verbs to the named services; empty = all.
    // Validated up front so a typo names itself instead of silently matching nothing.
    for want in services {
        if !boxes.iter().any(|b| &b.name == want) {
            return Err(Error::Compose(format!(
                "no service '{want}' in {file} (services: {})",
                boxes
                    .iter()
                    .map(|b| b.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }
    // Verbs that answer a question about the stack rather than changing it return here.
    if run_terminal_verb(
        action,
        &mut boxes,
        &TerminalOpts {
            pod: &pod,
            file,
            tail,
            follow,
            all,
            services,
            no_pod,
        },
    )? {
        return Ok(());
    }

    let mut levels = crate::compose::topo_levels(&boxes).map_err(Error::Compose)?;
    // `start` launches only what is NOT already running. Filtering the LEVELS (not `boxes`) keeps the
    // dependency graph exactly as computed - dropping a service from `boxes` would make its dependents
    // reference an unknown name - and keeps every level entry backed by a real box.
    if action == ComposeAction::Start {
        for level in &mut levels {
            level.retain(|n| !is_box_alive(n));
        }
        if levels.iter().all(|l| l.is_empty()) {
            println!("compose start: every service is already running");
            return Ok(());
        }
    }
    // DRIFT DETECTION. `up` on a running stack used to fail with "a box named 'x' is already
    // running", so an edit to the compose file was never applied and the user had to know to run
    // `down` first. Reconcile instead: a service whose definition still matches is LEFT ALONE (no
    // needless restart, no dropped connections), one whose definition changed is stopped here so the
    // launch loop below recreates it from the new definition.
    //
    // This is only safe because `up` now verifies the stack after bring-up: without that check a
    // service that dies immediately would be recreated on every invocation, silently, forever.
    if action == ComposeAction::Up {
        let mut kept = 0usize;
        let mut stale: Vec<String> = Vec::new();
        for level in &mut levels {
            level.retain(|n| {
                let Some(b) = boxes.iter().find(|b| &b.name == n) else {
                    return true;
                };
                match registry::find(n) {
                    None => true, // not running: launch it
                    Some(inst) => match reconcile_decision(&inst, &definition_hash(b)) {
                        Reconcile::UpToDate => {
                            kept += 1;
                            false
                        }
                        Reconcile::Recreate => {
                            stale.push(n.clone());
                            true
                        }
                    },
                }
            });
        }
        if !stale.is_empty() {
            let short: Vec<&str> = stale
                .iter()
                .map(|n| n.strip_prefix(&format!("{pod}-")).unwrap_or(n))
                .collect();
            println!("→ definition changed, recreating: {}", short.join(", "));
            // Stopped BEFORE the launch loop so the name is free when it is recreated.
            let _ = stop(&stale, false);
        }
        if kept > 0 && levels.iter().all(|l| l.is_empty()) {
            println!("compose up: {kept} service(s) already up to date");
            return Ok(());
        }
        if kept > 0 {
            println!("→ {kept} service(s) already up to date, left running");
        }
    }
    // Static rejection of conditions that can NEVER be satisfied - caught here, not left to time out
    // at runtime (adversarial-review 2d). `topo_order` above already rejects cycles and unknown deps.
    validate_conditions(&boxes)?;
    // Static rejection of DUPLICATE published host ports: the bring-up below is CONCURRENT per level,
    // so two services on the same host port would race for the bind - one wins, the other dies with
    // EADDRINUSE buried in its own log while `up` still reports success (a silent partial failure,
    // empirically confirmed). Caught here from the parsed file: deterministic, before any box starts.
    check_port_collisions(&boxes)?;
    // Self-gated (see its doc comment): `config` and `systemd` reach the SAME rejection through the
    // same call, so the dry run can never disagree with the bring-up about what is startable.
    check_pod_global_conflicts(&boxes, no_pod)?;
    // Softer sibling: two services whose IMAGES expose the same port without either DECLARING it (two
    // nginx on :80, two node apps on :3000). Best-effort and cache-only (never pulls just to warn),
    // a WARNING not an error because an image's EXPOSE is a hint, not a guaranteed bind.
    warn_image_expose_collisions(&boxes, no_pod);
    // A pod shares ONE network namespace, so a `net.*` sysctl written on one service applies to every
    // service in the stack and the last one to start wins. The file makes it look per-service; say so
    // rather than let an operator tune one service and silently retune the others.
    if !no_pod && boxes.len() > 1 {
        for b in &boxes {
            for kv in b.sysctls.iter().filter(|s| s.starts_with("net.")) {
                let key = kv.split('=').next().unwrap_or(kv);
                eprintln!(
                    "kern compose: service '{}': sysctl '{key}' applies to the WHOLE pod (services \
                     share one network namespace) - the last service to start wins; use --no-pod for \
                     per-service network settings",
                    b.name
                );
            }
        }
    }
    let self_exe =
        std::env::current_exe().map_err(|e| Error::Compose(format!("locating kern: {e}")))?;
    // Docker's PROJECT DIRECTORY: every service's box runs with CWD = the compose file's dir, so a
    // relative `env_file: ./x.env`, `-v ./data:/d`, or `rootfs: ./root` resolves against it (as Docker
    // anchors them) instead of against kern's own CWD - which broke `up` from any other directory. The
    // box reads `env_file` before the systemd-scope re-exec, and `systemd-run --scope` keeps the cwd, so
    // both the pre- and post-re-exec resolutions land in the project dir.
    let project_dir = compose_dir(file);

    // Compose `build:` - build each service's image via `kern build` BEFORE the launch loop, so a box
    // with `build:` gets a real image to run. Four hardenings the adversarial review demanded, because
    // `build:` is the first place the YAML parser drives a privileged operation on host paths:
    //  1. `context`/`dockerfile` are CONFINED under the compose file's directory (traversal guard).
    //  2. `build.args` are already `${VAR}`-interpolated by the parser (never literal `${VAR}`).
    //  3. a build failure fails the WHOLE `up` with a linked message ("service X: build failed …"),
    //     since a box whose image never built can't start (and its depends_completed/healthy peers
    //     would hang) - fail-fast beats a half-up stack.
    //  4. `image:` + `build:` together = build AND tag as `image` (compose semantics); a `build:` with
    //     no `image:` gets a synthesized tag. We never silently use a stale registry image for a box
    //     the user meant to build locally.
    resolve_builds(&mut boxes, file, &self_exe)?;
    // Docker resolves a RELATIVE bind source (`./certs:/dst`, `.:/app`) against the compose file's
    // directory. kern's `-v` needs an absolute path or a named volume, so rewrite relative binds here
    // to absolute (confined under the compose dir - traversal guard, like a build context). A `named:`
    // source or an already-absolute `/host:/dst` passes through untouched.
    resolve_relative_binds(&mut boxes, file)?;

    // A fresh epoch token for THIS `up`. Stamped into every `depends_completed` target's exit sidecar
    // and required to match on read, so a sidecar left by a previous `up` of the same stack can't
    // satisfy this run's wait (adversarial-review 1a). Uniqueness only needs to hold within this
    // process's lifetime; our pid + a monotonic-ish clock read is plenty and needs no rng/new deps.
    let up_token = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    // Auto-pod: a multi-service stack gets a shared network (name resolution + outbound) unless the
    // user opts out or every box already shares the host net (`--net`). Reuse an existing pod so
    // `up` is idempotent.
    let use_pod = !no_pod && boxes.len() >= 2 && boxes.iter().any(|b| !b.net);
    if use_pod && crate::pod::holder_pid(&pod).is_none() {
        // Map a uid RANGE into the pod's shared user ns when ANY member needs it (`wants_uid_range`,
        // the single statement of that rule). A pod member setns's into the holder's user ns and writes
        // NO map of its own, so the holder's map is authoritative - `--uid-range` on the member alone is
        // a no-op, and the decision must be made HERE, before the holder unshares. A pod of only
        // single-uid rootfs services stays single-uid (faster). The pod reports an unavailable range
        // only if a member ASKED for it, matching the per-box rule.
        let pod_needs_range = if boxes.iter().any(|b| b.uid_range) {
            UidRange::Requested
        } else if boxes.iter().any(|b| b.wants_uid_range()) {
            UidRange::ImageDefault
        } else {
            UidRange::Off
        };
        crate::pod::create_with_range(&pod, true, pod_needs_range)?;
    }
    // Feedback-first: a `--net` (host-network) service in a podded stack is NOT on the pod net, so its
    // peers can't reach it by name - say so rather than let it silently not resolve.
    if use_pod {
        for b in boxes.iter().filter(|b| b.net) {
            eprintln!(
                "kern: note: service '{}' uses --net (host network) - it is NOT reachable by name inside pod '{pod}'",
                b.name
            );
        }
    }

    // Count what will actually be LAUNCHED, not how many services the file has: with drift
    // reconciliation the levels may already have been filtered down to the changed ones, and a
    // header promising more boxes than it starts is the kind of small untruth this codebase avoids.
    let total: usize = levels.iter().map(Vec::len).sum();
    eprintln!(
        "→ bringing up {total} box(es) in {} dependency {}: {}",
        levels.len(),
        if levels.len() == 1 { "level" } else { "levels" },
        levels
            .iter()
            .map(|l| format!("[{}]", l.join(", ")))
            .collect::<Vec<_>>()
            .join(" → ")
    );
    // Bring each dependency LEVEL up CONCURRENTLY - every box in a level is independent (its deps live
    // in earlier levels) - with a barrier before the next level so `depends_on` still holds. Wall-clock
    // becomes Σ-per-LEVEL instead of Σ-per-box: a wide flat stack starts in one shot, not one-by-one.
    let started = std::sync::atomic::AtomicUsize::new(0);
    // Cap concurrent starts so a very WIDE level (100s of independent services) doesn't fork a
    // thundering herd of simultaneous overlay-mount/cgroup/userns setups (and reserve 100s of thread
    // stacks on a small board). A normal stack (≤cap services in a level) runs fully parallel as a
    // single chunk; a huge level is barriered into cap-sized chunks. I/O-bound starts want generous
    // concurrency (kern handles 200 parallel boxes), so cap = 4×CPUs clamped to [8, 32].
    let start_cap = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .saturating_mul(4)
        .clamp(8, 32);
    for level in &levels {
        for chunk in level.chunks(start_cap) {
            // One worker per service in this chunk; `thread::scope` joins them ALL (the barrier) before
            // we advance. Each worker runs the exact same start sequence the old serial loop did.
            let results: Vec<Result<(), Error>> = std::thread::scope(|scope| {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|name| {
                        let b = boxes.iter().find(|b| &b.name == name).unwrap();
                        let (started, pod, up_token, self_exe, boxes, project_dir) =
                            (&started, &pod, &up_token, &self_exe, &boxes, &project_dir);
                        scope.spawn(move || -> Result<(), Error> {
                            // Conditional deps (healthy/completed) live in an earlier, already-started
                            // level; plain `depends_on` is honored by the level barrier itself.
                            wait_for_conditions(b, pod, up_token)?;
                            let n = started.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                            let dep = if b.depends_on.is_empty() {
                                String::new()
                            } else {
                                format!(" (after {})", b.depends_on.join(", "))
                            };
                            let src = b
                                .image
                                .as_deref()
                                .or(b.rootfs.as_deref())
                                .unwrap_or("(no source)");
                            eprintln!("→ [{n}/{total}] starting '{}'  {src}{dep}", b.name);
                            let mut cmd = std::process::Command::new(self_exe);
                            // Anchor the box's relative paths (env_file/-v/rootfs) to the project dir.
                            cmd.current_dir(project_dir);
                            cmd.arg("box").arg(&b.name);
                            // Record the fingerprint WITH the box, so the next `up` can compare.
                            cmd.arg("--def-hash").arg(definition_hash(b));
                            b.push_box_flags(&mut cmd);
                            // A box not on the host net joins the stack pod → reachable by name from peers.
                            if use_pod && !b.net {
                                cmd.arg("--pod").arg(pod);
                            }
                            // If a peer waits on THIS box's completion, hand it the stack+run-scoped exit
                            // KEY via env and CLEAR that exact key BEFORE the spawn. Each box owns a UNIQUE
                            // key (carries this `up`'s token), so concurrent workers never touch each
                            // other's - the review-round-2 invariant holds under parallelism too.
                            let is_completion_target = boxes
                                .iter()
                                .any(|other| other.depends_completed.iter().any(|d| d == &b.name));
                            if is_completion_target {
                                let key = exit_key(pod, up_token, &b.name);
                                registry::clear_exit(&key);
                                cmd.env("KERN_EXIT_KEY", &key);
                            }
                            cmd.arg("-d");
                            if !b.command.is_empty() {
                                cmd.arg("--").args(&b.command);
                            }
                            let status = cmd.status().map_err(|e| {
                                Error::Compose(format!("starting '{}': {e}", b.name))
                            })?;
                            if !status.success() {
                                return Err(Error::Compose(format!(
                                    "box '{}' failed to start",
                                    b.name
                                )));
                            }
                            Ok(())
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| {
                        h.join().unwrap_or_else(|_| {
                            Err(Error::Compose("compose worker panicked".into()))
                        })
                    })
                    .collect()
            });
            // Abort the whole `up` on the first failure in this chunk (peers already started stay up,
            // like Docker's partial bring-up).
            for r in results {
                r?;
            }
        }
        // Register this level's pod aliases AFTER the barrier - serial, so the racy /etc/hosts
        // read-modify-write in `add_member` never runs concurrently, and the NEXT level resolves them.
        if use_pod {
            for name in level {
                let b = boxes.iter().find(|b| &b.name == name).unwrap();
                if !b.net {
                    for alias in &b.net_aliases {
                        crate::pod::add_member(&pod, alias)?;
                    }
                }
            }
        }
    }
    // FAIL-CLOSED sul bring-up. Launching a box only proves the launcher returned; a service that
    // dies half a second later (an internal port already taken by a pod peer, a missing binary, a
    // config it reads at startup) left `up` printing "started" and exiting 0 while the stack was
    // already broken. That is the "reports success while losing something" class this codebase
    // refuses everywhere else.
    //
    // We wait for an EVENT, not for a duration: a settle window just long enough to observe an
    // IMMEDIATE failure (failed execve, failed bind, permissions), shared by the whole stack rather
    // than paid per service. A service that dies later is NOT `up`'s business - that is supervision,
    // and stretching this window to catch it would reintroduce the arbitrary wait it avoids.
    //
    // Healthy services are left RUNNING. A stack whose database holds data in a volume must not be
    // torn down because an unrelated service failed; the exit code and the message carry the failure.
    let dead = settle_and_collect_dead(&boxes, &pod, &up_token);
    if !dead.is_empty() {
        return Err(Error::Compose(format!(
            "{} service(s) died within {BRING_UP_SETTLE_MS}ms of starting: {}\n  the rest of the \
             stack is still running; inspect with `kern compose {file} logs <service>`\n  (`up` \
             reports deaths at STARTUP; a service that dies later is not detected yet)",
            dead.len(),
            dead.join(", ")
        )));
    }
    println!("compose up: {total} box(es) started. track with `kern ps`.");
    if use_pod {
        println!(
            "  pod '{pod}': services reach each other by name. tear down with `kern compose {file} down`."
        );
    }
    Ok(())
}

/// Derive a STABLE, per-stack pod name from a compose file path. Uses the parent DIRECTORY name
/// (Docker's project-name rule - compose files are conventionally named `compose.yaml`, so the
/// directory identifies the stack, not the near-constant stem) plus a short hash of the CANONICAL
/// absolute path, so two same-named dirs in different locations never collapse into one pod. Same
/// file → same name (so `up` and `down` agree); different stacks → different pods.
fn compose_pod_name(file: &str) -> String {
    let path = std::path::Path::new(file);
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let raw = canon
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .or_else(|| path.file_stem().and_then(|s| s.to_str()))
        .unwrap_or("compose");
    let base: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(40)
        .collect();
    let base = if base.is_empty() { "compose" } else { &base };
    // A short hash of the canonical path disambiguates identical dir names in different locations.
    format!("{base}-{:08x}", fnv1a(&canon.to_string_lossy()) as u32)
}

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

/// The verbs `kern config` takes. ONE definition, referenced by the parser that refuses an unknown one
/// and by the dispatch below, because they were two lists and a verb added to one and not the other
/// would have been accepted and then silently treated as `list`.
pub(crate) const CONFIG_USAGE: &str = "config [list|add|rm|edit|setup|probe|clear]";

const CONFIG_ADD_USAGE: &str = "config add <vcpu|vgpio|vdisk>:<name> [--field value …] [--update]";
const CONFIG_RM_USAGE: &str = "config rm <vcpu|vgpio|vdisk>:<name>";

/// Split a `kind:name` token into a known profile kind + a name, or a usage error.
fn parse_profile_token(token: &str, usage: &'static str) -> Result<(String, String), Error> {
    let (kind, name) = token.split_once(':').ok_or(Error::Usage(usage))?;
    if crate::config::profile_fields(kind).is_empty() {
        return Err(Error::Config(format!(
            "unknown profile kind '{kind}' - use vcpu, vgpio or vdisk"
        )));
    }
    Ok((kind.to_string(), name.to_string()))
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

/// `kern config setup [--force]` - write a starter `kern.toml` to the default location (refusing to
/// clobber an existing one unless `--force`).
/// The host's resource inventory - `config probe` prints it; `config setup` seeds a kern.toml whose
/// example profiles already fit THIS machine (real core count / cpuset range / i2c buses).
struct HostInv {
    ncpu: usize,
    ram: String,
    disks: Vec<DiskInfo>, // physical block devices (whole disks, not partitions)
    gpiochips: Vec<String>, // short names, e.g. "gpiochip0"
    i2c: Vec<String>,     // "i2c-0", …
    spi: Vec<String>,     // "spidev0.0", …
}

/// A physical disk from `/sys/block`, for `kern probe` and the `[[disk]]` example in `config setup`.
struct DiskInfo {
    name: String, // "nvme0n1", "sda"
    size: u64,    // bytes
    ssd: bool,    // rotational == 0
    model: String,
}

/// Whole physical disks from `/sys/block`, sorted by name. Skips virtual/loop/ram/dm/optical devices
/// and zero-sized entries (empty card readers). Read-only - a hardware inventory, not a pool manager.
fn read_disks() -> Vec<DiskInfo> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/sys/block") else {
        return out;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if ["loop", "ram", "zram", "dm-", "sr", "md", "fd", "nbd"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            continue;
        }
        let base = e.path();
        let sectors: u64 = std::fs::read_to_string(base.join("size"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if sectors == 0 {
            continue; // an empty card reader / removed medium
        }
        let ssd = std::fs::read_to_string(base.join("queue/rotational"))
            .map(|s| s.trim() == "0")
            .unwrap_or(false);
        let model = std::fs::read_to_string(base.join("device/model"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        out.push(DiskInfo {
            name,
            size: sectors * 512, // /sys/block reports 512-byte sectors regardless of physical size
            ssd,
            model,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn detect_host() -> HostInv {
    let ncpu = std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| s.lines().filter(|l| l.starts_with("processor")).count())
        .unwrap_or(0);
    let ram = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|v| v.split_whitespace().next())
                .and_then(|kb| kb.parse::<u64>().ok())
        })
        .map(|kb| human_bytes(kb * 1024))
        .unwrap_or_else(|| "?".into());
    let mut dev: Vec<String> = std::fs::read_dir("/dev")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    dev.sort();
    let by =
        |pat: &str| -> Vec<String> { dev.iter().filter(|n| n.starts_with(pat)).cloned().collect() };
    HostInv {
        ncpu,
        ram,
        disks: read_disks(),
        gpiochips: by("gpiochip"),
        i2c: by("i2c-"),
        spi: by("spidev"),
    }
}

/// Physical disks as display labels ("nvme0n1  931G  SSD (…)") for the `kern top` Overview tab. The
/// `/sys/block` parsing lives in one place ([`read_disks`]).
pub(crate) fn host_disks() -> Vec<String> {
    read_disks().iter().map(disk_label).collect()
}

/// One-line label for a disk in `kern probe`: `nvme0n1  931G  SSD (Samsung 980)`.
fn disk_label(d: &DiskInfo) -> String {
    let kind = if d.ssd { "SSD" } else { "HDD" };
    let model = if d.model.is_empty() {
        String::new()
    } else {
        format!(" ({})", d.model)
    };
    format!("{}  {}  {kind}{model}", d.name, human_bytes(d.size))
}

/// A ready-to-use kern.toml whose example profiles use THIS host's real numbers (so a beginner can
/// `kern run vcpu:heavy` straight away, no guessing). Only includes a GPIO block if the host has one.
fn tailored_kern_toml(h: &HostInv) -> String {
    let n = h.ncpu.max(1);
    let half = ((n as f64 / 2.0) * 10.0).round() / 10.0; // ~half the cores, one decimal
    let pin_hi = n.saturating_sub(1).min(3);
    let mut s = format!(
        "# ~/.config/kern/kern.toml - generated by `kern config setup` for this host \
         ({n} cores, {ram}).\n# Attach a profile by prefix:  kern run vcpu:heavy -- ./train.sh   \
         ·  edit with `kern config edit`\n\n[kern]\nlog_level = \"info\"\n\n\
         # ── CPU ──  (profile fields match the CLI flags: cpus=--cpus, cpuset=--cpuset-cpus, memory=--memory, nice=--nice)\n\
         [[cpu]]\nid = \"cpu:0\"\ncores = {n}.0\n\n\
         [[vcpu]]\nname = \"heavy\"     # ~half this host, pinned to the first cores\n\
         backend = \"cpu:0\"\ncpus = {half}\ncpuset = \"0-{pin_hi}\"\nmemory = \"512 MB\"\n\n\
         [[vcpu]]\nname = \"lean\"\nbackend = \"cpu:0\"\ncpus = 0.5\nmemory = \"256m\"\n",
        ram = h.ram
    );
    // A [[disk]] pool + a vdisk profile that references it, seeded from this host's primary disk, so
    // `kern box … vdisk:scratch` has a real target. Only when a disk was actually detected.
    if let Some(d) = h.disks.first() {
        let kind = if d.ssd { "SSD" } else { "HDD" };
        let model = if d.model.is_empty() {
            String::new()
        } else {
            format!(" {}", d.model)
        };
        s.push_str(&format!(
            "\n# ── Disk - `kern box … vdisk:scratch` gets a size-capped ext4 volume ──\n\
             [[disk]]\nid = \"disk:0\"\npath = \"/\"\ndevice = \"{dev}\"   # {size} {kind}{model}\n\n\
             [[vdisk]]\nname = \"scratch\"\nbackend = \"disk:0\"\nsize = \"2g\"\n",
            dev = d.name,
            size = human_bytes(d.size),
        ));
    }
    if !h.i2c.is_empty() || !h.gpiochips.is_empty() {
        s.push_str(
            "\n# ── GPIO / I/O - `kern box … vgpio:io` binds ONLY these devices into the box ──\n\
             [[gpio]]\nid = \"gpio:0\"\n\n[[vgpio]]\nname = \"io\"\nbackend = \"gpio:0\"\n",
        );
        if let Some(first) = h.i2c.first() {
            // Keep the comment lean: show a few real buses, not all of them.
            let shown = h.i2c.iter().take(4).cloned().collect::<Vec<_>>().join(", ");
            let more = h.i2c.len().saturating_sub(4);
            let extra = if more > 0 {
                format!(" (+{more} more)")
            } else {
                String::new()
            };
            s.push_str(&format!(
                "i2c = [\"/dev/{first}\"]    # host buses: {shown}{extra}\n"
            ));
        }
        if !h.gpiochips.is_empty() {
            s.push_str(&format!(
                "pins = [17]           # gpiochips: {}\n",
                h.gpiochips.join(", ")
            ));
        }
    } else {
        s.push_str(
            "\n# (no GPIO/I2C detected here - add a [[vgpio]] profile when you attach hardware)\n",
        );
    }
    s
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

/// `kern validate [path]` - parse a `kern.toml` (the given path, or the default location) and report
/// success with profile counts, or the offending line. Exits non-zero on a parse error.
/// Count `[` and `]` in `line` that are OUTSIDE single/double quotes - so a bracket inside a string
/// value doesn't fool the multi-line-array tracking in `validate`. Escape-agnostic (TOML basic strings
/// use `\\`, but for bracket-balance the simple quote toggle is sufficient for a best-effort linter).
fn brackets_outside_quotes(line: &str) -> (usize, usize) {
    let (mut opens, mut closes, mut q) = (0usize, 0usize, 0u8);
    for b in line.bytes() {
        match b {
            b'"' | b'\'' if q == 0 => q = b,
            _ if b == q => q = 0,
            b'[' if q == 0 => opens += 1,
            b']' if q == 0 => closes += 1,
            _ => {}
        }
    }
    (opens, closes)
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

/// `kern examples` - print a commented example `kern.toml` to stdout (redirect it into
/// `~/.config/kern/kern.toml` to get started).
pub fn examples() -> Result<(), Error> {
    print!("{EXAMPLE_KERN_TOML}");
    Ok(())
}

/// A ready-to-use example config covering the resource families kern-public supports (CPU/GPIO/disk).
const EXAMPLE_KERN_TOML: &str = r#"# ~/.config/kern/kern.toml - resource profiles for `kern run`/`kern box`.
# Attach a profile by prefix, e.g.  kern run vcpu:heavy -- ./train.sh

[kern]
log_level = "info"

# ── CPU ──────────────────────────────────────────────────────────────────
# Declare the host CPU budget (optional), then carve named vCPU profiles. Every [[vcpu]] MUST name a
# `backend`: a [[cpu]] id below, or the reserved "host" (the whole host CPU, no [[cpu]] needed).
[[cpu]]
id = "cpu:0"
cores = 8.0           # host capacity (physical cores)

[[vcpu]]
name = "heavy"
backend = "cpu:0"     # REQUIRED: a [[cpu]] id above, or "host" for the whole host CPU
cpus = 4.0            # core quota (like --cpus): 4 cores
cpuset = "0-3"        # pin to CPUs 0-3 (like --cpuset-cpus)
memory = "2g"         # RAM cap (like --memory)
nice = -5             # scheduling priority (like --nice): -20..19

[[vcpu]]
name = "lean"
backend = "host"      # no [[cpu]] to declare: slice the whole host directly
cpus = 0.5
memory = "256m"

# ── GPIO / I/O - `kern box vgpio:leds …` binds ONLY these devices into the box ──
[[gpio]]
id = "gpio:0"
pins = [17, 27, 22]

[[vgpio]]
name = "leds"
backend = "gpio:0"    # REQUIRED: a [[gpio]] id above, or "host" for the host's own device nodes
pins = [17, 27]       # a subset of the [[gpio]]'s pins - expose ONLY these lines, nothing else

# ── Disk - `kern box vdisk:scratch …` mounts a size-capped volume at /vdisk/scratch ──
[[disk]]
id = "data"
path = "/var/lib/kern/volumes"

[[vdisk]]
name = "scratch"
backend = "data"      # REQUIRED: a [[disk]] id above, or "ram" for a RAM-backed tmpfs
size = "2g"
"#;

#[cfg(test)]
mod commit_tests {
    use super::*;

    #[test]
    fn unescape_mountinfo_decodes_octal_and_leaves_plain_paths() {
        // Plain paths (the common case) pass through untouched.
        assert_eq!(unescape_mountinfo("/proc"), "/proc");
        assert_eq!(unescape_mountinfo("/mnt/vol"), "/mnt/vol");
        assert_eq!(unescape_mountinfo("/"), "/");
        // mountinfo octal-escapes space (\040), tab (\011), newline (\012), backslash (\134).
        assert_eq!(unescape_mountinfo("/mnt/my\\040vol"), "/mnt/my vol");
        assert_eq!(unescape_mountinfo("/a\\134b"), "/a\\b");
        // A lone backslash not starting a 3-octal escape is preserved verbatim (never panics).
        assert_eq!(unescape_mountinfo("/a\\b"), "/a\\b");
        assert_eq!(unescape_mountinfo("/end\\"), "/end\\");
    }
}

#[cfg(test)]
mod net_resource_tests {
    use super::*;

    fn inst(name: &str, pid: i32, pod: &str) -> registry::Instance {
        registry::Instance {
            name: name.to_string(),
            pid,
            pid1: 0,
            rootfs: String::new(),
            command: String::new(),
            started: 0,
            starttime: 0,
            ports: String::new(),
            volumes: String::new(),
            pod: pod.to_string(),
            workdir: String::new(),
            egress: String::new(),
            landlock_rw: String::new(),
            memory_max: None,
            pids_max: None,
            labels: String::new(),
            stop_signal: 0,
            stop_grace: 0,
            def_hash: String::new(),
            cap_drop_all: false,
            cap_drops: String::new(),
            cap_adds: String::new(),
            seccomp_mode: kern_isolation::SeccompFilter::Denylist,
            apparmor: String::new(),
            cap_recorded: true,
            aa_recorded: true,
            seccomp_recorded: true,
            posture_corrupt: false,
            cgroup: String::new(),
            cgroup_id: None,
            orphaned: false,
        }
    }

    #[test]
    fn ref_matches_name_pid_and_pod_with_name_winning() {
        let web = inst("web", 100, "myapp");
        let db = inst("db", 101, "myapp");
        let live: std::collections::HashSet<String> =
            ["web", "db"].into_iter().map(String::from).collect();
        // by exact NAME
        assert!(ref_matches(&web, "web", &live));
        assert!(!ref_matches(&db, "web", &live));
        // by POD name - selects every member of the pod
        assert!(ref_matches(&web, "myapp", &live));
        assert!(ref_matches(&db, "myapp", &live));
        // by PID (as a string) when no live box bears that exact name
        assert!(ref_matches(&web, "100", &live));
        assert!(!ref_matches(&web, "101", &live));
        // NAME WINS: a ref equal to a live box name never falls through to the pid/pod branch - so a
        // box literally named "web" can't sweep a same-named pod, and a numeric name isn't shadowed.
        let numname = inst("100", 999, "grp");
        let live2: std::collections::HashSet<String> =
            ["100"].into_iter().map(String::from).collect();
        assert!(ref_matches(&numname, "100", &live2)); // matches by its NAME…
        let other = inst("x", 100, "grp"); // …and NOT by a coincidental pid == that name
        assert!(!ref_matches(&other, "100", &live2));
    }

    #[test]
    fn ref_matches_empty_ref_never_sweeps_standalone_boxes() {
        // A standalone box has pod == "". An empty ref (`kern stop ""`) must NOT match it via the pod
        // branch - otherwise one stray empty argument would stop/pause every standalone box at once.
        let empty = std::collections::HashSet::new();
        let solo = inst("solo", 7, "");
        assert!(!ref_matches(&solo, "", &empty));
        // …and an empty ref also can't match a real pod member (there's no pod named "").
        let member = inst("m", 8, "realpod");
        assert!(!ref_matches(&member, "", &empty));
    }

    #[test]
    fn matching_refs_dedups_a_box_selected_by_both_its_name_and_pod() {
        // `kern stop web mypod` where box `web` is a member of `mypod`: the box matches TWO refs but
        // must appear once (else stop would kill -SIGKILL a pid twice / double-print).
        let running = vec![inst("web", 10, "mypod"), inst("db", 11, "mypod")];
        let sel = boxes_matching_refs(running, &["web".into(), "mypod".into()]);
        assert_eq!(
            sel.len(),
            2,
            "web selected by name AND pod must not duplicate"
        );
        let names: Vec<&str> = sel.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["web", "db"]);
    }

    #[test]
    fn a_box_named_like_a_pod_wins_over_the_pod_members() {
        // NAME-wins across the whole ref: a standalone box literally named `web` coexisting with a pod
        // also named `web` → `kern stop web` selects ONLY the standalone box, never the pod's members
        // (the pod branch is gated off whenever a live box bears that exact name).
        let running = vec![
            inst("web", 20, ""),      // standalone box literally named "web"
            inst("api", 21, "web"),   // a DIFFERENT box that belongs to a pod named "web"
            inst("cache", 22, "web"), // another member of pod "web"
        ];
        let sel = boxes_matching_refs(running, &["web".into()]);
        let names: Vec<&str> = sel.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["web"], "name wins; pod members are not swept");
    }

    #[test]
    fn matching_refs_selects_two_pods_and_a_loose_name_together() {
        // `kern stop p1 p2 loner` sweeps every member of both pods plus the standalone - one pass,
        // stable order, no cross-contamination between pods.
        let running = vec![
            inst("a1", 30, "p1"),
            inst("b1", 31, "p2"),
            inst("a2", 32, "p1"),
            inst("loner", 33, ""),
            inst("c", 34, "p3"), // untouched
        ];
        let sel = boxes_matching_refs(running, &["p1".into(), "p2".into(), "loner".into()]);
        let mut names: Vec<&str> = sel.iter().map(|b| b.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["a1", "a2", "b1", "loner"]);
    }

    #[test]
    fn brackets_outside_quotes_ignores_strings() {
        // Deep validate audit: a `[`/`]` inside a string value must NOT count toward the multi-line
        // array balance - else `name = "has ] bracket"` would spuriously open/close an array and make
        // the validator silently skip the following lines.
        assert_eq!(brackets_outside_quotes("pins = [1, 2, 3]"), (1, 1)); // real array
        assert_eq!(brackets_outside_quotes(r#"name = "has ] bracket""#), (0, 0)); // ] in string
        assert_eq!(brackets_outside_quotes(r#"x = "[ open only""#), (0, 0)); // [ in string
        assert_eq!(brackets_outside_quotes("pins = ["), (1, 0)); // multi-line array open
        assert_eq!(brackets_outside_quotes("]"), (0, 1)); // multi-line array close
        assert_eq!(brackets_outside_quotes(r#"a = '][' single"#), (0, 0)); // single-quoted
    }

    #[test]
    fn run_leading_dashdash_is_not_reclassified_as_a_profile() {
        // Hacker-mode regression: `kern run -- vcpu:heavy prog` - the `--` end-of-options contract means
        // `vcpu:heavy` is the literal command, NOT a profile to peel. peel_run_profiles must skip the
        // leading `--` and return start=1 without applying any profile.
        fn empty() -> AppliedProfiles {
            AppliedProfiles {
                memory: None,
                cpus: None,
                cpuset: None,
                nice: None,
                vgpio: Vec::new(),
                vdisk: Vec::new(),
            }
        }
        let cmd = vec![
            "--".to_string(),
            "vcpu:heavy".to_string(),
            "prog".to_string(),
        ];
        let mut out = empty();
        // Must NOT error on a (possibly non-existent) profile name, and must start the command at 1
        // (right after the `--`), leaving `vcpu:heavy prog` as the literal argv.
        let start = peel_run_profiles(&cmd, None, &mut out).unwrap();
        assert_eq!(start, 1);
        assert!(out.cpuset.is_none() && out.cpus.is_none() && out.memory.is_none());
        assert_eq!(&cmd[start..], ["vcpu:heavy", "prog"]);
    }

    #[test]
    fn parse_volumes_guards_targets() {
        // `parse_volumes` resolves the registry root from the process-global `XDG_RUNTIME_DIR`; hold
        // `TEST_ENV_LOCK` so a sibling test flipping that var under /tmp can't make `/tmp` look like an
        // ancestor of the (relocated) registry root and spuriously refuse a valid `-v`.
        let _env = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Bad targets are rejected before any mount.
        for bad in [
            "data:mnt",        // relative
            "data:/../escape", // traversal
            "data:/proc",      // shadows the box's proc
            "data:/sys",
            "data:/dev",
            "data:/",      // over the whole rootfs
            "data:/./x",   // dot component
            "data://proc", // leading-double-slash bypass - resolves to /proc at mount time
            "data://sys",
            "data://dev",
            "data:///dev", // triple slash too
            "data://dev/", // trailing slash after the bypass
        ] {
            assert!(
                parse_volumes(&[bad.into()]).is_err(),
                "should reject -v {bad}"
            );
        }
        // A subpath of an essential mount is allowed (use an existing host source to stay hermetic).
        assert!(
            parse_volumes(&["/tmp:/dev/foo".into()]).is_ok(),
            "a subpath like /dev/foo must be allowed"
        );
        assert!(parse_volumes(&["/tmp:/data".into()]).is_ok());
    }

    #[test]
    fn a_volume_source_that_resolves_onto_the_registry_is_refused_in_every_form() {
        // The anti-forgery gate canonicalizes the source BEFORE the overlap check, so every path form
        // that RESOLVES onto a trust-bearing registry dir - trailing slash, `.`/`..`, a symlink, or the
        // PARENT that contains it - must be refused, not just the exact literal. A test on the literal
        // alone would leave the equivalent forms unproven (adversarial review, final round). Each must
        // fail with the OVERLAP message, not a source-not-found error, so the dirs are materialized
        // first.
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-forgegate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // Canonicalize the base so a symlinked `/tmp` (rare, but real on some systems) can't make the
        // PARENT-form comparison inconsistent with what `parse_volumes` canonicalizes.
        let tmp = std::fs::canonicalize(&tmp).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &tmp);

        // Materialize instances/claims/exit so `canonicalize` of the forms below succeeds. Production
        // resolves the identity set non-creatingly, so the test must create the dirs explicitly.
        crate::registry::materialize_authoritative_dirs_for_test();
        assert!(
            !crate::registry::trusted_state_dirs().is_empty(),
            "registry state dirs were created"
        );
        let kern = tmp.join("kern");
        std::os::unix::fs::symlink(&kern, tmp.join("link")).unwrap();
        std::fs::create_dir_all(tmp.join("kern-other")).unwrap();

        let refused = |src: String| -> bool {
            parse_volumes(&[format!("{src}:/r")])
                .err()
                .map(|e| {
                    e.to_string()
                        .contains("refusing to mount the kern registry")
                })
                .unwrap_or(false)
        };
        let t = tmp.to_string_lossy().into_owned();
        for form in [
            format!("{t}/kern"),              // the exact dir
            format!("{t}/kern/"),             // trailing slash
            format!("{t}/./kern"),            // a `.` component
            format!("{t}/kern/../kern"),      // a `..` round-trip
            format!("{t}/kern/instances/.."), // `..` out of a subdir
            format!("{t}/kern/instances"),    // a trust-bearing subdir directly
            format!("{t}/kern/claims"),       // and another
            format!("{t}/kern/waitexit"), // the `ps -a` breadcrumb dir (forgeable exited records)
            format!("{t}/link"),          // a symlink resolving onto the registry
            t.clone(),                    // the PARENT that contains kern/
        ] {
            assert!(refused(form.clone()), "must refuse -v source {form}");
        }
        // PARAMETRIZED on the production list: every dir `trusted_state_dirs()` protects must be refused
        // directly. So a dir added there (as `waitexit/` was) is auto-covered here instead of needing a
        // new literal above - the literal list drifting from production is the exact gap that let
        // `waitexit/` ship unprotected.
        for d in crate::registry::trusted_state_dirs() {
            assert!(
                refused(d.to_string_lossy().into_owned()),
                "must refuse trusted state dir {d:?}"
            );
        }
        // A sibling that merely shares a name prefix stays mountable.
        assert!(
            parse_volumes(&[format!("{t}/kern-other:/r")]).is_ok(),
            "a sibling of the registry must stay mountable"
        );

        std::env::remove_var("XDG_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn cp_save_write_guard_follows_a_symlink_into_the_registry() {
        // `kern cp box:/x <dst>` / `kern save -o <dst>` write via `File::create`, which FOLLOWS a symlink
        // at `dst`. A parent-only check let a symlink final component (in a safe dir, pointing at the
        // registry) redirect the write onto a peer's posture record - a real forgery bypass. The guard
        // must follow the link to where the write LANDS. Covers a direct link, a link to a not-yet-existing
        // registry path, and a two-hop chain; a link to a safe target stays writable.
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-wguard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let tmp = std::fs::canonicalize(&tmp).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &tmp);
        crate::registry::materialize_authoritative_dirs_for_test();

        let safe = tmp.join("safe");
        std::fs::create_dir_all(&safe).unwrap();
        let instances = tmp.join("kern/instances");
        std::fs::write(instances.join("rec"), b"posture").unwrap();

        let g =
            |p: &std::path::Path| crate::secret::guard_host_write_path(&p.to_string_lossy(), "cp");
        // direct symlink onto an existing registry record
        let l1 = safe.join("l1");
        std::os::unix::fs::symlink(instances.join("rec"), &l1).unwrap();
        assert!(
            g(&l1).is_err(),
            "symlink onto a registry record must be refused"
        );
        // symlink onto a NOT-yet-existing registry path (write would CREATE it)
        let l2 = safe.join("l2");
        std::os::unix::fs::symlink(instances.join("newrec"), &l2).unwrap();
        assert!(
            g(&l2).is_err(),
            "symlink onto a new registry path must be refused"
        );
        // two-hop chain -> record
        let l3 = safe.join("l3");
        std::os::unix::fs::symlink(&l1, &l3).unwrap();
        assert!(
            g(&l3).is_err(),
            "a symlink chain into the registry must be refused"
        );
        // a symlink onto a SAFE target stays writable (target in `safe/`, NOT the runtime dir root -
        // that dir is an ANCESTOR of the registry and refused by design), and a plain safe path too
        let good = safe.join("good");
        std::os::unix::fs::symlink(safe.join("target.txt"), &good).unwrap();
        assert!(
            g(&good).is_ok(),
            "a symlink to a safe target must stay writable"
        );
        assert!(
            g(&safe.join("plain.txt")).is_ok(),
            "an ordinary path must stay writable"
        );

        std::env::remove_var("XDG_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn parse_tmpfs_guards_hardened_mounts_incl_double_slash() {
        for bad in [
            "/proc",
            "/sys",
            "/dev",      // exact hardened roots
            "/proc/foo", // under a hardened root
            "//proc",
            "//sys",
            "//dev", // leading-double-slash bypass
            "///dev/x",
        ] {
            assert!(
                parse_tmpfs(&[bad.into()]).is_err(),
                "should reject --tmpfs {bad}"
            );
        }
        // A normal tmpfs path is fine.
        assert!(parse_tmpfs(&["/scratch".into()]).is_ok());
        assert!(parse_tmpfs(&["/var/cache:64m".into()]).is_ok());
    }

    #[test]
    fn image_command_resolution() {
        let img = kern_oci::ImageConfig {
            entrypoint: vec!["docker-entrypoint.sh".into()],
            cmd: vec!["redis-server".into()],
            ..Default::default()
        };
        // No user command → entrypoint + image Cmd.
        assert_eq!(
            resolve_image_command(&[], false, &img),
            vec!["docker-entrypoint.sh", "redis-server"]
        );
        // User command → entrypoint + user command (image Cmd dropped, docker-style).
        assert_eq!(
            resolve_image_command(&["redis-cli".into()], false, &img),
            vec!["docker-entrypoint.sh", "redis-cli"]
        );
        // --ssh + no command → keep-alive, ignore the image command.
        assert_eq!(
            resolve_image_command(&[], true, &img),
            vec!["sleep", "infinity"]
        );
        // No image config + no command → a shell (the --rootfs / bare case).
        let empty = kern_oci::ImageConfig::default();
        assert_eq!(
            resolve_image_command(&[], false, &empty),
            vec![DEFAULT_SHELL]
        );
        // No image config + user command → the user command unchanged.
        assert_eq!(
            resolve_image_command(&["echo".into(), "hi".into()], false, &empty),
            vec!["echo", "hi"]
        );
    }

    #[test]
    fn restart_policy_parses_docker_names_only() {
        assert_eq!(RestartPolicy::parse("no"), Some(RestartPolicy::No));
        assert_eq!(
            RestartPolicy::parse("on-failure"),
            Some(RestartPolicy::OnFailure)
        );
        assert_eq!(RestartPolicy::parse("always"), Some(RestartPolicy::Always));
        assert_eq!(
            RestartPolicy::parse("unless-stopped"),
            Some(RestartPolicy::UnlessStopped)
        );
        // Unknown tokens don't parse - so a bare `--restart` won't swallow the next arg/command.
        assert_eq!(RestartPolicy::parse("sh"), None);
        assert_eq!(RestartPolicy::parse("--memory"), None);
        assert_eq!(RestartPolicy::parse(""), None);
        // Only always/unless-stopped are reboot-persistent (→ a systemd unit).
        assert!(RestartPolicy::Always.persistent() && RestartPolicy::UnlessStopped.persistent());
        assert!(!RestartPolicy::OnFailure.persistent() && !RestartPolicy::No.persistent());
    }

    #[test]
    fn systemd_quote_neutralizes_expansion_and_quoting() {
        // Plain arg is just wrapped.
        assert_eq!(systemd_quote("alpine"), "\"alpine\"");
        // `$` and `%` (systemd env/specifier expansion) are doubled so they stay literal.
        assert_eq!(systemd_quote("echo $(date +%s)"), "\"echo $$(date +%%s)\"");
        // Embedded quotes/backslashes are C-escaped so the ExecStart line stays parseable.
        assert_eq!(systemd_quote(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    /// `WORKDIR /app` + `COPY . .` is the shape most application Dockerfiles have, and joining the
    /// relative dot destination onto the workdir built `/app/.`, which `cp` cannot create. The
    /// neighbours that DID work are pinned too, because they are why the bug survived: `COPY . /app`
    /// and `COPY main.py .` both went down other paths.
    ///
    /// `..` must come out UNTOUCHED. Resolving it here would silently convert an escape that
    /// `sanitize_rootfs_rel` rejects into one it never sees.
    #[test]
    fn a_dot_destination_collapses_but_dotdot_survives_for_the_guard() {
        assert_eq!(collapse_dot_segments("/app/."), "/app");
        assert_eq!(collapse_dot_segments("/a/b/c/."), "/a/b/c");
        assert_eq!(collapse_dot_segments("/app/./sub"), "/app/sub");
        assert_eq!(collapse_dot_segments("//app//sub//"), "/app/sub");
        assert_eq!(collapse_dot_segments("/app"), "/app");
        // A destination that reduces to nothing is the rootfs itself, not the empty string.
        assert_eq!(collapse_dot_segments("/."), "/");
        assert_eq!(collapse_dot_segments("/"), "/");
        // Left for the guard to refuse, never resolved here.
        assert_eq!(collapse_dot_segments("/app/.."), "/app/..");
        assert_eq!(collapse_dot_segments("/../../etc"), "/../../etc");
        assert!(sanitize_rootfs_rel("..", &collapse_dot_segments("/app/..")[1..]).is_err());
    }

    #[test]
    fn sanitize_ref_is_traversal_free_and_collision_free() {
        // No `.`/`/`/`:` survive → a `..` ref can't build a `cache/..` traversal.
        for r in ["..", ".", "../../etc", "a/../b"] {
            let s = sanitize_ref(r);
            assert!(
                !s.contains('/') && s != ".." && s != "." && !s.split('-').any(|p| p == ".."),
                "{r} → {s} still looks traversal-ish"
            );
        }
        // Distinct refs that used to collapse together now differ (the hash suffix).
        assert_ne!(sanitize_ref("foo/bar"), sanitize_ref("foo_bar"));
        assert_ne!(sanitize_ref("alpine:3.19"), sanitize_ref("alpine:3_19"));
        // Same ref → same key (stable cache).
        assert_eq!(sanitize_ref("redis:alpine"), sanitize_ref("redis:alpine"));
    }

    #[test]
    fn layer_cache_key_helpers() {
        // Deterministic + chained: same inputs → same key; a changed repr OR a changed parent key
        // → different key (so a change busts this layer and everything after it).
        let k0 = layer_key("base", "RUN a");
        assert_eq!(k0, layer_key("base", "RUN a"));
        assert_ne!(k0, layer_key("base", "RUN b")); // repr changed
        assert_ne!(k0, layer_key("other", "RUN a")); // parent key changed
        assert_eq!(k0.len(), 32); // 128-bit hex
                                  // chain_lower stacks top (last) first, base (first) last - overlayfs shadow order.
        assert_eq!(
            chain_lower(&["base".into(), "l1".into(), "l2".into()]),
            "l2:l1:base"
        );
    }

    #[test]
    fn content_hash_changes_with_content() {
        let d = format!("/tmp/.kern-ch-{}", std::process::id());
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(format!("{d}/a"), b"one").unwrap();
        let p = std::path::Path::new(&d);
        let h1 = content_hash(p, p, None);
        assert_eq!(h1, content_hash(p, p, None)); // stable
        std::fs::write(format!("{d}/a"), b"two").unwrap();
        assert_ne!(h1, content_hash(p, p, None)); // content changed
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn content_hash_respects_dockerignore() {
        // An ignored file must NOT contribute to the key (mirrors what COPY actually keeps): editing
        // `secret.env` when `.dockerignore` excludes it leaves the key unchanged, and a real file does
        // change it. Guards the cache-correctness + don't-hash-ignored-bytes fix.
        let d = format!("/tmp/.kern-chi-{}", std::process::id());
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(format!("{d}/.dockerignore"), b"secret.env\nnode_modules\n").unwrap();
        std::fs::write(format!("{d}/app.txt"), b"code").unwrap();
        std::fs::write(format!("{d}/secret.env"), b"KEY=1").unwrap();
        std::fs::create_dir_all(format!("{d}/node_modules/x")).unwrap();
        std::fs::write(format!("{d}/node_modules/x/big"), b"junk").unwrap();
        let p = std::path::Path::new(&d);
        let ig = crate::dockerignore::DockerIgnore::load(p);
        assert!(ig.is_some(), "the .dockerignore should load");
        let base = content_hash(p, p, ig.as_ref());
        // Changing an IGNORED file leaves the key unchanged.
        std::fs::write(format!("{d}/secret.env"), b"KEY=changed").unwrap();
        std::fs::write(format!("{d}/node_modules/x/big"), b"junk-changed").unwrap();
        assert_eq!(
            base,
            content_hash(p, p, ig.as_ref()),
            "ignored change must not bust"
        );
        // Changing a KEPT file does bust the key.
        std::fs::write(format!("{d}/app.txt"), b"code2").unwrap();
        assert_ne!(
            base,
            content_hash(p, p, ig.as_ref()),
            "kept change must bust"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn clamp_cpuset_narrows_overwide_pins() {
        // Host CPU count (same source as the fn) - the test is host-agnostic.
        let host = std::fs::read_to_string("/proc/cpuinfo")
            .map(|t| t.lines().filter(|l| l.starts_with("processor")).count())
            .unwrap_or(1)
            .max(1);
        let max = host - 1;
        // An over-wide range is capped to the host's max CPU (never a raw `0-9999`).
        let want = if max == 0 {
            "0".to_string()
        } else {
            format!("0-{max}")
        };
        assert_eq!(
            clamp_cpuset(Some("0-9999".into()))
                .ok()
                .flatten()
                .as_deref(),
            Some(want.as_str())
        );
        // An in-range single is untouched; `None` passes through.
        assert_eq!(
            clamp_cpuset(Some("0".into())).ok().flatten().as_deref(),
            Some("0")
        );
        assert!(clamp_cpuset(None).ok().flatten().is_none());
        // Nothing in the list exists here → REFUSED, not passed through. This used to return the
        // original on the reasoning that the backend would reject it loudly; measured on a 28-CPU
        // machine, `--cpuset-cpus 28` reached systemd, applied nothing, printed nothing and exited 0
        // with the process free to use every CPU. A cap that cannot be applied must not silently
        // become no cap.
        let err = clamp_cpuset(Some("9999".into())).expect_err("an impossible pin must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("9999"),
            "the message must quote the request, got {msg}"
        );
        assert!(
            msg.contains("Refusing"),
            "the message must say it refused, got {msg}"
        );
        // The off-by-one is the case that actually mattered: one past the last CPU.
        assert!(
            clamp_cpuset(Some(host.to_string())).is_err(),
            "CPU index {host} does not exist on a {host}-CPU host and must be refused"
        );
        // ... while the last real CPU is accepted untouched, so the refusal is not over-broad.
        assert_eq!(
            clamp_cpuset(Some(max.to_string()))
                .ok()
                .flatten()
                .as_deref(),
            Some(max.to_string().as_str())
        );
        // A partially-valid list still clamps to the valid part rather than refusing.
        assert_eq!(
            clamp_cpuset(Some(format!("0,{host}")))
                .ok()
                .flatten()
                .as_deref(),
            Some("0")
        );
    }

    #[test]
    fn flat_image_key_is_content_addressed_and_ignore_aware() {
        // Guards the flat-build cache key: content-addressed (a changed Dockerfile / copied file busts
        // it → never a stale image) yet ignore-aware (an ignored file's change does NOT bust it).
        use crate::dockerfile::Instr;
        let d = format!("/tmp/.kern-fk-{}", std::process::id());
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(format!("{d}/node_modules")).unwrap();
        std::fs::write(format!("{d}/app.txt"), b"v1").unwrap();
        std::fs::write(format!("{d}/secret.env"), b"S").unwrap();
        std::fs::write(format!("{d}/node_modules/big"), b"junk").unwrap();
        std::fs::write(format!("{d}/.dockerignore"), b"node_modules\nsecret.env\n").unwrap();
        let ctx = std::path::Path::new(&d);
        let ig = crate::dockerignore::DockerIgnore::load(ctx);
        let instrs = vec![
            Instr::From {
                image: "scratch".into(),
                as_name: None,
            },
            Instr::Copy {
                srcs: vec![".".into()],
                dst: "/app".into(),
                from: None,
                chmod: None,
            },
        ];
        let key = |c: &std::path::Path| flat_image_key("base", &instrs, c, c, ig.as_ref());
        let k0 = key(ctx);
        assert_eq!(k0, key(ctx), "stable across calls");
        // Changing an IGNORED file must NOT move the key.
        std::fs::write(format!("{d}/secret.env"), b"CHANGED").unwrap();
        std::fs::write(format!("{d}/node_modules/big"), b"CHANGED").unwrap();
        assert_eq!(k0, key(ctx), "ignored change must not move the key");
        // Changing a KEPT file MUST move the key.
        std::fs::write(format!("{d}/app.txt"), b"v2").unwrap();
        assert_ne!(k0, key(ctx), "kept change must move the key");
        // A different instruction set (different dst) MUST move the key even with identical files.
        let instrs2 = vec![
            Instr::From {
                image: "scratch".into(),
                as_name: None,
            },
            Instr::Copy {
                srcs: vec![".".into()],
                dst: "/other".into(),
                from: None,
                chmod: None,
            },
        ];
        assert_ne!(
            key(ctx),
            flat_image_key("base", &instrs2, ctx, ctx, ig.as_ref()),
            "different instructions → different key"
        );
        // A different base lower MUST move the key.
        assert_ne!(
            key(ctx),
            flat_image_key("base2", &instrs, ctx, ctx, ig.as_ref()),
            "different base → different key"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn compose_pod_name_is_stable_unique_and_safe() {
        let ok = |n: &str| {
            !n.is_empty()
                && !n.starts_with('.')
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        };
        // Stable for the same path (so `up` and `down` agree) and always a valid pod name.
        let n = compose_pod_name("/srv/myapp/compose.yaml");
        assert_eq!(n, compose_pod_name("/srv/myapp/compose.yaml"));
        assert!(ok(&n) && n.starts_with("myapp-"), "dir-based + valid: {n}");
        // Two same-named compose files in DIFFERENT dirs → DIFFERENT pods (no cross-stack collision).
        assert_ne!(
            compose_pod_name("/srv/a/compose.yaml"),
            compose_pod_name("/srv/b/compose.yaml")
        );
        // Odd/empty stems still produce a valid name (base falls back, hash suffix appended).
        assert!(ok(&compose_pod_name("compose.yaml")));
        assert!(ok(&compose_pod_name("....")));
    }

    #[test]
    fn run_batching_helpers() {
        // Only the shell form is batchable.
        assert_eq!(
            run_shell_script(&["/bin/sh".into(), "-c".into(), "echo hi".into()]),
            Some("echo hi")
        );
        assert_eq!(run_shell_script(&["node".into(), "app.js".into()]), None);
        // Single quoting is `'\''`-safe.
        assert_eq!(shell_quote_single("a'b"), "'a'\\''b'");
        // A single script isn't re-wrapped.
        assert_eq!(
            combine_run_scripts(&["echo hi"]),
            vec!["/bin/sh", "-c", "echo hi"]
        );
        // Multiple scripts → each in its own subshell, `&&`-chained (fail-fast) and quoting-safe.
        assert_eq!(
            combine_run_scripts(&["a", "it's b"]),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "/bin/sh -c 'a' && /bin/sh -c 'it'\\''s b'".to_string(),
            ]
        );
    }

    #[test]
    fn image_config_sidecar_round_trips() {
        let c = kern_oci::ImageConfig {
            entrypoint: vec!["/entry".into()],
            cmd: vec!["-c".into(), "run".into()],
            env: vec!["A=1".into(), "B=2".into()],
            workdir: Some("/app".into()),
            user: Some("1000:1000".into()),
            exposed_ports: vec![(80, false), (53, true)],
        };
        let dir = std::env::temp_dir().join(format!("kern-imgcfg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("x.image");
        write_image_config(&f, &c).expect("write the config sidecar");
        // A write that cannot happen must be reported, not discarded. The sidecar used to be written
        // with `let _ =`, so an image could be cached and announced ready with no entrypoint, no env
        // and no user, and the box silently fell back to a shell. Forced here with a path whose
        // parent does not exist, which fails on every filesystem.
        assert!(
            write_image_config(&dir.join("no-such-dir").join("x.image"), &c).is_err(),
            "an unwritable config sidecar must be an error, not a silent no-op"
        );
        let r = read_image_config(&f);
        assert_eq!(r.entrypoint, c.entrypoint);
        assert_eq!(r.cmd, c.cmd);
        assert_eq!(r.env, c.env);
        assert_eq!(r.workdir, c.workdir);
        assert_eq!(r.user, c.user);
        assert_eq!(
            r.exposed_ports, c.exposed_ports,
            "the image's EXPOSE (used by the pod port-collision warning) must survive the sidecar"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hostname_validation() {
        assert_eq!(validate_hostname(None).unwrap(), None);
        assert_eq!(
            validate_hostname(Some("my-box.1")).unwrap().as_deref(),
            Some("my-box.1")
        );
        for bad in [
            "-lead",
            "trail-",
            ".dot",
            "has/slash",
            "sp ace",
            &"x".repeat(65),
        ] {
            assert!(
                validate_hostname(Some(bad)).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn tmpfs_parse_and_blocked_mounts() {
        assert_eq!(
            parse_tmpfs(&["/scratch:64M".into()]).unwrap(),
            vec![("/scratch".to_string(), "64m".to_string())]
        );
        // No size → empty (kernel default).
        assert_eq!(
            parse_tmpfs(&["/cache".into()]).unwrap(),
            vec![("/cache".to_string(), String::new())]
        );
        // Hardened mounts and their subpaths are refused; so are relative/`..` paths and bad sizes.
        for bad in [
            "/proc",
            "/sys/kernel",
            "/dev",
            "/dev/shm",
            "relative",
            "/a/../b",
            "/x:huge",
        ] {
            assert!(
                parse_tmpfs(&[bad.to_string()]).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn user_parse() {
        assert_eq!(parse_user(None).unwrap(), None);
        assert_eq!(parse_user(Some("1000")).unwrap(), Some((1000, 1000)));
        assert_eq!(parse_user(Some("1000:2000")).unwrap(), Some((1000, 2000)));
        for bad in ["alice", "1000:bob", ":5", "1000:"] {
            assert!(parse_user(Some(bad)).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn tag_ref_cannot_escape_the_cache() {
        // `tag`'s path safety rests entirely on `sanitize_ref`: a traversal ref must map to a key with
        // no `/` and no `..`, so `cache.join(key)` can never land outside the cache. Lock that here so a
        // future edit to sanitize_ref can't silently reopen a `tag ../../etc/x` escape.
        for evil in [
            "../../etc/passwd",
            "/etc/shadow",
            "a/../../b",
            "..",
            ".",
            "foo:../bar",
        ] {
            let key = sanitize_ref(evil);
            assert!(
                !key.contains('/'),
                "key for {evil:?} has a separator: {key}"
            );
            assert!(!key.contains(".."), "key for {evil:?} has `..`: {key}");
            // The join stays inside the cache root (no parent-dir component escapes it).
            let joined = std::path::Path::new("/cache/kern").join(&key);
            assert!(
                joined.starts_with("/cache/kern"),
                "{evil:?} → {joined:?} escaped the cache"
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn merged_view_honours_opaque_no_secret_resurrection() {
        // REGRESSION for the opaque-dir leak: two stacked layers where an UPPER layer made `/app` opaque
        // (`rm -rf /app && mkdir /app`, marked by `user.overlay.opaque`) and a LOWER layer holds a secret
        // `/app/token`. Reading the merged view (`merged_view_extract`) must NOT resurrect the secret -
        // the kernel applies the opaque, so `/app/token` is gone and only the upper's `marker` remains.
        // A naive raw-layer walk (the old fast-path) leaked the secret here.
        let base = std::env::temp_dir().join(format!("kern-mvbase-{}", std::process::id()));
        let top = std::env::temp_dir().join(format!("kern-mvtop-{}", std::process::id()));
        let out = std::env::temp_dir().join(format!("kern-mvout-{}", std::process::id()));
        for d in [&base, &top, &out] {
            let _ = std::fs::remove_dir_all(d);
        }
        std::fs::create_dir_all(base.join("app")).unwrap();
        std::fs::write(base.join("app/token"), b"SECRET_MUST_NOT_RESURFACE").unwrap();
        std::fs::create_dir_all(top.join("app")).unwrap();
        std::fs::write(top.join("app/marker"), b"public").unwrap();
        std::fs::create_dir_all(&out).unwrap();
        // Mark the top's `/app` opaque. In a userns-owned overlay kern mounts WITHOUT `userxattr`, so the
        // kernel reads `trusted.overlay.opaque`; but a plain test process can only set `user.overlay.*`.
        // We therefore skip if we can't establish the opaque (CI without the privilege) rather than pass
        // vacuously - the real guarantee is exercised end-to-end by the build tests.
        let set_trusted = std::process::Command::new("setfattr")
            .args(["-n", "trusted.overlay.opaque", "-v", "y"])
            .arg(top.join("app"))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !set_trusted {
            let _ = std::fs::remove_dir_all(&base);
            let _ = std::fs::remove_dir_all(&top);
            let _ = std::fs::remove_dir_all(&out);
            eprintln!(
                "skip: cannot set trusted.overlay.opaque (needs privilege); covered by build e2e"
            );
            return;
        }
        // chain is top-first: [top, base].
        let chain = vec![
            top.to_string_lossy().into_owned(),
            base.to_string_lossy().into_owned(),
        ];
        let r = merged_view_extract(&chain, Some("/app"), &out);
        // The copy of `/app` must succeed and contain ONLY `marker` - never the opaque-hidden `token`.
        assert!(r.is_ok(), "merged_view_extract failed: {r:?}");
        assert!(
            out.join("app/marker").exists(),
            "public marker should be copied"
        );
        assert!(
            !out.join("app/token").exists(),
            "SECRET RESURRECTED: the opaque-hidden token must not appear in the merged copy"
        );
        for d in [&base, &top, &out] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    #[test]
    fn copy_from_stage_cannot_escape_the_source_stage() {
        // The `COPY --from` security guard: a source that resolves (via `..` or a planted symlink)
        // OUTSIDE the source stage's rootfs must be rejected, exactly like a hostile context COPY. We
        // build a fake stage rootfs with a symlink to `/` and confirm a copy THROUGH it is refused.
        let stage = std::env::temp_dir().join(format!("kern-fromtest-{}", std::process::id()));
        let dest = std::env::temp_dir().join(format!("kern-fromdest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(stage.join("etc")).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(stage.join("etc/ok.txt"), b"in-stage").unwrap();
        // A legit in-stage copy succeeds.
        assert!(copy_from_stage_rootfs(&stage, "/etc/ok.txt", &dest).is_ok());
        assert!(dest.join("ok.txt").exists());
        // A `..` escape and a symlink-to-root escape are both refused (canonicalize + starts_with).
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/", stage.join("rootlink")).unwrap();
            let via_symlink = copy_from_stage_rootfs(&stage, "/rootlink/etc/hostname", &dest);
            assert!(
                via_symlink.is_err(),
                "a symlink-to-/ in the stage must not let a COPY --from escape"
            );
        }
        let via_dotdot = copy_from_stage_rootfs(&stage, "/etc/../../../../etc/passwd", &dest);
        assert!(via_dotdot.is_err(), "a `..` escape must be refused");
        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    #[cfg(unix)]
    fn copy_from_stage_preserves_inner_symlinks_no_follow() {
        // The double-copy escape class (reviewer 2a): copying a DIR out of a stage that CONTAINS an
        // absolute symlink to a host file must PRESERVE the symlink (cp -a no-follow), never dereference
        // it and copy the host file's bytes at build time. The symlink resolves only later, inside the
        // box, against the box's own rootfs - so a `→ /etc/passwd` reads the box's passwd, not the host's.
        let stage = std::env::temp_dir().join(format!("kern-sym-{}", std::process::id()));
        let dest = std::env::temp_dir().join(format!("kern-symdst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(stage.join("app")).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(stage.join("app/real.txt"), b"real").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", stage.join("app/evil")).unwrap();
        // Copy the whole `app` dir out - succeeds, and `evil` arrives as a SYMLINK, not the host file.
        assert!(copy_from_stage_rootfs(&stage, "/app", &dest).is_ok());
        let copied = dest.join("app/evil");
        let meta = std::fs::symlink_metadata(&copied).expect("evil should exist");
        assert!(
            meta.file_type().is_symlink(),
            "the inner symlink must be preserved as a symlink, not dereferenced to the host file"
        );
        assert_eq!(
            std::fs::read_link(&copied).unwrap(),
            std::path::Path::new("/etc/passwd"),
            "the symlink target must be verbatim, resolved only inside the box at run"
        );
        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    #[cfg(unix)]
    fn copy_from_stage_preserves_relative_symlink_no_host_read() {
        // Reviewer 2a residual vector: a RELATIVE symlink inside a copied dir whose target ESCAPES the
        // stage rootfs (many `..` → a host file). It must arrive as a verbatim symlink, its host target
        // NEVER read at build time (canary check), and stay dangling once inside the box. This is the
        // one case the absolute-symlink test didn't exercise; `cp -a` is no-follow so it's preserved.
        let stage = std::env::temp_dir().join(format!("kern-rel-{}", std::process::id()));
        let dest = std::env::temp_dir().join(format!("kern-reldst-{}", std::process::id()));
        let canary = std::env::temp_dir().join(format!("kern-rel-canary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(stage.join("sub")).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(&canary, b"HOST-SECRET-DO-NOT-LEAK").unwrap();
        // A relative symlink with enough `..` to reach the canary if it were ever followed.
        let rel_target = format!("../../../../../../../../..{}", canary.display());
        std::os::unix::fs::symlink(&rel_target, stage.join("sub/rellink")).unwrap();
        assert!(copy_from_stage_rootfs(&stage, "/sub", &dest).is_ok());
        let copied = dest.join("sub/rellink");
        let meta = std::fs::symlink_metadata(&copied).expect("rellink should exist");
        assert!(
            meta.file_type().is_symlink(),
            "the relative symlink must be preserved, not dereferenced"
        );
        // The link target is verbatim (relative), and the canary's CONTENT never entered the copy tree.
        assert_eq!(
            std::fs::read_link(&copied).unwrap().to_string_lossy(),
            rel_target
        );
        // Walk the whole copied tree: no file may contain the host secret's bytes (nothing dereferenced).
        fn contains_secret(p: &std::path::Path) -> bool {
            if let Ok(rd) = std::fs::read_dir(p) {
                for e in rd.flatten() {
                    let ep = e.path();
                    let ft = match std::fs::symlink_metadata(&ep) {
                        Ok(m) => m.file_type(),
                        Err(_) => continue,
                    };
                    if ft.is_symlink() {
                        continue; // never follow - the whole point
                    } else if ft.is_dir() {
                        if contains_secret(&ep) {
                            return true;
                        }
                    } else if let Ok(b) = std::fs::read(&ep) {
                        if b.windows(11).any(|w| w == b"HOST-SECRET") {
                            return true;
                        }
                    }
                }
            }
            false
        }
        assert!(
            !contains_secret(&dest),
            "the host canary's bytes must NEVER appear in the copied tree (no build-time deref)"
        );
        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&dest);
        let _ = std::fs::remove_file(&canary);
    }
}

#[cfg(test)]
mod scratch_tests {
    use super::{fs_magic_of, OVERLAYFS_SUPER_MAGIC};

    #[test]
    fn fs_magic_probes_the_deepest_existing_ancestor() {
        // /tmp exists → Some(magic), and on a dev host it is never overlayfs.
        let m = fs_magic_of(std::path::Path::new("/tmp")).expect("statfs /tmp");
        assert_ne!(
            m, OVERLAYFS_SUPER_MAGIC,
            "/tmp must not read as overlayfs on a host"
        );
        // A path that does not exist yet resolves via its ancestors (same magic as /tmp itself).
        let ghost = std::path::Path::new("/tmp/kern-test-does-not-exist-xyz/scratch/deeper");
        assert_eq!(fs_magic_of(ghost), Some(m));
    }
}

#[cfg(test)]
mod glob_tests {
    use super::{expand_copy_srcs, glob_expand_ctx, glob_match_component, has_glob_meta};

    fn m(p: &str, n: &str) -> bool {
        glob_match_component(p.as_bytes(), n.as_bytes())
    }

    #[test]
    fn glob_component_matcher() {
        assert!(m("*.txt", "a.txt") && m("*.txt", "f.txt") && !m("*.txt", "a.md"));
        assert!(m("?.txt", "a.txt") && !m("?.txt", "ab.txt"));
        assert!(m("[fg].txt", "f.txt") && m("[fg].txt", "g.txt") && !m("[fg].txt", "h.txt"));
        assert!(m("[!f].txt", "g.txt") && !m("[!f].txt", "f.txt"));
        assert!(m("[a-z]1", "b1") && !m("[a-z]1", "B1"));
        assert!(m("*", "anything.at.all") && m("abc", "abc") && !m("abc", "abd"));
        // `*` does not span a component (matcher is per-component), and matches an empty run.
        assert!(m("a*", "a") && m("*z", "z"));
        assert!(has_glob_meta("*.txt") && has_glob_meta("a?b") && !has_glob_meta("plain.txt"));
    }

    #[test]
    fn expand_against_a_context() {
        let dir = std::env::temp_dir().join(format!("kern-glob-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("d")).unwrap();
        for f in ["f.txt", "g.txt", "h.md"] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        std::fs::write(dir.join("d/a.txt"), b"x").unwrap();
        let mut got = glob_expand_ctx(&dir, "*.txt");
        got.sort();
        assert_eq!(got, vec!["f.txt".to_string(), "g.txt".to_string()]);
        assert_eq!(
            glob_expand_ctx(&dir, "d/*.txt"),
            vec!["d/a.txt".to_string()]
        );
        // A literal source passes through expand_copy_srcs; an unmatched glob is an error.
        assert_eq!(
            expand_copy_srcs(&dir, &["f.txt".to_string()]).unwrap(),
            vec!["f.txt".to_string()]
        );
        assert!(expand_copy_srcs(&dir, &["*.zzz".to_string()]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod add_url_tests {
    use super::{add_url_basename, apply_chmod};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn apply_chmod_sets_the_mode_and_rejects_garbage() {
        let dir = std::env::temp_dir().join(format!("kern-chmod-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("f");
        std::fs::write(&f, b"x").unwrap();
        // None → leave as-is (no error).
        assert!(apply_chmod(&f, None).is_ok());
        // Octal forms: 755, 0755, 0o755 all → rwxr-xr-x (0o755).
        for m in ["755", "0755", "0o755"] {
            apply_chmod(&f, Some(m)).unwrap();
            assert_eq!(
                std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
                0o755,
                "mode {m}"
            );
        }
        apply_chmod(&f, Some("644")).unwrap();
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o644
        );
        // A non-octal mode is a clear error, not a silent no-op.
        assert!(apply_chmod(&f, Some("rwx")).is_err());
        assert!(apply_chmod(&f, Some("999")).is_err()); // 9 isn't an octal digit
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_url_basename_is_a_safe_filename() {
        // Normal cases: the last path segment, query/fragment stripped.
        assert_eq!(
            add_url_basename("https://x.io/dl/tool-1.2.3.tar.gz"),
            "tool-1.2.3.tar.gz"
        );
        assert_eq!(add_url_basename("https://x.io/f?token=abc"), "f");
        assert_eq!(add_url_basename("https://x.io/f#frag"), "f");
        // Traversal / degenerate segments must NOT escape the scratch dir → fixed safe name.
        assert_eq!(add_url_basename("https://x.io/.."), "download");
        assert_eq!(add_url_basename("https://x.io/."), "download");
        assert_eq!(add_url_basename("https://x.io/"), "download");
        // A bare host with no path segment yields the host as a (harmless, non-escaping) name.
        assert_eq!(add_url_basename("https://x.io"), "x.io");
        // A separator or NUL smuggled into the last segment (defensive) → safe name.
        assert_eq!(add_url_basename("https://x.io/a\\b"), "download");
        assert_eq!(add_url_basename("https://x.io/a\0b"), "download");
    }
}

#[cfg(test)]
mod save_tag_tests {
    use super::*;

    #[test]
    fn ensure_repo_tag_appends_latest_only_when_untagged() {
        // a bare repo → :latest (so `docker load` doesn't reject "invalid tag")
        assert_eq!(ensure_repo_tag("alpine"), "alpine:latest");
        assert_eq!(ensure_repo_tag("library/nginx"), "library/nginx:latest");
        // an explicit tag is preserved
        assert_eq!(ensure_repo_tag("alpine:3.19"), "alpine:3.19");
        // a registry PORT is not a tag (it's before the last '/')
        assert_eq!(
            ensure_repo_tag("localhost:5000/app"),
            "localhost:5000/app:latest"
        );
        assert_eq!(
            ensure_repo_tag("localhost:5000/app:v2"),
            "localhost:5000/app:v2"
        );
    }
}

#[cfg(test)]
mod image_rm_tests {
    use super::*;

    // Build a fake pulled-image entry in `cache`: a `<stem>.ok` sentinel (content = ref) + a `<stem>/`
    // payload dir with one file of `bytes` bytes.
    fn fake_image(cache: &std::path::Path, stem: &str, refname: &str, bytes: usize) {
        std::fs::write(cache.join(format!("{stem}.ok")), refname).unwrap();
        let dir = cache.join(stem);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("blob"), vec![0u8; bytes]).unwrap();
    }

    /// A layer can carry a directory with no owner write bit (`dr-xr-xr-x` is ordinary in
    /// Fedora-based images). Unlinking a file needs write on its PARENT, so a plain `remove_dir_all`
    /// stops at the first one and leaves the rest on disk while `rmi` reports the size it measured
    /// beforehand. Measured on `quay.io/podman/stable`: "freed 600.5M", **456 MB still there**.
    /// On an SD-card board that is the difference between a full disk and an empty one.
    #[test]
    fn a_read_only_directory_does_not_survive_the_delete() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("kern-ro-rm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let deep = base.join("a/bloccata/dentro");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("file"), b"x").unwrap();
        // Take the write bit off the directory that HOLDS the file, which is what blocks the unlink.
        let ro = base.join("a/bloccata");
        let mut p = std::fs::metadata(&ro).unwrap().permissions();
        p.set_mode(0o555);
        std::fs::set_permissions(&ro, p).unwrap();
        // The plain call is expected to fail here - that is the bug being pinned.
        assert!(
            std::fs::remove_dir_all(&base).is_err(),
            "fixture is wrong: the plain remove succeeded, so it proves nothing"
        );
        force_remove_dir_all(&base);
        assert!(
            !base.exists(),
            "the tree survived the delete: rmi would report bytes it never freed"
        );
    }

    #[test]
    fn rmi_removes_only_the_named_image_and_reports_freed() {
        // Process-global env (XDG_CACHE_HOME) - serialize with every other env-mutating test.
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-rmitest-{}", std::process::id()));
        let cache = tmp.join("kern/images");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&cache).unwrap();
        std::env::set_var("XDG_CACHE_HOME", &tmp);

        fake_image(&cache, "alpine_3_19-aaaa", "alpine:3.19", 4096);
        fake_image(&cache, "alpine_3_20-bbbb", "alpine:3.20", 4096);

        // Resolve BY REF (as shown in `kern images`) and delete just that one.
        let freed = remove_image(&cache, "alpine:3.19").expect("image should be found by ref");
        assert!(
            freed >= 4096,
            "freed should include the payload dir, got {freed}"
        );
        assert!(
            !cache.join("alpine_3_19-aaaa.ok").exists() && !cache.join("alpine_3_19-aaaa").exists(),
            "the removed image's sentinel and payload are both gone"
        );
        // The OTHER image is untouched (no over-broad sweep).
        assert!(
            cache.join("alpine_3_20-bbbb.ok").exists() && cache.join("alpine_3_20-bbbb").is_dir(),
            "an unrelated image must survive a targeted rmi"
        );
        // Also resolvable BY STEM, and a miss returns None (→ "no such image", never a silent success).
        assert!(
            remove_image(&cache, "alpine_3_20-bbbb").is_some(),
            "stem resolves too"
        );
        assert!(remove_image(&cache, "ghost:1").is_none(), "a miss is None");

        std::env::remove_var("XDG_CACHE_HOME");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rmi_rejects_a_planted_dotdot_stem_and_cannot_escape_the_cache() {
        // A file literally named `...ok` has file_stem() == ".."; unchecked, cache.join("..") would let
        // a `remove_dir_all` wipe the cache's PARENT. `is_safe_stem` must reject it - a delete never
        // escapes the images dir, whatever a planted sentinel is named.
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-rmiesc-{}", std::process::id()));
        let cache = tmp.join("kern/images");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&cache).unwrap();
        // A canary living in the cache's PARENT (`kern/`) - it must survive no matter what.
        let canary = tmp.join("kern/CANARY");
        std::fs::write(&canary, b"do-not-delete").unwrap();
        // Plant the hostile sentinel: `...ok` (stem "..") with an arbitrary ref content.
        std::fs::write(cache.join("...ok"), "evil:1").unwrap();

        assert!(is_safe_stem("alpine_3_19-aaaa"));
        assert!(!is_safe_stem("..") && !is_safe_stem(".") && !is_safe_stem(""));
        // Neither the stem `..` nor the ref content can resolve to a deletion.
        assert!(
            remove_image(&cache, "..").is_none(),
            "a `..` stem is never a target"
        );
        assert!(
            remove_image(&cache, "evil:1").is_none(),
            "a planted sentinel's ref is inert"
        );
        assert!(canary.exists(), "the cache-parent canary must be untouched");
        assert!(cache.exists(), "the cache dir itself must be untouched");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rmi_removes_the_base_and_image_sidecars_too() {
        // rmi must delete ALL sidecar forms (via the shared drop_image_artifacts) - a leaked `.base`
        // would otherwise misclassify a later same-name pull.
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-rmiside-{}", std::process::id()));
        let cache = tmp.join("kern/images");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&cache).unwrap();
        std::env::set_var("XDG_CACHE_HOME", &tmp);

        let stem = "myapp-cccc";
        std::fs::write(cache.join(format!("{stem}.ok")), "myapp:latest").unwrap();
        std::fs::write(cache.join(format!("{stem}.base")), "alpine").unwrap();
        std::fs::write(cache.join(format!("{stem}.image")), "{}").unwrap();
        std::fs::create_dir_all(cache.join(format!("{stem}.diff"))).unwrap();

        assert!(remove_image(&cache, "myapp:latest").is_some());
        for suffix in [".ok", ".base", ".image", ".diff"] {
            assert!(
                !cache.join(format!("{stem}{suffix}")).exists(),
                "rmi must remove the {suffix} sidecar"
            );
        }

        std::env::remove_var("XDG_CACHE_HOME");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rmi_never_follows_a_symlinked_payload_dir() {
        // If the payload `<stem>/` is a SYMLINK to a dir outside the cache, deleting the image must NOT
        // reach through it - remove_dir_all unlinks the symlink, never the target's contents.
        use std::os::unix::fs::symlink;
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-rmisym-{}", std::process::id()));
        let cache = tmp.join("kern/images");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&cache).unwrap();
        // A victim dir OUTSIDE the cache with a canary the delete must never touch.
        let victim = tmp.join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("keep"), b"precious").unwrap();
        // Plant an image whose payload dir is a symlink to the victim.
        let stem = "evil-dddd";
        std::fs::write(cache.join(format!("{stem}.ok")), "evil:latest").unwrap();
        symlink(&victim, cache.join(stem)).unwrap();

        assert!(
            remove_image(&cache, "evil:latest").is_some(),
            "the sentinel resolves"
        );
        assert!(
            !cache.join(format!("{stem}.ok")).exists(),
            "the .ok sentinel is removed"
        );
        // The crucial invariant: the symlink TARGET (outside the cache) is untouched.
        assert!(
            victim.join("keep").exists(),
            "a symlinked payload's target must survive rmi"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rmi_keeps_a_layer_still_referenced_by_another_image() {
        // A shared L/ layer named by TWO images' manifests must survive rmi of the first, and only be
        // reclaimed once its last referrer is removed - the fail-closed sweep, end to end.
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-rmilayer-{}", std::process::id()));
        let cache = tmp.join("kern/images");
        let lc = cache.join("L");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&lc).unwrap();
        std::env::set_var("XDG_CACHE_HOME", &tmp);

        let key = "0123456789abcdef0123456789abcdef"; // 32 hex
        std::fs::create_dir_all(lc.join(key)).unwrap();
        std::fs::write(lc.join(key).join("blob"), vec![0u8; 2048]).unwrap();
        for (stem, refn) in [("app1-1111", "app1:latest"), ("app2-2222", "app2:latest")] {
            std::fs::write(cache.join(format!("{stem}.ok")), refn).unwrap();
            std::fs::write(
                cache.join(format!("{stem}.layers")),
                format!("base\n{key}\n"),
            )
            .unwrap();
        }

        assert!(remove_image(&cache, "app1:latest").is_some());
        assert!(
            lc.join(key).is_dir(),
            "a layer still referenced by another image must survive rmi"
        );
        assert!(remove_image(&cache, "app2:latest").is_some());
        assert!(
            !lc.join(key).exists(),
            "an orphaned layer is reclaimed once its last referrer is gone"
        );

        std::env::remove_var("XDG_CACHE_HOME");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn image_stat_flags_missing_layers_not_empty_builds() {
        // The honesty fix behind `kern images`: image_stat returns (size, dangling) in one pass, and
        // distinguishes a broken image (layers gone → would fail to run) from a legitimately EMPTY build
        // (a present but 0-byte layer → size 0 but NOT dangling).
        let tmp = std::env::temp_dir().join(format!("kern-dangling-{}", std::process::id()));
        let cache = tmp.join("images");
        let lc = cache.join("L");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&lc).unwrap();

        // Present but empty layer → size 0, NOT dangling (a valid empty build).
        std::fs::create_dir_all(lc.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).unwrap();
        std::fs::write(
            cache.join("empty-1.layers"),
            "base\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        assert_eq!(
            image_stat(&cache, "empty-1"),
            (0, false),
            "a present (0-byte) layer is a valid empty build: size 0, not dangling"
        );
        // Missing layer → dangling.
        std::fs::write(
            cache.join("broken-2.layers"),
            "base\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();
        assert!(
            image_stat(&cache, "broken-2").1,
            "a manifest naming a missing L/ layer is dangling"
        );
        // A flat pulled image (dir present) → never dangling.
        std::fs::create_dir_all(cache.join("pulled-3")).unwrap();
        assert!(
            !image_stat(&cache, "pulled-3").1,
            "a present flat rootfs is intact"
        );
        // A bare sentinel with no payload at all → dangling.
        assert!(
            image_stat(&cache, "orphan-4").1,
            "no flat/diff/layers → nothing to run"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn kill_box_reaps_a_foreground_sigterm_ignoring_init() {
        // Reproduces the reported bug: a FOREGROUND box's init is NOT a process-group leader, so the
        // historical `kill(-pid)` misses it, and a workload that ignores SIGTERM never dies. `kill_box`
        // must reach it by signalling `pid1` directly (SIGKILL, unignorable) and CONFIRM the exit.
        // Skip gracefully where pidfd_open is unavailable (kernel < 5.3); target boards are 5.15+.
        let self_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id() as i32, 0) };
        if self_fd < 0 {
            eprintln!("skip: pidfd_open unsupported on this kernel");
            return;
        }
        unsafe { libc::close(self_fd as i32) };

        // Fork a child that ignores SIGTERM and does NOT `setsid` (it stays in our process group, like
        // a foreground box's init), then busy-loops. Only async-signal-safe calls before it spins.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
            loop {
                std::hint::spin_loop();
            }
        }

        unsafe { libc::usleep(50_000) }; // let it install the handler and start spinning
        assert_eq!(
            unsafe { libc::kill(child, 0) },
            0,
            "child should be running"
        );
        // The OLD mechanism alone can't touch it: it's not a group leader, so no group has id `child`
        // - `kill(-child, SIGTERM)` is a harmless ESRCH, and SIGTERM is ignored regardless.
        unsafe { libc::kill(-child, libc::SIGTERM) };
        unsafe { libc::usleep(50_000) };
        assert_eq!(
            unsafe { libc::kill(child, 0) },
            0,
            "the process-group SIGTERM must NOT reach a foreground, SIGTERM-ignoring init"
        );

        // The fix: `kill_box` signals pid1 directly and confirms the exit before returning.
        assert!(
            kill_box_graceful(child, child, libc::SIGTERM, 0).confirmed(),
            "kill_box must confirm the foreground box is gone"
        );
        // Reap the zombie (kill_box confirms via the pidfd BEFORE the process is reaped).
        crate::eintr::reap(child);
        assert_ne!(
            unsafe { libc::kill(child, 0) },
            0,
            "child must be dead after kill_box"
        );
    }

    /// `stop` records what the box's exit code REALLY was, and the only place that fact survives is
    /// the unreaped zombie: `/proc/<pid>/stat` field 52. A clean shutdown (`trap ... exit 0`) and a
    /// SIGKILL are the two shapes this has to tell apart - reading them as the same 137 is exactly
    /// the bug this exists to prevent.
    ///
    /// The live-process case is the discriminant: it proves the function reads a real status rather
    /// than answering from the pid, and that a not-yet-dead init can never be recorded as exited.
    /// The child is held on a pipe until that check has run - asserting it against a child racing us
    /// to `_exit` made THIS TEST flaky (seen once in five full-suite runs), which is the same defect
    /// class it was written to catch, just on the test's side of the line.
    #[test]
    fn zombie_exit_code_tells_a_clean_exit_from_a_kill() {
        // (what the child does, what `waitpid` semantics say the code is)
        for (want, kill_self) in [(7, false), (0, false), (128 + libc::SIGKILL, true)] {
            let mut fds = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
            let (rd, wr) = (fds[0], fds[1]);
            let child = unsafe { libc::fork() };
            assert!(child >= 0, "fork");
            if child == 0 {
                // Async-signal-safe only: no allocation, no Rust runtime, between fork and _exit.
                unsafe { libc::close(wr) };
                let mut byte = 0u8;
                // Block until the parent has taken its live reading. EOF (parent died) releases too,
                // so a failing test cannot leave this child behind.
                while unsafe { libc::read(rd, std::ptr::addr_of_mut!(byte).cast(), 1) } < 0 {}
                if kill_self {
                    unsafe { libc::raise(libc::SIGKILL) };
                }
                unsafe { libc::_exit(want) };
            }
            unsafe { libc::close(rd) };
            // Live, not yet dead: there is no status to read and none must be invented.
            assert_eq!(
                zombie_exit_code(child),
                None,
                "a live process has no exit status to report"
            );
            // Let it go, and drop our end so an early failure above still releases it.
            unsafe { libc::write(wr, b"g".as_ptr().cast(), 1) };
            unsafe { libc::close(wr) };
            // Wait for the zombie WITHOUT reaping it - that is the window `stop` reads in.
            let mut seen = None;
            for _ in 0..2000 {
                if let Some(code) = zombie_exit_code(child) {
                    seen = Some(code);
                    break;
                }
                unsafe { libc::usleep(1_000) };
            }
            crate::eintr::reap(child);
            assert_eq!(
                seen,
                Some(want),
                "the zombie's recorded status must decode to the code the child really exited with"
            );
        }
    }

    /// The grace a box is left with, as an arithmetic fact rather than a race between two timers.
    ///
    /// The end-to-end version of this - a workload flushing for 1.5 s under a 2 s timeout - proves
    /// the number reaches the poll, but it can only ever have a sub-second margin, because a
    /// sub-second truncation is only visible to a flush that falls between `floor(T)` and `T`. On
    /// WSL2 that margin is gone: the same 1.5 s flush MEASURED 1723 ms there, and a 0.5 s one 1007 ms,
    /// so the platform's own overhead eats it. This test is the invariant; that one is the wiring.
    #[test]
    fn remaining_grace_keeps_the_milliseconds_it_was_given() {
        use std::time::Duration;
        // Nothing spent yet: the box's own grace, in full and in milliseconds.
        assert_eq!(remaining_grace_ms(3, Duration::ZERO), 3000);
        // Part spent since the phase-1 signal: the REST of its own grace, to the millisecond. A
        // whole-second truncation here spent up to 999 ms of what the caller asked for.
        assert_eq!(remaining_grace_ms(3, Duration::from_millis(1)), 2999);
        assert_eq!(remaining_grace_ms(3, Duration::from_millis(1500)), 1500);
        // Its own grace is an UPPER bound: once spent, this box is SIGKILLed even if a longer-lived
        // member of the same stack is still inside its own. Measured before this: a service asking
        // 1 s in a stack whose longest ask was 4 s was killed at 5154 ms.
        assert_eq!(remaining_grace_ms(1, Duration::from_millis(4000)), 0);
        assert_eq!(remaining_grace_ms(3, Duration::from_millis(3000)), 0);
        // Configured with no grace at all: straight to the SIGKILL, whatever the clock says.
        assert_eq!(remaining_grace_ms(0, Duration::ZERO), 0);
        assert_eq!(remaining_grace_ms(0, Duration::from_millis(500)), 0);
        // Degenerate inputs saturate instead of wrapping into a short wait or a long one.
        assert_eq!(remaining_grace_ms(u64::MAX, Duration::ZERO), u64::MAX);
        assert_eq!(remaining_grace_ms(3, Duration::MAX), 0);
    }

    /// The mapping from a teardown to the recorded code: only a status we actually READ is reported
    /// as the box's own. Everything else stays 137, the historical "we tore it down" value.
    #[test]
    fn teardown_reports_a_read_status_and_falls_back_to_137() {
        assert_eq!(Teardown::Gone(Some(0)).exit_code(), 0);
        assert_eq!(Teardown::Gone(Some(7)).exit_code(), 7);
        assert_eq!(Teardown::Gone(Some(137)).exit_code(), 137);
        assert_eq!(Teardown::Gone(None).exit_code(), 137);
        assert_eq!(Teardown::Unconfirmed.exit_code(), 137);
        assert!(Teardown::Gone(None).confirmed());
        assert!(!Teardown::Unconfirmed.confirmed());
    }
}

#[cfg(test)]
mod relative_bind_tests {
    use super::*;

    fn one(spec: &str, dir: &std::path::Path) -> Result<String, Error> {
        let mut b = vec![crate::compose::ComposeBox {
            name: "a".into(),
            volumes: vec![spec.to_string()],
            ..Default::default()
        }];
        let f = dir.join("docker-compose.yml");
        resolve_relative_binds(&mut b, &f.to_string_lossy())?;
        Ok(b.remove(0).volumes.remove(0))
    }

    #[test]
    fn bare_dot_is_a_path_not_a_volume_name() {
        // `.:/app` (mount the project root) is the single most common bind there is. The rule "no
        // slash means named volume" sent it to the volume-name validator, which refused `.`.
        let tmp = std::env::temp_dir().join(format!("kern-bind-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let got = one(".:/app", &tmp).expect("`.` resolves");
        let want = std::fs::canonicalize(&tmp).unwrap_or_else(|_| tmp.clone());
        assert_eq!(got, format!("{}:/app", want.to_string_lossy()));
        // Options after the target survive the rewrite.
        assert!(one(".:/app:ro", &tmp).expect("ro").ends_with(":/app:ro"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_real_volume_name_is_still_left_alone() {
        // Only `.`/`..` change meaning: a bare name is still a named volume, untouched.
        let tmp = std::env::temp_dir().join(format!("kern-bind2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        assert_eq!(one("dati:/app", &tmp).expect("named"), "dati:/app");
        assert_eq!(one("/abs:/app", &tmp).expect("abs"), "/abs:/app");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_missing_bind_source_is_created_under_the_project() {
        // Docker creates it, and refusing broke the most ordinary workflow there is: clone a repo
        // whose compose file says `./data:/var/lib/mysql` and `up` failed because `./data` is not in
        // the tree yet.
        let tmp = std::env::temp_dir().join(format!("kern-bind4-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let got = one("./nuovo:/app", &tmp).expect("missing source is created");
        assert!(
            tmp.join("nuovo").is_dir(),
            "the directory now exists: {got}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn an_escaping_source_is_refused_without_creating_anything() {
        // Containment is decided LEXICALLY, before any mkdir: `canonicalize` needs the path to exist,
        // so checking after creating would let the very input we reject leave a directory behind
        // OUTSIDE the project.
        let tmp = std::env::temp_dir().join(format!("kern-bind5-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let outside = tmp.parent().map(|p| p.join("kern-bind5-escape"));
        for spec in ["../kern-bind5-escape:/m", "./a/../../kern-bind5-escape:/m"] {
            assert!(one(spec, &tmp).is_err(), "{spec} must be refused");
        }
        if let Some(o) = &outside {
            assert!(!o.exists(), "nothing may be created outside the project");
        }
        // A `..` that stays INSIDE is still fine.
        assert!(one("a/b/../c:/m", &tmp).is_ok());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn dotdot_still_cannot_escape_the_project_directory() {
        // The traversal guard is a deliberate divergence from Docker and must survive this change.
        let tmp = std::env::temp_dir().join(format!("kern-bind3-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        assert!(
            one("..:/app", &tmp).is_err(),
            "`..` escapes the compose dir"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

#[cfg(test)]
mod compose_action_tests {
    use super::*;

    #[test]
    fn every_documented_verb_parses() {
        // The help text and the parser must not drift: every verb kern advertises has to resolve.
        for (word, want) in [
            ("up", ComposeAction::Up),
            ("down", ComposeAction::Down),
            ("stop", ComposeAction::Stop),
            ("start", ComposeAction::Start),
            ("restart", ComposeAction::Restart),
            ("ps", ComposeAction::Ps),
            ("logs", ComposeAction::Logs),
            ("build", ComposeAction::Build),
            ("pull", ComposeAction::Pull),
            ("config", ComposeAction::Config),
        ] {
            assert_eq!(ComposeAction::from_verb(word), Some(want), "verb {word}");
        }
    }

    #[test]
    fn unknown_verb_is_none_not_a_guess() {
        // A typo must NOT silently resolve to something (the caller turns `None` into a message that
        // lists the real verbs); `stop` must not be reachable from `stopp`.
        for word in ["", "pippo", "stopp", "UP", "Down", "--up", "up "] {
            assert_eq!(ComposeAction::from_verb(word), None, "{word:?}");
        }
    }

    #[test]
    fn only_up_start_and_restart_launch_anything() {
        // The dispatch returns early for every other verb. If a new verb is added and forgotten here,
        // this test states the intended contract rather than letting it silently start a stack.
        for a in [
            ComposeAction::Down,
            ComposeAction::Stop,
            ComposeAction::Ps,
            ComposeAction::Logs,
            ComposeAction::Build,
            ComposeAction::Pull,
            ComposeAction::Config,
        ] {
            assert!(
                !matches!(
                    a,
                    ComposeAction::Up | ComposeAction::Start | ComposeAction::Restart
                ),
                "{a:?} must not be a launching verb"
            );
        }
    }
}

#[cfg(test)]
mod label_filter_tests {
    use super::*;

    fn inst_with(labels: &str) -> registry::Instance {
        registry::Instance {
            name: "b".into(),
            pid: 1,
            pid1: 0,
            rootfs: String::new(),
            command: String::new(),
            started: 0,
            starttime: 0,
            ports: String::new(),
            volumes: String::new(),
            pod: String::new(),
            workdir: String::new(),
            egress: String::new(),
            landlock_rw: String::new(),
            memory_max: None,
            pids_max: None,
            labels: labels.into(),
            stop_signal: 0,
            stop_grace: 0,
            def_hash: String::new(),
            cap_drop_all: false,
            cap_drops: String::new(),
            cap_adds: String::new(),
            seccomp_mode: kern_isolation::SeccompFilter::Denylist,
            apparmor: String::new(),
            cap_recorded: true,
            aa_recorded: true,
            seccomp_recorded: true,
            posture_corrupt: false,
            cgroup: String::new(),
            cgroup_id: None,
            orphaned: false,
        }
    }

    fn f(k: &str, v: &str) -> Vec<(String, String)> {
        vec![(k.to_string(), v.to_string())]
    }

    #[test]
    fn exact_pair_matches() {
        let b = inst_with("app=web,tier=front");
        assert!(ps_matches(&b, &f("label", "app=web")));
        assert!(ps_matches(&b, &f("label", "tier=front")));
        assert!(!ps_matches(&b, &f("label", "app=api")));
    }

    #[test]
    fn bare_key_matches_any_value() {
        let b = inst_with("app=web");
        assert!(ps_matches(&b, &f("label", "app")));
        assert!(!ps_matches(&b, &f("label", "tier")));
    }

    #[test]
    fn bare_key_is_not_a_substring_match() {
        // `app` must NOT match `apple=1`: a prefix is a different key, and a filter that quietly
        // over-matches would select boxes the operator did not mean to touch.
        let b = inst_with("apple=1");
        assert!(!ps_matches(&b, &f("label", "app")));
        assert!(ps_matches(&b, &f("label", "apple")));
    }

    #[test]
    fn no_labels_matches_nothing() {
        let b = inst_with("");
        assert!(!ps_matches(&b, &f("label", "app")));
        assert!(!ps_matches(&b, &f("label", "app=web")));
    }

    #[test]
    fn value_containing_equals_is_matched_whole() {
        // A value may itself contain '=', e.g. a base64 or a query string. The pair is compared as a
        // whole, so this must match exactly and not be split at the second '='.
        let b = inst_with("cfg=a=b");
        assert!(ps_matches(&b, &f("label", "cfg=a=b")));
        assert!(ps_matches(&b, &f("label", "cfg")));
        assert!(!ps_matches(&b, &f("label", "cfg=a")));
    }
}

#[cfg(test)]
mod bring_up_check_tests {
    use super::*;

    #[test]
    fn only_an_awaited_completion_may_have_exited() {
        // The exit sidecar is written ONLY for a service some peer awaits with
        // `service_completed_successfully`, so the presence of a clean exit IS the declared intention:
        // a migration task that finished passes, and a long-running service that exited 0 by mistake
        // (a wrong command that printed help and returned 0, a config that made it terminate cleanly)
        // does NOT, because nobody declared it was allowed to end.
        //
        // A reviewer read the simplified rule as "any exit 0 is legitimate", which would have left
        // exactly that case silent. It does not, and this test pins the distinction so a future
        // simplification cannot quietly widen it.
        let pod = "p";
        let token = "t";
        let awaited = exit_key(pod, token, "migrate");
        registry::set_exit(&awaited, 0);
        assert_eq!(
            registry::exit_of(&awaited),
            Some(0),
            "awaited: clean end recorded"
        );
        // A service nobody awaits has no sidecar at all, which is not `Some(0)` and therefore counts
        // as a death - the check `settle_and_collect_dead` performs.
        assert_eq!(registry::exit_of(&exit_key(pod, token, "web")), None);
        registry::clear_exit(&awaited);
    }
}

#[cfg(test)]
mod drift_tests {
    use super::*;

    fn svc(name: &str) -> crate::compose::ComposeBox {
        crate::compose::ComposeBox {
            name: name.to_string(),
            image: Some("alpine".into()),
            ..Default::default()
        }
    }
    fn inst(hash: &str) -> registry::Instance {
        registry::Instance {
            name: "a".into(),
            pid: 1,
            pid1: 0,
            rootfs: String::new(),
            command: String::new(),
            started: 0,
            starttime: 0,
            ports: String::new(),
            volumes: String::new(),
            pod: String::new(),
            workdir: String::new(),
            egress: String::new(),
            landlock_rw: String::new(),
            memory_max: None,
            pids_max: None,
            labels: String::new(),
            stop_signal: 0,
            stop_grace: 0,
            def_hash: hash.into(),
            cap_drop_all: false,
            cap_drops: String::new(),
            cap_adds: String::new(),
            seccomp_mode: kern_isolation::SeccompFilter::Denylist,
            apparmor: String::new(),
            cap_recorded: true,
            aa_recorded: true,
            seccomp_recorded: true,
            posture_corrupt: false,
            cgroup: String::new(),
            cgroup_id: None,
            orphaned: false,
        }
    }

    #[test]
    fn the_hash_is_stable_and_field_order_independent() {
        // Two readings of the same definition must agree, or `up` would recreate the whole stack on
        // every invocation.
        let a = svc("x");
        assert_eq!(definition_hash(&a), definition_hash(&a));
        // Same content, and the hash is derived from the emitted argv, so it does not depend on how
        // the file happened to be written.
        let b = svc("x");
        assert_eq!(definition_hash(&a), definition_hash(&b));
    }

    #[test]
    fn every_field_that_changes_the_box_changes_the_hash() {
        let base = definition_hash(&svc("x"));
        let mut env = svc("x");
        env.env = vec!["V=1".into()];
        let mut ports = svc("x");
        ports.ports = vec!["1:1".into()];
        let mut img = svc("x");
        img.image = Some("busybox".into());
        let mut cmd = svc("x");
        cmd.command = vec!["echo".into(), "hi".into()];
        let mut mem = svc("x");
        mem.memory = Some("64m".into());
        for (what, h) in [
            ("environment", definition_hash(&env)),
            ("ports", definition_hash(&ports)),
            ("image", definition_hash(&img)),
            ("command", definition_hash(&cmd)),
            ("mem_limit", definition_hash(&mem)),
        ] {
            assert_ne!(h, base, "changing {what} must change the fingerprint");
        }
    }

    #[test]
    fn argv_boundaries_are_hashed_not_just_bytes() {
        // `["ab","c"]` must not hash like `["a","bc"]`: without a separator a concatenation of two
        // different definitions would collide and a real change would be missed.
        let mut a = svc("x");
        a.env = vec!["AB=".into(), "C=".into()];
        let mut b = svc("x");
        b.env = vec!["A=".into(), "BC=".into()];
        assert_ne!(definition_hash(&a), definition_hash(&b));
    }

    #[test]
    fn an_unchanged_service_is_left_alone_and_a_changed_one_is_recreated() {
        let want = definition_hash(&svc("x"));
        assert_eq!(reconcile_decision(&inst(&want), &want), Reconcile::UpToDate);
        assert_eq!(
            reconcile_decision(&inst("deadbeef"), &want),
            Reconcile::Recreate
        );
    }

    #[test]
    fn a_box_without_a_fingerprint_is_not_recreated_forever() {
        // Registered by an older kern, or started outside compose. Treating it as changed would
        // recreate it on EVERY `up`; treating it as current costs at most one missed recreate, after
        // which it carries a fingerprint and behaves normally.
        assert_eq!(
            reconcile_decision(&inst(""), "anything"),
            Reconcile::UpToDate
        );
    }
}

#[cfg(test)]
mod pod_global_tests {
    use super::*;

    fn svc(name: &str) -> crate::compose::ComposeBox {
        crate::compose::ComposeBox {
            name: name.to_string(),
            ..Default::default()
        }
    }
    fn err(boxes: &[crate::compose::ComposeBox]) -> String {
        match check_pod_global_conflicts(boxes, false) {
            Err(Error::Compose(m)) => m,
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    /// `expose:` joins the same space as `port:` and `ports:`. Without it, a real
    /// `docker-compose.yml` using the Compose spelling stayed outside the preflight and collided at
    /// runtime.
    #[test]
    fn expose_shares_the_port_space_with_port_and_ports() {
        // expose against a declared port.
        let mut a = svc("api");
        a.expose = vec![(3000, false)];
        let mut b = svc("admin");
        b.port = Some(3000);
        assert!(err(&[a, b]).contains("3000/tcp"));

        // expose contro una mappatura pubblicata.
        let mut c = svc("api");
        c.expose = vec![(3000, false)];
        let mut d = svc("admin");
        d.ports = vec!["9000:3000".into()];
        assert!(err(&[c, d]).contains("3000/tcp"));

        // expose contro expose.
        let mut e = svc("api");
        e.expose = vec![(3000, false)];
        let mut f = svc("admin");
        f.expose = vec![(3000, false)];
        assert!(err(&[e, f]).contains("3000/tcp"));

        // The protocol matters: udp and tcp on the same number are different sockets.
        let mut g = svc("api");
        g.expose = vec![(53, true)];
        let mut h = svc("dns");
        h.expose = vec![(53, false)];
        assert!(
            check_pod_global_conflicts(&[g, h], false).is_ok(),
            "udp and tcp do not collide"
        );

        // A service declaring the same port in two spellings states one fact twice.
        let mut solo = svc("api");
        solo.port = Some(3000);
        solo.expose = vec![(3000, false)];
        solo.ports = vec!["8080:3000".into()];
        assert!(
            check_pod_global_conflicts(&[solo], false).is_ok(),
            "un servizio non collide con se stesso"
        );

        // Piu' porte esposte: collide solo quella davvero condivisa.
        let mut m = svc("api");
        m.expose = vec![(3000, false), (9090, false)];
        let mut n = svc("metrics");
        n.expose = vec![(9090, false)];
        let msg = err(&[m, n]);
        assert!(msg.contains("9090/tcp") && !msg.contains("3000"), "{msg}");
    }

    /// A DECLARED `port` is what makes an internal-only service visible to this check at all. The
    /// conflict was derived from `ports:` mappings alone, so two services that publish nothing and
    /// talk to each other by name could both claim `:3000`: the preflight saw neither, both boxes
    /// started, one died with EADDRINUSE, and the stack was half up.
    #[test]
    fn a_declared_port_makes_an_unpublished_service_visible_to_the_preflight() {
        let mut a = svc("api");
        a.port = Some(3000);
        let mut b = svc("admin");
        b.port = Some(3000);
        let m = err(&[a, b]);
        assert!(m.contains("container port 3000/tcp"), "{m}");
        assert!(
            m.contains("api") && m.contains("admin"),
            "both services named: {m}"
        );
        // The message must offer the way out the field exists for.
        assert!(m.contains("port:"), "the remedy names the field: {m}");
    }

    /// A declared port and a published mapping are the same claim, so they must collide across
    /// services and must NOT collide with themselves.
    #[test]
    fn declared_and_published_ports_share_one_space_without_self_conflict() {
        // Same service declaring 3000 and publishing 8080:3000 states one fact twice: not a conflict.
        let mut solo = svc("api");
        solo.port = Some(3000);
        solo.ports = vec!["8080:3000".into()];
        assert!(
            check_pod_global_conflicts(&[solo], false).is_ok(),
            "a service must not conflict with itself"
        );

        // One declares, the other publishes the same internal port: a real conflict.
        let mut a = svc("api");
        a.port = Some(3000);
        let mut b = svc("admin");
        b.ports = vec!["3002:3000".into()];
        assert!(err(&[a, b]).contains("3000/tcp"));

        // Different internal ports are exactly the way out, and must pass.
        let mut c = svc("api");
        c.port = Some(3000);
        let mut d = svc("admin");
        d.port = Some(3100);
        assert!(
            check_pod_global_conflicts(&[c, d], false).is_ok(),
            "distinct ports must be allowed"
        );
    }

    /// A declared TCP port must not be confused with a UDP publication of the same number: they are
    /// different sockets and both can bind.
    #[test]
    fn a_declared_port_is_tcp_and_does_not_collide_with_udp() {
        let mut a = svc("api");
        a.port = Some(3000);
        let mut b = svc("metrics");
        b.ports = vec!["3000:3000/udp".into()];
        assert!(
            check_pod_global_conflicts(&[a, b], false).is_ok(),
            "tcp/3000 and udp/3000 are different sockets"
        );
    }

    #[test]
    fn same_container_port_is_a_conflict_even_with_different_host_ports() {
        // The case a reviewer's premise said was rare: two DIFFERENT services on the same INTERNAL
        // port, published on different host ports. Common by default, because every framework has one
        // canonical port. Before this, both boxes started, one died with EADDRINUSE, and `up` exited 0.
        let mut a = svc("api");
        a.ports = vec!["3001:3000".into()];
        let mut b = svc("admin");
        b.ports = vec!["3002:3000".into()];
        let m = err(&[a, b]);
        assert!(m.contains("container port 3000/tcp"), "{m}");
        assert!(m.contains("'api'") && m.contains("'admin'"), "{m}");
        // The message must offer the way out, not just the diagnosis.
        assert!(
            m.contains("--no-pod") || m.contains("different container ports"),
            "{m}"
        );
    }

    #[test]
    fn different_container_ports_are_fine_and_so_is_one_service_alone() {
        let mut a = svc("api");
        a.ports = vec!["3001:3000".into()];
        let mut b = svc("web");
        b.ports = vec!["3002:8080".into()];
        assert!(check_pod_global_conflicts(&[a, b], false).is_ok());
        // A single service publishing the same port twice is a HOST-port problem, caught elsewhere.
        let mut solo = svc("solo");
        solo.ports = vec!["1:3000".into(), "2:3000".into()];
        assert!(check_pod_global_conflicts(&[solo], false).is_ok());
    }

    #[test]
    fn tcp_and_udp_on_the_same_number_do_not_conflict() {
        let mut a = svc("a");
        a.ports = vec!["1:53".into()];
        let mut b = svc("b");
        b.ports = vec!["2:53/udp".into()];
        assert!(check_pod_global_conflicts(&[a, b], false).is_ok());
    }

    #[test]
    fn same_net_sysctl_with_different_values_is_a_conflict() {
        // The knob belongs to the shared namespace: the last service to start would decide, and the
        // file does not say which that is.
        let mut a = svc("a");
        a.sysctls = vec!["net.core.somaxconn=1024".into()];
        let mut b = svc("b");
        b.sysctls = vec!["net.core.somaxconn=2048".into()];
        assert!(err(&[a, b]).contains("different values"));
        // The SAME value from two services is consistent, not a conflict.
        let mut d = svc("d");
        d.sysctls = vec!["net.core.somaxconn=1024".into()];
        let mut e = svc("e");
        e.sysctls = vec!["net.core.somaxconn=1024".into()];
        assert!(check_pod_global_conflicts(&[d, e], false).is_ok());
    }

    #[test]
    fn non_net_sysctls_are_not_pod_global() {
        // `kernel.*`/`fs.*` are not namespaced by the network namespace: two services may differ.
        let mut a = svc("a");
        a.sysctls = vec!["kernel.msgmax=1".into()];
        let mut b = svc("b");
        b.sysctls = vec!["kernel.msgmax=2".into()];
        assert!(check_pod_global_conflicts(&[a, b], false).is_ok());
    }

    #[test]
    fn extra_hosts_shadowing_a_service_name_is_a_conflict() {
        // Both write the pod's shared /etc/hosts, so the winner would be decided by write order, and
        // a service silently resolving elsewhere is the worst kind of wrong.
        let db = svc("db");
        let mut app = svc("app");
        app.add_host = vec!["db:9.9.9.9".into()];
        assert!(err(&[db, app]).contains("same name as a service"));
        // An unrelated host entry is fine.
        let mut ok_app = svc("app");
        ok_app.add_host = vec!["esterno:9.9.9.9".into()];
        assert!(check_pod_global_conflicts(&[svc("db"), ok_app], false).is_ok());
    }

    /// The gate lives INSIDE the function, and this test is why it stays there.
    ///
    /// It used to be restated at every call site, and the sites drifted: `up` applied it, `systemd`
    /// ran with no gate at all, and `config`, the verb that answers "does this file come up?", never
    /// called the check, so it declared healthy a stack that `up` refused. Moving the gate back out,
    /// into one of the three sites, would reopen that divergence.
    #[test]
    fn the_gate_is_inside_so_no_caller_can_restate_it_differently() {
        // `ComposeBox` is not Clone, so the pair is rebuilt for each assertion.
        let pair = || {
            let (mut a, mut b) = (svc("a"), svc("b"));
            a.port = Some(3100);
            b.port = Some(3100);
            [a, b]
        };
        // Positive control: the collision is really there, otherwise the assertions below would be
        // measuring the absence of a conflict rather than the gate.
        assert!(err(&pair()).contains("3100"));
        // `--no-pod`: each service gets its own namespace, so the collision no longer exists.
        assert!(check_pod_global_conflicts(&pair(), true).is_ok());
        // A lone service shares with nobody, whatever the flag says.
        let [solo, _] = pair();
        assert!(check_pod_global_conflicts(&[solo], false).is_ok());
    }
}

#[cfg(test)]
mod port_collision_tests {
    use super::*;

    // A ComposeBox with just a name + published ports - every other field is its Default. Enough to
    // drive `check_port_collisions`, which only reads `.name` and `.ports`.
    fn svc(name: &str, ports: &[&str]) -> crate::compose::ComposeBox {
        crate::compose::ComposeBox {
            name: name.to_string(),
            ports: ports.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    // Assert a collision was reported AND that the message names both offenders (a silent or vague
    // rejection would be a regression - the whole point is a loud, actionable pre-flight error).
    fn assert_collides(boxes: &[crate::compose::ComposeBox], needles: &[&str]) {
        match check_port_collisions(boxes) {
            Err(Error::Compose(msg)) => {
                for n in needles {
                    assert!(msg.contains(n), "message {msg:?} should mention {n:?}");
                }
            }
            other => panic!("expected a compose collision error, got {other:?}"),
        }
    }

    #[test]
    fn distinct_host_ports_are_fine() {
        let boxes = [svc("web", &["8080:80"]), svc("api", &["8081:80"])];
        assert!(check_port_collisions(&boxes).is_ok());
    }

    #[test]
    fn same_host_port_two_services_collides() {
        let boxes = [svc("a", &["9500:80"]), svc("b", &["9500:81"])];
        assert_collides(&boxes, &["'a'", "'b'", "9500/tcp"]);
    }

    #[test]
    fn different_protocol_same_port_is_fine() {
        // tcp/9000 and udp/9000 are independent bindings - NOT a collision.
        //
        // CONTRACT-level, not compose-reachable today: the compose parser strips `/tcp` and drops
        // non-TCP entries before they get here, so a `/udp` spec never reaches this function from a
        // real file (verified e2e - two `/udp` services start with NOTHING published). This covers the
        // function's own contract so the protocol dimension stays correct if kern gains UDP publish.
        let boxes = [svc("a", &["9000:80"]), svc("b", &["9000:80/udp"])];
        assert!(check_port_collisions(&boxes).is_ok());
    }

    #[test]
    fn wildcard_bind_subsumes_specific_ip() {
        // 0.0.0.0:9700 and 127.0.0.1:9700 both want the loopback port - overlap.
        let boxes = [
            svc("x", &["0.0.0.0:9700:80"]),
            svc("y", &["127.0.0.1:9700:81"]),
        ];
        assert_collides(&boxes, &["'x'", "'y'", "9700/tcp"]);
    }

    #[test]
    fn distinct_specific_ips_same_port_are_fine() {
        // Two DIFFERENT concrete addresses can both hold port 9800 - no overlap, no error.
        let boxes = [
            svc("x", &["127.0.0.1:9800:80"]),
            svc("y", &["192.168.1.5:9800:81"]),
        ];
        assert!(check_port_collisions(&boxes).is_ok());
    }

    #[test]
    fn intra_service_duplicate_is_caught() {
        // One service publishing the same host port twice would also fail at bind time - catch it here.
        let boxes = [svc("solo", &["9500:80", "9500:81"])];
        assert_collides(&boxes, &["'solo'", "more than once", "9500/tcp"]);
    }

    #[test]
    fn range_publish_overlap_is_caught() {
        // `8000-8002:8000-8002` expands to host ports 8000,8001,8002; a peer on 8001 collides on the
        // shared port even though the two specs aren't textually equal.
        let boxes = [
            svc("range", &["8000-8002:8000-8002"]),
            svc("peer", &["8001:81"]),
        ];
        assert_collides(&boxes, &["'range'", "'peer'", "8001/tcp"]);
    }

    #[test]
    fn unparseable_spec_is_left_for_the_per_box_path() {
        // A spec `ports::parse` rejects must NOT be treated as a collision here (that would mask the
        // real "invalid port" error the per-box start reports). No panic, no false positive.
        let boxes = [svc("bad", &["not-a-port"]), svc("ok", &["8080:80"])];
        assert!(check_port_collisions(&boxes).is_ok());
    }

    // ---- extreme / adversarial edge cases ----------------------------------------------------

    #[test]
    fn nothing_to_check_is_ok() {
        // No services at all, and services with an empty `ports:` list. Must not panic or false-positive.
        assert!(check_port_collisions(&[]).is_ok());
        let boxes = [svc("quiet", &[]), svc("also_quiet", &[])];
        assert!(check_port_collisions(&boxes).is_ok());
    }

    #[test]
    fn partially_overlapping_ranges_collide_on_the_shared_port() {
        // 8000-8005 and 8003-8008 share 8003..8005. The specs are textually different and neither is a
        // subset of the other - only real expansion catches this.
        let boxes = [
            svc("lo", &["8000-8005:8000-8005"]),
            svc("hi", &["8003-8008:8003-8008"]),
        ];
        assert_collides(&boxes, &["'lo'", "'hi'"]);
    }

    #[test]
    fn adjacent_ranges_do_not_collide() {
        // Off-by-one boundary in the OTHER direction: 8000-8004 then 8005-8009 touch but never overlap.
        let boxes = [
            svc("lo", &["8000-8004:8000-8004"]),
            svc("hi", &["8005-8009:8005-8009"]),
        ];
        assert!(check_port_collisions(&boxes).is_ok());
    }

    #[test]
    fn max_range_boundary() {
        // `ports::parse` caps a single spec at MAX_RANGE (1024). At the cap the spec expands and a peer
        // inside it collides; one PAST the cap is rejected by the parser, so we must stay silent and let
        // the per-box path report it - NOT invent a collision from a spec that will never bind.
        let at_cap = [svc("big", &["1-1024:1-1024"]), svc("peer", &["512:80"])];
        assert_collides(&at_cap, &["'big'", "'peer'", "512/tcp"]);
        let past_cap = [svc("huge", &["1-1025:1-1025"]), svc("peer", &["512:80"])];
        assert!(check_port_collisions(&past_cap).is_ok());
    }

    #[test]
    fn port_number_boundaries() {
        // The extremes of the valid range (1 and 65535) are ordinary ports to the checker.
        assert_collides(
            &[svc("a", &["1:1"]), svc("b", &["1:2"])],
            &["1/tcp", "'a'", "'b'"],
        );
        assert_collides(
            &[svc("a", &["65535:1"]), svc("b", &["65535:2"])],
            &["65535/tcp", "'a'", "'b'"],
        );
        // Adjacent extremes don't collide.
        assert!(check_port_collisions(&[svc("a", &["65534:1"]), svc("b", &["65535:1"])]).is_ok());
    }

    #[test]
    fn explicit_tcp_equals_default_tcp() {
        // `8080:80` and `8080:80/tcp` are the SAME protocol - a spelling difference must not hide the clash.
        let boxes = [svc("a", &["8080:80"]), svc("b", &["8080:81/tcp"])];
        assert_collides(&boxes, &["8080/tcp", "'a'", "'b'"]);
    }

    #[test]
    fn protocol_suffix_is_case_insensitive() {
        // `ports::parse` accepts `/UDP`; two udp mappings spelled differently still collide, and a
        // `/UDP` mapping still does NOT collide with tcp on the same port. CONTRACT-level like
        // `different_protocol_same_port_is_fine` - compose strips the proto before this point.
        assert_collides(
            &[svc("a", &["9000:80/udp"]), svc("b", &["9000:81/UDP"])],
            &["9000/udp"],
        );
        assert!(
            check_port_collisions(&[svc("a", &["9000:80/UDP"]), svc("b", &["9000:81"])]).is_ok()
        );
    }

    #[test]
    fn wildcard_twice_collides() {
        // Two services BOTH on 0.0.0.0 for the same port - the wildcard-vs-wildcard branch.
        let boxes = [
            svc("a", &["0.0.0.0:9100:80"]),
            svc("b", &["0.0.0.0:9100:81"]),
        ];
        assert_collides(&boxes, &["9100/tcp", "'a'", "'b'"]);
    }

    #[test]
    fn wildcard_arriving_second_still_collides() {
        // Order matters to the implementation (the wildcard may be inserted before OR after the specific
        // address), so cover both directions: specific-then-wildcard, and wildcard-then-specific.
        assert_collides(
            &[
                svc("spec", &["127.0.0.1:9200:80"]),
                svc("wild", &["0.0.0.0:9200:81"]),
            ],
            &["9200/tcp", "'spec'", "'wild'"],
        );
        assert_collides(
            &[
                svc("wild", &["0.0.0.0:9300:80"]),
                svc("spec", &["127.0.0.1:9300:81"]),
            ],
            &["9300/tcp", "'wild'", "'spec'"],
        );
    }

    #[test]
    fn wildcard_collides_with_a_far_away_specific_address() {
        // 0.0.0.0 subsumes EVERY address, not just loopback: a LAN-bound peer conflicts too.
        let boxes = [
            svc("lan", &["192.168.1.5:9400:80"]),
            svc("wild", &["0.0.0.0:9400:81"]),
        ];
        assert_collides(&boxes, &["'lan'", "'wild'"]);
    }

    #[test]
    fn default_bind_is_loopback_so_bare_and_explicit_loopback_collide() {
        // A bare `9500:80` defaults to 127.0.0.1 (kern is loopback-default). It MUST clash with an
        // explicit `127.0.0.1:9500:81` - otherwise the checker would disagree with the real bind.
        let boxes = [
            svc("bare", &["9500:80"]),
            svc("explicit", &["127.0.0.1:9500:81"]),
        ];
        assert_collides(&boxes, &["'bare'", "'explicit'", "9500/tcp"]);
    }

    #[test]
    fn intra_service_wildcard_duplicate_names_the_service_once() {
        // Same service, same wildcard port twice: the message must say "more than once" (not name the
        // service twice as if there were two culprits).
        let boxes = [svc("solo", &["0.0.0.0:9600:80", "0.0.0.0:9600:81"])];
        match check_port_collisions(&boxes) {
            Err(Error::Compose(m)) => {
                assert!(m.contains("more than once"), "got {m:?}");
                assert!(
                    !m.contains("and 'solo'"),
                    "should not read as two services: {m:?}"
                );
            }
            other => panic!("expected a collision, got {other:?}"),
        }
    }

    #[test]
    fn many_services_no_collision_is_linear_not_quadratic() {
        // REGRESSION GUARD. A single `-p` may expand to 1024 ports, so a legal stack of ranges reaches
        // tens of thousands of mappings. The pairwise version of this check measured 10.5 s on exactly
        // this shape (40 services) before any box started; bucketing makes it milliseconds. Distinct
        // bind IPs mean there is NO collision, so the scan cannot exit early - the worst case.
        let boxes: Vec<_> = (0..40)
            .map(|i| {
                svc(
                    &format!("s{i}"),
                    &[&format!("10.0.{}.{}:1-1024:1-1024", i / 256, i % 256)],
                )
            })
            .collect();
        let t0 = std::time::Instant::now();
        assert!(
            check_port_collisions(&boxes).is_ok(),
            "distinct IPs never collide"
        );
        let dt = t0.elapsed();
        // Generous ceiling (the quadratic form took ~10.5 s here, ~260x this bound) so the test is a
        // real signal on slow CI rather than a flake.
        assert!(
            dt < std::time::Duration::from_secs(2),
            "41k-mapping check should be milliseconds, took {dt:?} - did the pairwise scan come back?"
        );
    }

    #[test]
    fn collision_is_reported_deterministically() {
        // HashMap iteration order is randomized per process, but the SCAN walks services and specs in
        // file order, so the reported pair must be stable - a flaky error message would be a UX bug and
        // would make the e2e tests non-reproducible. Same input, same message, every time.
        let boxes = [
            svc("first", &["7000:80"]),
            svc("second", &["7000:81"]),
            svc("third", &["7000:82"]),
        ];
        let msg = match check_port_collisions(&boxes) {
            Err(Error::Compose(m)) => m,
            other => panic!("expected a collision, got {other:?}"),
        };
        for _ in 0..64 {
            match check_port_collisions(&boxes) {
                Err(Error::Compose(m)) => assert_eq!(m, msg, "message must be stable"),
                other => panic!("expected a collision, got {other:?}"),
            }
        }
        // And it names the FIRST conflicting pair in file order, not an arbitrary one.
        assert!(
            msg.contains("'first'") && msg.contains("'second'") && !msg.contains("'third'"),
            "should report the earliest pair: {msg:?}"
        );
    }

    #[test]
    fn every_spec_of_a_service_is_checked_not_just_the_first() {
        // A service's LAST port must be checked too (an early-exit bug would pass the first spec only).
        let boxes = [
            svc("multi", &["7100:80", "7101:81", "7102:82"]),
            svc("late", &["7102:83"]),
        ];
        assert_collides(&boxes, &["'multi'", "'late'", "7102/tcp"]);
    }

    #[test]
    fn a_malformed_spec_does_not_stop_the_scan() {
        // The `continue` on an unparseable spec must skip only THAT spec: a real collision after it is
        // still caught (a `return` there would silently disable the whole check).
        let boxes = [
            svc("a", &["bogus:spec:here:too", "7200:80"]),
            svc("b", &["7200:81"]),
        ];
        assert_collides(&boxes, &["'a'", "'b'", "7200/tcp"]);
    }
}

/// `kern stop --all` used to delete EVERY `kern-*.service` in the user's unit directory, because it
/// identified its own persistent boxes by file name. A unit the user wrote by hand was removed by an
/// unrelated `stop --all` - including the one `kern compose … systemd` tells them to write, which is
/// named exactly that way. Ownership is now read from the file, and these tests pin both marks.
#[cfg(test)]
mod managed_unit_ownership {
    use super::*;

    fn write(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).expect("test fixture");
        p
    }

    #[test]
    fn the_managed_systemd_unit_disables_systemds_start_rate_limit() {
        // REGRESSION: a persistent box's generated unit sets `Restart=always` + `RestartSec=1`. It MUST
        // also set `StartLimitIntervalSec=0`, or systemd's default (`StartLimitBurst=5` in 10s) leaves
        // the unit `failed` after a fast crash-loop - which with `RestartSec=1` happens in ~5s - and
        // `--restart always` then SILENTLY stops restarting, breaking the "restart on any exit,
        // indefinitely" contract and the up-for-days reliability this path exists for. Asserted on the
        // source because the unit is written to a FILE (a side effect), not returned, so there is no
        // value to assert without a `systemd` on the runner. Needle built via `concat!` so this test's
        // own text is not what it counts.
        let src = include_str!("mod.rs");
        let needle = concat!("StartLimitIntervalSec", "=0\\n\\n");
        assert!(
            src.contains(needle),
            "the managed systemd unit must carry StartLimitIntervalSec=0 before the [Service] section"
        );
    }

    #[test]
    fn persistent_supervision_falls_back_to_in_process_without_systemd() {
        use super::persistent_supervision;
        // (detached, persistent, has_pod, systemd_present) -> (use_systemd_unit, in_process_restart_always)
        // Standalone persistent + a systemd --user manager: systemd supervises (reboot-survival).
        assert_eq!(
            persistent_supervision(true, true, false, true),
            (true, false)
        );
        // Standalone persistent + NO systemd: THE FIX - fall back to the in-process supervisor so the box
        // still runs and restarts on any exit. Before this it errored on the unit install and never ran.
        assert_eq!(
            persistent_supervision(true, true, false, false),
            (false, true)
        );
        // A pod member is ALWAYS in-process, regardless of systemd (it needs the holder's namespace).
        assert_eq!(
            persistent_supervision(true, true, true, true),
            (false, true)
        );
        assert_eq!(
            persistent_supervision(true, true, true, false),
            (false, true)
        );
        // Not persistent (`on-failure`/`no`): neither always-path (on-failure is its own capped loop).
        assert_eq!(
            persistent_supervision(true, false, false, false),
            (false, false)
        );
        // Foreground persistent (rejected upstream): no systemd unit, no in-process always here either.
        assert_eq!(
            persistent_supervision(false, true, false, true),
            (false, false)
        );
    }

    #[test]
    fn only_units_kern_wrote_are_claimed() {
        let dir = std::env::temp_dir().join(format!("kern-unit-own-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("test fixture");

        // Written by kern today: carries the explicit marker.
        let marked = write(
            &dir,
            "kern-api.service",
            "[Unit]\nDescription=kern box api\nX-KernManagedBox=api\n[Service]\nExecStart=/bin/true\n",
        );
        assert!(is_kern_managed_unit(&marked));

        // Written by an OLDER kern: no marker, but the description kern has always used. It must stay
        // claimable, or upgrading would strand every already-installed persistent box.
        let legacy = write(
            &dir,
            "kern-old.service",
            "[Unit]\nDescription=kern box old\n[Service]\nExecStart=/bin/true\n",
        );
        assert!(is_kern_managed_unit(&legacy));

        // The unit `kern compose … systemd` emits: same NAME shape, not kern's to delete.
        let stack = write(
            &dir,
            "kern-web.service",
            "[Unit]\nDescription=kern compose stack web\n[Service]\nExecStart=/usr/bin/kern compose /srv/x.yml up\n",
        );
        assert!(
            !is_kern_managed_unit(&stack),
            "a stack unit is the user's file"
        );

        // Someone else's unit that happens to start with `kern-`.
        let stranger = write(
            &dir,
            "kern-backup.service",
            "[Unit]\nDescription=nightly backup\n[Service]\nExecStart=/usr/local/bin/backup\n",
        );
        assert!(!is_kern_managed_unit(&stranger));

        // Unreadable or absent: not ours. Never delete what cannot be verified.
        assert!(!is_kern_managed_unit(&dir.join("does-not-exist.service")));

        // Binary rubbish under a kern-ish name: not ours, and no panic.
        let binary = dir.join("kern-bin.service");
        std::fs::write(&binary, [0xff_u8, 0xfe, 0x00, 0x01]).expect("test fixture");
        assert!(!is_kern_managed_unit(&binary));

        // A marker buried in a huge file is still found up to the read cap, and beyond it the answer
        // is the safe one rather than a long read.
        let big = dir.join("kern-big.service");
        let mut body = String::from("[Unit]\nX-KernManagedBox=big\n");
        body.push_str(&"# padding\n".repeat(200));
        std::fs::write(&big, &body).expect("test fixture");
        assert!(is_kern_managed_unit(&big));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A verb the parser accepts but that neither the help nor the usage message names is a verb that
/// does not exist for the reader. `systemd` was exactly that, because the list was written by hand
/// in three places. There is one list now, and these tests anchor it from both sides.
#[cfg(test)]
mod compose_verbs_are_one_list {
    use super::*;

    #[test]
    fn every_listed_verb_parses_and_every_parsed_verb_is_listed() {
        let help = compose_verbs_help();
        for (name, action) in COMPOSE_VERBS {
            assert_eq!(
                ComposeAction::from_verb(name),
                Some(*action),
                "'{name}' e' in elenco ma il parser non lo accetta"
            );
            assert!(
                help.split('|').any(|v| v == *name),
                "'{name}' is accepted but does not appear in the help text: {help}"
            );
        }
        // The text must not announce anything the parser refuses.
        for v in help.split('|') {
            assert!(
                ComposeAction::from_verb(v).is_some(),
                "the help text announces '{v}', which the parser does not accept"
            );
        }
        // No duplicates: two entries with the same name would make the second unreachable.
        let mut names: Vec<&str> = COMPOSE_VERBS.iter().map(|(n, _)| *n).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            total,
            "un verbo compare due volte in COMPOSE_VERBS"
        );
    }

    #[test]
    fn an_unknown_verb_is_refused_rather_than_guessed() {
        for bad in ["", "UP", "upp", "systemctl", "--up", "up "] {
            assert!(
                ComposeAction::from_verb(bad).is_none(),
                "'{bad}' non deve essere interpretato come un verbo"
            );
        }
    }
}

/// The graceful stop waited out the whole grace period even when the box's init could not receive
/// the signal: a namespace PID 1 discards signals it has no handler for, so a `sleep` never dies of
/// SIGTERM. `kern stop` took 9013 ms instead of 2, and a `compose down` of four services would have
/// been 36 seconds.
#[cfg(test)]
mod stop_does_not_wait_for_the_impossible {
    use super::*;

    #[test]
    fn a_signal_the_init_cannot_catch_is_not_waited_for() {
        // This test process has a real SigCgt mask: whatever it holds, the function must read it
        // without panicking and answer consistently with /proc.
        let me = std::process::id() as i32;
        let status = std::fs::read_to_string(format!("/proc/{me}/status")).unwrap_or_default();
        let mask = status
            .lines()
            .find_map(|l| l.strip_prefix("SigCgt:"))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
            .unwrap_or(0);
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGUSR1] {
            let expected = mask & (1u64 << (sig - 1)) != 0;
            assert_eq!(
                init_catches_signal(me, sig),
                expected,
                "the verdict for signal {sig} must match SigCgt in /proc"
            );
        }
    }

    #[test]
    fn an_unknown_process_stays_on_the_patient_path() {
        // Not knowing must mean WAIT, not kill early: erring that way costs a wait, erring the
        // other way would cut a real shutdown in half.
        assert!(init_catches_signal(0, libc::SIGTERM), "invalid pid");
        assert!(init_catches_signal(-1, libc::SIGTERM), "negative pid");
        assert!(
            init_catches_signal(i32::MAX, libc::SIGTERM),
            "pid that does not exist: /proc unreadable, so we wait"
        );
        // A signal number out of range must not shift the bit past the mask.
        let me = std::process::id() as i32;
        assert!(init_catches_signal(me, 0));
        assert!(init_catches_signal(me, 65));
        assert!(init_catches_signal(me, -5));
    }
}

#[cfg(test)]
mod uninstall_only_removes_what_kern_installed {
    use super::*;

    #[test]
    fn only_the_file_an_installer_placed_is_this_verbs_to_delete() {
        // Identity, not path text: these need to be REAL files, which is the point. The previous version
        // of this test passed paths that did not exist and passed against string comparison, which is
        // exactly what let a symlinked install go unremoved.
        let base = std::env::temp_dir().join(format!("kern-inst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        std::fs::create_dir_all(home.join(".local/bin")).unwrap();
        std::fs::create_dir_all(base.join("pkg")).unwrap();
        std::fs::create_dir_all(base.join("src/target/release")).unwrap();

        // 1. What an installer produces: a real binary at the install path.
        let installed = home.join(".local/bin/kern");
        std::fs::write(&installed, b"#!/bin/sh\n").unwrap();
        assert!(
            is_installed_binary(&installed, &home),
            "a binary at the install path must be removable"
        );

        // 2. A PACKAGED install: the install path is a symlink into a library directory, and
        // `current_exe()` hands us the resolved target. String comparison answered false here and
        // refused to remove a legitimate install; identity answers true.
        let real = base.join("pkg/kern");
        std::fs::write(&real, b"#!/bin/sh\n").unwrap();
        std::fs::remove_file(&installed).unwrap();
        std::os::unix::fs::symlink(&real, &installed).unwrap();
        assert!(
            is_installed_binary(&real, &home),
            "a symlinked install must still be recognised through its target"
        );

        // 3. What nobody asked us to touch: a build in a source tree, and a copy somebody placed by hand.
        let build = base.join("src/target/release/kern");
        std::fs::write(&build, b"#!/bin/sh\n").unwrap();
        assert!(
            !is_installed_binary(&build, &home),
            "a source-tree build must survive uninstall run from that tree"
        );
        let opt = base.join("pkg/kern-copy");
        std::fs::write(&opt, b"#!/bin/sh\n").unwrap();
        assert!(
            !is_installed_binary(&opt, &home),
            "a hand-placed copy is not an installation"
        );

        // 4. Another user's home is not this home.
        let other = base.join("other-home");
        std::fs::create_dir_all(other.join(".local/bin")).unwrap();
        let theirs = other.join(".local/bin/kern");
        std::fs::write(&theirs, b"#!/bin/sh\n").unwrap();
        assert!(
            !is_installed_binary(&theirs, &home),
            "another user's install is not ours to delete"
        );

        // 5. A path that does not exist cannot be identified, so it is not removable.
        assert!(!is_installed_binary(&base.join("gone"), &home));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_hardlinked_blob_is_counted_once_and_a_symlink_is_never_followed_out_of_the_tree() {
        let base = std::env::temp_dir().join(format!("kern-uninst-sz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("sub")).unwrap();
        std::fs::write(base.join("blob"), vec![0u8; 65536]).unwrap();
        let one = dir_bytes(&base);
        assert!(
            one >= 65536,
            "a 64 KiB file must account for at least its bytes, got {one}"
        );

        // The layer store hardlinks a blob shared between two images. Removing the tree frees those
        // blocks ONCE, so counting them twice would overstate what the user gets back - which is
        // exactly what this reported on a real cache before the fix (5.22 GiB claimed, 3.38 freed).
        std::fs::hard_link(base.join("blob"), base.join("sub/same-blob")).unwrap();
        assert_eq!(
            dir_bytes(&base),
            one,
            "a second link to the same inode must add nothing"
        );

        // A symlink pointing anywhere contributes 0: removal does not follow it either.
        std::os::unix::fs::symlink("/usr", base.join("link")).unwrap();
        assert_eq!(dir_bytes(&base), one, "a symlink must not be counted");

        // An unreadable or absent subtree contributes 0 rather than aborting the whole plan.
        assert_eq!(dir_bytes(&base.join("does-not-exist")), 0);
        let _ = std::fs::remove_dir_all(&base);
    }
}

#[cfg(test)]
mod config_verbs_are_defined_in_one_place {
    use super::*;

    #[test]
    fn a_verb_the_dispatch_does_not_know_is_an_error_not_a_silent_listing() {
        // The parser refuses an unknown verb first, so this is defence in depth against the two lists
        // drifting: a verb added there without a case here must fail loudly, because listing the
        // profiles and exiting 0 is indistinguishable from success.
        for stranger in ["show", "inspect", "ls", "", "LIST"] {
            let e = config_cmd(stranger, false, false);
            assert!(
                matches!(e, Err(Error::Usage(u)) if u == CONFIG_USAGE),
                "config_cmd({stranger:?}) must be a usage error, got {e:?}"
            );
        }
    }

    #[test]
    fn the_usage_string_names_every_verb_the_parser_accepts() {
        // The one place the verb set is written must actually list what works, or the error message
        // sends the reader to a verb that does not exist (or hides one that does).
        for verb in ["list", "add", "rm", "edit", "setup", "probe", "clear"] {
            assert!(
                CONFIG_USAGE.contains(verb),
                "the usage string does not mention `{verb}`: {CONFIG_USAGE}"
            );
        }
    }
}

/// `--plan` must preview every kind of profile a box can carry, not the one that was implemented
/// first.
///
/// It reported `vgpio:` device grants and nothing else, so a box attached to a CPU cap, a device and
/// a scratch disk previewed one of the three. The comment justifying the vgpio case said it exactly:
/// a preview that lists three mounts while saying nothing about `/dev/i2c-5` is not a preview of what
/// will be created. A 256M ceiling and a 48M disk are no different.
///
/// Asserted on the FUNCTION BODY rather than on behaviour because the output goes to stdout and the
/// resolvers need a config file on disk; the shape is what regresses when a fourth kind is added or
/// a third is dropped. Scoped to the body so this test's own text cannot satisfy it.
#[cfg(test)]
mod the_plan_previews_every_profile_kind {
    #[test]
    fn all_three_kinds_are_picked_and_resolved() {
        let src = include_str!("mod.rs");
        let Some(start) = src.find("pub fn box_plan") else {
            panic!("box_plan is gone; this contract test cannot find what it guards");
        };
        let body = &src[start..];
        let Some(end) = body.find("\n}\n") else {
            panic!("cannot find the end of box_plan");
        };
        let body = &body[..end];

        for kind in ["vcpu:", "vgpio:", "vdisk:"] {
            assert!(
                body.contains(&format!("pick(\"{kind}\")")),
                "box_plan no longer picks {kind} profiles out of the attached list, so a box \
                 carrying one previews without it"
            );
        }
        for resolver in ["resolve_vcpu", "resolve_vgpio", "resolve_vdisk"] {
            assert!(
                body.contains(resolver),
                "box_plan no longer calls {resolver}, so that kind is either unreported or \
                 reported from the raw config instead of the resolved values the launch uses"
            );
        }
        // Each kind must also report a failure to attach HERE rather than at launch, which is the
        // whole reason the plan resolves instead of printing the profile names back.
        // The FORMAT string, not the phrase: the doc comment above the function also contains
        // "cannot attach", and counting that made the first version of this assertion read 4.
        assert_eq!(
            body.matches("cannot attach: {e}").count(),
            3,
            "every kind must say why it cannot attach at PLAN time rather than at launch; found a \
             different number of Err arms that print it"
        );
    }
}
