//! Subcommand implementations. One responsibility per function; the roadmap promotes each
//! `Pending` verb (box/run/pull/compose) to its own module here.

use crate::cli::GlobalOpts;
use crate::error::Error;
use crate::registry;
use crate::sandbox::SandboxCtx;
use kern_common::BoxName;
use kern_isolation::{
    exec_in_box, run_in_sandbox, run_in_sandbox_with, MountMode, OverlayDirs, SandboxSpec, Volume,
};
use std::path::PathBuf;

pub fn version() -> Result<(), Error> {
    println!("kern {}", kern_common::VERSION);
    Ok(())
}

pub fn help() -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    let (b, c, d, z) = (p.b, p.c, p.d, p.z);
    println!("{}", crate::ui::logo(&p));
    println!(
        "\
  {b}kern {ver}{z} {d}— a fast, lightweight sandbox & virtual resource manager{z}

{b}USAGE:{z}
    kern [--no-gpu] <COMMAND> [ARGS]

{b}COMMANDS:{z}
    {c}box{z} <name> (--rootfs <dir>|--image <ref>) [opts] [-- CMD...]   Run CMD in a sandbox
    {c}box{z} <name> --plan                                              Preview the isolation sequence
    {c}exec{z} <name> [--env K=V] [-w <dir>] [-- CMD...]                 Run CMD in a running box
    {c}search{z} <query> [--json]                                        Search Docker Hub for images
    {c}pull{z} <image> [--dest <dir>]                                    Download an OCI image
    {c}images{z} [--json]                                                List pulled (cached) images
    {c}compose{z} <file>                                                 Bring up a stack (TOML)
    {c}ps{z} [--json]                                                    List running boxes
    {c}top{z}                                                            Interactive task manager (TUI)
    {c}stats{z} [--json]                                                 Per-box memory + CPU
    {c}logs{z} <name>                                                    Show a box's output
    {c}stop{z} <name>                                                    Stop running box(es)
    {c}run{z}        Run with resource limits               {d}(roadmap){z}

{b}OPTIONS for box:{z}
    --rootfs <dir>      Root filesystem to enter
    --image <ref>       OCI image to pull and run (e.g. alpine, alpine:3.19)
    -d, --detach        Run in the background (track with `kern ps`)
    --read-only         Read-only root (default is a writable overlay)
    -v, --volume S:D[:ro]   Bind-mount a host path into the box (repeatable)
    -e, --env K=V       Set an environment variable (repeatable)
    -w, --workdir <dir> Working directory inside the box
    --net               Share the host network (outbound; no network isolation)
    --uid-range         Map a sub-uid/gid range (needed for apt/dpkg, www-data); default maps
                        only the caller (faster + more isolated)
    --bind-rootfs       Bind --rootfs directly instead of an overlay — faster on kernels with a
                        slow overlayfs, but the source is mutable & shared (no per-box isolation)
    --plan              Preview the isolation sequence instead of running

{b}OPTIONS:{z}
    --no-gpu       Never load any GPU driver interposer (off by default)
    -V, --version  Print version
    -h, --help     Print this help

{d}The CLI/config surface is NOT frozen until 1.0.
See {z}{c}https://github.com/getkern/kern{z}",
        ver = kern_common::VERSION
    );
    Ok(())
}

/// `kern box <name> --plan` — show the ordered mount/pivot/remount sequence the sandbox setup
/// would perform. Privilege-free: it records the sequence via the isolation seam rather than
/// executing it, so it works anywhere and exercises the 0.2 step-sequence + mount-ordering
/// typestate end to end.
pub fn box_plan(name: &str) -> Result<(), Error> {
    let name = BoxName::parse(name).map_err(Error::InvalidBox)?;
    let ctx = SandboxCtx::new(name);
    println!("isolation plan for box '{}':", ctx.name.as_str());
    for (i, step) in ctx.plan().iter().enumerate() {
        println!("  {}. {step}", i + 1);
    }
    Ok(())
}

/// Arguments for [`box_run`]. A struct (not a long parameter list) keeps the call site readable
/// as box options grow (`-v`, `--env`, `--workdir`, `--net`).
pub struct BoxRunArgs<'a> {
    pub name: &'a str,
    pub rootfs: Option<&'a str>,
    pub image: Option<&'a str>,
    pub command: &'a [String],
    pub detached: bool,
    pub read_only: bool,
    pub volumes: &'a [String],
    pub env: &'a [String],
    pub workdir: Option<&'a str>,
    pub share_net: bool,
    pub uid_range: bool,
    pub bind_rootfs: bool,
}

/// `kern box <name> (--rootfs <dir> | --image <ref>) [-d] [-v ...] [--env ...] [-- cmd...]` — run
/// a command in a real sandbox: a fresh user + PID + (net) + UTS + IPC + mount namespace, the
/// rootfs pivoted in, seccomp-filtered, cgroup-capped. `--image` pulls an OCI image (cached).
/// Defaults to `/bin/sh`. Foreground propagates the exit code; `-d` detaches (track via `kern ps`).
pub fn box_run(args: BoxRunArgs) -> Result<(), Error> {
    let name = BoxName::parse(args.name).map_err(Error::InvalidBox)?;
    let cmd = default_if_empty(args.command);
    let volumes = parse_volumes(args.volumes)?;
    let env = parse_envs(args.env)?;
    // Robust resource caps: re-exec this whole invocation inside a transient systemd user scope
    // with memory + task limits (proper cgroup delegation). No-op if already scoped or if
    // systemd --user isn't available — then the best-effort cgroup in run_in_sandbox applies.
    reexec_in_scope_if_possible();

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
                "--bind-rootfs is writable-only — a read-only bind remount is denied on the \
                 kernels where it helps; drop --bind-rootfs to get a read-only overlay root"
                    .to_string(),
            ));
        }
    }

    // The lower/base rootfs: an explicit --rootfs, or pull --image into a local cache.
    let lower = match (args.rootfs, args.image) {
        (Some(r), _) => r.to_string(),
        (None, Some(img)) => pull_to_cache(img)?,
        (None, None) => return Err(Error::Sandbox("need --rootfs or --image".to_string())),
    };

    // Always an overlay (image/rootfs = read-only lower, private upper takes writes).
    // `--read-only` then remounts that overlay read-only after pivot.
    let (spec, scratch) = build_spec(BuildSpec {
        name: &name,
        lower,
        cmd,
        read_only: args.read_only,
        volumes,
        env,
        workdir: args.workdir.map(str::to_string),
        share_net: args.share_net,
        uid_range: args.uid_range,
        bind_rootfs: args.bind_rootfs,
    })?;

    if args.detached {
        return run_detached(&name, spec, scratch);
    }
    let result = run_in_sandbox(&spec);
    cleanup_scratch(scratch.as_deref());
    match result {
        // Propagate the sandboxed command's exit code as kern's, like `docker run`. This is the
        // one place a non-0/1 exit code is produced — a deliberate terminal action.
        Ok(code) => std::process::exit(code),
        Err(e) => Err(Error::Sandbox(e.to_string())),
    }
}

/// Parsed inputs for [`build_spec`].
struct BuildSpec<'a> {
    name: &'a BoxName,
    lower: String,
    cmd: Vec<String>,
    read_only: bool,
    volumes: Vec<Volume>,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    share_net: bool,
    uid_range: bool,
    bind_rootfs: bool,
}

/// Build the sandbox spec. **Always an overlay** (the image/rootfs is the read-only lower; a
/// private upper takes writes) over a scratch tree under the runtime dir, removed after the box
/// exits. `--read-only` then remounts that overlay read-only.
///
/// Why overlay even for `--read-only` (rather than a plain bind + remount-ro): on some kernels a
/// **bind** mount cannot be remounted read-only inside a user namespace (e.g. Android-kernel
/// boards return EPERM — the bind inherits a lock from a host mount the child userns doesn't own),
/// whereas an **overlay** has its own superblock created in the namespace and *can* be remounted
/// read-only. Using overlay for both modes makes `--read-only` work everywhere and keeps the
/// image immutable (writes, when allowed, only ever hit the discarded upper).
///
/// When `--net` shares the host network, the host's `/etc/resolv.conf` is copied into the upper
/// so DNS works out of the box.
fn build_spec(b: BuildSpec) -> Result<(SandboxSpec, Option<PathBuf>), Error> {
    let hostname = b.name.as_str().to_string();

    // `--bind-rootfs`: skip the overlay and bind the rootfs directly. On kernels with a slow
    // overlayfs mount (some Android-kernel boards: ~31 ms for an overlay vs ~8 ms for a bind) this
    // is the difference between winning and losing on raw start. The trade-off — accepted by the
    // explicit flag — is that the source is mutable and shared: writes land in the rootfs dir and
    // boxes sharing one rootfs are not isolated from each other. There is no overlay scratch.
    //
    // Unlike the overlay path, we deliberately do NOT inject `/etc/resolv.conf` here even with
    // `--net`: that would be a host-side, privileged write into the user-supplied rootfs, and a
    // symlink there (e.g. `/etc/resolv.conf -> ../../host/file`) would make it clobber a file
    // *outside* the rootfs. A bind-mode box uses whatever `/etc/resolv.conf` its rootfs already
    // ships (`--net` still gives outbound networking; add a resolv.conf to the rootfs if needed).
    if b.bind_rootfs {
        let spec = SandboxSpec {
            root: b.lower,
            mode: MountMode::Bind,
            overlay: None,
            read_only: b.read_only,
            command: b.cmd,
            hostname,
            volumes: b.volumes,
            env: b.env,
            workdir: b.workdir,
            share_net: b.share_net,
            uid_range: b.uid_range,
        };
        return Ok((spec, None));
    }

    let scratch = scratch_dir().join(format!("{}-{}", b.name.as_str(), std::process::id()));
    own_only_dir(&scratch).map_err(|e| Error::Sandbox(format!("scratch dir: {e}")))?;
    let (upper, work, merged) = (
        scratch.join("upper"),
        scratch.join("work"),
        scratch.join("merged"),
    );
    for d in [&upper, &work, &merged] {
        std::fs::create_dir_all(d).map_err(|e| Error::Sandbox(format!("scratch dir: {e}")))?;
    }
    // With `--net` sharing the host network, copy the host's resolv.conf into the upper so DNS
    // resolves inside the box. A private copy → the box can't touch the host's file, and it's
    // removed with the scratch. (Best-effort: no host resolv.conf → IPs still work.)
    if b.share_net {
        if let Ok(conf) = std::fs::read("/etc/resolv.conf") {
            let etc = upper.join("etc");
            if std::fs::create_dir_all(&etc).is_ok() {
                let _ = std::fs::write(etc.join("resolv.conf"), conf);
            }
        }
    }
    let spec = SandboxSpec {
        root: merged.to_string_lossy().into_owned(),
        mode: MountMode::Overlay,
        overlay: Some(OverlayDirs {
            lower: b.lower,
            upper: upper.to_string_lossy().into_owned(),
            work: work.to_string_lossy().into_owned(),
        }),
        read_only: b.read_only, // remount the overlay read-only after pivot
        command: b.cmd,
        hostname,
        volumes: b.volumes,
        env: b.env,
        workdir: b.workdir,
        share_net: b.share_net,
        uid_range: b.uid_range,
    };
    Ok((spec, Some(scratch)))
}

/// Parse `-v src:dst[:ro]` specs into [`Volume`]s. Both paths must be absolute; the source must
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
        if !source.starts_with('/') || !target.starts_with('/') {
            return Err(Error::Sandbox(format!(
                "-v '{s}': both paths must be absolute"
            )));
        }
        // A NUL byte can't be a C string later (and would otherwise surface as an opaque mount
        // error post-fork) — reject it here.
        if target.contains('\0') {
            return Err(Error::Sandbox(format!("-v '{s}': target has a NUL byte")));
        }
        // Reject `.`/`..` components in the target so it can't climb out of the box root (the
        // in-box `open_in_root` walk enforces this too — this is the fail-fast, before any pull).
        if target.split('/').any(|c| c == "." || c == "..") {
            return Err(Error::Sandbox(format!(
                "-v '{s}': target must not contain '.' or '..'"
            )));
        }
        // Resolve the source to an absolute, symlink-free host path; reject a missing source early
        // (clearer than a post-fork mount failure).
        let canon = std::fs::canonicalize(source)
            .map_err(|e| Error::Sandbox(format!("-v '{s}': source {source}: {e}")))?;
        out.push(Volume {
            source: canon.to_string_lossy().into_owned(),
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

/// `kern exec <name> [--env K=V] [--workdir <dir>] [-- cmd...]` — run a command inside an
/// already-running box, joining its namespaces. Defaults to `/bin/sh`. Propagates the exit code.
pub fn exec(
    name: &str,
    command: &[String],
    env: &[String],
    workdir: Option<&str>,
) -> Result<(), Error> {
    let name = BoxName::parse(name).map_err(Error::InvalidBox)?;
    let env = parse_envs(env)?;
    let cmd = default_if_empty(command);
    let inst = registry::list()
        .into_iter()
        .find(|i| i.name == name.as_str())
        .ok_or_else(|| Error::Sandbox(format!("no running box named '{}'", name.as_str())))?;
    // PID 1 of the box. Older entries (or a race before the supervisor recorded it) → fall back
    // to the supervisor's sole child.
    let pid1 = if inst.pid1 > 0 {
        inst.pid1
    } else {
        registry::child_of(inst.pid)
            .ok_or_else(|| Error::Sandbox("could not locate the box's main process".to_string()))?
    };
    match exec_in_box(pid1, &cmd, &env, workdir) {
        Ok(code) => std::process::exit(code),
        Err(e) => Err(Error::Sandbox(e.to_string())),
    }
}

/// Remove a box's writable scratch tree (best-effort).
fn cleanup_scratch(scratch: Option<&std::path::Path>) {
    if let Some(s) = scratch {
        let _ = std::fs::remove_dir_all(s);
    }
}

/// Run the box in the background: fork a supervisor that detaches from the terminal, registers
/// itself, runs the sandbox to completion, then de-registers. The supervisor's pid is what
/// `kern ps` tracks (it lives for the box's lifetime).
fn run_detached(name: &BoxName, spec: SandboxSpec, scratch: Option<PathBuf>) -> Result<(), Error> {
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
        // ── Foreground launcher ── block on readiness, then report truthfully.
        if have_pipe {
            unsafe { libc::close(wr) };
            // Block until the box exec()s (EOF) or signals failure (1 byte). Retry on EINTR so a
            // stray signal can't be misread as a successful start.
            let mut byte = [0u8; 1];
            let n = loop {
                let r = unsafe { libc::read(rd, byte.as_mut_ptr().cast(), 1) };
                if r < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                break r;
            };
            unsafe { libc::close(rd) };
            if n > 0 {
                // The box signalled failure (or died) before exec. Reap the supervisor so it
                // can't linger as a zombie, then point at the captured reason.
                let mut st = 0i32;
                unsafe { libc::waitpid(child, &mut st, 0) };
                return Err(Error::Sandbox(format!(
                    "box '{}' exited before starting — run `kern logs {}` for the reason",
                    name.as_str(),
                    name.as_str()
                )));
            }
        }
        println!("box '{}' started (detached, pid {child})", name.as_str());
        return Ok(());
    }
    // ── Supervisor ──
    // SAFETY (fork): kern is single-threaded (std + libc only, no runtime threads), so running
    // ordinary Rust — allocation, registry writes — after fork is sound. If a future change ever
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
    let mut inst = registry::Instance {
        name: name.as_str().to_string(),
        pid,
        pid1: 0,
        rootfs: spec.root.clone(),
        command: spec.command.join(" "),
        started: registry::now_unix(),
        starttime: registry::proc_starttime(pid),
    };
    let path = registry::register(&inst).ok();
    // Run the box; when PID 1 is known, rewrite our registry entry with it so `kern exec` can
    // join the box's namespaces. The file key is `name-<supervisorpid>`, so this overwrites it.
    // stderr is the per-box log now (detach_stdio), so a setup failure here is captured for
    // `kern logs <name>` — and the readiness guard signals the failure to the launcher.
    if let Err(e) = run_in_sandbox_with(&spec, have_pipe.then_some(wr), |pid1| {
        inst.pid1 = pid1;
        let _ = registry::register(&inst);
    }) {
        eprintln!("kern: box failed to start: {e}");
    } // blocks until the box exits
    if let Some(p) = path {
        registry::unregister(&p);
    }
    cleanup_scratch(scratch.as_deref());
    unsafe { libc::_exit(0) };
}

/// Memory + task ceilings for a sandbox scope. `MemorySwapMax=0` makes `MemoryMax` a HARD total
/// cap — without it, a workload over the RAM cap just swaps (on a host with swap) instead of OOM.
const SCOPE_MEMORY_MAX: &str = "MemoryMax=512M";
const SCOPE_SWAP_MAX: &str = "MemorySwapMax=0";
const SCOPE_TASKS_MAX: &str = "TasksMax=512";

/// If a systemd user manager is available and we aren't already inside a kern scope, re-exec
/// the whole `kern` invocation under `systemd-run --user --scope` with cgroup caps, so the
/// sandbox (and any fork bomb in it) is hard-limited. This replaces the process on success; on
/// any failure it returns and the caller falls back to the best-effort cgroup path.
fn reexec_in_scope_if_possible() {
    use std::os::unix::process::CommandExt;

    if std::env::var_os("KERN_SCOPE").is_some() {
        return; // already inside our scope
    }
    // Gate on a running user manager (so the exec can't strand us in a broken systemd-run).
    let has_user_systemd = std::env::var_os("XDG_RUNTIME_DIR")
        .map(|d| std::path::Path::new(&d).join("systemd").exists())
        .unwrap_or(false);
    if !has_user_systemd {
        return;
    }
    let Ok(self_exe) = std::env::current_exe() else {
        return;
    };
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut cmd = std::process::Command::new("systemd-run");
    cmd.args([
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        "-p",
        SCOPE_MEMORY_MAX,
        "-p",
        SCOPE_SWAP_MAX,
        "-p",
        SCOPE_TASKS_MAX,
        "--",
    ])
    .arg(self_exe)
    .args(&args)
    .env("KERN_SCOPE", "1");
    // exec() only returns on failure → fall through to the best-effort path.
    let _ = cmd.exec();
}

/// Detach stdio: stdin from `/dev/null`; stdout/stderr to the box's `log` file (so `kern logs`
/// can show it), or `/dev/null` if no log path. So a detached box neither holds nor spams the
/// terminal, but its output is captured.
fn detach_stdio(log: Option<&std::path::Path>) {
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null >= 0 {
            libc::dup2(null, 0);
        }
        let out = log
            .and_then(|p| std::ffi::CString::new(p.to_string_lossy().as_bytes()).ok())
            .map(|c| {
                libc::open(
                    c.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                    0o600,
                )
            })
            .filter(|fd| *fd >= 0);
        let sink = out.unwrap_or(null);
        if sink >= 0 {
            libc::dup2(sink, 1);
            libc::dup2(sink, 2);
        }
        if let Some(fd) = out {
            if fd > 2 {
                libc::close(fd);
            }
        }
        if null > 2 {
            libc::close(null);
        }
    }
}

/// `kern ps [--json]` — list running boxes. Dead entries are pruned on read.
pub fn ps(json: bool) -> Result<(), Error> {
    let boxes = registry::list();
    if json {
        let mut out = String::from("[");
        for (i, b) in boxes.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"name\":{},\"pid\":{},\"rootfs\":{},\"command\":{},\"started\":{}}}",
                json_str(&b.name),
                b.pid,
                json_str(&b.rootfs),
                json_str(&b.command),
                b.started
            ));
        }
        out.push(']');
        println!("{out}");
    } else {
        println!("{:<16} {:>8} {:>8}  COMMAND", "NAME", "PID", "UPTIME");
        let now = registry::now_unix();
        for b in &boxes {
            let up = now.saturating_sub(b.started);
            println!("{:<16} {:>8} {:>7}s  {}", b.name, b.pid, up, b.command);
        }
    }
    Ok(())
}

/// Minimal JSON string escaping for `kern ps --json`.
fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            // Escape every other control char (C0/DEL/C1, incl. ESC `0x1b`) as `\u00XX` — keeps the
            // JSON valid and stops a crafted registry name/description from injecting a real escape
            // sequence into a terminal that cats the output.
            c if c.is_control() => o.push_str(&format!("\\u{:04x}", c as u32)),
            _ => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Human-readable byte size (K/M/G).
pub(crate) fn human_bytes(b: u64) -> String {
    const M: u64 = 1 << 20;
    const G: u64 = 1 << 30;
    if b >= G {
        format!("{:.1}G", b as f64 / G as f64)
    } else if b >= M {
        format!("{:.0}M", b as f64 / M as f64)
    } else {
        format!("{}K", b / 1024)
    }
}

/// `kern stats [--json]` — current memory + cumulative CPU time per running box (from cgroup).
pub fn stats(json: bool) -> Result<(), Error> {
    let boxes = registry::list();
    if json {
        let mut out = String::from("[");
        for (i, b) in boxes.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            // `null` (not 0) when the box has no dedicated cgroup to read — "unknown", not "zero".
            let num = |v: Option<u64>| v.map_or("null".to_string(), |n| n.to_string());
            out.push_str(&format!(
                "{{\"name\":{},\"pid\":{},\"mem_bytes\":{},\"cpu_usec\":{}}}",
                json_str(&b.name),
                b.pid,
                num(registry::mem_bytes(b.pid)),
                num(registry::cpu_usec(b.pid))
            ));
        }
        out.push(']');
        println!("{out}");
    } else {
        println!("{:<16} {:>8} {:>9} {:>9}", "NAME", "PID", "MEM", "CPU");
        for b in &boxes {
            let mem = registry::mem_bytes(b.pid).map_or("-".into(), human_bytes);
            let cpu =
                registry::cpu_usec(b.pid).map_or("-".into(), |u| format!("{:.1}s", u as f64 / 1e6));
            println!("{:<16} {:>8} {:>9} {:>9}", b.name, b.pid, mem, cpu);
        }
    }
    Ok(())
}

/// `kern images [--json]` — list OCI images pulled into the local cache. Each completed pull leaves
/// a `<sanitized>.ok` sentinel whose *content* is the original image ref, next to the `<sanitized>/`
/// rootfs dir — so we recover the real name, the on-disk size, and when it was pulled.
pub fn images(json: bool) -> Result<(), Error> {
    let cache = cache_dir();
    let mut rows: Vec<(String, u64, u64)> = Vec::new(); // (image ref, size bytes, pulled unix)
    if let Ok(entries) = std::fs::read_dir(&cache) {
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) != Some("ok") {
                continue; // skip the `<name>/` dirs, `.lock` files, `scratch/`
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()).map(String::from) else {
                continue;
            };
            let name = std::fs::read_to_string(&path)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| stem.clone());
            let size = dir_size(&cache.join(&stem));
            let pulled = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            rows.push((name, size, pulled));
        }
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));

    if json {
        let mut out = String::from("[");
        for (i, (name, size, pulled)) in rows.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"image\":{},\"size_bytes\":{size},\"pulled\":{pulled}}}",
                json_str(name)
            ));
        }
        out.push(']');
        println!("{out}");
    } else if rows.is_empty() {
        println!("no images cached yet — pull one with `kern pull <image>` (or `kern box <name> --image <image>`)");
    } else {
        println!("{:<30} {:>9}  PULLED", "REPOSITORY", "SIZE");
        let now = registry::now_unix();
        for (name, size, pulled) in &rows {
            println!(
                "{:<30} {:>9}  {}",
                truncate(name, 30), // untrusted (the `.ok` sentinel content) — strip escapes
                human_bytes(*size),
                fmt_age(now.saturating_sub(*pulled))
            );
        }
    }
    Ok(())
}

/// Recursive on-disk size of `dir` in bytes (best-effort). Uses the no-follow dirent file type, so
/// symlinks are neither followed nor counted.
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

/// `kern search <query> [--json]` — search Docker Hub (the same registry `kern pull` uses) for
/// public images. Prints name, stars, whether it's an official image, and the description.
pub fn search(query: &str, json: bool) -> Result<(), Error> {
    let results = kern_oci::search(query, 25).map_err(|e| Error::Oci(e.to_string()))?;
    if json {
        let mut out = String::from("[");
        for (i, r) in results.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"name\":{},\"description\":{},\"stars\":{},\"official\":{}}}",
                json_str(&r.name),
                json_str(&r.description),
                r.stars,
                r.official
            ));
        }
        out.push(']');
        println!("{out}");
    } else if results.is_empty() {
        println!("no images found for '{query}'");
    } else {
        println!(
            "{:<32} {:>6} {:<8} DESCRIPTION",
            "NAME", "STARS", "OFFICIAL"
        );
        for r in &results {
            println!(
                "{:<32} {:>6} {:<8} {}",
                truncate(&r.name, 32),
                r.stars,
                if r.official { "[ok]" } else { "" },
                truncate(&r.description, 46)
            );
        }
        println!("\npull one with:  kern pull <NAME>");
    }
    Ok(())
}

/// Prepare an **untrusted** string for a terminal table: first strip control/escape characters
/// (so a crafted registry name/description or cached image ref can't inject ANSI sequences into the
/// user's terminal), then truncate to at most `max` characters with an `…`.
fn truncate(s: &str, max: usize) -> String {
    let clean: String = s.chars().filter(|c| !c.is_control()).collect();
    if clean.chars().count() <= max {
        return clean;
    }
    let mut t: String = clean.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}

/// `kern logs <name>` — print the captured stdout/stderr of the most recent box named `name`.
pub fn logs(name: &str) -> Result<(), Error> {
    let dir = registry::logs_dir().map_err(|e| Error::Sandbox(format!("logs dir: {e}")))?;
    let prefix = format!("{name}-");
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let fname = e.file_name();
            let fname = fname.to_string_lossy();
            if fname.starts_with(&prefix) && fname.ends_with(".log") {
                if let Ok(mtime) = e.metadata().and_then(|m| m.modified()) {
                    if newest.as_ref().is_none_or(|(t, _)| mtime > *t) {
                        newest = Some((mtime, e.path()));
                    }
                }
            }
        }
    }
    match newest {
        Some((_, path)) => {
            let body = std::fs::read_to_string(&path)
                .map_err(|e| Error::Sandbox(format!("reading log: {e}")))?;
            print!("{body}");
            Ok(())
        }
        None => Err(Error::Sandbox(format!("no logs for box '{name}'"))),
    }
}

/// `kern top` — live, auto-refreshing view of running boxes (name, pid, uptime, mem, cpu%).
/// Reads the registry + each box's cgroup every second; exit with Ctrl-C.
/// `kern top` — an interactive task-manager TUI (tabs, live refresh, keyboard nav) when stdout is
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

/// `kern pull <image> [--dest <dir>]` — download an OCI image into a rootfs directory.
pub fn pull(image: &str, dest: Option<&str>) -> Result<(), Error> {
    let dest = match dest {
        Some(d) => PathBuf::from(d),
        None => std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(sanitize_ref(image)),
    };
    println!("pulling {image} -> {}", dest.display());
    kern_oci::pull(image, &dest).map_err(|e| Error::Oci(e.to_string()))?;
    println!(
        "done. run it: kern box <name> --rootfs {} -- /bin/sh",
        dest.display()
    );
    Ok(())
}

/// Pull `image` into a local cache and return its rootfs path. Reuse is gated on a sibling
/// completion sentinel (`<ref>.ok`), not "directory is non-empty" — so an interrupted pull (or a
/// stray file) never makes a partial/poisoned rootfs look valid; we re-pull cleanly.
fn pull_to_cache(image: &str) -> Result<String, Error> {
    use std::os::unix::io::AsRawFd;
    let cache = cache_dir();
    own_only_dir(&cache).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
    let safe = sanitize_ref(image);
    let dir = cache.join(&safe);
    let sentinel = cache.join(format!("{safe}.ok"));
    if sentinel.exists() {
        return Ok(dir.to_string_lossy().into_owned()); // fast path: already cached
    }
    // Serialize concurrent pulls of the SAME image: take an exclusive lock, then re-check the
    // sentinel (another process may have completed the pull while we waited). Different images
    // use different lock files, so they still pull in parallel.
    let lock = std::fs::File::create(cache.join(format!("{safe}.lock")))
        .map_err(|e| Error::Oci(format!("pull lock: {e}")))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(Error::Oci("could not acquire pull lock".into()));
    }
    if !sentinel.exists() {
        eprintln!("→ image '{image}' not cached — pulling once (reused after)");
        let _ = std::fs::remove_dir_all(&dir); // clear any partial extraction
        std::fs::create_dir_all(&dir).map_err(|e| Error::Oci(format!("cache dir: {e}")))?;
        kern_oci::pull(image, &dir).map_err(|e| Error::Oci(e.to_string()))?;
        let _ = std::fs::write(&sentinel, image.as_bytes());
    }
    // lock released when `lock` drops
    Ok(dir.to_string_lossy().into_owned())
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

/// Create `dir` (and parents) private to this user (mode 0700). Mitigates a local-user symlink/
/// clobber attack on a predictable cache path: another user can't pre-create or enter it.
fn own_only_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// A filesystem-safe directory name for an image reference.
fn sanitize_ref(image: &str) -> String {
    image.replace(['/', ':'], "_")
}

/// Per-box writable overlay scratch (upper/work) — placed on **tmpfs** where possible
/// (`$XDG_RUNTIME_DIR` → `/run/user/<uid>`, both tmpfs), else `/tmp`. tmpfs makes the create /
/// overlay-mount / cleanup RAM-fast and keeps the writable layer ephemeral; its pages count
/// against the box's memory cap. Created mode 0700 by the caller.
fn scratch_dir() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(x).join("kern/scratch");
    }
    let uid = unsafe { libc::getuid() };
    let run = PathBuf::from(format!("/run/user/{uid}"));
    if run.is_dir() {
        return run.join("kern/scratch");
    }
    PathBuf::from(format!("/tmp/kern-{uid}/scratch"))
}

/// `kern stop <name>` — stop running box(es) with that name: SIGKILL the supervisor's process
/// group (which tears down the box's PID namespace), drop the registry entry, and remove the
/// writable scratch.
pub fn stop(name: &str) -> Result<(), Error> {
    let dir = registry::dir().map_err(|e| Error::Sandbox(format!("registry: {e}")))?;
    let matches: Vec<_> = registry::list()
        .into_iter()
        .filter(|b| b.name == name)
        .collect();
    if matches.is_empty() {
        return Err(Error::Sandbox(format!("no running box named '{name}'")));
    }
    for b in matches {
        // The supervisor `setsid`-ed, so its pgid == its pid; the box shares the group.
        unsafe { libc::kill(-b.pid, libc::SIGKILL) };
        let _ = std::fs::remove_file(dir.join(format!("{}-{}", b.name, b.pid)));
        cleanup_box_scratch(&b.rootfs);
        println!("stopped '{}' (pid {})", b.name, b.pid);
    }
    Ok(())
}

/// Remove the overlay scratch behind a box, derived from its merge path
/// (`<cache>/scratch/<name>-<pid>/merged`).
fn cleanup_box_scratch(rootfs: &str) {
    let p = std::path::Path::new(rootfs);
    if p.file_name().is_some_and(|n| n == "merged") {
        if let Some(scratch) = p.parent() {
            if scratch.to_string_lossy().contains("/scratch/") {
                let _ = std::fs::remove_dir_all(scratch);
            }
        }
    }
}

/// `kern compose <file>` — bring up a stack of boxes (detached) in `depends_on` order. Each
/// service is launched via a fresh `kern box -d` subprocess, so it gets its own scope + registry
/// entry; track the stack with `kern ps`.
pub fn compose(file: &str) -> Result<(), Error> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| Error::Compose(format!("reading {file}: {e}")))?;
    let boxes = crate::compose::parse(&text).map_err(Error::Compose)?;
    let order = crate::compose::topo_order(&boxes).map_err(Error::Compose)?;
    let self_exe =
        std::env::current_exe().map_err(|e| Error::Compose(format!("locating kern: {e}")))?;

    eprintln!(
        "→ bringing up {} box(es) in order: {}",
        order.len(),
        order.join(" → ")
    );
    for (i, name) in order.iter().enumerate() {
        let b = boxes.iter().find(|b| &b.name == name).unwrap();
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
        eprintln!(
            "→ [{}/{}] starting '{name}'  {src}{dep}",
            i + 1,
            order.len()
        );
        let mut cmd = std::process::Command::new(&self_exe);
        cmd.arg("box").arg(&b.name);
        if let Some(img) = &b.image {
            cmd.arg("--image").arg(img);
        }
        if let Some(rf) = &b.rootfs {
            cmd.arg("--rootfs").arg(rf);
        }
        cmd.arg("-d");
        if !b.command.is_empty() {
            cmd.arg("--").args(&b.command);
        }
        let status = cmd
            .status()
            .map_err(|e| Error::Compose(format!("starting '{}': {e}", b.name)))?;
        if !status.success() {
            return Err(Error::Compose(format!("box '{}' failed to start", b.name)));
        }
    }
    println!(
        "compose up: {} box(es) started. track with `kern ps`.",
        order.len()
    );
    Ok(())
}

/// A recognised runtime verb that lands in a later 0.x release.
pub fn pending(name: &'static str, opts: &GlobalOpts) -> Result<(), Error> {
    let _ = opts; // GPU-off is the only behaviour wired so far
    Err(Error::NotYetImplemented(name))
}
