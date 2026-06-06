//! Command parsing and dispatch.
//!
//! A tiny hand-rolled parser keeps the binary dependency-free. The roadmap target is a
//! `clap`-derive command enum + `match` dispatch (same shape, see ARCHITECTURE.md).

use crate::commands;
use crate::error::Error;

/// Global runtime options that apply to any command.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct GlobalOpts {
    /// `--no-gpu`: never load any GPU driver interposer. Decouples the sandbox trust decision
    /// from the driver-interposition trust decision; any GPU support is opt-in and off by
    /// default. The runtime itself is GPU-free.
    pub no_gpu: bool,
}

/// The parsed subcommand.
#[derive(Debug, PartialEq)]
pub enum Command {
    Version,
    Help,
    /// `kern box <name> --plan`: print the ordered isolation step sequence (no privileges).
    BoxPlan {
        name: String,
    },
    /// `kern box <name> (--rootfs <dir> | --image <ref>) [-d] [-- cmd...]`: run in a sandbox.
    BoxRun {
        name: String,
        rootfs: Option<String>,
        image: Option<String>,
        command: Vec<String>,
        detached: bool,
        read_only: bool,
        /// `-v src:dst[:ro]` (repeatable): host paths bind-mounted in.
        volumes: Vec<String>,
        /// `--env K=V` / `-e K=V` (repeatable): extra environment for the workload.
        env: Vec<String>,
        /// `--workdir <dir>` / `-w <dir>`: working directory inside the box.
        workdir: Option<String>,
        /// `--net`: share the host network namespace (outbound networking; no net isolation).
        share_net: bool,
        /// `--uid-range`: map a sub-uid/gid range (apt/dpkg, www-data). Default maps only the caller.
        uid_range: bool,
        /// `--bind-rootfs`: bind the rootfs directly instead of an overlay (faster on slow-overlay
        /// kernels; source becomes mutable & shared).
        bind_rootfs: bool,
        /// `--memory`/`-m`: hard memory ceiling in bytes (default cap if `None`).
        memory: Option<u64>,
        /// `--cpus`: CPU cap in cores, K8s semantics (1.5 = 1½ cores; uncapped if `None`).
        cpus: Option<f64>,
        /// `-it`/`-t`: allocate a PTY so the box gets an interactive controlling terminal.
        tty: bool,
        /// `-p host:box` (repeatable): publish a box TCP port on a host port.
        ports: Vec<(u32, u16, u16)>,
        /// `--restart`: restart a detached box on non-zero exit (on-failure policy).
        restart: bool,
        /// `--health-cmd <cmd>`: shell command run periodically in the box (exit 0 = healthy).
        health_cmd: Option<String>,
        /// `--health-interval <sec>`: seconds between health checks (default 30).
        health_interval: u64,
    },
    /// `kern run [--memory M] [--cpus N] [--] <cmd...>`: run a command under cgroup CPU/memory
    /// caps WITHOUT a full sandbox — the resource-governor verb (composes with `box`'s isolation).
    Run {
        command: Vec<String>,
        memory: Option<u64>,
        cpus: Option<f64>,
    },
    /// `kern exec <name> [-it] [--env K=V] [--workdir <dir>] [-- cmd...]`: run a command in a box.
    Exec {
        name: String,
        command: Vec<String>,
        env: Vec<String>,
        workdir: Option<String>,
        /// `-it`/`-t`/`-i`: allocate an interactive PTY for the exec'd command.
        tty: bool,
    },
    /// `kern stop <name>... | --all`: stop running box(es) by name, or every running box.
    Stop {
        names: Vec<String>,
        all: bool,
    },
    /// `kern pull <image> [--dest <dir>]`: download an OCI image into a rootfs.
    Pull {
        image: String,
        dest: Option<String>,
    },
    /// `kern search <query> [--json]`: search Docker Hub for images.
    Search {
        query: String,
        json: bool,
    },
    /// `kern images [--json]`: list pulled (cached) images.
    Images {
        json: bool,
    },
    /// `kern ps [--json]`: list running boxes.
    Ps {
        json: bool,
    },
    /// `kern stats [--json]`: per-box memory + CPU.
    Stats {
        json: bool,
    },
    /// `kern logs <name>`: print a box's captured output.
    Logs {
        name: String,
    },
    /// `kern top`: live auto-refreshing box monitor.
    Top,
    /// `kern compose <file>`: bring up a stack of boxes in dependency order.
    Compose {
        file: String,
    },
}

/// Split argv into global options and a subcommand.
pub fn parse(args: &[String]) -> Result<(GlobalOpts, Command), Error> {
    let mut opts = GlobalOpts::default();
    let mut rest: Vec<&str> = Vec::new();
    for a in args {
        match a.as_str() {
            "--no-gpu" => opts.no_gpu = true,
            other => rest.push(other),
        }
    }
    let cmd = match rest.first().copied() {
        None | Some("--help" | "-h" | "help") => Command::Help,
        Some("--version" | "-V" | "version") => Command::Version,
        // `box`: `--plan` previews; `--rootfs <dir>`/`--image <ref>` [-d] [-- cmd] runs it.
        Some("box") => parse_box(&rest)?,
        // `exec <name> [opts] [-- cmd]`: run a command in an existing box.
        Some("exec") => parse_exec(&rest)?,
        // `search <query> [--json]`: search Docker Hub for images.
        Some("search") => match rest.iter().skip(1).find(|a| !a.starts_with('-')) {
            Some(q) => Command::Search {
                query: (*q).to_string(),
                json: rest.contains(&"--json"),
            },
            None => return Err(Error::Usage("search <query> [--json]")),
        },
        // `pull <image> [--dest <dir>]`: download an OCI image.
        Some("pull") => parse_pull(&rest).ok_or(Error::Usage("pull <image> [--dest <dir>]"))?,
        // `images`: list pulled (cached) images.
        Some("images") => Command::Images {
            json: rest.contains(&"--json"),
        },
        // `stop <name>`: stop running box(es).
        Some("stop") => {
            let all = rest.iter().any(|a| *a == "--all" || *a == "-a");
            let names: Vec<String> = rest
                .iter()
                .skip(1)
                .filter(|a| !a.starts_with('-'))
                .map(|s| (*s).to_string())
                .collect();
            if !all && names.is_empty() {
                return Err(Error::Usage("stop <name>... | stop --all"));
            }
            Command::Stop { names, all }
        }
        // `ps`: list running boxes.
        Some("ps") => Command::Ps {
            json: rest.contains(&"--json"),
        },
        // `stats`: per-box memory + CPU.
        Some("stats") => Command::Stats {
            json: rest.contains(&"--json"),
        },
        // `logs <name>`: a box's captured output.
        Some("logs") => match rest.get(1) {
            Some(n) if !n.starts_with('-') => Command::Logs {
                name: (*n).to_string(),
            },
            _ => return Err(Error::Usage("logs <name>")),
        },
        // `top`: live box monitor.
        Some("top") => Command::Top,
        // `compose <file>`: bring up a stack.
        Some("compose") => match rest.get(1) {
            Some(f) if !f.starts_with('-') => Command::Compose {
                file: (*f).to_string(),
            },
            _ => return Err(Error::Usage("compose <file>")),
        },
        // `run [--memory M] [--cpus N] [--] <cmd...>`: cap a command without a full sandbox.
        Some("run") => parse_run(&rest)?,
        Some(other) => return Err(Error::UnknownCommand(other.to_string())),
    };
    Ok((opts, cmd))
}

/// Parse the `box` subcommand. `--plan` previews the isolation sequence (no privileges);
/// `--rootfs <dir>` or `--image <ref>` runs the command (after `--`, default `/bin/sh`) in a
/// real sandbox. Without a rootfs/image it still routes to `BoxRun` (which reports the missing
/// source); `--plan` previews instead of running.
fn parse_box(rest: &[&str]) -> Result<Command, Error> {
    let mut name: Option<&str> = None;
    let mut rootfs: Option<String> = None;
    let mut image: Option<String> = None;
    let mut plan = false;
    let mut detached = false;
    let mut read_only = false;
    let mut share_net = false;
    let mut uid_range = false;
    let mut bind_rootfs = false;
    let mut tty = false;
    let mut restart = false;
    let mut health_cmd: Option<String> = None;
    let mut health_interval = 30u64;
    let mut ports: Vec<(u32, u16, u16)> = Vec::new();
    let mut memory: Option<u64> = None;
    let mut cpus: Option<f64> = None;
    let mut volumes: Vec<String> = Vec::new();
    let mut env: Vec<String> = Vec::new();
    let mut workdir: Option<String> = None;
    let mut command: Vec<String> = Vec::new();
    let mut after_dd = false;
    let mut i = 1; // rest[0] == "box"
    while i < rest.len() {
        let a = rest[i];
        if after_dd {
            command.push(a.to_string());
        } else {
            match a {
                "--" => after_dd = true,
                "--plan" => plan = true,
                "-d" | "--detach" => detached = true,
                "--read-only" | "--ro" => read_only = true,
                "--net" => share_net = true,
                "--uid-range" => uid_range = true,
                "--bind-rootfs" => bind_rootfs = true,
                // `--restart`: restart a detached box if it exits non-zero (on-failure policy).
                "--restart" => restart = true,
                // `--health-cmd <cmd>`: shell command run periodically in the box; exit 0 = healthy.
                "--health-cmd" => {
                    i += 1;
                    match rest.get(i) {
                        Some(c) => health_cmd = Some((*c).to_string()),
                        None => return Err(Error::Usage("--health-cmd <shell command>")),
                    }
                }
                // `--health-interval <sec>`: seconds between health checks (default 30).
                "--health-interval" => {
                    i += 1;
                    match rest
                        .get(i)
                        .and_then(|v| v.parse::<u64>().ok())
                        .filter(|s| *s > 0)
                    {
                        Some(s) => health_interval = s,
                        None => return Err(Error::Usage("--health-interval <seconds> (e.g. 10)")),
                    }
                }
                // `-it`/`-ti`/`-t`/`-i`: allocate an interactive PTY for the box (shells, REPLs).
                "-it" | "-ti" | "-t" | "-i" | "--tty" | "--interactive" => tty = true,
                "--rootfs" => {
                    i += 1;
                    rootfs = rest.get(i).map(|v| (*v).to_string());
                }
                "--image" => {
                    i += 1;
                    image = rest.get(i).map(|v| (*v).to_string());
                }
                "-v" | "--volume" => {
                    i += 1;
                    if let Some(v) = rest.get(i) {
                        volumes.push((*v).to_string());
                    }
                }
                "-e" | "--env" => {
                    i += 1;
                    if let Some(v) = rest.get(i) {
                        env.push((*v).to_string());
                    }
                }
                "-w" | "--workdir" => {
                    i += 1;
                    workdir = rest.get(i).map(|v| (*v).to_string());
                }
                "-p" | "--publish" => {
                    i += 1;
                    match rest.get(i).and_then(|v| crate::ports::parse(v)) {
                        Some(p) => ports.push(p),
                        None => return Err(Error::Usage("-p <hostport>:<boxport> (e.g. 8080:80)")),
                    }
                }
                "-m" | "--memory" => {
                    i += 1;
                    match rest.get(i).and_then(|v| parse_size(v)) {
                        Some(b) => memory = Some(b),
                        None => {
                            return Err(Error::Usage("--memory <size> (e.g. 512m, 1g, 268435456)"))
                        }
                    }
                }
                "--cpus" => {
                    i += 1;
                    match rest
                        .get(i)
                        .and_then(|v| v.parse::<f64>().ok())
                        .filter(|c| *c > 0.0 && c.is_finite())
                    {
                        Some(c) => cpus = Some(c),
                        None => return Err(Error::Usage("--cpus <n> (e.g. 1.5 = 1½ cores, 2)")),
                    }
                }
                // Reject an unknown flag rather than silently ignoring it: a typo'd `--read-only`
                // must NOT quietly run a writable box. (Flags after `--` are part of the command.)
                s if s.starts_with('-') => {
                    return Err(Error::Usage("box: unknown flag (see --help)"))
                }
                s if name.is_none() => name = Some(s),
                _ => {}
            }
        }
        i += 1;
    }
    // Always route to the real command; missing name → BoxName rejects it, missing rootfs/image
    // → box_run reports it. `--plan` wins (non-destructive preview).
    let cmd = if plan {
        Command::BoxPlan {
            name: name.unwrap_or_default().to_string(),
        }
    } else {
        Command::BoxRun {
            name: name.unwrap_or_default().to_string(),
            rootfs,
            image,
            command,
            detached,
            read_only,
            volumes,
            env,
            workdir,
            share_net,
            uid_range,
            bind_rootfs,
            memory,
            cpus,
            tty,
            ports,
            restart,
            health_cmd,
            health_interval,
        }
    };
    Ok(cmd)
}

/// Parse `run [--memory M] [--cpus N] [--] <cmd...>`. Flags come first; the first bare token (or
/// everything after `--`) begins the command, after which nothing is treated as a flag. An empty
/// command is a usage error.
fn parse_run(rest: &[&str]) -> Result<Command, Error> {
    let mut memory: Option<u64> = None;
    let mut cpus: Option<f64> = None;
    let mut command: Vec<String> = Vec::new();
    let mut i = 1; // rest[0] == "run"
    while i < rest.len() {
        match rest[i] {
            "--" => {
                command.extend(rest[i + 1..].iter().map(|s| (*s).to_string()));
                break;
            }
            "-m" | "--memory" => {
                i += 1;
                match rest.get(i).and_then(|v| parse_size(v)) {
                    Some(b) => memory = Some(b),
                    None => return Err(Error::Usage("--memory <size> (e.g. 512m, 1g)")),
                }
            }
            "--cpus" => {
                i += 1;
                match rest
                    .get(i)
                    .and_then(|v| v.parse::<f64>().ok())
                    .filter(|c| *c > 0.0 && c.is_finite())
                {
                    Some(c) => cpus = Some(c),
                    None => return Err(Error::Usage("--cpus <n> (e.g. 1.5, 2)")),
                }
            }
            s if s.starts_with('-') => {
                return Err(Error::Usage(
                    "run: unknown flag (put `--` before the command)",
                ))
            }
            // First bare token → the command starts here; everything from here on is the command.
            _ => {
                command.extend(rest[i..].iter().map(|s| (*s).to_string()));
                break;
            }
        }
        i += 1;
    }
    if command.is_empty() {
        return Err(Error::Usage("run [--memory M] [--cpus N] [--] <cmd...>"));
    }
    Ok(Command::Run {
        command,
        memory,
        cpus,
    })
}

/// Parse a memory size like `512m`, `1g`, `512mb`, or a bare `268435456` (= bytes) into bytes.
/// Units are binary (k = 1024). Returns `None` on a malformed value — the caller turns that into a
/// usage error.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let last = s.chars().last()?.to_ascii_lowercase();
    let (num, mult): (&str, u64) = match last {
        '0'..='9' => (s, 1),
        // accept a trailing 'b' on a unit ("mb"/"gb") or on its own (bytes)
        'b' => {
            let body = &s[..s.len() - 1];
            match body.chars().last().map(|c| c.to_ascii_lowercase()) {
                Some('k') => (&body[..body.len() - 1], 1024),
                Some('m') => (&body[..body.len() - 1], 1024 * 1024),
                Some('g') => (&body[..body.len() - 1], 1024 * 1024 * 1024),
                _ => (body, 1),
            }
        }
        'k' => (&s[..s.len() - 1], 1024),
        'm' => (&s[..s.len() - 1], 1024 * 1024),
        'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => return None,
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .filter(|b| *b > 0)
}

/// Parse `exec <name> [--env K=V] [--workdir <dir>] [-- cmd...]`. Missing name → usage error.
fn parse_exec(rest: &[&str]) -> Result<Command, Error> {
    let mut name: Option<&str> = None;
    let mut env: Vec<String> = Vec::new();
    let mut workdir: Option<String> = None;
    let mut command: Vec<String> = Vec::new();
    let mut tty = false;
    let mut after_dd = false;
    let mut i = 1; // rest[0] == "exec"
    while i < rest.len() {
        let a = rest[i];
        if after_dd {
            command.push(a.to_string());
        } else {
            match a {
                "--" => after_dd = true,
                "-e" | "--env" => {
                    i += 1;
                    if let Some(v) = rest.get(i) {
                        env.push((*v).to_string());
                    }
                }
                "-w" | "--workdir" => {
                    i += 1;
                    workdir = rest.get(i).map(|v| (*v).to_string());
                }
                "-it" | "-ti" | "-t" | "-i" | "--tty" | "--interactive" => tty = true,
                s if s.starts_with('-') => {
                    return Err(Error::Usage("exec: unknown flag (see --help)"))
                }
                s if name.is_none() => name = Some(s),
                _ => {}
            }
        }
        i += 1;
    }
    match name {
        Some(n) => Ok(Command::Exec {
            name: n.to_string(),
            command,
            env,
            workdir,
            tty,
        }),
        None => Err(Error::Usage("exec <name> [-- cmd...]")),
    }
}

/// Parse `pull <image> [--dest <dir>]`. `None` if no image was given.
fn parse_pull(rest: &[&str]) -> Option<Command> {
    let mut image: Option<&str> = None;
    let mut dest: Option<String> = None;
    let mut i = 1; // rest[0] == "pull"
    while i < rest.len() {
        match rest[i] {
            "--dest" => {
                i += 1;
                dest = rest.get(i).map(|v| (*v).to_string());
            }
            s if s.starts_with('-') => {}
            s if image.is_none() => image = Some(s),
            _ => {}
        }
        i += 1;
    }
    image.map(|img| Command::Pull {
        image: img.to_string(),
        dest,
    })
}

/// Parse and run.
pub fn run(args: &[String]) -> Result<(), Error> {
    // `--no-gpu` is parsed into `opts` (the runtime is GPU-free, so it's a forward-compat no-op for
    // now); no dispatch arm consumes it yet.
    let (_opts, cmd) = parse(args)?;
    match cmd {
        Command::Version => commands::version(),
        Command::Help => commands::help(),
        Command::BoxPlan { name } => commands::box_plan(&name),
        Command::BoxRun {
            name,
            rootfs,
            image,
            command,
            detached,
            read_only,
            volumes,
            env,
            workdir,
            share_net,
            uid_range,
            bind_rootfs,
            memory,
            cpus,
            tty,
            ports,
            restart,
            health_cmd,
            health_interval,
        } => commands::box_run(commands::BoxRunArgs {
            name: &name,
            rootfs: rootfs.as_deref(),
            image: image.as_deref(),
            command: &command,
            detached,
            read_only,
            volumes: &volumes,
            env: &env,
            workdir: workdir.as_deref(),
            share_net,
            uid_range,
            bind_rootfs,
            memory,
            cpus,
            tty,
            ports: &ports,
            restart,
            health_cmd: health_cmd.as_deref(),
            health_interval,
        }),
        Command::Run {
            command,
            memory,
            cpus,
        } => commands::run(&command, memory, cpus),
        Command::Exec {
            name,
            command,
            env,
            workdir,
            tty,
        } => commands::exec(&name, &command, &env, workdir.as_deref(), tty),
        Command::Search { query, json } => commands::search(&query, json),
        Command::Images { json } => commands::images(json),
        Command::Pull { image, dest } => commands::pull(&image, dest.as_deref()),
        Command::Stop { names, all } => commands::stop(&names, all),
        Command::Ps { json } => commands::ps(json),
        Command::Stats { json } => commands::stats(json),
        Command::Logs { name } => commands::logs(&name),
        Command::Top => commands::top(),
        Command::Compose { file } => commands::compose(&file),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_gpu_flag_is_parsed_and_default_off() {
        let (o, _) = parse(&["box".into()]).unwrap();
        assert!(!o.no_gpu, "GPU interposition is off by default");
        let (o, _) = parse(&["--no-gpu".into(), "box".into()]).unwrap();
        assert!(o.no_gpu);
    }

    #[test]
    fn version_and_help_resolve() {
        assert_eq!(parse(&["--version".into()]).unwrap().1, Command::Version);
        assert_eq!(parse(&[]).unwrap().1, Command::Help);
    }

    #[test]
    fn box_dispatch_and_plan() {
        // `box <name> --plan` → BoxPlan.
        let plan = parse(&["box".into(), "web".into(), "--plan".into()])
            .unwrap()
            .1;
        assert_eq!(plan, Command::BoxPlan { name: "web".into() });
        // `box <name>` with no rootfs/image still routes to BoxRun (box_run reports the missing
        // source) — NOT a misleading "not implemented".
        assert!(matches!(
            parse(&["box".into(), "web".into()]).unwrap().1,
            Command::BoxRun { name, rootfs: None, image: None, .. } if name == "web"
        ));
    }

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("512"), Some(512));
        assert_eq!(parse_size("512m"), Some(512 * 1024 * 1024));
        assert_eq!(parse_size("1g"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("512mb"), Some(512 * 1024 * 1024));
        assert_eq!(parse_size("1024k"), Some(1024 * 1024));
        assert_eq!(parse_size("0"), None); // zero is not a useful cap
        assert_eq!(parse_size("pippo"), None);
        assert_eq!(parse_size(""), None);
    }

    #[test]
    fn box_parses_memory_and_cpus() {
        let cmd = parse(&[
            "box".into(),
            "x".into(),
            "--memory".into(),
            "256m".into(),
            "--cpus".into(),
            "1.5".into(),
        ])
        .unwrap()
        .1;
        assert!(matches!(
            cmd,
            Command::BoxRun { memory: Some(m), cpus: Some(c), .. }
                if m == 256 * 1024 * 1024 && (c - 1.5).abs() < 1e-9
        ));
        // Malformed values are usage errors, never silently ignored.
        assert!(matches!(
            parse(&["box".into(), "x".into(), "--memory".into(), "nope".into()]),
            Err(Error::Usage(_))
        ));
        assert!(matches!(
            parse(&["box".into(), "x".into(), "--cpus".into(), "0".into()]),
            Err(Error::Usage(_))
        ));
    }

    #[test]
    fn box_publish_ports() {
        let (_, cmd) = parse(&[
            "box".into(),
            "x".into(),
            "-p".into(),
            "8080:80".into(), // default → 127.0.0.1 (loopback only)
            "-p".into(),
            "0.0.0.0:443:443".into(), // explicit all-interfaces
        ])
        .unwrap();
        let Command::BoxRun { ports, .. } = cmd else {
            panic!("expected BoxRun")
        };
        assert_eq!(ports, vec![(0x7f00_0001, 8080, 80), (0, 443, 443)]);
        // Malformed mappings are usage errors, never silently dropped.
        for bad in ["0:80", "abc", "80", "80:0", "999.0.0.1:8080:80"] {
            assert!(
                matches!(
                    parse(&["box".into(), "x".into(), "-p".into(), bad.to_string()]),
                    Err(Error::Usage(_))
                ),
                "-p {bad}"
            );
        }
    }

    #[test]
    fn box_it_flag_allocates_tty() {
        for f in ["-it", "-ti", "-t", "-i", "--tty", "--interactive"] {
            let (_, cmd) = parse(&["box".into(), "x".into(), f.to_string()]).unwrap();
            assert!(matches!(cmd, Command::BoxRun { tty: true, .. }), "flag {f}");
        }
        // off by default
        let (_, cmd) = parse(&["box".into(), "x".into()]).unwrap();
        assert!(matches!(cmd, Command::BoxRun { tty: false, .. }));
    }

    #[test]
    fn run_parses_flags_then_command() {
        // Flags first, then the command; the first bare token begins the command.
        let (_, cmd) = parse(&[
            "run".into(),
            "--memory".into(),
            "256m".into(),
            "--cpus".into(),
            "2".into(),
            "echo".into(),
            "hi".into(),
        ])
        .unwrap();
        let Command::Run {
            command,
            memory,
            cpus,
        } = cmd
        else {
            panic!("expected Run")
        };
        assert_eq!(command, ["echo", "hi"]);
        assert_eq!(memory, Some(256 * 1024 * 1024));
        assert_eq!(cpus, Some(2.0));
        // `--` form; flags after it belong to the command.
        let (_, cmd) = parse(&["run".into(), "--".into(), "ls".into(), "-la".into()]).unwrap();
        let Command::Run { command, .. } = cmd else {
            panic!()
        };
        assert_eq!(command, ["ls", "-la"]);
        // An unknown flag before the command is a usage error (catches typos), not a silent run.
        assert!(matches!(
            parse(&["run".into(), "--bogus".into()]),
            Err(Error::Usage(_))
        ));
        // Empty command → usage error.
        assert!(matches!(parse(&["run".into()]), Err(Error::Usage(_))));
    }

    #[test]
    fn stop_takes_multiple_names_or_all() {
        // Multiple names are ALL captured (the old parser silently kept only the first).
        let cmd = parse(&["stop".into(), "a".into(), "b".into(), "c".into()])
            .unwrap()
            .1;
        assert_eq!(
            cmd,
            Command::Stop {
                names: vec!["a".into(), "b".into(), "c".into()],
                all: false,
            }
        );
        // `--all` sets the flag; names may be empty.
        assert_eq!(
            parse(&["stop".into(), "--all".into()]).unwrap().1,
            Command::Stop {
                names: vec![],
                all: true
            }
        );
        // Flags are not captured as names: `stop --all x` keeps all=true and name x.
        assert_eq!(
            parse(&["stop".into(), "--all".into(), "x".into()])
                .unwrap()
                .1,
            Command::Stop {
                names: vec!["x".into()],
                all: true
            }
        );
    }

    #[test]
    fn missing_required_args_are_usage_errors() {
        // `pull`/`compose`/`stop` without their argument → a usage error, not "not implemented".
        for argv in [vec!["pull"], vec!["compose"], vec!["stop"]] {
            let args: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
            assert!(matches!(parse(&args), Err(Error::Usage(_))), "{argv:?}");
        }
    }

    #[test]
    fn unknown_command_errors() {
        assert!(matches!(
            parse(&["frobnicate".into()]),
            Err(Error::UnknownCommand(_))
        ));
    }

    #[test]
    fn exec_parses_it_flag() {
        let argv: Vec<String> = ["exec", "svc", "-it", "--", "sh"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        match parse(&argv).unwrap().1 {
            Command::Exec {
                name, tty, command, ..
            } => {
                assert_eq!(name, "svc");
                assert!(tty, "-it should set tty");
                assert_eq!(command, vec!["sh".to_string()]);
            }
            other => panic!("expected Exec, got {other:?}"),
        }
        // Without -it, tty is false.
        let argv: Vec<String> = ["exec", "svc"].iter().map(|s| s.to_string()).collect();
        assert!(matches!(
            parse(&argv).unwrap().1,
            Command::Exec { tty: false, .. }
        ));
    }
}
