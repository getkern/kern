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
#[derive(Debug, PartialEq, Eq)]
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
    },
    /// `kern exec <name> [--env K=V] [--workdir <dir>] [-- cmd...]`: run a command in a box.
    Exec {
        name: String,
        command: Vec<String>,
        env: Vec<String>,
        workdir: Option<String>,
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
    /// A runtime subcommand recognised but not yet implemented in this 0.x scaffold.
    Pending(&'static str),
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
        // Recognised runtime verbs — implemented across the 0.x roadmap.
        Some("run") => Command::Pending("run"),
        Some(other) => return Err(Error::UnknownCommand(other.to_string())),
    };
    Ok((opts, cmd))
}

/// Parse the `box` subcommand. `--plan` previews the isolation sequence (no privileges);
/// `--rootfs <dir>` or `--image <ref>` runs the command (after `--`, default `/bin/sh`) in a
/// real sandbox. Without a rootfs/image and without `--plan` → `Pending`.
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
        }
    };
    Ok(cmd)
}

/// Parse `exec <name> [--env K=V] [--workdir <dir>] [-- cmd...]`. Missing name → usage error.
fn parse_exec(rest: &[&str]) -> Result<Command, Error> {
    let mut name: Option<&str> = None;
    let mut env: Vec<String> = Vec::new();
    let mut workdir: Option<String> = None;
    let mut command: Vec<String> = Vec::new();
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
    let (opts, cmd) = parse(args)?;
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
        }),
        Command::Exec {
            name,
            command,
            env,
            workdir,
        } => commands::exec(&name, &command, &env, workdir.as_deref()),
        Command::Search { query, json } => commands::search(&query, json),
        Command::Images { json } => commands::images(json),
        Command::Pull { image, dest } => commands::pull(&image, dest.as_deref()),
        Command::Stop { names, all } => commands::stop(&names, all),
        Command::Ps { json } => commands::ps(json),
        Command::Stats { json } => commands::stats(json),
        Command::Logs { name } => commands::logs(&name),
        Command::Top => commands::top(),
        Command::Compose { file } => commands::compose(&file),
        Command::Pending(name) => commands::pending(name, &opts),
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
}
