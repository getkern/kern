//! `kern-docker`: the `docker` command line, translated into kern's own and run by this binary.
//!
//! WHAT IT IS. A translator of argv, inside `kern`: called as `kern-docker` (a link to kern), it
//! reads a `docker ...` command, writes the kern command with the same meaning, and runs it through
//! kern's own parser. No daemon, no socket, no second program. Scripts that call the `docker` CLI
//! (`docker exec -i db psql < seed.sql`, `docker compose up -d --build`, `docker run --rm --network
//! stack_default img cmd`) then run against kern's boxes.
//!
//! WHAT IT REFUSES, LOUDLY. A docker flag is translated only from the tables below, which list the
//! flags whose meaning kern has the same. Anything else stops the command with exit 125 (docker's own
//! code for a refusal before a container runs), naming the flag. Nothing is ever handed to a docker
//! binary: a script that reached a real engine through this name would be running somewhere the
//! user did not choose.
//!
//! THE NAME `docker`. kern answers to it only where the user asked for it:
//! * level 1, `kern compat docker -- CMD`: that command, and every process it starts, finds
//!   `docker` and `docker-compose` in a folder of kern's at the front of PATH and carries
//!   `KERN_DOCKER_SHIM=1`; nothing outside that command changes;
//! * level 2, `kern compat docker link <dir>`: a `docker` link in a folder the user names, recorded
//!   in kern's config dir, shown by `kern doctor`, removed by `kern compat docker unlink <dir>`.
//!
//! A `docker` link to kern made any other way is refused with a line saying how to ask for it. Until
//! 2026-09-19 a symlink called `docker` made kern answer silently, and a benchmark published kern's
//! numbers under Docker's name because `docker --version` answered for kern. Two things close that
//! here: the name is answered only on request, and `docker version` / `docker --version` say kern
//! and kern's version, never a Docker version (a script that gates on Docker's version number
//! stops there, which is the honest outcome).
//!
//! `DOCKER_HOST` or `DOCKER_CONTEXT` set means the script asked for a particular engine, and kern is
//! not one: refused, naming the variable. A script calling `/usr/bin/docker` by its full path
//! bypasses level 1 by construction; that is said in the docs.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::error::Error;

/// The variable level 1 puts on the command it runs, and the only way besides a registered link
/// that kern answers to the name `docker`.
pub(crate) const SHIM_ENV: &str = "KERN_DOCKER_SHIM";

/// The exit code of a refusal: docker's own for "the command was refused before a container ran".
pub(crate) const REFUSED_EXIT: u8 = 125;

/// What argv[0] makes this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// `kern`, or any name that is not one of the shim's.
    Kern,
    /// `kern-docker`, or `docker` where it was asked for.
    Docker,
    /// `docker-compose` where it was asked for: `docker compose ...`.
    Compose,
}

/// A refusal, said by the caller as `kern-docker: <reason>` with [`REFUSED_EXIT`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refused(pub(crate) String);

/// A translated command: kern's argv, what to print on stdout after it succeeded (`run -d` and
/// `create` print the container's name where docker prints its id, so `id=$(docker run -d ...)`
/// gets something `docker logs "$id"` accepts), and a note for stderr before it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) argv: Vec<String>,
    pub(crate) print_after: Option<String>,
    pub(crate) note: Option<String>,
}

impl Plan {
    fn plain(argv: Vec<String>) -> Plan {
        Plan {
            argv,
            print_after: None,
            note: None,
        }
    }
}

/// The mode for an invocation. `invoked` is argv[0]'s file name; `shim_env` is [`SHIM_ENV`] set to
/// `1`; `registered` answers whether argv[0] is a link made by `kern compat docker link`, and is
/// asked only when the name is `docker`/`docker-compose` and the variable is not set (it reads PATH
/// and a file, which plain `kern` invocations never pay).
pub(crate) fn mode_for(
    invoked: &str,
    shim_env: bool,
    registered: impl FnOnce() -> bool,
) -> Result<Mode, Refused> {
    let asked = |m: Mode| -> Result<Mode, Refused> {
        if shim_env || registered() {
            Ok(m)
        } else {
            Err(Refused(format!(
                "this is kern, started under the name `{invoked}`. kern answers to that name only \
                 where it was asked to: inside `kern compat docker -- <command>`, or through a link \
                 made with `kern compat docker link <dir>`. Otherwise type `kern`, or call it \
                 `kern-docker`"
            )))
        }
    };
    match invoked {
        "kern-docker" => Ok(Mode::Docker),
        "docker" => asked(Mode::Docker),
        "docker-compose" => asked(Mode::Compose),
        _ => Ok(Mode::Kern),
    }
}

/// `DOCKER_HOST` / `DOCKER_CONTEXT`: a script that sets either asked for a particular engine.
pub(crate) fn engine_variable(get: impl Fn(&str) -> Option<OsString>) -> Option<Refused> {
    for var in ["DOCKER_HOST", "DOCKER_CONTEXT"] {
        if let Some(v) = get(var).filter(|v| !v.is_empty()) {
            return Some(Refused(format!(
                "{var} is set ({}): the command asks for a particular docker engine, and kern is \
                 not one. Unset {var} to run it with kern",
                v.to_string_lossy()
            )));
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------
// The flag tables. A flag is here only when kern's flag of that name does what docker's does.

/// A docker flag the shim translates.
struct Flag {
    /// The spellings docker accepts.
    docker: &'static [&'static str],
    /// The spelling written into kern's argv.
    kern: &'static str,
    /// Takes a value.
    value: bool,
}

const fn v(docker: &'static [&'static str], kern: &'static str) -> Flag {
    Flag {
        docker,
        kern,
        value: true,
    }
}

const fn b(docker: &'static [&'static str], kern: &'static str) -> Flag {
    Flag {
        docker,
        kern,
        value: false,
    }
}

/// `docker run`, onto `kern box`.
const RUN: &[Flag] = &[
    b(&["-d", "--detach"], "--detach"),
    b(&["--rm"], "--rm"),
    b(&["-i", "--interactive"], "-i"),
    b(&["-t", "--tty"], "-t"),
    b(&["--init"], "--init"),
    b(&["--privileged"], "--privileged"),
    b(&["--read-only"], "--read-only"),
    v(&["--name"], "--name"),
    v(&["-e", "--env"], "--env"),
    v(&["--env-file"], "--env-file"),
    v(&["-v", "--volume"], "--volume"),
    v(&["--mount"], "--mount"),
    v(&["-p", "--publish"], "--publish"),
    v(&["-w", "--workdir"], "--workdir"),
    v(&["-u", "--user"], "--user"),
    v(&["--network", "--net"], "--network"),
    v(&["--entrypoint"], "--entrypoint"),
    v(&["-l", "--label"], "--label"),
    v(&["-h", "--hostname"], "--hostname"),
    v(&["--add-host"], "--add-host"),
    v(&["--dns"], "--dns"),
    v(&["--dns-search"], "--dns-search"),
    v(&["--dns-option"], "--dns-option"),
    v(&["--tmpfs"], "--tmpfs"),
    v(&["--shm-size"], "--shm-size"),
    v(&["--pids-limit"], "--pids-limit"),
    v(&["--ulimit"], "--ulimit"),
    v(&["--sysctl"], "--sysctl"),
    v(&["--ipc"], "--ipc"),
    v(&["--cap-add"], "--cap-add"),
    v(&["--cap-drop"], "--cap-drop"),
    v(&["--group-add"], "--group-add"),
    v(&["--restart"], "--restart"),
    v(&["--stop-signal"], "--stop-signal"),
    v(&["--stop-timeout"], "--stop-timeout"),
    v(&["--health-cmd"], "--health-cmd"),
    v(&["--health-interval"], "--health-interval"),
    v(&["--health-retries"], "--health-retries"),
    v(&["--health-start-period"], "--health-start-period"),
    v(&["--health-start-interval"], "--health-start-interval"),
    v(&["--health-timeout"], "--health-timeout"),
    v(&["-m", "--memory"], "--memory"),
    v(&["--memory-swap"], "--memory-swap"),
    v(&["--memory-reservation"], "--memory-reservation"),
    v(&["--cpus"], "--cpus"),
    v(&["--cpuset-cpus"], "--cpuset-cpus"),
    v(&["--gpus"], "--gpus"),
    v(&["--device"], "--device"),
    v(&["--security-opt"], "--security-opt"),
    v(&["--log-driver"], "--log-driver"),
    v(&["--pull"], "--pull"),
];

/// `docker create`, onto `kern create`, whose parser spells these short.
const CREATE: &[Flag] = &[
    b(&["-i", "--interactive"], "-i"),
    b(&["-t", "--tty"], "-t"),
    v(&["--name"], "--name"),
    v(&["-e", "--env"], "-e"),
    v(&["-v", "--volume"], "-v"),
    v(&["-p", "--publish"], "-p"),
    v(&["-w", "--workdir"], "-w"),
    v(&["-u", "--user"], "-u"),
    v(&["-l", "--label"], "-l"),
];

const EXEC: &[Flag] = &[
    b(&["-i", "--interactive"], "-i"),
    b(&["-t", "--tty"], "-t"),
    v(&["-e", "--env"], "--env"),
    v(&["-u", "--user"], "--user"),
    v(&["-w", "--workdir"], "--workdir"),
];

const PS: &[Flag] = &[
    b(&["-a", "--all"], "--all"),
    b(&["-q", "--quiet"], "--quiet"),
    b(&["--no-trunc"], "--no-trunc"),
    v(&["--format"], "--format"),
    v(&["-f", "--filter"], "--filter"),
    v(&["-n", "--last"], "--last"),
];

const LOGS: &[Flag] = &[
    b(&["-f", "--follow"], "--follow"),
    b(&["-t", "--timestamps"], "--timestamps"),
    v(&["-n", "--tail"], "--tail"),
    v(&["--since"], "--since"),
    v(&["--until"], "--until"),
];

const INSPECT: &[Flag] = &[v(&["-f", "--format"], "--format")];
const RM: &[Flag] = &[b(&["-f", "--force"], "--force")];
const STOP: &[Flag] = &[v(&["-t", "--time", "--timeout"], "--time")];
const START: &[Flag] = &[b(&["-a", "--attach"], "--attach")];
const IMAGES: &[Flag] = &[
    v(&["--format"], "--format"),
    v(&["-f", "--filter"], "--filter"),
];
const RMI: &[Flag] = &[b(&["-f", "--force"], "--force")];
const PULL: &[Flag] = &[
    b(&["-q", "--quiet"], "--quiet"),
    v(&["--platform"], "--platform"),
];
const SAVE: &[Flag] = &[v(&["-o", "--output"], "--output")];
const LOAD: &[Flag] = &[v(&["-i", "--input"], "--input")];
const CP: &[Flag] = &[b(&["-a", "--archive"], "--archive")];
const STATS: &[Flag] = &[b(&["--no-stream"], "--no-stream")];
const LOGIN: &[Flag] = &[
    v(&["-u", "--username"], "--username"),
    v(&["-p", "--password"], "--password"),
    b(&["--password-stdin"], "--password-stdin"),
];
const BUILD: &[Flag] = &[
    v(&["-t", "--tag"], "--tag"),
    v(&["-f", "--file"], "--file"),
    v(&["--build-arg"], "--build-arg"),
    v(&["--target"], "--target"),
    b(&["--no-cache"], "--no-cache"),
    v(&["--platform"], "--platform"),
    v(&["--secret"], "--secret"),
    v(&["--ssh"], "--ssh"),
    b(&["-q", "--quiet"], "--quiet"),
    v(&["--progress"], "--progress"),
];
const VOLUME_LS: &[Flag] = &[
    b(&["-q", "--quiet"], "--quiet"),
    v(&["--format"], "--format"),
    v(&["-f", "--filter"], "--filter"),
];
const NETWORK_LS: &[Flag] = &[v(&["--format"], "--format")];
const NETWORK_INSPECT: &[Flag] = &[v(&["-f", "--format"], "--format")];
const VERSION_FLAGS: &[Flag] = &[v(&["-f", "--format"], "--format")];
const NONE: &[Flag] = &[];

/// The flags docker takes BEFORE the verb that choose an engine or a client config. Each is a
/// request kern cannot honour, so each is refused by name.
const GLOBAL_REFUSED: &[&str] = &[
    "-H",
    "--host",
    "-c",
    "--context",
    "--config",
    "-D",
    "--debug",
    "-l",
    "--log-level",
    "--tls",
    "--tlscacert",
    "--tlscert",
    "--tlskey",
    "--tlsverify",
];

// ---------------------------------------------------------------------------------------------
// Reading docker's grammar.

/// How a verb's positionals are laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tail {
    /// Every positional is an argument of the verb; flags may follow them.
    Args,
    /// The first positional names the container (or the image); every word after it is the
    /// command, verbatim, flags included.
    Command,
}

/// One flag as read: its table entry and its value.
struct Seen {
    flag: &'static Flag,
    value: Option<String>,
}

#[derive(Default)]
struct Parsed {
    flags: Vec<Seen>,
    positionals: Vec<String>,
    command: Vec<String>,
}

impl Parsed {
    /// The value of the last occurrence of a kern flag, as docker lets a later flag win.
    fn value_of(&self, kern: &str) -> Option<&str> {
        self.flags
            .iter()
            .rev()
            .find(|s| s.flag.kern == kern)
            .and_then(|s| s.value.as_deref())
    }

    fn has(&self, kern: &str) -> bool {
        self.flags.iter().any(|s| s.flag.kern == kern)
    }

    /// The flags in kern's spelling, in the order they were given.
    fn kern_flags(&self, skip: impl Fn(&Seen) -> bool) -> Vec<String> {
        let mut out = Vec::with_capacity(self.flags.len() * 2);
        for s in self.flags.iter().filter(|s| !skip(s)) {
            out.push(s.flag.kern.to_string());
            if let Some(v) = &s.value {
                out.push(v.clone());
            }
        }
        out
    }
}

fn lookup(table: &'static [Flag], spelling: &str) -> Option<&'static Flag> {
    table.iter().find(|f| f.docker.contains(&spelling))
}

fn untranslated(verb: &str, flag: &str) -> Refused {
    Refused(format!(
        "docker {verb} {flag}: kern has no flag with the same meaning, so the command is not run. \
         Remove {flag}, or write the command for kern (`kern help` lists its verbs and flags)"
    ))
}

fn needs_value(verb: &str, flag: &str) -> Refused {
    Refused(format!("docker {verb} {flag} needs a value"))
}

/// Read `args` (the words after the verb) in docker's grammar: `--name value`, `--name=value`,
/// `-x value`, `-xvalue` and `-x=value` for a short flag with a value, `-abc` for short flags
/// without one, `--flag=true|false` for a boolean, and `--` ending the flags.
fn parse(
    verb: &str,
    table: &'static [Flag],
    args: &[String],
    tail: Tail,
) -> Result<Parsed, Refused> {
    let mut p = Parsed::default();
    let mut only_positionals = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if !only_positionals && a == "--" {
            only_positionals = true;
            i += 1;
            continue;
        }
        if only_positionals || !a.starts_with('-') || a == "-" {
            p.positionals.push(a.to_string());
            if tail == Tail::Command {
                p.command = args
                    .get(i + 1..)
                    .map(<[String]>::to_vec)
                    .unwrap_or_default();
                return Ok(p);
            }
            i += 1;
            continue;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, val)) => (n, Some(val)),
                None => (long, None),
            };
            let spelling = format!("--{name}");
            let flag = lookup(table, &spelling).ok_or_else(|| untranslated(verb, &spelling))?;
            if flag.value {
                let value = match inline {
                    Some(val) => val.to_string(),
                    None => {
                        i += 1;
                        args.get(i)
                            .cloned()
                            .ok_or_else(|| needs_value(verb, &spelling))?
                    }
                };
                p.flags.push(Seen {
                    flag,
                    value: Some(value),
                });
            } else {
                match inline {
                    None | Some("true") => p.flags.push(Seen { flag, value: None }),
                    Some("false") => {}
                    Some(other) => {
                        return Err(Refused(format!(
                            "docker {verb} {spelling}={other}: {spelling} takes true or false"
                        )))
                    }
                }
            }
            i += 1;
            continue;
        }
        // Short flags: `-x`, `-xVALUE`, `-x=VALUE`, `-abc`.
        let body = &a[1..];
        let mut consumed_next = false;
        for (at, c) in body.char_indices() {
            let spelling = format!("-{c}");
            let Some(flag) = lookup(table, &spelling) else {
                let named = if body.chars().count() == 1 {
                    spelling
                } else {
                    format!("{spelling} (in {a})")
                };
                return Err(untranslated(verb, &named));
            };
            if !flag.value {
                p.flags.push(Seen { flag, value: None });
                continue;
            }
            let rest = &body[at + c.len_utf8()..];
            let value = if rest.is_empty() {
                consumed_next = true;
                args.get(i + 1)
                    .cloned()
                    .ok_or_else(|| needs_value(verb, &spelling))?
            } else {
                rest.strip_prefix('=').unwrap_or(rest).to_string()
            };
            p.flags.push(Seen {
                flag,
                value: Some(value),
            });
            break;
        }
        i += if consumed_next { 2 } else { 1 };
    }
    Ok(p)
}

/// A verb whose kern form is `<kern verb> <flags> <positionals>`.
fn simple(
    verb: &str,
    kern: &[&str],
    table: &'static [Flag],
    args: &[String],
) -> Result<Plan, Refused> {
    let p = parse(verb, table, args, Tail::Args)?;
    let mut argv: Vec<String> = kern.iter().map(|s| (*s).to_string()).collect();
    argv.extend(p.kern_flags(|_| false));
    argv.extend(p.positionals);
    Ok(Plan::plain(argv))
}

/// A name for a container docker would have named itself: `kd-` and 8 hex digits from the kernel's
/// random source. `None` if it cannot be read, which the caller turns into a refusal: a name made
/// from the clock could collide with a box started in the same second.
fn generated_name() -> Option<String> {
    use std::io::Read;
    let mut bytes = [0u8; 4];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .ok()?;
    Some(format!(
        "kd-{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    ))
}

/// The note `run` says when the box gets kern's default network rather than docker's.
const NETWORK_NOTE: &str = "kern-docker: run without --network: the box has no network, which is \
     kern's default (docker's default bridge reaches the internet). --network <project>_default \
     joins a running stack with its outbound; --network host shares this machine's";

/// `docker run`/`docker create`: flags, then the image, then the command.
fn run_like(
    verb: &str,
    kern_verb: &str,
    table: &'static [Flag],
    args: &[String],
    name: impl FnOnce() -> Option<String>,
) -> Result<Plan, Refused> {
    let p = parse(verb, table, args, Tail::Command)?;
    let Some(image) = p.positionals.first().cloned() else {
        return Err(Refused(format!("docker {verb} needs an image")));
    };
    let detach = p.has("--detach");
    // docker's default network is a bridge with outbound; kern's is none. `bridge` and `default`
    // name that default, so they are taken as "the default" and said, never sent to kern as a pod.
    let network = p.value_of("--network");
    let default_net = matches!(network, None | Some("bridge") | Some("default"));
    let mut argv = vec![kern_verb.to_string()];
    argv.extend(p.kern_flags(|s| {
        s.flag.kern == "--network" && matches!(s.value.as_deref(), Some("bridge") | Some("default"))
    }));
    let given = p.value_of("--name").map(str::to_string);
    let announce = kern_verb == "create" || detach;
    let name = match given {
        Some(n) => Some(n),
        None if announce => {
            let n = name().ok_or_else(|| {
                Refused(format!(
                    "docker {verb}: no --name, and no random name could be made (/dev/urandom is \
                     unreadable); give one with --name"
                ))
            })?;
            argv.push("--name".to_string());
            argv.push(n.clone());
            Some(n)
        }
        None => None,
    };
    argv.push("--image".to_string());
    argv.push(image);
    if !p.command.is_empty() {
        argv.push("--".to_string());
        argv.extend(p.command);
    }
    Ok(Plan {
        argv,
        print_after: if announce { name } else { None },
        note: (kern_verb == "box" && default_net).then(|| NETWORK_NOTE.to_string()),
    })
}

/// `docker exec [flags] CONTAINER CMD...`: the command after `--`, so no word of it is read as a
/// kern flag.
fn exec(args: &[String]) -> Result<Plan, Refused> {
    let p = parse("exec", EXEC, args, Tail::Command)?;
    let Some(container) = p.positionals.first().cloned() else {
        return Err(Refused(
            "docker exec needs a container and a command".to_string(),
        ));
    };
    if p.command.is_empty() {
        return Err(Refused(format!(
            "docker exec {container}: a command is needed"
        )));
    }
    let mut argv = vec!["exec".to_string()];
    argv.extend(p.kern_flags(|_| false));
    argv.push(container);
    argv.push("--".to_string());
    argv.extend(p.command);
    Ok(Plan::plain(argv))
}

fn version(args: &[String]) -> Result<Plan, Refused> {
    let p = parse("version", VERSION_FLAGS, args, Tail::Args)?;
    if let Some(extra) = p.positionals.first() {
        return Err(Refused(format!(
            "docker version takes no argument ('{extra}')"
        )));
    }
    let ver = kern_common::VERSION;
    let text = match p.value_of("--format").map(str::trim) {
        None => format!(
            "Client: kern-docker\n Version:  {ver}\n\nServer: kern\n Version:  {ver}\n \
             (this docker command line is answered by kern, translated into kern's own)"
        ),
        Some("{{.Client.Version}}") | Some("{{.Server.Version}}") => ver.to_string(),
        Some(other) => {
            return Err(Refused(format!(
                "docker version --format {other}: kern answers {{{{.Client.Version}}}} and \
                 {{{{.Server.Version}}}} (both kern's version, {ver})"
            )))
        }
    };
    Ok(Plan {
        argv: Vec::new(),
        print_after: Some(text),
        note: None,
    })
}

/// `docker volume <verb>`.
fn volume(args: &[String]) -> Result<Plan, Refused> {
    let (sub, rest) = split_sub(args);
    match sub {
        Some("ls" | "list") => simple("volume ls", &["volume", "ls"], VOLUME_LS, rest),
        Some("rm" | "remove") => simple("volume rm", &["volume", "rm"], NONE, rest),
        Some("create") => simple("volume create", &["volume", "create"], NONE, rest),
        Some("inspect") => simple("volume inspect", &["volume", "inspect"], NONE, rest),
        Some(other) => Err(Refused(format!(
            "docker volume {other}: not translated (ls, rm, create and inspect are)"
        ))),
        None => Err(Refused(
            "docker volume needs a verb: ls, rm, create, inspect".to_string(),
        )),
    }
}

/// `docker network <verb>`.
fn network(args: &[String]) -> Result<Plan, Refused> {
    let (sub, rest) = split_sub(args);
    match sub {
        Some("ls" | "list") => simple("network ls", &["network", "ls"], NETWORK_LS, rest),
        Some("inspect") => simple(
            "network inspect",
            &["network", "inspect"],
            NETWORK_INSPECT,
            rest,
        ),
        Some("create") => simple("network create", &["network", "create"], NONE, rest),
        Some("rm" | "remove") => simple("network rm", &["network", "rm"], NONE, rest),
        Some(other) => Err(Refused(format!(
            "docker network {other}: not translated (ls, inspect, create and rm are)"
        ))),
        None => Err(Refused(
            "docker network needs a verb: ls, inspect, create, rm".to_string(),
        )),
    }
}

fn split_sub(args: &[String]) -> (Option<&str>, &[String]) {
    match args.split_first() {
        Some((first, rest)) => (Some(first.as_str()), rest),
        None => (None, &[]),
    }
}

/// One docker verb and the words after it.
fn verb(name: &str, args: &[String]) -> Result<Plan, Refused> {
    match name {
        "run" => run_like("run", "box", RUN, args, generated_name),
        "create" => run_like("create", "create", CREATE, args, generated_name),
        "exec" => exec(args),
        "ps" => simple("ps", &["ps"], PS, args),
        "logs" => simple("logs", &["logs"], LOGS, args),
        "inspect" => simple("inspect", &["inspect"], INSPECT, args),
        "rm" => simple("rm", &["rm"], RM, args),
        "stop" => simple("stop", &["stop"], STOP, args),
        "restart" => simple("restart", &["restart"], STOP, args),
        "start" => simple("start", &["start"], START, args),
        "kill" => simple("kill", &["kill"], NONE, args),
        "images" => simple("images", &["images"], IMAGES, args),
        "rmi" => simple("rmi", &["rmi"], RMI, args),
        "pull" => simple("pull", &["pull"], PULL, args),
        "push" => simple("push", &["push"], NONE, args),
        "tag" => simple("tag", &["tag"], NONE, args),
        "save" => simple("save", &["save"], SAVE, args),
        "load" => simple("load", &["load"], LOAD, args),
        "history" => simple("history", &["history"], NONE, args),
        "cp" => simple("cp", &["cp"], CP, args),
        "stats" => simple("stats", &["stats"], STATS, args),
        "wait" => simple("wait", &["wait"], NONE, args),
        "rename" => simple("rename", &["rename"], NONE, args),
        "port" => simple("port", &["port"], NONE, args),
        "login" => simple("login", &["login"], LOGIN, args),
        "logout" => simple("logout", &["logout"], NONE, args),
        "info" => simple("info", &["info"], NONE, args),
        "build" => simple("build", &["build"], BUILD, args),
        "version" => version(args),
        "volume" => volume(args),
        "network" => network(args),
        // `docker compose`: kern's compose reads the same file and the same flags, with refusals
        // of its own for the ones it does not take.
        "compose" => compose(args),
        "container" => {
            let (sub, rest) = split_sub(args);
            match sub {
                Some("ls" | "list" | "ps") => verb("ps", rest),
                Some("rm" | "remove") => verb("rm", rest),
                Some(
                    s @ ("run" | "create" | "exec" | "logs" | "inspect" | "stop" | "restart"
                    | "start" | "kill" | "cp" | "stats" | "wait" | "rename" | "port"),
                ) => verb(s, rest),
                Some(other) => Err(Refused(format!("docker container {other}: not translated"))),
                None => Err(Refused("docker container needs a verb".to_string())),
            }
        }
        "image" => {
            let (sub, rest) = split_sub(args);
            match sub {
                Some("ls" | "list") => verb("images", rest),
                Some("rm" | "remove") => verb("rmi", rest),
                Some(
                    s @ ("pull" | "push" | "tag" | "save" | "load" | "history" | "build"
                    | "inspect"),
                ) => verb(s, rest),
                Some(other) => Err(Refused(format!("docker image {other}: not translated"))),
                None => Err(Refused("docker image needs a verb".to_string())),
            }
        }
        other => Err(Refused(format!(
            "docker {other}: not translated into kern, so it is not run (kern never hands a \
             command to a docker engine)"
        ))),
    }
}

/// The help the shim prints for `docker`, `docker help` and `docker --help`.
const HELP: &str = "kern-docker: the docker command line, answered by kern.

Translated: run, create, exec, ps, logs, inspect, rm, stop, restart, start, kill, images, rmi, pull,
push, tag, save, load, history, cp, stats, wait, rename, port, login, logout, info, build, version,
volume ls|rm|create|inspect, network ls|inspect|create|rm, container <verb>, image <verb>, compose.

A flag is translated only when kern's flag of that name means the same; any other stops the
command with exit 125, naming it. Nothing is handed to a docker engine.";

/// `docker compose ...` / `docker-compose ...`: kern's compose, except `version`, which says kern
/// (`--short` alone prints the bare version, as compose's does) instead of looking for a file.
fn compose(args: &[String]) -> Result<Plan, Refused> {
    if args.first().map(String::as_str) == Some("version") {
        let ver = kern_common::VERSION;
        let text = match args.get(1..).unwrap_or_default() {
            [] => format!("kern-docker compose {ver} (kern's compose, answering the docker compose command line)"),
            [f] if f == "--short" => ver.to_string(),
            [f, ..] => return Err(untranslated("compose version", f)),
        };
        return Ok(Plan {
            argv: Vec::new(),
            print_after: Some(text),
            note: None,
        });
    }
    let mut argv = vec!["compose".to_string()];
    argv.extend(args.iter().cloned());
    Ok(Plan::plain(argv))
}

/// Translate a full docker argv (the words after `docker`).
pub(crate) fn translate(mode: Mode, args: &[String]) -> Result<Plan, Refused> {
    if mode == Mode::Compose {
        return compose(args);
    }
    let Some(first) = args.first().map(String::as_str) else {
        return Ok(Plan {
            argv: Vec::new(),
            print_after: Some(HELP.to_string()),
            note: None,
        });
    };
    match first {
        "help" | "--help" => Ok(Plan {
            argv: Vec::new(),
            print_after: Some(HELP.to_string()),
            note: None,
        }),
        "-v" | "--version" => Ok(Plan {
            argv: Vec::new(),
            print_after: Some(format!(
                "kern-docker {v} (kern {v}: this docker command line is answered by kern)",
                v = kern_common::VERSION
            )),
            note: None,
        }),
        f if f.starts_with('-') => {
            let spelling = f.split_once('=').map_or(f, |(n, _)| n);
            if GLOBAL_REFUSED.contains(&spelling) {
                Err(Refused(format!(
                    "docker {spelling}: it chooses a docker engine or client config, and kern is \
                     not one; remove it to run the command with kern"
                )))
            } else {
                Err(Refused(format!(
                    "docker {spelling}: not translated into kern, so the command is not run"
                )))
            }
        }
        name => verb(name, &args[1..]),
    }
}

// ---------------------------------------------------------------------------------------------
// Level 2: links the user asked for, recorded in kern's config dir.

/// The file listing the `docker` links made by `kern compat docker link`, one absolute path a line.
fn links_file() -> Option<PathBuf> {
    crate::config::default_path().and_then(|p| p.parent().map(|d| d.join("docker-links")))
}

fn read_links() -> Vec<PathBuf> {
    let Some(f) = links_file() else {
        return Vec::new();
    };
    std::fs::read_to_string(f)
        .map(|t| parse_links(&t))
        .unwrap_or_default()
}

/// The lines of the links file that are absolute paths; anything else is not a link kern made.
fn parse_links(text: &str) -> Vec<PathBuf> {
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with('/'))
        .map(PathBuf::from)
        .collect()
}

fn write_links(links: &[PathBuf]) -> Result<(), Error> {
    let f = links_file().ok_or_else(|| {
        Error::Cli("no config directory (HOME and XDG_CONFIG_HOME are both unset)".to_string())
    })?;
    let dir = f
        .parent()
        .ok_or_else(|| Error::Cli(format!("{} has no parent directory", f.display())))?;
    std::fs::create_dir_all(dir)
        .map_err(|e| Error::Cli(format!("cannot create {}: {e}", dir.display())))?;
    let mut text = String::new();
    for l in links {
        text.push_str(&l.to_string_lossy());
        text.push('\n');
    }
    let tmp = dir.join(format!(".docker-links.{}", std::process::id()));
    std::fs::write(&tmp, text)
        .and_then(|()| std::fs::rename(&tmp, &f))
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            Error::Cli(format!("cannot write {}: {e}", f.display()))
        })
}

/// The path argv[0] ran from: itself when it has a slash (made absolute against the current
/// directory), else the first match in PATH, which is the one the shell ran.
fn invoked_path(arg0: &OsStr, path_var: Option<OsString>) -> Option<PathBuf> {
    let p = Path::new(arg0);
    if arg0.as_encoded_bytes().contains(&b'/') {
        return if p.is_absolute() {
            Some(p.to_path_buf())
        } else {
            std::env::current_dir().ok().map(|d| d.join(p))
        };
    }
    std::env::split_paths(&path_var?)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(p))
        .find(|c| std::fs::symlink_metadata(c).is_ok())
}

/// Does `link` resolve to this very binary?
fn points_to_this_kern(link: &Path) -> bool {
    match (
        std::fs::canonicalize(link),
        crate::selfupdate::this_exe()
            .and_then(|e| std::fs::canonicalize(&e).map_err(|err| Error::Cli(err.to_string()))),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Is argv[0] a link `kern compat docker link` made, still pointing at this kern?
pub(crate) fn invoked_through_registered_link(arg0: &OsStr) -> bool {
    let Some(p) = invoked_path(arg0, crate::global_env("PATH")) else {
        return false;
    };
    read_links().iter().any(|l| l == &p) && points_to_this_kern(&p)
}

/// The first `docker` in PATH, which is the one a script calling `docker` gets.
fn docker_in_path() -> Option<PathBuf> {
    invoked_path(OsStr::new("docker"), crate::global_env("PATH"))
}

fn absolute_dir(dir: &str) -> Result<PathBuf, Error> {
    let d = std::fs::canonicalize(dir)
        .map_err(|e| Error::Cli(format!("compat docker: '{dir}': {e}")))?;
    if !d.is_dir() {
        return Err(Error::Cli(format!(
            "compat docker: '{}' is not a directory",
            d.display()
        )));
    }
    Ok(d)
}

/// What a script calling `docker` gets, for `link` and `status`.
/// `in_path` is [`docker_in_path`], read once by the caller for every link it reports on.
fn path_verdict(link: &Path, in_path: Option<&Path>) -> String {
    match in_path {
        Some(first) if first == link => {
            "it comes first in PATH: a script calling `docker` gets kern".to_string()
        }
        Some(first) => format!(
            "another docker comes first in PATH ({}), and that one is what a script calling \
             `docker` gets; put {} before it in PATH, or call the link by its path",
            first.display(),
            link.parent()
                .map_or_else(String::new, |d| d.display().to_string())
        ),
        None => format!(
            "{} is not in PATH: add it, or call the link by its path",
            link.parent()
                .map_or_else(String::new, |d| d.display().to_string())
        ),
    }
}

fn link(dir: &str) -> Result<(), Error> {
    let d = absolute_dir(dir)?;
    let target = d.join("docker");
    let exe = crate::selfupdate::this_exe()?;
    match std::fs::symlink_metadata(&target) {
        Ok(_) if points_to_this_kern(&target) => {}
        Ok(_) => {
            return Err(Error::Cli(format!(
                "compat docker link: {} exists and is not kern, and kern does not replace it",
                target.display()
            )))
        }
        Err(_) => std::os::unix::fs::symlink(&exe, &target).map_err(|e| {
            Error::Cli(format!(
                "compat docker link: cannot create {}: {e}",
                target.display()
            ))
        })?,
    }
    let mut links = read_links();
    if !links.contains(&target) {
        links.push(target.clone());
        write_links(&links)?;
    }
    println!(
        "linked: {} -> {} ({})",
        target.display(),
        exe.display(),
        path_verdict(&target, docker_in_path().as_deref())
    );
    println!("remove it with: kern compat docker unlink {}", d.display());
    Ok(())
}

fn unlink(dir: &str) -> Result<(), Error> {
    let d = absolute_dir(dir)?;
    let target = d.join("docker");
    let mut links = read_links();
    let was_listed = links.contains(&target);
    links.retain(|l| l != &target);
    if was_listed {
        write_links(&links)?;
    }
    match std::fs::symlink_metadata(&target) {
        Ok(m) if m.file_type().is_symlink() && points_to_this_kern(&target) => {
            std::fs::remove_file(&target).map_err(|e| {
                Error::Cli(format!(
                    "compat docker unlink: cannot remove {}: {e}",
                    target.display()
                ))
            })?;
            println!("removed: {}", target.display());
            Ok(())
        }
        Ok(_) => Err(Error::Cli(format!(
            "compat docker unlink: {} is not a link to kern, so it is left in place{}",
            target.display(),
            if was_listed {
                " (it is no longer recorded)"
            } else {
                ""
            }
        ))),
        Err(_) if was_listed => {
            println!(
                "{} was already gone; it is no longer recorded",
                target.display()
            );
            Ok(())
        }
        Err(_) => Err(Error::Cli(format!(
            "compat docker unlink: there is no {}",
            target.display()
        ))),
    }
}

fn status() -> Result<(), Error> {
    let links = read_links();
    if links.is_empty() {
        println!("no docker link made by kern (`kern compat docker link <dir>` makes one)");
    }
    let in_path = docker_in_path();
    for l in &links {
        let state = if points_to_this_kern(l) {
            path_verdict(l, in_path.as_deref())
        } else if std::fs::symlink_metadata(l).is_ok() {
            "it no longer points at this kern".to_string()
        } else {
            "it is gone".to_string()
        };
        println!("{}: {state}", l.display());
    }
    match in_path {
        Some(p) if links.contains(&p) => {}
        Some(p) => println!("`docker` in PATH: {} (not kern's)", p.display()),
        None => println!("`docker` in PATH: none"),
    }
    println!("{}", socket_status());
    Ok(())
}

/// The `kern doctor` row: present only when a link was made.
pub(crate) fn doctor_row() -> Option<(bool, String, String)> {
    let links = read_links();
    let first = links.first()?;
    let ours = points_to_this_kern(first);
    let in_path = docker_in_path();
    let ok = ours && in_path.as_deref() == Some(first.as_path());
    let more = match links.len() {
        0 | 1 => String::new(),
        n => format!(" (and {} more)", n - 1),
    };
    let state = if ours {
        path_verdict(first, in_path.as_deref())
    } else {
        "it no longer points at this kern".to_string()
    };
    Some((
        ok,
        format!("docker link: {}{more}: {state}", first.display()),
        "`kern compat docker status` lists them, `kern compat docker unlink <dir>` removes one"
            .to_string(),
    ))
}

// ---------------------------------------------------------------------------------------------
// Level 1: one command, with `docker` answered by kern.

/// A folder name that is a process id, so the sweep below can only ever remove what level 1 made.
fn is_pid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 10 && n.bytes().all(|c| c.is_ascii_digit())
}

fn pid_alive(pid: i32) -> bool {
    // SAFETY: kill with signal 0 only checks that the process exists.
    pid > 0
        && (unsafe { libc::kill(pid, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
}

/// Remove the folders of level-1 runs whose process is gone (one killed before it cleaned up).
fn sweep_stale(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(n) = name.to_str().filter(|n| is_pid_name(n)) else {
            continue;
        };
        if n.parse::<i32>().is_ok_and(|pid| !pid_alive(pid)) {
            let p = root.join(n);
            if p.parent() == Some(root) {
                let _ = std::fs::remove_dir_all(&p);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The Docker API socket: `serve`, `enable`, `disable`.

/// The units `enable` writes, in the user's systemd directory.
const SOCKET_UNIT: &str = "kern-compat-docker.socket";
const SERVICE_UNIT: &str = "kern-compat-docker.service";
/// The first line of a unit kern wrote: `disable` removes only a file that starts with it.
const UNIT_MARK: &str =
    "# Written by `kern compat docker enable`; `kern compat docker disable` removes it.";
/// A socket-started server exits after this long without a connection; systemd starts it again.
const IDLE_EXIT: std::time::Duration = std::time::Duration::from_secs(60);

/// `$XDG_RUNTIME_DIR/kern/compat-docker.sock`: in kern's runtime root, which no box may mount.
fn socket_path() -> Result<PathBuf, Error> {
    crate::registry::runtime_subdir_public("compat-docker")
        .ok()
        .and_then(|d| d.parent().map(|r| r.join("compat-docker.sock")))
        .ok_or_else(|| Error::Cli("compat docker: kern has no runtime directory".into()))
}

fn export_line(path: &Path) -> String {
    format!(
        "export DOCKER_HOST=unix://{} TESTCONTAINERS_RYUK_DISABLED=true",
        path.display()
    )
}

/// systemd passed the listening socket to THIS process (`LISTEN_PID`, `LISTEN_FDS=1`).
fn socket_activated() -> bool {
    // SAFETY: getpid has no preconditions.
    let me = unsafe { libc::getpid() }.to_string();
    crate::global_env("LISTEN_PID").is_some_and(|p| p == OsStr::new(&me))
        && crate::global_env("LISTEN_FDS").is_some_and(|n| n == "1")
}

/// `kern compat docker serve`: the Docker Engine API on `$XDG_RUNTIME_DIR/kern/compat-docker.sock`,
/// every request run as a `kern` command by this binary. In the foreground it runs until killed;
/// started by the socket unit it exits when idle.
fn serve(args: &[String]) -> Result<(), Error> {
    let kern = std::env::current_exe().map_err(|e| {
        Error::Cli(format!(
            "compat docker serve: cannot name kern's own binary: {e}"
        ))
    })?;
    let (listen, idle) = match args {
        [] if socket_activated() => (kern_compat::Listen::Inherited(3), Some(IDLE_EXIT)),
        [] => {
            let p = socket_path()?;
            eprintln!("  {}", export_line(&p));
            (kern_compat::Listen::Path(p), None)
        }
        // Started by a bridge (`__stdio`) where no systemd user manager is: it exits when idle,
        // as the socket unit's does.
        [f] if f == "--exit-when-idle" => {
            (kern_compat::Listen::Path(socket_path()?), Some(IDLE_EXIT))
        }
        // NO OTHER PATH: kern's runtime root is the one place no box may mount, whole or by a
        // parent; a socket in any other directory could be handed to a box with that directory.
        _ => return Err(Error::Usage("compat docker serve")),
    };
    kern_compat::serve(listen, kern, idle)
        .map_err(|e| Error::Cli(format!("compat docker serve: {e}")))
}

/// Connect to the API socket; with `start`, start a server first when none answers (WSL, where no
/// systemd user manager starts one), waiting up to 3 s for it to listen.
fn connect_api(start: bool) -> Result<std::os::unix::net::UnixStream, Error> {
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    let path = socket_path()?;
    if let Ok(s) = UnixStream::connect(&path) {
        return Ok(s);
    }
    if !start {
        return Err(Error::Cli(format!(
            "compat docker: nothing serves {}",
            path.display()
        )));
    }
    let kern = std::env::current_exe()
        .map_err(|e| Error::Cli(format!("compat docker: cannot name kern's own binary: {e}")))?;
    // Its own process group, stdio on /dev/null: it outlives this bridge and the terminal.
    std::process::Command::new(kern)
        .args(["compat", "docker", "serve", "--exit-when-idle"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| Error::Cli(format!("compat docker: cannot start the server: {e}")))?;
    for _ in 0..300 {
        if let Ok(s) = UnixStream::connect(&path) {
            return Ok(s);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Err(Error::Cli(format!(
        "compat docker: the server did not listen on {} within 3 s",
        path.display()
    )))
}

/// `kern compat docker __stdio [--windows-peer <key>]`: one connection to the API carried over this
/// process's stdin and stdout, for `kern.exe`'s named pipe on Windows. Bytes only: the HTTP, and
/// the streams an attach or exec hands over, are the server's. `--windows-peer` names the Windows
/// process behind the pipe, which the server files a test session under (it cannot watch a
/// Windows pid; `kern.exe` tells it when that process ends, through `__session-ended`).
fn stdio_bridge(args: &[String]) -> Result<(), Error> {
    use std::io::{Read, Write};
    match args {
        [] => {}
        [f, k] if f == "--windows-peer" && kern_compat::valid_peer_key(k) => {}
        _ => {
            return Err(Error::Usage(
                "compat docker __stdio [--windows-peer <pid>-<time>]",
            ))
        }
    }
    let sock = connect_api(true)?;
    let mut up = sock
        .try_clone()
        .map_err(|e| Error::Cli(format!("compat docker: {e}")))?;
    let lift = std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 64 * 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = up.shutdown(std::net::Shutdown::Write);
    });
    let mut down = sock;
    let mut stdout = std::io::stdout().lock();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match down.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stdout
                    .write_all(&buf[..n])
                    .and_then(|()| stdout.flush())
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    // The answer is over: the stdin reader may still wait on a client that says nothing more.
    // The process ends here and takes it along; joining would wait for the client.
    drop(lift);
    Ok(())
}

/// `kern compat docker __session-ended <key>`: the Windows process behind a test session ended
/// (`kern.exe` saw it); the server removes that session's containers.
fn session_ended(args: &[String]) -> Result<(), Error> {
    use std::io::{Read, Write};
    let [key] = args else {
        return Err(Error::Usage("compat docker __session-ended <pid>-<time>"));
    };
    if !kern_compat::valid_peer_key(key) {
        return Err(Error::Usage("compat docker __session-ended <pid>-<time>"));
    }
    // No server, no containers it filed: nothing to remove.
    let Ok(mut s) = connect_api(false) else {
        return Ok(());
    };
    let req = format!(
        "POST /_kern/session-ended?owner={key} HTTP/1.1\r\nHost: kern\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes())
        .map_err(|e| Error::Cli(format!("compat docker: {e}")))?;
    let mut answer = String::new();
    let _ = s.read_to_string(&mut answer);
    if answer.starts_with("HTTP/1.1 204") {
        Ok(())
    } else {
        Err(Error::Cli(format!(
            "compat docker: the server answered {:?}",
            answer.lines().next().unwrap_or_default()
        )))
    }
}

/// `~/.config/systemd/user` (or `$XDG_CONFIG_HOME/systemd/user`).
fn unit_dir() -> Result<PathBuf, Error> {
    crate::xdg_var("XDG_CONFIG_HOME")
        .or_else(|| {
            crate::global_env("HOME")
                .filter(|h| !h.is_empty())
                .map(|h| PathBuf::from(h).join(".config"))
        })
        .map(|c| c.join("systemd").join("user"))
        .ok_or_else(|| Error::Cli("compat docker: neither XDG_CONFIG_HOME nor HOME is set".into()))
}

/// `systemctl --user ARGS`, its status and stderr.
fn systemctl_user(args: &[&str]) -> (bool, String) {
    match std::process::Command::new("systemctl")
        .arg("--user")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
    {
        Ok(o) => (
            o.status.success(),
            String::from_utf8_lossy(&o.stderr).trim().to_string(),
        ),
        Err(e) => (false, format!("cannot run systemctl: {e}")),
    }
}

/// A unit file kern wrote, judged by its first line.
fn is_ours(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|t| t.lines().next() == Some(UNIT_MARK))
}

/// Write `text` to `path` unless a file that is not kern's is there.
fn write_unit(path: &Path, text: &str) -> Result<(), Error> {
    if std::fs::symlink_metadata(path).is_ok() && !is_ours(path) {
        return Err(Error::Cli(format!(
            "compat docker enable: {} exists and kern did not write it: not replaced",
            path.display()
        )));
    }
    std::fs::write(path, text).map_err(|e| {
        Error::Cli(format!(
            "compat docker enable: cannot write {}: {e}",
            path.display()
        ))
    })
}

/// `kern compat docker enable`: a `systemd --user` socket unit on
/// `$XDG_RUNTIME_DIR/kern/compat-docker.sock`; the server starts at the first connection and exits
/// after a minute without one. Boxes it started keep running when it exits (`KillMode=process`).
fn enable() -> Result<(), Error> {
    let (reachable, why) = systemctl_user(&["show-environment"]);
    if !reachable {
        return Err(Error::Cli(format!(
            "compat docker enable: no systemd user manager here ({why}): run `kern compat docker serve` \
             in the foreground instead, a process that runs until it is stopped"
        )));
    }
    let kern = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| {
            Error::Cli(format!(
                "compat docker enable: cannot name kern's own binary: {e}"
            ))
        })?;
    let kern = kern.to_str().filter(|k| !k.contains(char::is_whitespace)).ok_or_else(|| {
        Error::Cli(format!(
            "compat docker enable: kern's path {} has a space or is not UTF-8, which a unit's ExecStart cannot carry as written",
            kern.display()
        ))
    })?.to_string();
    let dir = unit_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| {
        Error::Cli(format!(
            "compat docker enable: cannot create {}: {e}",
            dir.display()
        ))
    })?;
    write_unit(
        &dir.join(SOCKET_UNIT),
        &format!(
            "{UNIT_MARK}\n[Unit]\nDescription=kern: the Docker API socket (kern compat docker)\n\n[Socket]\n\
             ListenStream=%t/kern/compat-docker.sock\nSocketMode=0600\nDirectoryMode=0700\nRemoveOnStop=true\n\n\
             [Install]\nWantedBy=sockets.target\n"
        ),
    )?;
    write_unit(
        &dir.join(SERVICE_UNIT),
        &format!(
            "{UNIT_MARK}\n[Unit]\nDescription=kern: the Docker API, answered by kern\nRequires={SOCKET_UNIT}\n\n\
             [Service]\nExecStart={kern} compat docker serve\n# The boxes it started outlive it.\nKillMode=process\n"
        ),
    )?;
    let (ok, why) = systemctl_user(&["daemon-reload"]);
    if !ok {
        return Err(Error::Cli(format!(
            "compat docker enable: systemctl --user daemon-reload: {why}"
        )));
    }
    let (ok, why) = systemctl_user(&["enable", "--now", SOCKET_UNIT]);
    if !ok {
        return Err(Error::Cli(format!(
            "compat docker enable: systemctl --user enable --now {SOCKET_UNIT}: {why}"
        )));
    }
    let path = socket_path()?;
    println!(
        "the Docker API socket is on: {}, served by kern from the first connection\n  {}",
        path.display(),
        export_line(&path)
    );
    Ok(())
}

/// `kern compat docker disable`: the socket unit off and both units removed.
fn disable() -> Result<(), Error> {
    let dir = unit_dir()?;
    let files = [dir.join(SOCKET_UNIT), dir.join(SERVICE_UNIT)];
    if !files.iter().any(|f| is_ours(f)) {
        println!(
            "the Docker API socket is not enabled (no unit written by kern in {})",
            dir.display()
        );
        return Ok(());
    }
    let _ = systemctl_user(&["disable", "--now", SOCKET_UNIT]);
    let _ = systemctl_user(&["stop", SERVICE_UNIT]);
    for f in files.iter().filter(|f| is_ours(f)) {
        std::fs::remove_file(f).map_err(|e| {
            Error::Cli(format!(
                "compat docker disable: cannot remove {}: {e}",
                f.display()
            ))
        })?;
    }
    let _ = systemctl_user(&["daemon-reload"]);
    println!("the Docker API socket is off; boxes it started keep running");
    Ok(())
}

/// The `status` line of the socket.
fn socket_status() -> String {
    let enabled = unit_dir().is_ok_and(|d| is_ours(&d.join(SOCKET_UNIT)));
    let path = socket_path()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    if !enabled {
        return format!(
            "Docker API socket: off (`kern compat docker enable`, or `kern compat docker serve` in the foreground){}",
            if path.is_empty() { String::new() } else { format!("; it would be {path}") }
        );
    }
    let listening = systemctl_user(&["is-active", "--quiet", SOCKET_UNIT]).0;
    let serving = systemctl_user(&["is-active", "--quiet", SERVICE_UNIT]).0;
    format!(
        "Docker API socket: {} on {path}{}",
        if listening {
            "enabled, listening"
        } else {
            "enabled, NOT listening (systemctl --user status kern-compat-docker.socket)"
        },
        if serving {
            ", the server is running (it exits after a minute without a client)"
        } else {
            ", the server starts at the next connection"
        }
    )
}

fn run_wrapped(cmd: &[String]) -> Result<(), Error> {
    use std::os::unix::process::ExitStatusExt;
    let Some((prog, rest)) = cmd.split_first() else {
        return Err(Error::Usage(
            "compat docker [--] <command> [args...] | link <dir> | unlink <dir> | status",
        ));
    };
    let root = crate::registry::runtime_subdir("compat-docker")
        .map_err(|e| Error::Cli(format!("compat docker: no runtime directory: {e}")))?;
    sweep_stale(&root);
    let dir = root.join(std::process::id().to_string());
    std::fs::create_dir_all(&dir).map_err(|e| {
        Error::Cli(format!(
            "compat docker: cannot create {}: {e}",
            dir.display()
        ))
    })?;
    let cleanup = |d: &Path| {
        if d.parent() == Some(root.as_path()) {
            let _ = std::fs::remove_dir_all(d);
        }
    };
    let exe = match crate::selfupdate::this_exe() {
        Ok(e) => e,
        Err(e) => {
            cleanup(&dir);
            return Err(e);
        }
    };
    for name in ["docker", "docker-compose"] {
        if let Err(e) = std::os::unix::fs::symlink(&exe, dir.join(name)) {
            cleanup(&dir);
            return Err(Error::Cli(format!(
                "compat docker: cannot link {name}: {e}"
            )));
        }
    }
    let mut path = OsString::from(dir.as_os_str());
    if let Some(old) = crate::global_env("PATH").filter(|p| !p.is_empty()) {
        path.push(":");
        path.push(old);
    }
    let child = std::process::Command::new(prog)
        .args(rest)
        .env("PATH", &path)
        .env(SHIM_ENV, "1")
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            cleanup(&dir);
            return Err(Error::Cli(format!(
                "compat docker: cannot start '{prog}': {e}"
            )));
        }
    };
    // THE PARENT OUTLIVES A Ctrl-C, as a shell does: the terminal signals the whole foreground
    // group, the command decides what to do with it, and this process stays to remove its folder.
    // Set after the spawn, so the command does not inherit the ignored disposition.
    // SAFETY: signal() with SIG_IGN and the saved previous handlers; no handler code runs.
    let (old_int, old_quit) = unsafe {
        (
            libc::signal(libc::SIGINT, libc::SIG_IGN),
            libc::signal(libc::SIGQUIT, libc::SIG_IGN),
        )
    };
    let waited = child.wait();
    // SAFETY: restoring the dispositions saved above.
    unsafe {
        libc::signal(libc::SIGINT, old_int);
        libc::signal(libc::SIGQUIT, old_quit);
    }
    cleanup(&dir);
    let status =
        waited.map_err(|e| Error::Cli(format!("compat docker: waiting for '{prog}': {e}")))?;
    let code = status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1);
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Workload(code.clamp(0, 255)))
    }
}

/// `kern compat <args>`: only `docker` today.
pub(crate) fn compat(args: &[String]) -> Result<(), Error> {
    const USAGE: &str =
        "compat docker [--] <command> [args...] | compat docker link <dir> | compat docker unlink <dir> | compat docker status | compat docker enable | compat docker disable | compat docker serve | compat docker pipe (Windows)";
    match args.split_first() {
        Some((tool, rest)) if tool == "docker" => match rest.split_first() {
            Some((w, tail)) if w == "--" => run_wrapped(tail),
            Some((w, tail)) if w == "link" => match tail {
                [dir] => link(dir),
                _ => Err(Error::Usage("compat docker link <dir>")),
            },
            Some((w, tail)) if w == "unlink" => match tail {
                [dir] => unlink(dir),
                _ => Err(Error::Usage("compat docker unlink <dir>")),
            },
            Some((w, tail)) if w == "status" && tail.is_empty() => status(),
            Some((w, tail)) if w == "serve" => serve(tail),
            Some((w, tail)) if w == "enable" && tail.is_empty() => enable(),
            Some((w, _)) if w == "pipe" => Err(Error::Cli(
                "compat docker pipe: the named pipe for Windows programs is served by kern.exe; run it in Windows \
                 (here, Linux programs use the socket: `kern compat docker enable`)"
                    .into(),
            )),
            Some((w, tail)) if w == "__stdio" => stdio_bridge(tail),
            Some((w, tail)) if w == "__session-ended" => session_ended(tail),
            Some((w, tail)) if w == "disable" && tail.is_empty() => disable(),
            Some(_) => run_wrapped(rest),
            None => Err(Error::Usage(USAGE)),
        },
        Some((tool, _)) => Err(Error::Cli(format!(
            "compat {tool}: kern has a compatibility layer for docker only"
        ))),
        None => Err(Error::Usage(USAGE)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    fn argv(mode: Mode, v: &[&str]) -> Vec<String> {
        match translate(mode, &s(v)) {
            Ok(p) => p.argv,
            Err(Refused(r)) => vec![format!("REFUSED: {r}")],
        }
    }

    fn refused(v: &[&str]) -> String {
        match translate(Mode::Docker, &s(v)) {
            Ok(p) => format!("NOT REFUSED: {:?}", p.argv),
            Err(Refused(r)) => r,
        }
    }

    #[test]
    fn the_name_docker_is_answered_only_where_it_was_asked_for() {
        assert_eq!(mode_for("kern", false, || true), Ok(Mode::Kern));
        assert_eq!(mode_for("kern-docker", false, || false), Ok(Mode::Docker));
        assert_eq!(mode_for("docker", true, || false), Ok(Mode::Docker));
        assert_eq!(mode_for("docker", false, || true), Ok(Mode::Docker));
        assert_eq!(
            mode_for("docker-compose", true, || false),
            Ok(Mode::Compose)
        );
        let r = mode_for("docker", false, || false);
        assert!(
            matches!(&r, Err(Refused(m)) if m.contains("kern compat docker")),
            "{r:?}"
        );
        // The registry (PATH + a file) is not read for plain kern, nor when the variable answered.
        let asked = std::cell::Cell::new(0u32);
        let probe = || {
            asked.set(asked.get() + 1);
            false
        };
        assert_eq!(mode_for("kern", false, probe), Ok(Mode::Kern));
        assert_eq!(mode_for("kern-docker", false, probe), Ok(Mode::Docker));
        assert_eq!(mode_for("docker", true, probe), Ok(Mode::Docker));
        assert_eq!(asked.get(), 0);
        assert!(mode_for("docker", false, probe).is_err());
        assert_eq!(asked.get(), 1);
    }

    #[test]
    fn an_engine_variable_is_refused_by_name() {
        let r = engine_variable(|k| (k == "DOCKER_HOST").then(|| OsString::from("tcp://x:2375")));
        assert!(
            matches!(&r, Some(Refused(m)) if m.starts_with("DOCKER_HOST is set (tcp://x:2375)"))
        );
        let r = engine_variable(|k| (k == "DOCKER_CONTEXT").then(|| OsString::from("remote")));
        assert!(matches!(&r, Some(Refused(m)) if m.starts_with("DOCKER_CONTEXT is set")));
        assert_eq!(engine_variable(|_| Some(OsString::new())), None);
        assert_eq!(engine_variable(|_| None), None);
    }

    #[test]
    fn run_becomes_box_with_the_image_and_the_command_after_a_separator() {
        let p = run_like(
            "run",
            "box",
            RUN,
            &s(&[
                "--rm",
                "-e",
                "A=1",
                "--network",
                "shop_default",
                "-v",
                "data:/x",
                "busybox:1.36",
                "sh",
                "-c",
                "echo -n hi",
            ]),
            || Some("kd-test".to_string()),
        );
        assert_eq!(
            p.map(|p| (p.argv, p.print_after, p.note)),
            Ok((
                s(&[
                    "box",
                    "--rm",
                    "--env",
                    "A=1",
                    "--network",
                    "shop_default",
                    "--volume",
                    "data:/x",
                    "--image",
                    "busybox:1.36",
                    "--",
                    "sh",
                    "-c",
                    "echo -n hi"
                ]),
                None,
                None
            ))
        );
    }

    #[test]
    fn run_detached_names_the_box_and_prints_the_name_as_docker_prints_the_id() {
        let p = run_like("run", "box", RUN, &s(&["-d", "nginx"]), || {
            Some("kd-0a1b2c3d".to_string())
        });
        let Ok(p) = p else {
            panic!("refused: {p:?}");
        };
        assert_eq!(
            p.argv,
            s(&[
                "box",
                "--detach",
                "--name",
                "kd-0a1b2c3d",
                "--image",
                "nginx"
            ])
        );
        assert_eq!(p.print_after.as_deref(), Some("kd-0a1b2c3d"));
        let p = run_like(
            "run",
            "box",
            RUN,
            &s(&["-d", "--name", "web", "nginx"]),
            || None,
        );
        assert_eq!(p.map(|p| p.print_after), Ok(Some("web".to_string())));
        let p = run_like("run", "box", RUN, &s(&["-d", "nginx"]), || None);
        assert!(
            matches!(&p, Err(Refused(m)) if m.contains("--name")),
            "{p:?}"
        );
    }

    #[test]
    fn docker_short_flag_grammar_is_read_as_docker_reads_it() {
        // Combined booleans, an attached value, `-x=value`, `--flag=value`, a boolean `=false`.
        assert_eq!(
            argv(
                Mode::Docker,
                &[
                    "run",
                    "-dit",
                    "-eA=1",
                    "-p=8080:80",
                    "--name=web",
                    "--rm=false",
                    "img"
                ]
            ),
            s(&[
                "box",
                "--detach",
                "-i",
                "-t",
                "--env",
                "A=1",
                "--publish",
                "8080:80",
                "--name",
                "web",
                "--image",
                "img"
            ])
        );
        // A flag value that looks like a flag is a value.
        assert_eq!(
            argv(Mode::Docker, &["run", "--rm", "-e", "-x", "img"]),
            s(&["box", "--rm", "--env", "-x", "--image", "img"])
        );
        // Everything after the image is the command, flags included.
        assert_eq!(
            argv(
                Mode::Docker,
                &["run", "--rm", "img", "ls", "-la", "--color"]
            ),
            s(&["box", "--rm", "--image", "img", "--", "ls", "-la", "--color"])
        );
    }

    #[test]
    fn an_untranslated_flag_stops_the_command_and_is_named() {
        let r = refused(&["run", "--rm", "--log-opt", "max-size=1m", "img"]);
        assert!(
            r.starts_with("docker run --log-opt: kern has no flag"),
            "{r}"
        );
        let r = refused(&["run", "-P", "img"]);
        assert!(r.starts_with("docker run -P:"), "{r}");
        let r = refused(&["run", "-dP", "img"]);
        assert!(r.contains("-P (in -dP)"), "{r}");
        let r = refused(&["exec", "-d", "c", "true"]);
        assert!(r.starts_with("docker exec -d:"), "{r}");
        let r = refused(&["images", "-q"]);
        assert!(r.starts_with("docker images -q:"), "{r}");
        let r = refused(&["run", "--rm=maybe", "img"]);
        assert!(r.contains("takes true or false"), "{r}");
        let r = refused(&["run", "--name"]);
        assert!(r.contains("needs a value"), "{r}");
        let r = refused(&["system", "prune"]);
        assert!(r.starts_with("docker system: not translated"), "{r}");
        let r = refused(&["-H", "tcp://x", "ps"]);
        assert!(
            r.starts_with("docker -H: it chooses a docker engine"),
            "{r}"
        );
        let r = refused(&["--context=remote", "ps"]);
        assert!(r.starts_with("docker --context:"), "{r}");
        let r = refused(&["--weird", "ps"]);
        assert!(r.starts_with("docker --weird: not translated"), "{r}");
    }

    #[test]
    fn the_default_network_is_said_not_sent_as_a_pod_name() {
        for net in [None, Some("bridge"), Some("default")] {
            let mut a = vec!["--rm"];
            if let Some(n) = net {
                a.extend(["--network", n]);
            }
            a.push("img");
            let p = run_like("run", "box", RUN, &s(&a), || None);
            let Ok(p) = p else {
                panic!("refused: {p:?}");
            };
            assert_eq!(p.argv, s(&["box", "--rm", "--image", "img"]), "{net:?}");
            assert_eq!(p.note.as_deref(), Some(NETWORK_NOTE), "{net:?}");
        }
        let p = run_like("run", "box", RUN, &s(&["--network", "host", "img"]), || {
            None
        });
        assert_eq!(p.map(|p| p.note), Ok(None));
    }

    #[test]
    fn exec_puts_the_command_after_a_separator_so_its_flags_stay_its_own() {
        assert_eq!(
            argv(
                Mode::Docker,
                &[
                    "exec",
                    "-i",
                    "usbim-postgres",
                    "psql",
                    "-U",
                    "postgres",
                    "-d",
                    "app"
                ]
            ),
            s(&[
                "exec",
                "-i",
                "usbim-postgres",
                "--",
                "psql",
                "-U",
                "postgres",
                "-d",
                "app"
            ])
        );
        assert_eq!(
            argv(
                Mode::Docker,
                &["exec", "-it", "-u", "root", "-e", "X=1", "web", "sh"]
            ),
            s(&["exec", "-i", "-t", "--user", "root", "--env", "X=1", "web", "--", "sh"])
        );
        let r = refused(&["exec", "web"]);
        assert!(r.contains("a command is needed"), "{r}");
    }

    #[test]
    fn the_listing_verbs_map_docker_only_spellings_onto_kerns() {
        assert_eq!(
            argv(
                Mode::Docker,
                &["ps", "-a", "--format", "{{.Names}}", "-f", "name=web"]
            ),
            s(&[
                "ps",
                "--all",
                "--format",
                "{{.Names}}",
                "--filter",
                "name=web"
            ])
        );
        assert_eq!(
            argv(
                Mode::Docker,
                &["logs", "-f", "-n", "50", "--since", "10m", "web"]
            ),
            s(&["logs", "--follow", "--tail", "50", "--since", "10m", "web"])
        );
        assert_eq!(
            argv(Mode::Docker, &["inspect", "-f", "{{.State.Status}}", "web"]),
            s(&["inspect", "--format", "{{.State.Status}}", "web"])
        );
        assert_eq!(
            argv(Mode::Docker, &["stop", "-t", "0", "web"]),
            s(&["stop", "--time", "0", "web"])
        );
        assert_eq!(
            argv(Mode::Docker, &["container", "ls", "-q"]),
            s(&["ps", "--quiet"])
        );
        assert_eq!(
            argv(Mode::Docker, &["image", "rm", "-f", "x"]),
            s(&["rmi", "--force", "x"])
        );
        assert_eq!(
            argv(Mode::Docker, &["volume", "ls", "-q"]),
            s(&["volume", "ls", "--quiet"])
        );
        assert_eq!(
            argv(Mode::Docker, &["volume", "rm", "a", "b"]),
            s(&["volume", "rm", "a", "b"])
        );
        assert_eq!(
            argv(
                Mode::Docker,
                &[
                    "build",
                    "-t",
                    "app:1",
                    "-f",
                    "Dockerfile.dev",
                    "--build-arg",
                    "V=2",
                    "."
                ]
            ),
            s(&[
                "build",
                "--tag",
                "app:1",
                "--file",
                "Dockerfile.dev",
                "--build-arg",
                "V=2",
                "."
            ])
        );
    }

    #[test]
    fn compose_is_handed_to_kerns_compose_whole() {
        assert_eq!(
            argv(
                Mode::Docker,
                &[
                    "compose",
                    "-f",
                    "a.yml",
                    "up",
                    "-d",
                    "--build",
                    "--force-recreate",
                    "--no-deps",
                    "api"
                ]
            ),
            s(&[
                "compose",
                "-f",
                "a.yml",
                "up",
                "-d",
                "--build",
                "--force-recreate",
                "--no-deps",
                "api"
            ])
        );
        assert_eq!(argv(Mode::Compose, &["ps"]), s(&["compose", "ps"]));
        let v = translate(Mode::Compose, &s(&["version", "--short"]));
        assert_eq!(
            v.map(|p| (p.argv, p.print_after)),
            Ok((Vec::new(), Some(kern_common::VERSION.to_string())))
        );
        let v = translate(Mode::Docker, &s(&["compose", "version"]));
        assert!(
            matches!(&v, Ok(Plan { print_after: Some(t), .. }) if t.starts_with("kern-docker compose ")),
            "{v:?}"
        );
    }

    #[test]
    fn version_says_kern_and_never_a_docker_version() {
        let p = translate(Mode::Docker, &s(&["version"]));
        let Ok(p) = p else {
            panic!("refused: {p:?}");
        };
        let text = p.print_after.unwrap_or_default();
        assert!(text.contains("Server: kern"), "{text}");
        assert!(text.contains(kern_common::VERSION), "{text}");
        let p = translate(
            Mode::Docker,
            &s(&["version", "--format", "{{.Server.Version}}"]),
        );
        assert_eq!(
            p.map(|p| p.print_after),
            Ok(Some(kern_common::VERSION.to_string()))
        );
        let p = translate(Mode::Docker, &s(&["--version"]));
        assert!(
            matches!(&p, Ok(Plan { print_after: Some(t), .. }) if t.starts_with("kern-docker "))
        );
        let r = refused(&["version", "--format", "{{json .}}"]);
        assert!(r.starts_with("docker version --format {{json .}}"), "{r}");
    }

    #[test]
    fn create_prints_a_name_and_uses_kerns_short_spellings() {
        let p = run_like(
            "create",
            "create",
            CREATE,
            &s(&["--name", "w", "-e", "A=1", "img", "sleep", "9"]),
            || None,
        );
        assert_eq!(
            p.map(|p| (p.argv, p.print_after, p.note)),
            Ok((
                s(&["create", "--name", "w", "-e", "A=1", "--image", "img", "--", "sleep", "9"]),
                Some("w".to_string()),
                None
            ))
        );
    }

    /// THE ACCEPTANCE LIST: the shapes of the docker calls in usbim-assets' package.json and
    /// scripts/ (recorded 19/11: seeding through `exec -i ... < file.sql`, a token read with `exec
    /// ... cat`, one-offs on the stack's network with a volume, a forced rebuild of one service, and
    /// the listing verbs). Every one must translate; none may be refused.
    #[test]
    fn the_usbim_assets_command_shapes_all_translate() {
        let shapes: &[&[&str]] = &[
            &[
                "compose",
                "-f",
                "docker-compose.yml",
                "-p",
                "usbim",
                "up",
                "-d",
            ],
            &[
                "compose",
                "up",
                "-d",
                "--build",
                "--force-recreate",
                "--no-deps",
                "api",
            ],
            &["compose", "down", "-v"],
            &["compose", "ps"],
            &["compose", "logs", "-f", "--tail", "100", "api"],
            &[
                "compose", "exec", "-T", "postgres", "psql", "-U", "postgres",
            ],
            &["compose", "build", "api"],
            &["compose", "restart", "worker"],
            &["compose", "stop"],
            &["compose", "rm", "-f"],
            &["compose", "config"],
            &[
                "exec",
                "-i",
                "usbim-postgres",
                "psql",
                "-U",
                "postgres",
                "-d",
                "usbim",
            ],
            &["exec", "usbim-hatchet", "cat", "/config/client.token"],
            &[
                "exec",
                "-it",
                "-e",
                "PGPASSWORD=x",
                "-u",
                "postgres",
                "usbim-postgres",
                "psql",
            ],
            &["ps", "-a", "--format", "{{.Names}}\t{{.Status}}"],
            &["ps", "-q", "-f", "name=usbim"],
            &["logs", "--tail", "200", "--since", "10m", "usbim-api"],
            &[
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                "usbim-postgres",
            ],
            &[
                "run",
                "--rm",
                "--network",
                "usbim_default",
                "-v",
                "usbim_data:/x",
                "-e",
                "A=1",
                "alpine",
                "ls",
                "/x",
            ],
            &["volume", "ls", "-q"],
            &["volume", "rm", "usbim_pgdata"],
            &["images"],
            &["rmi", "usbim-api:latest"],
            &["version"],
            &["info"],
        ];
        for shape in shapes {
            let r = translate(Mode::Docker, &s(shape));
            assert!(r.is_ok(), "docker {} was refused: {r:?}", shape.join(" "));
        }
    }

    #[test]
    fn the_links_file_keeps_only_absolute_paths() {
        assert_eq!(
            parse_links("/home/u/bin/docker\n\n  relative/docker\n /opt/x/docker \n"),
            vec![
                PathBuf::from("/home/u/bin/docker"),
                PathBuf::from("/opt/x/docker")
            ]
        );
    }

    #[test]
    fn the_sweep_only_ever_removes_folders_named_like_a_pid() {
        assert!(is_pid_name("12345"));
        assert!(!is_pid_name(""));
        assert!(!is_pid_name("12a"));
        assert!(!is_pid_name(".."));
        assert!(!is_pid_name("12345678901"));
    }
}
