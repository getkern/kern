//! `docker` → `kern` CLI shim: rewrite a `docker …` argv into an equivalent `kern …` argv.
//!
//! Activated only when the binary is invoked *as* `docker` / `docker-compose` (via a symlink or
//! wrapper). This is **pure argument rewriting**: no daemon, no `docker.sock`, no Engine API. kern's
//! `box` verb already speaks Docker's common flag dialect (`-d`/`-p`/`-e`/`-v`/`-w`/`-it`/`-m`/`--cpus`),
//! so the shim's real work is structural (`docker run IMAGE cmd` → `kern box NAME --image IMAGE -- cmd`)
//! plus a small verb map.
//!
//! Design rule (safety over convenience): flags fall into three buckets.
//! PASS - kern accepts the same flag; forwarded verbatim.
//! DROP - pure metadata with no runtime effect (labels); dropped with a stderr note.
//! FAIL - behaviour-changing and unsupported (`--device`, `--gpus`, namespace sharing, ...): we error
//! loudly instead of silently dropping, so a script never runs with different semantics than it
//! asked for. Unknown flags also FAIL - the opposite of a best-effort shim that silently misbehaves.
//!
//! No `unwrap`/`expect`/`panic!`: every branch returns `Result`/`Option`.

use std::fmt;

/// The argv kern actually decided to run, after any shim translation.
///
/// Exists because kern RE-EXECS itself when it caps a box through a `systemd-run --scope`, and that
/// re-exec used to replay `std::env::args()`, which is what the USER typed rather than what kern
/// resolved. Invoked through a symlink named `docker`, the second pass lost twice over:
/// `current_exe()` resolves the symlink, so `argv[0]` came back as `kern` and the shim no longer
/// recognised itself, and the args replayed were the untranslated `run --rm IMAGE cmd`, which kern's
/// own `run` verb then rejected as an unknown flag. The command simply failed, on exactly the setup
/// the README documents (`ln -s "$(command -v kern)" ~/.local/bin/docker`) and exactly on the hosts
/// that take the scope path: a normal non-root Linux user. It worked as root, which is why it had
/// gone unnoticed.
///
/// Replaying the DECIDED command instead of the typed one also means the second pass never needs to
/// re-derive anything: translation happens once, at the edge, and everything downstream sees kern's
/// own dialect.
static EFFECTIVE: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

/// Set on the scope re-exec to say "the argv you received is already kern's dialect".
///
/// The re-exec names the binary by its RESOLVED path, which is usually `kern` and then translation
/// never triggers. But a shim installed as a COPY named `docker` (rather than a symlink) re-enters
/// `main` still called `docker`, and without this marker it would translate the already-translated
/// argv and refuse `box …` as a command Docker does not have.
pub const DIALECT_ENV: &str = "KERN_ARGV_IS_KERN_DIALECT";

/// Is this process the far side of a re-exec that already carries kern's own dialect?
pub fn argv_already_translated() -> bool {
    std::env::var_os(DIALECT_ENV).is_some()
}

/// Record the post-translation argv (without `argv[0]`). Called once, from `main`.
pub fn set_effective(args: &[String]) {
    let _ = EFFECTIVE.set(args.to_vec());
}

/// The post-translation argv, or the raw one if `main` never recorded it (tests, direct library use).
pub fn effective_args() -> Vec<String> {
    EFFECTIVE
        .get()
        .cloned()
        .unwrap_or_else(|| std::env::args().skip(1).collect())
}

/// Why a `docker` argv could not be translated. Carries enough context for a precise message.
#[derive(Debug, PartialEq, Eq)]
pub enum ShimError {
    /// Empty argv (`docker` with no subcommand).
    Empty,
    /// A `docker` subcommand kern has no equivalent for (e.g. `swarm`, `network`, `service`).
    UnknownCommand(String),
    /// A flag that would change runtime behaviour and that kern does not support.
    UnsupportedFlag { cmd: &'static str, flag: String },
    /// A value flag given without its value (`docker run -e` at end of argv).
    MissingValue { flag: String },
    /// `docker run` with no image positional.
    MissingImage,
    /// A user-controlled positional (name / image / compose file) that begins with `-`. Left as-is it
    /// would be re-parsed by kern as a FLAG - a flag-injection escalation vector. Refused, exactly as
    /// Docker refuses such names/references.
    InjectedFlag { role: &'static str, value: String },
    /// An empty image reference (`docker run "" …`): invalid, and would silently shift the command.
    EmptyImage,
}

impl fmt::Display for ShimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShimError::Empty => write!(f, "docker: no subcommand given"),
            ShimError::UnknownCommand(c) => write!(
                f,
                "docker compat: '{c}' has no kern equivalent (kern is daemonless: no swarm/service/network CRUD/docker.sock). Run it under real Docker."
            ),
            ShimError::UnsupportedFlag { cmd, flag } => write!(
                f,
                "docker compat: '{cmd} {flag}' is not supported by kern and changes behaviour, so it is refused (not silently ignored). Use `kern {cmd}` directly, or run under Docker."
            ),
            ShimError::MissingValue { flag } => {
                write!(f, "docker compat: flag '{flag}' expects a value")
            }
            ShimError::MissingImage => {
                write!(f, "docker compat: `docker run` needs an image argument")
            }
            ShimError::InjectedFlag { role, value } => write!(
                f,
                "docker compat: refusing {role} '{value}' - it begins with '-' and would be read as a flag (injection). A {role} cannot start with '-'."
            ),
            ShimError::EmptyImage => {
                write!(f, "docker compat: empty image reference is invalid")
            }
        }
    }
}

/// `docker run` boolean flags kern's `box` accepts verbatim (verified against `parse_box` in cli.rs).
const RUN_BOOL_PASS: &[&str] = &[
    "-d",
    "--detach",
    "-i",
    "--interactive",
    "-t",
    "--tty",
    "-it",
    "-ti",
    "--privileged",
    "--read-only",
    "--init",
];
/// `docker run` boolean flags that are inert on kern (a box is already ephemeral), dropped quietly.
const RUN_BOOL_DROP: &[&str] = &["--rm"];
/// `docker run` boolean flags that are behaviour-changing and unsupported -> FAIL.
const RUN_BOOL_FAIL: &[&str] = &["-P", "--publish-all"];
/// `docker run` value flags kern's `box` accepts verbatim (each verified against `parse_box`).
/// NOTE `--user`/`-u`: kern maps a NUMERIC uid[:gid] only; Docker also accepts a username. A username
/// is forwarded and kern rejects it with a clear error (loud, not silent) - acceptable per fail-loud.
const RUN_VAL_PASS: &[&str] = &[
    "-p",
    "--publish",
    "-e",
    "--env",
    "--env-file",
    "-v",
    "--volume",
    "-w",
    "--workdir",
    "-m",
    "--memory",
    "--cpus",
    "--cpuset-cpus",
    "--pids-limit",
    "--network",
    "--net",
    "--restart",
    "--hostname",
    "--add-host",
    "--health-cmd",
    "-u",
    "--user",
    "--cap-add",
    "--cap-drop",
    "--tmpfs",
    // Implemented by kern with Docker's own spelling and semantics.
    "-l",
    "--label",
    "--ulimit",
    "--sysctl",
];
/// `docker run` value flags that are pure metadata (no runtime effect), dropped with a note.
const RUN_VAL_DROP: &[&str] = &["--label-file"];
/// `docker run` value flags that change behaviour and have NO kern equivalent -> FAIL (never dropped).
/// The namespace-sharing flags (`--pid`/`--ipc`/`--uts`/`--userns`/`--cgroupns`) are refused on purpose:
/// kern isolates those namespaces by design, so honouring a `=host` share would break its boundary.
const RUN_VAL_FAIL: &[&str] = &[
    "--security-opt",
    "--device",
    "--gpus",
    "--pid",
    "--ipc",
    "--uts",
    "--userns",
    "--cgroupns",
    "--mount",
];

/// Split a possibly-`=`-joined flag (`--env=X`) into `(name, Some(value))`, else `(flag, None)`.
fn split_eq(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((k, v)) => (k, Some(v)),
        None => (arg, None),
    }
}

/// True if `flag` is in `set`. Small linear scan (sets are tiny, one-shot at startup).
fn is(flag: &str, set: &[&str]) -> bool {
    set.contains(&flag)
}

/// Guard a user-controlled positional (box name, image ref, compose file) against flag injection:
/// if it begins with `-`, kern's own parser would treat it as a flag, so an attacker-controlled value
/// like `--privileged` could inject privileges. Docker enforces the same rule (names/refs never start
/// with `-`). Refuse rather than sanitize, so the failure is loud and total.
fn reject_leading_dash(role: &'static str, value: &str) -> Result<(), ShimError> {
    if value.starts_with('-') {
        return Err(ShimError::InjectedFlag {
            role,
            value: value.to_string(),
        });
    }
    Ok(())
}

/// Translate a full `docker <verb> …` argv (WITHOUT arg0) into a `kern …` argv.
pub fn translate(argv: &[String]) -> Result<Vec<String>, ShimError> {
    let (verb, rest) = argv.split_first().ok_or(ShimError::Empty)?;
    match verb.as_str() {
        "run" | "create" => translate_run(rest),
        "exec" => translate_exec(rest),
        "compose" => translate_compose(rest),
        // Near-1:1 verbs: kern uses the same name and compatible argv.
        "ps" | "logs" | "stop" | "kill" | "pause" | "unpause" | "attach" | "inspect" | "stats"
        | "rename" | "tag" | "commit" | "wait" | "diff" | "events" | "pull" | "push" | "images"
        | "search" | "top" | "cp" | "login" | "info" | "history" => {
            let mut out = Vec::with_capacity(rest.len() + 1);
            out.push(verb.clone());
            out.extend(rest.iter().cloned());
            Ok(out)
        }
        // `docker volume <create|ls|rm|inspect|prune> …` -> `kern volume …`. kern HAS a volume store
        // (`kern volume`, the same verbs), so refusing this as "no kern equivalent" would send a user
        // to real Docker for something that works here - and compose already auto-creates named
        // volumes. Sub-verb and arguments pass through untouched: the two vocabularies coincide.
        "volume" => {
            let mut out = Vec::with_capacity(rest.len() + 1);
            out.push("volume".into());
            out.extend(rest.iter().cloned());
            Ok(out)
        }
        // `docker build` -> `kern build` (kern uses `-t`/`--tag`, `-f`, `--build-arg`: same names).
        "build" => {
            let mut out = Vec::with_capacity(rest.len() + 1);
            out.push("build".into());
            out.extend(rest.iter().cloned());
            Ok(out)
        }
        // `docker rm` removes a container; a kern box is gone once stopped, so map to `stop`
        // (removing what is running). `docker rmi` removes an image -> `kern rmi`.
        "rm" => {
            let mut out = vec!["stop".to_string()];
            out.extend(
                rest.iter()
                    .filter(|a| *a != "-f" && *a != "--force")
                    .cloned(),
            );
            Ok(out)
        }
        "rmi" => {
            let mut out = vec!["rmi".to_string()];
            out.extend(rest.iter().cloned());
            Ok(out)
        }
        "version" | "--version" | "-v" => Ok(vec!["--version".into()]),
        "--help" | "-h" | "help" => Ok(vec!["--help".into()]),
        other => Err(ShimError::UnknownCommand(other.to_string())),
    }
}

/// `docker run [flags] IMAGE [cmd…]` -> `kern box NAME --image IMAGE [flags] -- [cmd…]`.
///
/// The parser must consume each value flag's argument correctly to locate the first *positional*,
/// which is the image; everything after it is the container command.
fn translate_run(rest: &[String]) -> Result<Vec<String>, ShimError> {
    let mut name: Option<String> = None;
    let mut passthrough: Vec<String> = Vec::new();
    let mut image: Option<String> = None;
    let mut command: Vec<String> = Vec::new();
    // `--entrypoint`: held aside, then prepended to the command below (Docker's entrypoint ++ command).
    let mut entrypoint: Option<String> = None;

    let mut i = 0;
    while i < rest.len() {
        let arg = &rest[i];
        // Once the image is set, everything remaining is the command (verbatim).
        if image.is_some() {
            command.push(arg.clone());
            i += 1;
            continue;
        }
        if arg == "--" {
            // Explicit end-of-flags before the image (rare with docker, but honour it).
            i += 1;
            if let Some(img) = rest.get(i) {
                image = Some(img.clone());
                i += 1;
            }
            continue;
        }
        if let Some(stripped) = arg.strip_prefix('-') {
            let _ = stripped; // it's a flag
            let (flag, inline) = split_eq(arg);
            // --name: becomes the positional box name. Guard against flag injection: a name that
            // begins with `-` would be re-parsed by kern as a flag (`--privileged`, …).
            if flag == "--name" {
                let val = value_of(flag, inline, rest, &mut i)?;
                reject_leading_dash("box name", &val)?;
                name = Some(val);
                continue;
            }
            // -h in `docker run` means hostname; kern spells it --hostname.
            if flag == "-h" {
                let val = value_of(flag, inline, rest, &mut i)?;
                passthrough.push("--hostname".into());
                passthrough.push(val);
                continue;
            }
            if is(flag, RUN_BOOL_FAIL) {
                return Err(ShimError::UnsupportedFlag {
                    cmd: "run",
                    flag: flag.to_string(),
                });
            }
            if is(flag, RUN_BOOL_DROP) {
                i += 1;
                continue;
            }
            if is(flag, RUN_BOOL_PASS) {
                passthrough.push(arg.clone());
                i += 1;
                continue;
            }
            // `--entrypoint`: no kern flag mirrors it, but the SEMANTICS are expressible - Docker runs
            // `entrypoint ++ command`, and a kern box command is exactly that concatenation. Captured
            // here and prepended below, so `docker run --entrypoint` behaves like a compose
            // `entrypoint:` (which the compose parser already composes the same way).
            if flag == "--entrypoint" {
                let val = value_of(flag, inline, rest, &mut i)?;
                reject_leading_dash("entrypoint", &val)?;
                // `--entrypoint ""` RESETS the image entrypoint (Docker's documented escape hatch, used
                // to run a plain shell in an image that normally starts a daemon). Prepending the empty
                // string instead made the box try to exec "" and die with ENOENT.
                entrypoint = if val.is_empty() { None } else { Some(val) };
                continue;
            }
            if is(flag, RUN_VAL_FAIL) {
                return Err(ShimError::UnsupportedFlag {
                    cmd: "run",
                    flag: flag.to_string(),
                });
            }
            if is(flag, RUN_VAL_DROP) {
                // Consume its value too, then drop with a note.
                let _ = value_of(flag, inline, rest, &mut i)?;
                eprintln!(
                    "docker compat: dropping metadata flag '{flag}' (no runtime effect on kern)"
                );
                continue;
            }
            if is(flag, RUN_VAL_PASS) {
                let val = value_of(flag, inline, rest, &mut i)?;
                passthrough.push(flag.to_string());
                passthrough.push(val);
                continue;
            }
            // Combined boolean short flags (`-dit` == `-d -i -t`). Expand ONLY a cluster made
            // entirely of known boolean shorts; a cluster carrying a value-taking or unknown short
            // is refused - we never guess where a value would attach.
            if !arg.starts_with("--") && arg.len() >= 3 && !arg.contains('=') {
                let body = &arg[1..];
                if body.chars().all(|c| matches!(c, 'd' | 'i' | 't')) {
                    for c in body.chars() {
                        passthrough.push(format!("-{c}"));
                    }
                    i += 1;
                    continue;
                }
            }
            // Unknown flag: refuse loudly rather than guess.
            return Err(ShimError::UnsupportedFlag {
                cmd: "run",
                flag: flag.to_string(),
            });
        }
        // First positional = image.
        image = Some(arg.clone());
        i += 1;
    }

    let image = image.ok_or(ShimError::MissingImage)?;
    if image.is_empty() {
        return Err(ShimError::EmptyImage);
    }
    // The image is forwarded as the VALUE of `--image`; a leading `-` still makes an invalid ref and
    // is refused for defence-in-depth (kern would try to pull a bogus name otherwise).
    reject_leading_dash("image", &image)?;
    // A deterministic name if the user gave none: docker auto-names too. Use a stable prefix so
    // repeated `docker run` without --name doesn't collide within one shell (kern requires a name).
    let name = name.unwrap_or_else(|| format!("box-{}", std::process::id()));

    // `--entrypoint X` + trailing args = Docker's `entrypoint ++ command`: X becomes argv[0] and the
    // positionals after the image become its arguments. Exactly what the compose parser already does
    // with `entrypoint:` + `command:`, so `docker run --entrypoint` and a compose `entrypoint:` can't
    // disagree. kern has no `--entrypoint` flag: the composition IS the box command.
    if let Some(ep) = entrypoint {
        command.insert(0, ep);
    }

    let mut out: Vec<String> = Vec::with_capacity(passthrough.len() + command.len() + 5);
    out.push("box".into());
    out.push(name);
    out.push("--image".into());
    out.push(image);
    out.extend(passthrough);
    if !command.is_empty() {
        out.push("--".into());
        out.extend(command);
    }
    Ok(out)
}

/// Read the value for a value-flag: either the inline `=X`, or the next argv element (advancing `i`).
fn value_of(
    flag: &str,
    inline: Option<&str>,
    rest: &[String],
    i: &mut usize,
) -> Result<String, ShimError> {
    if let Some(v) = inline {
        *i += 1;
        return Ok(v.to_string());
    }
    // consume the flag, then its value
    *i += 1;
    let v = rest.get(*i).ok_or_else(|| ShimError::MissingValue {
        flag: flag.to_string(),
    })?;
    *i += 1;
    Ok(v.clone())
}

/// `docker exec [flags] NAME cmd…` -> `kern exec NAME [flags] -- cmd…`.
/// kern's `exec` takes `[-it] [--env K=V] [-w DIR]` then `-- CMD`.
fn translate_exec(rest: &[String]) -> Result<Vec<String>, ShimError> {
    let mut flags: Vec<String> = Vec::new();
    let mut name: Option<String> = None;
    let mut command: Vec<String> = Vec::new();

    let mut i = 0;
    while i < rest.len() {
        let arg = &rest[i];
        if name.is_some() {
            command.push(arg.clone());
            i += 1;
            continue;
        }
        let (flag, inline) = split_eq(arg);
        match flag {
            "-it" | "-ti" | "-i" | "-t" | "--interactive" | "--tty" => {
                flags.push(arg.clone());
                i += 1;
            }
            "-e" | "--env" => {
                let v = value_of(flag, inline, rest, &mut i)?;
                flags.push("--env".into());
                flags.push(v);
            }
            "-w" | "--workdir" => {
                let v = value_of(flag, inline, rest, &mut i)?;
                flags.push("-w".into());
                flags.push(v);
            }
            "-u" | "--user" | "--privileged" | "-d" | "--detach" => {
                return Err(ShimError::UnsupportedFlag {
                    cmd: "exec",
                    flag: flag.to_string(),
                });
            }
            other if other.starts_with('-') => {
                return Err(ShimError::UnsupportedFlag {
                    cmd: "exec",
                    flag: flag.to_string(),
                });
            }
            _ => {
                name = Some(arg.clone());
                i += 1;
            }
        }
    }

    let name = name.ok_or(ShimError::MissingImage)?; // reuse: "needs a target"; message is generic enough
    let mut out: Vec<String> = Vec::with_capacity(flags.len() + command.len() + 3);
    out.push("exec".into());
    out.push(name);
    out.extend(flags);
    if !command.is_empty() {
        out.push("--".into());
        out.extend(command);
    }
    Ok(out)
}

/// `docker compose [-f FILE] up|down …` -> `kern compose <FILE> up|down …`.
/// kern takes the file as a positional; docker uses `-f`. Default to `docker-compose.yml`.
/// The `docker compose` sub-verbs kern implements. Used only to decide where the sub-command starts,
/// so a flag after it is routed to the sub-command instead of to `compose` itself.
const COMPOSE_VERBS: &[&str] = &[
    "up", "down", "stop", "start", "restart", "ps", "logs", "build", "pull", "config",
];

fn translate_compose(rest: &[String]) -> Result<Vec<String>, ShimError> {
    let mut files: Vec<String> = Vec::new();
    let mut tail: Vec<String> = Vec::new();
    let mut i = 0;
    // Position decides what `-f` means, exactly as in Docker: BEFORE the sub-verb it is
    // `--file`, AFTER it belongs to the sub-command (`logs -f` = follow). Without this,
    // `docker compose -f stack.yml logs -f` swallowed the follow flag as a second filename.
    let mut seen_verb = false;
    while i < rest.len() {
        let (flag, inline) = split_eq(&rest[i]);
        if !seen_verb && !flag.starts_with('-') && COMPOSE_VERBS.contains(&flag) {
            seen_verb = true;
            tail.push(rest[i].clone());
            i += 1;
            continue;
        }
        // `up -d` is THE canonical compose invocation, and it asks for what kern already does: a
        // compose service is detached by construction, there is no attached mode to opt out of. It
        // belongs in the DROP bucket, like the no-op flags on the `docker run` side. Forwarding it
        // verbatim (the previous behaviour, since compose had no buckets at all) handed `-d` to a
        // parser that does not know it, so the single most common command in the ecosystem died on
        // kern's generic usage text. Only AFTER the verb: before it, `-d` is docker's own global
        // debug flag and none of our business.
        if seen_verb && (flag == "-d" || flag == "--detach") && inline.is_none() {
            i += 1;
            continue;
        }
        if !seen_verb && (flag == "-f" || flag == "--file") {
            let f = value_of(flag, inline, rest, &mut i)?;
            // The file is forwarded as a positional to `kern compose <file>`; a leading `-` would be
            // re-parsed as a flag (`--no-pod`, …) - injection. Refuse.
            reject_leading_dash("compose file", &f)?;
            // EVERY `-f` is kept, in order: `-f base.yml -f override.yml` is Docker's merge, and
            // keeping only the last one silently ran the override alone (a stack missing its images).
            files.push(f);
            continue;
        }
        tail.push(rest[i].clone());
        i += 1;
    }
    if files.is_empty() {
        files.push("docker-compose.yml".to_string());
    }
    let mut out: Vec<String> = Vec::with_capacity(tail.len() + files.len() + 1);
    out.push("compose".into());
    out.extend(files);
    out.extend(tail);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn run_basic_image_and_cmd() {
        let out = translate(&v(&["run", "alpine", "echo", "hi"])).unwrap();
        // box <name> --image alpine -- echo hi
        assert_eq!(out[0], "box");
        assert_eq!(out[2], "--image");
        assert_eq!(out[3], "alpine");
        let sep = out.iter().position(|x| x == "--").unwrap();
        assert_eq!(&out[sep + 1..], &["echo", "hi"]);
    }

    #[test]
    fn run_maps_name_and_passes_ports_env() {
        let out = translate(&v(&[
            "run", "-d", "--name", "web", "-p", "8080:80", "-e", "K=V", "nginx",
        ]))
        .unwrap();
        assert_eq!(out[0], "box");
        assert_eq!(out[1], "web"); // --name became the positional
        assert!(out.contains(&"--image".to_string()));
        assert!(out.contains(&"nginx".to_string()));
        assert!(out.windows(2).any(|w| w == ["-p", "8080:80"]));
        assert!(out.windows(2).any(|w| w == ["-e", "K=V"]));
        assert!(out.contains(&"-d".to_string()));
    }

    #[test]
    fn run_drops_rm_but_forwards_labels() {
        // `--rm` stays dropped: a kern box is already ephemeral, so it is a genuine no-op.
        // `-l/--label` is NO LONGER dropped - kern records labels in the registry and
        // `kern ps --filter label=` selects on them, so dropping them lost real function.
        let out = translate(&v(&["run", "--rm", "-l", "app=x", "alpine", "true"])).unwrap();
        assert!(!out.contains(&"--rm".to_string()), "{out:?}");
        assert!(out.windows(2).any(|w| w == ["-l", "app=x"]), "{out:?}");
        // `--label-file` has no kern equivalent and is still dropped with a note, not forwarded.
        let lf = translate(&v(&["run", "--label-file", "f", "alpine", "true"])).unwrap();
        assert!(!lf.contains(&"--label-file".to_string()), "{lf:?}");
    }

    #[test]
    fn run_forwards_ulimit_and_sysctl() {
        // Both are implemented by kern with Docker's spelling, so they must reach the box rather than
        // fail as "no kern equivalent" (which is what they did before they were implemented).
        let out = translate(&v(&[
            "run",
            "--ulimit",
            "nofile=1024:2048",
            "--sysctl",
            "net.core.somaxconn=1024",
            "alpine",
            "true",
        ]))
        .unwrap();
        assert!(
            out.windows(2)
                .any(|w| w == ["--ulimit", "nofile=1024:2048"]),
            "{out:?}"
        );
        assert!(
            out.windows(2)
                .any(|w| w == ["--sysctl", "net.core.somaxconn=1024"]),
            "{out:?}"
        );
    }

    #[test]
    fn run_forwards_user_and_caps() {
        // Verified supported by kern's `box`: -u/--user (numeric), --cap-add, --tmpfs, --env-file.
        let out = translate(&v(&[
            "run",
            "-u",
            "1000:1000",
            "--cap-add",
            "NET_ADMIN",
            "alpine",
        ]))
        .unwrap();
        assert!(out.windows(2).any(|w| w == ["-u", "1000:1000"]));
        assert!(out.windows(2).any(|w| w == ["--cap-add", "NET_ADMIN"]));
    }

    #[test]
    fn entrypoint_is_prepended_to_the_command() {
        // Docker: `--entrypoint X image a b` runs `X a b`. kern has no --entrypoint flag; the box
        // command IS the concatenation, which is also how the compose parser composes
        // `entrypoint:` + `command:` - the two paths must not disagree.
        assert_eq!(
            translate(&v(&["run", "--entrypoint", "/bin/echo", "alpine", "ciao"])).unwrap(),
            v(&[
                "box",
                &format!("box-{}", std::process::id()),
                "--image",
                "alpine",
                "--",
                "/bin/echo",
                "ciao"
            ])
        );
        // Entrypoint with no trailing command: it becomes the whole command.
        assert_eq!(
            translate(&v(&["run", "--entrypoint=/bin/true", "alpine"])).unwrap(),
            v(&[
                "box",
                &format!("box-{}", std::process::id()),
                "--image",
                "alpine",
                "--",
                "/bin/true"
            ])
        );
        // Injection guard: an entrypoint starting with '-' would be re-read as a kern flag.
        assert!(matches!(
            translate(&v(&["run", "--entrypoint", "--privileged", "alpine"])),
            Err(ShimError::InjectedFlag {
                role: "entrypoint",
                ..
            })
        ));
        // Missing value is still an error, not a silent drop.
        assert!(translate(&v(&["run", "alpine"]))
            .and(translate(&v(&["run", "--entrypoint"])))
            .is_err());
    }

    #[test]
    fn run_fails_on_flags_with_no_kern_equivalent() {
        // No kern equivalent -> must fail loudly (never silently dropped). Includes the
        // namespace-sharing flags kern isolates by design.
        for f in ["--security-opt", "--device", "--pid", "--userns"] {
            assert!(
                matches!(
                    translate(&v(&["run", f, "x", "alpine"])),
                    Err(ShimError::UnsupportedFlag { .. })
                ),
                "flag {f} should fail loudly"
            );
        }
    }

    #[test]
    fn run_fails_on_unknown_flag() {
        assert!(matches!(
            translate(&v(&["run", "--frobnicate", "alpine"])),
            Err(ShimError::UnsupportedFlag { .. })
        ));
    }

    #[test]
    fn run_inline_eq_value() {
        let out = translate(&v(&["run", "--env=A=B", "-p=9000:9000", "alpine"])).unwrap();
        assert!(out.windows(2).any(|w| w == ["--env", "A=B"]));
        assert!(out.windows(2).any(|w| w == ["-p", "9000:9000"]));
    }

    #[test]
    fn run_missing_image_fails() {
        assert_eq!(translate(&v(&["run", "-d"])), Err(ShimError::MissingImage));
    }

    #[test]
    fn run_missing_value_fails() {
        assert_eq!(
            translate(&v(&["run", "-e"])),
            Err(ShimError::MissingValue { flag: "-e".into() })
        );
    }

    #[test]
    fn exec_inserts_separator() {
        let out = translate(&v(&["exec", "-it", "web", "sh", "-c", "ls"])).unwrap();
        assert_eq!(out[0], "exec");
        assert_eq!(out[1], "web");
        let sep = out.iter().position(|x| x == "--").unwrap();
        assert_eq!(&out[sep + 1..], &["sh", "-c", "ls"]);
    }

    #[test]
    fn compose_maps_file_flag() {
        let out = translate(&v(&["compose", "-f", "stack.yml", "up"])).unwrap();
        assert_eq!(out, v(&["compose", "stack.yml", "up"]));
        let out2 = translate(&v(&["compose", "up"])).unwrap();
        assert_eq!(out2, v(&["compose", "docker-compose.yml", "up"]));
    }

    #[test]
    fn passthrough_verbs() {
        assert_eq!(translate(&v(&["ps", "-a"])).unwrap(), v(&["ps", "-a"]));
        assert_eq!(
            translate(&v(&["logs", "web"])).unwrap(),
            v(&["logs", "web"])
        );
        assert_eq!(
            translate(&v(&["stop", "web"])).unwrap(),
            v(&["stop", "web"])
        );
    }

    #[test]
    fn rm_maps_to_stop() {
        assert_eq!(
            translate(&v(&["rm", "-f", "web"])).unwrap(),
            v(&["stop", "web"])
        );
    }

    #[test]
    fn volume_verbs_pass_through() {
        // kern has a real volume store with the same verbs, so `docker volume …` must reach it rather
        // than being refused as "no kern equivalent" (regression: compose auto-creates named volumes,
        // then `docker volume ls` sent the user to real Docker to inspect them).
        for sub in ["ls", "create", "rm", "inspect", "prune"] {
            assert_eq!(
                translate(&v(&["volume", sub, "dati"])).unwrap(),
                v(&["volume", sub, "dati"]),
                "docker volume {sub} must map 1:1"
            );
        }
        // A bare `docker volume` keeps its (empty) argument list - kern prints its own usage.
        assert_eq!(translate(&v(&["volume"])).unwrap(), v(&["volume"]));
    }

    /// `docker compose up -d` is the most typed command in the ecosystem, and it used to die on
    /// kern's generic usage text: compose had no DROP bucket at all, so `-d` was forwarded to a
    /// parser that does not accept it. kern's compose services are detached by construction, so the
    /// flag asks for what already happens and is dropped, not refused.
    #[test]
    fn compose_up_detach_is_dropped_not_forwarded() {
        let out = translate(&v(&["compose", "up", "-d"])).expect("translates");
        assert!(!out.contains(&"-d".to_string()), "got {out:?}");
        assert_eq!(out[0], "compose");
        assert!(out.contains(&"up".to_string()));

        let long = translate(&v(&["compose", "up", "--detach"])).expect("translates");
        assert!(!long.contains(&"--detach".to_string()), "got {long:?}");

        // With an explicit file, the file still travels and `-d` still does not.
        let withf = translate(&v(&["compose", "-f", "stack.yml", "up", "-d"])).expect("translates");
        assert!(withf.contains(&"stack.yml".to_string()), "got {withf:?}");
        assert!(!withf.contains(&"-d".to_string()), "got {withf:?}");
    }

    /// The drop must not eat a `-f` that means "follow", nor anything that merely looks like `-d`.
    #[test]
    fn compose_drop_does_not_touch_neighbouring_flags() {
        let logs =
            translate(&v(&["compose", "-f", "stack.yml", "logs", "-f"])).expect("translates");
        assert!(
            logs.contains(&"-f".to_string()),
            "follow swallowed: {logs:?}"
        );
        // A `-d=…` form is not docker's detach flag; leave it alone rather than guess at it.
        let odd = translate(&v(&["compose", "up", "-d=1"])).expect("translates");
        assert!(odd.contains(&"-d=1".to_string()), "got {odd:?}");
    }

    #[test]
    fn compose_dash_f_is_positional_like_docker() {
        // BEFORE the sub-verb `-f` is --file; AFTER it belongs to the sub-command. Regression: with a
        // single rule, `docker compose -f stack.yml logs -f` swallowed the follow flag as a filename.
        assert_eq!(
            translate(&v(&["compose", "-f", "stack.yml", "logs", "-f", "api"])).unwrap(),
            v(&["compose", "stack.yml", "logs", "-f", "api"])
        );
        // No `-f` at all: the conventional default file, verb and args preserved in order.
        assert_eq!(
            translate(&v(&["compose", "ps"])).unwrap(),
            v(&["compose", "docker-compose.yml", "ps"])
        );
        // `--tail` and its value survive untouched.
        assert_eq!(
            translate(&v(&["compose", "logs", "--tail", "20", "web"])).unwrap(),
            v(&[
                "compose",
                "docker-compose.yml",
                "logs",
                "--tail",
                "20",
                "web"
            ])
        );
        // The injection guard on the file still holds.
        assert!(matches!(
            translate(&v(&["compose", "-f", "--no-pod", "up"])),
            Err(ShimError::InjectedFlag { .. })
        ));
    }

    #[test]
    fn unknown_command_fails() {
        assert_eq!(
            translate(&v(&["swarm", "init"])),
            Err(ShimError::UnknownCommand("swarm".into()))
        );
    }

    #[test]
    fn empty_fails() {
        assert_eq!(translate(&[]), Err(ShimError::Empty));
    }
}

#[cfg(test)]
mod security {
    //! Adversarial tests: every one of these was an empirically-found injection/edge vector, now
    //! required to fail closed. A regression here is a security regression.
    use super::*;
    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn name_flag_injection_refused() {
        // `docker run --name --privileged alpine`: the name must NOT become a kern flag.
        assert_eq!(
            translate(&v(&["run", "--name", "--privileged", "alpine"])),
            Err(ShimError::InjectedFlag {
                role: "box name",
                value: "--privileged".into()
            })
        );
    }

    #[test]
    fn image_leading_dash_refused() {
        assert_eq!(
            translate(&v(&["run", "--", "--privileged"])),
            Err(ShimError::InjectedFlag {
                role: "image",
                value: "--privileged".into()
            })
        );
    }

    #[test]
    fn compose_file_flag_injection_refused() {
        assert_eq!(
            translate(&v(&["compose", "-f", "--no-pod", "up"])),
            Err(ShimError::InjectedFlag {
                role: "compose file",
                value: "--no-pod".into()
            })
        );
    }

    #[test]
    fn empty_image_refused() {
        assert_eq!(
            translate(&v(&["run", "", "alpine"])),
            Err(ShimError::EmptyImage)
        );
    }

    #[test]
    fn combined_short_flags_expand() {
        // `-dit` -> `-d -i -t`
        let out = translate(&v(&["run", "-dit", "alpine"])).unwrap();
        assert!(out.windows(1).any(|w| w == ["-d"]));
        assert!(out.contains(&"-i".to_string()));
        assert!(out.contains(&"-t".to_string()));
        assert!(out.contains(&"alpine".to_string()));
    }

    #[test]
    fn combined_short_with_unknown_refused() {
        // `-dx`: contains an unknown short - must NOT be guessed.
        assert!(matches!(
            translate(&v(&["run", "-dx", "alpine"])),
            Err(ShimError::UnsupportedFlag { .. })
        ));
    }

    #[test]
    fn value_that_looks_like_flag_stays_a_value() {
        // `-e --privileged`: `--privileged` is the VALUE of `-e`, forwarded as such (not a kern flag).
        let out = translate(&v(&["run", "-e", "--privileged", "alpine"])).unwrap();
        assert!(out.windows(2).any(|w| w == ["-e", "--privileged"]));
    }

    #[test]
    fn dashdash_inside_command_preserved() {
        // A `--` that belongs to the container command must survive verbatim.
        let out = translate(&v(&["run", "alpine", "sh", "-c", "--", "x"])).unwrap();
        let sep = out.iter().position(|x| x == "--").unwrap();
        assert_eq!(&out[sep + 1..], &["sh", "-c", "--", "x"]);
    }

    #[test]
    fn exec_leading_dash_target_refused() {
        // `docker exec -- sh`: `--` cannot be a target; refused (not silently mistaken for a box).
        assert!(translate(&v(&["exec", "--", "sh"])).is_err());
    }
}

#[cfg(test)]
mod fuzz_robustness {
    //! Bounded in-tree fuzz: 200k deterministic pseudo-random argvs. `translate` MUST always return
    //! (Ok/Err) and NEVER panic - no index OOB, no unhandled slice, no arithmetic overflow - on any
    //! input, however malformed. (A full cargo-fuzz+ASAN target that exercises this continuously is a
    //! follow-up once kern-cli exposes a lib entry; this proves the panic-free property empirically now.)
    use super::*;

    // xorshift64* - a tiny deterministic PRNG (no external crate; reproducible seed).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545F4914F6CDD1D)
        }
        fn pick<'a>(&mut self, choices: &[&'a str]) -> &'a str {
            let idx = (self.next() as usize) % choices.len();
            choices[idx]
        }
    }

    #[test]
    fn translate_never_panics_on_arbitrary_argv() {
        // An alphabet mixing verbs, real flags, injection bait, separators, empties, unicode, and junk.
        let alphabet = [
            "run",
            "exec",
            "compose",
            "ps",
            "swarm",
            "build",
            "rm",
            "rmi",
            "logs",
            "-d",
            "-it",
            "-dit",
            "-dx",
            "--name",
            "--privileged",
            "-p",
            "-e",
            "--entrypoint",
            "-u",
            "-f",
            "--no-pod",
            "--",
            "-",
            "--=",
            "=x",
            "",
            "alpine",
            "sh",
            "-c",
            "8080:80",
            "K=V",
            "--env=A=B",
            "-p=1:1",
            "--label",
            "app=x",
            "ñ",
            "🔥",
            "--foo",
            "-l",
            "-v",
            "/a:/b",
            "--name=",
            "value",
        ];
        let mut rng = Rng(0x1234_5678_9ABC_DEF0);
        let mut oks = 0u64;
        let mut errs = 0u64;
        for _ in 0..200_000u64 {
            let len = (rng.next() as usize) % 8; // 0..=7 args
            let argv: Vec<String> = (0..len).map(|_| rng.pick(&alphabet).to_string()).collect();
            // The property under test: this call must return, never panic.
            match translate(&argv) {
                Ok(out) => {
                    // Invariant: a successful `run`/`create` translation always starts with `box`
                    // and never leaks a bare injected flag into the NAME slot.
                    if out.first().map(String::as_str) == Some("box") {
                        // out[1] is the name; it must never be a value we refused (starts with '-').
                        if let Some(nm) = out.get(1) {
                            assert!(
                                !nm.starts_with('-'),
                                "injected flag reached NAME slot: {out:?}"
                            );
                        }
                    }
                    oks += 1;
                }
                Err(_) => errs += 1,
            }
        }
        // Sanity: the corpus exercised both accept and reject paths.
        assert!(
            oks > 0 && errs > 0,
            "fuzz corpus too one-sided: ok={oks} err={errs}"
        );
    }

    /// The re-exec under `systemd-run --scope` must replay the DECIDED command, not the typed one.
    ///
    /// Found on the Pi 5 rather than at a desk: `docker run --rm alpine echo hi` through the symlink
    /// the README documents failed with "kern run: unknown flag". kern re-execs itself to apply the
    /// cap through a scope, and the second pass received `argv[0]` already resolved through the
    /// symlink, so the shim did not recognise itself, together with the UNTRANSLATED arguments. As
    /// root it did not happen, because the direct path does not re-exec: which is why it went
    /// unnoticed on every development machine.
    #[test]
    fn the_reexec_replays_the_translated_argv_not_the_typed_one() {
        let typed: Vec<String> = ["run", "--rm", "alpine:3.19", "echo", "hi"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let translated = translate(&typed).expect("docker run is translatable");
        // Positive control: the translation really does change the shape, otherwise the assertions
        // below would be distinguishing nothing.
        assert_ne!(translated, typed, "the translation must change the argv");
        assert_eq!(translated.first().map(String::as_str), Some("box"));
        assert!(
            !translated.iter().any(|a| a == "--rm"),
            "`--rm` is in the DROP bucket and must not survive: {translated:?}"
        );

        set_effective(&translated);
        // What the re-exec and the persistent unit replay is the translated form, which kern
        // speaks, and not `run --rm …`, which kern's own `run` verb refuses.
        assert_eq!(effective_args(), translated);
        assert_eq!(effective_args().first().map(String::as_str), Some("box"));
    }
}
