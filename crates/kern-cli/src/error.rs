//! Error type for the CLI.
//!
//! A hand-rolled enum keeps the binary dependency-free. The roadmap target is a
//! `thiserror`-derived enum per crate (see ARCHITECTURE.md); the *shape* - a typed error with
//! an optional actionable hint, mapped to an exit code in one place - is already here.

#[derive(Debug)]
pub enum Error {
    UnknownCommand(String),
    /// A box name failed validation (path separator / traversal / empty).
    InvalidBox(&'static str),
    /// An operational/validation failure inside a box command (a bad `-v` spec, a secret, a `box cp`,
    /// a pod op…). The message is self-explanatory, so it carries no generic hint - unlike [`Setup`],
    /// which is the genuine "the sandbox couldn't start here" failure. ([`Setup`]: Error::Setup)
    Sandbox(String),
    /// The sandbox itself could not be created/run (namespaces, mounts, exec) - an environment
    /// problem, not bad input. Carries the "needs unprivileged user namespaces" hint.
    Setup(String),
    /// A named box isn't running (or has no logs) - a lookup miss, not a setup failure.
    NotRunning(String),
    /// A box name is already held by a live box - a naming conflict, not a setup failure.
    AlreadyRunning(String),
    /// A `kern volume` operation failed for a non-in-use reason (unknown name, bad name, I/O). The
    /// hint points at `kern volume ls` - NOT at boxes (that's [`AlreadyRunning`], used when a volume
    /// is in use) - and is dropped entirely when the message already carries its own remedy, which
    /// it does for the EACCES case. ([`AlreadyRunning`]: Error::AlreadyRunning)
    Volume(String),
    /// An OCI image pull/extract failed.
    Oci(String),
    /// A compose file could not be parsed or brought up.
    Compose(String),
    /// A `kern build` failed: a bad Dockerfile, a COPY that escapes the image, or the build context.
    Build(String),
    /// A `kern.toml` profile could not be parsed, found, or applied.
    Config(String),
    /// A recognised command was invoked with missing/invalid arguments.
    /// A flag or verb the CLI does not take. Displays BARE, with no kind prefix: routed through
    /// `Config` it read `error: config: config list: unknown flag …` with "config" doubled, and through
    /// `Sandbox` it read `error: sandbox: uninstall: unknown flag …`, announcing a parse error as a
    /// sandbox failure. The message already names the verb, so a prefix can only get in the way. Its
    /// hint points at `--help`, unlike `Config`'s, which sent someone who mistyped a flag to read about
    /// where profiles live.
    Cli(String),
    Usage(&'static str),
    /// A WORKLOAD's own exit status, to be adopted as kern's.
    ///
    /// `compose run <service> <command>` is transparent about what the command did: a test runner
    /// that exits 3 must make `kern` exit 3, or a CI job cannot tell a failing suite from a failing
    /// runtime. Carried as an error variant rather than a `process::exit` inside the command layer,
    /// because that layer returns `Result` and the mapping to a status happens in exactly one place
    /// (see `main`). It prints NOTHING: the command already said whatever it had to say on its own
    /// stdout, and "error: exited 3" underneath would be kern narrating someone else's result.
    Workload(i32),
}

impl Error {
    /// An optional one-line, actionable hint shown under the error.
    pub fn hint(&self) -> Option<String> {
        match self {
            // A DOCKER HABIT GETS THE PAIR THAT DOES THE JOB, rather than a pointer to a list of
            // fifty verbs. `kern rm` does not exist and never will: a box is stopped and its
            // remains are collected, which is two verbs because they are two decisions. An outside
            // reviewer typed it, and so does everyone arriving from Docker; kern's own README
            // shipped it once. Naming the pair costs one line and absorbs the habit.
            // A workload's own status carries no hint: kern has nothing to add about someone
            // else's exit code.
            Error::Workload(_) => None,
            Error::UnknownCommand(c) => Some(match c.as_str() {
                "rm" => "kern has no `rm`: `kern stop <name>` ends a box and `kern gc` collects \
                         what stopped boxes left behind. For an image it is `kern rmi`, for a \
                         volume `kern volume rm`"
                    .into(),
                "start" => "kern has no `start`: a box is created and started in one step, with \
                            `kern box <name> --image <image>`"
                    .into(),
                "restart" => "kern has no `restart`: `kern stop <name>` and start it again, or \
                              give the box `--restart` so kern supervises it"
                    .into(),
                _ => "run `kern --help` for the list of commands".to_string(),
            }),
            Error::InvalidBox(_) => Some(
                "box names: letters/digits/_/./- only, no leading '-' or '.', max 200 chars".into(),
            ),
            // Operational/validation errors are self-explanatory - no generic hint (it used to
            // wrongly show the userns/rootfs hint on `-v`/secret/port errors).
            Error::Sandbox(_) => None,
            // Branch on the message, for the same reason `oci_hint` does: the setup step that failed
            // decides what the reader should do next, and the variant alone does not know it. An
            // external reviewer measured a box refused by `RLIMIT_NPROC` and got
            //
            //   error: sandbox: fork(idmap helper) failed: Resource temporarily unavailable (os error 11)
            //   hint: needs unprivileged user namespaces and a valid --rootfs directory
            //
            // The message is exact and the hint sends the reader to two places that are both fine.
            // EAGAIN on a fork is a process-limit problem: user namespaces are enabled and the rootfs
            // is valid, or the code would not have reached the fork.
            //
            // Matched on `(os error 11)` rather than on the prose, and the reason is structural
            // rather than empirical: that suffix is APPENDED by `io::Error`'s Display impl, so only
            // the text before it can ever come from libc. It is invariant by construction, which also
            // means a glibc build is as safe as the shipped musl one. Checking locales instead would
            // have proved nothing on the shipped binary, which is static musl with no locale
            // machinery in it at all.
            //
            // The key is asserted from a REAL failure, not from a rendering a test built: see
            // `eagain_hint_survives_a_real_failure_not_a_constructed_one` in tests/smoke.rs. The
            // gap that closes is an errno reaching here through something that is not an
            // `io::Error`, which drops the suffix and reverts this hint in silence.
            // "TASKS (threads), not processes" is not a detail. The reviewer who reported this hint
            // then read `ulimit -u` against a PROCESS count, got 10 against 149, and concluded the
            // kernel was accounting something unobservable. It costs two rounds and a wrong mechanism
            // to omit it, to a reader who already had the errno and a reason to care. Measured here:
            // an x86_64 desktop owned 208 processes and 1918 TASKS, and the limit at which a single
            // fork started succeeding was 1932. Against the task count the threshold IS the count;
            // against the process count it looks like a factor of nine.
            //
            // What is deliberately NOT said: the charge is per-UID across the whole KERNEL, so on a
            // shared-kernel host (WSL2 runs several distributions on one) the tasks are spread over
            // PID namespaces and no single `/proc` can see them all. True, and measured, and it would
            // read as noise to the reader on a laptop. The threads clause is the half that is true
            // everywhere and wrong to omit.
            Error::Setup(msg) if msg.contains("os error 11") => Some(
                "out of process slots: `ulimit -u` is per-UID and counts TASKS (threads), not \
                 processes, across the whole system, so another program owned by this user, or one \
                 with many threads, can exhaust it. Compare `ulimit -u` against the task count, or \
                 raise `LimitNPROC=`/`DefaultLimitNPROC=` for this session"
                    .into(),
            ),
            // A FORK FAILURE IS NEVER A USERNS OR ROOTFS PROBLEM, whatever the errno, and the
            // generic hint below asserts that it is.
            //
            // The EAGAIN branch above fixed one errno in this class after a reviewer was sent to two
            // places that were both fine. A second reviewer then hit the same wrong hint under a
            // DIFFERENT one, on WSL2 kernel 6.6, deterministically 3 of 3:
            //
            //   error: sandbox: fork failed: Out of memory (os error 12)
            //   hint: needs unprivileged user namespaces and a valid --rootfs directory
            //
            // and reported, correctly, that the hint invents a diagnosis. So the rule is widened from
            // one errno to the whole class, because the argument was never about EAGAIN: by the time
            // any fork on this path runs, the user namespace has been created and the rootfs has been
            // validated, or control would not have reached it. Naming them is wrong for every errno,
            // and enumerating errnos one reviewer at a time is how the third one gets found by a user.
            //
            // WHAT THIS DELIBERATELY DOES NOT SAY IS THE CAUSE. On the developer's host,
            // `clone3(CLONE_INTO_CGROUP)` into a cgroup it may not write answers EACCES, and into a
            // populated one EBUSY; neither is the ENOMEM measured above, and the mechanism behind
            // that one is not known here. A hint that guessed would be the same defect this branch
            // exists to remove. It names the errno the kernel gave, says where the failure is not,
            // and points at the two things a reader can actually inspect.
            Error::Setup(msg) if msg.contains("fork") => Some(
                "the process could not be created. The errno above is the kernel's own answer. The two limits a fork can hit are `ulimit -u`, which is per-UID and counts threads across the whole system, and the `pids.max` of the cgroup kern is starting in. The user namespace and the rootfs are already established by the time kern forks, so neither is the cause"
                    .into(),
            ),
            // A refused `-v` already carries its own cause and its own remedy, and the general hint
            // under it is not merely redundant but false: it says the failure is "a host capability
            // rather than a wrong command" when the host is fine and the source path is the wrong
            // one, then sends the reader to `kern doctor`, which cannot see a submount under a
            // volume source. Keyed on the message rather than the variant, same shape as
            // `Error::Volume` above and `oci_hint` below, because the setup error crosses a process
            // boundary as a plain string and the variant that built it is gone by here.
            Error::Setup(msg) if msg.contains("mount(volume bind) failed for -v ") => None,
            // THE SAME STRING THE ISOLATION CRATE PRINTS from inside the forked child, which cannot
            // reach this function. Two wordings for one condition drift, and the older one here named
            // two of the four things a setup failure is.
            Error::Setup(_) => Some(kern_isolation::SETUP_FAILURE_HINT.into()),
            Error::NotRunning(_) => Some("run `kern ps` to see running boxes".into()),
            Error::AlreadyRunning(_) => {
                Some("run `kern ps` to see running boxes; `kern stop <name>` frees the name".into())
            }
            // A volume error that already carries its own remedy needs no generic pointer under it:
            // printing "run `kern volume ls`" beneath two paste-ready commands is noise, and noise
            // under an instruction is how an instruction gets skipped. Multi-line means the message
            // brought its own fix. Same shape as `oci_hint` below, which branches on the message
            // rather than on the variant.
            Error::Volume(msg) => {
                (!msg.contains('\n')).then(|| "run `kern volume ls` to see existing volumes".into())
            }
            // The right hint depends on *why* the pull failed - telling someone whose image name is
            // wrong to "install curl and tar" sends them down the wrong path. Branch on the message.
            Error::Oci(msg) => Some(oci_hint(msg)),
            // THE HINT USED TO DESCRIBE THE WRONG FILE FORMAT. kern reads two kinds of stack: a
            // `docker-compose.yml` and its own TOML. The hint named only the TOML
            // (``compose: `[box.NAME]` tables with image/rootfs, command, depends_on``), so every
            // refusal of a YAML file - which is almost all of them - ended with advice about a
            // syntax the reader is not writing. MEASURED on `services:` written as a list: the
            // message said the block was empty (wrong, and fixed at the parser) and the hint then
            // sent the reader to TOML. Two wrong directions under one mistake.
            //
            // SUPPRESSED WHEN THE MESSAGE ALREADY CARRIES ITS REPAIR, which is the rule `Volume`
            // above already follows and `oci_hint` below: a generic pointer printed under a
            // paste-ready instruction is noise, and noise under an instruction is how an
            // instruction gets skipped. A backtick is the marker, because that is how this codebase
            // writes a key or a command inside a sentence, and a newline is the other (a
            // multi-line message brought its own fix).
            Error::Compose(msg) => (!msg.contains('`') && !msg.contains('\n')).then(|| {
                "compose: a stack is a `docker-compose.yml` (`services:` with `image:` or \
                 `build:`) or a kern TOML (`[box.NAME]` with image/rootfs, command, depends_on)"
                    .into()
            }),
            // A build-history lookup miss (`build logs|inspect <id>`) is not a Dockerfile problem, so
            // point it at the list - not the FROM/COPY hint, which would mislead. Same message-shape
            // routing as `oci_hint`.
            Error::Build(msg) if msg.starts_with("no build ") => {
                Some("run `kern builds` to list build ids".into())
            }
            Error::Build(_) => Some(
                "build: the Dockerfile must start with FROM (ARG may precede it); COPY/ADD paths \
                 stay inside the image"
                    .into(),
            ),
            Error::Config(_) => {
                Some("profiles live in ~/.config/kern/kern.toml - see docs/CONFIG.md".into())
            }
            Error::Cli(_) | Error::Usage(_) => Some("run `kern --help` for full usage".into()),
        }
    }
}

/// Pick the hint for a pull failure from the shape of its message. `curl`/`tar` missing is a real but
/// *rare* cause; a mistyped name or a private repo is the common one, so only surface the tooling hint
/// when a tool actually failed. The message is the `OciError` Display (or a local cache error).
fn oci_hint(msg: &str) -> String {
    if msg.starts_with("bad image reference") {
        "image refs look like `alpine`, `alpine:3.19`, or `ghcr.io/user/app:tag`".into()
    } else if msg.contains("curl failed")
        || msg.contains("tar failed")
        || msg.contains("sha256sum")
        || msg.contains("zstd")
    {
        "pull/push need `curl`, GNU `tar`, `gzip`, `sha256sum` (and `zstd` for zstd-compressed images) on PATH, plus a working network"
            .into()
    } else if msg.contains("rate-limiting") {
        // The error already says the name and tag are NOT the problem, and already names the way out.
        // Appending the generic name/tag hint under it made the two lines contradict each other, which
        // is worse than no hint: the reader has to guess which half to believe.
        "an authenticated pull has a much higher quota; `kern login <registry>` once and it persists"
            .into()
    } else {
        // Registry / manifest / not-found: the name or tag is the likely culprit.
        "check the image name and tag exist; private images need `kern login` first".into()
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownCommand(c) => write!(f, "unknown command '{c}'"),
            Error::InvalidBox(why) => write!(f, "invalid box name: {why}"),
            Error::Sandbox(why) => write!(f, "sandbox: {why}"),
            Error::Setup(why) => write!(f, "sandbox: {why}"),
            Error::NotRunning(why) => write!(f, "{why}"),
            Error::AlreadyRunning(why) => write!(f, "{why}"),
            Error::Volume(why) => write!(f, "{why}"),
            // The OCI error already carries its own kind prefix (`registry:`/`extract:`/`ref:` from
            // `OciError`'s Display), so we don't add another - a doubled "registry: registry:" was the
            // symptom. A local cache error (no OCI prefix) still reads fine on its own.
            Error::Oci(why) => write!(f, "{why}"),
            Error::Compose(why) => write!(f, "compose: {why}"),
            Error::Build(why) => write!(f, "build: {why}"),
            Error::Config(why) => write!(f, "config: {why}"),
            Error::Cli(why) => write!(f, "{why}"),
            Error::Usage(u) => write!(f, "usage: kern {u}"),
            // Deliberately empty: `main` never prints this one. See the variant's doc.
            Error::Workload(_) => Ok(()),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_hint_routes_history_miss_to_the_builds_list() {
        // A build-history lookup miss points at `kern builds`, not the Dockerfile/FROM hint.
        let miss = Error::Build("no build '1-2'".into()).hint().unwrap();
        assert!(miss.contains("kern builds"));
        assert!(!miss.contains("FROM"));
        // A real build error keeps the Dockerfile hint.
        let real = Error::Build("RUN failed (exit 1)".into()).hint().unwrap();
        assert!(real.contains("FROM"));
    }

    /// **Every process-creation failure site in the isolation crate reaches the fork branch, and the
    /// set of them is pinned so a new one cannot be added silently.**
    ///
    /// The branch matches on the word `fork` in the rendered message, and an outside reviewer could
    /// not exercise it end to end because both of our kernels answer `RLIMIT_NPROC=1` with EAGAIN,
    /// which the more specific branch takes first. So it is proven by CONSTRUCTION instead, through the
    /// real rendering chain rather than a hand-written string:
    ///
    ///     Error::last("fork")  ->  Error::Syscall("fork", io)
    ///     Display              ->  "fork failed: {io}"
    ///     the CLI              ->  Error::Setup(e.to_string())
    ///     hint()               ->  msg.contains("fork")
    ///
    /// The remaining hole is a FUTURE site named something the match cannot see - `clone3`, `posix_spawn`,
    /// `vfork` - which would silently fall through to the generic setup hint and re-open exactly the
    /// defect that was reported twice. This reads the isolation crate's own source, extracts every
    /// `Error::last("...")` operation, and requires the process-creation ones to be exactly the set
    /// named here. Adding one fails this test rather than a user.
    #[test]
    fn every_process_creation_failure_site_reaches_the_fork_hint() {
        let mut ops: Vec<String> = Vec::new();
        for dir in ["../kern-isolation/src", "crates/kern-isolation/src"] {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for e in entries.flatten() {
                let Ok(text) = std::fs::read_to_string(e.path()) else {
                    continue;
                };
                let mut rest = text.as_str();
                while let Some(i) = rest.find("Error::last(\"") {
                    rest = &rest[i + 13..];
                    if let Some(j) = rest.find('"') {
                        ops.push(rest[..j].to_string());
                        rest = &rest[j..];
                    }
                }
            }
            if !ops.is_empty() {
                break;
            }
        }
        assert!(
            ops.len() > 20,
            "the isolation source must have been read: found {} operations",
            ops.len()
        );
        ops.sort();
        ops.dedup();
        // Anything that creates a process. Matched broadly on purpose, because the point is to CATCH
        // a name nobody thought of, so the filter has to be wider than the match arm it checks.
        //
        // `unshare(...)` is excluded and that exclusion is the one judgement in this test:
        // `unshare(CLONE_NEWNS)` carries the substring `clone` and creates NO process, it moves the
        // caller into a new namespace, and the generic setup hint is right for it. The CALL is
        // excluded rather than the substring, so a future `clone3` still trips the filter.
        let creators: Vec<&String> = ops
            .iter()
            .filter(|o| {
                let lower = o.to_ascii_lowercase();
                !lower.starts_with("unshare(")
                    && (lower.contains("fork")
                        || lower.contains("clone")
                        || lower.contains("spawn")
                        || lower.contains("exec"))
            })
            .collect();
        let names: Vec<&str> = creators.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            names,
            // `fork(id-mapped)` is the layer unpack and the id-mapped removal (see
            // `kern_isolation::with_id_mapped_userns`). It CONTAINS `fork`, so the hint branch
            // already covers it; the list is pinned so a new site is a conscious addition rather
            // than something that slid in behind a substring match.
            vec!["execvp", "fork", "fork(id-mapped)", "fork(idmap helper)"],
            "the process-creation failure sites changed. A new one must either contain `fork`, so the \
             hint branch sees it, or be given its own branch: falling through to the generic setup \
             hint is the defect this test exists to stop"
        );
        // `execvp` is deliberately in that list and deliberately NOT a fork failure: it has its own
        // reporting in the isolation crate, and it must NOT collect the fork hint here.
        for op in ["fork", "fork(idmap helper)"] {
            for errno in [libc::EAGAIN, libc::ENOMEM, libc::EPERM, libc::EINVAL] {
                // THE REAL CHAIN, not a literal: `Display` is what puts the operation into the string
                // the match arm reads, so a change to it breaks this test rather than the hint.
                let iso = kern_isolation::Error::Syscall(
                    match op {
                        "fork" => "fork",
                        _ => "fork(idmap helper)",
                    },
                    std::io::Error::from_raw_os_error(errno),
                );
                let rendered = iso.to_string();
                assert!(
                    rendered.contains("fork"),
                    "the rendering must carry the operation, or the match arm cannot see it: {rendered}"
                );
                let hint = Error::Setup(rendered.clone())
                    .hint()
                    .unwrap_or_else(|| String::from("<none>"));
                let expected_specific = errno == libc::EAGAIN;
                if expected_specific {
                    assert!(
                        hint.contains("ulimit -u"),
                        "EAGAIN keeps its own, more specific branch: {hint}"
                    );
                } else {
                    assert!(
                        hint.contains("the process could not be created"),
                        "errno {errno} on {op} must reach the fork branch, got: {hint}"
                    );
                }
                assert!(
                    !hint.contains("could not be BUILT"),
                    "a fork failure must never collect the generic setup hint: {hint}"
                );
            }
        }
    }

    /// **No fork failure is blamed on user namespaces or the rootfs, for ANY errno.**
    ///
    /// The EAGAIN test below covers one errno with a measured mechanism. This one covers the CLASS,
    /// and it exists because a real-failure test could not: on the developer's host `RLIMIT_NPROC=1`
    /// produces EAGAIN, which the more specific branch catches first, so the end-to-end test in
    /// `tests/smoke.rs` stays GREEN with this branch deleted. It asserts the guard it names without
    /// exercising it, which is the same defect this project has now made twice.
    ///
    /// A constructed value is adequate HERE and not for EAGAIN, and the difference is structural
    /// rather than a shortcut: that branch matches on `(os error 11)`, a suffix appended by
    /// `io::Error`'s Display, so it can be lost by a change in how an errno reaches the formatter and
    /// needs a real failure to prove it survives. This branch matches on the word `fork`, which comes
    /// from kern's own message and from nowhere else.
    ///
    /// The ENOMEM case is the one an external reviewer measured on WSL2 kernel 6.6, deterministic
    /// 3 of 3, where the hint told them to check user namespaces and `--rootfs` and both were fine.
    #[test]
    fn no_errno_makes_a_fork_failure_a_userns_or_rootfs_problem() {
        // Every rendering kern can produce for a failed fork, including the two errnos measured in
        // the field and the two the developer's own kernel returns for an unreachable cgroup.
        for errno in [
            libc::EAGAIN,
            libc::ENOMEM,
            libc::EACCES,
            libc::EBUSY,
            libc::EPERM,
            libc::EINVAL,
        ] {
            let io = std::io::Error::from_raw_os_error(errno);
            for msg in [
                format!("fork failed: {io}"),
                format!("fork(idmap helper) failed: {io}"),
            ] {
                let hint = Error::Setup(msg.clone())
                    .hint()
                    .unwrap_or_else(|| String::from("<no hint>"));
                // THE EXACT SENTENCE, not the words in it. This hint mentions the rootfs in order
                // to RULE IT OUT, which is the opposite of pointing at it, and an assertion on the
                // bare word failed against the CORRECT message. What is forbidden is the generic
                // setup hint being handed to a fork failure, so that is what is named.
                assert!(
                    !hint.contains("needs unprivileged user namespaces and a valid --rootfs"),
                    "errno {errno} rendered as {msg:?} got the generic setup hint: {hint}"
                );
                // AND IT MUST READ AS A SENTENCE. A `\`-continued literal that rustfmt joins back
                // onto one line keeps the indentation as runs of spaces INSIDE the string, and the
                // user sees them. That happened while writing this very hint.
                assert!(
                    !hint.contains("  "),
                    "errno {errno}: the hint carries collapsed indentation as double spaces: {hint:?}"
                );
                assert!(
                    hint != "<no hint>",
                    "errno {errno} was left with no hint at all: {msg:?}"
                );
            }
        }
        // THE CONTROL, or the loop above is satisfiable by a build that returns nothing for every
        // Setup error: a setup failure that is NOT a fork must still get the general hint.
        //
        // Compared against the CONSTANT and not against a phrase copied out of it. The first version
        // of this line asserted the words "unprivileged user namespaces", and when that wording was
        // replaced the test went red for a reason that had nothing to do with what it guards. A test
        // that breaks when the prose is edited is a test nobody will keep.
        let general = Error::Setup("unshare(CLONE_NEWUSER) failed".into())
            .hint()
            .expect("a non-fork setup error must still carry the general hint");
        assert_eq!(general, kern_isolation::SETUP_FAILURE_HINT);
    }

    /// A setup failure caused by EAGAIN on a fork is a process-limit problem, and the userns/rootfs
    /// hint sends the reader to two places that are both already fine: the code could not have
    /// reached the fork otherwise. Reported by an external reviewer who hit it with a tightened
    /// `ulimit -u`, message exact and hint pointing elsewhere.
    ///
    /// The subject is the REAL rendering, not a hand-written string: the message is built from
    /// `std::io::Error::from_raw_os_error(EAGAIN)` exactly as `Error::last` builds it, so a change in
    /// how Rust renders errno breaks this test rather than the hint in the field.
    #[test]
    fn setup_hint_names_the_process_limit_on_eagain() {
        let rendered = format!(
            "fork(idmap helper) failed: {}",
            std::io::Error::from_raw_os_error(libc::EAGAIN)
        );
        assert!(
            rendered.contains("os error 11"),
            "the match key is gone from the rendering: {rendered}"
        );
        let h = Error::Setup(rendered).hint().unwrap();
        assert!(h.contains("ulimit -u"), "got: {h}");
        assert_ne!(
            h,
            kern_isolation::SETUP_FAILURE_HINT,
            "a fork that ran out of process slots must not collect the generic setup hint"
        );
        // Every other setup failure keeps the hint it had, compared against the CONSTANT so that
        // editing the prose does not fail a test about routing.
        let other = Error::Setup("pivot_root failed: Invalid argument (os error 22)".into())
            .hint()
            .unwrap_or_default();
        assert_eq!(other, kern_isolation::SETUP_FAILURE_HINT, "got: {other}");
    }

    /// A volume bind that explained itself gets no generic hint under it, and every other setup
    /// failure still does.
    ///
    /// The subject is the REAL message: it is built by the same code path the sandbox uses, so if
    /// that wording is ever rephrased past the key this test goes red instead of the field silently
    /// regaining a hint that contradicts the line above it.
    #[test]
    fn a_refused_volume_bind_does_not_collect_the_generic_setup_hint() {
        let msg = "mount(volume bind) failed for -v /tmp:/x: Invalid argument (os error 22). 1 filesystem is mounted under /tmp (/tmp/RustDesk-1000/cliprdr-server). kern binds a volume NON-recursively";
        assert!(
            Error::Setup(msg.into()).hint().is_none(),
            "a message that already names its own remedy must not be followed by the generic one"
        );
        // THE CONTROL: the suppression is keyed on this message and not on the variant, so a
        // different setup failure keeps the hint. Compared against the CONSTANT, not its prose.
        assert_eq!(
            Error::Setup("mount(overlay) failed: Invalid argument (os error 22)".into())
                .hint()
                .unwrap_or_default(),
            kern_isolation::SETUP_FAILURE_HINT
        );
    }

    #[test]
    fn oci_hint_points_at_the_actual_cause() {
        // A tool failure → the tooling hint.
        assert!(oci_hint("curl failed: exit 6").contains("curl"));
        assert!(oci_hint("tar failed: bad header").contains("tar"));
        // A zstd-compressed image without the `zstd` tool → the tooling hint names zstd.
        assert!(oci_hint(
            "zstd failed: this image uses zstd-compressed layers but `zstd` is not installed"
        )
        .contains("zstd"));
        // A bad reference → the ref-format hint, not tooling.
        let r = oci_hint("bad image reference: alpine::");
        assert!(r.contains("image refs"));
        assert!(!r.contains("curl"));
        // A missing/private image → name/tag/login, not tooling.
        let reg = oci_hint("registry: cannot access 'me/app' - it may be private");
        assert!(reg.contains("kern login"));
        assert!(!reg.contains("curl"));
        // "no manifest for <arch>" and local cache errors fall through to the same safe hint.
        assert!(oci_hint("registry: no manifest for aarch64").contains("image name"));
        // A rate limit must NOT get the name/tag hint: the error itself states that the name is not
        // the problem, and two contradicting lines are worse than one.
        let rl = oci_hint(
            "registry: registry-1.docker.io is rate-limiting this pull of 'library/alpine'",
        );
        assert!(
            !rl.contains("check the image name"),
            "a rate limit must not be hinted as a naming problem: {rl}"
        );
        assert!(
            rl.contains("quota"),
            "the hint must name the actual remedy: {rl}"
        );
    }
}

#[cfg(test)]
mod hint_tests {
    use super::Error;

    /// A DOCKER VERB THAT KERN DOES NOT HAVE NAMES THE PAIR THAT DOES THE JOB.
    ///
    /// `kern rm` does not exist and never will: stopping a box and collecting what it left behind
    /// are two decisions, so they are two verbs. Everyone arriving from Docker types it anyway, an
    /// outside reviewer did, and kern's own README shipped it once. A hint that only says "run
    /// --help" sends them to a list of fifty verbs to find the two.
    #[test]
    fn a_docker_verb_kern_lacks_is_answered_with_the_verbs_that_replace_it() {
        let hint = |v: &str| Error::UnknownCommand(v.to_string()).hint().expect("a hint");
        let rm = hint("rm");
        assert!(rm.contains("kern stop"), "{rm}");
        assert!(rm.contains("kern gc"), "{rm}");
        assert!(
            rm.contains("kern rmi"),
            "and the image verb, which IS `rm`-shaped: {rm}"
        );
        assert!(hint("start").contains("kern box"), "{}", hint("start"));
        assert!(hint("restart").contains("--restart"), "{}", hint("restart"));
        // THE FALLBACK IS STILL THERE, or this would be a table that swallowed every typo.
        assert_eq!(
            hint("nonsense"),
            "run `kern --help` for the list of commands"
        );
        // The hints are single-line: a line break in a hint reads as a second error.
        for v in ["rm", "start", "restart", "nonsense"] {
            assert!(!hint(v).contains('\n'), "{v} hint wraps: {}", hint(v));
        }
    }
}
