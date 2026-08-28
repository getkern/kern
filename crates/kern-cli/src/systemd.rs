//! `kern compose <file> systemd` - emit a systemd unit for a stack, on stdout, installing nothing.
//!
//! kern is daemonless: after a reboot PID 1 starts, not you, so a stack that must come back needs an
//! init to be told about it. That is the ONE thing kern cannot do for itself, and it is why this
//! generator exists. It writes to stdout and never to disk: where a unit belongs is a decision about
//! someone's machine (system vs user, which target, enabled or not), and a runtime that quietly
//! installs units into `/etc` is doing something the user did not ask for.
//!
//! **What the unit does NOT do.** It brings the stack up at boot and tears it down at stop. It does
//! not supervise. A service with a `restart:` policy IS restarted when it dies, and the emitted unit
//! says so rather than letting a reader infer a gap wider than the real one. What is missing is a
//! watcher over the member SET: nothing re-applies policy once an individual supervisor is gone.
//!
//! WHICH SUPERVISOR, because it is not one mechanism and an earlier version of this paragraph named
//! only the second. Measured on 2026-08-28, x86 desktop with a `systemd --user` manager:
//!
//!   A stack of ONE service is a standalone persistent box, so it takes the systemd path and gets a
//!   `kern-<stack>-<svc>.service` unit. Killing its supervisor restarted it (pid 294823 -> 294940).
//!
//!   A stack of TWO is a POD, and a pod member cannot take a standalone unit: it needs the holder's
//!   shared namespace, which a unit outliving the holder could not re-join. Zero systemd units
//!   existed for that stack, and the supervisor is a `kern box` process `up` leaves running. Killing
//!   THAT left the member `orphaned` and it was never restarted, still orphaned 36 s later.
//!
//! So the gap this paragraph exists to name is real and it is narrower on a one-service stack, where
//! systemd is the watcher kern does not have. Two paths, and the unit's own comment names the one
//! the reader is about to install for.
//!
//! No `unwrap`/`expect`/`panic!`: every branch returns `Result`.

use crate::error::Error;

/// Where the generated unit is meant to live, which decides three things at once: the install target,
/// whether `loginctl enable-linger` matters, and whether a network ordering line is meaningful.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnitScope {
    /// `systemctl --user`, for a rootless kern. The user manager has no `network-online.target`, and
    /// without lingering the unit stops at logout.
    User,
    /// `systemctl` (system manager), for a kern running as real root.
    System,
}

impl UnitScope {
    /// The scope that matches the caller. Real uid, not effective: a setuid binary must not emit a
    /// system unit on behalf of a normal user.
    pub fn detect() -> Self {
        if unsafe { libc::getuid() } == 0 {
            Self::System
        } else {
            Self::User
        }
    }

    fn install_target(self) -> &'static str {
        match self {
            // `default.target` is the user manager's own boot target. `multi-user.target` is the
            // system one; `graphical.target` pulls it in, so this covers a desktop too.
            Self::User => "default.target",
            Self::System => "multi-user.target",
        }
    }
}

/// A value that is about to be written into a unit file, refused if it cannot be written SAFELY.
///
/// Two characters make a path dangerous in a unit, and both fail silently rather than loudly:
///
/// * A NEWLINE ends the current directive and starts a new one. A path containing `\n` would let its
///   own author append arbitrary directives (`ExecStartPost=`, `User=root`) to the unit. This is the
///   injection vector, and it is refused rather than escaped, because a path with a newline in it is
///   pathological in every other way too.
/// * A `%` begins a systemd SPECIFIER (`%h` home, `%i` instance, `%%` a literal percent). Left as-is,
///   `/srv/100%/stack.yml` becomes something else entirely at unit-load time, pointing kern at a path
///   the user never wrote. It is escapable, so it is escaped.
fn unit_safe(role: &'static str, value: &str) -> Result<String, Error> {
    if value.contains('\n') || value.contains('\r') {
        return Err(Error::Compose(format!(
            "{role} contains a newline: it cannot be written into a systemd unit, where a line break \
             starts a new directive. Move the file to a path without one."
        )));
    }
    // Escape LAST, so the check above sees the original text.
    Ok(value.replace('%', "%%"))
}

/// Quote a command-line argument for `ExecStart=`. systemd splits the command on whitespace unless
/// the argument is double-quoted, so a path with a space silently becomes two arguments and kern is
/// handed a compose file that does not exist.
fn exec_arg(value: &str) -> String {
    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/._-:+=@,".contains(&b))
    {
        return value.to_string();
    }
    // systemd's own escaping inside a quoted argument: backslash and double quote.
    let inner = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{inner}\"")
}

/// Everything the unit text needs, resolved and checked by the caller. Borrowed, not owned: the
/// renderer copies each field exactly once, into the string it returns.
pub struct UnitSpec<'a> {
    /// Absolute path of the `kern` binary that will run at boot.
    pub kern_bin: &'a str,
    /// Absolute path of the compose file.
    pub compose_file: &'a str,
    /// Directory the stack's relative binds resolve against (the compose file's own directory).
    pub workdir: &'a str,
    /// Stack name, used for the unit description only. The unit's FILE name is the caller's choice.
    pub project: &'a str,
    pub scope: UnitScope,
}

/// Render the unit text. Pure: no I/O, no environment reads, so it is testable and cannot surprise a
/// caller by touching the machine. Every interpolated value has passed [`unit_safe`].
pub fn render_unit(spec: &UnitSpec<'_>) -> Result<String, Error> {
    let bin = unit_safe("the kern binary path", spec.kern_bin)?;
    let file = unit_safe("the compose file path", spec.compose_file)?;
    let dir = unit_safe("the compose directory", spec.workdir)?;
    let project = unit_safe("the project name", spec.project)?;

    let (bin_q, file_q, dir_q) = (exec_arg(&bin), exec_arg(&file), exec_arg(&dir));

    // `network-online.target` exists in the SYSTEM manager. The user manager has no such unit, and
    // ordering against a unit that does not exist is not an error but is not a guarantee either, so
    // it is emitted only where it means something.
    let network = match spec.scope {
        UnitScope::System => "After=network-online.target\nWants=network-online.target\n",
        UnitScope::User => "",
    };
    let linger = match spec.scope {
        UnitScope::User => {
            "# A user unit runs only while you are logged in, unless lingering is enabled:\n\
             #   loginctl enable-linger $USER\n"
        }
        UnitScope::System => "",
    };

    Ok(format!(
        "# Generated by `kern compose {file} systemd`. Not installed: write it where you want it.\n\
         #\n\
         # This unit brings the stack UP at boot and tears it DOWN at stop. It does NOT supervise.\n\
         # A service with a `restart:` policy is still restarted when it dies: by its own systemd\n\
         # unit for a single-service stack, or by the `kern box` supervisor `up` leaves running for\n\
         # a pod. What is missing is a watcher over the member SET, so nothing re-applies policy\n\
         # once an individual supervisor is gone: a pod member whose supervisor is killed stays\n\
         # down.\n\
         {linger}#\n\
         # Install ({scope_word}):\n\
         #   kern compose {file} systemd > {unit_path}\n\
         #   systemctl {ctl} daemon-reload\n\
         #   systemctl {ctl} enable --now {unit_name}\n\
         \n\
         [Unit]\n\
         Description=kern compose stack {project}\n\
         Documentation=https://getkern.dev\n\
         {network}\
         \n\
         [Service]\n\
         # `up` starts detached boxes and exits, so the unit is `oneshot` + `RemainAfterExit`:\n\
         # with `Type=simple` systemd would read that exit as the stack having died.\n\
         Type=oneshot\n\
         RemainAfterExit=yes\n\
         WorkingDirectory={dir_q}\n\
         ExecStart={bin_q} compose {file_q} up\n\
         ExecStop={bin_q} compose {file_q} down\n\
         # `up` pulls images on first boot, which can outlast the default 90s.\n\
         TimeoutStartSec=600\n\
         \n\
         [Install]\n\
         WantedBy={target}\n",
        file = file,
        linger = linger,
        scope_word = match spec.scope {
            UnitScope::User => "user unit, rootless kern",
            UnitScope::System => "system unit, kern as root",
        },
        unit_path = match spec.scope {
            UnitScope::User => "~/.config/systemd/user/kern-<name>.service",
            UnitScope::System => "/etc/systemd/system/kern-<name>.service",
        },
        ctl = match spec.scope {
            UnitScope::User => "--user",
            UnitScope::System => "",
        },
        unit_name = "kern-<name>.service",
        project = project,
        network = network,
        dir_q = dir_q,
        bin_q = bin_q,
        file_q = file_q,
        target = spec.scope.install_target(),
    ))
}

/// Resolve the machine-dependent inputs and print the unit. The ONLY function here that touches the
/// environment, so [`render_unit`] stays pure and the failure modes are all reported from one place.
pub fn print_unit(file: &str, project: &str) -> Result<(), Error> {
    // systemd requires the first token of `ExecStart=` to be an ABSOLUTE path: it does not search
    // `PATH`. `current_exe` is the binary actually running, which is also the one the user just
    // invoked, so the unit cannot end up pointing at a different kern than the one that wrote it.
    let bin = std::env::current_exe()
        .map_err(|e| Error::Compose(format!("cannot resolve this kern binary's own path: {e}")))?;
    let bin = bin.to_string_lossy().into_owned();

    // A unit starts from PID 1 and inherits no working directory, so a relative compose path would
    // resolve against `/`. Canonicalize rather than join: it also resolves `..` and symlinks, so the
    // unit records the path the file actually has.
    let abs = std::fs::canonicalize(file)
        .map_err(|e| Error::Compose(format!("cannot resolve '{file}' to an absolute path: {e}")))?;
    let dir = abs
        .parent()
        .ok_or_else(|| Error::Compose(format!("'{file}' has no parent directory")))?;

    let unit = render_unit(&UnitSpec {
        kern_bin: &bin,
        compose_file: &abs.to_string_lossy(),
        workdir: &dir.to_string_lossy(),
        project,
        scope: UnitScope::detect(),
    })?;
    print!("{unit}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec<'a>(file: &'a str, scope: UnitScope) -> UnitSpec<'a> {
        UnitSpec {
            kern_bin: "/usr/local/bin/kern",
            compose_file: file,
            workdir: "/srv/app",
            project: "app",
            scope,
        }
    }

    /// A `%` in a path is a systemd SPECIFIER, not a character: unescaped, `/srv/100%/x.yml` loads as
    /// a different path than the one the user wrote, and kern is pointed somewhere else entirely.
    #[test]
    fn a_percent_is_escaped_everywhere_it_appears() {
        let u = render_unit(&spec("/srv/100%/stack.yml", UnitScope::User)).expect("renders");
        assert!(u.contains("/srv/100%%/stack.yml"), "{u}");
        // And nowhere is a lone `%` left: every one must be doubled.
        for (i, w) in u.as_bytes().windows(2).enumerate() {
            if w[0] == b'%' && w[1] != b'%' {
                // A doubled `%%` consumes both bytes, so a survivor here is a real single `%`.
                let prev = u.as_bytes().get(i.wrapping_sub(1)).copied().unwrap_or(0);
                assert_eq!(prev, b'%', "unescaped specifier at byte {i} in:\n{u}");
            }
        }
    }

    /// A newline would end the directive and let the path's own author append arbitrary ones. This is
    /// the injection vector, and it is refused rather than escaped.
    #[test]
    fn a_newline_in_any_field_is_refused() {
        assert!(render_unit(&spec("/srv/a\nExecStartPost=/bin/id", UnitScope::User)).is_err());
        assert!(render_unit(&spec("/srv/a\rb.yml", UnitScope::User)).is_err());

        let mut s = spec("/srv/ok.yml", UnitScope::User);
        s.kern_bin = "/bin/kern\nUser=root";
        assert!(
            render_unit(&s).is_err(),
            "a binary path must be checked too"
        );
        s.kern_bin = "/usr/local/bin/kern";
        s.project = "app\n[Service]";
        assert!(
            render_unit(&s).is_err(),
            "the description must be checked too"
        );
    }

    /// systemd splits `ExecStart=` on whitespace: an unquoted path with a space becomes two arguments
    /// and kern is handed a file that does not exist.
    #[test]
    fn a_path_with_spaces_is_quoted_for_execstart() {
        let u = render_unit(&spec("/srv/my app/stack.yml", UnitScope::User)).expect("renders");
        assert!(u.contains("compose \"/srv/my app/stack.yml\" up"), "{u}");
        // A plain path is NOT quoted: quoting everything would be correct but unreadable.
        let plain = render_unit(&spec("/srv/app/stack.yml", UnitScope::User)).expect("renders");
        assert!(plain.contains("compose /srv/app/stack.yml up"), "{plain}");
    }

    /// The two scopes differ in three places, and getting any of them wrong produces a unit that
    /// loads but never runs at boot.
    #[test]
    fn user_and_system_units_differ_where_they_must() {
        let user = render_unit(&spec("/srv/app/stack.yml", UnitScope::User)).expect("renders");
        assert!(user.contains("WantedBy=default.target"));
        assert!(
            !user.contains("network-online.target"),
            "the user manager has none"
        );
        assert!(
            user.contains("enable-linger"),
            "the logout caveat must be stated"
        );

        let sys = render_unit(&spec("/srv/app/stack.yml", UnitScope::System)).expect("renders");
        assert!(sys.contains("WantedBy=multi-user.target"));
        assert!(sys.contains("Wants=network-online.target"));
        assert!(
            !sys.contains("enable-linger"),
            "lingering is a user-unit concern"
        );
    }

    /// `up` exits once the boxes are detached. With `Type=simple` systemd reads that as the stack
    /// having died and marks the unit failed; the pair below is what makes the state truthful.
    #[test]
    fn the_unit_models_a_command_that_exits() {
        let u = render_unit(&spec("/srv/app/stack.yml", UnitScope::User)).expect("renders");
        assert!(u.contains("Type=oneshot"));
        assert!(u.contains("RemainAfterExit=yes"));
        assert!(u.contains("ExecStop=") && u.contains("down"));
        // The unit claims no supervision of its own...
        assert!(
            u.contains("does NOT supervise"),
            "the limit must be stated in the unit"
        );
        // ...and says whose job it is instead, so the reader does not infer that a `restart:`
        // service is unsupervised too: it has a supervisor, and only the stack-wide watcher is
        // missing. Both mechanisms are named, because there are two and an earlier version of this
        // text named only the pod one: a single-service stack is supervised by systemd, a pod member
        // by a `kern box` process. Measured, not read off the code.
        assert!(
            u.contains("still restarted when it dies"),
            "the limit must be stated at its real width, not wider"
        );
        // Asserted on fragments that do not cross the unit's own line wrapping. The first attempt
        // used "its own systemd unit", which the renderer breaks after "systemd", and the test went
        // red against text that said exactly the right thing. A line break switching off an
        // assertion is the same defect the documentation gates hit this week.
        for mechanism in ["its own systemd", "supervisor `up` leaves running"] {
            assert!(
                u.contains(mechanism),
                "the unit names only one of the two supervisors, missing {mechanism:?}"
            );
        }
    }
}
