//! `kern unshare [--] [CMD...]`: run a command with the ids a box's files carry on disk.
//!
//! A box maps its root to the caller and its other users to the caller's subordinate range
//! (`/etc/subuid`), so a bind-mounted directory a box's postgres wrote is owned on the host by
//! something like uid 100999, which the caller cannot `chown`, `chmod` or remove. Inside the user
//! namespace kern builds for its own cleanups (`gc`, `rmi`, `volume rm`, builds), those files belong
//! to box uid 999 again and uid 0 there may change them. This verb runs any command there, as
//! `podman unshare` does for podman: `kern unshare -- rm -rf ./old-rootfs`,
//! `kern unshare -- chown -R 0:0 ./data`, `kern unshare -- ls -ln ./data`.
//!
//! WITHOUT A RANGE (no `newuidmap`/`newgidmap`, or no `/etc/subuid` line) the namespace maps only the
//! caller's own id: the command still runs as uid 0, but a box's other users are not in the map and
//! their files stay out of reach. That is said before the command starts, not left to show up as
//! `Operation not permitted` from inside it.

use crate::error::Error;

/// The command to run: `cmd`, or the caller's shell (`$SHELL`, else `/bin/sh`) when none is given.
fn argv_of(cmd: &[String]) -> Result<Vec<std::ffi::CString>, Error> {
    let words: Vec<String> = if cmd.is_empty() {
        let shell = crate::global_env("SHELL")
            .and_then(|s| s.into_string().ok())
            .filter(|s| s.starts_with('/'))
            .unwrap_or_else(|| "/bin/sh".to_string());
        vec![shell]
    } else {
        cmd.to_vec()
    };
    words
        .into_iter()
        .map(|w| {
            std::ffi::CString::new(w)
                .map_err(|_| Error::Usage("unshare [--] [CMD...]: an argument holds a NUL byte"))
        })
        .collect()
}

/// Run it and exit with its status.
pub(crate) fn run(cmd: &[String]) -> Result<(), Error> {
    let argv = argv_of(cmd)?;
    let outcome = kern_isolation::exec_in_id_mapped_userns(&argv, |ranged| {
        if !ranged {
            eprintln!(
                "kern: unshare: no subordinate id range here (newuidmap/newgidmap and an /etc/subuid \
                 line for this user), so only your own files are uid 0 inside: the files of a box's \
                 other users stay out of reach"
            );
        }
    })
    .map_err(|e| Error::Sandbox(format!("unshare: {e}")))?;
    std::process::exit(outcome.code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_is_taken_as_given_and_a_nul_is_refused() {
        let a = argv_of(&["rm".into(), "-rf".into(), "./x".into()]).unwrap_or_default();
        assert_eq!(
            a.iter()
                .map(|c| c.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            ["rm", "-rf", "./x"]
        );
        assert!(argv_of(&["a\0b".into()]).is_err());
    }
}
