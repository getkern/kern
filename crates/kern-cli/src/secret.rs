//! `--secret` - deliver a secret into the box as `/run/secrets/<name>` (mode 0400) without ever
//! writing it to the box's image or leaving it in the workload's environment.
//!
//! Three source forms (Docker-ish), disambiguated host-side:
//! * `NAME=value` - an inline literal (handy, but visible in the host's `ps` AND recorded in the
//!   systemd journal on the cgroup-scope re-exec, so it outlives the box; prefer a file/stdin for
//!   real secrets);
//! * `NAME=-` - read the value from kern's **stdin** (never hits `argv` or the process table);
//! * `SRC[:NAME]` - read a host **file** (`NAME` defaults to the file's basename). A world-writable
//!   secret file is rejected (anyone could have tampered with it) and a group/world-readable one is
//!   warned about.
//!
//! The bytes are read **on the host, before** the box's namespaces/pivot, then written into a
//! RAM-backed `tmpfs` at `/run/secrets` inside the box (see `kern-isolation`) so they never touch
//! the persisted overlay upper. This module is the host half: parse + validate + read.

use crate::error::Error;
use std::io::Read;

/// A secret's in-box file name: a single path component, so it can't escape `/run/secrets`. The
/// shared [`kern_common::valid_resource_name`] rule (one definition for volumes, secrets, pods, profiles).
fn valid_name(name: &str) -> bool {
    kern_common::valid_resource_name(name)
}

fn name_err(name: &str) -> Error {
    Error::Sandbox(format!(
        "--secret name '{name}' is invalid (letters/digits/_/./- only, no '/'/'..', ≤64)"
    ))
}

/// Parse `--secret` specs into `(name, bytes)` pairs to hand to the sandbox. Reads files/stdin here
/// (on the host, pre-fork) so the box side only writes already-materialised bytes.
/// The mode a secret gets when the caller names none: read-only to the OWNER, which is kern's own
/// default and predates any compose consideration. `kern compose` passes the Compose Specification's
/// default (`0444`, world-readable) explicitly, so the wider mode is visible at the call site that
/// owes it rather than applied to every box on the machine.
pub const DEFAULT_SECRET_MODE: libc::mode_t = 0o400;

/// `mode` is the file mode each secret is created with inside the box; see
/// [`kern_isolation::Secret`] for why it is a parameter and not a constant.
/// The environment variable a `--secret-env <name>` reads its content from.
///
/// PREFIXED AND DERIVED, so the box and the driver cannot disagree about where to look, and so a
/// variable the workload happens to have cannot be mistaken for a secret's content.
#[must_use]
pub(crate) fn secret_env_var(name: &str) -> String {
    format!("{ENV_PREFIX}{name}")
}

/// The prefix every secret-content variable carries, as a constant rather than a literal repeated
/// where it is needed: the pod holder scrubs by this prefix before forking, and a holder that
/// scrubbed a DIFFERENT string than the one secrets are named with would be worse than one that
/// scrubbed nothing, because it would look done.
pub(crate) const ENV_PREFIX: &str = "KERN_SECRET_";

/// `--secret-env <name>`: a secret whose CONTENT comes from this process's environment.
///
/// THE ARGV-FREE FORM THE `--secret NAME=value` WARNING STEERS TO. `/proc/<pid>/cmdline` is
/// world-readable on Linux and, when kern re-execs under a systemd scope, the argv is recorded in
/// the journal where it outlives the box. A value in the environment is readable only by the same
/// user, and never persists.
///
/// EXISTS FOR THE SPECIFICATION'S `secrets: {x: {environment: VAR}}`, which `kern compose` forwards
/// by putting the value in the child's environment and the NAME on the command line.
///
/// A MISSING VARIABLE IS AN ERROR AND NOT AN EMPTY SECRET. A service that reads a password file
/// would take the empty string as the password, which fails somewhere else entirely; refusing here
/// names the variable the caller has to set.
pub(crate) fn parse_secret_envs(
    names: &[String],
    mode: libc::mode_t,
) -> Result<Vec<kern_isolation::Secret>, Error> {
    let mut out: Vec<kern_isolation::Secret> = Vec::with_capacity(names.len());
    for name in names {
        if !valid_name(name) {
            return Err(name_err(name));
        }
        let var = secret_env_var(name);
        let Ok(value) = std::env::var(&var) else {
            return Err(Error::Sandbox(format!(
                "--secret-env {name}: {var} is not set in this process's environment, so there is \
                 no content to deliver at /run/secrets/{name}"
            )));
        };
        if out.iter().any(|s| s.name == *name) {
            return Err(Error::Sandbox(format!(
                "--secret-env: duplicate name '{name}'"
            )));
        }
        out.push(kern_isolation::Secret {
            name: name.clone(),
            bytes: value.into_bytes(),
            mode,
        });
    }
    Ok(out)
}

pub fn parse_secrets(
    specs: &[String],
    mode: libc::mode_t,
) -> Result<Vec<kern_isolation::Secret>, Error> {
    let mut out: Vec<kern_isolation::Secret> = Vec::with_capacity(specs.len());
    let mut stdin_used = false;
    for spec in specs {
        // A `NAME=…` form (inline or stdin) takes precedence over the file form, so a value that
        // happens to contain `:` is not misread as a filename. A leading `/` is always a file.
        let (name, bytes) =
            if let Some((k, v)) = spec.split_once('=').filter(|_| !spec.starts_with('/')) {
                if !valid_name(k) {
                    return Err(name_err(k));
                }
                if v == "-" {
                    if stdin_used {
                        return Err(Error::Sandbox(
                            "--secret: only one value can be read from stdin ('-')".into(),
                        ));
                    }
                    stdin_used = true;
                    let mut buf = Vec::new();
                    std::io::stdin().read_to_end(&mut buf).map_err(|e| {
                        Error::Sandbox(format!("--secret {k}=-: reading stdin: {e}"))
                    })?;
                    (k.to_string(), buf)
                } else {
                    // Inline value: convenient, but it sits in THIS process's argv, so it is visible in
                    // `ps` / `/proc/<pid>/cmdline` for the box's lifetime - AND, when kern re-execs under a
                    // systemd `--user` scope for cgroup caps, the argv is recorded in the systemd unit /
                    // journal, where it PERSISTS after the box exits (a hacker-mode audit surfaced this
                    // beyond the ephemeral `ps` exposure). Warn honestly and steer to the argv-free forms.
                    eprintln!(
                    "kern: warning: --secret {k}=<value> is visible in `ps` and recorded in the \
                         systemd journal (persists after the box exits); \
                         prefer '{k}=-' (read from stdin) or a file ('SRC:{k}')"
                );
                    (k.to_string(), v.as_bytes().to_vec())
                }
            } else {
                // File form `SRC[:NAME]`. `NAME` (if given) is the last `:`-segment; the rest is the path
                // (so an absolute path keeps working - only a trailing `:name` is peeled off).
                let (src, name) = match spec.rsplit_once(':') {
                    Some((s, n)) if valid_name(n) && !s.is_empty() => (s, n.to_string()),
                    _ => {
                        let base = spec
                            .rsplit('/')
                            .next()
                            .filter(|b| !b.is_empty())
                            .unwrap_or("secret");
                        (spec.as_str(), base.to_string())
                    }
                };
                if !valid_name(&name) {
                    return Err(name_err(&name));
                }
                let bytes = read_secret_file(src)?;
                (name, bytes)
            };
        if out.iter().any(|s| s.name == name) {
            return Err(Error::Sandbox(format!("--secret: duplicate name '{name}'")));
        }
        out.push(kern_isolation::Secret { name, bytes, mode });
    }
    Ok(out)
}

/// The class-closing CHECK every host-path-whose-content-reaches-a-box shares: canonicalize
/// symlink-free and refuse anything under `<runtime>/kern` (a peer's `ssh/` key, `secret`s,
/// `instances/` posture records - exactly the theft the `-v` guard stops), returning the CANONICAL
/// path so a symlink can't redirect the read AFTER the check. `what` names the flag for the message.
/// The one security primitive is the predicate [`crate::registry::path_overlaps_trusted_state`], shared
/// by EVERY host-path entry point; this function is the SANDBOX-domain READ wrapper of it, used by
/// `--env-file`, `--secret`, `--rootfs`, and `kern cp`'s host SOURCE (`boxcp::copy_in`). The WRITE side -
/// `kern cp`'s host DESTINATION and `kern save -o` - uses the sibling [`guard_host_write_path`] (it
/// checks where the write LANDS, since the target may not exist yet). The build-domain sites (the `kern
/// build` CONTEXT and `-f` Dockerfile) call the predicate directly, raising `Error::Build`. ANY new path
/// whose bytes cross the host/box boundary MUST run the predicate, so the class stays closed by OMISSION -
/// `kern cp` was the one that slipped, copying a peer's `ssh/` key or posture record straight through.
pub(crate) fn guard_host_path(path: &str, what: &str) -> Result<std::path::PathBuf, Error> {
    let canon = std::fs::canonicalize(path)
        .map_err(|e| Error::Sandbox(format!("{what} source '{path}': {e}")))?;
    refuse_if_registry(&canon, path, what)?;
    Ok(canon)
}

/// The WRITE-side sibling of [`guard_host_path`]: refuse a host destination that lands on the registry.
/// The target may not exist yet (a to-be-created file), so the check is on the PARENT dir the write lands
/// in - if that resolves onto a trust-bearing registry dir, the write would forge or clobber a peer's
/// state / posture record (the danger the `-v` guard names). A `BOX_DATA` dir (`logs/`/`scratch/`) stays
/// writable, via the same [`crate::registry::path_overlaps_trusted_state`] allowlist. Used by `kern cp`
/// (box→host) and `kern save -o`; `what` names the flag for the message.
///
/// CRUCIAL: `File::create`/`open(O_CREAT)` FOLLOWS a symlink at `dst`, so a symlink FINAL component -
/// which anyone who can write `dst`'s directory could plant pointing at `<runtime>/kern` - would redirect
/// the write into the registry past a parent-only check. So resolve where the write ACTUALLY lands by
/// following a symlink chain at `dst` (bounded, ELOOP-style) to the final target, THEN canonicalize that
/// target's parent (which also resolves a symlinked parent dir). Checking only `dst`'s literal parent was
/// a real bypass.
pub(crate) fn guard_host_write_path(dst: &str, what: &str) -> Result<(), Error> {
    let mut landing = std::path::PathBuf::from(dst);
    for _ in 0..40 {
        match std::fs::read_link(&landing) {
            Ok(t) if t.is_absolute() => landing = t,
            Ok(t) => landing = landing.parent().map(|p| p.join(&t)).unwrap_or(t),
            Err(_) => break, // not a symlink (or unreadable) - this is where the write lands
        }
    }
    let parent = landing
        .parent()
        .filter(|s| !s.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    if let Ok(cparent) = std::fs::canonicalize(parent) {
        if crate::registry::path_overlaps_trusted_state(&cparent) {
            return Err(Error::Sandbox(format!(
                "{what} '{dst}': refusing to write into the kern registry - it would forge or clobber \
                 another box's state or posture records"
            )));
        }
    }
    Ok(())
}

/// The single registry refusal shared by [`guard_host_path`] and [`read_host_file_for_box`]: `Err` if the
/// already-canonicalized `canon` resolves onto `<runtime>/kern`, `Ok(())` if clear. One message in one
/// place, so the two entry points cannot drift on the wording of the check that closes the theft class.
fn refuse_if_registry(canon: &std::path::Path, path: &str, what: &str) -> Result<(), Error> {
    if crate::registry::path_overlaps_trusted_state(canon) {
        return Err(Error::Sandbox(format!(
            "{what} source '{path}': refusing to expose the kern registry to a box - it holds another \
             box's secrets (ssh host keys), state and posture records"
        )));
    }
    Ok(())
}

/// Read a host file whose CONTENT is delivered into a box AS A VALUE, guarded against the registry.
/// `--env-file` uses this. It does NOT apply secret hygiene (an env file is commonly 0644), and it
/// tolerates a non-canonicalizable source - a FIFO, `/dev/fd/N` from process substitution
/// (`--env-file <(...)`), `/dev/stdin` - which the old `read_to_string` accepted. Such a source is not
/// a registry FILE (those are real paths that always `canonicalize`), so the registry guard - whose
/// threat is a compose/operator PATH pointing at `<runtime>/kern`, and a path always canonicalizes -
/// still holds: a canonicalizable source is checked, a non-canonicalizable one cannot be the record it
/// protects.
pub(crate) fn read_host_file_for_box(path: &str, what: &str) -> Result<Vec<u8>, Error> {
    match std::fs::canonicalize(path) {
        Ok(canon) => {
            refuse_if_registry(&canon, path, what)?;
            std::fs::read(&canon)
        }
        Err(_) => std::fs::read(path), // FIFO / /dev/fd / /dev/stdin: not a registry record, read as-is
    }
    .map_err(|e| Error::Sandbox(format!("{what} source '{path}': {e}")))
}

/// A `--secret` FILE: the guarded read PLUS secret hygiene - a regular file, refuse a world-writable
/// source (anyone could swap the value), warn on a group/world-readable one. A secret earns the checks
/// an env file does not.
fn read_secret_file(path: &str) -> Result<Vec<u8>, Error> {
    use std::os::unix::fs::PermissionsExt;
    let canon = guard_host_path(path, "--secret")?;
    let meta = std::fs::metadata(&canon)
        .map_err(|e| Error::Sandbox(format!("--secret source '{path}': {e}")))?;
    if !meta.is_file() {
        return Err(Error::Sandbox(format!(
            "--secret source '{path}' is not a regular file"
        )));
    }
    let mode = meta.permissions().mode();
    if mode & 0o002 != 0 {
        return Err(Error::Sandbox(format!(
            "--secret source '{path}' is world-writable (mode {:04o}) - refusing",
            mode & 0o7777
        )));
    }
    if mode & 0o044 != 0 {
        eprintln!(
            "kern: warning: --secret source '{path}' is group/world-readable (mode {:04o}) - consider chmod 600",
            mode & 0o7777
        );
    }
    std::fs::read(&canon).map_err(|e| Error::Sandbox(format!("--secret source '{path}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pairs a parse produced, as `(name, bytes)`, so an assertion reads the same as it did
    /// before the mode joined the struct: the tests here are about NAMES and BYTES, and spelling the
    /// third field into every one of them would be noise around the thing they check.
    fn pairs(s: &[kern_isolation::Secret]) -> Vec<(String, Vec<u8>)> {
        s.iter()
            .map(|x| (x.name.clone(), x.bytes.clone()))
            .collect()
    }

    /// THE MODE TRAVELS WITH EVERY SECRET, and the two defaults are different on purpose.
    ///
    /// `kern box --secret` keeps owner-only `0400`: that surface is kern's own and nobody asked to
    /// widen it. `kern compose` passes the Compose Specification's `0444` explicitly, because a
    /// secret only the owner can read is unreadable to every image that drops to a non-root user.
    /// MEASURED on a box whose image declares `USER appuser` (uid 1500): with `--secret-mode 444`
    /// the workload reads the secret, with the `0400` default it gets `Permission denied`.
    #[test]
    fn every_secret_carries_the_mode_it_was_parsed_with() {
        let s = parse_secrets(&["TOKEN=abc".into()], DEFAULT_SECRET_MODE).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].mode, 0o400, "kern's own default is owner-only");

        let s = parse_secrets(&["A=1".into(), "B=2".into()], 0o444).unwrap();
        assert_eq!(s.len(), 2);
        assert!(
            s.iter().all(|x| x.mode == 0o444),
            "the mode applies to EVERY secret of the box, not just the first"
        );
    }

    #[test]
    fn inline_and_named_forms() {
        let s = parse_secrets(&["TOKEN=abc".into()], DEFAULT_SECRET_MODE).unwrap();
        assert_eq!(pairs(&s), vec![("TOKEN".to_string(), b"abc".to_vec())]);
        // A value containing '=' and ':' survives (split_once on the first '=', not a file).
        let s = parse_secrets(&["URL=a=b:c".into()], DEFAULT_SECRET_MODE).unwrap();
        assert_eq!(pairs(&s), vec![("URL".to_string(), b"a=b:c".to_vec())]);
    }

    #[test]
    fn file_form_auto_and_explicit_name() {
        let tmp = std::env::temp_dir().join(format!("kern-sec-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let f = tmp.join("api.key");
        std::fs::write(&f, b"XYZ").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        // auto-name = basename
        let s = parse_secrets(&[f.to_string_lossy().into_owned()], DEFAULT_SECRET_MODE).unwrap();
        assert_eq!(pairs(&s), vec![("api.key".to_string(), b"XYZ".to_vec())]);
        // explicit :NAME
        let spec = format!("{}:tok", f.to_string_lossy());
        let s = parse_secrets(&[spec], DEFAULT_SECRET_MODE).unwrap();
        assert_eq!(pairs(&s), vec![("tok".to_string(), b"XYZ".to_vec())]);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rejects_bad_name_world_writable_and_dupes() {
        assert!(parse_secrets(&["../evil=x".into()], DEFAULT_SECRET_MODE).is_err());
        assert!(parse_secrets(&["a/b=x".into()], DEFAULT_SECRET_MODE).is_err());
        assert!(parse_secrets(&["A=1".into(), "A=2".into()], DEFAULT_SECRET_MODE).is_err());

        let tmp = std::env::temp_dir().join(format!("kern-sec2-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let f = tmp.join("ww");
        std::fs::write(&f, b"x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            parse_secrets(&[format!("{}:k", f.to_string_lossy())], DEFAULT_SECRET_MODE).is_err()
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
