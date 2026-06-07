//! `--secret` — deliver a secret into the box as `/run/secrets/<name>` (mode 0400) without ever
//! writing it to the box's image or leaving it in the workload's environment.
//!
//! Three source forms (Docker-ish), disambiguated host-side:
//! * `NAME=value` — an inline literal (handy, but visible in the host's `ps`; prefer a file/stdin for
//!   real secrets);
//! * `NAME=-` — read the value from kern's **stdin** (never hits `argv` or the process table);
//! * `SRC[:NAME]` — read a host **file** (`NAME` defaults to the file's basename). A world-writable
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
pub fn parse_secrets(specs: &[String]) -> Result<Vec<(String, Vec<u8>)>, Error> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::with_capacity(specs.len());
    let mut stdin_used = false;
    for spec in specs {
        // A `NAME=…` form (inline or stdin) takes precedence over the file form, so a value that
        // happens to contain `:` is not misread as a filename. A leading `/` is always a file.
        let (name, bytes) = if let Some((k, v)) =
            spec.split_once('=').filter(|_| !spec.starts_with('/'))
        {
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
                std::io::stdin()
                    .read_to_end(&mut buf)
                    .map_err(|e| Error::Sandbox(format!("--secret {k}=-: reading stdin: {e}")))?;
                (k.to_string(), buf)
            } else {
                // Inline value: convenient, but it sits in THIS process's argv, so it is visible
                // in `ps` / `/proc/<pid>/cmdline` — and a detached box's supervisor keeps it there
                // for the box's whole lifetime. Warn and steer to the forms that never hit argv.
                eprintln!(
                        "kern: warning: --secret {k}=<value> is visible in `ps` for the box's lifetime; \
                         prefer '{k}=-' (read from stdin) or a file ('SRC:{k}')"
                    );
                (k.to_string(), v.as_bytes().to_vec())
            }
        } else {
            // File form `SRC[:NAME]`. `NAME` (if given) is the last `:`-segment; the rest is the path
            // (so an absolute path keeps working — only a trailing `:name` is peeled off).
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
        if out.iter().any(|(n, _)| n == &name) {
            return Err(Error::Sandbox(format!("--secret: duplicate name '{name}'")));
        }
        out.push((name, bytes));
    }
    Ok(out)
}

/// Read a secret file, refusing a world-writable one (tamperable by any local user) and warning on a
/// group/world-readable one (a secret should be `chmod 600`).
fn read_secret_file(path: &str) -> Result<Vec<u8>, Error> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| Error::Sandbox(format!("--secret source '{path}': {e}")))?;
    if !meta.is_file() {
        return Err(Error::Sandbox(format!(
            "--secret source '{path}' is not a regular file"
        )));
    }
    let mode = meta.permissions().mode();
    if mode & 0o002 != 0 {
        return Err(Error::Sandbox(format!(
            "--secret source '{path}' is world-writable (mode {:04o}) — refusing",
            mode & 0o7777
        )));
    }
    if mode & 0o044 != 0 {
        eprintln!(
            "kern: warning: secret '{path}' is group/world-readable (mode {:04o}) — consider chmod 600",
            mode & 0o7777
        );
    }
    std::fs::read(path).map_err(|e| Error::Sandbox(format!("--secret source '{path}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_and_named_forms() {
        let s = parse_secrets(&["TOKEN=abc".into()]).unwrap();
        assert_eq!(s, vec![("TOKEN".to_string(), b"abc".to_vec())]);
        // A value containing '=' and ':' survives (split_once on the first '=', not a file).
        let s = parse_secrets(&["URL=a=b:c".into()]).unwrap();
        assert_eq!(s, vec![("URL".to_string(), b"a=b:c".to_vec())]);
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
        let s = parse_secrets(&[f.to_string_lossy().into_owned()]).unwrap();
        assert_eq!(s, vec![("api.key".to_string(), b"XYZ".to_vec())]);
        // explicit :NAME
        let spec = format!("{}:tok", f.to_string_lossy());
        let s = parse_secrets(&[spec]).unwrap();
        assert_eq!(s, vec![("tok".to_string(), b"XYZ".to_vec())]);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rejects_bad_name_world_writable_and_dupes() {
        assert!(parse_secrets(&["../evil=x".into()]).is_err());
        assert!(parse_secrets(&["a/b=x".into()]).is_err());
        assert!(parse_secrets(&["A=1".into(), "A=2".into()]).is_err());

        let tmp = std::env::temp_dir().join(format!("kern-sec2-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let f = tmp.join("ww");
        std::fs::write(&f, b"x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(parse_secrets(&[format!("{}:k", f.to_string_lossy())]).is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
