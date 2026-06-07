//! Error type for the CLI.
//!
//! A hand-rolled enum keeps the binary dependency-free. The roadmap target is a
//! `thiserror`-derived enum per crate (see ARCHITECTURE.md); the *shape* — a typed error with
//! an optional actionable hint, mapped to an exit code in one place — is already here.

#[derive(Debug)]
pub enum Error {
    UnknownCommand(String),
    /// A box name failed validation (path separator / traversal / empty).
    InvalidBox(&'static str),
    /// An operational/validation failure inside a box command (a bad `-v` spec, a secret, a `box cp`,
    /// a pod op…). The message is self-explanatory, so it carries no generic hint — unlike [`Setup`],
    /// which is the genuine "the sandbox couldn't start here" failure. ([`Setup`]: Error::Setup)
    Sandbox(String),
    /// The sandbox itself could not be created/run (namespaces, mounts, exec) — an environment
    /// problem, not bad input. Carries the "needs unprivileged user namespaces" hint.
    Setup(String),
    /// A named box isn't running (or has no logs) — a lookup miss, not a setup failure.
    NotRunning(String),
    /// A box name is already held by a live box — a naming conflict, not a setup failure.
    AlreadyRunning(String),
    /// A `kern volume` operation failed for a non-in-use reason (unknown name, bad name, I/O). The
    /// hint points at `kern volume ls` — NOT at boxes (that's [`AlreadyRunning`], used when a volume
    /// is in use). ([`AlreadyRunning`]: Error::AlreadyRunning)
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
    Usage(&'static str),
}

impl Error {
    /// An optional one-line, actionable hint shown under the error.
    pub fn hint(&self) -> Option<String> {
        match self {
            Error::UnknownCommand(_) => Some("run `kern --help` for the list of commands".into()),
            Error::InvalidBox(_) => Some(
                "box names: letters/digits/_/./- only, no leading '-' or '.', max 64 chars".into(),
            ),
            // Operational/validation errors are self-explanatory — no generic hint (it used to
            // wrongly show the userns/rootfs hint on `-v`/secret/port errors).
            Error::Sandbox(_) => None,
            Error::Setup(_) => {
                Some("needs unprivileged user namespaces and a valid --rootfs directory".into())
            }
            Error::NotRunning(_) => Some("run `kern ps` to see running boxes".into()),
            Error::AlreadyRunning(_) => {
                Some("run `kern ps` to see running boxes; `kern stop <name>` frees the name".into())
            }
            Error::Volume(_) => Some("run `kern volume ls` to see existing volumes".into()),
            // The right hint depends on *why* the pull failed — telling someone whose image name is
            // wrong to "install curl and tar" sends them down the wrong path. Branch on the message.
            Error::Oci(msg) => Some(oci_hint(msg)),
            Error::Compose(_) => {
                Some("compose: `[box.NAME]` tables with image/rootfs, command, depends_on".into())
            }
            Error::Build(_) => Some(
                "build: the Dockerfile must start with FROM (ARG may precede it); COPY/ADD paths \
                 stay inside the image"
                    .into(),
            ),
            Error::Config(_) => {
                Some("profiles live in ~/.config/kern/kern.toml — see docs/CONFIG.md".into())
            }
            Error::Usage(_) => Some("run `kern --help` for full usage".into()),
        }
    }
}

/// Pick the hint for a pull failure from the shape of its message. `curl`/`tar` missing is a real but
/// *rare* cause; a mistyped name or a private repo is the common one, so only surface the tooling hint
/// when a tool actually failed. The message is the `OciError` Display (or a local cache error).
fn oci_hint(msg: &str) -> String {
    if msg.starts_with("bad image reference") {
        "image refs look like `alpine`, `alpine:3.19`, or `ghcr.io/user/app:tag`".into()
    } else if msg.contains("curl failed") || msg.contains("tar failed") || msg.contains("sha256sum")
    {
        "pull/push need `curl`, GNU `tar`, `gzip` and `sha256sum` on PATH, plus a working network"
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
            // `OciError`'s Display), so we don't add another — a doubled "registry: registry:" was the
            // symptom. A local cache error (no OCI prefix) still reads fine on its own.
            Error::Oci(why) => write!(f, "{why}"),
            Error::Compose(why) => write!(f, "compose: {why}"),
            Error::Build(why) => write!(f, "build: {why}"),
            Error::Config(why) => write!(f, "config: {why}"),
            Error::Usage(u) => write!(f, "usage: kern {u}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oci_hint_points_at_the_actual_cause() {
        // A tool failure → the tooling hint.
        assert!(oci_hint("curl failed: exit 6").contains("curl"));
        assert!(oci_hint("tar failed: bad header").contains("tar"));
        // A bad reference → the ref-format hint, not tooling.
        let r = oci_hint("bad image reference: alpine::");
        assert!(r.contains("image refs"));
        assert!(!r.contains("curl"));
        // A missing/private image → name/tag/login, not tooling.
        let reg = oci_hint("registry: cannot access 'me/app' — it may be private");
        assert!(reg.contains("kern login"));
        assert!(!reg.contains("curl"));
        // "no manifest for <arch>" and local cache errors fall through to the same safe hint.
        assert!(oci_hint("registry: no manifest for aarch64").contains("image name"));
    }
}
