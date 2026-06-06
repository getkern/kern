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
    /// The sandbox could not be set up or run (namespaces, mounts, exec).
    Sandbox(String),
    /// A named box isn't running (or has no logs) — a lookup miss, not a setup failure.
    NotRunning(String),
    /// An OCI image pull/extract failed.
    Oci(String),
    /// A compose file could not be parsed or brought up.
    Compose(String),
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
            Error::Sandbox(_) => {
                Some("needs unprivileged user namespaces and a valid --rootfs directory".into())
            }
            Error::NotRunning(_) => Some("run `kern ps` to see running boxes".into()),
            Error::Oci(_) => {
                Some("needs `curl` and GNU `tar`; check the image name and network".into())
            }
            Error::Compose(_) => {
                Some("compose: `[box.NAME]` tables with image/rootfs, command, depends_on".into())
            }
            Error::Usage(_) => Some("run `kern --help` for full usage".into()),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownCommand(c) => write!(f, "unknown command '{c}'"),
            Error::InvalidBox(why) => write!(f, "invalid box name: {why}"),
            Error::Sandbox(why) => write!(f, "sandbox: {why}"),
            Error::NotRunning(why) => write!(f, "{why}"),
            Error::Oci(why) => write!(f, "pull: {why}"),
            Error::Compose(why) => write!(f, "compose: {why}"),
            Error::Usage(u) => write!(f, "usage: kern {u}"),
        }
    }
}

impl std::error::Error for Error {}
