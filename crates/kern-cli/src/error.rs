//! Error type for the CLI.
//!
//! A hand-rolled enum keeps the binary dependency-free. The roadmap target is a
//! `thiserror`-derived enum per crate (see ARCHITECTURE.md); the *shape* — a typed error with
//! an optional actionable hint, mapped to an exit code in one place — is already here.

#[derive(Debug)]
pub enum Error {
    UnknownCommand(String),
    NotYetImplemented(&'static str),
    /// A box name failed validation (path separator / traversal / empty).
    InvalidBox(&'static str),
}

impl Error {
    /// An optional one-line, actionable hint shown under the error.
    pub fn hint(&self) -> Option<String> {
        match self {
            Error::UnknownCommand(_) => Some("run `kern --help` for the list of commands".into()),
            Error::NotYetImplemented(_) => {
                Some("this lands in a later 0.x release — see the roadmap in README.md".into())
            }
            Error::InvalidBox(_) => Some(
                "box names: letters/digits/_/./- only, no leading '-' or '.', max 64 chars".into(),
            ),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownCommand(c) => write!(f, "unknown command '{c}'"),
            Error::NotYetImplemented(c) => write!(f, "'{c}' is not implemented yet"),
            Error::InvalidBox(why) => write!(f, "invalid box name: {why}"),
        }
    }
}

impl std::error::Error for Error {}
