//! Error type for the CLI.
//!
//! 0.1 scaffold uses a hand-rolled enum to stay dependency-free. The roadmap target is a
//! `thiserror`-derived enum per crate (see ARCHITECTURE.md); the *shape* — a typed error with
//! an optional actionable hint, mapped to an exit code in one place — is already here.

#[derive(Debug)]
pub enum Error {
    UnknownCommand(String),
    NotYetImplemented(&'static str),
}

impl Error {
    /// An optional one-line, actionable hint shown under the error.
    pub fn hint(&self) -> Option<String> {
        match self {
            Error::UnknownCommand(_) => Some("run `kern --help` for the list of commands".into()),
            Error::NotYetImplemented(_) => {
                Some("this lands in a later 0.x release — see the roadmap in README.md".into())
            }
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownCommand(c) => write!(f, "unknown command '{c}'"),
            Error::NotYetImplemented(c) => write!(f, "'{c}' is not implemented yet (0.1 scaffold)"),
        }
    }
}

impl std::error::Error for Error {}
