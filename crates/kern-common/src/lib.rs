//! Shared types and utilities for kern.
//!
//! Newtypes live here so units (bytes vs MiB, names vs paths) can't be mixed up by accident.
//! This is a 0.1 scaffold — see the roadmap in README.md / ARCHITECTURE.md.

/// The kern version, sourced from the workspace `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A validated sandbox / box name. Newtype so a raw `String` can't be passed where a
/// vetted name is required. Validation is intentionally strict (no path separators / `..`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxName(String);

impl BoxName {
    /// Parse a box name, rejecting anything that could traverse the filesystem.
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        if s.is_empty() {
            return Err("box name is empty");
        }
        if s.contains('/')
            || s.contains('\\')
            || s.contains('\0')
            || s.split('/').any(|c| c == "..")
        {
            return Err("box name contains a path separator or traversal");
        }
        Ok(BoxName(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_name_accepts_simple() {
        assert_eq!(BoxName::parse("web").unwrap().as_str(), "web");
    }

    #[test]
    fn box_name_rejects_traversal() {
        assert!(BoxName::parse("../etc").is_err());
        assert!(BoxName::parse("a/b").is_err());
        assert!(BoxName::parse("").is_err());
    }
}
