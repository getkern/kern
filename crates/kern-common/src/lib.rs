//! Shared types and utilities for kern.
//!
//! Newtypes live here so units (bytes vs MiB, names vs paths) can't be mixed up by accident.
//! This is a 0.1 scaffold — see the roadmap in README.md / ARCHITECTURE.md.

/// The kern version, sourced from the workspace `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A validated sandbox / box name. Newtype so a raw `String` can't be passed where a vetted
/// name is required.
///
/// The name becomes a real filesystem path component and may reach a command line, so the
/// charset is deliberately conservative: ASCII letters, digits, `_`, `.`, `-` only, no leading
/// `-` (argument-injection) or `.` (`.`/`..` and hidden dirs), bounded length. This blocks path
/// traversal, NUL, whitespace, control characters and shell metacharacters by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxName(String);

impl BoxName {
    /// Maximum length, in bytes. Conservative — box names are short identifiers.
    pub const MAX_LEN: usize = 64;

    /// Parse a box name under the conservative rules above.
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        if s.is_empty() {
            return Err("box name is empty");
        }
        if s.len() > Self::MAX_LEN {
            return Err("box name is too long (max 64 characters)");
        }
        // First char gates the two injection-class footguns: leading '-' (looks like a flag)
        // and leading '.' (`.`, `..`, hidden dirs).
        let first = s.as_bytes()[0];
        if !(first.is_ascii_alphanumeric() || first == b'_') {
            return Err("box name must start with a letter, digit or '_'");
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
        {
            return Err("box name allows only letters, digits, '_', '.' and '-'");
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
    fn box_name_accepts_sane_identifiers() {
        for ok in ["web", "my_box", "api-1", "v2.3", "_internal", "A0"] {
            assert_eq!(
                BoxName::parse(ok).unwrap().as_str(),
                ok,
                "should accept {ok}"
            );
        }
    }

    #[test]
    fn box_name_rejects_traversal_and_separators() {
        for bad in ["../etc", "a/b", "a\\b", "..", ".", "", "/etc/passwd"] {
            assert!(BoxName::parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn box_name_rejects_injection_class() {
        // leading '-' (flag injection), leading '.' (dotfiles), shell metachars, whitespace,
        // control chars, NUL and non-ascii must all be rejected.
        for bad in [
            "-rf",
            "--plan",
            ".hidden",
            "web;rm",
            "$(id)",
            "a b",
            "tab\there",
            "💥",
        ] {
            assert!(BoxName::parse(bad).is_err(), "should reject {bad:?}");
        }
        assert!(BoxName::parse("nul\0byte").is_err());
    }

    #[test]
    fn box_name_enforces_length_cap() {
        assert!(BoxName::parse(&"a".repeat(BoxName::MAX_LEN)).is_ok());
        assert!(BoxName::parse(&"a".repeat(BoxName::MAX_LEN + 1)).is_err());
    }
}
