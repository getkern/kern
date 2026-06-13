//! Shared types and utilities for kern.
//!
//! Newtypes live here so units (bytes vs MiB, names vs paths) can't be mixed up by accident.
//! This is a 0.1 scaffold — see the roadmap in README.md / ARCHITECTURE.md.

/// The kern version, sourced from the workspace `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Registry credentials shared by `kern login`/`logout` and the OCI pull path.
pub mod registry_auth;

/// The tiny TOML-ish value readers (quoted string / bool / `[...]` array / `#` comment) shared by the
/// `kern.toml` profile loader and the `kern-compose` file parser.
pub mod toml_lite;

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

/// Parse a binary size like `512m`, `1g`, `512mb`, `2t`, or a bare byte count (`268435456`) into
/// bytes. Units are binary (`k`=1024). An optional trailing `b` is accepted (`mb`==`m`), as is
/// surrounding whitespace. Returns `None` on a malformed, zero, or overflowing value — callers layer
/// their own upper cap / `Result` / error message. One source of truth for `--memory`, `--size`,
/// vdisk sizes and profile size fields, so they can never disagree on what `512m` means.
pub fn parse_binary_size(s: &str) -> Option<u64> {
    const K: u64 = 1024;
    let lower = s.trim().to_ascii_lowercase();
    let t = lower.strip_suffix('b').unwrap_or(&lower).trim_end(); // "gb"→"g", "512 b"→"512"
    let (num, mult) = match t.chars().last()? {
        'k' => (&t[..t.len() - 1], K),
        'm' => (&t[..t.len() - 1], K * K),
        'g' => (&t[..t.len() - 1], K * K * K),
        't' => (&t[..t.len() - 1], K * K * K * K),
        '0'..='9' => (t, 1),
        _ => return None,
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .filter(|b| *b > 0)
}

/// The shared rule for a kern resource name — volume, secret, pod, profile/vdisk. Each becomes a
/// filesystem path component and/or a `kind:name` attach token, so: non-empty, ≤64 bytes, charset
/// `[A-Za-z0-9_.-]`, no `..` substring (path escape), no leading `-` (argument injection) or `.`
/// (dotfiles / `.`/`..`). One definition so the four callers can't drift into subtly different rules
/// (a name valid for a pod but not a volume, etc.). Callers layer their own error message / type.
pub fn valid_resource_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.contains("..")
        && !name.starts_with('-')
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

/// Format a byte count for display with binary units: an exact multiple prints as an integer
/// (`512M`, `2G`), otherwise one decimal (`1.5G`), and anything below 1 KiB as `N B` (so `0` reads
/// `0 B`, not `0K`). One convention for the box banner, `ps`/`stats`, `top` and volume sizes, so the
/// same `512 MiB` never renders three different ways.
pub fn fmt_bytes(b: u64) -> String {
    const K: u64 = 1024;
    for (unit, sz) in [("T", K.pow(4)), ("G", K.pow(3)), ("M", K.pow(2)), ("K", K)] {
        if b >= sz {
            return if b % sz == 0 {
                format!("{}{unit}", b / sz)
            } else {
                format!("{:.1}{unit}", b as f64 / sz as f64)
            };
        }
    }
    format!("{b} B")
}

/// Right-pad `text` to `width` VISIBLE columns (Unicode scalar count), returning `pad + text`. Use this
/// instead of `{:>width}` when the cell may contain a multi-byte glyph like `∞` (1 column, 3 bytes):
/// the `{:>N}` formatter counts bytes, so it would misalign the column. Apply any colour AFTER padding
/// (colour codes are zero-width and must not count toward the field). One helper for the volume QUOTA
/// cell in `kern volume ls` and the `kern top` Storage tab, so the two can't drift.
pub fn pad_visible(text: &str, width: usize) -> String {
    let pad = width.saturating_sub(text.chars().count());
    format!("{}{}", " ".repeat(pad), text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_bytes_convention() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(256 * 1024), "256K");
        assert_eq!(fmt_bytes(512 * 1024 * 1024), "512M");
        assert_eq!(fmt_bytes(1024 * 1024 * 1024), "1G");
        assert_eq!(fmt_bytes(1536 * 1024 * 1024), "1.5G"); // non-exact → one decimal
        assert_eq!(fmt_bytes(2 * 1024u64.pow(4)), "2T");
    }

    #[test]
    fn pad_visible_counts_columns_not_bytes() {
        // A 3-byte 1-column glyph pads by COLUMN width, so the field is 10 columns wide (not 8).
        assert_eq!(pad_visible("∞", 10), "         ∞"); // 9 spaces + ∞ = 10 columns
        assert_eq!(pad_visible("∞", 10).chars().count(), 10);
        assert_eq!(pad_visible("2G", 10), "        2G");
        // Text already at/over width isn't truncated (saturating pad = 0).
        assert_eq!(pad_visible("1234567890", 10), "1234567890");
        assert_eq!(pad_visible("overlong", 3), "overlong");
    }

    #[test]
    fn parse_binary_size_units_and_forms() {
        assert_eq!(parse_binary_size("512"), Some(512));
        assert_eq!(parse_binary_size("1k"), Some(1024));
        assert_eq!(parse_binary_size("512m"), Some(512 * 1024 * 1024));
        assert_eq!(parse_binary_size("2g"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_binary_size("64t"), Some(64 * 1024u64.pow(4)));
        assert_eq!(parse_binary_size("512mb"), parse_binary_size("512m")); // trailing 'b' allowed
        assert_eq!(parse_binary_size(" 1G "), Some(1024 * 1024 * 1024)); // whitespace tolerant
        assert_eq!(parse_binary_size("0"), None); // zero rejected
        assert_eq!(parse_binary_size("abc"), None);
        assert_eq!(parse_binary_size(""), None);
        assert_eq!(parse_binary_size("b"), None);
    }

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
