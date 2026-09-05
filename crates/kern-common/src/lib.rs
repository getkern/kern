//! Shared types and utilities for kern.
//!
//! Newtypes live here so units (bytes vs MiB, names vs paths) can't be mixed up by accident.
//! This is a 0.1 scaffold - see the roadmap in README.md / ARCHITECTURE.md.

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
    /// Maximum length, in bytes. Conservative - box names are short identifiers.
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
/// surrounding whitespace. Returns `None` on a malformed, zero, or overflowing value - callers layer
/// their own upper cap / `Result` / error message. One source of truth for `--memory`, `--size`,
/// vdisk sizes and profile size fields, so they can never disagree on what `512m` means.
pub fn parse_binary_size(s: &str) -> Option<u64> {
    const K: u64 = 1024;
    let lower = s.trim().to_ascii_lowercase();
    // "gib"→"g", "gb"→"g", "512 b"→"512". THE IEC FORM IS STRIPPED FIRST, and it has to be: one pass
    // of `strip_suffix('b')` turns "2gib" into "2gi", whose last character is not a unit, so the most
    // precise spelling of a binary size was the one form this parser refused while it accepted the
    // sloppier "2gb". An operator who writes what they mean got an error; one who writes "2gb" did
    // not. The units here have always been binary, so "gib" and "gb" name the same number and both
    // are taken.
    let t = lower
        .strip_suffix("ib")
        .or_else(|| lower.strip_suffix('b'))
        .unwrap_or(&lower)
        .trim_end();
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

/// The shared rule for a kern resource name - volume, secret, pod, profile/vdisk. Each becomes a
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

/// Render `items` as a JSON array, `render` producing each element.
///
/// Eight emitters had written the same loop by hand: open a `[`, `enumerate`, push a `,` when the
/// index is non-zero, close with `]`. The separator is the whole risk. Getting it wrong in one of
/// eight places produces output that is not JSON at all, and the consumer that finds out is a script
/// in someone else's pipeline. Written once, it cannot be got wrong in the ninth.
///
/// `render` returns an owned `String` because that is what every caller already builds with
/// `format!`. These run once per invocation over a list a human asked for, never in a box-start
/// path, so the allocation per element is not on any hot path; the array itself reserves once.
pub fn json_array<T>(items: &[T], mut render: impl FnMut(&T) -> String) -> String {
    let mut out = String::with_capacity(items.len() * 64 + 2);
    out.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&render(item));
    }
    out.push(']');
    out
}

/// Escape `s` as a JSON string literal, quotes included.
///
/// Lives here and not next to one emitter because FIVE verbs print JSON (`ps`, `images`, `stats`,
/// `inspect`, `volume ls`) and a second copy of an escaper is how one of them ends up not escaping
/// something. The control-character branch is the security-relevant one: a box name or a volume
/// name is attacker-influenced in the case kern exists for, and a raw `0x1b` reaching a terminal
/// that cats the output is a repaint of kern's own words. Same defect class as the `kern.toml`
/// backend field, closed here by construction for every caller at once.
///
/// Not zero-copy on purpose: the escaped form is a different length than the input in the general
/// case, and these emitters run once per invocation on a list a human asked for, not in a box-start
/// path. The capacity is pre-reserved so the common case (nothing to escape) is a single allocation.
pub fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if c.is_control() => o.push_str(&format!("\\u{:04x}", c as u32)),
            _ => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Is this boolean env flag SET? A variable exported but EMPTY counts as unset.
///
/// `KERN_NO_SCOPE= kern box …`, and the `export FOO=${FOO:-}` idiom every CI script uses, both leave the
/// name present with an empty value. Read with a bare `is_some()`, which meant "the flag is on", so on a
/// host where the systemd scope IS the enforcement (a Raspberry Pi 5, measured 2026-07-30) an empty
/// `KERN_NO_SCOPE` left `--memory` at `max` and a workload 3x over its cap exited 0, with nothing
/// printed. The project already treats an exported-but-blank `KERN_CONFIG` and `XDG_CONFIG_HOME` as
/// unset for exactly this reason; the boolean flags had never been given the rule.
pub fn env_flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

/// Is kern's own PROGRESS output wanted here? True only when stderr is a terminal.
///
/// kern and a box's workload share one stderr, and kern's launcher writes progress into it: pull
/// steps, layer lines, per-service compose bring-up. In a terminal that is the point. Anywhere else
/// it is contamination of someone else's stream, and the SDK made the cost concrete: `run_code` on an
/// uncached image came back with six `→ layer …` lines sitting in front of the program's own output,
/// and an agent reading that result spent its context on kern's housekeeping.
///
/// The repo already had this rule for the `kern box` status panel ("ONLY when stderr is a terminal, so
/// pipes/scripts/`kern logs` stay clean"); the pull and compose paths never adopted it. One predicate
/// now, so a new progress line inherits the rule instead of having to remember it. `scripts/progress-
/// is-tty-gated.py` fails the build on a progress line that goes out any other way.
///
/// NOT for errors, warnings or `kern: note:` advice. Those are how kern reports something the user has
/// to act on, and a pipe is exactly where they must still arrive: silence there would trade one wrong
/// behaviour for a worse one. This gates the narrator, not the messenger.
pub fn progress_wanted() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
}

/// Write one line of kern's own progress to stderr, and ONLY when [`progress_wanted`].
///
/// Same arguments as `eprintln!`. Every progress line in the workspace goes through this; the gate
/// script enforces it, because the failure it prevents is a line nobody thought of as output.
#[macro_export]
macro_rules! progress {
    ($($arg:tt)*) => {{
        if $crate::progress_wanted() {
            eprintln!($($arg)*);
        }
    }};
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

#[cfg(test)]
mod an_exported_but_empty_flag_is_not_set {
    use super::*;

    #[test]
    fn empty_counts_as_unset_because_that_is_what_a_shell_means_by_it() {
        // The shape that silently disabled cap enforcement: `KERN_NO_SCOPE= kern box …`, and the
        // `export FOO=${FOO:-}` idiom, both leave the name present with an empty value.
        let name = "KERN_TEST_FLAG_EMPTY_IS_UNSET";
        std::env::remove_var(name);
        assert!(!env_flag(name), "absent must be off");
        std::env::set_var(name, "");
        assert!(!env_flag(name), "exported but EMPTY must be off");
        std::env::set_var(name, "1");
        assert!(env_flag(name), "a value must be on");
        std::env::set_var(name, "0");
        assert!(
            env_flag(name),
            "any non-empty value is on: this is a presence flag, not a boolean"
        );
        std::env::remove_var(name);
    }
}

/// Every spelling of a size that is accepted must mean the same number.
#[cfg(test)]
mod size_spellings {
    use super::parse_binary_size as p;

    const G: u64 = 1 << 30;

    /// The case this module was written for. `2gb` was accepted and `2GiB`, the precise spelling of
    /// exactly the same quantity, was the one form refused: one pass of `strip_suffix('b')` left
    /// `2gi`, whose last character is not a unit.
    #[test]
    fn the_iec_spelling_agrees_with_the_short_one() {
        for s in [
            "2g", "2G", "2gb", "2GB", "2gib", "2GiB", "2GIB", "2 g", "2 GiB", " 2g ",
        ] {
            assert_eq!(p(s), Some(2 * G), "{s:?}");
        }
    }

    #[test]
    fn every_unit_takes_the_iec_form() {
        assert_eq!(p("512kib"), p("512k"));
        assert_eq!(p("512mib"), p("512m"));
        assert_eq!(p("512gib"), p("512g"));
        assert_eq!(p("1tib"), p("1t"));
    }

    /// The units were always binary, so the IEC spelling must not be read as a decimal one: `1gib`
    /// is 1073741824 and not 1000000000. Asserting the value, not just the agreement, because two
    /// spellings could agree on the wrong number.
    #[test]
    fn the_units_are_binary_and_stay_binary() {
        assert_eq!(p("1kib"), Some(1024));
        assert_eq!(p("1mib"), Some(1024 * 1024));
        assert_eq!(p("1gib"), Some(G));
        assert_eq!(p("1tib"), Some(1024 * G));
    }

    /// A suffix is not a size on its own, and nothing here may make one parse.
    #[test]
    fn a_bare_unit_is_still_refused() {
        for s in [
            "", " ", "b", "gib", "ib", "g", "kib", "two gib", "-2gib", "2.5gib",
        ] {
            assert_eq!(p(s), None, "{s:?}");
        }
    }

    /// Zero is not a size any caller can use, whichever way it is spelled.
    #[test]
    fn zero_is_refused_in_every_spelling() {
        for s in ["0", "0k", "0gib", "0 GiB", "0b"] {
            assert_eq!(p(s), None, "{s:?}");
        }
    }
}
