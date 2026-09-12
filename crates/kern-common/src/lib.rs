//! Shared types and utilities for kern.
//!
//! Newtypes live here so units (bytes vs MiB, names vs paths) can't be mixed up by accident.
//! This is a 0.1 scaffold - see the roadmap in README.md / ARCHITECTURE.md.

/// The kern version. On a release binary this is the tag, exactly as before: the release workflow
/// rewrites `Cargo.toml` from the tag and `build.rs` passes that through untouched. On a build from
/// source, where `Cargo.toml` still reads the de-versioned `0.0.0`, this is `git describe` instead
/// (`v0.9.2-45-gf7622ee-dirty`), because a binary that cannot say which build it is turns any
/// comparison of two builds into a guess. See `build.rs` for why that is not a hypothetical.
pub const VERSION: &str = env!("KERN_VERSION");

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
    /// Maximum length, in bytes, DERIVED from the longest name kern builds out of it rather than
    /// picked for being small.
    ///
    /// Every derived name is `kern-box-<name>-<pid>` or shorter: 9 bytes of prefix, the name, a
    /// separator and a pid (10 digits covers any `pid_max`), plus `.scope` when it becomes a systemd
    /// unit. At 200 that is 226 bytes, inside both `NAME_MAX` (255, the filesystem limit on the
    /// registry entry, the cgroup leaf, the log and the health sidecar) and systemd's 256.
    ///
    /// IT WAS 64, "conservative", and 64 is what `<project>-<service>` exceeds on any real compose
    /// project: MEASURED on Sentry self-hosted, where
    /// `sentry-self-hosted-snuba-subscription-consumer-generic-metrics-counters` is 71 bytes and the
    /// service simply refused to start, on a name Docker Compose generates and accepts. The box's
    /// hostname is a separate matter and always was: `set_hostname` truncates to `HOST_NAME_MAX`,
    /// which is 64 and is the kernel's limit, not this one.
    pub const MAX_LEN: usize = 200;

    /// Parse a box name under the conservative rules above.
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        if s.is_empty() {
            return Err("box name is empty");
        }
        if s.len() > Self::MAX_LEN {
            return Err("box name is too long (max 200 characters)");
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

/// The smallest memory cap kern accepts, and it exists because A BARE NUMBER IS BYTES.
///
/// `--memory 64` caps the box at 64 bytes, not at 64 MiB. Every box given it dies in ~3 ms with
/// kern's own OOM message, which tells the reader to raise the cap: they raise it to `128`, and it
/// happens again. The message is true and it sends the reader in a circle, because the mistake is the
/// missing unit and nothing in the output says so.
///
/// MEASURED on this host (x86_64, kernel 7.0, `--image alpine`), which is where the number comes
/// from rather than from another runtime's choice:
///
/// | cap | what starts |
/// |---|---|
/// | 4 KiB, 64 KiB, 128 KiB | nothing: exit 137 with the OOM message |
/// | 256 KiB | `/bin/true`, but not a shell |
/// | 384 KiB | `/bin/sh -c 'echo hi'` and `busybox ls` |
///
/// So the floor sits AT the largest measured value where nothing ran, and the refusal is `< FLOOR`:
/// it can only ever reject a cap that cannot start a box, and never one that measurably works. It is
/// deliberately NOT docker's 6 MiB minimum, which would refuse the 384 KiB case that runs here.
pub const MIN_MEMORY_CAP_BYTES: u64 = 128 * 1024;

/// Is this memory cap below the floor a box needs to start? See [`MIN_MEMORY_CAP_BYTES`]. One
/// definition, so the CLI flag, a compose file's keys and a profile's `memory` field cannot disagree
/// about which caps are impossible.
#[must_use]
pub fn memory_cap_below_floor(bytes: u64) -> bool {
    bytes < MIN_MEMORY_CAP_BYTES
}

/// Parse a binary size like `512m`, `1g`, `512mb`, `2t`, or a bare byte count (`268435456`) into
/// bytes. Units are binary (`k`=1024). An optional trailing `b` is accepted (`mb`==`m`), as is
/// surrounding whitespace. Returns `None` on a malformed, zero, or overflowing value - callers layer
/// their own upper cap / `Result` / error message. One source of truth for `--memory`, `--size`,
/// vdisk sizes and profile size fields, so they can never disagree on what `512m` means.
///
/// NO FLOOR HERE, on purpose: a 64 KiB `--tmpfs` or `--shm-size` is a legitimate size, and only a
/// memory CAP is impossible that small. The floor is [`memory_cap_below_floor`], applied by the
/// callers that parse a cap.
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
    let num = num.trim();
    if let Some(n) = num.parse::<u64>().ok().and_then(|n| n.checked_mul(mult)) {
        return Some(n).filter(|b| *b > 0);
    }
    // A FRACTIONAL SIZE, WHICH DOCKER ACCEPTS AND THIS PARSER REFUSED. Compose sizes go through
    // go-units, whose `RAMInBytes` parses a float, so `1.5g` is an ordinary thing to write in a
    // compose file. MEASURED on Docker's OWN `minecraft` sample, which sets
    // `deploy.resources.limits.memory: 1.5G`: the stack died with `usage: kern --memory <size>`,
    // an error about kern's flag for a value the user never typed.
    //
    // THE CHARSET IS CHECKED EXPLICITLY rather than left to `f64::from_str`, which also accepts
    // `1e3`, `inf`, `NaN` and a sign. A size is digits with at most one dot; everything else is a
    // typo, and a parser that silently read `inf` or `-1` as a memory cap would be worse than one
    // that refuses a fraction.
    let mut dots = 0usize;
    if num.is_empty()
        || !num.bytes().all(|c| {
            if c == b'.' {
                dots += 1;
                true
            } else {
                c.is_ascii_digit()
            }
        })
        || dots != 1
    {
        return None;
    }
    let f: f64 = num.parse().ok()?;
    // Truncating, which is what go-units does: `1.5g` is 1610612736 bytes under both.
    let bytes = f * mult as f64;
    if !bytes.is_finite() || bytes < 1.0 || bytes >= u64::MAX as f64 {
        return None;
    }
    Some(bytes as u64)
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

    /// A FRACTIONAL SIZE IS A SIZE, because Docker's own samples write one.
    ///
    /// Compose sizes are parsed by go-units, which takes a float, so `1.5G` is ordinary in a compose
    /// file. MEASURED on Docker's `minecraft` sample (`deploy.resources.limits.memory: 1.5G`): the
    /// stack died with a usage error about kern's `--memory` flag. After the change the box comes up
    /// and its own cgroup reads `memory.max` = 1610612736, which is the number this test asserts.
    #[test]
    fn parse_binary_size_takes_a_fraction_and_still_refuses_a_non_number() {
        assert_eq!(parse_binary_size("1.5g"), Some(1_610_612_736));
        assert_eq!(parse_binary_size("1.5G"), Some(1_610_612_736));
        assert_eq!(parse_binary_size("1.5gb"), Some(1_610_612_736));
        assert_eq!(parse_binary_size("0.5k"), Some(512));
        // Truncating, which is what go-units does, so the two agree on the awkward values too.
        assert_eq!(parse_binary_size("1.7"), Some(1));
        // THE INTEGER PATH IS UNCHANGED AND EXACT. A size big enough to lose precision as an `f64`
        // must not start going through the float branch: 2^53 + 1 bytes is representable as a `u64`
        // and is not as an `f64`, so this asserts the integer parse still runs first.
        assert_eq!(
            parse_binary_size("9007199254740993"),
            Some(9_007_199_254_740_993)
        );
        // WHAT A FLOAT PARSER WOULD HAVE TAKEN AND A SIZE MUST NOT. `f64::from_str` accepts every
        // one of these, and a memory cap of `inf` or `-1` is worse than a refused fraction.
        // A LEADING DOT IS A NUMBER: Go's `ParseFloat` reads ".5" and so does this, so the two
        // agree that `.5g` is half a gibibyte rather than one of them refusing it.
        assert_eq!(parse_binary_size(".5g"), Some(512 * 1024 * 1024));
        for junk in [
            "1e3", "inf", "-inf", "NaN", "-1", "-1g", "1.2.3", "1.", "1 . 5", ".",
        ] {
            assert_eq!(parse_binary_size(junk), None, "{junk} must not parse");
        }
        // A LEADING `+` IS TAKEN, AND THAT PREDATES THIS CHANGE: `u64::from_str` accepts one, so the
        // integer branch has always read `+5` as 5. Recorded rather than quietly left untested, so
        // that whoever decides to tighten it is changing something this file says out loud.
        assert_eq!(parse_binary_size("+5"), Some(5));
        assert_eq!(parse_binary_size("+5g"), Some(5 * 1024 * 1024 * 1024));
        // Zero stays rejected however it is spelled: a cap of nothing is not a cap.
        assert_eq!(parse_binary_size("0.0g"), None);
        assert_eq!(parse_binary_size("0.0000001k"), None);
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
        // THE LENGTH A REAL COMPOSE PROJECT PRODUCES. `<project>-<service>` is what Docker Compose
        // names a container, and Sentry self-hosted's longest is 71 bytes - refused outright while
        // the limit was 64, on a name `docker compose up` accepts. The name kern derives from it
        // (`kern-box-<name>-<pid>`, plus `.scope` as a systemd unit) still fits every limit below.
        let real = "sentry-self-hosted-snuba-subscription-consumer-generic-metrics-counters";
        assert_eq!(real.len(), 71);
        assert!(BoxName::parse(real).is_ok(), "{real}");
        let derived = format!(
            "kern-box-{}-{}.scope",
            "a".repeat(BoxName::MAX_LEN),
            u32::MAX
        );
        assert!(
            derived.len() < 255,
            "the longest name kern builds must fit NAME_MAX and a systemd unit name: {}",
            derived.len()
        );
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
    ///
    /// `"2.5gib"` USED TO BE IN THIS LIST AND WAS MOVED OUT ON PURPOSE. It is not a bare unit: it is
    /// a fractional size, refused as a side effect of an integer-only parse rather than by any rule
    /// this test states. It now parses, because Docker's own samples write one, and it is asserted
    /// in `parse_binary_size_takes_a_fraction_and_still_refuses_a_non_number` with its value. A
    /// negative fraction stays here, where it belongs.
    #[test]
    fn a_bare_unit_is_still_refused() {
        for s in [
            "", " ", "b", "gib", "ib", "g", "kib", "two gib", "-2gib", "-2.5gib", "gib2",
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
