//! The help text and the parser must agree about which flags exist.
//!
//! `reject_unknown_flags` carries a per-verb list of accepted flags, and `--help` carries a per-verb
//! description of the same thing. That is the same rule written twice, so it will drift: a flag added to
//! one and not the other either gets refused while documented, or accepted while undocumented. The
//! project has paid for this class ten times, and the fix that closed the flag-swallowing defect
//! introduced a fresh instance of it.
//!
//! This test is the guard. It reads the SHIPPED `--help`, extracts every flag it advertises for the
//! hardened verbs, and asserts the SHIPPED parser accepts each one - and refuses a flag neither knows.
//! Nothing here is hand-written except the verb names, so the two definitions cannot silently diverge.

use std::process::Command;

/// A `kern` whose ENTIRE state lives under a private temp tree.
///
/// This suite RUNS the hardened verbs to see whether the parser accepts each advertised flag, and two
/// of them - `gc` and `prune` - delete things for a living. Only `XDG_RUNTIME_DIR` was redirected, so
/// `cargo test` reaped the developer's real image cache: three images on this machine had lost their
/// rootfs that way, one of them three days before anyone noticed, and a node SDK integration test had
/// been failing ever since for what looked like an unrelated reason. A test that destroys the data of
/// the machine it runs on also invalidates every verification run that follows it.
///
/// `HOME` is redirected too, because every one of kern's directory resolvers falls back to it when its
/// XDG variable is unset - redirecting only the XDG names would leave that fallback pointing at the
/// real home.
fn kern() -> Command {
    let sandbox = std::env::temp_dir().join(format!("kern-help-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&sandbox);
    let mut c = Command::new(env!("CARGO_BIN_EXE_kern"));
    c.env("HOME", &sandbox)
        .env("XDG_CACHE_HOME", sandbox.join("cache"))
        .env("XDG_DATA_HOME", sandbox.join("data"))
        .env("XDG_CONFIG_HOME", sandbox.join("config"))
        .env("XDG_RUNTIME_DIR", sandbox.join("run"));
    c
}

/// The verbs whose flags are now checked at parse time. `top` is absent on purpose and not in silence:
/// it opens an interactive TUI, so running it in a test suite would hang rather than assert.
const HARDENED: &[&str] = &[
    "ps", "images", "stats", "doctor", "examples", "gc", "history", "info", "probe", "prune",
    "recover", "validate",
];

/// Flags a help line advertises: `--json`, `-q`, `-n`. Stops at the description, which starts after the
/// bracketed argument forms, so prose containing a dash is not mistaken for a flag.
fn flags_in(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for tok in line.split_whitespace() {
        let t = tok.trim_matches(|c| matches!(c, '[' | ']' | '(' | ')' | '|' | ',' | '.'));
        if t.len() >= 2
            && t.starts_with('-')
            && t.chars()
                .nth(1)
                .is_some_and(|c| c == '-' || c.is_ascii_alphabetic())
        {
            // `--filter name=|status=` advertises the flag, not its values.
            let name = t.split('=').next().unwrap_or(t).to_string();
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

fn help_text() -> String {
    let out = kern().arg("--help").output().expect("run kern --help");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn every_flag_help_advertises_is_accepted_by_the_parser() {
    let help = help_text();
    assert!(help.contains("USAGE"), "kern --help produced no usage text");

    let mut checked = 0;
    for verb in HARDENED {
        // The verb's own row in the help listing.
        let Some(line) = help
            .lines()
            .find(|l| l.trim_start().starts_with(&format!("{verb} ")) || l.trim() == *verb)
        else {
            panic!("`{verb}` is hardened but has no row in --help");
        };
        for flag in flags_in(line) {
            // Parse only: a bogus VALUE is fine, we are asserting the flag itself is known. The check
            // reads stderr rather than the exit code, because some of these verbs legitimately fail for
            // unrelated reasons (no config, nothing to prune) and that is not what is under test.
            let out = kern()
                .args([verb.to_string(), flag.clone(), "1".to_string()])
                .output()
                .expect("run kern");
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(
                !err.contains("unknown flag"),
                "`kern {verb} {flag}` is advertised in --help but the parser refuses it: {err}"
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 8,
        "only {checked} advertised flags were found across {} verbs - the help parsing is probably wrong, \
         which would make this test pass without checking anything",
        HARDENED.len()
    );
}

#[test]
fn a_flag_neither_side_knows_is_refused_by_every_hardened_verb() {
    for verb in HARDENED {
        let out = kern()
            .args([verb, "--definitely-not-a-real-flag"])
            .output()
            .expect("run kern");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("unknown flag"),
            "`kern {verb} --definitely-not-a-real-flag` was not refused. stderr: {err}"
        );
        assert!(
            !out.status.success(),
            "`kern {verb}` with a bogus flag exited 0"
        );
    }
}

/// The other direction. The test above walks help -> parser, which catches the defect that hurts a
/// reader: being told about a flag that does not work. This one walks parser -> help, catching the
/// quieter one: a flag that works but is documented nowhere, so nobody finds it.
///
/// The allowed lists live in the parser and are private, so this reads the source at COMPILE time
/// with `include_str!`. Not elegant, but it compares the two real definitions instead of a third
/// hand-written copy, which is the whole point.
#[test]
fn every_flag_the_parser_accepts_is_advertised_in_help() {
    let src = include_str!("../src/cli.rs");
    let help = help_text();

    // `reject_unknown_flags("ps", &rest, &["--json", "-q", …])`, possibly wrapped across lines by rustfmt.
    let flat: String = src.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut found = 0;
    for verb in HARDENED {
        let needle = format!("reject_unknown_flags( \"{verb}\", &rest, &[");
        let alt = format!("reject_unknown_flags(\"{verb}\", &rest, &[");
        let Some(start) = flat.find(&needle).or_else(|| flat.find(&alt)) else {
            panic!("`{verb}` is in HARDENED but has no reject_unknown_flags call in cli.rs");
        };
        let rest = &flat[start..];
        let list = &rest[rest.find("&[").unwrap() + 2..rest.find(']').expect("unterminated list")];
        let line = help
            .lines()
            .find(|l| l.trim_start().starts_with(&format!("{verb} ")) || l.trim() == *verb)
            .unwrap_or_else(|| panic!("`{verb}` has no row in --help"));

        for raw in list.split(',') {
            let flag = raw.trim().trim_matches('"');
            if flag.is_empty() {
                continue;
            }
            found += 1;
            // `--quiet` is the long spelling of `-q`; help shows one of a synonym pair, which is fine.
            let synonyms: &[(&str, &str)] = &[("--quiet", "-q"), ("-q", "--quiet")];
            let alt_ok = synonyms.iter().any(|(a, b)| *a == flag && line.contains(b));
            assert!(
                line.contains(flag) || alt_ok,
                "the parser accepts `kern {verb} {flag}` but --help never mentions it:\n  {line}"
            );
        }
    }
    assert!(
        found >= 8,
        "only {found} parser flags were extracted from cli.rs - the source parsing is wrong, which would \
         make this test pass without checking anything"
    );
}

/// No verb may advertise the same flag twice in one `--help`.
///
/// `kern box --help` listed `--timeout` on two lines: "Auto-stop the box after N seconds" and
/// "Auto-stop: SIGTERM at n seconds, SIGKILL 2 seconds later (so n+2 worst case)". Both were true
/// and only the second was complete, so a reader who scanned to the first entry and stopped had no
/// way to know a kill can land n+2 seconds in. An outside tester read it that way and reported the
/// timeout as broken; it was not, it was measured at a constant 2.0 s of grace on 1, 2 and 5 second
/// timeouts.
///
/// One fact with two homes is the class this project keeps paying for. Two entries for one flag
/// cannot be kept in agreement by attention, so they are refused.
#[test]
fn no_verb_advertises_a_flag_twice() {
    for verb in ["box", "run", "compose", "pull", "push", "volume", "pod"] {
        let out = kern().args([verb, "--help"]).output().expect("run kern");
        let text = String::from_utf8_lossy(&out.stdout);
        let mut seen: Vec<&str> = Vec::new();
        let mut dupes: Vec<&str> = Vec::new();
        for line in text.lines() {
            // Only the definition lines: a flag NAMED inside a description is a reference, not a
            // second entry, and refusing those would make every cross-reference a failure.
            let t = line.trim_start();
            if line.len() == t.len() || !t.starts_with("--") {
                continue;
            }
            let flag = t.split([' ', '=', ',']).next().unwrap_or("");
            if flag.len() < 3 {
                continue;
            }
            if seen.contains(&flag) {
                dupes.push(flag);
            } else {
                seen.push(flag);
            }
        }
        assert!(
            !seen.is_empty(),
            "`kern {verb} --help` advertised no flags at all, so this test guards nothing"
        );
        assert!(
            dupes.is_empty(),
            "`kern {verb} --help` lists {dupes:?} more than once. Two entries for one flag drift \
             apart, and the reader believes whichever they reach first."
        );
    }
}
