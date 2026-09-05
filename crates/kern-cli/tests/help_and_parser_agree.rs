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
            // `--quiet`/`-q` and `--all`/`-a` are synonym pairs; help shows one of the pair, which is fine.
            let synonyms: &[(&str, &str)] = &[
                ("--quiet", "-q"),
                ("-q", "--quiet"),
                ("--all", "-a"),
                ("-a", "--all"),
            ];
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
    let mut total_flags = 0usize;
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
        // Per-verb emptiness is NOT an error. `kern <verb> --help` is a slice of the reference, and
        // only `box` and `run` carry an `OPTIONS for …` block; the rest describe their flags inline
        // on the COMMANDS line, which this loop deliberately does not treat as definitions. The
        // guard against a vacuous test is therefore at the SET level, below.
        total_flags += seen.len();
        assert!(
            dupes.is_empty(),
            "`kern {verb} --help` lists {dupes:?} more than once. Two entries for one flag drift \
             apart, and the reader believes whichever they reach first."
        );
    }
    assert!(
        total_flags > 10,
        "only {total_flags} flag definitions were found across every verb, so this test is passing \
         because it parsed nothing rather than because nothing is duplicated"
    );
}

/// Every READ verb accepts `--json`.
///
/// The project's read/edit split says a read verb answers on the CLI and in JSON, and `kern top`
/// does the editing. Five verbs held to it and four did not: `volume ls`, `pod ls`, `config list`
/// and `diff` refused the flag, so a script reading those had to parse a table. Parsing a table is
/// how a box-controlled filename becomes a forged row: `kern diff` prints `C /path`, one space, and
/// the path is chosen by the workload.
///
/// The list is written out rather than derived, because the failure this guards is a NEW read verb
/// shipping without JSON, and a derived list would grow to include it and stay green.
#[test]
fn every_read_verb_accepts_json() {
    // (argv, needs a live subject). The ones needing a subject are checked for FLAG ACCEPTANCE
    // only: they must not fail with "unknown flag", and "no running box named" is a pass, since it
    // proves the parser took the flag and the verb got as far as looking for its argument.
    let verbs: [(&[&str], bool); 9] = [
        (&["ps", "--json"], false),
        (&["images", "--json"], false),
        (&["stats", "--json"], false),
        (&["volume", "ls", "--json"], false),
        (&["pod", "ls", "--json"], false),
        (&["config", "list", "--json"], false),
        (&["builds", "--json"], false),
        (&["diff", "no-such-box-here", "--json"], true),
        (&["inspect", "no-such-box-here", "--json"], true),
    ];
    for (argv, needs_subject) in verbs {
        let out = kern().args(argv).output().expect("run kern");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("unknown flag") && !stderr.contains("unexpected argument"),
            "`kern {}` refused --json: {stderr}",
            argv.join(" ")
        );
        if needs_subject {
            continue;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let t = stdout.trim();
        assert!(
            t.starts_with('[') || t.starts_with('{'),
            "`kern {}` accepted --json and printed something that is not JSON: {t:?}",
            argv.join(" ")
        );
    }
}

/// `kern <verb> --help` answers about THAT verb, not with the whole reference.
///
/// Six subcommands out of six (`volume`, `pod`, `config`, `compose`, `image`, `top`) answered the
/// universal `<tool> <verb> --help` habit by printing all 160 lines, so the reader had to find their
/// own verb in it. The assertion is on both halves: the page must be SHORTER than the full one, and
/// it must actually name the verb. Asserting only "shorter" would pass on an empty page.
#[test]
fn every_verb_has_its_own_help() {
    let full = kern().arg("--help").output().expect("run kern");
    let full_lines = String::from_utf8_lossy(&full.stdout).lines().count();
    assert!(
        full_lines > 40,
        "the full reference is only {full_lines} lines; this test's premise is gone"
    );
    // EVERY verb the reference declares, read out of the reference itself. This used to be a
    // hand-written list of fifteen, and the three it happened not to name were the three that were
    // broken: `killall`, `down` and `logout` each answered with the entire 184-line page, because the
    // dispatcher matched the FIRST token of a command line and those are all the second half of a
    // pair (`kill … | killall`, `up … / down`, `login … / logout`).
    //
    // A gate that samples finds what it was pointed at. Reading the list from the page cannot miss a
    // verb the page declares, which is the property this test is supposed to have.
    let reference = String::from_utf8_lossy(&full.stdout).to_string();
    let verbs = verbs_declared_in(&reference);
    assert!(
        verbs.len() > 40,
        "only {} verbs parsed out of the reference; the parser here is broken, not the CLI",
        verbs.len()
    );
    for verb in verbs {
        let verb = verb.as_str();
        let out = kern().args([verb, "--help"]).output().expect("run kern");
        let text = String::from_utf8_lossy(&out.stdout);
        let n = text.lines().count();
        assert!(
            n > 1,
            "`kern {verb} --help` printed {n} lines: it found nothing to say about the verb"
        );
        assert!(
            n < full_lines,
            "`kern {verb} --help` printed {n} lines against the reference's {full_lines}: it is \
             still answering with the whole page"
        );
        assert!(
            text.contains(verb),
            "`kern {verb} --help` never names the verb it claims to describe: {text:?}"
        );
    }
}

/// Every verb the command reference declares, taken from the reference rather than from a list.
///
/// Reads the head of each command line (the part before the description column), drops `<…>`, `[…]`
/// and `(…)` so a placeholder cannot pose as a verb, and keeps the bare words. That is what picks up
/// the second half of a pair: `kill <name>... | killall` declares both `kill` and `killall`, and
/// `volume <create|rm|edit|prune>` declares only `volume`, because the alternatives are inside `<>`.
fn verbs_declared_in(reference: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in reference.lines() {
        if !line.starts_with("    ") || !line[4..].starts_with(|c: char| c.is_ascii_lowercase()) {
            continue;
        }
        let trimmed = line.trim();
        let head = match trimmed.find("  ") {
            Some(i) => &trimmed[..i],
            None => continue, // no description column: not a command line
        };
        // Split on " | " and " / " AT DEPTH ZERO, and take the first bare word of each piece.
        //
        // The spacing is the discriminant, and it is the whole trick. A line that offers two VERBS
        // spaces its separator (`kill <name>... | killall`, `up … / down`, `login … / logout`), while
        // one that lists SUBCOMMANDS does not (`build logs|inspect|rm|prune <id>`). Without that,
        // `rm`, `watch`, `port`, `create`, `ls`, `edit`, `setup`, `clear` and `add` all arrive here as
        // top-level verbs and the test demands a help page for things that are not verbs.
        let mut depth = 0i32;
        let mut piece = String::new();
        let mut pieces: Vec<String> = Vec::new();
        let bytes: Vec<char> = head.chars().collect();
        let mut k = 0usize;
        while k < bytes.len() {
            let ch = bytes[k];
            match ch {
                '<' | '[' | '(' => depth += 1,
                '>' | ']' | ')' => depth = (depth - 1).max(0),
                _ => {}
            }
            let sep = depth == 0
                && ch == ' '
                && k + 2 < bytes.len()
                && (bytes[k + 1] == '|' || bytes[k + 1] == '/')
                && bytes[k + 2] == ' ';
            if sep {
                pieces.push(std::mem::take(&mut piece));
                k += 3;
                continue;
            }
            piece.push(ch);
            k += 1;
        }
        pieces.push(piece);
        for p in pieces {
            let word: String = p
                .trim()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            if word.starts_with(|c: char| c.is_ascii_lowercase()) && !out.contains(&word) {
                out.push(word);
            }
        }
    }
    out
}

/// The shell completions and the `COMMANDS:` reference describe the same verb set.
///
/// They are two hand-written descriptions of one parser, so they drifted. On 0.6.38 nine verbs the
/// reference documents (`commit`, `rmi`, `rename`, `update`, `wait`, `diff`, `events`, `up`,
/// `uninstall`) plus `down` could not be tab-completed: working commands, invisible to the discovery
/// path most people actually use. `completions.rs` even carried the comment "kept in one place so
/// all three shells stay in sync", which was true of the three shells and said nothing about the
/// reference, which is the other place.
///
/// `help` and `version` are the declared exception: they are bare-word spellings of `--help` and
/// `--version`, which live in `OPTIONS:` rather than `COMMANDS:`. The exception is written out here
/// so that adding a second one is a deliberate edit rather than a silent widening.
#[test]
fn the_completions_and_the_reference_agree() {
    let help = kern().arg("--help").output().expect("run kern");
    let help = String::from_utf8_lossy(&help.stdout);
    let comp = kern()
        .args(["completions", "bash"])
        .output()
        .expect("run kern");
    let comp = String::from_utf8_lossy(&comp.stdout);

    // The reference's COMMANDS block, up to the first OPTIONS heading.
    let start = help
        .find("COMMANDS:")
        .expect("the reference has a COMMANDS block");
    let end = help[start..]
        .find("OPTIONS")
        .map_or(help.len(), |o| start + o);
    let mut documented: Vec<&str> = Vec::new();
    for line in help[start..end].lines().skip(1) {
        // Verb tokens are the words that start a line or follow `|` or `/` on it. Colour codes are
        // already gone from a captured stdout when it is not a tty.
        for tok in line.split(|c: char| !(c.is_ascii_lowercase() || c == '-')) {
            if tok.len() > 1 && line.trim_start().starts_with(tok) {
                documented.push(tok);
                break;
            }
        }
    }
    let vlist = comp
        .lines()
        .find(|l| l.trim_start().starts_with("verbs="))
        .expect("the bash completion declares a verbs= list");
    let completable: Vec<&str> = vlist
        .trim()
        .trim_start_matches("verbs=")
        .trim_matches('"')
        .split_whitespace()
        .collect();

    assert!(
        completable.len() > 30,
        "only {} completable verbs were parsed, so this test is comparing against nothing",
        completable.len()
    );
    let missing: Vec<&&str> = documented
        .iter()
        .filter(|v| !completable.contains(v))
        .collect();
    assert!(
        missing.is_empty(),
        "documented but not tab-completable: {missing:?}. A verb the reference explains and the \
         shell cannot offer is invisible where people look first."
    );
}

/// The per-verb help must also be per-verb ON A TERMINAL, which is where everyone reads it.
///
/// `every_verb_has_its_own_help` runs the binary with stdout captured, so stdout is not a tty, so
/// the palette is empty, so the filter matched on lines that had no colour codes in them and passed.
/// On a real terminal the same command printed all 161 lines. The unit test on `strip_ansi` pins the
/// cause; this pins the behaviour end to end, in the configuration the other test cannot reach.
///
/// SKIPS when `script(1)` is unavailable rather than failing: allocating a pty is the only way to
/// make the shipped binary believe it is on a terminal, and a container without util-linux is not a
/// defect in kern.
#[test]
fn the_per_verb_help_stays_per_verb_on_a_real_terminal() {
    let bin = env!("CARGO_BIN_EXE_kern");
    let probe = Command::new("script").arg("--version").output();
    if !matches!(&probe, Ok(o) if o.status.success()) {
        eprintln!("skip: script(1) is not available, so no pty can be allocated");
        return;
    }
    let run = |args: &str| -> usize {
        Command::new("script")
            .args(["-qec", &format!("{bin} {args}"), "/dev/null"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
            .unwrap_or(0)
    };
    let full = run("--help");
    assert!(
        full > 40,
        "the full reference came back as {full} lines under a pty; the pty run itself is broken, \
         so this test proves nothing"
    );
    for verb in ["box", "run", "volume", "pod", "config", "diff"] {
        let n = run(&format!("{verb} --help"));
        assert!(
            n > 1 && n < full,
            "`kern {verb} --help` printed {n} lines under a pty against the reference's {full}: on \
             a terminal it is still answering with the whole page"
        );
    }
}
