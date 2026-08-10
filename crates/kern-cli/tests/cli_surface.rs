//! CLI-surface freeze gate. Snapshots the `kern --help` reference - every verb, its flags, and where
//! `--json` is offered - and fails the build on ANY change, so the CLI surface declared stable in
//! CHANGELOG.md ("As of v0.7.0 the command surface is stable ...") cannot drift silently. A
//! changed/added/removed verb or flag fails this test until the snapshot is regenerated (a conscious
//! act) and a CHANGELOG entry is added. This is the automated guard that turns the freeze from prose
//! into a gate - the same bar every other boundary in this repo is held to.
//!
//! The ASCII banner and the `kern <version>:` tagline are excluded (they change on a version bump, not
//! a surface change) by capturing from the `USAGE:` line onward. Trailing whitespace is normalized so
//! an editor's stripping cannot cause a false diff. `kern --help` is deterministic (verified) and the
//! debug and musl-release binaries emit byte-identical help.

use std::process::Command;

/// The frozen surface: `kern --help` from `USAGE:` onward, each line right-trimmed.
fn normalize(text: &str) -> String {
    let start = text
        .find("USAGE:")
        .expect("kern --help must contain a USAGE: section");
    text[start..]
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

#[test]
fn cli_surface_is_frozen() {
    let out = Command::new(env!("CARGO_BIN_EXE_kern"))
        .arg("--help")
        .output()
        .expect("run kern --help");
    assert!(
        out.status.success(),
        "kern --help exited non-zero: {:?}",
        out.status
    );
    let actual = normalize(&String::from_utf8_lossy(&out.stdout));
    let snapshot = normalize(include_str!("cli-surface.snapshot"));

    assert_eq!(
        actual, snapshot,
        "\n\nThe CLI surface (verbs / flags / --json in `kern --help`) changed vs \
         tests/cli-surface.snapshot.\n\
         - INTENTIONAL change: regenerate the snapshot and add a CHANGELOG entry (the CLI is declared \
         stable as of v0.7.0, so a removed/renamed verb or flag is a breaking change - minor bump):\n\
         \x20   cargo run -q -p getkern -- --help | sed -n '/USAGE:/,$p' | sed -e 's/[[:space:]]*$//' \
         > crates/kern-cli/tests/cli-surface.snapshot\n\
         - UNINTENTIONAL: you moved the CLI surface without meaning to.\n"
    );
}
