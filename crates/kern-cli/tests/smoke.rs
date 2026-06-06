//! Black-box integration tests: run the actual `kern` binary and assert its observable
//! behaviour. (Unit tests live inline in each module; these exercise the public CLI surface.)

use std::process::Command;

fn kern() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kern"))
}

#[test]
fn version_prints_and_succeeds() {
    let out = kern().arg("--version").output().expect("run kern");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.starts_with("kern 0.1.0"), "got: {s}");
}

#[test]
fn help_lists_commands() {
    let out = kern().arg("--help").output().expect("run kern");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    for verb in ["box", "run", "pull", "compose", "--no-gpu"] {
        assert!(s.contains(verb), "help missing {verb}");
    }
}

#[test]
fn no_gpu_is_accepted_on_any_command() {
    // `--no-gpu` must be a real, accepted code path (not just a README bullet).
    let out = kern().args(["--no-gpu", "box"]).output().expect("run kern");
    // box isn't implemented at 0.1, but the flag must parse (no "unknown" error).
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("unknown"), "--no-gpu should parse: {err}");
}

#[test]
fn unknown_command_fails_cleanly() {
    let out = kern().arg("frobnicate").output().expect("run kern");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown command"));
}
