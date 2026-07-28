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
    // Version-agnostic: assert the binary reports its own crate version, so a bump never breaks this.
    let want = format!("kern {}", env!("CARGO_PKG_VERSION"));
    assert!(s.starts_with(&want), "want prefix {want:?}, got: {s}");
}

#[test]
fn help_lists_commands() {
    let out = kern().arg("--help").output().expect("run kern");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    for verb in [
        "box", "run", "pull", "compose", // core
        "rename", "update", "wait", "diff", "events", // container-lifecycle verbs
    ] {
        assert!(s.contains(verb), "help missing {verb}");
    }
}

/// The new lifecycle verbs reject bad invocation at the parse/resolution layer - no sandbox needed,
/// so this runs everywhere (unlike a real box start). Covers both the usage errors and the
/// "no such running box" path each verb shares.
#[test]
fn lifecycle_verbs_reject_bad_input() {
    let fails = |args: &[&str]| {
        let out = kern().args(args).output().expect("run kern");
        assert!(
            !out.status.success(),
            "expected failure for `kern {}`",
            args.join(" ")
        );
    };
    // Usage errors (missing/invalid args), all before any box work.
    fails(&["rename", "only-one-arg"]); // needs <old> <new>
    fails(&["wait"]); // needs at least one box
    fails(&["diff"]); // needs a box
    fails(&["update", "somebox"]); // needs at least one of --memory/--cpus/--pids-limit
    fails(&["update", "b", "--cpus", "-1"]); // invalid cpus
    fails(&["update", "b", "--pids-limit", "abc"]); // invalid pids
                                                    // "no such running box" resolution errors (kern keeps no stopped boxes).
    let ghost = "kern-smoke-no-such-box-zzz";
    fails(&["rename", ghost, "newname"]);
    fails(&["wait", ghost]);
    fails(&["diff", ghost]);
    fails(&["update", ghost, "--memory", "64m"]);
}

#[test]
fn bare_kern_shows_the_short_banner() {
    // Bare `kern` → the concise banner, not the full command dump.
    let out = kern().output().expect("run kern");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("kern box"), "banner should mention `kern box`");
    assert!(s.contains("--help"), "banner should point to --help");
    // The long OPTIONS-for-box reference belongs to `--help`, not the bare banner.
    assert!(!s.contains("--cpuset-cpus"), "bare banner must stay short");
}

#[test]
fn unknown_command_fails_cleanly() {
    let out = kern().arg("frobnicate").output().expect("run kern");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown command"));
}

#[test]
fn box_plan_prints_ordered_isolation_sequence() {
    let out = kern()
        .args(["box", "web", "--plan"])
        .output()
        .expect("run kern");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("isolation plan for box 'web'"), "got: {s}");
    // The mount-ordering invariant must be visible: mount, then pivot, then read-only.
    let mount = s.find("mount(").expect("mount step");
    let pivot = s.find("pivot(").expect("pivot step");
    let ro = s.find("remount_ro(").expect("remount step");
    assert!(mount < pivot && pivot < ro, "steps out of order:\n{s}");
}

#[test]
fn box_plan_rejects_a_traversing_name() {
    let out = kern()
        .args(["box", "../etc", "--plan"])
        .output()
        .expect("run kern");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid box name"));
}

/// `--show-config` is a DRY RUN of the real decision, so it must not disagree with the box it
/// describes. It reported `uid_range: false` for every `--image` box while the box itself mapped a
/// range, because the per-image rule was written once in the run path and not at all in the dry run.
/// The provenance is asserted too: a default kern chose is not the same thing as a request, and a
/// caller deciding whether to opt out needs to tell them apart from the output alone.
#[test]
fn show_config_reports_the_uid_range_the_box_will_actually_get() {
    let field = |args: &[&str], key: &str| -> String {
        let out = kern()
            .args(args)
            .arg("--show-config")
            .output()
            .expect("run kern");
        assert!(out.status.success(), "--show-config should succeed");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}: ")))
            .unwrap_or_else(|| panic!("no `{key}` line for {args:?}"))
            .trim()
            .to_string()
    };

    // An image box gets the range even though nothing on the command line asked for one.
    let img = ["box", "t", "--image", "alpine"];
    assert_eq!(field(&img, "uid_range"), "true");
    assert_eq!(field(&img, "uid_range_source"), "image-default");

    // Asking explicitly is reported as a request, so it is distinguishable from the default.
    let asked = ["box", "t", "--image", "alpine", "--uid-range"];
    assert_eq!(field(&asked, "uid_range"), "true");
    assert_eq!(field(&asked, "uid_range_source"), "request");

    // The opt-out is reachable from the hot path and is reported honestly.
    let off = ["box", "t", "--image", "alpine", "--no-uid-range"];
    assert_eq!(field(&off, "uid_range"), "false");
    assert_eq!(field(&off, "uid_range_source"), "-");

    // A rootfs box is untouched by the image default: it keeps the tighter single-uid map.
    let rootfs = ["box", "t", "--rootfs", "/tmp"];
    assert_eq!(field(&rootfs, "uid_range"), "false");
    assert_eq!(field(&rootfs, "uid_range_source"), "-");
}
