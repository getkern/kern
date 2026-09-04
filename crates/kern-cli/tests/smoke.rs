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
                                                    // `--pids-limit` floor: a box needs a slot for its own PID 1 plus the workload, so 1 (and 0) are
                                                    // refused at PARSE, by name - the reviewer's finding was that `1` reached the box's setup fork and
                                                    // surfaced only a generic "fork failed" that never mentioned the cap. `/tmp` exists, so the sole
                                                    // failure is the floor, and the message must name the flag.
    let fails_naming = |args: &[&str], needle: &str| {
        let out = kern().args(args).output().expect("run kern");
        assert!(
            !out.status.success(),
            "expected failure for `kern {}`",
            args.join(" ")
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains(needle),
            "stderr of `kern {}` must mention {needle:?}, got: {err}",
            args.join(" ")
        );
    };
    fails_naming(
        &[
            "box",
            "x",
            "--rootfs",
            "/tmp",
            "--pids-limit",
            "1",
            "--",
            "true",
        ],
        "pids-limit",
    );
    fails_naming(
        &[
            "box",
            "x",
            "--rootfs",
            "/tmp",
            "--pids-limit",
            "0",
            "--",
            "true",
        ],
        "pids-limit",
    );
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

/// `KERN_NO_SCOPE=1` drops kern's own DEFAULT memory cap, and has to say so.
///
/// A plain `kern run` is not uncapped: it re-execs into a transient systemd scope carrying
/// `MemoryMax=512M`, `MemorySwapMax=0` and `TasksMax=512`, so a workload over that ceiling is
/// OOM-killed and told why. The opt-out skips the scope, and the default goes with it. Both warnings
/// on that path used to be gated on the caller having ASKED for a cap, so the case where nothing was
/// typed ran uncapped in the caller's own cgroup and printed nothing at all.
///
/// SKIP-GRACEFUL, and the control is what decides it: if a plain `kern run` already warns, this host
/// has no delegation to lose and there is nothing here to assert. A skip that says why beats a
/// failure that blames the host.
#[test]
fn the_opt_out_that_drops_the_default_cap_says_so() {
    let plain = kern()
        .args(["run", "--", "/bin/true"])
        .output()
        .expect("run kern");
    let plain_err = String::from_utf8_lossy(&plain.stderr).to_string();
    if !plain.status.success() || !plain_err.is_empty() {
        eprintln!(
            "SKIP: a plain `kern run` is not silently capped on this host, so the default this test \
             is about does not exist here. stderr: {plain_err}"
        );
        return;
    }

    let dropped = kern()
        .env("KERN_NO_SCOPE", "1")
        .args(["run", "--", "/bin/true"])
        .output()
        .expect("run kern");
    let err = String::from_utf8_lossy(&dropped.stderr);
    assert!(
        err.contains("DEFAULT memory cap"),
        "KERN_NO_SCOPE removed the default cap and said nothing. stderr: {err}"
    );

    // The two ways to mean it, each of which must return the command to silence: saying the uncapped
    // run is intended, and an embedder whose channel is a machine one.
    for (k, v) in [("KERN_ALLOW_UNCAPPED", "1"), ("KERN_QUIET", "1")] {
        let quiet = kern()
            .env("KERN_NO_SCOPE", "1")
            .env(k, v)
            .args(["run", "--", "/bin/true"])
            .output()
            .expect("run kern");
        assert!(
            quiet.stderr.is_empty(),
            "{k} did not silence the notice. stderr: {}",
            String::from_utf8_lossy(&quiet.stderr)
        );
    }
}

/// A box killed by its own memory cap must SAY so, and this covers the reporting END TO END rather
/// than the helper underneath it.
///
/// WHY THIS EXISTS SEPARATELY from `the_oom_directory_is_resolved_from_a_pid_and_outlives_it`: that
/// one asserts the helper resolves a directory, and it stayed green when the CALLER was reverted to
/// the old `oom_kill_count()` walk that reads kern's own ancestors. Measured: with that exact
/// regression put back, all 1048 tests passed. A helper nobody is required to call is not covered.
///
/// SKIP-GRACEFUL, and the condition is read from the BOX rather than from this test's assumptions:
/// if a plain `kern run` is not capped here (no cgroup delegation, no systemd, a container), then the
/// cap cannot fire and there is nothing to report. `memory.max` inside the box answers that, and it
/// is the same question the feature depends on, so the skip cannot hide the defect.
#[test]
fn a_box_killed_by_its_memory_cap_says_why() {
    let cap = kern()
        .args(["run", "--", "sh", "-c",
               "cat /sys/fs/cgroup$(awk -F: '/^0::/{print $3}' /proc/self/cgroup)/memory.max 2>/dev/null"])
        .output()
        .expect("run kern");
    let cap = String::from_utf8_lossy(&cap.stdout).trim().to_string();
    if cap.is_empty() || cap == "max" {
        eprintln!("SKIP: no memory cap is in force here (memory.max = {cap:?}), so none can fire");
        return;
    }
    // Ask for more than the cap. `bytearray` touches every page, so the kernel has to back it.
    let out = kern()
        .args(["run", "--", "python3", "-c", "bytearray(900*1024*1024)"])
        .output()
        .expect("run kern");
    if out.status.code() != Some(137) {
        eprintln!(
            "SKIP: the workload was not SIGKILLed here (exit {:?}), so there is no kill to explain",
            out.status.code()
        );
        return;
    }
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("OOM killer"),
        "exit 137 with nothing said about why. stderr: {err:?}"
    );
    // And the message must stay honest about what it measured: a subtree, not the process.
    assert!(
        err.contains("cgroup"),
        "the message must say where the killer fired: {err:?}"
    );
}

/// The other half: a SIGKILL that is NOT the memory cap must not be reported as one. Without this,
/// a version that printed the OOM line on every 137 would pass the test above.
#[test]
fn a_sigkill_that_is_not_an_oom_is_not_reported_as_one() {
    let out = kern()
        .args(["run", "--", "sh", "-c", "kill -9 $$"])
        .output()
        .expect("run kern");
    if out.status.code() != Some(137) {
        eprintln!(
            "SKIP: the shell did not die of SIGKILL here (exit {:?})",
            out.status.code()
        );
        return;
    }
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("OOM killer"),
        "a self-inflicted SIGKILL was blamed on the memory cap: {err:?}"
    );
}

/// `kern box` killed by its own cap must say why, DETERMINISTICALLY, and this is the case that the
/// `kern run` test above cannot cover.
///
/// TWO DEFECTS SIT UNDER THIS. The first: the message only ever existed on the systemd-scope path, so a
/// host with no systemd printed nothing. The second, found when the first was fixed and it still
/// printed nothing: `apply_limits` put the SUPERVISOR inside the box's cgroup, which carries
/// `memory.oom.group = 1`, so the kernel killed the reporter along with the box. Measured on WSL2: with
/// a workload exiting 7 the reporting branch was reached, with the OOM it never was.
///
/// The supervisor now sits in a sibling leaf and the workload joins the capped cgroup itself, and the
/// verdict is latched right after the reap, while the box's own cgroup still exists: reading it later
/// finds the directory already removed by the guard, which was a third measured miss.
///
/// WHAT THIS TEST CANNOT DO, stated rather than left to be discovered: on a host WITH systemd it does
/// not catch the supervisor-placement defect. `prepare_delegated_scope` already moves the supervisor
/// out of the box's cgroup on the scope path, so putting it back inside `apply_limits` leaves this
/// green here. Verified by doing exactly that. The defect is only visible where there is no scope, so
/// this assertion is a guard against the message disappearing, and the placement itself was measured
/// on WSL2 by hand.
#[test]
fn a_box_killed_by_its_cap_says_why() {
    let probe = kern()
        .args(["box", "captest-probe", "--image", "alpine", "--memory", "128m", "--",
               "/bin/sh", "-c",
               "cat /sys/fs/cgroup$(awk -F: '/^0::/{print $3}' /proc/self/cgroup)/memory.max 2>/dev/null"])
        .output()
        .expect("run kern");
    let cap = String::from_utf8_lossy(&probe.stdout).trim().to_string();
    if cap.is_empty() || cap == "max" {
        eprintln!("SKIP: a box gets no memory cap here (memory.max = {cap:?}), so none can fire");
        return;
    }
    let out = kern()
        .args([
            "box",
            "captest-oom",
            "--image",
            "python:3.12-slim",
            "--memory",
            "128m",
            "--",
            "python3",
            "-c",
            "bytearray(400*1024*1024)",
        ])
        .output()
        .expect("run kern");
    if out.status.code() != Some(137) {
        eprintln!(
            "SKIP: the box was not SIGKILLed here (exit {:?})",
            out.status.code()
        );
        return;
    }
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("OOM killer"),
        "exit 137 with nothing said about why: {err:?}"
    );
    assert!(
        err.contains("memory cap"),
        "the message must name the cap: {err:?}"
    );
}

/// The other half, on the box path: a SIGKILL that is not the cap must not be blamed on it. A version
/// that latched unconditionally, or printed on every 137, would pass the test above and fail this one.
#[test]
fn a_box_sigkilled_by_itself_is_not_blamed_on_the_cap() {
    let out = kern()
        .args([
            "box",
            "captest-kill",
            "--image",
            "alpine",
            "--",
            "/bin/sh",
            "-c",
            "kill -9 $$",
        ])
        .output()
        .expect("run kern");
    if out.status.code() != Some(137) {
        eprintln!(
            "SKIP: the shell did not die of SIGKILL here (exit {:?})",
            out.status.code()
        );
        return;
    }
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("OOM killer"),
        "a self-inflicted SIGKILL was blamed on the cap: {err:?}"
    );
}
