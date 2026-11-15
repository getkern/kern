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
    // Version-agnostic: assert the binary reports the version it was BUILT with, so a bump never
    // breaks this. Not `CARGO_PKG_VERSION`: since the version is derived at build time (the tag on a
    // release, `git describe` from source) that constant is `0.0.0` on every developer machine while
    // the binary prints something else, and this test would fail for everyone but CI.
    let want = format!("kern {}", kern_common::VERSION);
    assert!(s.starts_with(&want), "want prefix {want:?}, got: {s}");
    // The whole point of the change: a build from source must not answer `0.0.0`, because two builds
    // that both say `0.0.0` cannot be told apart, and that is how a fix and its predecessor got
    // compared as if they were one program. A release build says the tag, which is never `0.0.0`.
    //
    // SKIPPED, not failed, where git cannot answer: `0.0.0` is then the DELIBERATE fallback (a source
    // tarball, a vendored build), so asserting against it would be a false red about a designed
    // behaviour. The skip prints its reason, so a silently-skipped check cannot masquerade as a pass.
    if std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .is_ok_and(|o| o.status.success())
    {
        assert_ne!(
            kern_common::VERSION,
            "0.0.0",
            "in a git checkout the binary must be able to say which build it is; \
             `git describe` did not reach it"
        );
    } else {
        eprintln!("SKIP: not a git checkout, so `0.0.0` is the intended fallback here");
    }
}

/// The EAGAIN hint asserted from a REAL failure, not from a rendering this test built itself.
///
/// The unit test beside `Error::hint` constructs the message with `from_raw_os_error` and checks the
/// matcher against it. That proves the matcher matches a string this repo wrote. It does NOT prove
/// that the string a live failure produces still contains the key: an errno carried through anything
/// that is not an `io::Error` loses the `(os error 11)` suffix, the match fails, and the hint
/// silently reverts to the misleading one while the unit test stays green. A later pass named
/// that gap; this closes it, and it costs one `setrlimit`.
///
/// `RLIMIT_NPROC` is lowered in the CHILD only, between fork and exec, so the test runner's own
/// limit is untouched. `--rootfs /tmp` rather than an image, so no pull and no cache dependency.
#[test]
fn eagain_hint_survives_a_real_failure_not_a_constructed_one() {
    use std::os::unix::process::CommandExt;
    let mut cmd = kern();
    cmd.args(["box", "hintprobe", "--rootfs", "/tmp", "--", "/bin/true"]);
    // SAFETY: async-signal-safe between fork and exec. `setrlimit` is on the permitted list and
    // nothing here allocates or takes a lock.
    unsafe {
        cmd.pre_exec(|| {
            let r = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            if libc::setrlimit(libc::RLIMIT_NPROC, &r) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let Ok(out) = cmd.output() else {
        eprintln!("SKIP: could not spawn kern under a lowered RLIMIT_NPROC");
        return;
    };
    let err = String::from_utf8_lossy(&out.stderr);
    // SKIP, not FAIL, where the host did not produce the failure we are asking about: a kernel that
    // does not refuse the fork here has nothing to say about the hint, and asserting anyway would be
    // a red about the environment. The skip prints its reason so it cannot pass for a pass.
    if !err.contains("os error 11") {
        eprintln!("SKIP: this host did not refuse the fork with EAGAIN; stderr was: {err}");
        return;
    }
    assert!(
        err.contains("ulimit -u"),
        "a real EAGAIN failure did not get the process-limit hint: {err}"
    );
    assert!(
        !err.contains("user namespaces"),
        "a real EAGAIN failure was still pointed at user namespaces: {err}"
    );
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
                                                    // refused at PARSE, by name - the test's finding was that `1` reached the box's setup fork and
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

/// A PER-VERB `--help` MAY ONLY CONTAIN LINES THAT BELONG TO THAT VERB.
///
/// `kern <verb> --help` is a filtered view of the one reference `kern --help` prints, and the filter
/// decided what a line was by reading its first word before looking at its indentation. A
/// continuation line in the reference begins with a word like any other, so the tail of
/// `network create` - which starts "compose file names with `external: true`" - was taken for a
/// `compose` signature and printed under `compose ps`, dragging the line after it in as its own
/// continuation. Two lines of text about networks, in the help for a different verb, reading as
/// though they described the one above them.
///
/// Both directions are asserted, because the obvious fix for the first breaks the second: the
/// continuation rule exists so that `up`'s five explanatory lines reach `kern up --help` at all.
#[test]
fn a_per_verb_help_carries_no_line_from_another_verb() {
    let verb_help = |verb: &str| -> String {
        let out = kern()
            .args([verb, "--help"])
            .output()
            .unwrap_or_else(|e| panic!("run kern {verb} --help: {e}"));
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    let compose = verb_help("compose");
    assert!(
        compose.contains("compose <file> ps"),
        "the compose help lost its own signatures:\n{compose}"
    );
    assert!(
        !compose.contains("external: true"),
        "a `network create` continuation leaked into the compose help:\n{compose}"
    );

    // The other direction. `up` explains itself on the lines UNDER its signature, and those are the
    // reason the filter follows continuations at all; a filter that dropped them would pass the
    // assertion above while making the help useless.
    let up = verb_help("up");
    assert!(
        up.contains("DEFAULT: a namespace per service"),
        "the up help lost the continuation lines that explain it:\n{up}"
    );
    assert!(
        up.matches("                    ").count() >= 5,
        "fewer continuation lines than the reference gives `up`:\n{up}"
    );
}

/// THE VRAM CAVEAT BELONGS TO THE GRANT AND NOT TO THE HOST.
///
/// It used to be a `!` row in `kern doctor`, which fires on every host that has a DRM node at all:
/// a Raspberry Pi's `v3d`, a Jetson's `nv_platform`, WSL's passthrough node. Four lines of
/// MIG/SR-IOV vocabulary were spent there on readers who were not handing a GPU to anybody, and a
/// warning true of every host teaches people to skim the list that also carries "unprivileged userns
/// restricted". Both halves are asserted here: present on the GPU grant, absent on the other one.
#[test]
fn the_vram_caveat_prints_on_a_gpu_grant_and_not_on_another_device() {
    const CAVEAT: &str = "NOT a boundary against malicious code";
    let dir = std::env::temp_dir().join(format!("kern-gpuplan-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let cfg = dir.join("kern.toml");
    std::fs::write(
        &cfg,
        "[[vgpio]]\nname = \"gpu\"\nbackend = \"host\"\ndisplay = [\"/dev/dri/renderD128\"]\n\n\
         [[vgpio]]\nname = \"other\"\nbackend = \"host\"\nextra = [\"/dev/null\"]\n",
    )
    .expect("write config");
    let plan = |profile: &str| -> String {
        let out = kern()
            .args(["box", "p", "--config"])
            .arg(&cfg)
            .args([profile, "--plan"])
            .output()
            .expect("run kern");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let gpu = plan("vgpio:gpu");
    let other = plan("vgpio:other");
    let _ = std::fs::remove_dir_all(&dir);
    // Skipped rather than failed when the host has no render node: the grant cannot resolve there,
    // and a test that passes because the subject never ran is the one shape worth refusing.
    if gpu.contains("bind /dev/dri/renderD128") {
        assert!(gpu.contains(CAVEAT), "no caveat on a granted GPU:\n{gpu}");
    }
    assert!(
        gpu.contains(CAVEAT) || !std::path::Path::new("/dev/dri/renderD128").exists(),
        "a host with a render node printed no caveat:\n{gpu}"
    );
    assert!(
        !other.contains(CAVEAT),
        "the caveat leaked onto a non-GPU grant:\n{other}"
    );
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

/// `--show-config` PRINTS WHAT A PROFILE GRANTS, not only the cgroup numbers it produces.
///
/// The SDKs fingerprint a reusable box from this output: a resident sandbox and a prewarmed box are
/// both handed to a later call only when the fingerprint matches. It used to print what a `vcpu:`
/// profile yields (memory, cpus) and NOTHING a `vgpio:` or `vdisk:` profile yields - the device list
/// was resolved a few lines before the call and dropped. MEASURED: `uart = ["/dev/ttyS0"]` and
/// `uart = ["/dev/ttyS0", "/dev/ttyS1"]` under one profile name printed byte-identical output, so a
/// box built with one device grant was reused for a caller whose config granted another. `vgpio:` is
/// the only way to give a box a hardware device.
///
/// `/dev/null` and `/dev/zero` and not a serial port, because a CI runner has no `ttyS*` and a
/// device that does not exist is (correctly) dropped from the grant before it is printed.
#[test]
fn show_config_prints_the_devices_and_disks_a_profile_grants() {
    let home = std::env::temp_dir().join(format!("kern-showgrants-{}", std::process::id()));
    let cfg_dir = home.join("kern");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    let toml = cfg_dir.join("kern.toml");
    let show = |token: &str| -> String {
        let out = kern()
            .env("XDG_CONFIG_HOME", &home)
            .env_remove("KERN_CONFIG")
            .args([
                "box",
                "t",
                "--rootfs",
                "/tmp",
                "--show-config",
                token,
                "--",
                "/bin/true",
            ])
            .output()
            .expect("run kern");
        assert!(
            out.status.success(),
            "--show-config should succeed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let line = |out: &str, key: &str| -> String {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}: ")))
            .unwrap_or_else(|| panic!("no `{key}` line in:\n{out}"))
            .trim()
            .to_string()
    };

    std::fs::write(
        &toml,
        "[[vgpio]]\nname = \"t\"\nbackend = \"host\"\nextra = [\"/dev/null\"]\n",
    )
    .expect("write");
    let one = show("vgpio:t");
    std::fs::write(
        &toml,
        "[[vgpio]]\nname = \"t\"\nbackend = \"host\"\nextra = [\"/dev/null\", \"/dev/zero\"]\n",
    )
    .expect("write");
    let two = show("vgpio:t");
    assert_eq!(line(&one, "devices"), "/dev/null");
    assert_eq!(line(&two, "devices"), "/dev/null,/dev/zero");
    assert_ne!(
        one, two,
        "a different device grant must be a different resolved configuration"
    );

    // THE SAME SET IN ANOTHER ORDER IS THE SAME GRANT, so the line is canonical. Without this a
    // reordered list in kern.toml would read as a different box and every reuse would be refused.
    std::fs::write(
        &toml,
        "[[vgpio]]\nname = \"t\"\nbackend = \"host\"\nextra = [\"/dev/zero\", \"/dev/null\"]\n",
    )
    .expect("write");
    assert_eq!(
        show("vgpio:t"),
        two,
        "reordering a grant list must not change the output"
    );

    // A disk's size is part of what the box is given.
    std::fs::write(
        &toml,
        "[[vdisk]]\nname = \"s\"\nbackend = \"ram\"\nsize = \"64m\"\n",
    )
    .expect("w");
    let small = show("vdisk:s");
    std::fs::write(
        &toml,
        "[[vdisk]]\nname = \"s\"\nbackend = \"ram\"\nsize = \"8g\"\n",
    )
    .expect("w");
    let big = show("vdisk:s");
    assert!(line(&small, "vdisks").contains("size=67108864"), "{small}");
    assert!(line(&big, "vdisks").contains("size=8589934592"), "{big}");

    let _ = std::fs::remove_dir_all(&home);
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

    // DROPPING `ALL` DROPS THE DEFAULT WITH IT, because the capability the range serves is already
    // refused: measured inside a box, `chown` to another uid fails under `--cap-drop ALL` whether
    // the range is mapped or not. Worth 937 us of the 3956 on this path. The dry run has to say so,
    // or a caller reading it would opt out of something they no longer have.
    // ⛔ AND THE ANSWER DEPENDS ON THIS CALLER'S GROUPS, which is why the two constants that stood
    // here were wrong from 08:40 on 2026-11-12, when `range_buys_nothing_for` gained its
    // `inherits_groups` term: dropping the range also drops the box's ability to CLEAR the
    // supplementary groups it inherited, so the range is kept whenever there are any. On the host
    // this was found on the caller carries 14 groups and the field reads `true`; on a user with
    // none it reads `false`. A constant here asserts one host and fails every other one, and it
    // stayed red for seven hours because the only target run all day was `--bin kern`: an
    // integration target nobody runs is not a green.
    let primary = String::from_utf8(
        std::process::Command::new("id")
            .arg("-g")
            .output()
            .expect("id -g")
            .stdout,
    )
    .expect("utf8");
    let all = String::from_utf8(
        std::process::Command::new("id")
            .arg("-G")
            .output()
            .expect("id -G")
            .stdout,
    )
    .expect("utf8");
    let inherits_groups = all
        .split_whitespace()
        .any(|g| g != primary.trim() && !g.is_empty());

    let dropped = ["box", "t", "--image", "alpine", "--cap-drop", "ALL"];
    let want = if inherits_groups { "true" } else { "false" };
    assert_eq!(
        field(&dropped, "uid_range"),
        want,
        "with {} supplementary group(s) the range must be {want}",
        all.split_whitespace().count()
    );
    // THE SOURCE NAMES THE ORIGIN, NOT THE SURVIVAL. Measured: with the range kept it still reads
    // `image-default`, because that is where it came from; the groups are why the `--cap-drop ALL`
    // did not take it away. The two are different questions and this field answers the first, so
    // a reader who wants the second reads the groups. A fourth value here would be a vocabulary
    // change for whoever parses this output, which is not a decision to make from a test.
    assert_eq!(
        field(&dropped, "uid_range_source"),
        if inherits_groups {
            "image-default"
        } else {
            "-"
        },
        "the source names where the range came from"
    );

    // `all` is the same flag: the comparison is case-insensitive, as it is where the profile below
    // promotes itself. `CAP_ALL` is NOT tested, because `caps::resolve` refuses that spelling by
    // name, which is why the rule does not strip the prefix.
    // THE SAME HOST CONDITION AS ABOVE: what this row pins is that the spelling does not matter,
    // so it compares `all` against `ALL` rather than against a constant that only holds for a
    // caller with no supplementary groups.
    let lower = ["box", "t", "--image", "alpine", "--cap-drop", "all"];
    assert_eq!(
        field(&lower, "uid_range"),
        field(&dropped, "uid_range"),
        "the lower-case spelling must decide exactly as the upper-case one did"
    );

    // ANY `--cap-add` PUTS IT BACK, and this is the case that decides the rule rather than
    // illustrating it: measured, `--cap-drop ALL --cap-add CHOWN` chowns successfully WITH the range
    // and fails without it. A capability handed back can use the range, so any add at all cancels
    // the skip - the conservative reading, since being wrong here is a silent failure in an
    // entrypoint while being conservative costs under a millisecond.
    let added = [
        "box",
        "t",
        "--image",
        "alpine",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CHOWN",
    ];
    assert_eq!(field(&added, "uid_range"), "true");
    assert_eq!(field(&added, "uid_range_source"), "image-default");

    // A NARROWER DROP IS NOT `ALL`. Dropping one capability leaves the rest, so the range still
    // works and the default stands.
    let narrow = ["box", "t", "--image", "alpine", "--cap-drop", "NET_ADMIN"];
    assert_eq!(field(&narrow, "uid_range"), "true");

    // AN EXPLICIT REQUEST OUTRANKS THE SKIP, in both of its spellings. These are the caller asking
    // in as many words, and the skip is only ever a default being dropped.
    let asked_anyway = [
        "box",
        "t",
        "--image",
        "alpine",
        "--cap-drop",
        "ALL",
        "--uid-range",
    ];
    assert_eq!(field(&asked_anyway, "uid_range"), "true");
    assert_eq!(field(&asked_anyway, "uid_range_source"), "request");
    let as_user = [
        "box",
        "t",
        "--image",
        "alpine",
        "--cap-drop",
        "ALL",
        "--user",
        "5000",
    ];
    assert_eq!(field(&as_user, "uid_range"), "true");

    // THE PROFILE AND THE FLAG ARE PINNED TOGETHER. `--security-profile=untrusted` promotes itself
    // to `cap-drop ALL` inside `start`, and the rule spells that promotion out a second time because
    // it runs before it. If the profile ever stopped implying the drop, this is what would catch it:
    // the two must answer identically, including when an add cancels them.
    let profile = [
        "box",
        "t",
        "--image",
        "alpine",
        "--security-profile",
        "untrusted",
    ];
    // THE FIRST ROW IS THE POINT and it is host-independent: the profile must decide exactly as the
    // flag does. The second row used to repeat it as a constant, which is the same host assumption
    // the rows above carried, so it says what the flag said instead.
    assert_eq!(field(&profile, "uid_range"), field(&dropped, "uid_range"));
    let profile_added = [
        "box",
        "t",
        "--image",
        "alpine",
        "--security-profile",
        "untrusted",
        "--cap-add",
        "CHOWN",
    ];
    assert_eq!(field(&profile_added, "uid_range"), "true");
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
///
/// EXIT 137 IS NOT THE QUESTION, and believing it was made this test fail a release on a runner that
/// had done nothing wrong. 137 means the workload was SIGKILLed by SOMEBODY - the box's own cgroup
/// hitting its ceiling, or the HOST's OOM killer picking a victim while a shared runner allocates
/// 900 MB alongside other jobs, or anything else with a signal. kern already draws that line
/// deliberately (`start.rs` writes an OOM-outcome byte that is 1 only when "the kernel's OOM killer
/// fired against this box's OWN cgroup") and correctly says NOTHING when the kill came from
/// elsewhere. So the old assertion demanded a sentence whose absence was the right answer, and it
/// read exit 137 with an empty stderr as a defect in the message. MEASURED: green 12/12 here in both
/// host shapes, red once on a runner, on a commit that changed four version strings and no Rust.
///
/// THE QUESTION IS ASKED OF THE KERNEL, not of kern's stderr, which is the channel under test: the
/// `oom_kill` counter in `memory.events` of the slice the run's cgroup lives under, read before and
/// after. It is hierarchical, so it counts a kill in any descendant. No increment means no cgroup OOM
/// happened, and then there is nothing for kern to have explained.
#[test]
fn a_box_killed_by_its_memory_cap_says_why() {
    // The box's own cgroup path AND its ceiling, from one run: the path is what locates the counter,
    // and asking for it separately would name a different, already-gone per-run cgroup.
    let probe = kern()
        .args([
            "run",
            "--",
            "sh",
            "-c",
            "cg=$(awk -F: '/^0::/{print $3}' /proc/self/cgroup); echo $cg; \
                cat /sys/fs/cgroup$cg/memory.max 2>/dev/null",
        ])
        .output()
        .expect("run kern");
    let probe = String::from_utf8_lossy(&probe.stdout);
    let mut lines = probe.lines();
    let cg = lines.next().unwrap_or("").trim().to_string();
    let cap = lines.next().unwrap_or("").trim().to_string();
    if cap.is_empty() || cap == "max" {
        eprintln!("SKIP: no memory cap is in force here (memory.max = {cap:?}), so none can fire");
        return;
    }
    // The PARENT of the per-run cgroup: that one is created and removed per run, its parent is where
    // every run lands and where a hierarchical `oom_kill` accumulates.
    let slice = match cg.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => format!("/sys/fs/cgroup{parent}/memory.events"),
        _ => String::new(),
    };
    let kills = |p: &str| -> Option<u64> {
        std::fs::read_to_string(p).ok()?.lines().find_map(|l| {
            l.strip_prefix("oom_kill ")
                .and_then(|v| v.trim().parse().ok())
        })
    };
    let before = kills(&slice);

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
    // WAS IT THIS CGROUP'S OOM? Only then is there a message to demand. Unreadable counters skip too:
    // a test that cannot ask the kernel must not convict kern on the strength of an exit code.
    let seen = kills(&slice);
    match (before, seen) {
        (Some(b), Some(a)) if a > b => {}
        (Some(b), Some(a)) => {
            eprintln!(
                "SKIP: SIGKILLed but this cgroup recorded no OOM ({} -> {} in {slice}), so the kill \
                 came from outside the box and kern is right to say nothing",
                b, a
            );
            return;
        }
        _ => {
            eprintln!("SKIP: cannot read {slice}, so there is no independent judge of the kill");
            return;
        }
    }
    let err = String::from_utf8_lossy(&out.stderr);
    // THE NUMBERS GO IN THE MESSAGE, because the first version of this assertion said only "nothing
    // said about why" and a CI failure was then indistinguishable between two very different causes:
    // kern failing to report a real cgroup OOM, and kern's own before/after pair disagreeing with this
    // one (the file it reads from documents that exact intermittency, "two unrelated counters").
    // A red that cannot name its own cause costs the next reader the whole investigation.
    assert!(
        err.contains("OOM killer"),
        "exit 137, this cgroup DID record an OOM ({before:?} -> {seen:?} in {slice}), and kern said \
         nothing about why. stderr: {err:?}"
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

/// Did this host refuse to BUILD a box at all, as opposed to running one and disagreeing with us?
///
/// THE DISTINCTION IS THE WHOLE POINT, and getting it wrong has cost this project in both directions.
/// A test that skips whenever its expectation is unmet is a permanent no-op (the test below used to be
/// one). A test that asserts unconditionally reports the developer's machine: the GitHub runner allows
/// the user namespace and refuses its rootless uid map (Ubuntu 23.10+ ships
/// `kernel.apparmor_restrict_unprivileged_userns=1`), so NO box starts there and a hard assertion about
/// a box's exit code fails for a reason that has nothing to do with what is being tested. Measured: CI
/// red on x86 and aarch64 within minutes of the unconditional version.
///
/// So the skip keys on kern's OWN setup diagnostic, which is printed by the parent before any box
/// exists, and never on the value under test.
fn host_cannot_build_a_box(stderr: &str) -> bool {
    stderr.contains("unprivileged user namespaces are restricted")
        || stderr.contains("sandbox setup failed")
        || stderr.contains("the box could not be BUILT")
}

/// The guard above, against the message the runner ACTUALLY produced.
///
/// The fixture is copied verbatim from the failing x86 job (run 34689720520), because a guard written
/// from memory of what the runner says is a guard that stops matching the day the wording moves, and
/// the failure mode is silent: the test stops skipping and starts asserting on a host that cannot
/// answer. The positive control is the other half: an ordinary box failure must NOT be read as a host
/// that cannot build one, or every real defect would skip itself.
#[test]
fn the_host_capability_guard_matches_what_the_runner_prints() {
    let from_ci = "kern: sandbox setup failed: unprivileged user namespaces are restricted here - \
                   this host allows the namespace and refuses its rootless uid map (Ubuntu 23.10+ \
                   ships kernel.apparmor_restrict_unprivileged_userns=1), so no box can start. \
                   `kern doctor` prints the AppArmor profile to install\nhint: the box could not be \
                   BUILT, which is a host capability rather than a wrong command";
    assert!(host_cannot_build_a_box(from_ci));
    // POSITIVE CONTROL: the failures a test is SUPPOSED to catch must not be mistaken for a host that
    // cannot run one.
    assert!(!host_cannot_build_a_box(""));
    assert!(!host_cannot_build_a_box(
        "kern: the workload was killed by the kernel's OOM killer against this box's own memory cap."
    ));
    assert!(!host_cannot_build_a_box(
        "kern: cannot start '/x/bad.bin' in box: Exec format error (os error 8)"
    ));
}

/// The other half, on the box path: a 137 that is not the cap must not be blamed on it. A version that
/// latched unconditionally, or printed on every 137, would pass the test above and fail this one.
///
/// IT USED TO SKIP ON EVERY HOST, which is a green that guards nothing. The workload was
/// `sh -c "kill -9 $$"`, and the box's shell is pid 1 of its own pid namespace: the kernel does not
/// deliver an unhandled SIGKILL to a namespace's init from inside it, so the shell survived and exited 0
/// and the assertion below was never reached. Measured: `kern run` (no pid namespace of its own for the
/// shell) exits 137 there, `kern box` exits 0 - which is why the `kern run` twin of this test did run.
///
/// A workload CHOOSING exit 137 reaches the same branch (kern only sees the code) and is the sharper
/// case anyway: 137 without a signal behind it is exactly the ambiguity the message must not guess at.
#[test]
fn a_box_that_exits_137_without_an_oom_is_not_blamed_on_the_cap() {
    let out = kern()
        .args([
            "box",
            "captest-kill",
            "--image",
            "alpine",
            "--memory",
            "128m",
            "--",
            "/bin/sh",
            "-c",
            "exit 137",
        ])
        .output()
        .expect("run kern");
    let err = String::from_utf8_lossy(&out.stderr);
    if host_cannot_build_a_box(&err) {
        eprintln!("SKIP: this host cannot build a box, so it has no 137 to explain ({err})");
        return;
    }
    assert_eq!(
        out.status.code(),
        Some(137),
        "the box did not propagate the chosen exit code; stderr: {err:?}"
    );
    assert!(
        !err.contains("OOM killer"),
        "an exit 137 with no OOM behind it was blamed on the cap: {err:?}"
    );
}

/// Run `kern box` with a pipe on `KERN_STARTED_FD` and return `(exit code, the bytes it wrote)`.
///
/// The pipe is made with `libc::pipe` rather than `std::process::Command`'s own plumbing because kern
/// takes the fd NUMBER from the environment: a descriptor created without `O_CLOEXEC` is inherited with
/// its number intact, so no `pre_exec` is needed. The parent closes the write end before reading, or the
/// read would never see EOF and this test would hang instead of failing.
fn started_bytes(args: &[&str]) -> (Option<i32>, Vec<u8>) {
    let (code, sig, _) = started_bytes_and_stderr(args);
    (code, sig)
}

/// [`started_bytes`], and what kern said on stderr, from ONE run.
fn started_bytes_and_stderr(args: &[&str]) -> (Option<i32>, Vec<u8>, String) {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (r, w) = (fds[0], fds[1]);
    let child = kern()
        .args(args)
        .env("KERN_STARTED_FD", w.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn kern");
    assert_eq!(unsafe { libc::close(w) }, 0, "close the parent's write end");
    let mut got = Vec::new();
    let mut buf = [0u8; 8];
    loop {
        let n = unsafe { libc::read(r, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        got.extend_from_slice(&buf[..n as usize]);
    }
    unsafe { libc::close(r) };
    let out = child.wait_with_output().expect("wait for kern");
    (
        out.status.code(),
        got,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The `KERN_STARTED_FD` signal is FOUR bytes: the OOM verdict is the third, the workload's SIGNAL the
/// fourth.
///
/// WHY THE THIRD BYTE EXISTS. An SDK had only the exit code and the enforcement byte, and 137 plus "the
/// cap was enforced" is also what `kern stop` of a capped box looks like. Measured through the Python
/// binding: stopping a box during a cell was reported as `fault.type == "oom"`, which sends an agent to
/// retry with more memory a kill that had nothing to do with memory. kern already knows the answer - it
/// reads the box's own `memory.events` for the stderr sentence - and this puts that same observation on
/// a channel the workload cannot write, where stderr is a stream the workload shares.
///
/// WHY THE FOURTH BYTE, and two later passes found it from opposite directions: kern propagates the
/// workload's status as `128 + N`, so a workload the kernel SIGKILLed and one that called `exit(137)` are
/// BOTH a normal exit 137 of kern. MEASURED through the Python binding: `sys.exit(137)` was reported
/// `fault = killed` (an external kill that never happened) and `sys.exit(159)` was reported
/// `escape_blocked`, a security event a cell could fabricate in one line. The code is the right thing to
/// propagate and the wrong thing to classify from.
///
/// THE DISCRIMINATOR IS THE PAIR, not either run alone: a byte that were always 1 would pass the OOM
/// half, and one that were always 0 would pass the external-kill half. Both exit 137.
#[test]
fn the_started_signal_carries_the_oom_verdict_and_the_workload_signal() {
    let (code, sig) = started_bytes(&[
        "box",
        "sigtest-ok",
        "--image",
        "alpine",
        "--memory",
        "128m",
        "--",
        "/bin/true",
    ]);
    if code != Some(0) || sig.len() < 3 {
        eprintln!(
            "SKIP: no box with a started signal here (exit {code:?}, {} bytes)",
            sig.len()
        );
        return;
    }
    assert_eq!(
        sig[0], 1,
        "byte 0 must stay the unchanged `box started` signal: {sig:?}"
    );
    assert_eq!(
        sig[2], 0,
        "a box that exited cleanly was reported OOM-killed: {sig:?}"
    );
    let enforced = sig[1] == 1;

    // A 137 THAT IS NOT AN OOM, and it is a workload CHOOSING that exit code rather than a signal:
    // `kill -9 $$` cannot be used here, because the box's shell is pid 1 of its own pid namespace and
    // the kernel does not deliver an unhandled SIGKILL to a namespace's init from inside it - measured,
    // the shell survives and exits 0, which is also why the neighbouring test above only ever SKIPS.
    // A chosen 137 is the sharper case anyway: it is exactly the ambiguity the byte exists to remove.
    let (code, sig) = started_bytes(&[
        "box",
        "sigtest-kill",
        "--image",
        "alpine",
        "--memory",
        "128m",
        "--",
        "/bin/sh",
        "-c",
        "exit 137",
    ]);
    assert_eq!(
        code,
        Some(137),
        "the box did not propagate the chosen exit code"
    );
    assert_eq!(
        sig.len(),
        4,
        "a started box must write all four bytes: {sig:?}"
    );
    assert_eq!(
        sig[2], 0,
        "an exit 137 with no OOM behind it was reported as an OOM: {sig:?}"
    );
    // THE ONE A LATER PASS FOUND: the same exit code as the OOM below, and nothing signalled this
    // workload. Without this byte a cell could fabricate `fault = killed` with one `exit 137`.
    assert_eq!(
        sig[3], 0,
        "a workload that CHOSE exit 137 was reported as killed by a signal: {sig:?}"
    );

    if !enforced {
        eprintln!(
            "SKIP: the cap is not enforced here (byte 1 = {}), so no OOM can fire",
            sig[1]
        );
        return;
    }
    let (code, sig) = started_bytes(&[
        "box",
        "sigtest-oom",
        "--image",
        "python:3.12-slim",
        "--memory",
        "128m",
        "--",
        "python3",
        "-c",
        "bytearray(400*1024*1024)",
    ]);
    if code != Some(137) {
        eprintln!("SKIP: the box was not SIGKILLed here (exit {code:?})");
        return;
    }
    assert_eq!(
        sig.len(),
        4,
        "a started box must write all four bytes: {sig:?}"
    );
    assert_eq!(
        sig[2], 1,
        "a box taken by the OOM killer against its own cap reported no OOM: {sig:?}"
    );
    // The pair that makes the fourth byte load-bearing: the SAME exit 137 as the chosen one above, with
    // a signal behind it this time.
    assert_eq!(
        sig[3], 9,
        "a workload the kernel SIGKILLed must be reported as signalled, or it cannot be told from one \
         that chose 137: {sig:?}"
    );
}

/// `kern exec` puts the OOM verdict on `KERN_STARTED_FD` too, for a command killed WITH ITS BOX.
///
/// `memory.oom.group=1` makes an OOM take the whole box, so a command run with `kern exec` dies with
/// it. The exec path attributed that kill and printed a sentence, but wrote nothing to the caller's
/// descriptor, so an SDK could only read the 137: MEASURED, a resident sandbox reported
/// `bytearray(400 << 20)` under a 128 MiB cap as `killed`, where a fresh box says `oom`.
///
/// The control comes FIRST, because the OOM takes the box with it: an exec that CHOOSES exit 137 must
/// read as an exit with no signal and no OOM, or every 137 would be a kill.
#[test]
fn an_exec_killed_with_its_box_by_the_oom_killer_says_so_on_the_started_signal() {
    let name = format!("execoom-{}", std::process::id());
    let up = kern()
        .args([
            "box",
            &name,
            "-d",
            "--init",
            "--memory",
            "128m",
            "--image",
            "python:3.12-slim",
            "--",
            "sleep",
            "120",
        ])
        .output()
        .expect("run kern");
    if !up.status.success() {
        eprintln!(
            "SKIP: no detached box here: {}",
            String::from_utf8_lossy(&up.stderr)
        );
        return;
    }
    let (code, sig) = started_bytes(&["exec", &name, "--", "sh", "-c", "exit 137"]);
    assert_eq!(
        code,
        Some(137),
        "the exec did not propagate the chosen code"
    );
    assert_eq!(
        sig,
        vec![1, 0, 0, 0],
        "an exec that CHOSE exit 137 must read as ran, no OOM, no signal"
    );
    let (code, sig) = started_bytes(&[
        "exec",
        &name,
        "--",
        "python3",
        "-c",
        "bytearray(400*1024*1024)",
    ]);
    let _ = kern().args(["stop", &name]).output();
    if code != Some(137) {
        eprintln!("SKIP: the exec was not SIGKILLed here (exit {code:?}): the cap is not enforced");
        return;
    }
    assert_eq!(
        sig,
        vec![1, 0, 1, 9],
        "an exec killed with its box by the OOM killer must say so, in `kern box`'s byte order"
    );
}

/// A `kern exec` that REFUSES writes nothing on the started signal, because nothing started.
///
/// The refusal is the child's `_exit(126)` before it runs the command (here: a box already at its
/// `--pids-limit`, where the exec could only run outside the box's caps). To the parent that is the same
/// wait status as a command that ran and exited 126, and the CLI wrote `[1, 0, 0, 0]` for it. MEASURED
/// from an ssh session, where every exec refuses: an SDK reported the sandbox's refusal as the code's
/// own exit 126 with no fault. The control, an exec that runs, is the chosen-137 case above.
#[test]
fn an_exec_that_refuses_writes_nothing_on_the_started_signal() {
    let name = format!("execrefuse-{}", std::process::id());
    let up = kern()
        .args([
            "box",
            &name,
            "-d",
            "--pids-limit",
            "2",
            "--image",
            "alpine:latest",
            "--",
            "sh",
            "-c",
            "sleep 120 & wait",
        ])
        .output()
        .expect("run kern");
    if !up.status.success() {
        eprintln!(
            "SKIP: no detached box here: {}",
            String::from_utf8_lossy(&up.stderr)
        );
        return;
    }
    let (code, sig) = started_bytes(&["exec", &name, "--", "true"]);
    let _ = kern().args(["stop", &name]).output();
    if code != Some(126) {
        eprintln!("SKIP: this host did not refuse the exec at the pids limit (exit {code:?})");
        return;
    }
    assert!(
        sig.is_empty(),
        "a refused exec wrote {sig:?} on KERN_STARTED_FD: an SDK reads that as a command that ran"
    );
}

/// **`kern exec -u <user>` runs as that account of the BOX, resolved from the box's CURRENT files, and
/// never from the host's.**
///
/// Five things, on one box with a uid range:
///
/// - an account created INSIDE the box after it started (`adduser`) is found, with its uid, its
///   passwd group and its passwd home, because `docker exec --user` resolves against the
///   container's files as they are now;
/// - without `-u` the command is still box root, so the flag added a way out and changed no default;
/// - an unknown name is refused before anything runs: nothing on `KERN_STARTED_FD`, which an SDK
///   would read as a command that ran;
/// - a box that points its `/etc/passwd` at an absolute HOST path, where the host has a file
///   defining the name, gets a refusal: the link resolves inside the box, where nothing is there;
/// - a FIFO at `/etc/passwd` answers at once instead of waiting for a writer the box controls.
#[test]
fn exec_user_resolves_the_box_account_and_never_a_host_file() {
    let name = format!("execuser-{}", std::process::id());
    let up = kern()
        .args([
            "box",
            &name,
            "-d",
            "--image",
            "alpine:latest",
            "--",
            "sleep",
            "120",
        ])
        .output()
        .expect("run kern");
    if !up.status.success() {
        eprintln!(
            "SKIP: no detached box here: {}",
            String::from_utf8_lossy(&up.stderr)
        );
        return;
    }
    let exec = |args: &[&str]| {
        let mut argv = vec!["exec", name.as_str()];
        argv.extend_from_slice(args);
        kern().args(&argv).output().expect("run kern exec")
    };
    let text = |o: &std::process::Output| String::from_utf8_lossy(&o.stdout).trim().to_string();
    let map = exec(&["--", "cat", "/proc/self/uid_map"]);
    if text(&map).lines().count() < 2 {
        let _ = kern().args(["stop", &name]).output();
        eprintln!("SKIP: this host gives a box no uid range: {}", text(&map));
        return;
    }
    let made = exec(&[
        "--",
        "adduser",
        "-D",
        "-u",
        "4321",
        "-h",
        "/home/late",
        "late",
    ]);
    assert!(made.status.success(), "adduser in the box: {made:?}");
    // A group OUTSIDE the range (gid 70000 past a 65536-id map) and one inside it. `setgroups`
    // refuses a whole list for one unmapped gid, so `-u late` must get the mapped one and no warning.
    let grouped = exec(&[
        "--",
        "sh",
        "-c",
        "addgroup -g 70000 far && addgroup -g 4400 near && addgroup late far && addgroup late near",
    ]);
    assert!(grouped.status.success(), "addgroup in the box: {grouped:?}");
    let groups = exec(&["-u", "late", "--", "id", "-G"]);

    let late = exec(&[
        "-u",
        "late",
        "--",
        "sh",
        "-c",
        "echo $(id -u) $(id -g) $HOME",
    ]);
    let root = exec(&["--", "id", "-u"]);
    let (code, sig, ghost_said) =
        started_bytes_and_stderr(&["exec", &name, "-u", "ghost", "--", "true"]);

    // A HOST file that defines `victim`, at a path the box does not have.
    let host_file = std::env::temp_dir().join(format!("kern-hostonly-{}", std::process::id()));
    std::fs::write(&host_file, "victim:x:4242:4242::/:/bin/sh\n").expect("write the host file");
    let host_path = host_file.to_string_lossy().into_owned();
    let linked = exec(&["--", "sh", "-c", &format!("ln -sf {host_path} /etc/passwd")]);
    let victim = exec(&["-u", "victim", "--", "id", "-u"]);
    let fifo = exec(&["--", "sh", "-c", "rm -f /etc/passwd && mkfifo /etc/passwd"]);
    // WITH A DEADLINE, so a read that blocks turns this red instead of hanging the suite. MEASURED with
    // the non-blocking open taken out: the exec waited on the FIFO until the run was killed.
    let mut held = kern()
        .args(["exec", &name, "-u", "late", "--", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn kern exec");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let blocked = loop {
        match held.try_wait().expect("wait for kern exec") {
            Some(status) => break Some(status),
            None if std::time::Instant::now() >= deadline => {
                let _ = held.kill();
                let _ = held.wait();
                break None;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    };
    let _ = kern().args(["stop", &name]).output();
    let _ = std::fs::remove_file(&host_file);

    assert!(late.status.success(), "exec -u late: {late:?}");
    assert_eq!(text(&late), "4321 4321 /home/late", "exec -u late");
    let ids: Vec<&str> = std::str::from_utf8(&groups.stdout)
        .unwrap_or("")
        .split_whitespace()
        .collect();
    assert!(
        ids.contains(&"4400") && !ids.contains(&"70000"),
        "exec -u late groups: {ids:?}"
    );
    let said = String::from_utf8_lossy(&groups.stderr);
    assert!(
        !said.contains("could not give the workload the group"),
        "one unmapped gid cost the mapped ones: {said}"
    );
    assert_eq!(text(&root), "0", "exec without -u must stay box root");
    assert_eq!(
        code,
        Some(1),
        "an unknown user is kern's refusal, not the command's exit"
    );
    assert!(
        sig.is_empty(),
        "a refused -u wrote {sig:?} on KERN_STARTED_FD: an SDK reads that as a command that ran"
    );
    assert!(
        ghost_said.contains("no user 'ghost'"),
        "the refusal names the user: {ghost_said}"
    );
    assert!(linked.status.success(), "ln in the box: {linked:?}");
    assert!(
        !victim.status.success(),
        "exec -u victim resolved through a HOST file: {}",
        text(&victim)
    );
    let said = String::from_utf8_lossy(&victim.stderr);
    assert!(said.contains("no user 'victim'"), "{said}");
    assert!(fifo.status.success(), "mkfifo in the box: {fifo:?}");
    let Some(status) = blocked else {
        panic!("a FIFO at /etc/passwd held exec -u past 10 s: the read waits for a writer");
    };
    assert!(
        !status.success(),
        "a FIFO is no passwd, so `late` cannot resolve: {status:?}"
    );
}

/// **`kern exec -u` works in a box that dropped every capability, and the command keeps none.**
///
/// The exec child used to reapply the box's capability drop in one step BEFORE switching identity.
/// Under `--cap-drop ALL` that took `CAP_SETUID` and `CAP_SETGID` with it, and the switch failed
/// closed: MEASURED, `kern exec -u nobody` into a `--cap-drop ALL --user nobody` box answered "could
/// not drop to the box's own user", exit 126. That is the SDK's own posture for a non-root `user=`
/// with `persist=True`, and `kern compose exec` of a `cap_drop: [ALL]` service with a `user:`.
/// The other half is the boundary: after the switch, every capability set is empty.
#[test]
fn exec_user_works_under_cap_drop_all_and_keeps_no_capability() {
    let name = format!("execcapall-{}", std::process::id());
    let up = kern()
        .args([
            "box",
            &name,
            "-d",
            "--image",
            "alpine:latest",
            "--cap-drop",
            "ALL",
            "--user",
            "nobody",
            "--",
            "sleep",
            "120",
        ])
        .output()
        .expect("run kern");
    if !up.status.success() {
        eprintln!(
            "SKIP: no detached box here: {}",
            String::from_utf8_lossy(&up.stderr)
        );
        return;
    }
    let out = kern()
        .args([
            "exec",
            &name,
            "-u",
            "nobody",
            "--",
            "sh",
            "-c",
            "id -u; grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status",
        ])
        .output()
        .expect("run kern exec");
    let _ = kern().args(["stop", &name]).output();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "exec -u under --cap-drop ALL: {:?} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("65534"), "{text}");
    let sets: Vec<&str> = lines.collect();
    assert_eq!(sets.len(), 5, "{text}");
    for line in sets {
        assert!(
            line.ends_with("0000000000000000"),
            "a capability survived: {line}"
        );
    }
}

/// **On the single-uid map `kern exec -u` refuses an id the box does not have, by name, and box root
/// gets no warning about groups it could never hold.**
///
/// The map is the kernel's rule (an id outside every range cannot be set), read before the fork: the
/// child used to fail closed as "could not drop to the box's own user", exit 126, naming neither the
/// uid nor the map. A group the box's `/etc/group` does not have is refused by name too. And root on
/// that map: `setgroups` is denied there, root owns every mapped file, and both `kern box --user root`
/// and `kern exec -u root` used to print, on every run, that it "could not give the workload the
/// group(s) its image puts it in".
#[test]
fn exec_user_on_the_single_uid_map_refuses_by_name_and_root_hears_no_group_warning() {
    let name = format!("execsingle-{}", std::process::id());
    let up = kern()
        .args([
            "box",
            &name,
            "-d",
            "--image",
            "alpine:latest",
            "--no-uid-range",
            "--",
            "sleep",
            "120",
        ])
        .output()
        .expect("run kern");
    if !up.status.success() {
        eprintln!(
            "SKIP: no detached box here: {}",
            String::from_utf8_lossy(&up.stderr)
        );
        return;
    }
    let exec = |args: &[&str]| {
        let mut argv = vec!["exec", name.as_str()];
        argv.extend_from_slice(args);
        kern().args(&argv).output().expect("run kern exec")
    };
    let unmapped = exec(&["-u", "nobody", "--", "true"]);
    let no_group = exec(&["-u", "root:ghostgroup", "--", "true"]);
    let root = exec(&["-u", "root", "--", "id", "-u"]);
    let _ = kern().args(["stop", &name]).output();
    let boxed = kern()
        .args([
            "box",
            &format!("{name}-b"),
            "--image",
            "alpine:latest",
            "--no-uid-range",
            "--user",
            "root",
            "--",
            "true",
        ])
        .output()
        .expect("run kern box");

    let said = String::from_utf8_lossy(&unmapped.stderr);
    assert_eq!(unmapped.status.code(), Some(1), "{said}");
    assert!(said.contains("uid 65534 does not exist in box"), "{said}");
    assert!(said.contains("uid 0 alone"), "{said}");
    let said = String::from_utf8_lossy(&no_group.stderr);
    assert!(said.contains("no group 'ghostgroup'"), "{said}");
    assert!(root.status.success(), "{root:?}");
    assert_eq!(String::from_utf8_lossy(&root.stdout).trim(), "0");
    for (what, out) in [("exec -u root", &root), ("box --user root", &boxed)] {
        let said = String::from_utf8_lossy(&out.stderr);
        assert!(
            !said.contains("could not give the workload the group"),
            "{what} warned about groups root on the single-uid map can never hold: {said}"
        );
    }
}

/// **A workload whose image group list is refused keeps NONE of kern's own groups.**
///
/// `setgroups` refuses a whole list for one gid outside the box's map, and the process then kept the
/// groups it inherited, which are the host user's as the box sees them. MEASURED on an image whose
/// user is in group 70000 (past a 65536-id range): `kern box --user late` ran as
/// `groups=65534(nobody) x13,0(root)`, the box's root group among them. The list is cleared now, and
/// the warning says the gid is outside the map instead of suggesting the `--uid-range` already in use.
#[test]
fn a_refused_group_list_leaves_the_workload_with_none_of_the_callers_groups() {
    let dir = std::env::temp_dir().join(format!("kern-grp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("context dir");
    std::fs::write(
        dir.join("Dockerfile"),
        "FROM alpine:latest\nRUN addgroup -g 70000 far && adduser -D -u 4321 late && addgroup late far\n",
    )
    .expect("Dockerfile");
    let tag = format!("kern-smoke-grp:{}", std::process::id());
    let built = kern()
        .args(["build", "-q", "-t", &tag, &dir.to_string_lossy()])
        .output()
        .expect("run kern build");
    let _ = std::fs::remove_dir_all(&dir);
    if !built.status.success() {
        eprintln!(
            "SKIP: no build here: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        return;
    }
    let out = kern()
        .args([
            "box",
            &format!("grp-{}", std::process::id()),
            "--image",
            &tag,
            "--user",
            "late",
            "--",
            "id",
            "-G",
        ])
        .output()
        .expect("run kern box");
    let _ = kern().args(["image", "rm", &tag]).output();
    let said = String::from_utf8_lossy(&out.stderr);
    if said.contains("cannot drop to the target") {
        eprintln!("SKIP: no uid range for this user: {said}");
        return;
    }
    assert!(out.status.success(), "{out:?}");
    let ids: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .map(str::to_string)
        .collect();
    assert_eq!(
        ids,
        vec!["4321".to_string()],
        "the workload kept groups that are not its own: {said}"
    );
    assert!(said.contains("outside this box's gid map"), "{said}");
}

/// **A fork failure must never be answered with the user-namespace and rootfs hint, whatever the
/// errno.**
///
/// That hint has now been wrong twice, for two different errnos, to two different later passes. The
/// first time it was EAGAIN under `RLIMIT_NPROC` and it got its own branch. The second was ENOMEM on
/// WSL2, deterministic, and the reader was again sent to two places that were both fine.
///
/// The argument was never about a particular errno: by the time any fork on this path runs, the user
/// namespace exists and the rootfs has been validated, or control would not have reached the fork.
/// So the rule is the CLASS, and this test is on the class. Enumerating errnos one test at a
/// time is how the third one gets found by a user instead.
///
/// Driven through the SAME real failure the EAGAIN test uses, an `RLIMIT_NPROC` of 1, because a hint
/// asserted against a constructed `Error` value proves the match arm and not the rendering: an errno
/// that reaches the formatter through something other than an `io::Error` loses the `(os error N)`
/// suffix and would revert the specific branch in silence. This one matches on the word `fork`,
/// which comes from kern's own message rather than from libc, so it survives that.
#[test]
fn no_fork_failure_is_ever_blamed_on_user_namespaces_or_the_rootfs() {
    use std::os::unix::process::CommandExt;
    let mut cmd = kern();
    cmd.args(["box", "forkhint", "--rootfs", "/tmp", "--", "/bin/true"]);
    // SAFETY: async-signal-safe between fork and exec. `setrlimit` is on the permitted list and
    // nothing here allocates or takes a lock.
    unsafe {
        cmd.pre_exec(|| {
            let r = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            if libc::setrlimit(libc::RLIMIT_NPROC, &r) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("skip: could not even spawn kern under RLIMIT_NPROC=1: {e}");
            return;
        }
    };
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    if !err.contains("fork") {
        eprintln!("skip: this host did not fail at a fork under RLIMIT_NPROC=1, so the branch under test was never reached: {err}");
        return;
    }
    assert!(
        !err.contains("unprivileged user namespaces"),
        "a fork failure must not be blamed on user namespaces or the rootfs, which are both already \
         established by the time kern forks: {err}"
    );
    assert!(
        err.contains("hint:"),
        "and it must still carry SOME hint: removing the wrong one and leaving nothing would trade a \
         misleading pointer for no pointer at all: {err}"
    );
}

/// COMPOSE'S OWN VARIABLES COME FROM THE PROJECT `.env`, which is what Docker means by loading that
/// file "both for self-configuration and interpolation".
///
/// kern read `COMPOSE_PROFILES` from the process environment alone, so a project that ships its
/// profile selection in its `.env` - the ordinary way to ship one - had every profiled service
/// skipped, with a message telling the reader to set a variable their file already sets. MEASURED
/// on Sentry self-hosted, whose `.env` opens with `COMPOSE_PROFILES=feature-complete`: 28 of its 55
/// services were dropped.
///
/// The control is the same file with the line removed, which must still skip the service: without
/// it, this test would pass on a kern that ignores profiles altogether.
#[test]
fn compose_reads_its_own_variables_from_the_project_env_file() {
    let dir = std::env::temp_dir().join(format!("kern-it-profiles-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join("docker-compose.yml");
    std::fs::write(
        &file,
        concat!(
            "services:\n",
            "  sempre:\n",
            "    image: alpine\n",
            "  opzionale:\n",
            "    image: alpine\n",
            "    profiles: [extra]\n",
        ),
    )
    .expect("write compose");

    let config = |env_body: &str| -> String {
        std::fs::write(dir.join(".env"), env_body).expect("write .env");
        let out = kern()
            .current_dir(&dir)
            // The variable must NOT be inherited from whoever runs the suite, or the control below
            // would be measuring the test runner's environment.
            .env_remove("COMPOSE_PROFILES")
            .env_remove("COMPOSE_PROJECT_NAME")
            .args(["compose", "-f", "docker-compose.yml", "config"])
            .output()
            .expect("run kern");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };

    let with_profiles = config("COMPOSE_PROFILES=extra\n");
    let without = config("# nessun profilo qui\n");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        with_profiles.contains("2 service(s)") && !with_profiles.contains("skipped - profile"),
        "a profile named in the project .env must activate its service:\n{with_profiles}"
    );
    assert!(
        without.contains("skipped - profile"),
        "the CONTROL failed: with no profile selected the service must still be skipped, or this \
         test would pass on a kern that ignores `profiles:` entirely:\n{without}"
    );
}

/// `config` PRINTS THE WIRING AS A FIELD, because a tool that counts must not read prose.
///
/// The wiring is announced on stderr in a sentence that also names the alternatives, and that is
/// right for a reader: the pod advisory recommends the bridge, in those words. It is wrong for
/// anything that counts. A census keyed on `"on a bridge"` therefore counted every POD stack as a
/// bridge and reported 60% bridge on a corpus that is 85% pod; it was caught only by a count that
/// refused to reconcile. Improving an advisory must not be able to move a number, so the decision
/// is also printed as one token that says nothing else.
///
/// Both values are asserted from ONE file plus a flag, so the test cannot pass by printing a
/// constant.
#[test]
fn compose_config_prints_the_wiring_as_a_field() {
    let dir = std::env::temp_dir().join(format!("kern-it-wiring-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(
        dir.join("docker-compose.yml"),
        concat!(
            "services:\n",
            "  a:\n",
            "    image: alpine\n",
            "  b:\n",
            "    image: alpine\n",
        ),
    )
    .expect("write compose");
    let field = |extra: &[&str], key: &str| -> String {
        let mut c = kern();
        c.current_dir(&dir)
            .args(["compose", "-f", "docker-compose.yml", "config"]);
        for a in extra {
            c.arg(a);
        }
        let out = c.output().expect("run kern");
        let want = format!("  {key}: ");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix(&want).map(str::to_string))
            .unwrap_or_default()
    };
    let plain = field(&[], "wiring");
    let bridged = field(&["--bridge"], "wiring");
    let separated = field(&["--no-pod"], "wiring");
    let podded = field(&["--pod"], "wiring");
    // THE PROVENANCE, which is a second token so the first one can stay stable. `--bridge` and a
    // file that kern bridges by itself both print `bridge`, and only this line tells them apart:
    // one is a wiring the operator asked for, the other is the default for two or more services.
    let plain_src = field(&[], "wiring-source");
    let bridged_src = field(&["--bridge"], "wiring-source");
    let podded_src = field(&["--pod"], "wiring-source");
    // A SINGLE SERVICE KEEPS THE POD, and it is the control for the default: without it this test
    // would pass on a kern that has forgotten how to build a pod at all.
    std::fs::write(
        dir.join("one.yml"),
        concat!("services:\n", "  a:\n", "    image: alpine\n"),
    )
    .expect("write compose");
    let lone = kern()
        .current_dir(&dir)
        .args(["compose", "-f", "one.yml", "config"])
        .output()
        .expect("run kern");
    let lone_out = String::from_utf8_lossy(&lone.stdout).to_string();
    let lone_wiring = lone_out
        .lines()
        .find_map(|l| l.strip_prefix("  wiring: ").map(str::to_string))
        .unwrap_or_default();
    // A file that COLLIDES gets the bridge without anyone typing it.
    std::fs::write(
        dir.join("collide.yml"),
        concat!(
            "services:\n",
            "  a:\n",
            "    image: alpine\n",
            "    expose: [8080]\n",
            "  b:\n",
            "    image: alpine\n",
            "    expose: [8080]\n",
        ),
    )
    .expect("write compose");
    let auto = kern()
        .current_dir(&dir)
        .args(["compose", "-f", "collide.yml", "config"])
        .output()
        .expect("run kern");
    let auto_out = String::from_utf8_lossy(&auto.stdout).to_string();
    let line = |k: &str| -> String {
        let want = format!("  {k}: ");
        auto_out
            .lines()
            .find_map(|l| l.strip_prefix(&want).map(str::to_string))
            .unwrap_or_default()
    };
    let (auto_wiring, auto_src) = (line("wiring"), line("wiring-source"));
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        plain, "bridge",
        "two services get a namespace each by default, which is the arrangement Docker has"
    );
    assert_eq!(
        lone_wiring, "pod",
        "the CONTROL failed: one service has no peer to be separated from and keeps the pod, so \
         this test cannot pass on a kern that always answers `bridge`"
    );
    assert_eq!(bridged, "bridge", "--bridge is a namespace per service");
    assert_eq!(separated, "relay", "--no-pod reaches peers through relays");
    assert_eq!(
        podded, "pod",
        "--pod asks for the one shared namespace and gets it"
    );
    assert_eq!(plain_src, "auto", "nobody typed the bridge default");
    assert_eq!(bridged_src, "flag", "--bridge was typed");
    assert_eq!(podded_src, "flag", "--pod was typed");
    assert_eq!(
        (auto_wiring.as_str(), auto_src.as_str()),
        ("bridge", "auto"),
        "a collision gets the bridge without anyone typing it, and the source says so"
    );
}

/// A BRIDGE STACK IS NOT TOLD ABOUT RELAYS IT WILL NOT HAVE.
///
/// The relay notes describe the `--no-pod` wiring: peers reached through per-service loopback
/// aliases, and two services sharing an internal port not mutually reachable. A bridge has neither
/// property - its members meet on a real network - but the notes were keyed on "each service has its
/// own namespace", which a bridge also gives.
///
/// MEASURED on Elastic's own compose file, which kern wires on a bridge because three nodes share
/// port 9200: kern announced the bridge and then, in the very next line, said that two services
/// sharing an internal port "are still not mutually reachable", contradicting itself about the one
/// thing the reader had just been told the bridge was for.
///
/// The control is the SAME file under `--no-pod`, where every sentence in the note is true and it
/// must still appear: without it this test would pass on a kern that never prints the note at all.
#[test]
fn a_bridge_stack_is_not_told_about_the_relay_wiring_it_does_not_use() {
    let dir = std::env::temp_dir().join(format!("kern-it-relaynote-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    // Two services on the SAME internal port: the shape that makes kern choose a bridge by itself.
    std::fs::write(
        dir.join("docker-compose.yml"),
        concat!(
            "services:\n",
            "  a:\n",
            "    image: alpine\n",
            "    expose: [9200]\n",
            "  b:\n",
            "    image: alpine\n",
            "    expose: [9200]\n",
        ),
    )
    .expect("write compose");
    let config = |extra: &[&str]| -> String {
        let mut c = kern();
        c.current_dir(&dir)
            .args(["compose", "-f", "docker-compose.yml", "config"]);
        for a in extra {
            c.arg(a);
        }
        let out = c.output().expect("run kern");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };
    let auto = config(&[]);
    let nopod = config(&["--no-pod"]);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        auto.contains("on a bridge"),
        "the premise failed: this file must select the bridge:\n{auto}"
    );
    assert!(
        !auto.contains("loopback aliases"),
        "a bridge stack must not be told its peers are reached through relays:\n{auto}"
    );
    assert!(
        nopod.contains("loopback aliases"),
        "the CONTROL failed: under --no-pod the relay note is true and must be printed:\n{nopod}"
    );
}

/// A BRIDGE MEMBER REACHES ITS PEERS *AND* THE INTERNET, which is the arrangement a Docker container
/// has and the one `--bridge` exists to give.
///
/// Every member has its own network namespace, so the pod's single NAT - which lives in the holder's
/// namespace - is not theirs. `outbound_targets` knew that and then excluded any service writing
/// `restart:`, on the reasoning that systemd starts those and kern cannot hold them at the gate. That
/// reasoning is about a STANDALONE box: `persistent_supervision` puts every pod member on the
/// in-process supervisor whatever systemd offers, because it needs the holder's namespace.
///
/// MEASURED on Sentry self-hosted, which sets `restart: unless-stopped` on nearly every service: a
/// member's routing table held the on-link `10.89.0.0/24` and nothing else, there was no
/// `/etc/resolv.conf` at all, and pgbouncer died inside libevent's `evdns_base_new`. The stack's own
/// summary line meanwhile said "outbound to the internet (pasta)".
///
/// The peer half is asserted in the same run, because the fix adds a SECOND interface to the
/// namespace: if the default route and the bridge route ever fight, this is where it shows.
#[test]
fn a_bridge_member_has_a_route_out_and_still_reaches_its_peers() {
    let dir = std::env::temp_dir().join(format!("kern-it-bridgenet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(
        dir.join("compose.yml"),
        concat!(
            "services:\n",
            "  uno:\n",
            "    image: alpine\n",
            // `restart:` ON PURPOSE: it is the key that used to remove the NAT.
            "    restart: unless-stopped\n",
            "    command: [\"sleep\", \"60\"]\n",
            "  due:\n",
            "    image: alpine\n",
            "    restart: unless-stopped\n",
            "    command: [\"sleep\", \"60\"]\n",
        ),
    )
    .expect("write compose");
    let xdg = std::env::temp_dir().join(format!("kern-it-bridgenet-xdg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&xdg);
    let _ = std::fs::create_dir_all(&xdg);
    let run = |args: &[&str]| -> (String, String) {
        let out = kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(args)
            .output()
            .expect("run kern");
        (
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };

    let (_, err) = run(&[
        "compose",
        "-f",
        "compose.yml",
        "-p",
        "brt",
        "--bridge",
        "up",
        "-d",
    ]);
    let inside = |cmd: &str| run(&["exec", "brt-uno", "--", "sh", "-c", cmd]).0;
    let routes = inside("ip route");
    let resolv = inside("cat /etc/resolv.conf");
    let peer = inside("getent hosts due");
    let _ = run(&["compose", "-f", "compose.yml", "-p", "brt", "down"]);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);

    // A host without pasta, or one whose policy refuses the namespace opens, cannot produce the
    // condition: say so instead of asserting on a machine that could not answer.
    if err.contains("user namespaces")
        || err.contains("pasta")
        || (routes.is_empty() && peer.is_empty())
    {
        eprintln!("skip: this host could not bring the bridge stack up ({err})");
        return;
    }
    // THE CONTROL: the bridge route must be there, or the box under test is not a bridge member and
    // the assertion about the default route would be about something else entirely.
    assert!(
        routes.contains("eth0"),
        "the CONTROL failed: no bridge interface in the member, so this is not measuring a bridge \
         member: {routes:?}"
    );
    assert!(
        routes.contains("default"),
        "a bridge member has no route out: {routes:?}"
    );
    assert!(
        resolv.contains("nameserver"),
        "a bridge member has no resolver, so a workload that initialises one fails at start: \
         {resolv:?}"
    );
    assert!(
        peer.contains("due"),
        "the second interface must not cost the member its peers: {peer:?}"
    );
}

/// A stack whose FIRST service is refused must not leave its pod behind.
///
/// MEASURED before the guard existed, on 0.9.32-37-g02ecedf: `compose up` printed
/// `created pod '<project>-<hash>'`, the first box's start was refused, and the pod stayed - `up` with
/// 0 boxes. `kern ps` cannot show it, because that lists boxes, so the only place it appears is
/// `kern pod ls`, one more per attempt. A reader fixing a typo in a `mem_limit:` accumulates debris
/// nothing told them about.
///
/// The refusal used here is a `mem_limit:` below the floor a box needs to start, which is the shortest
/// way to a failure that happens BEFORE any box is registered. It is one of several ways in (an image
/// that cannot be pulled, a flag the CLI rejects) and the guard keys on the pod being empty, not on
/// which error occurred.
#[test]
fn a_refused_first_service_leaves_no_pod_behind() {
    let dir = std::env::temp_dir().join(format!("kern-it-podleak-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    if std::fs::create_dir_all(&dir).is_err() {
        eprintln!("SKIP: could not create a temp project dir");
        return;
    }
    let xdg = std::env::temp_dir().join(format!("kern-it-podleak-xdg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&xdg);
    let _ = std::fs::create_dir_all(&xdg);
    let run = |args: &[&str]| -> (String, String, Option<i32>) {
        match kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(args)
            .output()
        {
            Ok(out) => (
                String::from_utf8_lossy(&out.stdout).to_string(),
                String::from_utf8_lossy(&out.stderr).to_string(),
                out.status.code(),
            ),
            Err(e) => (String::new(), e.to_string(), None),
        }
    };
    let write = |body: &str| std::fs::write(dir.join("compose.yml"), body);

    // THE CONTROL FIRST, and it decides whether this host can answer at all: the same stack with a
    // unit on the cap must come up, put its pod in `pod ls`, and have `down` remove it. Without it,
    // every assertion below would also pass on a host that cannot create a pod in the first place.
    if write(concat!(
        "services:\n",
        "  web:\n",
        "    image: alpine\n",
        "    mem_limit: 64m\n",
        "    command: [\"sleep\", \"60\"]\n",
    ))
    .is_err()
    {
        eprintln!("SKIP: could not write the compose file");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let (_, up_err, _) = run(&["compose", "-f", "compose.yml", "-p", "leakctl", "up", "-d"]);
    let (pods_up, _, _) = run(&["pod", "ls"]);
    let _ = run(&["compose", "-f", "compose.yml", "-p", "leakctl", "down"]);
    let (pods_down, _, _) = run(&["pod", "ls"]);
    if !pods_up.contains("leakctl") {
        eprintln!("SKIP: this host did not bring the control stack up, so it cannot show the leak ({up_err})");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&xdg);
        return;
    }
    assert!(
        !pods_down.contains("leakctl"),
        "the CONTROL failed: `compose down` left the pod behind, so this test cannot tell a leak from \
         ordinary teardown: {pods_down:?}"
    );

    // THE CASE: a cap of 64 BYTES. The service cannot start, and nothing is ever registered.
    if write(concat!(
        "services:\n",
        "  web:\n",
        "    image: alpine\n",
        "    mem_limit: 64\n",
        "    command: [\"sleep\", \"60\"]\n",
    ))
    .is_err()
    {
        eprintln!("SKIP: could not rewrite the compose file");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&xdg);
        return;
    }
    let (_, err, code) = run(&["compose", "-f", "compose.yml", "-p", "leakcase", "up", "-d"]);
    let (pods, _, _) = run(&["pod", "ls"]);
    let _ = run(&["compose", "-f", "compose.yml", "-p", "leakcase", "down"]);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);

    assert_ne!(code, Some(0), "a refused service must fail the up: {err:?}");
    assert!(
        err.contains("BARE NUMBER IS BYTES"),
        "the refusal must name the actual mistake: {err:?}"
    );
    assert!(
        !pods.contains("leakcase"),
        "the pod outlived the stack that could not start: {pods:?}"
    );
}

/// Run `kern box` with a pipe on `KERN_ALIVE_FD` and report what that pipe said, bounded.
///
/// Returns `(exit code, state)` with the SAME three states the bindings decide on, because a test that
/// modelled the protocol differently would pass while they broke:
///   * `"past-setup"`: EOF (the workload `execvp`'d, so the child's `FD_CLOEXEC` closed it) or a byte
///     beyond the ack (kern reported setup or exec failed).
///   * `"in-setup"`: the ack arrived and nothing else did, within the window.
///   * `"unknown"`: nothing at all, which is what a kern predating this channel does.
///
/// The window is what makes this a test and not a hang: a box that reaches neither end state would
/// otherwise block the suite forever.
fn alive_state(args: &[&str], window: std::time::Duration) -> (Option<i32>, &'static str) {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return (None, "open");
    }
    let (r, w) = (fds[0], fds[1]);
    let child = kern()
        .args(args)
        .env("KERN_ALIVE_FD", w.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn();
    let Ok(mut child) = child else {
        unsafe {
            libc::close(r);
            libc::close(w);
        }
        return (None, "open");
    };
    // The parent's own copy must go, or the read end can never see EOF: kern's child and this process
    // would both hold a write end. Same reason the `-d` launcher closes its copy.
    unsafe { libc::close(w) };
    let mut pfd = libc::pollfd {
        fd: r,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = i32::try_from(window.as_millis()).unwrap_or(i32::MAX);
    // Drain until an end state or the window closes: kern writes its ack FIRST, so the first readable
    // event is a byte on every path and a single read cannot tell the three states apart.
    let mut acked = false;
    let state = loop {
        pfd.revents = 0;
        let n = unsafe { libc::poll(&mut pfd, 1, ms) };
        if n <= 0 {
            break if acked { "in-setup" } else { "unknown" };
        }
        let mut b = [0u8; 64];
        let got = unsafe { libc::read(r, b.as_mut_ptr().cast(), b.len()) };
        if got <= 0 {
            break "past-setup"; // EOF: the workload exec'd
        }
        let read = usize::try_from(got).unwrap_or(0);
        if b[..read].iter().any(|c| *c != b'A') {
            break "past-setup"; // a byte beyond the ack: kern said setup failed
        }
        acked = true;
    };
    unsafe { libc::close(r) };
    let code = match child.wait() {
        Ok(st) => st.code(),
        Err(_) => None,
    };
    let _ = child.stderr.take();
    (code, state)
}

/// `KERN_ALIVE_FD` distinguishes a box that REACHED its workload from one that did not.
///
/// WHY IT EXISTS. `KERN_STARTED_FD` is written at teardown, so an SDK whose own deadline fires first
/// kills kern before that write and learns nothing: "the workload was slow" and "kern never reached
/// `execvp` because its setup blocked" are the same overrun. MEASURED through the Python binding
/// before this: a box whose volume source was a FIFO sat in `wait_for_partner` past 404 seconds and
/// came back `fault=timeout`, a TRANSIENT class an agent retries forever. The FIFO is refused by type
/// now; an `lstat` on a dead NFS mount or a FUSE with no daemon blocks identically and is not a FIFO.
///
/// This is the readiness pipe the `-d` launcher already used, handed to the caller instead of being
/// built internally, so the three states are the ones that path has relied on for releases.
#[test]
fn the_alive_fd_tells_a_started_workload_from_a_box_still_in_setup() {
    let window = std::time::Duration::from_secs(20);
    // A healthy box: the workload execs, `FD_CLOEXEC` closes the descriptor, the reader sees EOF.
    let (code, state) = alive_state(
        &[
            "box",
            "alivetest-ok",
            "--image",
            "alpine",
            "--",
            "/bin/sh",
            "-c",
            "echo hi",
        ],
        window,
    );
    if code != Some(0) {
        eprintln!("SKIP: this host could not run a plain box (exit {code:?}), so it has no exec to observe");
        return;
    }
    assert_eq!(
        state, "past-setup",
        "a box whose workload ran must close the alive fd, or an SDK cannot tell it from a stuck setup"
    );
    // THE OTHER STATE, and without it the assertion above would also pass on a kern that closed the fd
    // unconditionally: a command that does not exist fails INSIDE the box, after the fork, so the child
    // writes the failure byte rather than reaching exec.
    let (code, state) = alive_state(
        &["box", "alivetest-127", "--image", "alpine", "--", "/nope"],
        window,
    );
    assert_eq!(
        code,
        Some(127),
        "a missing command must still be the workload's own 127"
    );
    assert_eq!(
        state, "past-setup",
        "a box whose command could not be started is past the setup phase, so it must not read as a box \
         still building"
    );
}

/// A COMPOSE REFUSAL DOES NOT END WITH ADVICE ABOUT THE OTHER FILE FORMAT.
///
/// kern reads two kinds of stack, a `docker-compose.yml` and its own TOML, and every compose error
/// used to print the same closing hint: ``compose: `[box.NAME]` tables with image/rootfs, command,
/// depends_on``. That is TOML syntax, so a refused YAML file - which is nearly every refusal - ended
/// with instructions for a language the reader is not writing.
///
/// TWO THINGS ARE ASSERTED, and the second is what stops the fix from becoming a deletion:
///   1. a message that already carries its own repair gets NO generic hint under it, because a
///      pointer printed beneath a paste-ready instruction is how the instruction gets skipped;
///   2. a message that does NOT carry one still gets a hint, and that hint names BOTH formats.
#[test]
fn a_compose_refusal_does_not_advise_the_other_file_format() {
    let dir = std::env::temp_dir().join(format!("kern-it-hint-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let run = |body: &str, name: &str| -> String {
        let p = dir.join(name);
        std::fs::write(&p, body).expect("write");
        let out = kern()
            .args(["compose", "-f", p.to_str().unwrap_or_default(), "config"])
            .output()
            .expect("run kern");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };
    // Carries its own repair (it names the keys to write): no generic hint.
    let shaped = run("services:\n  - web\n  - db\n", "a.yml");
    // Carries none: the hint appears, and covers both formats.
    let dup = run(
        "services:\n  a:\n    image: alpine\n  a:\n    image: busybox\n",
        "b.yml",
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !shaped.contains("hint:"),
        "a refusal that already tells the reader what to write must not carry a generic hint \
         too:\n{shaped}"
    );
    assert!(
        dup.contains("hint:"),
        "the CONTROL failed: a refusal with no repair of its own must still point somewhere, or \
         this test would pass on a kern that simply stopped hinting:\n{dup}"
    );
    assert!(
        dup.contains("docker-compose.yml") && dup.contains("[box.NAME]"),
        "and the hint must name BOTH formats kern reads, since the refusal cannot know which one \
         the reader is writing:\n{dup}"
    );
}

/// `kern build --check` REPORTS AND BUILDS NOTHING, and its exit code is the answer.
///
/// The verb exists so a project can ask "will my Dockerfile build here, and is there a line kern
/// will quietly not act on" WITHOUT paying for a base image and half a build to find out. Three
/// properties make it useful and each is asserted: it touches nothing, it names the lines kern does
/// not act on, and it exits non-zero on a file that would not build - so it can gate somebody else's
/// pipeline.
///
/// Run against the BINARY rather than the function, because the exit code is half the contract and a
/// unit test cannot see one.
#[test]
fn build_check_reports_without_building_and_its_status_is_the_answer() {
    let dir = std::env::temp_dir().join(format!("kern-bc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let write = |name: &str, body: &str| {
        std::fs::write(dir.join(name), body).expect("write Dockerfile");
    };
    let check = |file: &str| {
        kern()
            .args(["build", "--check", "-f"])
            .arg(dir.join(file))
            .arg(&dir)
            .output()
            .expect("run kern build --check")
    };

    // A FILE THAT BUILDS: exit 0, every acted-on line reported, and the one kern drops named as
    // dropped rather than passed over in silence.
    write(
        "Dockerfile",
        "FROM alpine:3.19\nVOLUME /data\nEXPOSE 8080\nRUN true\n",
    );
    let out = check("Dockerfile");
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "a buildable file must exit 0: {text}");
    assert!(
        text.contains("EXPOSE"),
        "an honoured line is listed: {text}"
    );
    assert!(
        text.contains("dropped") && text.contains("VOLUME"),
        "the line kern does not act on must be NAMED: {text}"
    );

    // NOTHING WAS BUILT. The verb's whole point is that it costs nothing, so the image it would
    // have produced must not exist and no build record may have been written for it.
    let images = kern().arg("images").output().expect("run kern images");
    assert!(
        !String::from_utf8_lossy(&images.stdout).contains("kern-bc-"),
        "--check must not leave an image behind"
    );

    // A FILE THAT WOULD NOT BUILD: non-zero, with the refusal carried through rather than a generic
    // failure - the reason is the useful part, and it is what a pipeline prints.
    write("Dockerfile.onbuild", "FROM alpine:3.19\nONBUILD RUN true\n");
    let out = check("Dockerfile.onbuild");
    let text = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!out.status.success(), "ONBUILD must fail the check");
    assert!(text.contains("ONBUILD"), "and name it: {text}");

    // A BUILD SECRET IS HONOURED NOW (`kern build --secret`), so the check passes and names the
    // mount by its type, where it used to refuse the file as one kern could not build.
    write(
        "Dockerfile.secret",
        "FROM alpine:3.19\nRUN --mount=type=secret,id=n,target=/r npm ci\n",
    );
    let out = check("Dockerfile.secret");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "a build secret is honoured now: {text}"
    );
    assert!(
        text.contains("--mount secret"),
        "and the report names the mount: {text}"
    );
    // A MOUNT THAT CANNOT BE READ still fails it, by name.
    write(
        "Dockerfile.badmount",
        "FROM alpine:3.19\nRUN --mount=type=volume,target=/v true\n",
    );
    let out = check("Dockerfile.badmount");
    let text = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        !out.status.success(),
        "an unknown mount type must fail the check"
    );
    assert!(text.contains("type=volume"), "and name it: {text}");

    // A COPY THAT ESCAPES THE CONTEXT IS NOT "BUILDS HERE", and the first version of this verb said
    // it was. The gate's whole value is that a green means green: a file whose first COPY the build
    // then refuses is the one answer a check must never give.
    write(
        "Dockerfile.escape",
        "FROM alpine:3.19\nCOPY ../../etc/passwd /stolen\n",
    );
    let out = check("Dockerfile.escape");
    let text = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        !out.status.success(),
        "a context escape must fail the check"
    );
    assert!(
        text.contains("escapes the build context"),
        "and name the rule it broke: {text}"
    );
    // Same for a source that simply is not there, which the build refuses for its own reason.
    write("Dockerfile.missing", "FROM alpine:3.19\nCOPY nope.txt /x\n");
    assert!(
        !check("Dockerfile.missing").status.success(),
        "a COPY of a file the context does not hold must fail the check"
    );

    // WHAT IT MUST NOT REFUSE: a glob, which names no file until the directory is read, and a
    // `COPY --from`, which resolves against a filesystem that does not exist until that stage has
    // been built. Both are left to the build - the direction that never refuses something that works.
    write("Dockerfile.glob", "FROM alpine:3.19\nCOPY *.txt /x/\n");
    assert!(
        check("Dockerfile.glob").status.success(),
        "a glob must be left to the build, not guessed at"
    );
    write(
        "Dockerfile.stage",
        "FROM alpine:3.19 AS b\nRUN true\nFROM alpine:3.19\nCOPY --from=b /anywhere /x\n",
    );
    assert!(
        check("Dockerfile.stage").status.success(),
        "a COPY --from names a filesystem that does not exist yet"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// KERN DOES NOT ANSWER TO ANOTHER TOOL'S NAME, whatever the file it is invoked through is called.
///
/// Until 2026-09-19 a symlink called `docker` made this binary read its own `argv[0]`, rewrite a
/// Docker command line into kern's dialect and run it. What that cost is measurable and was
/// measured: `examples/benchmark.py` shells out to whatever `docker` is on PATH, and on a machine
/// carrying the symlink it published OUR binary as the competitor - `docker run --rm  4.2 ms` beside
/// a real podman at 285 ms in the same run - because `docker --version` answered for kern.
///
/// The compatibility kern does offer is untouched and is not this: `kern box` takes Docker's common
/// flags and `kern compose` reads a `docker-compose.yml` unchanged. Borrowing the NAME added only
/// the ability to type `docker` instead of `kern`.
///
/// Asserted through a real symlink rather than by grepping for a deleted module, because the
/// behaviour is what a user meets and a module can come back under any name.
#[test]
fn kern_does_not_translate_a_docker_command_line() {
    let dir = std::env::temp_dir().join(format!("kern-noshim-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let link = dir.join("docker");
    let _ = std::fs::remove_file(&link);
    if std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_kern"), &link).is_err() {
        eprintln!("skip: cannot create a symlink here");
        return;
    }

    // It says what it is. A shim answered this with kern's version too, so this alone is not the
    // assertion - it is the control that the binary under the link really is ours.
    let v = std::process::Command::new(&link).arg("--version").output();
    let Ok(v) = v else {
        eprintln!("skip: cannot spawn through the symlink");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let ver = String::from_utf8_lossy(&v.stdout).to_lowercase();
    assert!(
        ver.contains("kern"),
        "invoked as docker it must name itself kern: {ver:?}"
    );

    // THE ASSERTION. `docker run --rm IMAGE cmd` is Docker's grammar, and the shim turned it into
    // `kern box NAME --image IMAGE -- cmd`. kern's own parser has no `--rm` on `run`, so a binary
    // that still translated would succeed here and one that does not must refuse in kern's voice.
    let out = std::process::Command::new(&link)
        .args(["run", "--rm", "alpine", "/bin/true"])
        .output()
        .expect("spawn through the symlink");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a Docker command line was accepted through a `docker` symlink: the shim is back. \
         stderr={err:?}"
    );
    assert!(
        err.contains("kern"),
        "the refusal must come from kern in its own words, not from a translation layer: {err:?}"
    );

    // And `docker compose version` must not claim to BE the other tool. That one line said
    // `Docker Compose version <kern's number>` while `--version` and `info` both answered `kern`,
    // and its own comment claimed the surface "has never claimed to be Docker". It had.
    let c = std::process::Command::new(&link)
        .args(["compose", "version"])
        .output()
        .expect("spawn through the symlink");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&c.stdout),
        String::from_utf8_lossy(&c.stderr)
    );
    assert!(
        !all.contains("Docker Compose version"),
        "kern announced itself as Docker Compose: {all:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A name longer than the column must widen the column, not shift every row after it.
///
/// FOUR TABLES HAD A FIXED NAME WIDTH and `kern ps` had already been fixed; these are the ones that
/// fix did not reach. `volume ls` and `network ls` are asserted here because they need no box, no
/// user namespace and no busybox, so this guard runs on every host - including the CI runners where
/// the box-based half of it would honestly skip.
///
/// MEASURED BEFORE THE FIX, not supposed: this host already had a compose stack's
/// `CEIJ-GPSDEGoTracker-49cf4a99_postgres_data` (42 chars) in its volume directory, and it pushed
/// SIZE and QUOTA out of line for every row of `volume ls`, header included - a table whose header
/// lines up with no row in it.
///
/// THE TEST OWNS ITS STATE: `XDG_DATA_HOME` moves the volume directory and `XDG_RUNTIME_DIR` the
/// network directory, so it neither reads the developer's real volumes nor leaves anything behind.
/// That also makes the expected width exactly computable, which is the whole assertion: the column
/// is as wide as the longest name, so the cell after it starts at the same offset in the header and
/// in every row.
#[test]
fn a_long_name_widens_the_column_instead_of_shifting_the_row() {
    let tmp = std::env::temp_dir().join(format!("kern-it-colw-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("temp dir");
    let data = tmp.join("data");
    let run = tmp.join("run");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&run).unwrap();
    let k = |args: &[&str]| -> String {
        let o = kern()
            .env("XDG_DATA_HOME", &data)
            .env("XDG_RUNTIME_DIR", &run)
            .args(args)
            .output()
            .expect("run kern");
        String::from_utf8_lossy(&o.stdout).to_string()
    };

    // `NAME` padded to `nw`, then one separator space, in the header AND in every row.
    let aligned = |table: &str, nw: usize, names: &[&str], what: &str| {
        let mut lines = table.lines();
        let header = lines.next().unwrap_or_default();
        let cell =
            |l: &str| -> String { l.chars().take(nw).collect::<String>().trim().to_string() };
        assert_eq!(
            cell(header),
            "NAME",
            "{what}: header NAME cell is not {nw} wide: {header:?}"
        );
        assert_eq!(
            header.chars().nth(nw),
            Some(' '),
            "{what}: no separator after the header's NAME cell: {header:?}"
        );
        for l in lines.filter(|l| !l.trim().is_empty()) {
            assert!(
                names.contains(&cell(l).as_str()),
                "{what}: the first {nw} columns of a row are not one whole name - \
                 the column did not widen and every cell after it is shifted: {l:?}"
            );
            assert_eq!(
                l.chars().nth(nw),
                Some(' '),
                "{what}: no separator after a row's NAME cell: {l:?}"
            );
        }
    };

    // VOLUMES: floor 28, so a 35-character name is what proves the column moved.
    let long_vol = "a-volume-name-that-is-thirty-four-x";
    assert_eq!(long_vol.len(), 35);
    k(&["volume", "create", long_vol]);
    k(&["volume", "create", "shortvol"]);
    aligned(
        &k(&["volume", "ls"]),
        35,
        &[long_vol, "shortvol"],
        "volume ls",
    );

    // NETWORKS: floor 24, so a 29-character name proves the same for that table.
    let long_net = "a-network-name-of-twentyeight";
    assert_eq!(long_net.len(), 29);
    k(&["network", "create", long_net]);
    k(&["network", "create", "net2"]);
    aligned(
        &k(&["network", "ls"]),
        29,
        &[long_net, "net2"],
        "network ls",
    );

    // AND THE FLOOR IS UNCHANGED: with only short names the tables are exactly as wide as they were
    // before any of this, so the fix cannot have quietly reformatted everyone's output.
    k(&["volume", "rm", long_vol]);
    k(&["network", "rm", long_net]);
    aligned(
        &k(&["volume", "ls"]),
        28,
        &["shortvol"],
        "volume ls, short names only",
    );
    aligned(
        &k(&["network", "ls"]),
        24,
        &["net2"],
        "network ls, short names only",
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

/// No list verb lets a name off disk carry a terminal escape to stdout.
///
/// ENUMERATED, NOT WALKED. `network ls` was found printing `ev^[[2Jil^[]0;PWNED^G` with the ESC and
/// BEL bytes intact, and fixing only that one would have left `pod ls`, which had exactly the same
/// hole and was found by running every list verb against the same planted name instead of inspecting
/// the one already known broken. Both listings walk a state directory and yield every entry
/// verbatim, so what they return is what is ON DISK, not what `create` accepted - the creation-time
/// `valid_resource_name` check does not cover them, and two functions away the REFUSAL for the same
/// name already scrubbed it.
///
/// NOT REACHABLE FROM A BOX TODAY, and this test does not pretend otherwise: planting the directory
/// needs write access to kern's runtime dir, and `-v` refuses to mount that into a box by name. This
/// is the layer under that refusal, and it is cheap to hold.
///
/// THE FIXTURE IS ASSERTED LIVE. A sweep where no verb lists anything passes while testing nothing,
/// so at least one verb must be shown to have actually reached the planted name and neutralised it.
#[test]
fn no_list_verb_carries_a_terminal_escape_off_disk() {
    let tmp = std::env::temp_dir().join(format!("kern-it-esc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (run, data, conf) = (tmp.join("run"), tmp.join("data"), tmp.join("conf"));
    for d in [&run, &data, &conf] {
        std::fs::create_dir_all(d).expect("temp dir");
    }
    // ESC + a CSI erase-screen, ESC + an OSC title set ending in BEL: the two shapes that repaint or
    // retitle a terminal. `PWNED` is the marker that says the name was actually reached.
    let evil = "ev\u{1b}[2Jil\u{1b}]0;PWNED\u{7}";
    for d in [
        "networks",
        "volumes",
        "pods",
        "secrets",
        "instances",
        "builds",
        "images",
    ] {
        let _ = std::fs::create_dir_all(run.join("kern").join(d).join(evil));
        let _ = std::fs::create_dir_all(run.join("kern").join(d).join(format!("plain-{d}")));
    }
    let _ = std::fs::create_dir_all(data.join("kern/volumes").join(evil));

    let verbs: [&[&str]; 9] = [
        &["network", "ls"],
        &["volume", "ls"],
        &["pod", "ls"],
        &["secret", "ls"],
        &["images"],
        &["ps", "-a"],
        &["stats"],
        &["history", "-n", "10"],
        &["top"],
    ];
    let mut reached = Vec::new();
    for args in verbs {
        let out = kern()
            .env("XDG_RUNTIME_DIR", &run)
            .env("XDG_DATA_HOME", &data)
            .env("XDG_CONFIG_HOME", &conf)
            .args(args)
            .output()
            .expect("run kern");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        // Colour is off (not a TTY), so ANY escape here came from the planted name.
        let bad: Vec<char> = text
            .chars()
            .filter(|c| *c == '\u{1b}' || *c == '\u{7}')
            .collect();
        assert!(
            bad.is_empty(),
            "`kern {}` carried {} raw terminal control char(s) off disk: {text:?}",
            args.join(" "),
            bad.len()
        );
        if text.contains("PWNED") {
            reached.push(args.join(" "));
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);
    assert!(
        !reached.is_empty(),
        "no verb listed the planted name, so this swept nothing; the fixture stopped being live"
    );
    eprintln!("reached and neutralised by: {reached:?}");
}

/// `kern recover` LEAVES A BOX THAT IS STILL BEING BUILT ALONE.
///
/// A box creates its overlay scratch (`<runtime>/kern/scratch/<name>-<pid>/{upper,work,merged}`)
/// before it mounts the overlay and before it writes its registry entry, so during that window it is
/// a directory no live entry names. `recover` removed every such directory, and the other `kern` then
/// mounted over directories that had just been deleted: `mount(overlay) failed: No such file or
/// directory`. MEASURED on 0.30.2: 0 failures in 160 boxes from four workers, 42 in 160 with a
/// `recover` loop beside them. The Python SDK runs `recover` when a prewarmed session closes, which is
/// how several MCP servers on one machine came to break each other's calls.
///
/// Built here without the race, so the verdict does not depend on timing: one scratch directory
/// named for a creator that is ALIVE (this test process) and one for a creator that has EXITED (a
/// child reaped before `recover` runs). The control is the second one - a `recover` that removed
/// nothing would pass the first assertion by doing no work at all.
#[test]
fn recover_keeps_scratch_whose_creator_is_alive_and_removes_the_dead() {
    let runtime = std::env::temp_dir().join(format!("kern-recover-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&runtime);
    let scratch = runtime.join("kern/scratch");
    std::fs::create_dir_all(&scratch).expect("mkdir scratch");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    // A pid that existed and does not any more: a child, run to completion and reaped.
    let dead = {
        let mut c = Command::new("true").spawn().expect("spawn true");
        let pid = c.id();
        c.wait().expect("reap true");
        pid
    };
    let alive = std::process::id();
    let in_build = scratch.join(format!("box-in-build-{alive}"));
    let orphan = scratch.join(format!("box-crashed-{dead}"));
    for d in [&in_build, &orphan] {
        for sub in ["upper", "work", "merged"] {
            std::fs::create_dir_all(d.join(sub)).expect("mkdir scratch leaf");
        }
    }

    let out = kern()
        .env("XDG_RUNTIME_DIR", &runtime)
        .arg("recover")
        .output()
        .expect("run kern recover");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        in_build.join("upper").is_dir() && in_build.join("work").is_dir(),
        "recover removed the scratch of a box whose creator is still running, which is a box \
         mid-build: its overlay mount would now fail with ENOENT\n{said}"
    );
    assert!(
        !orphan.exists(),
        "the CONTROL: recover must still reclaim the scratch of a creator that has exited, or the \
         assertion above passes by doing nothing\n{said}"
    );
    let _ = std::fs::remove_dir_all(&runtime);
}

/// "NO IMAGES CACHED YET" SAYS WHETHER THAT IS THE WHOLE TRUTH.
///
/// MEASURED from a field report: `rm -rf` over the cache to free space took everything it could and
/// stopped at the files a uid-mapped extraction had left owned by a subordinate uid, so the index was
/// gone and 5.2 MB were not. `kern images` then said "no images cached yet", and `kern rmi` - whose
/// own error sends the reader to `kern images` - said "no such image". Three true sentences
/// composing into a false one, and the reader concluded the files were not kern's.
///
/// No box and no network: a directory under the images root is all the state this needs, which is
/// also why the assertion is exact rather than a timing or a size range.
#[test]
fn an_empty_listing_names_bytes_in_the_cache_that_no_image_claims() {
    let home = std::env::temp_dir().join(format!("kern-it-cachewreck-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let images = home.join("kern/images");
    std::fs::create_dir_all(&images).expect("the images root");
    let listing = |label: &str| -> String {
        let out = kern()
            .env("XDG_CACHE_HOME", &home)
            .arg("images")
            .output()
            .unwrap_or_else(|e| panic!("{label}: run kern images: {e}"));
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };

    // THE CONTROL FIRST: an images root that is really empty gets the plain sentence and no note.
    let empty = listing("empty");
    assert!(empty.contains("no images cached yet"), "{empty}");
    assert!(
        !empty.contains("no image claims"),
        "an empty cache must not be accused of holding anything: {empty}"
    );

    // Now the wreck: a directory the listing cannot read as an image, holding bytes.
    let orphan = images.join("node_22-alpine-deadbeefdeadbeef");
    std::fs::create_dir_all(orphan.join("opt/yarn/lib")).expect("the orphan tree");
    std::fs::write(orphan.join("opt/yarn/lib/cli.js"), vec![b'x'; 4096]).expect("some bytes");
    let said = listing("wrecked");
    assert!(said.contains("no images cached yet"), "{said}");
    assert!(
        said.contains("no image claims") && said.contains("gc --images"),
        "the note must name the state and the tool that reclaims it: {said}"
    );
    assert!(
        said.contains("1 entry"),
        "one directory under the root is one entry, whatever it holds inside: {said}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// THE DRY RUN SAYS WHAT `up` WILL SAY ABOUT A PATH THAT LEAVES THE PROJECT, AND `include:` IS READ
/// THROUGH THE REAL COMMAND.
///
/// MEASURED 2026-11-12 on LLMSystems/vLLMux, which keeps its compose file in `deploy/` and builds
/// from `..`: `compose config` printed a clean preview and `compose up` refused "build context '..'
/// escapes the compose directory". And on NVIDIA-Omniverse/usd-search, whose services live in files
/// it `include:`s from `infra/compose/`, kern listed none of them. Both are driven through the
/// binary here, because each defect lived in the command and not in a function a unit test calls.
#[test]
fn compose_config_refuses_a_path_out_of_the_project_and_reads_include() {
    let root = std::env::temp_dir().join(format!("kern-smoke-guard-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("deploy")).expect("fixture dir");
    std::fs::create_dir_all(root.join("infra/compose")).expect("fixture dir");
    let run = |dir: &std::path::Path, body: &str| -> (bool, String) {
        std::fs::write(dir.join("docker-compose.yml"), body).expect("write compose");
        let out = kern()
            .current_dir(dir)
            .env_remove("COMPOSE_PROFILES")
            .args(["compose", "-f", "docker-compose.yml", "config"])
            .output()
            .expect("run kern");
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let deploy = root.join("deploy");
    let (ok, said) = run(
        &deploy,
        "services:\n  b:\n    image: alpine\n    build: ..\n",
    );
    let (inside_ok, inside) = run(
        &deploy,
        "services:\n  b:\n    image: alpine\n    volumes:\n      - ./data:/data\n",
    );
    std::fs::write(
        root.join("infra/compose/m.yml"),
        "services:\n  included:\n    image: alpine\n",
    )
    .expect("write included");
    let (inc_ok, inc) = run(
        &root,
        "include:\n  - infra/compose/m.yml\nservices:\n  top:\n    image: alpine\n",
    );
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        !ok && said.contains("escapes the project directory"),
        "config must refuse what up refuses:\n{said}"
    );
    assert!(
        inside_ok,
        "the CONTROL: a path inside the project still passes, or the guard is a blanket:\n{inside}"
    );
    assert!(
        inc_ok && inc.contains("included") && inc.contains("2 service(s)"),
        "an included model's services are part of the stack:\n{inc}"
    );
}

/// ⛔ `--project-root`: THE OPERATOR WIDENS THE PROJECT, the file cannot.
///
/// LLMSystems/vLLMux keeps its compose file in `deploy/` and builds from `..`; docker runs it and
/// kern refused. The refusal stays the default (a downloaded file must not reach `../../.ssh`), it
/// now names the flag, and with the flag the same file passes; a root that does not contain the
/// file is refused, because widening is not moving.
#[test]
fn compose_project_root_widens_the_boundary_and_only_around_the_file() {
    let root = std::env::temp_dir().join(format!("kern-smoke-proot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("repo/deploy")).expect("fixture dir");
    std::fs::create_dir_all(root.join("elsewhere")).expect("fixture dir");
    std::fs::create_dir_all(root.join("repo/data")).expect("fixture dir");
    std::fs::write(
        root.join("repo/deploy/compose.yaml"),
        "services:\n  b:\n    image: alpine\n    build: ..\n    volumes:\n      - ../data:/data\n",
    )
    .expect("write compose");
    let run = |extra: &[&str]| -> (bool, String) {
        let mut args: Vec<String> = vec!["compose".into()];
        args.extend(extra.iter().map(|s| (*s).to_string()));
        args.extend(["-f".into(), "deploy/compose.yaml".into(), "config".into()]);
        let out = kern()
            .current_dir(root.join("repo"))
            .env_remove("COMPOSE_PROFILES")
            .args(&args)
            .output()
            .expect("run kern");
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let (plain_ok, plain) = run(&[]);
    let repo = root.join("repo").to_string_lossy().into_owned();
    let (wide_ok, wide) = run(&["--project-root", &repo]);
    let other = root.join("elsewhere").to_string_lossy().into_owned();
    let (other_ok, other_said) = run(&["--project-root", &other]);
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        !plain_ok && plain.contains("--project-root"),
        "the default refuses, and the refusal names the way to widen it:\n{plain}"
    );
    assert!(
        wide_ok,
        "the operator's root lets the file's paths reach it:\n{wide}"
    );
    assert!(
        !other_ok && other_said.contains("does not contain"),
        "a root beside the project is refused:\n{other_said}"
    );
}

/// `kern compose <verb> <service>` WITH NO FILE is docker's spelling: the word after the verb is a
/// service and the file is found in the directory. MEASURED in the field: `kern compose up -d
/// immich-machine-learning`, typed as immich's docs write it, answered "reading
/// immich-machine-learning: No such file or directory".
#[test]
fn a_word_after_the_compose_verb_is_a_service_and_the_file_is_discovered() {
    let dir = std::env::temp_dir().join(format!("kern-smoke-disc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(
        dir.join("docker-compose.yml"),
        "services:\n  web:\n    image: alpine\n",
    )
    .expect("write");
    let out = kern()
        .current_dir(&dir)
        .env_remove("COMPOSE_PROFILES")
        .args(["compose", "ps", "web"])
        .output()
        .expect("run kern");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !said.contains("reading web"),
        "the service name was read as a compose file:\n{said}"
    );
    assert!(out.status.success(), "{said}");
}

/// ⛔ A COMPOSE FILE CONNECTS NO BUILD TO A HOST SOCKET. FOUND BY AUDIT, rootless: `build.ssh:
/// [x=<a socket in the project>]` and a `RUN --mount=type=ssh` reached the listener, and the same
/// way the user's systemd manager or a docker socket. `-v` refuses a socket; so does `build.ssh`
/// now, unless it is the operator's own agent. The listener is real here, and nothing may connect.
#[test]
fn compose_build_ssh_never_reaches_a_host_socket_the_file_names() {
    let dir = std::env::temp_dir().join(format!("kern-smoke-sshsock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let listener =
        std::os::unix::net::UnixListener::bind(dir.join("host.sock")).expect("bind a socket");
    listener.set_nonblocking(true).expect("nonblocking");
    std::fs::write(
        dir.join("Dockerfile"),
        "FROM scratch\nRUN --mount=type=ssh,id=x true\n",
    )
    .expect("write");
    std::fs::write(
        dir.join("compose.yaml"),
        "services:\n  a:\n    image: kern-smoke-sshsock:1\n    build:\n      context: .\n      ssh:\n        - x=./host.sock\n",
    )
    .expect("write");
    let out = kern()
        .current_dir(&dir)
        .env_remove("SSH_AUTH_SOCK")
        .args(["compose", "build"])
        .output()
        .expect("run kern");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let connected = listener.accept().is_ok();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !out.status.success() && said.contains("not your SSH agent"),
        "a compose file's socket was accepted for a build:\n{said}"
    );
    assert!(
        !connected,
        "something connected to the host socket:\n{said}"
    );
}

/// `compose up <svc>` BUILDS ONLY WHAT IT STARTS, as docker does. MEASURED in the field: `up ollama
/// ollama-webui` on valiantlynx/ollama-docker built the file's `app` service too. Here the other
/// service's build would fail outright, so trying it at all is visible.
#[test]
fn compose_up_of_one_service_does_not_build_the_others() {
    let dir = std::env::temp_dir().join(format!("kern-smoke-onlybuild-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(
        dir.join("compose.yaml"),
        "services:\n  a:\n    build: ./no-such-context\n  b:\n    image: kern-smoke-no-such-image:1\n",
    )
    .expect("write");
    let out = kern()
        .current_dir(&dir)
        .env_remove("COMPOSE_PROFILES")
        .args(["compose", "up", "-d", "--pull", "never", "b"])
        .output()
        .expect("run kern");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !said.contains("no-such-context"),
        "the service that was not asked for was built:\n{said}"
    );
}

/// ⛔ `image:` + `build:` FOLLOWS DOCKER, MEASURED with Compose v5.0.2: an image that is here (or can
/// be pulled) is used and not rebuilt, one that is not is built, and `--build` builds. kern built
/// every time, so open-webui's `up` was a full build from source where docker downloads the image.
/// Offline: `pull_policy: never`, so "not here" can only mean "build it".
#[test]
fn compose_image_and_build_uses_the_image_when_it_exists_as_docker_does() {
    let dir = std::env::temp_dir().join(format!("kern-smoke-g4-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("ctx")).expect("dir");
    std::fs::write(dir.join("ctx/Dockerfile"), "FROM scratch\nCOPY f /f\n").expect("write");
    std::fs::write(dir.join("ctx/f"), "x").expect("write");
    std::fs::write(
        dir.join("compose.yaml"),
        "services:\n  s:\n    image: kern-smoke-g4:1\n    build: ./ctx\n    pull_policy: never\n    command: [\"/f\"]\n",
    )
    .expect("write");
    let up = |extra: &[&str]| {
        let mut args = vec!["compose", "-f", "compose.yaml", "up", "-d"];
        args.extend_from_slice(extra);
        let out = kern()
            .current_dir(&dir)
            .env("XDG_CACHE_HOME", dir.join("cache"))
            .env("XDG_DATA_HOME", dir.join("data"))
            .env_remove("COMPOSE_PROFILES")
            .args(&args)
            .output()
            .expect("run kern");
        let _ = kern()
            .current_dir(&dir)
            .env("XDG_CACHE_HOME", dir.join("cache"))
            .env("XDG_DATA_HOME", dir.join("data"))
            .args(["compose", "-f", "compose.yaml", "down"])
            .output();
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };
    let first = up(&[]);
    let second = up(&[]);
    let forced = up(&["--build"]);
    let _ = std::fs::remove_dir_all(&dir);
    if first.contains("user namespaces") {
        eprintln!("skip: no user namespaces to build in: {first}");
        return;
    }
    assert!(
        first.contains("is not available") && first.contains("built 'kern-smoke-g4:1'"),
        "an image that is not here was not built:\n{first}"
    );
    assert!(
        second.contains("using the published image") && !second.contains("built 'kern-smoke-g4:1'"),
        "an image that is here was built again:\n{second}"
    );
    assert!(
        forced.contains("built 'kern-smoke-g4:1'"),
        "`--build` did not build:\n{forced}"
    );
}

/// ⛔ A SERVICE THAT RUNS ITS PUBLISHED IMAGE IS NOT REFUSED FOR A BUILD CONTEXT IT NEVER READS.
/// InvokeAI builds from `..` and names its published image; docker uses the image. The context
/// guard still applies the moment a build is asked for.
#[test]
fn an_unread_build_context_outside_the_project_is_not_refused() {
    let dir = std::env::temp_dir().join(format!("kern-smoke-ctxout-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("proj/docker")).expect("dir");
    std::fs::write(dir.join("proj/Dockerfile"), "FROM scratch\nCOPY f /f\n").expect("write");
    std::fs::write(dir.join("proj/f"), "x").expect("write");
    std::fs::write(
        dir.join("proj/docker/compose.yaml"),
        "services:\n  s:\n    image: kern-smoke-ctxout:1\n    build:\n      context: ..\n    pull_policy: never\n    command: [\"/f\"]\n",
    )
    .expect("write");
    let compose = |extra: &[&str]| {
        let mut args = vec!["compose", "-f", "compose.yaml"];
        args.extend_from_slice(extra);
        let out = kern()
            .current_dir(dir.join("proj/docker"))
            .env("XDG_CACHE_HOME", dir.join("cache"))
            .env("XDG_DATA_HOME", dir.join("data"))
            .env_remove("COMPOSE_PROFILES")
            .args(&args)
            .output()
            .expect("run kern");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };
    // Put the image in place the way a published one would be: built once, explicitly allowed.
    let seeded = compose(&["--project-root", "..", "build"]);
    let up = compose(&["up", "-d"]);
    let _ = compose(&["down"]);
    let forced = compose(&["up", "-d", "--build"]);
    let _ = compose(&["down"]);
    let _ = std::fs::remove_dir_all(&dir);
    if seeded.contains("user namespaces") {
        eprintln!("skip: no user namespaces to build in: {seeded}");
        return;
    }
    assert!(
        seeded.contains("built 'kern-smoke-ctxout:1'"),
        "the fixture image was not built:\n{seeded}"
    );
    assert!(
        up.contains("using the published image") && !up.contains("escapes the compose directory"),
        "a context nothing reads was refused:\n{up}"
    );
    assert!(
        forced.contains("escapes the compose directory"),
        "`--build` with a context outside the project was not refused:\n{forced}"
    );
}

/// ⛔ INSIDE A GIT REPOSITORY THE REPOSITORY IS THE PROJECT, AND NOTHING OUTSIDE IT IS. Kokoro-FastAPI
/// keeps its compose file in `docker/gpu/` and binds `../../web`; docker accepts it, and kern refused
/// it until `--project-root`. A path leaving the repository is still refused, and a repository that
/// holds the home directory (a dotfiles repository) widens nothing.
#[test]
fn a_compose_file_in_a_git_repository_may_reach_the_repository_and_nothing_else() {
    let dir = std::env::temp_dir().join(format!("kern-smoke-gitroot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let repo = dir.join("repo");
    std::fs::create_dir_all(repo.join(".git")).expect("dir");
    std::fs::create_dir_all(repo.join("docker/gpu")).expect("dir");
    std::fs::create_dir_all(repo.join("web")).expect("dir");
    std::fs::create_dir_all(dir.join("outside")).expect("dir");
    let config = |bind: &str, home: &std::path::Path| {
        std::fs::write(
            repo.join("docker/gpu/compose.yaml"),
            format!("services:\n  s:\n    image: alpine:3.19\n    volumes:\n      - {bind}:/d\n"),
        )
        .expect("write");
        let out = kern()
            .current_dir(repo.join("docker/gpu"))
            .env("HOME", home)
            .env_remove("COMPOSE_PROFILES")
            .args(["compose", "-f", "compose.yaml", "config"])
            .output()
            .expect("run kern");
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let elsewhere = dir.join("home");
    std::fs::create_dir_all(&elsewhere).expect("dir");
    let (in_ok, in_out) = config("../../web", &elsewhere);
    let (out_ok, out_out) = config("../../../outside", &elsewhere);
    let (dot_ok, dot_out) = config("../../web", &repo);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        in_ok && in_out.contains("the project is the git repository"),
        "a path inside the repository was refused:\n{in_out}"
    );
    assert!(
        !out_ok,
        "a path outside the repository was accepted:\n{out_out}"
    );
    assert!(
        !dot_ok,
        "a repository holding HOME widened the project:\n{dot_out}"
    );
}

/// ⛔ `compose exec` IS NOT A DEVICE GRANT: it enters a box the `up` already granted (or refused).
/// MEASURED in the field: jellyfin came up with `--allow-device-grants`, and every `compose exec`
/// after it was refused for a GPU it was not asking for. With nothing running the answer must be
/// "not running", never the grant gate.
#[test]
fn compose_exec_is_not_refused_by_the_device_grant_gate() {
    let dir = std::env::temp_dir().join(format!("kern-smoke-execgate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(
        dir.join("compose.yaml"),
        "services:\n  g:\n    image: kern-smoke-no-such-image:1\n    gpus: all\n",
    )
    .expect("write");
    let out = kern()
        .current_dir(&dir)
        .env_remove("COMPOSE_PROFILES")
        .args(["compose", "-f", "compose.yaml", "exec", "-T", "g", "true"])
        .output()
        .expect("run kern");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !said.contains("nothing granted it"),
        "`compose exec` met the device grant gate:\n{said}"
    );
}

/// ⛔ A BIND KERN WILL REFUSE IS REFUSED BEFORE ANYTHING IS BUILT OR PULLED. Kokoro-FastAPI's file
/// downloaded its image for nine minutes and was then refused for a bind outside the project.
#[test]
fn a_refused_bind_is_refused_before_any_build() {
    let dir = std::env::temp_dir().join(format!("kern-smoke-bindfirst-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("proj/ctx")).expect("dir");
    std::fs::create_dir_all(dir.join("outside")).expect("dir");
    std::fs::write(dir.join("proj/ctx/Dockerfile"), "FROM scratch\nCOPY f /f\n").expect("write");
    std::fs::write(dir.join("proj/ctx/f"), "x").expect("write");
    std::fs::write(
        dir.join("proj/compose.yaml"),
        "services:\n  s:\n    build: ./ctx\n    volumes:\n      - ../outside:/o\n",
    )
    .expect("write");
    let out = kern()
        .current_dir(dir.join("proj"))
        .env("XDG_CACHE_HOME", dir.join("cache"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .env_remove("COMPOSE_PROFILES")
        .args(["compose", "-f", "compose.yaml", "up", "-d"])
        .output()
        .expect("run kern");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !out.status.success() && said.contains("outside"),
        "the bind outside the project was not refused:\n{said}"
    );
    assert!(
        !said.contains("built '"),
        "the service was built before its bind was refused:\n{said}"
    );
}

/// ⛔ A REGISTRY THAT CANNOT BE REACHED IS NOT A REGISTRY SAYING NO. With `image:` + `build:`, kern
/// builds from source when the registry refuses the image (docker's rule); a transfer that broke is
/// no answer about the image, and building the project from source on a line that just failed is the
/// slowest way to fail. MEASURED in the field on Kokoro-FastAPI's file.
#[test]
fn an_unreachable_registry_does_not_turn_into_a_build_from_source() {
    let dir = std::env::temp_dir().join(format!("kern-smoke-unreach-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("ctx")).expect("dir");
    std::fs::write(dir.join("ctx/Dockerfile"), "FROM scratch\nCOPY f /f\n").expect("write");
    std::fs::write(dir.join("ctx/f"), "x").expect("write");
    std::fs::write(
        dir.join("compose.yaml"),
        "services:\n  s:\n    image: 127.0.0.1:1/kern-smoke/unreachable:1\n    build: ./ctx\n",
    )
    .expect("write");
    let out = kern()
        .current_dir(&dir)
        .env("XDG_CACHE_HOME", dir.join("cache"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .env_remove("COMPOSE_PROFILES")
        .args(["compose", "-f", "compose.yaml", "up", "-d"])
        .output()
        .expect("run kern");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = kern()
        .current_dir(&dir)
        .env("XDG_CACHE_HOME", dir.join("cache"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .args(["compose", "-f", "compose.yaml", "down"])
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !out.status.success() && said.contains("could not be fetched"),
        "an unreachable registry was not reported as such:\n{said}"
    );
    assert!(
        !said.contains("built '"),
        "an unreachable registry was taken as \"build it from source\":\n{said}"
    );
}

/// ⛔ A MISSING `env_file:` STOPS THE FILE BEFORE ANYTHING IS FETCHED, as docker's loader stops it
/// ("env file <path> not found", measured with docker compose v5.0.2). kern found out when the box
/// started, after InvokeAI's multi-GB image had been downloaded. The image here is on a registry
/// that cannot be reached, so a fetch attempted first would answer with a different error.
#[test]
fn a_missing_env_file_stops_config_and_up_before_any_fetch() {
    let dir = std::env::temp_dir().join(format!("kern-smoke-envfile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(
        dir.join("compose.yaml"),
        "services:\n  s:\n    image: 127.0.0.1:1/kern-smoke/envfile:1\n    env_file:\n      - .env\n  t:\n    image: 127.0.0.1:1/kern-smoke/optional:1\n    env_file:\n      - path: ./absent.env\n        required: false\n",
    )
    .expect("write");
    let run = |args: &[&str]| {
        let out = kern()
            .current_dir(&dir)
            .env("XDG_CACHE_HOME", dir.join("cache"))
            .env("XDG_DATA_HOME", dir.join("data"))
            .env_remove("COMPOSE_PROFILES")
            .args(args)
            .output()
            .expect("run kern");
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let (cfg_ok, cfg) = run(&["compose", "-f", "compose.yaml", "config"]);
    let (up_ok, up) = run(&["compose", "-f", "compose.yaml", "up", "-d", "s"]);
    let (_, optional) = run(&["compose", "-f", "compose.yaml", "up", "-d", "t"]);
    let _ = std::fs::remove_dir_all(&dir);
    for (ok, said, verb) in [(cfg_ok, &cfg, "config"), (up_ok, &up, "up")] {
        assert!(
            !ok && said.contains("env file") && said.contains(".env not found"),
            "{verb} did not stop on the missing env file:\n{said}"
        );
        assert!(
            !said.contains("could not be fetched") && !said.contains("curl"),
            "{verb} fetched before reading the file:\n{said}"
        );
    }
    assert!(
        !optional.contains("absent.env not found"),
        "`required: false` was refused:\n{optional}"
    );
}

/// `up --abort-on-container-exit --exit-code-from tests` ENDS WHEN THE TEST DOES, with its status.
///
/// MEASURED before the fix with `redis` and a `redis-cli ping` test: a test that exited before `up`
/// began following the logs was skipped, its output never shown, and `up` waited on the database
/// until the CI job's own timeout. One that exited inside the 150 ms start window was reported as
/// "died", exited 1 whatever it returned, and left the database running.
///
/// Three tests, each against a `db` that never exits on its own: a fast one that prints and exits 3,
/// a SILENT one that exits 4 (no log file to follow), and a slow one that exits 0. Each `up` is
/// given a deadline and killed past it, so a hang fails here instead of hanging the suite.
#[test]
fn abort_on_container_exit_returns_the_tests_own_status() {
    let dir = std::env::temp_dir().join(format!("kern-it-abort-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    if std::fs::create_dir_all(&dir).is_err() {
        eprintln!("SKIP: could not create a temp project dir");
        return;
    }
    let xdg = std::env::temp_dir().join(format!("kern-it-abort-xdg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&xdg);
    let _ = std::fs::create_dir_all(&xdg);
    let run_within = |args: &[&str], secs: u64| -> (String, Option<i32>, bool) {
        let mut child = match kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return (e.to_string(), None, false),
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        let mut hung = false;
        while matches!(child.try_wait(), Ok(None)) {
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                hung = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        match child.wait_with_output() {
            Ok(out) => (
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ),
                out.status.code(),
                hung,
            ),
            Err(e) => (e.to_string(), None, hung),
        }
    };
    let stack = |test_cmd: &str| {
        format!(
            "services:\n  db:\n    image: alpine\n    command: [\"sleep\", \"300\"]\n  tests:\n    \
             image: alpine\n    command: [\"sh\", \"-c\", \"{test_cmd}\"]\n"
        )
    };
    // THE CONTROL: the stack must come up at all on this host, or nothing below can be measured.
    if std::fs::write(dir.join("compose.yml"), stack("sleep 1")).is_err() {
        eprintln!("SKIP: could not write the compose file");
        return;
    }
    let (out, _, _) = run_within(
        &["compose", "-f", "compose.yml", "-p", "abortctl", "up", "-d"],
        60,
    );
    let _ = run_within(
        &["compose", "-f", "compose.yml", "-p", "abortctl", "down"],
        60,
    );
    if !out.contains("box(es) started") {
        eprintln!("SKIP: this host did not bring the control stack up ({out})");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&xdg);
        return;
    }
    let mut failures = Vec::new();
    for (cmd, want, marker) in [
        ("echo T-FAST; exit 3", 3, Some("T-FAST")),
        ("exit 4", 4, None),
        ("sleep 2; echo T-SLOW", 0, Some("T-SLOW")),
    ] {
        let _ = std::fs::write(dir.join("compose.yml"), stack(cmd));
        let args = [
            "compose",
            "-f",
            "compose.yml",
            "-p",
            "abortit",
            "up",
            "--abort-on-container-exit",
            "--exit-code-from",
            "tests",
        ];
        let (out, code, hung) = run_within(&args, 60);
        let (ps, _, _) = run_within(&["ps"], 30);
        let _ = run_within(
            &["compose", "-f", "compose.yml", "-p", "abortit", "down"],
            60,
        );
        if hung {
            failures.push(format!("`{cmd}`: up did not return within 60 s:\n{out}"));
        } else if code != Some(want) {
            failures.push(format!("`{cmd}`: exit {code:?}, want {want}:\n{out}"));
        }
        if marker.is_some_and(|m| !out.contains(m)) {
            failures.push(format!("`{cmd}`: the test's output was not shown:\n{out}"));
        }
        if ps.contains("abortit-db") {
            failures.push(format!("`{cmd}`: the stack was left running:\n{ps}"));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    assert!(failures.is_empty(), "{}", failures.join("\n---\n"));
}

/// A PUBLISHED PORT REACHES THE BOX'S ADDRESS, AND THE BOX'S NAME IS THAT ADDRESS, as under Docker.
///
/// MEASURED before: `-p` forwarded to the box's `127.0.0.1`, from `127.0.0.1`. A listener bound to
/// loopback only answered 200 to a LAN client, a Redis in protected mode answered `+PONG` to one, and
/// a box's own name resolved to `127.0.0.1` (or, on an image shipping `/etc/hosts`, not at all).
///
/// Two boxes on alpine's `nc`, one bound to `127.0.0.1`, one to every interface: the second is the
/// CONTROL, so a host where nothing can be published at all skips instead of passing. Then the name,
/// standalone and in a pod.
#[test]
fn a_published_port_reaches_the_box_address_and_the_name_is_that_address() {
    let xdg = std::env::temp_dir().join(format!("kern-it-boxaddr-xdg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&xdg);
    let _ = std::fs::create_dir_all(&xdg);
    let run = |args: &[&str]| -> (String, Option<i32>) {
        match kern().env("XDG_RUNTIME_DIR", &xdg).args(args).output() {
            Ok(o) => (
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
                o.status.code(),
            ),
            Err(e) => (e.to_string(), None),
        }
    };
    let free = || {
        std::net::TcpListener::bind(("127.0.0.1", 0))
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .unwrap_or(0)
    };
    let fetch = |port: u16| -> String {
        use std::io::Read;
        for _ in 0..30 {
            if let Ok(mut c) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(3)));
                let mut s = String::new();
                let _ = c.read_to_string(&mut s);
                if !s.is_empty() {
                    return s;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        String::new()
    };
    let serve = |bind: &str, word: &str| {
        format!("while true; do echo {word} | nc -l -s {bind} -p 81 >/dev/null 2>&1; done")
    };
    let (lo_port, any_port) = (free(), free());
    let lo_map = format!("{lo_port}:81");
    let any_map = format!("{any_port}:81");
    let lo_cmd = serve("127.0.0.1", "LO-ONLY");
    let any_cmd = serve("0.0.0.0", "ANY-IF");
    let _ = run(&[
        "box", "smlo", "-d", "-p", &lo_map, "--image", "alpine", "--", "sh", "-c", &lo_cmd,
    ]);
    let _ = run(&[
        "box", "smany", "-d", "-p", &any_map, "--image", "alpine", "--", "sh", "-c", &any_cmd,
    ]);
    let any = fetch(any_port);
    // Only a few tries for the loopback one: the control above already waited for the box to be up.
    let lo = {
        use std::io::Read;
        let mut s = String::new();
        if let Ok(mut c) = std::net::TcpStream::connect(("127.0.0.1", lo_port)) {
            let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(3)));
            let _ = c.read_to_string(&mut s);
        }
        s
    };
    // A box that PUBLISHES has the address and its name resolves to it; one with nothing to reach
    // it skips the address, and its name stays on loopback (that is what spares the SDK's cells).
    let name_port = format!("{}:81", free());
    let (name_alone, _) = run(&[
        "box",
        "--rm",
        "-p",
        &name_port,
        "--image",
        "alpine",
        "--",
        "sh",
        "-c",
        "getent hosts $(hostname)",
    ]);
    let (name_plain, _) = run(&[
        "box",
        "--rm",
        "--image",
        "alpine",
        "--",
        "sh",
        "-c",
        "getent hosts $(hostname); ip -4 addr",
    ]);
    let _ = run(&["pod", "create", "smaddr"]);
    let (name_pod, _) = run(&[
        "box", "smmember", "--rm", "--pod", "smaddr", "--image", "alpine", "--", "getent", "hosts",
        "smmember",
    ]);
    let _ = run(&["stop", "smlo"]);
    let _ = run(&["stop", "smany"]);
    let _ = run(&["pod", "rm", "smaddr"]);
    let _ = std::fs::remove_dir_all(&xdg);
    if !any.contains("ANY-IF") {
        eprintln!(
            "SKIP: this host did not publish the control box's port, so it cannot show the rule"
        );
        return;
    }
    assert!(
        !lo.contains("LO-ONLY"),
        "a listener on the box's 127.0.0.1 only was published: {lo:?}"
    );
    assert!(
        name_alone.contains("192.0.0.8"),
        "a box's own name must resolve to its address: {name_alone:?}"
    );
    assert!(
        name_plain.contains("127.0.0.1") && !name_plain.contains("192.0.0.8"),
        "a box with nothing to reach it must not pay for an address: {name_plain:?}"
    );
    assert!(
        name_pod.contains("192.0.0.8"),
        "a pod member's name must resolve to the pod's address: {name_pod:?}"
    );
}

/// `network_mode: service:X` JOINS X's NETWORK NAMESPACE in a stack with a namespace per service, as
/// under Docker.
///
/// MEASURED before: on a bridge stack the key was not honoured at all (kern said so), so a client put
/// behind a VPN container got a namespace, an address and a route of its own and reached the network
/// directly. Docker, same file: one namespace inode for both, the client sees the VPN's loopback, a
/// peer reaches the client's port at the VPN's name and does not resolve the client's.
///
/// Three services (a third makes the stack a bridge by default). The control is the target's own
/// line: if it never prints, the host cannot run the stack and this skips. Then the refusal Docker
/// makes for `ports:` on a joining service, in Docker's words.
#[test]
fn network_mode_service_joins_the_named_services_namespace() {
    let dir = std::env::temp_dir().join(format!("kern-it-join-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    if std::fs::create_dir_all(&dir).is_err() {
        eprintln!("SKIP: could not create a temp project dir");
        return;
    }
    let xdg = std::env::temp_dir().join(format!("kern-it-join-xdg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&xdg);
    let _ = std::fs::create_dir_all(&xdg);
    let run = |args: &[&str]| -> String {
        match kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(args)
            .output()
        {
            Ok(o) => format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => e.to_string(),
        }
    };
    let _ = std::fs::write(
        dir.join("compose.yml"),
        concat!(
            "services:\n",
            "  vpn:\n    image: alpine\n",
            "    command: [\"sh\", \"-c\", \"echo VPN=$$(readlink /proc/self/ns/net); ",
            "while true; do echo CTL | nc -l -s 127.0.0.1 -p 9000; done\"]\n",
            "  client:\n    image: alpine\n    network_mode: \"service:vpn\"\n",
            "    command: [\"sh\", \"-c\", \"sleep 1; echo CLIENT=$$(readlink /proc/self/ns/net) ",
            "LO=$$(nc -w 2 127.0.0.1 9000 </dev/null); sleep 30\"]\n",
            "  peer:\n    image: alpine\n",
            "    command: [\"sh\", \"-c\", \"sleep 2; getent hosts client || echo PEER=unresolved; sleep 30\"]\n",
        ),
    );
    let _ = run(&["compose", "-f", "compose.yml", "-p", "joinit", "up", "-d"]);
    let mut logs = String::new();
    for _ in 0..40 {
        logs = run(&["compose", "-f", "compose.yml", "-p", "joinit", "logs"]);
        if logs.contains("CLIENT=") && logs.contains("PEER=") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let _ = run(&["compose", "-f", "compose.yml", "-p", "joinit", "down"]);
    let _ = std::fs::write(
        dir.join("ports.yml"),
        "services:\n  vpn:\n    image: alpine\n    command: [\"sleep\", \"5\"]\n  client:\n    \
         image: alpine\n    network_mode: \"service:vpn\"\n    ports: [\"18402:80\"]\n",
    );
    let refused = run(&["compose", "-f", "ports.yml", "-p", "joinpt", "up", "-d"]);
    let _ = run(&["compose", "-f", "ports.yml", "-p", "joinpt", "down"]);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    let field = |key: &str| {
        logs.split_whitespace()
            .find_map(|w| w.strip_prefix(key))
            .unwrap_or("")
            .to_string()
    };
    let (vpn, client) = (field("VPN="), field("CLIENT="));
    if vpn.is_empty() {
        eprintln!(
            "SKIP: this host did not bring the stack up, so it cannot show the join:\n{logs}"
        );
        return;
    }
    assert_eq!(
        client, vpn,
        "the client must be in the vpn's network namespace:\n{logs}"
    );
    assert_eq!(field("LO="), "CTL", "and see the vpn's loopback:\n{logs}");
    assert!(
        logs.contains("PEER=unresolved"),
        "a peer does not resolve a joining service:\n{logs}"
    );
    assert!(
        refused.contains("conflicting options: port publishing"),
        "ports on a joining service are refused as Docker refuses them:\n{refused}"
    );
}

/// A BOX WITH OUTBOUND NEVER REACHES WHAT THE HOST KEEPS ON LOOPBACK, by any road out of it.
///
/// MEASURED before the fix, against the real loopback-only services of a development machine (the
/// shape of `kubectl port-forward`, a kind API, a local database): a box in a pod opened 12 of 21
/// tries across 7 such ports, through the gateway pasta answered for and through `host-gateway`.
/// After: 0 of 21, in a pod, on a compose bridge and under `--no-pod`, with `--net` as the control
/// that reached all 7.
///
/// The test owns both listeners, so it needs no service of the host's: one on `127.0.0.1` (must stay
/// shut) and one on every interface (the CONTROL: it must open through `host-gateway`, or this host
/// gives a pod no outbound and the test skips instead of passing).
#[test]
fn a_pod_box_never_reaches_the_hosts_loopback() {
    use std::io::Write as _;
    let Ok(lo) = std::net::TcpListener::bind(("127.0.0.1", 0)) else {
        eprintln!("SKIP: could not bind a loopback listener");
        return;
    };
    let Ok(any) = std::net::TcpListener::bind(("0.0.0.0", 0)) else {
        eprintln!("SKIP: could not bind a wildcard listener");
        return;
    };
    let lo_port = lo.local_addr().map(|a| a.port()).unwrap_or(0);
    let any_port = any.local_addr().map(|a| a.port()).unwrap_or(0);
    for l in [lo, any] {
        std::thread::spawn(move || {
            for mut c in l.incoming().flatten() {
                let _ = c.write_all(b"HOST\n");
            }
        });
    }
    let xdg = std::env::temp_dir().join(format!("kern-it-hostlo-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let run = |args: &[&str]| -> String {
        match kern().env("XDG_RUNTIME_DIR", &xdg).args(args).output() {
            Ok(o) => format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => e.to_string(),
        }
    };
    let probe = format!(
        "gw=$(ip route | awk '/^default/{{print $3; exit}}'); hg=$(awk '$2==\"hg\"{{print $1; exit}}' /etc/hosts); \
         for r in $gw $hg; do nc -z -w 3 $r {lo_port} && echo LO-OPEN-$r; done; \
         nc -z -w 3 $hg {any_port} && echo CONTROL-OPEN; echo DONE"
    );
    let _ = run(&["pod", "create", "hostlo"]);
    let out = run(&[
        "box",
        "--rm",
        "--pod",
        "hostlo",
        "--add-host",
        "hg:host-gateway",
        "--image",
        "alpine",
        "--",
        "sh",
        "-c",
        &probe,
    ]);
    let _ = run(&["pod", "rm", "hostlo"]);
    let _ = std::fs::remove_dir_all(&xdg);
    if !out.contains("CONTROL-OPEN") {
        eprintln!(
            "SKIP: a pod box here cannot reach the host at all, so the rule cannot show:\n{out}"
        );
        return;
    }
    assert!(
        !out.contains("LO-OPEN"),
        "a pod box reached a listener the host keeps on 127.0.0.1:\n{out}"
    );
}

/// `--ssh` ON A TAKEN PORT PRINTS NO `ssh` COMMAND AND LEAVES NO KEYS.
///
/// MEASURED before: a second box asking for an `--ssh` port another box held printed a ready-to-paste
/// `kern: ssh: ssh -p ...` line for a box that never ran, then the refusal, and its key directory
/// stayed in the runtime dir. The port is held here by the test itself, so no sshd is needed: the
/// refusal comes before anything starts.
#[test]
fn an_ssh_box_on_a_taken_port_prints_no_command_and_leaves_no_keys() {
    let Ok(held) = std::net::TcpListener::bind(("127.0.0.1", 0)) else {
        eprintln!("SKIP: could not hold a port");
        return;
    };
    let port = held.local_addr().map(|a| a.port()).unwrap_or(0).to_string();
    let xdg = std::env::temp_dir().join(format!("kern-it-sshport-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let out = match kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box", "sshtaken", "--ssh", &port, "--image", "alpine", "--", "true",
        ])
        .output()
    {
        Ok(o) => format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => e.to_string(),
    };
    let keys_left = xdg.join("kern/ssh/sshtaken").exists();
    let _ = std::fs::remove_dir_all(&xdg);
    drop(held);
    if !out.contains("cannot publish host port") {
        eprintln!("SKIP: the refusal this test is about did not happen here:\n{out}");
        return;
    }
    assert!(
        !out.contains("kern: ssh: ssh -p"),
        "no ssh command for a box that never ran:\n{out}"
    );
    assert!(!keys_left, "the refused box's keys must be removed");
}

/// A PORT WITH NO HOST NUMBER IS PUBLISHED ON ONE THE KERNEL PICKS, as Docker publishes it.
///
/// MEASURED against `docker run -p`: `80`, `ip::80` and `0:80` publish on a host port Docker picks,
/// the same number for `0.0.0.0` and `[::]`, and `docker port` lists every binding. kern refused all
/// three with its usage line, and compose turned `ports: ["80"]` into a port that was not published,
/// which is how one file runs as several stacks at once (one per pull request). Asserted here: the
/// box answers on the port `kern port` reports, every line carries the same number, and two compose
/// projects of one file get two different ports.
#[test]
fn a_port_with_no_host_number_is_published_on_a_picked_one() {
    use std::io::Read;
    let xdg = std::env::temp_dir().join(format!("kern-it-rport-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let dir = std::env::temp_dir().join(format!("kern-it-rport-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let run = |args: &[&str]| -> (String, String) {
        match kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(args)
            .output()
        {
            Ok(o) => (
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            ),
            Err(e) => (String::new(), e.to_string()),
        }
    };
    let serve = "while true; do echo PICKED | nc -l -p 80 >/dev/null 2>&1; done";
    let (_, started) = run(&[
        "box", "rport", "-d", "-p", "80", "--image", "alpine", "--", "sh", "-c", serve,
    ]);
    let (lines, _) = run(&["port", "rport", "80"]);
    let ports: Vec<u16> = lines
        .lines()
        .filter_map(|l| l.rsplit(':').next())
        .filter_map(|p| p.trim().parse().ok())
        .collect();
    let mut answer = String::new();
    if let Some(p) = ports.first() {
        for _ in 0..20 {
            if let Ok(mut c) = std::net::TcpStream::connect(("127.0.0.1", *p)) {
                let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(3)));
                let _ = c.read_to_string(&mut answer);
                if !answer.is_empty() {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
    let _ = run(&["stop", "rport"]);
    let _ = std::fs::write(
        dir.join("compose.yml"),
        "services:\n  web:\n    image: alpine\n    command: [\"sleep\", \"30\"]\n    ports: [\"80\"]\n",
    );
    let _ = run(&["compose", "-f", "compose.yml", "-p", "rpa", "up", "-d"]);
    let _ = run(&["compose", "-f", "compose.yml", "-p", "rpb", "up", "-d"]);
    let (a, _) = run(&[
        "compose",
        "-f",
        "compose.yml",
        "-p",
        "rpa",
        "port",
        "web",
        "80",
    ]);
    let (b, _) = run(&[
        "compose",
        "-f",
        "compose.yml",
        "-p",
        "rpb",
        "port",
        "web",
        "80",
    ]);
    let _ = run(&["compose", "-f", "compose.yml", "-p", "rpa", "down"]);
    let _ = run(&["compose", "-f", "compose.yml", "-p", "rpb", "down"]);
    let _ = std::fs::remove_dir_all(&xdg);
    let _ = std::fs::remove_dir_all(&dir);
    if started.contains("error") && !started.contains("publish") {
        eprintln!("SKIP: this host could not start the box:\n{started}");
        return;
    }
    assert!(
        !ports.is_empty(),
        "`kern port` must name the picked port:\n{lines}\n{started}"
    );
    assert!(
        ports.iter().all(|p| *p == ports[0] && *p != 0),
        "one number, never 0: {lines}"
    );
    assert!(
        answer.contains("PICKED"),
        "the box must answer on the picked port: {lines}"
    );
    assert!(
        !a.trim().is_empty() && !b.trim().is_empty() && a.trim() != b.trim(),
        "two projects of one file get two ports: {a:?} {b:?}"
    );
}

/// A stack whose LATER service is refused leaves neither its pod nor its earlier services behind.
///
/// MEASURED with a GPU service asking for a card the host lacks, after a cache and a web service had
/// been prepared: nothing kept running, and the pod stayed `0 up` with its holder alive, one per
/// failed CI job. Two causes, both measured: the guard that removes an empty pod ran BEFORE the gate
/// write ends closed (locals drop in reverse order), so it was itself holding the boxes it waited
/// on; and once that order is right the prepared boxes still leave a few milliseconds after the
/// gates close. The refusal here is a `mem_limit:` below what a box needs, which needs no GPU.
#[test]
fn a_later_refused_service_leaves_no_pod_behind() {
    let dir = std::env::temp_dir().join(format!("kern-it-laterref-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let xdg = std::env::temp_dir().join(format!("kern-it-laterref-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let run = |args: &[&str]| -> String {
        match kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(args)
            .output()
        {
            Ok(o) => format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => e.to_string(),
        }
    };
    let _ = std::fs::write(
        dir.join("compose.yml"),
        concat!(
            "services:\n",
            "  first:\n    image: alpine\n    command: [\"sleep\", \"60\"]\n",
            "  second:\n    image: alpine\n    depends_on: [first]\n    mem_limit: 64\n",
            "    command: [\"sleep\", \"60\"]\n",
        ),
    );
    let up = run(&["compose", "-f", "compose.yml", "-p", "laterref", "up", "-d"]);
    let pods = run(&["pod", "ls"]);
    let ps = run(&["ps"]);
    let _ = run(&["compose", "-f", "compose.yml", "-p", "laterref", "down"]);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    if !up.contains("BARE NUMBER IS BYTES") {
        eprintln!("SKIP: the refusal this test is about did not happen here:\n{up}");
        return;
    }
    assert!(
        !pods.contains("laterref"),
        "the pod outlived the failed bring-up:\n{pods}\n{up}"
    );
    assert!(
        !ps.contains("first"),
        "an earlier service outlived the failed bring-up:\n{ps}"
    );
}

/// A SERVICE'S LOG SPANS ITS RESTARTS AND ENDS AT `down`, as a container's does under Docker.
///
/// MEASURED against Docker on one file: after two `compose restart`s Docker's `logs` held three runs'
/// lines and kern's one, so the output of a run that crashed was gone once it was restarted; and
/// kern kept every run's log file after `down`. Asserted: three runs after two restarts, `--tail k`
/// the last k lines of that history for every k, one run after `down` + `up`.
#[test]
fn a_services_log_spans_its_restarts_and_ends_at_down() {
    let dir = std::env::temp_dir().join(format!("kern-it-logs-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let xdg = std::env::temp_dir().join(format!("kern-it-logs-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let run = |args: &[&str]| -> String {
        match kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(args)
            .output()
        {
            Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
            Err(_) => String::new(),
        }
    };
    let _ = std::fs::write(
        dir.join("compose.yml"),
        "services:\n  s:\n    image: alpine\n    command: [\"sh\", \"-c\", \"echo RUN-$$$$; sleep 60\"]\n",
    );
    let c = |verb: &[&str]| {
        let mut a = vec!["compose", "-f", "compose.yml", "-p", "logspan"];
        a.extend_from_slice(verb);
        run(&a)
    };
    let pause = || std::thread::sleep(std::time::Duration::from_millis(800));
    let _ = c(&["up", "-d"]);
    pause();
    let _ = c(&["restart"]);
    pause();
    let _ = c(&["restart"]);
    pause();
    let count = |s: &str| s.lines().filter(|l| l.contains("RUN-")).count();
    let full = c(&["logs"]);
    let all = count(&full);
    // `--tail k` is the last k lines of the whole history, for every k, so some k crosses from the
    // newest run into the one before it. Compared as text, not by counting `RUN-` lines: a run's log
    // can also hold kern's own start-up notes (a non-root host without cgroup delegation writes two),
    // so the lines per run are not known in advance.
    let lines: Vec<&str> = full.lines().collect();
    let tails: Vec<(usize, bool)> = (1..=lines.len())
        .map(|k| {
            let got = c(&["logs", "--tail", &k.to_string()]);
            (
                k,
                got.lines().collect::<Vec<_>>() == lines[lines.len() - k..],
            )
        })
        .collect();
    let _ = c(&["down"]);
    let _ = c(&["up", "-d"]);
    pause();
    let fresh = count(&c(&["logs"]));
    let _ = c(&["down"]);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    if all == 0 {
        eprintln!("SKIP: this host did not run the service");
        return;
    }
    assert_eq!(all, 3, "three runs after two restarts");
    let wrong: Vec<usize> = tails
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(k, _)| *k)
        .collect();
    assert!(
        wrong.is_empty(),
        "--tail k is not the last k lines for k in {wrong:?}:\n{full}"
    );
    assert_eq!(fresh, 1, "after down + up the history starts over");
}

/// A STACK LEAVES NO EXITED ROW IN `ps -a`: not after `down`, and not beside a restarted service.
///
/// MEASURED against Docker on a 1:1 run of the same files, three ways kern left one. A
/// `network_mode: service:X` sidecar was recorded with no pod, so `down` never found its record (one
/// `exit 137` row per run, four after four runs). A service that exits on its stop signal (sshd) had
/// its supervisor write the record AFTER `down` had cleared them, one run in three. And `restart`
/// left the stopped run's row beside the new box, where Docker restarts one container.
#[test]
fn a_stack_leaves_no_exited_row_after_down_or_a_restart() {
    let dir = std::env::temp_dir().join(format!("kern-it-psa-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let xdg = std::env::temp_dir().join(format!("kern-it-psa-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let run = |args: &[&str]| -> String {
        match kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(args)
            .output()
        {
            Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
            Err(_) => String::new(),
        }
    };
    let trap = "[\"sh\", \"-c\", \"trap 'exit 0' TERM; while :; do sleep 1; done\"]";
    let _ = std::fs::write(
        dir.join("compose.yml"),
        format!(
            "services:\n  s:\n    image: alpine\n    command: {trap}\n  back:\n    image: alpine\n    \
             command: {trap}\n  sidecar:\n    image: alpine\n    network_mode: \"service:back\"\n    \
             command: [\"sleep\", \"600\"]\n"
        ),
    );
    let c = |verb: &[&str]| {
        let mut a = vec!["compose", "-f", "compose.yml", "-p", "psa"];
        a.extend_from_slice(verb);
        run(&a)
    };
    let exited = || -> Vec<String> {
        run(&["ps", "-a"])
            .lines()
            .filter(|l| l.contains("psa-") && l.contains(" exit "))
            .map(str::to_string)
            .collect()
    };
    let pause = || std::thread::sleep(std::time::Duration::from_millis(600));
    let _ = c(&["up", "-d"]);
    pause();
    let ran = run(&["ps"]).contains("sidecar");
    let _ = c(&["restart", "s"]);
    pause();
    let after_restart = exited();
    let mut after_down = Vec::new();
    for _ in 0..3 {
        let _ = c(&["down"]);
        after_down.extend(exited());
        let _ = c(&["up", "-d"]);
        pause();
    }
    let _ = c(&["down"]);
    after_down.extend(exited());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    if !ran {
        eprintln!("SKIP: this host did not run the stack");
        return;
    }
    assert!(
        after_restart.is_empty(),
        "a restarted service left an exited row: {after_restart:?}"
    );
    assert!(
        after_down.is_empty(),
        "`down` left exited rows: {after_down:?}"
    );
}

/// A BOX WHOSE WORKLOAD HAS ALREADY EXITED IS NOT WAITED ON FOR ITS GRACE, and keeps its own code.
///
/// MEASURED on WSL2 as an unprivileged user without cgroup delegation: `compose down` of a service
/// that traps SIGTERM beside a `sleep` took 10.3-11.5 s in 5 runs of 12, 0.3 s in the others. The
/// stop signal ended the trapping box before the teardown loop reached it; with no reaper hold its
/// init was already reaped, and the graceful wait, given no init, slept the whole remaining grace.
/// Here `slow` holds the loop for 1 s inside its grace while `fast` exits at once, in both orders.
/// Where a reaper hold exists (a dedicated cgroup) the init stays a zombie and this passes anyway.
#[test]
fn stop_does_not_wait_the_grace_on_a_box_that_already_exited() {
    let xdg = std::env::temp_dir().join(format!("kern-it-stopgone-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let run = |args: &[&str]| -> String {
        match kern().env("XDG_RUNTIME_DIR", &xdg).args(args).output() {
            Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
            Err(_) => String::new(),
        }
    };
    let id = std::process::id();
    let (slow, fast) = (format!("stopgone-slow-{id}"), format!("stopgone-fast-{id}"));
    let start = |name: &str, on_term: &str| {
        let script = format!("trap '{on_term}' TERM; while :; do sleep 0.1; done");
        let _ = run(&[
            "box", "--image", "alpine", "-d", "--name", name, "--", "sh", "-c", &script,
        ]);
    };
    let mut timings = Vec::new();
    let mut codes = Vec::new();
    for order in [
        [slow.as_str(), fast.as_str()],
        [fast.as_str(), slow.as_str()],
    ] {
        start(&slow, "sleep 1; exit 0");
        start(&fast, "exit 0");
        std::thread::sleep(std::time::Duration::from_millis(500));
        if !run(&["ps"]).contains(&fast) {
            let _ = run(&["stop", &slow, &fast]);
            let _ = std::fs::remove_dir_all(&xdg);
            eprintln!("SKIP: this host did not run the boxes");
            return;
        }
        let t = std::time::Instant::now();
        let _ = run(&["stop", order[0], order[1]]);
        timings.push(t.elapsed());
        codes.extend(
            run(&["ps", "-a"])
                .lines()
                .filter(|l| l.contains(&fast))
                .map(str::to_string),
        );
        let _ = run(&["rm", &slow]);
        let _ = run(&["rm", &fast]);
    }
    let _ = std::fs::remove_dir_all(&xdg);
    for (i, t) in timings.iter().enumerate() {
        assert!(
            *t < std::time::Duration::from_secs(5),
            "stop order {i} took {t:?}: the grace was waited on a box that had already exited"
        );
    }
    assert!(
        codes.iter().all(|l| l.contains("exit 0")),
        "the box that exited on its signal must keep its code 0: {codes:?}"
    );
}

/// `allow_gpu_grants` IS READ FROM THE OPERATOR'S OWN `kern.toml`, AND GRANTS THE GPU ONLY.
///
/// Through the real config reader, not the decision function: with the key in the operator's config a
/// `gpus: all` service gets past the gate with no flag, while a `devices:` node in the same config is
/// still refused; without it the GPU is refused and the refusal names the key. Whether a card is then
/// found is the host's business, so the assertion is on the gate's sentence alone.
#[test]
fn allow_gpu_grants_is_read_from_the_operators_config_and_grants_the_gpu_only() {
    let base = std::env::temp_dir().join(format!("kern-it-gpugrant-{}", std::process::id()));
    let (dir, cfg_on, cfg_off, xdg) = (
        base.join("p"),
        base.join("on"),
        base.join("off"),
        base.join("xdg"),
    );
    for d in [&dir, &cfg_on.join("kern"), &cfg_off.join("kern"), &xdg] {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(
        cfg_on.join("kern/kern.toml"),
        "[kern]\nallow_gpu_grants = true\n",
    );
    let _ = std::fs::write(cfg_off.join("kern/kern.toml"), "[kern]\n");
    let _ = std::fs::write(
        dir.join("gpu.yml"),
        "services:\n  g:\n    image: alpine\n    command: [\"true\"]\n    gpus: all\n",
    );
    let _ = std::fs::write(
        dir.join("dev.yml"),
        "services:\n  d:\n    image: alpine\n    command: [\"true\"]\n    devices:\n      - \"/dev/null:/dev/null\"\n",
    );
    let up = |file: &str, cfg: &std::path::Path| -> String {
        let out = kern()
            .current_dir(&dir)
            .env("XDG_CONFIG_HOME", cfg)
            .env("XDG_RUNTIME_DIR", &xdg)
            .env_remove("KERN_CONFIG")
            .args(["compose", "-f", file, "-p", "gpugrant", "up", "-d"])
            .output();
        let _ = kern()
            .current_dir(&dir)
            .env("XDG_CONFIG_HOME", cfg)
            .env("XDG_RUNTIME_DIR", &xdg)
            .env_remove("KERN_CONFIG")
            .args(["compose", "-f", file, "-p", "gpugrant", "down"])
            .output();
        match out {
            Ok(o) => format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => e.to_string(),
        }
    };
    let gpu_on = up("gpu.yml", &cfg_on);
    let gpu_off = up("gpu.yml", &cfg_off);
    let dev_on = up("dev.yml", &cfg_on);
    let _ = std::fs::remove_dir_all(&base);
    assert!(
        !gpu_on.contains("nothing granted it"),
        "allow_gpu_grants in the operator's config grants the GPU with no flag:\n{gpu_on}"
    );
    assert!(
        gpu_off.contains("nothing granted it") && gpu_off.contains("allow_gpu_grants (GPUs only)"),
        "without the key the GPU is refused and the refusal names it:\n{gpu_off}"
    );
    assert!(
        dev_on.contains("--allow-device-grants") && dev_on.contains("/dev/null"),
        "allow_gpu_grants does not grant a `devices:` node:\n{dev_on}"
    );
}

/// `compose ps -q SERVICE` NAMES THAT SERVICE, BY AN ID THAT A RECREATE CHANGES.
///
/// MEASURED against Docker on a selective-recreate check (change one service, `up -d`, compare
/// `ps -q` of each before and after): kern recreated only the changed service, as Docker did, and the
/// check still failed, for two reasons. `ps -q stable` printed every service of the stack, and it
/// printed names, which a recreate does not change. Asserted: one line per named service; the
/// unchanged service keeps its id and the changed one gets a new one; the JSON `ID` is the same id.
#[test]
fn compose_ps_q_names_the_service_by_an_id_a_recreate_changes() {
    let dir = std::env::temp_dir().join(format!("kern-it-psq-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let xdg = std::env::temp_dir().join(format!("kern-it-psq-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let file = |mark: &str| {
        let _ = std::fs::write(
            dir.join("compose.yml"),
            format!(
                "services:\n  stable:\n    image: alpine\n    command: [\"sleep\", \"600\"]\n  moving:\n    \
                 image: alpine\n    environment:\n      MARK: {mark}\n    command: [\"sleep\", \"600\"]\n"
            ),
        );
    };
    let c = |verb: &[&str]| -> String {
        let mut a = vec!["compose", "-f", "compose.yml", "-p", "psq"];
        a.extend_from_slice(verb);
        match kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(&a)
            .output()
        {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(_) => String::new(),
        }
    };
    file("one");
    let _ = c(&["up", "-d"]);
    let (s1, m1, all) = (
        c(&["ps", "-q", "stable"]),
        c(&["ps", "-q", "moving"]),
        c(&["ps", "-q"]),
    );
    let json = c(&["ps", "--format", "json", "stable"]);
    file("two");
    let _ = c(&["up", "-d"]);
    let (s2, m2) = (c(&["ps", "-q", "stable"]), c(&["ps", "-q", "moving"]));
    let _ = c(&["down"]);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    if all.is_empty() {
        eprintln!("SKIP: this host did not run the stack");
        return;
    }
    assert_eq!(
        all.lines().count(),
        2,
        "`ps -q` lists both services: {all:?}"
    );
    assert_eq!(
        s1.lines().count(),
        1,
        "`ps -q stable` lists that service alone: {s1:?}"
    );
    assert!(
        s1.parse::<u32>().is_ok() && m1.parse::<u32>().is_ok(),
        "`ps -q` prints an id: {s1:?} {m1:?}"
    );
    assert!(
        json.contains(&format!("\"ID\":\"{s1}\"")),
        "the JSON carries the same id: {json}"
    );
    assert!(
        !json.contains("psq-moving"),
        "`ps --format json stable` is that service alone: {json}"
    );
    assert_eq!(
        s1, s2,
        "the unchanged service was not recreated, so its id is the same"
    );
    assert_ne!(
        m1, m2,
        "the changed service was recreated, so its id is new"
    );
}

/// A COMPOSE TEARDOWN LETS AN INIT THAT CANNOT HEAR SIGTERM FINISH INSIDE ITS GRACE, AS DOCKER DOES;
/// `kern stop` STILL KILLS IT AT ONCE.
///
/// MEASURED against Docker: a service whose PID 1 is Python with no SIGTERM handler (it catches only
/// SIGINT, `SigCgt 0x2`, so the kernel discards a SIGTERM to a namespace's init) printed its result
/// under Docker, which waits the grace before SIGKILL, and nothing under kern, which killed it on the
/// spot. The same init here, finishing a 2 s job in-process (no child the stop signal could reach):
/// `compose down` at 1 s must let it write its file and return well inside the 10 s grace, while
/// `kern stop` of the same box keeps its immediate kill (the SDKs stop their boxes on a deadline).
#[test]
fn compose_down_lets_a_deaf_init_finish_and_kern_stop_still_kills_it() {
    let dir = std::env::temp_dir().join(format!("kern-it-deaf-{}", std::process::id()));
    let out = dir.join("out");
    let _ = std::fs::create_dir_all(&out);
    let xdg = std::env::temp_dir().join(format!("kern-it-deaf-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let job = "import time; time.sleep(2); open('/out/done', 'w').write('DONE')";
    let _ = std::fs::write(
        dir.join("compose.yml"),
        format!(
            "services:\n  job:\n    image: python:3.12-slim\n    volumes:\n      - ./out:/out\n    command: [\"python3\", \"-c\", \"{job}\"]\n"
        ),
    );
    let run = |args: &[&str]| {
        kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    };
    let pause = || std::thread::sleep(std::time::Duration::from_millis(1000));
    let _ = run(&["compose", "-f", "compose.yml", "-p", "deaf", "up", "-d"]);
    pause();
    let ran = run(&["ps"]).contains("job");
    let t = std::time::Instant::now();
    let _ = run(&["compose", "-f", "compose.yml", "-p", "deaf", "down"]);
    let down = t.elapsed();
    let finished = std::fs::read_to_string(out.join("done")).unwrap_or_default();
    let _ = std::fs::remove_file(out.join("done"));
    let spec = format!("{}:/out", out.display());
    let name = format!("deaf-stop-{}", std::process::id());
    let _ = run(&[
        "box",
        "--image",
        "python:3.12-slim",
        "-d",
        "--name",
        &name,
        "-v",
        &spec,
        "--",
        "python3",
        "-c",
        job,
    ]);
    pause();
    let t = std::time::Instant::now();
    let _ = run(&["stop", &name]);
    let stop = t.elapsed();
    std::thread::sleep(std::time::Duration::from_millis(2500));
    let after_stop = out.join("done").exists();
    let _ = run(&["rm", &name]);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    if !ran {
        eprintln!("SKIP: this host did not run the stack");
        return;
    }
    assert_eq!(
        finished.trim(),
        "DONE",
        "compose down let the job finish inside its grace"
    );
    assert!(
        down > std::time::Duration::from_millis(500),
        "it waited for the job: {down:?}"
    );
    assert!(
        down < std::time::Duration::from_secs(6),
        "and returned when it ended: {down:?}"
    );
    assert!(
        stop < std::time::Duration::from_secs(1),
        "kern stop still kills at once: {stop:?}"
    );
    assert!(
        !after_stop,
        "so the job that kern stop ended never wrote its file"
    );
}

/// A COMPOSE TEARDOWN SIGNALS THE INIT, NOT ITS CHILDREN, AS DOCKER DOES.
///
/// MEASURED against Docker on `sh -c 'sleep 3; date > /out/done'` stopped at 1 s: the shell is PID 1
/// and cannot hear SIGTERM, Docker signals only it, so the `sleep` ran to its end and the file was
/// written 1.95 s into a 2.2 s `down`. kern signalled the whole process group, which killed the
/// `sleep` at once and ran the script's next command at stop time. Asserted: the file is written
/// when the `sleep` ends, not when `down` begins.
#[test]
fn compose_down_signals_the_init_and_not_its_children() {
    let dir = std::env::temp_dir().join(format!("kern-it-grp-{}", std::process::id()));
    let out = dir.join("out");
    let _ = std::fs::create_dir_all(&out);
    let xdg = std::env::temp_dir().join(format!("kern-it-grp-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let _ = std::fs::write(
        dir.join("compose.yml"),
        "services:\n  job:\n    image: alpine\n    volumes:\n      - ./out:/out\n    \
         command: [\"sh\", \"-c\", \"sleep 2; echo DONE > /out/done\"]\n",
    );
    let c = |verb: &[&str]| {
        let mut a = vec!["compose", "-f", "compose.yml", "-p", "grp"];
        a.extend_from_slice(verb);
        kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(&a)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    };
    let _ = c(&["up", "-d"]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let ran = c(&["ps"]).contains("job");
    let began = std::time::Instant::now();
    let watch = std::thread::spawn({
        let done = out.join("done");
        move || {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(8);
            while std::time::Instant::now() < until {
                if done.exists() {
                    return Some(std::time::Instant::now());
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            None
        }
    });
    let _ = c(&["down"]);
    let written = watch.join().ok().flatten();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    if !ran {
        eprintln!("SKIP: this host did not run the stack");
        return;
    }
    let at = written.map(|w| w.duration_since(began));
    assert!(
        at.is_some_and(|a| a > std::time::Duration::from_millis(900)),
        "the file is written when the `sleep` ends (about 1.5 s in), not at the stop signal: {at:?}"
    );
}

/// `compose top` IS DOCKER'S TABLE, AND `--abort-on-container-exit` KEEPS STREAMING WHILE IT STOPS.
///
/// MEASURED against Docker Compose v5: `top` printed one table with SERVICE # UID PID PPID C STIME
/// TTY TIME CMD where kern printed PID and COMMAND under a header per service; and with one service
/// exiting at once beside one still working, Docker's `up --abort-on-container-exit` printed the
/// working service's last lines while the stack stopped, which kern, ending the follow at the first
/// exit, did not.
#[test]
fn compose_top_is_dockers_table_and_abort_streams_while_it_stops() {
    let dir = std::env::temp_dir().join(format!("kern-it-top-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let xdg = std::env::temp_dir().join(format!("kern-it-top-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let run = |args: &[&str]| -> String {
        kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    };
    let _ = std::fs::write(
        dir.join("top.yml"),
        "services:\n  ops:\n    image: alpine\n    command: [\"sleep\", \"600\"]\n",
    );
    let _ = run(&["compose", "-f", "top.yml", "-p", "toptab", "up", "-d"]);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let top = run(&["compose", "-f", "top.yml", "-p", "toptab", "top"]);
    let _ = run(&[
        "compose", "-f", "top.yml", "-p", "toptab", "down", "-t", "0",
    ]);
    let _ = std::fs::write(
        dir.join("abort.yml"),
        "services:\n  quick:\n    image: alpine\n    command: [\"true\"]\n  slow:\n    image: alpine\n    \
         command: [\"sh\", \"-c\", \"echo SLOW-START; sleep 2; echo SLOW-DONE\"]\n",
    );
    let abort = run(&[
        "compose",
        "-f",
        "abort.yml",
        "-p",
        "abortlog",
        "up",
        "--abort-on-container-exit",
    ]);
    let _ = run(&["compose", "-f", "abort.yml", "-p", "abortlog", "down"]);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    if !top.contains("ops") {
        eprintln!("SKIP: this host did not run the stack:\n{top}");
        return;
    }
    // A host with no delegated cgroup cannot list a box's processes, and `top` says so; the table
    // is then not asserted, the abort below still is.
    if !top.contains("no delegated cgroup") {
        let mut lines = top.lines();
        let header: Vec<&str> = lines
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        assert_eq!(
            header,
            ["SERVICE", "#", "UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"],
            "Docker's columns:\n{top}"
        );
        let row: Vec<&str> = lines
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        assert!(
            row.first() == Some(&"ops") && row.get(3).is_some_and(|p| p.parse::<u32>().is_ok()),
            "a row per process, service first and a numeric pid:\n{top}"
        );
    }
    assert!(
        abort.contains("SLOW-START") && abort.contains("SLOW-DONE"),
        "the working service's lines are streamed while the stack stops:\n{abort}"
    );
}

/// A COMPOSE STOP OF A `restart: always` SERVICE THAT EXITS ON ITS SIGNAL DOES NOT BRING IT BACK.
///
/// A compose stop signals the init alone, as Docker does, so the supervisor never hears it and would
/// restart a workload that exited on SIGTERM; it is ended once the workload has. Asserted against the
/// shape Docker was measured on (a `trap 'exit 0' TERM` loop under `restart: always`): nothing of the
/// stack is running three seconds after `down`, past the restart policy's first one-second backoff.
#[test]
fn compose_down_of_a_restart_always_service_does_not_bring_it_back() {
    let dir = std::env::temp_dir().join(format!("kern-it-rchk-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let xdg = std::env::temp_dir().join(format!("kern-it-rchk-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    // A marker in the workload's own command line: a box restarted after `down` removed its record is
    // invisible to `kern ps`, so the host's process table is what is read.
    let marker = format!("rchk-marker-{}", std::process::id());
    let _ = std::fs::write(
        dir.join("compose.yml"),
        format!(
            "services:\n  svc:\n    image: alpine\n    restart: always\n    \
             command: [\"sh\", \"-c\", \"trap 'exit 0' TERM; while :; do sleep 1; done\", \"{marker}\"]\n"
        ),
    );
    let run = |args: &[&str]| -> String {
        kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    };
    let running = || -> usize {
        std::fs::read_dir("/proc")
            .map(|rd| {
                rd.flatten()
                    .filter(|e| {
                        std::fs::read(e.path().join("cmdline"))
                            .is_ok_and(|c| String::from_utf8_lossy(&c).contains(&marker))
                    })
                    .count()
            })
            .unwrap_or(0)
    };
    let _ = run(&["compose", "-f", "compose.yml", "-p", "rchk", "up", "-d"]);
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let ran = running();
    let _ = run(&["compose", "-f", "compose.yml", "-p", "rchk", "down"]);
    std::thread::sleep(std::time::Duration::from_secs(4));
    let after = running();
    let _ = run(&[
        "compose",
        "-f",
        "compose.yml",
        "-p",
        "rchk",
        "down",
        "-t",
        "0",
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    if ran == 0 {
        eprintln!("SKIP: this host did not run the stack");
        return;
    }
    assert_eq!(
        after, 0,
        "no process of the service runs after `down`, restart policy or not"
    );
}

/// A MISSING BIND SOURCE IS CREATED 0755, THE MODE DOCKER'S DAEMON GIVES IT.
///
/// MEASURED on one file under both: Docker created `./shared_data` as `root:root 755`, kern as the
/// user with the user's umask (`775` under umask 002), so the group could write a directory Docker
/// keeps closed. Asserted: no group or other write bit (the umask may only take bits away).
#[test]
fn a_missing_bind_source_is_created_without_group_write() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("kern-it-mode-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let xdg = std::env::temp_dir().join(format!("kern-it-mode-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let _ = std::fs::write(
        dir.join("compose.yml"),
        "services:\n  s:\n    image: alpine\n    command: [\"true\"]\n    volumes:\n      - ./made_here:/data\n",
    );
    // UMASK 002, the common user default, under which the difference shows: with 022 the user's
    // umask alone already gives 755.
    let mut up = kern();
    up.current_dir(&dir).env("XDG_RUNTIME_DIR", &xdg).args([
        "compose",
        "-f",
        "compose.yml",
        "-p",
        "mode",
        "up",
        "--abort-on-container-exit",
    ]);
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `umask` is async-signal-safe and touches only the child's own process state.
        unsafe {
            up.pre_exec(|| {
                libc::umask(0o002);
                Ok(())
            });
        }
    }
    let _ = up.output();
    let mode = std::fs::metadata(dir.join("made_here")).map(|m| m.permissions().mode() & 0o777);
    let _ = kern()
        .current_dir(&dir)
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["compose", "-f", "compose.yml", "-p", "mode", "down"])
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    let Ok(mode) = mode else {
        eprintln!("SKIP: the bind source was not created on this host");
        return;
    };
    assert_eq!(
        mode & 0o022,
        0,
        "created {mode:o}: no group or other write, as Docker's 755"
    );
}

/// `ipc: "service:X"` SHARES X'S IPC NAMESPACE AND /dev/shm WHEN X IS `shareable`, AND IS REFUSED
/// WHEN IT IS NOT, AS DOCKER DOES BOTH.
///
/// MEASURED against Docker Compose v5 on one file: the consumer read what the producer wrote to
/// `/dev/shm` with the producer `ipc: shareable`, and Docker refused the file with "non-shareable
/// IPC" without it. kern applied neither: every service kept its own IPC namespace and `/dev/shm`,
/// with a warning. Asserted: the data, the SAME IPC namespace inode on both sides, and the refusal.
#[test]
fn ipc_service_shares_a_shareable_donors_namespace_and_shm() {
    let dir = std::env::temp_dir().join(format!("kern-it-ipc-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let xdg = std::env::temp_dir().join(format!("kern-it-ipc-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let producer_cmd =
        r#"readlink /proc/self/ns/ipc > /dev/shm/ns; echo data-sync > /dev/shm/p; sleep 30"#;
    // `$$` because Compose interpolates `$` in the file, as Docker does.
    let consumer_cmd = r#"sleep 1; cat /dev/shm/p; [ "$$(readlink /proc/self/ns/ipc)" = "$$(cat /dev/shm/ns)" ] && echo SAME_IPC_NS"#;
    let file = |shareable: bool| {
        let quote = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            "services:\n  producer:\n    image: alpine\n{}    command: [\"sh\", \"-c\", \"{}\"]\n  consumer:\n    image: alpine\n    ipc: \"service:producer\"\n    command: [\"sh\", \"-c\", \"{}\"]\n",
            if shareable { "    ipc: shareable\n" } else { "" },
            quote(producer_cmd),
            quote(consumer_cmd),
        )
    };
    let up = |f: &str| -> (Option<i32>, String) {
        let _ = std::fs::write(dir.join("compose.yml"), f);
        let out = kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args([
                "compose",
                "-f",
                "compose.yml",
                "-p",
                "ipcs",
                "up",
                "--abort-on-container-exit",
                "--exit-code-from",
                "consumer",
            ])
            .output();
        let _ = kern()
            .current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .args([
                "compose",
                "-f",
                "compose.yml",
                "-p",
                "ipcs",
                "down",
                "-t",
                "0",
            ])
            .output();
        match out {
            Ok(o) => (
                o.status.code(),
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
            ),
            Err(e) => (None, e.to_string()),
        }
    };
    let (rc, shared) = up(&file(true));
    // Read right after the shareable stack's `down`: the next start of a box of that name clears a
    // stale directory too, so reading at the end would not see a teardown that forgot it.
    let left = std::fs::read_dir(xdg.join("kern").join("shm"))
        .map(|d| d.count())
        .unwrap_or(0);
    // A STALE DIRECTORY, as a box killed before its teardown leaves one: a donor started without
    // `shareable` must not be joinable because of it.
    let _ = std::fs::create_dir_all(xdg.join("kern").join("shm").join("ipcs-producer"));
    let (_, refused) = up(&file(false));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    if !shared.contains("consumer") {
        eprintln!("SKIP: this host did not run the stack:\n{shared}");
        return;
    }
    assert!(
        shared.contains("data-sync"),
        "the consumer reads the producer's /dev/shm:\n{shared}"
    );
    assert!(
        shared.contains("SAME_IPC_NS"),
        "and is in its IPC namespace:\n{shared}"
    );
    assert_eq!(rc, Some(0), "the consumer's own status:\n{shared}");
    assert!(
        refused.contains("non-shareable IPC"),
        "a donor that is not shareable is refused:\n{refused}"
    );
    assert_eq!(left, 0, "the shared memory directory goes with the stack");
}

/// A HOST PORT RANGE ONTO ONE BOX PORT GIVES EACH BOX A FREE PORT OF IT, AS DOCKER DOES.
///
/// MEASURED against Docker Compose v5: `ports: ["8080-8095:80"]` under `--scale web=15` gave each
/// replica a different port of the range. kern refused the spec as malformed. Asserted with the
/// first port of the range held by this test: the first box takes the second port, the next box the
/// third, and a box finding the whole range taken is refused in Docker's words.
#[test]
fn a_host_port_range_onto_one_box_port_picks_a_free_port_of_it() {
    let xdg = std::env::temp_dir().join(format!("kern-it-range-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let Ok(held) = std::net::TcpListener::bind("0.0.0.0:18320") else {
        eprintln!("SKIP: port 18320 is not free on this host");
        return;
    };
    let run = |args: &[&str]| -> (Option<i32>, String) {
        match kern().env("XDG_RUNTIME_DIR", &xdg).args(args).output() {
            Ok(o) => (
                o.status.code(),
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
            ),
            Err(e) => (None, e.to_string()),
        }
    };
    let id = std::process::id();
    let names: Vec<String> = (1..=3).map(|n| format!("range-{n}-{id}")).collect();
    let mut started = Vec::new();
    for n in &names {
        started.push(run(&[
            "box",
            "--image",
            "alpine",
            "-d",
            "--name",
            n,
            "-p",
            "18320-18322:80",
            "--",
            "sleep",
            "30",
        ]));
    }
    let (_, ps) = run(&["ps"]);
    for n in &names {
        let _ = run(&["stop", n]);
        let _ = run(&["rm", n]);
    }
    drop(held);
    let _ = std::fs::remove_dir_all(&xdg);
    // A refusal of the SPEC is the defect this test is about, never a reason to skip.
    assert!(
        !started[0].1.contains("port"),
        "the range spec is accepted: {:?}",
        started[0]
    );
    if !ps.contains(&names[0]) {
        eprintln!("SKIP: this host did not run the box:\n{ps}");
        return;
    }
    let row = |n: &str| {
        ps.lines()
            .find(|l| l.contains(n))
            .unwrap_or_default()
            .to_string()
    };
    assert!(
        row(&names[0]).contains(":18321->80"),
        "the first free port of the range:\n{ps}"
    );
    assert!(
        row(&names[1]).contains(":18322->80"),
        "the next one for the next box:\n{ps}"
    );
    assert!(
        started[2].1.contains("port is already allocated"),
        "a box finding the range taken is refused in Docker's words: {:?}",
        started[2]
    );
}

/// FIVE THINGS A SECOND MODEL'S CASES FOUND, EACH MEASURED AGAINST DOCKER ON THE SAME FILE.
///
/// `run --entrypoint "sh -c 'exit 42'"` exited 42 under Docker and 127 under kern; `COMPOSE_FILE`
/// was ignored; a key that is not a compose key (`networks_advanced:`) started a stack Docker refuses
/// to start; an `on-failure:3` service under `--abort-on-container-exit` stopped the stack after its
/// third restart instead of its first exit; and a 72-character project name was refused.
#[test]
fn compose_entrypoint_compose_file_unknown_keys_first_exit_and_long_projects() {
    let dir = std::env::temp_dir().join(format!("kern-it-gem-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let xdg = std::env::temp_dir().join(format!("kern-it-gem-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let w = |f: &str, t: &str| {
        let _ = std::fs::write(dir.join(f), t);
    };
    let run = |env: &[(&str, &str)], args: &[&str]| -> (Option<i32>, String) {
        let mut c = kern();
        c.current_dir(&dir)
            .env("XDG_RUNTIME_DIR", &xdg)
            .env_remove("COMPOSE_FILE");
        for (k, v) in env {
            c.env(k, v);
        }
        match c.args(args).output() {
            Ok(o) => (
                o.status.code(),
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
            ),
            Err(e) => (None, e.to_string()),
        }
    };
    // COMPOSE_FILE, split on `:` and merged in order, with no `-f`.
    w("a.yml", "services:\n  one:\n    image: alpine\n");
    w("b.yml", "services:\n  two:\n    image: alpine\n");
    let (_, merged) = run(
        &[("COMPOSE_FILE", "a.yml:b.yml")],
        &["compose", "config", "--services"],
    );
    // A key that is not a compose key, and a one-letter typo of one.
    w(
        "bad.yml",
        "services:\n  app:\n    image: alpine\n    networks_advanced:\n      aliases: [x]\n",
    );
    let (bad_rc, bad) = run(&[], &["compose", "-f", "bad.yml", "config"]);
    w(
        "typo.yml",
        "services:\n  app:\n    image: alpine\n    enviroment:\n      A: b\n",
    );
    let (_, typo) = run(&[], &["compose", "-f", "typo.yml", "config"]);
    // `--entrypoint` as a string.
    w("ep.yml", "services:\n  s:\n    image: alpine\n");
    let (ep_rc, ep) = run(
        &[],
        &[
            "compose",
            "-f",
            "ep.yml",
            "-p",
            "gemep",
            "run",
            "--rm",
            "--entrypoint",
            "sh -c 'exit 42'",
            "s",
        ],
    );
    // A run that ends is an exit, restart policy or not.
    w(
        "flaky.yml",
        "services:\n  flaky:\n    image: alpine\n    restart: \"on-failure:3\"\n    command: [\"sh\", \"-c\", \"echo FLAKY-RUN; exit 1\"]\n",
    );
    let (flaky_rc, flaky) = run(
        &[],
        &[
            "compose",
            "-f",
            "flaky.yml",
            "-p",
            "gemflaky",
            "up",
            "--abort-on-container-exit",
            "--exit-code-from",
            "flaky",
        ],
    );
    let _ = run(
        &[],
        &["compose", "-f", "flaky.yml", "-p", "gemflaky", "down"],
    );
    // A project name Docker accepts and the old 64-byte bound refused.
    let long = "verylongprojectnamethatextendsovermanycharactersforboundarytesting123456";
    w(
        "long.yml",
        "services:\n  s:\n    image: alpine\n    command: [\"sleep\", \"30\"]\n",
    );
    let (long_rc, long_out) = run(&[], &["compose", "-f", "long.yml", "-p", long, "up", "-d"]);
    let (_, ps) = run(&[], &["ps"]);
    let _ = run(&[], &["compose", "-f", "long.yml", "-p", long, "down"]);
    // A service behind a profile, started with it: `ps` and `down` without it still reach it.
    w(
        "prof.yml",
        "services:\n  gated:\n    image: alpine\n    profiles: [front]\n    command: [\"sleep\", \"31\"]\n",
    );
    let _ = run(
        &[],
        &[
            "compose",
            "-f",
            "prof.yml",
            "-p",
            "gemprof",
            "--profile",
            "front",
            "up",
            "-d",
        ],
    );
    let (_, prof_ps) = run(&[], &["compose", "-f", "prof.yml", "-p", "gemprof", "ps"]);
    let (prof_down_rc, prof_down) =
        run(&[], &["compose", "-f", "prof.yml", "-p", "gemprof", "down"]);
    let (_, after_prof) = run(&[], &["ps"]);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);

    assert!(
        merged.contains("one") && merged.contains("two"),
        "COMPOSE_FILE merges a.yml and b.yml:\n{merged}"
    );
    assert_ne!(
        bad_rc,
        Some(0),
        "a key Docker's schema does not have is refused:\n{bad}"
    );
    assert!(
        bad.contains("not a compose key") && bad.contains("networks_advanced"),
        "{bad}"
    );
    assert!(
        typo.contains("not a compose key") && typo.contains("`environment:`"),
        "the typo names the key it is one edit from:\n{typo}"
    );
    if !ps.contains("NAME") {
        eprintln!("SKIP (runtime half): this host lists no boxes");
        return;
    }
    assert_eq!(
        ep_rc,
        Some(42),
        "the entrypoint string is split as a shell would:\n{ep}"
    );
    assert_eq!(flaky_rc, Some(1), "the service's own status:\n{flaky}");
    let runs = flaky.matches("FLAKY-RUN").count();
    assert!(
        runs == 1,
        "stopped at the first exit, not after three restarts ({runs} runs):\n{flaky}"
    );
    assert_eq!(
        long_rc,
        Some(0),
        "a 72-byte project name starts:\n{long_out}"
    );
    assert!(ps.contains("sleep 30"), "and its service runs:\n{ps}");
    assert!(
        prof_ps.contains("sleep 31") && !prof_ps.contains("inactive profile"),
        "`ps` without the profile lists the running service:\n{prof_ps}"
    );
    assert_eq!(
        prof_down_rc,
        Some(0),
        "`down` without the profile succeeds:\n{prof_down}"
    );
    assert!(
        !after_prof.contains("sleep 31"),
        "and stops it:\n{after_prof}"
    );
}

/// THE SHAPE OF A CODE SANDBOX, RUN AS A ONE-OFF: `network_mode: none`, `read_only`, a `/tmp` tmpfs,
/// and the script mounted INTO that tmpfs with `run -v`. MEASURED against Docker on a case written
/// for both: kern took the `-v` spec for the service name, then (with `-v` read) mounted the tmpfs
/// over the bind so the script was not there, and the one-off joined the stack's pod with outbound.
/// Docker ran the script with no network.
#[test]
fn a_sandbox_one_off_mounts_its_script_inside_its_tmpfs_with_no_network() {
    let dir = std::env::temp_dir().join(format!("kern-it-sandbox1-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let xdg = std::env::temp_dir().join(format!("kern-it-sandbox1-xdg-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&xdg);
    let _ = std::fs::write(
        dir.join("compose.yml"),
        "services:\n  sandbox:\n    image: alpine\n    network_mode: \"none\"\n    read_only: true\n    \
         tmpfs:\n      - /tmp:size=8m,mode=1777\n",
    );
    let _ = std::fs::write(
        dir.join("job.sh"),
        "echo SCRIPT-RAN; ip -o link | grep -vc ': lo:' ; echo IFACES-DONE\n",
    );
    let spec = format!("{}:/tmp/job.sh:ro", dir.join("job.sh").display());
    let out = match kern()
        .current_dir(&dir)
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "compose",
            "-f",
            "compose.yml",
            "-p",
            "sbx1",
            "run",
            "--rm",
            "-v",
            &spec,
            "sandbox",
            "sh",
            "/tmp/job.sh",
        ])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(e) => e.to_string(),
    };
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&xdg);
    assert!(
        out.contains("SCRIPT-RAN"),
        "the script mounted inside the tmpfs must run:\n{out}"
    );
    let ifaces: Vec<&str> = out
        .lines()
        .skip_while(|l| !l.contains("SCRIPT-RAN"))
        .skip(1)
        .take(1)
        .collect();
    assert_eq!(
        ifaces,
        vec!["0"],
        "a `network_mode: none` one-off has no interface but lo:\n{out}"
    );
}
