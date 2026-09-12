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
/// silently reverts to the misleading one while the unit test stays green. An external reviewer named
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
    assert_eq!(
        out.status.code(),
        Some(137),
        "the box did not propagate the chosen exit code; stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
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
    (out.status.code(), got)
}

/// The `KERN_STARTED_FD` signal is THREE bytes, and the third one is the OOM verdict.
///
/// WHY THE THIRD BYTE EXISTS. An SDK had only the exit code and the enforcement byte, and 137 plus "the
/// cap was enforced" is also what `kern stop` of a capped box looks like. Measured through the Python
/// binding: stopping a box during a cell was reported as `fault.type == "oom"`, which sends an agent to
/// retry with more memory a kill that had nothing to do with memory. kern already knows the answer - it
/// reads the box's own `memory.events` for the stderr sentence - and this puts that same observation on
/// a channel the workload cannot write, where stderr is a stream the workload shares.
///
/// THE DISCRIMINATOR IS THE PAIR, not either run alone: a byte that were always 1 would pass the OOM
/// half, and one that were always 0 would pass the external-kill half. Both exit 137.
#[test]
fn the_started_signal_carries_the_oom_verdict_in_its_third_byte() {
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
        3,
        "a started box must write all three bytes: {sig:?}"
    );
    assert_eq!(
        sig[2], 0,
        "an exit 137 with no OOM behind it was reported as an OOM: {sig:?}"
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
        3,
        "a started box must write all three bytes: {sig:?}"
    );
    assert_eq!(
        sig[2], 1,
        "a box taken by the OOM killer against its own cap reported no OOM: {sig:?}"
    );
}

/// **A fork failure must never be answered with the user-namespace and rootfs hint, whatever the
/// errno.**
///
/// That hint has now been wrong twice, for two different errnos, to two different reviewers. The
/// first time it was EAGAIN under `RLIMIT_NPROC` and it got its own branch. The second was ENOMEM on
/// WSL2, deterministic, and the reader was again sent to two places that were both fine.
///
/// The argument was never about a particular errno: by the time any fork on this path runs, the user
/// namespace exists and the rootfs has been validated, or control would not have reached the fork.
/// So the rule is the CLASS, and this test is on the class. Enumerating errnos one reviewer at a
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
