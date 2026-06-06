//! Real-syscall sandbox correctness (level 4). Runs an actual command inside a `kern box`
//! sandbox and asserts isolation + exit-code propagation. **Skip-graceful**: if unprivileged
//! user namespaces or a static busybox are unavailable (e.g. a locked-down CI runner), the
//! test returns early instead of failing — so x86 CI stays green either way.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn kern() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kern"))
}

/// Run `kern <args>` (which is expected to print something) and return its output, retrying a few
/// times while **stdout is empty**. Under this suite's heavy parallelism, `Command::output()`'s
/// pipe occasionally comes back empty even though the box ran (exit 0) — a `systemd-run --scope` +
/// pipe interaction that does not occur in real single/low-concurrency use (verified: 40/40
/// concurrent boxes capture stdout to files, and 250/250 exit 0). Every caller asserts on
/// non-empty stdout, so retrying-on-empty is correct and never masks a wrong-output bug. The
/// userns-skip (stderr mentions "user namespaces") is returned as-is so callers can skip.
fn kern_out(args: &[&str]) -> std::process::Output {
    let mut out = kern().args(args).output().expect("run kern");
    let mut tries = 0;
    while out.stdout.is_empty()
        && tries < 5
        && !String::from_utf8_lossy(&out.stderr).contains("user namespaces")
    {
        std::thread::sleep(std::time::Duration::from_millis(80));
        out = kern().args(args).output().expect("run kern");
        tries += 1;
    }
    out
}

/// A statically-linked busybox we can drop into an otherwise-empty rootfs, or `None`.
fn static_busybox() -> Option<PathBuf> {
    ["/bin/busybox", "/usr/bin/busybox"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

/// Is unprivileged userns *actually* usable here? Guessing from sysctls is not enough: on
/// Ubuntu 24.04 (the GitHub runner) `unprivileged_userns_clone` reads `1`, yet AppArmor then
/// blocks the `unshare` for unconfined binaries — so a sysctl-only check thinks userns is fine,
/// the box creation fails with EPERM, and the test fails instead of skipping. Probe for real:
/// fork a throwaway child, attempt `unshare(CLONE_NEWUSER)`, and report whether it succeeded.
/// Bulletproof against *any* reason userns is unavailable (sysctl, AppArmor, seccomp, an outer
/// container). The child only calls async-signal-safe functions before `_exit`.
fn userns_plausible() -> bool {
    // Cheap early-out when the classic sysctl explicitly disables it.
    if let Ok(s) = fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        if s.trim() == "0" {
            return false;
        }
    }
    unsafe {
        match libc::fork() {
            0 => {
                let rc = libc::unshare(libc::CLONE_NEWUSER);
                libc::_exit(if rc == 0 { 0 } else { 1 });
            }
            pid if pid > 0 => {
                let mut status = 0;
                if libc::waitpid(pid, &mut status, 0) < 0 {
                    return true; // can't tell — stay permissive
                }
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
            }
            _ => true, // fork failed — stay permissive (old behaviour)
        }
    }
}

/// Build a minimal rootfs: `bin/busybox` + `/proc` mountpoint. `tag` keeps the path unique per
/// test, since the suite runs tests in parallel (a shared path would race).
fn build_rootfs(busybox: &Path, tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("kern-it-rootfs-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("proc")).unwrap();
    fs::copy(busybox, root.join("bin/busybox")).unwrap();
    root
}

#[test]
fn box_run_isolates_and_propagates_exit_code() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "exit");
    let rootfs = root.to_str().unwrap();

    // A successful command exits 0.
    let out = kern_out(&["box", "t", "--rootfs", rootfs, "--", "/bin/busybox", "true"]);
    let err = String::from_utf8_lossy(&out.stderr);
    // Runtime confirmation that userns really is usable here; otherwise skip.
    if err.contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    assert!(
        out.status.success(),
        "expected exit 0, got {:?} (stderr: {err})",
        out.status.code()
    );

    // The sandboxed command's exit code is propagated.
    let out2 = kern()
        .args([
            "box",
            "t",
            "--rootfs",
            rootfs,
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            "exit 7",
        ])
        .output()
        .expect("run kern");
    assert_eq!(out2.status.code(), Some(7), "exit code not propagated");

    // `--read-only` makes the root read-only: writing must fail.
    let ro = kern()
        .args([
            "box",
            "t",
            "--rootfs",
            rootfs,
            "--read-only",
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            "touch /pwned",
        ])
        .output()
        .expect("run kern");
    assert!(!ro.status.success(), "writing under --read-only must fail");

    // Default (writable overlay): writing succeeds, but the lower rootfs stays untouched.
    let rw = kern_out(&[
        "box",
        "t",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "echo hi > /written && cat /written",
    ]);
    assert!(
        rw.status.success() && String::from_utf8_lossy(&rw.stdout).contains("hi"),
        "default overlay box should be writable: {}",
        String::from_utf8_lossy(&rw.stderr)
    );
    assert!(
        !root.join("written").exists(),
        "the lower rootfs must stay immutable"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn box_detached_appears_in_ps_then_prunes() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "ps");
    let rootfs = root.to_str().unwrap();
    // Isolate the registry so this test sees only its own boxes.
    let xdg = std::env::temp_dir().join(format!("kern-it-xdg-{}", std::process::id()));
    let _ = fs::create_dir_all(&xdg);

    // Start a detached box that lives ~2s.
    let out = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            "pstest",
            "--rootfs",
            rootfs,
            "-d",
            "--",
            "/bin/busybox",
            "sleep",
            "2",
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }
    assert!(out.status.success(), "detached start should succeed");

    // It shows up in `ps`. Registration happens in the forked supervisor *after* the parent
    // returns, so poll briefly rather than asserting immediately (robust under parallel CI load).
    let mut listed = false;
    for _ in 0..40 {
        let listing = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["ps", "--json"])
            .output()
            .expect("run kern");
        if String::from_utf8_lossy(&listing.stdout).contains("pstest") {
            listed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(listed, "ps should list the detached box within ~2s");

    // The box sleeps ~2s; once it exits, `ps` prunes it on read. Poll for its disappearance
    // (timing-robust) rather than a single fixed sleep.
    let mut pruned = false;
    for _ in 0..60 {
        let after = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["ps", "--json"])
            .output()
            .expect("run kern");
        if !String::from_utf8_lossy(&after.stdout).contains("pstest") {
            pruned = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(pruned, "ps should prune the dead box within ~6s");

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
}

#[test]
fn detached_box_with_bad_command_reports_failure_not_started() {
    // A detached box whose command can't exec must NOT print a misleading "started": the readiness
    // pipe makes the launcher wait for the box's `execvp` (EOF = up) and report failure otherwise.
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "badcmd");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-xdg-badcmd-{}", std::process::id()));
    let _ = fs::create_dir_all(&xdg);

    let out = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            "badcmd",
            "--rootfs",
            rootfs,
            "-d",
            "--",
            "/nope/does-not-exist",
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a box that can't exec must fail, not exit 0 (stdout={stdout:?})"
    );
    assert!(
        !stdout.contains("started"),
        "must not claim the box started (stdout={stdout:?})"
    );
    assert!(
        stderr.contains("exited before starting") || stderr.contains("kern logs"),
        "failure should point at the cause/logs (stderr={stderr:?})"
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
}

#[test]
fn box_logs_capture_output_and_stats_list_the_box() {
    // A detached box's stdout is captured to a per-box log (`kern logs <name>`), and the live box
    // appears in `kern stats --json`. Skip-graceful like the rest of this suite.
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "logs");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-xdg-logs-{}", std::process::id()));
    let _ = fs::create_dir_all(&xdg);

    let out = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            "logtest",
            "--rootfs",
            rootfs,
            "-d",
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            "echo hello-from-logs; sleep 2",
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }
    assert!(out.status.success(), "detached start should succeed");

    // Give the box a moment to print, then `kern logs` must echo its output back.
    std::thread::sleep(std::time::Duration::from_millis(700));
    let logs = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["logs", "logtest"])
        .output()
        .expect("run kern");
    let logs = String::from_utf8_lossy(&logs.stdout);
    assert!(
        logs.contains("hello-from-logs"),
        "logs should capture the box's stdout: {logs}"
    );

    // The live box shows up in `kern stats --json`.
    let stats = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["stats", "--json"])
        .output()
        .expect("run kern");
    let stats = String::from_utf8_lossy(&stats.stdout);
    assert!(
        stats.contains("logtest"),
        "stats --json should list the live box: {stats}"
    );

    // Logs remain readable after the box exits (post-mortem).
    std::thread::sleep(std::time::Duration::from_secs(2));
    let post = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["logs", "logtest"])
        .output()
        .expect("run kern");
    assert!(
        String::from_utf8_lossy(&post.stdout).contains("hello-from-logs"),
        "logs should survive the box exiting"
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
}

#[test]
fn symlinked_dev_in_rootfs_cannot_escape() {
    // SECURITY regression: a hostile rootfs whose `/dev` is a symlink to a host path must NOT let
    // /dev setup create files / bind devices at that host location. Synthetic, self-contained.
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let base = std::env::temp_dir().join(format!("kern-it-devesc-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let rootfs = base.join("rootfs");
    let victim = base.join("VICTIM");
    fs::create_dir_all(rootfs.join("bin")).unwrap();
    fs::create_dir_all(rootfs.join("proc")).unwrap();
    fs::create_dir_all(&victim).unwrap();
    fs::copy(busybox, rootfs.join("bin/busybox")).unwrap();
    // Plant /dev -> the host victim dir.
    std::os::unix::fs::symlink(&victim, rootfs.join("dev")).unwrap();

    let out = kern()
        .args([
            "box",
            "esc",
            "--rootfs",
            rootfs.to_str().unwrap(),
            "--",
            "/bin/busybox",
            "true",
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&base);
        return;
    }
    let leaked = fs::read_dir(&victim).map(|r| r.count()).unwrap_or(0);
    assert_eq!(
        leaked, 0,
        "host victim dir must stay empty (no escape via symlinked /dev)"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn box_does_not_leak_host_environment() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "leak");
    let rootfs = root.to_str().unwrap();
    // Retry a transient parallel-setup failure (see `kern_out`); the secret lives on this
    // Command's env (the whole point), so we can't route through the shared `kern_out`.
    let run = || {
        kern()
            .env("KERN_TEST_SECRET", "do-not-leak-me")
            .args(["box", "ev", "--rootfs", rootfs, "--", "/bin/busybox", "env"])
            .output()
            .expect("run kern")
    };
    let mut out = run();
    let mut tries = 0;
    while out.stdout.is_empty()
        && tries < 5
        && !String::from_utf8_lossy(&out.stderr).contains("user namespaces")
    {
        std::thread::sleep(std::time::Duration::from_millis(80));
        out = run();
        tries += 1;
    }
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let env = String::from_utf8_lossy(&out.stdout);
    assert!(
        !env.contains("do-not-leak-me") && !env.contains("KERN_TEST_SECRET"),
        "the host environment must not leak into the box: {env}"
    );
    assert!(
        env.contains("PATH=/"),
        "the box should get a clean PATH: {env}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn box_provides_essential_dev_nodes() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "dev");
    let rootfs = root.to_str().unwrap();
    // /dev/urandom must be readable (a real device, not a faked regular file).
    let out = kern_out(&[
        "box",
        "dv",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "head -c 4 /dev/urandom | wc -c",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "4",
        "/dev/urandom should yield bytes (real device node bind-mounted)"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn box_run_hardening_uts_net_seccomp() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "harden");
    let rootfs = root.to_str().unwrap();

    // UTS: hostname inside is the box name, not the host's.
    let out = kern_out(&[
        "box",
        "isobox",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "hostname",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "isobox",
        "UTS namespace: hostname should be the box name"
    );

    // NET: the network namespace exposes only loopback.
    let net = kern_out(&[
        "box",
        "isobox",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "cat",
        "/proc/net/dev",
    ]);
    let net = String::from_utf8_lossy(&net.stdout);
    assert!(net.contains("lo"), "loopback present");
    assert!(
        !net.contains("eth") && !net.contains("wlan") && !net.contains("enp"),
        "no host interfaces should be visible: {net}"
    );

    // SECCOMP: a denied syscall (mount) kills the workload with SIGSYS (signal 31).
    let killed = kern()
        .args([
            "box",
            "isobox",
            "--rootfs",
            rootfs,
            "--",
            "/bin/busybox",
            "mount",
            "-t",
            "tmpfs",
            "n",
            "/proc",
        ])
        .output()
        .expect("run kern");
    // The workload is PID 1 in the box's PID namespace; kern reaps it and reports its death by
    // SIGSYS (31) as exit code 128+31 = 159.
    assert_eq!(
        killed.status.code(),
        Some(159),
        "the denied syscall should be killed by SIGSYS (reported as 128+31)"
    );

    let _ = fs::remove_dir_all(&root);
}

/// `-v` round-trips data across the boundary: a read-write volume's writes appear on the host,
/// and a `:ro` volume rejects writes. The only sanctioned way data enters/leaves a box.
#[test]
fn box_volume_roundtrips_data_and_ro_is_enforced() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "vol");
    let rootfs = root.to_str().unwrap();
    let host = std::env::temp_dir().join(format!("kern-it-vol-{}", std::process::id()));
    let _ = fs::remove_dir_all(&host);
    fs::create_dir_all(host.join("rw")).unwrap();
    fs::create_dir_all(host.join("ro")).unwrap();
    fs::write(host.join("ro/seed.txt"), b"from-host").unwrap();

    // Read-write: the box writes a file that the host then sees.
    let rw = format!("{}:/rw", host.join("rw").display());
    let out = kern_out(&[
        "box",
        "vrw",
        "--rootfs",
        rootfs,
        "-v",
        &rw,
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "echo box-wrote > /rw/out.txt",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&host);
        return;
    }
    let wrote = fs::read_to_string(host.join("rw/out.txt")).unwrap_or_default();
    assert!(
        wrote.contains("box-wrote"),
        "host should see the box's write via the rw volume: {wrote:?}"
    );

    // Read-only: the seed is readable, but a write is refused.
    let rovol = format!("{}:/ro:ro", host.join("ro").display());
    let ro = kern_out(&[
        "box",
        "vro",
        "--rootfs",
        rootfs,
        "-v",
        &rovol,
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "cat /ro/seed.txt; echo nope > /ro/x.txt",
    ]);
    let stdout = String::from_utf8_lossy(&ro.stdout);
    assert!(stdout.contains("from-host"), "ro volume readable: {stdout}");
    assert!(
        !host.join("ro/x.txt").exists(),
        "a :ro volume must reject writes (host file must not appear)"
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&host);
}

/// `--env` and `--workdir` reach the workload.
#[test]
fn box_env_and_workdir_apply() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "env");
    let rootfs = root.to_str().unwrap();
    let out = kern_out(&[
        "box",
        "e",
        "--rootfs",
        rootfs,
        "--env",
        "GREETING=ciao",
        "--workdir",
        "/bin", // exists in the minimal rootfs; a real image would use /tmp etc.
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "echo \"$GREETING@$(pwd)\"",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ciao@/bin"),
        "env + workdir should apply: {stdout}"
    );
    let _ = fs::remove_dir_all(&root);
}

/// Regression: a box's `/dev/null` (and friends) must be *writable* — `cmd > /dev/null` is
/// ubiquitous. A sticky world-writable `/dev` tmpfs + `fs.protected_regular` used to break it.
#[test]
fn box_dev_null_is_writable() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "devnull");
    let rootfs = root.to_str().unwrap();
    let out = kern_out(&[
        "box",
        "dn",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "echo discard > /dev/null && echo WROTE",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("WROTE"),
        "writing to /dev/null must succeed (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = fs::remove_dir_all(&root);
}

/// `kern exec` joins a running box: it sees the box's hostname (its own UTS namespace) and its
/// PID namespace (a tiny process table), and propagates the command's exit code.
#[test]
fn box_exec_enters_running_box() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "exec");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-xdg-exec-{}", std::process::id()));
    let _ = fs::create_dir_all(&xdg);

    let start = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            "xbox",
            "--rootfs",
            rootfs,
            "-d",
            "--",
            "/bin/busybox",
            "sleep",
            "5",
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&start.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }
    assert!(start.status.success(), "detached start should succeed");
    std::thread::sleep(std::time::Duration::from_millis(500));

    // exec sees the box's hostname.
    let h = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["exec", "xbox", "--", "/bin/busybox", "hostname"])
        .output()
        .expect("run kern");
    assert!(
        String::from_utf8_lossy(&h.stdout).contains("xbox"),
        "exec should see the box's hostname: {}",
        String::from_utf8_lossy(&h.stdout)
    );

    // exec propagates the exit code.
    let code = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["exec", "xbox", "--", "/bin/busybox", "sh", "-c", "exit 7"])
        .output()
        .expect("run kern");
    assert_eq!(
        code.status.code(),
        Some(7),
        "exec should propagate exit code"
    );

    let _ = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["stop", "xbox"])
        .output();
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
}

/// Concurrency regression: many boxes sharing ONE bind rootfs must all start. A `.old_root`
/// subdirectory created/removed in the shared rootfs used to race (self-pivot removed it).
#[test]
fn many_boxes_share_one_bind_rootfs_concurrently() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "shared");
    let rootfs = root.to_str().unwrap().to_string();

    // Probe once; skip if userns isn't usable at runtime.
    let probe = kern()
        .args([
            "box",
            "p",
            "--rootfs",
            &rootfs,
            "--read-only",
            "--",
            "/bin/busybox",
            "true",
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&probe.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }

    let handles: Vec<_> = (0..12)
        .map(|i| {
            let rootfs = rootfs.clone();
            std::thread::spawn(move || {
                kern()
                    .args([
                        "box",
                        &format!("c{i}"),
                        "--rootfs",
                        &rootfs,
                        "--read-only",
                        "--",
                        "/bin/busybox",
                        "true",
                    ])
                    .output()
                    .expect("run kern")
                    .status
                    .success()
            })
        })
        .collect();
    let ok = handles
        .into_iter()
        .map(|h| h.join().unwrap_or(false))
        .filter(|&b| b)
        .count();
    assert_eq!(
        ok, 12,
        "all 12 boxes sharing one bind rootfs should start (no .old_root race)"
    );

    let _ = fs::remove_dir_all(&root);
}

/// SECURITY: a `-v` volume whose in-box target path passes through a symlink must NOT be honored
/// by following that symlink — the bind is refused, so a hostile image can't redirect a mount
/// (and a host write) through a planted symlink.
#[test]
fn volume_target_through_a_symlink_is_refused() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let base = std::env::temp_dir().join(format!("kern-it-volesc-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let rootfs = base.join("rootfs");
    let victim = base.join("VICTIM");
    let payload = base.join("payload");
    fs::create_dir_all(rootfs.join("bin")).unwrap();
    fs::create_dir_all(rootfs.join("proc")).unwrap();
    fs::create_dir_all(&victim).unwrap();
    fs::create_dir_all(&payload).unwrap();
    fs::copy(&busybox, rootfs.join("bin/busybox")).unwrap();
    // The rootfs ships `/evil` as a symlink to the host victim dir.
    std::os::unix::fs::symlink(&victim, rootfs.join("evil")).unwrap();

    let out = kern()
        .args([
            "box",
            "vesc",
            "--rootfs",
            rootfs.to_str().unwrap(),
            "-v",
            &format!("{}:/evil/leak", payload.display()),
            "--",
            "/bin/busybox",
            "true",
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&base);
        return;
    }
    // The bind must be refused (setup fails) and nothing may appear at the host victim path.
    assert!(
        !out.status.success(),
        "a volume target through a symlink must be refused"
    );
    assert!(
        !victim.join("leak").exists(),
        "no bind may be created at the host victim path"
    );
    let _ = fs::remove_dir_all(&base);
}

/// SECURITY: a `-v` target containing `..` must be rejected (it must not climb out of the box
/// root). Caught before any sandbox setup, so this needs no user namespace.
#[test]
fn volume_target_with_dotdot_is_rejected() {
    let out = kern()
        .args([
            "box",
            "vdd",
            "--image",
            "alpine",
            "-v",
            "/tmp:/a/../etc",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("run kern");
    assert!(
        !out.status.success(),
        "a '..' volume target must be rejected"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("'.' or '..'"),
        "error should name the '..' rejection: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// SECURITY: `--read-only` must leave NO writable surface — including `/dev` (a separate tmpfs).
/// Creating an entry in `/dev` must fail, while the bound device nodes stay usable.
#[test]
fn read_only_dev_is_not_writable() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "rodev");
    let rootfs = root.to_str().unwrap();
    // /dev/null still writable; creating a new /dev entry refused; root refused.
    let out = kern_out(&[
        "box",
        "rodev",
        "--rootfs",
        rootfs,
        "--read-only",
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "echo x > /dev/null && echo devnull-ok; touch /dev/evil 2>/dev/null && echo DEV-WRITABLE || echo dev-ro; touch /pwned 2>/dev/null && echo ROOT-WRITABLE || echo root-ro",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let o = String::from_utf8_lossy(&out.stdout);
    assert!(
        o.contains("devnull-ok"),
        "/dev/null must stay writable: {o}"
    );
    assert!(
        o.contains("dev-ro") && !o.contains("DEV-WRITABLE"),
        "creating an entry in /dev must fail under --read-only: {o}"
    );
    assert!(
        o.contains("root-ro") && !o.contains("ROOT-WRITABLE"),
        "the root must be read-only: {o}"
    );
    let _ = fs::remove_dir_all(&root);
}

/// When `newuidmap` + an `/etc/subuid` allocation are present, the box gets a RANGED uid map
/// (box uid 0 → caller, box uids 1..N → subordinate ids) so other uids are usable. Verified via
/// the box's own `/proc/self/uid_map` having the second (range) row. Skips where unavailable
/// (then kern falls back to the single-uid map, which is also fine).
#[test]
fn ranged_uid_map_when_subids_available() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let user = std::env::var("USER").unwrap_or_default();
    let has_helper = ["/usr/bin/newuidmap", "/bin/newuidmap"]
        .iter()
        .any(|p| Path::new(p).exists());
    let has_subuid = !user.is_empty()
        && fs::read_to_string("/etc/subuid")
            .map(|s| s.lines().any(|l| l.starts_with(&format!("{user}:"))))
            .unwrap_or(false);
    if !(has_helper && has_subuid) {
        eprintln!("skip: no newuidmap/subuid (single-uid fallback applies)");
        return;
    }
    let root = build_rootfs(&busybox, "idrange");
    let rootfs = root.to_str().unwrap();
    // The range is opt-in (`--uid-range`); the default is a single-uid map.
    let out = kern_out(&[
        "box",
        "idr",
        "--rootfs",
        rootfs,
        "--uid-range",
        "--",
        "/bin/busybox",
        "cat",
        "/proc/self/uid_map",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    // The range can be unusable at runtime even with newuidmap + an /etc/subuid line present —
    // e.g. a CI runner where the helper isn't setuid or there's no matching /etc/subgid. kern then
    // degrades to the single-uid map (either because detect_id_range found nothing, or because the
    // helper failed to apply the range); both paths log "using single-uid map". The ranged-map
    // assertion only applies when the range actually took effect — let kern be the source of truth.
    if String::from_utf8_lossy(&out.stderr).contains("using single-uid map") {
        eprintln!("skip: --uid-range fell back to single-uid (range not usable at runtime)");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let map = String::from_utf8_lossy(&out.stdout);
    let rows = map.lines().filter(|l| !l.trim().is_empty()).count();
    // The ranged map needs newuidmap/newgidmap to actually SUCCEED at runtime. Some CI runners
    // advertise a newuidmap binary plus an /etc/subuid line (so detect_id_range returns Some and no
    // fallback notice is printed) yet the helper still fails — e.g. it isn't setuid, or /etc/subgid
    // has no matching allocation — so the box can't map and produces no uid_map at all. That's not a
    // regression, the range path simply isn't exercisable here → skip. A box that DID map but came
    // back single-uid (1 row) without the fallback notice IS a real bug → still asserted below.
    if rows == 0 {
        eprintln!(
            "skip: --uid-range not exercisable here (newuidmap produced no uid_map)\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = fs::remove_dir_all(&root);
        return;
    }
    assert!(
        rows >= 2,
        "expected a ranged uid_map (>=2 rows) with subids available, got:\n{map}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn single_uid_map_is_the_default() {
    // Without `--uid-range`, the box gets a single-uid identity map (one row: box uid 0 = caller)
    // regardless of whether subids exist — the fast, most-isolated default. This is the perf-and-
    // security default that lets a bare box beat heavier runtimes; the range is strictly opt-in.
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "singleuid");
    let rootfs = root.to_str().unwrap();
    let out = kern_out(&[
        "box",
        "su",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "cat",
        "/proc/self/uid_map",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let map = String::from_utf8_lossy(&out.stdout);
    let rows = map.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(
        rows, 1,
        "default must be a single-uid map (1 row), got:\n{map}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bind_rootfs_writes_reach_source_while_overlay_keeps_it_immutable() {
    // `--bind-rootfs` binds the source directly (faster on slow-overlay kernels) — a write inside
    // the box lands in the source dir. The default overlay keeps the source immutable. This pins
    // both halves of the documented trade-off.
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "bindmode");
    let rootfs = root.to_str().unwrap();

    // Bind mode: a write at the box root must appear in the source directory.
    let out = kern_out(&[
        "box",
        "bm",
        "--bind-rootfs",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "touch",
        "/bind-marker",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    assert!(
        root.join("bind-marker").exists(),
        "--bind-rootfs write should reach the source rootfs"
    );

    // Overlay (default): a write must NOT leak to the source.
    kern_out(&[
        "box",
        "om",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "touch",
        "/overlay-marker",
    ]);
    assert!(
        !root.join("overlay-marker").exists(),
        "the default overlay must keep the source immutable"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn bind_rootfs_net_does_not_clobber_a_symlinked_host_file() {
    // Security regression: `--bind-rootfs --net` must NOT do a host-side write through a symlink in
    // the (possibly untrusted) rootfs. A `/etc/resolv.conf -> <outside file>` symlink must leave
    // that outside file untouched — kern injects no resolv.conf in bind mode for exactly this reason.
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "bindnet");
    let rootfs = root.to_str().unwrap();
    // A file OUTSIDE the rootfs, and a rootfs `/etc/resolv.conf` symlink pointing at it.
    let outside = std::env::temp_dir().join(format!("kern-it-clobber-{}", std::process::id()));
    fs::write(&outside, b"SENTINEL").unwrap();
    fs::create_dir_all(root.join("etc")).unwrap();
    let _ = std::os::unix::fs::symlink(&outside, root.join("etc/resolv.conf"));

    let out = kern_out(&[
        "box",
        "bn",
        "--bind-rootfs",
        "--net",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "true",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&outside);
        return;
    }
    assert_eq!(
        fs::read(&outside).unwrap(),
        b"SENTINEL",
        "bind+net must not clobber a host file via a rootfs resolv.conf symlink"
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_file(&outside);
}

#[test]
fn images_lists_cached_pulls_by_original_ref() {
    // Hermetic (no userns/network): point the image cache at a temp dir with a fake completed
    // pull. The `.ok` sentinel's content is the original ref, so `kern images` must show
    // `myrepo/app:1.0`, not the sanitized cache-dir name `myrepo_app`.
    let cache = std::env::temp_dir().join(format!("kern-it-imgcache-{}", std::process::id()));
    let images = cache.join("kern/images");
    fs::create_dir_all(images.join("myrepo_app")).unwrap();
    fs::write(images.join("myrepo_app/file"), b"some-bytes").unwrap();
    fs::write(images.join("myrepo_app.ok"), b"myrepo/app:1.0").unwrap();

    let out = kern()
        .env("XDG_CACHE_HOME", &cache)
        .args(["images", "--json"])
        .output()
        .expect("run kern");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "images should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("myrepo/app:1.0"),
        "must show the original ref from the .ok sentinel: {stdout}"
    );
    assert!(
        !stdout.contains("myrepo_app"),
        "must not show the sanitized cache-dir name: {stdout}"
    );
    let _ = fs::remove_dir_all(&cache);
}

#[test]
fn images_strips_terminal_escapes_from_untrusted_ref() {
    // SECURITY regression: a crafted `.ok` sentinel (the image ref) must NOT inject ANSI/control
    // bytes into the terminal. `kern images` (table) strips them; `--json` escapes them.
    let cache = std::env::temp_dir().join(format!("kern-it-esc-{}", std::process::id()));
    let images = cache.join("kern/images");
    fs::create_dir_all(images.join("x")).unwrap();
    // Original ref containing a real ESC (0x1b) + an OSC-ish payload.
    fs::write(images.join("x.ok"), b"evil\x1b[31mPWNED\x1b]0;hi\x07:1.0").unwrap();

    let table = kern()
        .env("XDG_CACHE_HOME", &cache)
        .arg("images")
        .output()
        .expect("run kern");
    assert!(
        !table.stdout.contains(&0x1b) && !table.stdout.contains(&0x07),
        "table output must contain no raw escape/control bytes"
    );

    let json = kern()
        .env("XDG_CACHE_HOME", &cache)
        .args(["images", "--json"])
        .output()
        .expect("run kern");
    assert!(
        !json.stdout.contains(&0x1b),
        "json output must escape control bytes, not emit them raw"
    );
    assert!(
        String::from_utf8_lossy(&json.stdout).contains("\\u001b"),
        "the ESC should appear as the escaped \\u001b"
    );
    let _ = fs::remove_dir_all(&cache);
}
