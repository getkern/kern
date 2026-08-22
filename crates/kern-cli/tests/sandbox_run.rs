//! Real-syscall sandbox correctness (level 4). Runs an actual command inside a `kern box`
//! sandbox and asserts isolation + exit-code propagation. **Skip-graceful**: if unprivileged
//! user namespaces or a static busybox are unavailable (e.g. a locked-down CI runner), the
//! test returns early instead of failing - so x86 CI stays green either way.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn kern() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kern"))
}

/// Run `kern <args>` (which is expected to print something) and return its output, retrying a few
/// times while **stdout is empty**. Under this suite's heavy parallelism, `Command::output()`'s
/// pipe occasionally comes back empty even though the box ran (exit 0) - a `systemd-run --scope` +
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
/// blocks the `unshare` for unconfined binaries - so a sysctl-only check thinks userns is fine,
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
                    return true; // can't tell - stay permissive
                }
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
            }
            _ => true, // fork failed - stay permissive (old behaviour)
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

/// Compile `src` (written as `srcname`) into a throwaway static binary with the first working
/// compiler in `cands` plus `flags`, or `None` if no compiler works or the build fails (the caller
/// SKIPs). The binary lands in a per-`tag` temp dir the CALLER removes once it has copied the binary
/// out (`remove_dir_all(returned.parent())`), so a successful build leaves nothing behind. Shared body
/// for both the C and the freestanding-asm builders - they differ only in candidates, flags and the
/// source extension.
fn compile_helper(
    cands: &[&str],
    flags: &[&str],
    src: &str,
    srcname: &str,
    tag: &str,
) -> Option<PathBuf> {
    let cc = cands.iter().copied().find(|c| {
        Command::new(c)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })?;
    let dir = std::env::temp_dir().join(format!("kern-it-cc-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).ok()?;
    let spath = dir.join(srcname);
    let opath = dir.join("out");
    fs::write(&spath, src).ok()?;
    let ok = Command::new(cc)
        .args(flags)
        .arg("-o")
        .arg(&opath)
        .arg(&spath)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if ok && opath.exists() {
        Some(opath)
    } else {
        let _ = fs::remove_dir_all(&dir);
        None
    }
}

/// A static C helper we can drop into an otherwise-empty rootfs (no shared libraries). Used where
/// busybox cannot express the probe (e.g. it has no `AF_PACKET` applet).
fn compile_static_helper(src: &str, tag: &str) -> Option<PathBuf> {
    compile_helper(
        &["cc", "gcc", "clang"],
        &["-static", "-O2"],
        src,
        "h.c",
        tag,
    )
}

/// A **freestanding 32-bit (i386)** static binary from GAS source. `-nostdlib` means no 32-bit
/// libc/crt is needed (the source provides `_start`), so it builds on a plain `cc` without
/// `gcc-multilib`. Used to fire a raw `int 0x80` from a real i386 process - the foreign-ABI path a
/// number-confusion bypass of the x86_64 seccomp filter would take.
#[cfg(target_arch = "x86_64")]
fn compile_i386_freestanding(asm: &str, tag: &str) -> Option<PathBuf> {
    compile_helper(
        &["cc", "gcc"],
        &["-m32", "-nostdlib", "-static"],
        asm,
        "p.s",
        tag,
    )
}

/// Copy a just-built helper binary into `rootfs_root/name`, then remove its now-garbage build dir so a
/// successful compile leaves no `/tmp` residue. Call after any host-side use of the binary.
fn place_helper(helper: &Path, rootfs_root: &Path, name: &str) {
    fs::copy(helper, rootfs_root.join(name)).unwrap();
    if let Some(dir) = helper.parent() {
        let _ = fs::remove_dir_all(dir);
    }
}

/// Source for a helper that invokes one syscall BY NUMBER (argv[1], `strtol` base 0 so both decimal
/// and `0x..` hex parse) with benign zero args, then exits 0. A KILL vector never returns (SIGSYS
/// reaps it); a benign one returns and exits 0. Shared by the mount-family and x32 tests - the filter
/// decides on the number alone, so zero args are fine (refused before the kernel reads them).
const SYSCALL_BY_NR_SRC: &str = r#"
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    syscall(strtol(argv[1], 0, 0), 0, 0, 0, 0, 0, 0);
    return 0;
}
"#;

/// Pull the hex value of a `CapXxx:` line out of `/proc/self/status` text (the last whitespace field).
fn cap_hex<'a>(status: &'a str, cap: &str) -> Option<&'a str> {
    status
        .lines()
        .find(|l| l.starts_with(cap))?
        .split_whitespace()
        .last()
}

#[test]
fn box_require_limits_starts_when_caps_bind_else_refuses() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "reqlim");
    let rootfs = root.to_str().unwrap();
    // `--require-limits` must NOT spuriously refuse a box whose caps CAN be enforced. Where cgroup v2
    // is delegated the box runs and exits 0. Where it cannot (WSL2 without cgroup_enable=memory, a CI
    // sandbox) the flag CORRECTLY refuses with a non-zero exit that names itself - that IS the
    // contract, so treat that path as a skip, not a failure.
    let out = kern()
        .args([
            "box",
            "reqlim",
            "--rootfs",
            rootfs,
            "--require-limits",
            "--",
            "/bin/busybox",
            "true",
        ])
        .output()
        .expect("run kern");
    let err = String::from_utf8_lossy(&out.stderr);
    let _ = fs::remove_dir_all(&root);
    if err.contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        return;
    }
    if err.contains("require-limits") {
        // The OTHER half of the wiring, asserted rather than skipped: where caps CANNOT bind,
        // `--require-limits` must REFUSE (not run uncapped). A future miswiring that passes `false` for
        // `require_all` would run the box uncapped here and, as a bare skip, pass green - so assert the
        // refusal is well-formed: non-zero exit, and it names the way out (`--allow-uncapped`).
        assert!(
            !out.status.success(),
            "a refusing --require-limits box must exit non-zero (stderr: {err})"
        );
        assert!(
            err.contains("--allow-uncapped"),
            "the refusal must name the way out, or the message regressed (stderr: {err})"
        );
        eprintln!("verified: --require-limits refused where caps are unenforceable");
        return;
    }
    assert!(
        out.status.success(),
        "a --require-limits box must run where caps ARE enforceable; exit {:?} (stderr: {err})",
        out.status.code()
    );
}

#[test]
fn box_security_profile_untrusted_forces_read_only_root() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "secprof");
    let rootfs = root.to_str().unwrap();
    // `--security-profile=untrusted` forces a read-only root (one of its constituents): a write under
    // `/` must fail. It also prints its resolved constituents to stderr, so the macro is visible.
    let out = kern()
        .args([
            "box",
            "secprof",
            "--rootfs",
            rootfs,
            "--security-profile",
            "untrusted",
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            "if echo x > /w 2>/dev/null; then echo WRITABLE; else echo READONLY; fi",
        ])
        .output()
        .expect("run kern");
    let err = String::from_utf8_lossy(&out.stderr);
    let outp = String::from_utf8_lossy(&out.stdout);
    let _ = fs::remove_dir_all(&root);
    if err.contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        return;
    }
    assert!(
        err.contains("security-profile"),
        "the profile must announce its resolved constituents (stderr: {err})"
    );
    assert!(
        outp.contains("READONLY"),
        "the untrusted profile must force a read-only root (stdout: {outp}, stderr: {err})"
    );
}

#[test]
fn box_security_profile_announcement_reflects_a_surviving_cap_add() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    // Transparency: a `--cap-add` wins over the profile's drop-all (adds are subtracted from the drop
    // mask), so the box KEEPS that cap. The announced line must SHOW it, not read a bare `cap-drop=ALL`
    // while the box retains a re-added cap - the same "never advertise a posture it did not get"
    // standard the seccomp value is held to. The line is printed during setup (before the userns clone),
    // so this asserts the honesty of the message regardless of whether the box fully starts here.
    let root = build_rootfs(&busybox, "spcapadd");
    let rootfs = root.to_str().unwrap();
    let out = kern()
        .args([
            "box",
            "spcapadd",
            "--rootfs",
            rootfs,
            "--security-profile",
            "untrusted",
            "--cap-add",
            "NET_BIND_SERVICE",
            "--",
            "/bin/busybox",
            "true",
        ])
        .output()
        .expect("run kern");
    let err = String::from_utf8_lossy(&out.stderr);
    let _ = fs::remove_dir_all(&root);
    assert!(
        err.contains("cap-add=NET_BIND_SERVICE"),
        "the untrusted-profile line must reflect a surviving --cap-add, not just cap-drop=ALL \
         (stderr: {err})"
    );
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
    assert!(
        out.status.success(),
        "detached start should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

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

/// `kern ps -a` surfaces a box that has EXITED (from the `waitexit` breadcrumb) with its exit code,
/// while plain `kern ps` still shows only the live ones - Docker's `ps -a`, without kern becoming a
/// stateful container store (the breadcrumb is reaped by `gc`). Regression guard for the exit-record
/// format: the code must round-trip through the multi-line sidecar and render as `exited (7)`.
#[test]
fn box_ps_dash_a_shows_an_exited_box_with_its_exit_code() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "psa");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-xdg-psa-{}", std::process::id()));
    let _ = fs::create_dir_all(&xdg);

    // A detached box that exits promptly with a KNOWN non-zero code.
    let out = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            "psadead",
            "--rootfs",
            rootfs,
            "-d",
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            "exit 7",
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }
    assert!(
        out.status.success(),
        "detached start should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The supervisor writes the `waitexit` breadcrumb AFTER the box exits, so poll. `ps -a --json`
    // must show `psadead` with `exit_code 7`; the LIVE-only `ps` must NOT (it is pruned on read).
    let mut saw_exited = false;
    for _ in 0..80 {
        let all = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["ps", "-a", "--json"])
            .output()
            .expect("run kern");
        let s = String::from_utf8_lossy(&all.stdout);
        if s.contains("psadead") && s.contains("\"exit_code\":7") {
            let live = kern()
                .env("XDG_RUNTIME_DIR", &xdg)
                .args(["ps", "--json"])
                .output()
                .expect("run kern");
            assert!(
                !String::from_utf8_lossy(&live.stdout).contains("psadead"),
                "an exited box must appear only in `ps -a`, never in plain `ps`"
            );
            saw_exited = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        saw_exited,
        "ps -a should list the exited box with exit_code 7 within ~8s"
    );

    // The same exited row renders through `--format`, proving the exit code survived the round-trip.
    let fmt = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["ps", "-a", "--format", "{{.Names}} {{.Status}}"])
        .output()
        .expect("run kern");
    assert!(
        String::from_utf8_lossy(&fmt.stdout).contains("psadead exited (7)"),
        "ps -a --format should render the exited status: {}",
        String::from_utf8_lossy(&fmt.stdout)
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
}

/// Remove a runtime dir ONLY if this test created it. [`runtime_dir_for_capped_box`] can hand back
/// the session's REAL `/run/user/<uid>`, and a blind `remove_dir_all` on that would walk the user's
/// live session sockets - dbus, pipewire, the compositor - deleting whatever it reached before the
/// first FUSE mount aborted it. This is the guard for that, not a tidiness helper.
fn drop_runtime_dir_if_ours(dir: &Path) {
    if dir.starts_with(std::env::temp_dir()) {
        let _ = fs::remove_dir_all(dir);
    }
}

/// The runtime dir for a test whose box needs its OWN cgroup: the REAL one when this session has a
/// systemd user manager, because that is how kern reaches the manager and how a box gets a dedicated
/// cgroup instead of landing in the caller's ambient one. Measured while chasing a flaky test: under
/// a private `$XDG_RUNTIME_DIR` the box joined the terminal's own scope
/// (`app-org.chromium.Chromium-3640.scope`), so nothing was recorded for it and the behaviour that
/// depends on that record could not hold. Falls back to a private dir, where such a box refuses to
/// start under `--require-limits` and the caller skips with kern's own reason.
fn runtime_dir_for_capped_box(tag: &str) -> PathBuf {
    let uid = unsafe { libc::getuid() };
    let real = PathBuf::from(format!("/run/user/{uid}"));
    if real.join("systemd").is_dir() {
        return real;
    }
    let d = std::env::temp_dir().join(format!("kern-it-xdg-{tag}-{}", std::process::id()));
    let _ = fs::create_dir_all(&d);
    d
}

/// `kern stop` on a workload that traps the signal and exits cleanly must record THAT exit code, not
/// the SIGKILL it never sent. The 137 was hardcoded when a stop was always a SIGKILL; the graceful
/// phase arrived later and the constant did not follow it in, so every clean shutdown of a real
/// service (nginx, redis, postgres - the ones that trap and flush) reported as killed.
///
/// The SIGTERM-IGNORING box is the discriminant: there 137 is the truth (kern really does SIGKILL an
/// init the kernel would never deliver the signal to), so a fix that simply stopped writing 137 would
/// fail this half. Both halves in one test, because only the pair distinguishes them.
#[test]
fn stop_records_the_workloads_own_exit_code_not_a_blanket_137() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "stopcode");
    let rootfs = root.to_str().unwrap();
    // Reading the init's status without racing its reaper needs the box to have its OWN cgroup, and
    // `--require-limits` is that precondition in kern's own vocabulary: it refuses to start where the
    // caps do not bind, which is exactly where no cgroup is recorded. A host that cannot provide one
    // therefore SKIPS here, with kern's refusal as the reason, instead of failing intermittently.
    let xdg = runtime_dir_for_capped_box("stopcode");
    let pid = std::process::id();

    // (box name, what its init does with SIGTERM, the code that must be recorded)
    let cases = [
        (format!("stopclean-{pid}"), "trap 'exit 7' TERM", 7),
        (format!("stopign-{pid}"), "trap '' TERM", 137),
    ];
    let mut ran = false;
    for (name, trap, want) in cases {
        let name = name.as_str();
        let out = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args([
                "box",
                name,
                "--rootfs",
                rootfs,
                "-d",
                "--require-limits",
                "--stop-timeout",
                "3",
                "--",
                "/bin/busybox",
                "sh",
                "-c",
                &format!("{trap}; while :; do sleep 0.2; done"),
            ])
            .output()
            .expect("run kern");
        if !out.status.success() {
            eprintln!(
                "skip: detached box did not start here: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            continue;
        }
        // Let the shell install its trap before the signal arrives: signalling first would test the
        // startup race, not the shutdown contract.
        std::thread::sleep(std::time::Duration::from_millis(700));
        let stop = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["stop", name])
            .output()
            .expect("run kern");
        assert!(
            stop.status.success(),
            "stop should succeed: {}",
            String::from_utf8_lossy(&stop.stderr)
        );
        ran = true;

        let mut got = None;
        let mut last = String::new();
        for _ in 0..40 {
            let all = kern()
                .env("XDG_RUNTIME_DIR", &xdg)
                .args(["ps", "-a", "--json"])
                .output()
                .expect("run kern");
            let s = String::from_utf8_lossy(&all.stdout);
            last = s.to_string();
            if let Some(row) = s.split(name).nth(1) {
                if let Some(code) = row.split("\"exit_code\":").nth(1) {
                    got = code
                        .split(|c: char| !c.is_ascii_digit() && c != '-')
                        .find(|t| !t.is_empty())
                        .and_then(|t| t.parse::<i32>().ok());
                    if got.is_some() {
                        break;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(
            got,
            Some(want),
            "`kern stop` on a box whose init does `{trap}` must record exit {want}; ps -a said {last}"
        );
        // The same number through the other surface that serves it. `kern wait` on a box that has
        // already exited answers from the exit record, like `docker wait` on a stopped container -
        // a box `ps -a` lists WITH its code must not be one `wait` refuses to speak about.
        let w = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["wait", name])
            .output()
            .expect("run kern");
        assert!(
            w.status.success(),
            "`kern wait` on an exited box should resolve it: {}",
            String::from_utf8_lossy(&w.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&w.stdout).trim(),
            want.to_string(),
            "`kern wait` must print the same code `ps -a` shows"
        );
    }
    if !ran {
        eprintln!("skip: no box started in this environment");
    }

    let _ = fs::remove_dir_all(&root);
    drop_runtime_dir_if_ours(&xdg);
}

/// A signal aimed at a FOREGROUND `kern box` is aimed at the box: kern forwards it, waits, and exits
/// with the WORKLOAD's code - not with its own death.
///
/// This is what makes a box's exit code independent of the init system. MEASURED before it: an Arduino
/// UNO Q (systemd 257) reported 143 for a box past its `--memory` cap where a Raspberry Pi 5 (252) and
/// a Jetson Orin Nano (249) reported 137 - the newer manager's `OOMPolicy=stop` also stops the scope,
/// and its SIGTERM killed kern while the box's real status was already there to be read. The same
/// mechanism is what a plain `kill <kern>` hits, which is what this test can reproduce anywhere.
///
/// The second signal must still end it, so a workload that ignores the first cannot make kern
/// unkillable.
#[test]
fn a_signal_to_a_foreground_box_reports_the_workloads_code_and_the_second_always_ends_it() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "fgsignal");
    let rootfs = root.to_str().unwrap();
    let pid = std::process::id();

    // POSITIVE CONTROL, and the only honest way to skip here. A signalled box is watched through its
    // exit CODE, so "the host cannot run a box" and "the contract is broken" arrive on the same
    // channel: the first version of this test guessed which codes meant the former (126/127) and a
    // GitHub runner answered 1, turning an environment into a red build. So the question is asked
    // separately, of a box that is not signalled at all - if THAT cannot run, nothing below can be
    // read, and kern's own stderr is the reason printed.
    let control = kern()
        .args([
            "box",
            &format!("fgsigctl-{pid}"),
            "--rootfs",
            rootfs,
            "--",
            "/bin/busybox",
            "true",
        ])
        .output()
        .expect("run kern");
    if !control.status.success() {
        eprintln!(
            "skip: this host cannot start a plain foreground box: {}",
            String::from_utf8_lossy(&control.stderr).trim()
        );
        let _ = fs::remove_dir_all(&root);
        return;
    }

    // (what the init does with SIGTERM, how many signals we send, the code kern must exit with)
    let cases = [
        ("trap 'exit 42' TERM", 1, 42),
        // Ignored, so the first signal can never end it: the SECOND is kern's own exit, 128+SIGTERM.
        ("trap '' TERM", 2, 143),
    ];
    for (trap, signals, want) in cases {
        let name = format!("fgsig{signals}-{pid}");
        // kern's stderr goes to a file rather than to /dev/null: a box that fails to start for a
        // reason the control did not hit must say so in the failure message, not leave a bare number.
        let errlog = std::env::temp_dir().join(format!("kern-{name}.err"));
        let err = fs::File::create(&errlog).expect("create stderr log");
        let mut child = kern()
            .args([
                "box",
                &name,
                "--rootfs",
                rootfs,
                "--",
                "/bin/busybox",
                "sh",
                "-c",
                &format!("{trap}; while :; do sleep 0.2; done"),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::from(err))
            .spawn()
            .expect("spawn kern");
        // WAIT for the box to be observably up, do not sleep and hope. Signalling a box that has not
        // started yet tests the startup race and not the shutdown contract, and how long a start takes
        // is a property of the host: measured in milliseconds here, and slow enough on a cold CI runner
        // that a fixed sleep is a coin toss. `ps` answering with this box's name is the fact itself.
        let mut up = false;
        for _ in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let ps = kern().args(["ps", "--json"]).output().expect("run kern");
            if String::from_utf8_lossy(&ps.stdout).contains(name.as_str()) {
                up = true;
                break;
            }
            // The box can also have died on its own; then there is nothing to signal and nothing to
            // read, and the reason is in kern's stderr below.
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
        }
        if !up {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!(
                "skip: the box never came up on this host: {}",
                fs::read_to_string(&errlog).unwrap_or_default().trim()
            );
            let _ = fs::remove_file(&errlog);
            continue;
        }
        // The shell needs its trap installed, which happens at its first instruction, after the box is
        // listed. One short settle is honest here: it is bounded work, not a start of unknown length.
        std::thread::sleep(std::time::Duration::from_millis(300));
        for _ in 0..signals {
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
        let status = child.wait().expect("wait kern");
        let code = status.code().unwrap_or(-1);
        let said = fs::read_to_string(&errlog).unwrap_or_default();
        let _ = fs::remove_file(&errlog);
        assert_eq!(
            code,
            want,
            "a foreground box whose init does `{trap}`, sent {signals} SIGTERM(s), must make kern \
             exit {want}; kern said: {}",
            said.trim()
        );
    }
    let _ = fs::remove_dir_all(&root);
}

/// The grace is what the caller asked for, not that minus up to a second. `stop` waits the time LEFT
/// until a deadline shared by the whole stack, and that remainder used to be rounded DOWN to whole
/// seconds: `--stop-timeout 3` gave a workload 2 s. Measured before the fix at 2019 ms and a SIGKILL
/// mid-flush, where Docker's `stop -t 3` let the same workload finish in 2799 ms and exit 5.
///
/// The workload's handler never returns, so `stop` is forced to spend the WHOLE grace and the
/// measurement is the grace itself: ~3 s fixed against ~2 s truncated. That shape is one-sided under
/// load - a busy machine can only make the wait LONGER, never shorter - which the obvious test (a
/// timed flush that must finish inside the grace) is not: there, load inflates the workload and
/// reports a defect that is really the platform. MEASURED under WSL2, a 1.5 s flush takes 1723 ms
/// and a 0.5 s one 1007 ms, which is exactly how much margin that shape has to give away.
///
/// The arithmetic itself is `remaining_grace_keeps_the_milliseconds_it_was_given`; this is the
/// wiring, that the millisecond value actually reaches the poll.
#[test]
fn stop_grace_is_not_rounded_down_to_whole_seconds() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "grace");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-xdg-grace-{}", std::process::id()));
    let _ = fs::create_dir_all(&xdg);

    let out = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            "graceflush",
            "--rootfs",
            rootfs,
            "-d",
            "--stop-timeout",
            "3",
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            "trap 'sleep 60' TERM; while :; do sleep 0.2; done",
        ])
        .output()
        .expect("run kern");
    if !out.status.success() {
        eprintln!(
            "skip: detached box did not start here: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }
    // Let the trap be installed before the signal arrives.
    std::thread::sleep(std::time::Duration::from_millis(700));
    let started = std::time::Instant::now();
    let stop = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["stop", "graceflush"])
        .output()
        .expect("run kern");
    let waited = started.elapsed();
    assert!(
        stop.status.success(),
        "stop should succeed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    // Truncated, this returns at ~2 s. The bound sits between the two, far enough from the fixed
    // value that only a regression - not a slow machine - can reach it.
    assert!(
        waited >= std::time::Duration::from_millis(2600),
        "a 3 s grace must be spent as 3 s, not floored to 2: stop returned after {} ms",
        waited.as_millis()
    );

    // And the handler that never returned really was SIGKILLed at the end of it.
    let mut got = None;
    let mut last = String::new();
    for _ in 0..40 {
        let all = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["ps", "-a", "--json"])
            .output()
            .expect("run kern");
        let s = String::from_utf8_lossy(&all.stdout);
        last = s.to_string();
        if let Some(row) = s.split("graceflush").nth(1) {
            if let Some(code) = row.split("\"exit_code\":").nth(1) {
                got = code
                    .split(|c: char| !c.is_ascii_digit() && c != '-')
                    .find(|t| !t.is_empty())
                    .and_then(|t| t.parse::<i32>().ok());
                if got.is_some() {
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(
        got,
        Some(137),
        "a handler that never returns is SIGKILLed at the end of the grace; ps -a said {last}"
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
}

/// A member's own `--stop-timeout` is when IT is killed, not when the longest-lived member of the
/// same teardown is. Phase 1 signals every box at once and the loop then waits on them one at a time,
/// so a box whose turn comes after a longer-lived one has already spent its grace and dies with it -
/// MEASURED on a four-service stack asking 1, 2, 4 and 6 s, all hanging in their handler: the 1 s
/// service was killed at 6201 ms, six times what it asked for, and the 4 s one at 6201 as well.
/// Waiting on the SHORTEST grace first makes the sequential loop optimal: each member waits only the
/// difference from the one before it, so all four now die on their own second (1195, 2196, 4200,
/// 6196) and the stack still finishes in max(grace).
///
/// Both boxes hang in their handler, so neither can exit early and the only thing under test is when
/// kern gives up on each. The bound is generous in both directions - the short box is expected at
/// ~1.2 s and the regression puts it at ~5.2 s - so a loaded machine cannot reach it.
#[test]
fn a_short_stop_timeout_is_not_held_to_a_longer_one_in_the_same_teardown() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "gracemix");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-xdg-gracemix-{}", std::process::id()));
    let _ = fs::create_dir_all(&xdg);
    let hang = "trap 'sleep 60' TERM; while :; do sleep 0.2; done";

    // (name, its own grace in seconds)
    let mut started = Vec::new();
    for (name, grace) in [("gracelong", "5"), ("graceshort", "1")] {
        let out = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args([
                "box",
                name,
                "--rootfs",
                rootfs,
                "-d",
                "--stop-timeout",
                grace,
                "--",
                "/bin/busybox",
                "sh",
                "-c",
                hang,
            ])
            .output()
            .expect("run kern");
        if !out.status.success() {
            eprintln!(
                "skip: detached box did not start here: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let _ = kern()
                .env("XDG_RUNTIME_DIR", &xdg)
                .args(["stop", "--all"])
                .output();
            let _ = fs::remove_dir_all(&root);
            drop_runtime_dir_if_ours(&xdg);
            return;
        }
        started.push(name);
    }
    // The short box's PID-namespace init: watching /proc for it is how we see WHEN kern gave up on
    // that box specifically, which a wall-clock on the whole `stop` cannot show.
    let inspect = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["inspect", "graceshort", "--json"])
        .output()
        .expect("run kern");
    let pid1: Option<i32> = String::from_utf8_lossy(&inspect.stdout)
        .split("\"pid1\":")
        .nth(1)
        .and_then(|t| {
            t.split(|c: char| !c.is_ascii_digit())
                .find(|x| !x.is_empty())
                .and_then(|x| x.parse().ok())
        });
    let Some(pid1) = pid1.filter(|p| *p > 0) else {
        eprintln!("skip: could not read the short box's pid1");
        let _ = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["stop", "--all"])
            .output();
        let _ = fs::remove_dir_all(&root);
        drop_runtime_dir_if_ours(&xdg);
        return;
    };
    // Let both shells install their handler before the signal arrives.
    std::thread::sleep(std::time::Duration::from_millis(700));

    let started_at = std::time::Instant::now();
    let mut stop = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["stop", "gracelong", "graceshort"])
        .spawn()
        .expect("spawn kern stop");
    let mut short_died = None;
    while started_at.elapsed() < std::time::Duration::from_secs(10) {
        if !Path::new(&format!("/proc/{pid1}")).exists() {
            short_died = Some(started_at.elapsed());
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let _ = stop.wait();

    let died = short_died.expect("the 1 s box must be gone well inside the 5 s one's grace");
    assert!(
        died < std::time::Duration::from_millis(3000),
        "a box asking 1 s must be killed on its own grace, not held to the 5 s one it was stopped \
         with: it died {} ms in",
        died.as_millis()
    );

    let _ = fs::remove_dir_all(&root);
    drop_runtime_dir_if_ours(&xdg);
}

/// The other half of the grace contract, and the half that reads like a bug until you know the
/// kernel rule: a grace the signal CANNOT end is skipped, not sat out.
///
/// A namespace PID 1 is special - the kernel DISCARDS a signal it has no handler for - so a box
/// whose init ignores SIGTERM cannot die of it, and waiting is a guaranteed wait for an event that
/// can never happen. kern reads `SigCgt` and goes straight to the SIGKILL; Docker and Podman sit out
/// the full grace and reach the same place later (MEASURED at 10 278 and 10 287 ms against 21.9).
///
/// Paired with `stop_grace_is_not_rounded_down_to_whole_seconds` deliberately, because the two shapes
/// look identical in a shell and behave oppositely: `trap "" TERM` is IGNORED (fast), while
/// `trap "sleep 60" TERM` is CAUGHT and never returns (the full grace). An audit that measures one
/// and compares it against the other's number reports a defect that is not there, so both numbers
/// live in tests rather than in prose.
#[test]
fn stop_skips_a_grace_the_kernel_would_make_pointless() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "skipgrace");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-xdg-skipgrace-{}", std::process::id()));
    let _ = fs::create_dir_all(&xdg);

    let out = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            "ignoresterm",
            "--rootfs",
            rootfs,
            "-d",
            "--stop-timeout",
            "3",
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            "trap '' TERM; while :; do sleep 0.2; done",
        ])
        .output()
        .expect("run kern");
    if !out.status.success() {
        eprintln!(
            "skip: detached box did not start here: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }
    // Let the shell install the disposition before the signal arrives.
    std::thread::sleep(std::time::Duration::from_millis(700));
    let started = std::time::Instant::now();
    let stop = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["stop", "ignoresterm"])
        .output()
        .expect("run kern");
    let waited = started.elapsed();
    assert!(
        stop.status.success(),
        "stop should succeed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    // Expected in single-digit milliseconds; a regression that waits it out returns at ~3000. The
    // bound is two orders of magnitude above the measurement and far below the grace, so a slow or
    // loaded machine cannot reach it.
    assert!(
        waited < std::time::Duration::from_millis(1000),
        "a grace the init cannot act on must be skipped, not waited out: stop took {} ms",
        waited.as_millis()
    );

    let mut got = None;
    let mut last = String::new();
    for _ in 0..40 {
        let all = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["ps", "-a", "--json"])
            .output()
            .expect("run kern");
        let s = String::from_utf8_lossy(&all.stdout);
        last = s.to_string();
        if let Some(row) = s.split("ignoresterm").nth(1) {
            if let Some(code) = row.split("\"exit_code\":").nth(1) {
                got = code
                    .split(|c: char| !c.is_ascii_digit() && c != '-')
                    .find(|t| !t.is_empty())
                    .and_then(|t| t.parse::<i32>().ok());
                if got.is_some() {
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // 137 is the truth here, not a fallback: this box really was SIGKILLed.
    assert_eq!(
        got,
        Some(137),
        "an init that ignores the signal is SIGKILLed, and that is what must be recorded; ps -a said {last}"
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
}

#[test]
fn inspect_shows_detail_then_prune_reclaims_logs() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "inspect");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-insp-{}", std::process::id()));
    let _ = fs::create_dir_all(&xdg);

    // A detached box that lives ~2s.
    let out = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            "insp",
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
    assert!(
        out.status.success(),
        "detached start should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // While alive, `inspect --json` reports the box's identity (pid + command).
    let mut inspected = false;
    for _ in 0..40 {
        let o = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["inspect", "insp", "--json"])
            .output()
            .expect("run kern");
        let s = String::from_utf8_lossy(&o.stdout);
        if o.status.success() && s.contains("\"name\":\"insp\"") && s.contains("\"pid\":") {
            assert!(
                s.contains("sleep"),
                "inspect should include the command: {s}"
            );
            inspected = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(inspected, "inspect should report a live box within ~2s");

    // Inspecting a name that isn't running fails (and would carry the `kern ps` hint).
    let miss = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["inspect", "ghost"])
        .output()
        .expect("run kern");
    assert!(!miss.status.success(), "inspect of a dead name must fail");

    // Wait for the box to exit (its log sidecar stays behind).
    for _ in 0..60 {
        let after = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["ps", "--json"])
            .output()
            .expect("run kern");
        if !String::from_utf8_lossy(&after.stdout).contains("insp") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // `prune` reclaims the dead box's leftover log; a subsequent prune finds nothing. Under this
    // suite's parallel load the box's log/breadcrumb can settle a beat AFTER it leaves `ps`, so the
    // first prune may leave a transient 0-byte artifact the next prune sweeps - retry until a prune
    // converges to "nothing to prune" (each iteration reclaims any lagging file, so it converges in a
    // couple of rounds). Bounded, so a real never-clearing leak still fails.
    let pruned = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["prune"])
        .output()
        .expect("run kern");
    assert!(pruned.status.success(), "prune should succeed");
    let mut converged = String::new();
    let mut clean = false;
    for _ in 0..20 {
        let again = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["prune"])
            .output()
            .expect("run kern");
        converged = String::from_utf8_lossy(&again.stdout).to_string();
        if converged.contains("nothing to prune") {
            clean = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        clean,
        "prune should converge to 'nothing to prune'; last output: {converged}"
    );

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
    assert!(
        out.status.success(),
        "detached start should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

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

/// A named volume (`-v name:/dest`) is auto-created and **persists across boxes**: what one box
/// writes, a later box reads back. Fully rootless (a dir bind-mount).
#[test]
fn named_volume_persists_across_boxes() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let data = std::env::temp_dir().join(format!("kern-it-vol-{}", std::process::id()));
    let _ = fs::create_dir_all(&data);
    let root = build_rootfs(&busybox, "namedvol");
    let rootfs = root.to_str().unwrap();

    // Box A writes into the auto-created volume.
    let a = kern()
        .env("XDG_DATA_HOME", &data)
        .args([
            "box",
            "va",
            "--rootfs",
            rootfs,
            "-v",
            "shared:/work",
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            "echo persisted > /work/f; echo OK",
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&a.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&data);
        return;
    }
    assert!(
        a.status.success(),
        "box A should write: {}",
        String::from_utf8_lossy(&a.stderr)
    );

    // Box B reads it back from the same named volume (retry on the empty-pipe race).
    let mut got = String::new();
    for _ in 0..6 {
        let b = kern()
            .env("XDG_DATA_HOME", &data)
            .args([
                "box",
                "vb",
                "--rootfs",
                rootfs,
                "-v",
                "shared:/work",
                "--",
                "/bin/busybox",
                "cat",
                "/work/f",
            ])
            .output()
            .expect("run kern");
        got = String::from_utf8_lossy(&b.stdout).into_owned();
        if !got.trim().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(80));
    }
    assert!(
        got.contains("persisted"),
        "box B must read what box A wrote: {got}"
    );

    // The volume shows up in `kern volume ls`.
    let ls = kern()
        .env("XDG_DATA_HOME", &data)
        .args(["volume", "ls"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&ls.stdout).contains("shared"));
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&data);
}

/// A `vdisk:` profile mounts a size-capped volume at `/vdisk/<name>` (rootless: a `tmpfs size=`),
/// and the size cap is really enforced - writing past it fails with ENOSPC.
#[test]
fn box_vdisk_mounts_size_capped_volume() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let cfgdir = std::env::temp_dir().join(format!("kern-it-vd-{}", std::process::id()));
    let _ = fs::create_dir_all(cfgdir.join("kern"));
    fs::write(
        cfgdir.join("kern/kern.toml"),
        "[[vdisk]]\nname = \"scratch\"\nbackend = \"ram\"\nsize = \"8m\"\n",
    )
    .unwrap();
    let root = build_rootfs(&busybox, "vdisk");
    let out = kern()
        .env("XDG_CONFIG_HOME", &cfgdir)
        .args([
            "box",
            "vd",
            "vdisk:scratch",
            "--rootfs",
            root.to_str().unwrap(),
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            // 4 MiB fits (under the 8 MiB cap); a further 8 MiB must fail with ENOSPC.
            "dd if=/dev/zero of=/vdisk/scratch/a bs=1M count=4 2>/dev/null && echo WROTE4; \
             dd if=/dev/zero of=/vdisk/scratch/b bs=1M count=8 2>/dev/null && echo WROTE8 || echo capped",
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&cfgdir);
        return;
    }
    let o = String::from_utf8_lossy(&out.stdout);
    assert!(
        o.contains("WROTE4"),
        "a write within the quota must succeed: {o}"
    );
    assert!(
        o.contains("capped") && !o.contains("WROTE8"),
        "a write past the size quota must fail (ENOSPC): {o}"
    );
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&cfgdir);
}

/// A `vgpio:` profile bind-mounts ONLY its listed devices into the box (real I/O passthrough), and
/// deny-by-default still holds - a device not in the profile stays absent. Skip-graceful: needs a
/// real host device (any `/dev/i2c-*` or `/dev/gpiochip*`); skipped where none exist (typical CI).
#[test]
fn box_vgpio_passes_listed_devices_only() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    // Find two distinct real devices: one to grant, one to withhold (proves deny-by-default).
    let devs: Vec<String> = (0..32)
        .map(|n| format!("/dev/i2c-{n}"))
        .filter(|p| Path::new(p).exists())
        .collect();
    let (grant, withhold) = match devs.as_slice() {
        [a, b, ..] => (a.clone(), b.clone()),
        _ => {
            eprintln!("skip: need ≥2 /dev/i2c-* devices for the vgpio passthrough test");
            return;
        }
    };
    let cfgdir = std::env::temp_dir().join(format!("kern-it-vg-{}", std::process::id()));
    let _ = fs::create_dir_all(cfgdir.join("kern"));
    fs::write(
        cfgdir.join("kern/kern.toml"),
        format!("[[vgpio]]\nname = \"io\"\nbackend = \"host\"\ni2c = [\"{grant}\"]\n"),
    )
    .unwrap();
    let root = build_rootfs(&busybox, "vgpio");
    let out = kern()
        .env("XDG_CONFIG_HOME", &cfgdir)
        .args([
            "box",
            "vg",
            "vgpio:io",
            "--rootfs",
            root.to_str().unwrap(),
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            &format!(
                "test -e {grant} && echo GRANTED; test -e {withhold} && echo LEAK || echo denied"
            ),
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&cfgdir);
        return;
    }
    let o = String::from_utf8_lossy(&out.stdout);
    assert!(
        o.contains("GRANTED"),
        "granted device must be in the box: {o}"
    );
    assert!(
        o.contains("denied") && !o.contains("LEAK"),
        "deny-by-default must hold: {o}"
    );
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&cfgdir);
}

/// A `vcpu:` profile applies to a `kern box` too (private idiom `kern box vcpu:<name> …`): the box
/// workload runs pinned to the profile's CPUs. Profile token order (before/after the name) is free.
#[test]
fn box_applies_vcpu_profile() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let cfgdir = std::env::temp_dir().join(format!("kern-it-bcfg-{}", std::process::id()));
    let _ = fs::create_dir_all(cfgdir.join("kern"));
    fs::write(
        cfgdir.join("kern/kern.toml"),
        "[[vcpu]]\nname = \"pin0\"\nbackend = \"host\"\ncpuset = \"0\"\nmemory = \"64m\"\n",
    )
    .unwrap();
    let root = build_rootfs(&busybox, "boxprof");
    let out = kern()
        .env("XDG_CONFIG_HOME", &cfgdir)
        .args([
            "box",
            "bp",
            "vcpu:pin0",
            "--rootfs",
            root.to_str().unwrap(),
            "--",
            "/bin/busybox",
            "grep",
            "Cpus_allowed_list",
            "/proc/self/status",
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&cfgdir);
        return;
    }
    let o = String::from_utf8_lossy(&out.stdout);
    let list = o
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .unwrap_or("");
    assert_eq!(list, "0", "box should be pinned to CPU 0 by vcpu:pin0: {o}");
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&cfgdir);
}

/// The config command surface round-trips: `kern examples` emits a config that `kern validate`
/// accepts and `kern config` lists - so the embedded example can never drift out of the schema.
#[test]
fn examples_output_validates_and_lists() {
    let dir = std::env::temp_dir().join(format!("kern-it-ex-{}", std::process::id()));
    let _ = fs::create_dir_all(&dir);
    let toml = dir.join("kern.toml");
    let ex = kern().args(["examples"]).output().expect("run kern");
    assert!(ex.status.success());
    fs::write(&toml, &ex.stdout).unwrap();

    let val = kern()
        .args(["validate", toml.to_str().unwrap()])
        .output()
        .expect("run kern");
    assert!(
        val.status.success(),
        "examples output must validate: {}",
        String::from_utf8_lossy(&val.stderr)
    );
    assert!(String::from_utf8_lossy(&val.stdout).contains("vcpu"));

    // A BAD VALUE for a recognized key fails validation with a non-zero exit and a line number.
    // (An unknown key would be tolerated/ignored - the parser only errors on malformed values of
    // keys it implements.)
    fs::write(&toml, "[[vcpu]]\nname = \"x\"\ncpus = abc\n").unwrap();
    let bad = kern()
        .args(["validate", toml.to_str().unwrap()])
        .output()
        .expect("run kern");
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("line 3"));
    let _ = fs::remove_dir_all(&dir);
}

/// A resource-centric `[[vcpu]]` profile in `kern.toml`, referenced by `kern run vcpu:<name>`,
/// applies its limits end-to-end: the whole chain (config discovery → classify → resolve → pin).
/// Pinning to CPU 0 is observable in `/proc/self/status` regardless of cgroup delegation.
#[test]
fn run_applies_vcpu_profile_from_kern_toml() {
    let cfgdir = std::env::temp_dir().join(format!("kern-it-cfg-{}", std::process::id()));
    let _ = fs::create_dir_all(cfgdir.join("kern"));
    fs::write(
        cfgdir.join("kern/kern.toml"),
        "[[vcpu]]\nname = \"pinned\"\nbackend = \"host\"\ncpuset = \"0\"\nmemory = \"64m\"\n",
    )
    .unwrap();
    // Retry on empty stdout - `kern run` re-execs into a systemd scope whose piped output can come
    // back empty under this suite's heavy parallelism (same race as `kern_out`).
    let mut o = String::new();
    for _ in 0..6 {
        let out = kern()
            .env("XDG_CONFIG_HOME", &cfgdir)
            .args([
                "run",
                "vcpu:pinned",
                "--",
                "grep",
                "Cpus_allowed_list",
                "/proc/self/status",
            ])
            .output()
            .expect("run kern");
        o = String::from_utf8_lossy(&out.stdout).into_owned();
        if !o.trim().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(80));
    }
    let list = o
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .unwrap_or("");
    assert_eq!(
        list, "0",
        "vcpu:pinned should pin to CPU 0 via the profile: {o}"
    );

    // `vgpu:` is NOT a kern-public concept (GPU is out of this edition): it is not a profile token,
    // so it is treated as a plain command - which doesn't exist - and the run fails, rather than
    // being recognized as any kind of "reserved" profile.
    let refused = kern()
        .env("XDG_CONFIG_HOME", &cfgdir)
        .args(["run", "vgpu:x", "--", "true"])
        .output()
        .expect("run kern");
    assert!(!refused.status.success());
    let _ = fs::remove_dir_all(&cfgdir);
}

/// `--cpuset-cpus` really pins the box, via `sched_setaffinity` - no cgroup `cpuset` delegation
/// needed. Pinning to CPU 0 (present on every host) must yield exactly `0` in the workload's
/// `Cpus_allowed_list`, which on any multi-CPU host differs from the unpinned `0-N`.
#[test]
fn box_cpuset_pins_cpus() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "cpuset");
    let rootfs = root.to_str().unwrap();
    let out = kern_out(&[
        "box",
        "pin",
        "--rootfs",
        rootfs,
        "--cpuset-cpus",
        "0",
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "grep Cpus_allowed_list /proc/self/status",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let o = String::from_utf8_lossy(&out.stdout);
    // The field is `Cpus_allowed_list:\t0` when pinned to CPU 0.
    let list = o
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .unwrap_or("");
    assert_eq!(list, "0", "box should be pinned to CPU 0 only, got '{o}'");
    let _ = fs::remove_dir_all(&root);
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

/// Device access is deny-by-default: the box's `/dev` is a fresh tmpfs with ONLY the safe
/// allowlist bound in, so a raw disk / physical-memory node is simply absent - and the box can't
/// fabricate one, because creating a device node in an unprivileged user namespace is refused by
/// the kernel (EPERM) even though `mknod` is reachable. That is what makes an eBPF device-cgroup
/// backstop unnecessary here: the boundary is the namespace + the allowlist, not a cooperative
/// filter. This test is the adversarial counterpart to `box_provides_essential_dev_nodes`.
#[test]
fn box_denies_unauthorized_devices() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "devdeny");
    let rootfs = root.to_str().unwrap();
    // (1) A physical-memory / raw-disk node must be ABSENT (never bound into the box's /dev).
    // (2) Fabricating a block device via mknod must FAIL - the userns forbids device-node creation,
    //     so a hostile workload can't reach the host disk even with the mknod syscall available.
    let out = kern_out(&[
        "box",
        "dd",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "test -e /dev/mem && echo MEM-PRESENT || echo mem-absent; \
         test -e /dev/sda && echo SDA-PRESENT || echo sda-absent; \
         /bin/busybox mknod /dev/rawdisk b 8 0 2>/dev/null && echo MKNOD-OK || echo mknod-denied",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let o = String::from_utf8_lossy(&out.stdout);
    assert!(
        o.contains("mem-absent"),
        "/dev/mem must not be present in the box (deny-by-default /dev): {o}"
    );
    assert!(
        o.contains("sda-absent"),
        "a host block device must not be present in the box: {o}"
    );
    assert!(
        o.contains("mknod-denied"),
        "creating a block device via mknod must fail in an unprivileged userns: {o}"
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
    // Whitelist, not blocklist: the netns must expose EXACTLY loopback (a blocklist of eth/wlan/enp
    // misses eno/ens/br/docker names). Parse the interface names out of /proc/net/dev (the token
    // before `:` on each device line; the two header lines carry no `:`).
    let ifaces: Vec<&str> = net
        .lines()
        .filter(|l| l.contains(':'))
        .filter_map(|l| l.split(':').next())
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect();
    assert_eq!(
        ifaces,
        ["lo"],
        "the box network namespace must expose ONLY loopback: {net}"
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

    // PROC MASKING (regression for a real pen-test finding): `/proc/sys` is mounted READ-ONLY, so a
    // root-mapped box (kern as root / WSL / sudo / CI) can't write a host-global, non-namespaced sysctl
    // like `kernel/core_pattern` (`|/evil` → runs as ROOT on the host at the next core dump). Confirm
    // the fresh procfs carries the read-only /proc/sys submount.
    let mounts = kern_out(&[
        "box",
        "isobox",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "cat",
        "/proc/mounts",
    ]);
    let mounts = String::from_utf8_lossy(&mounts.stdout);
    assert!(
        mounts.lines().any(|l| l.contains(" /proc/sys ")
            && l.split_whitespace()
                .any(|f| f == "ro" || f.starts_with("ro,"))),
        "/proc/sys must be mounted read-only (core_pattern escape guard):\n{mounts}"
    );

    // NO_NEW_PRIVS (regression for a red-team finding): PID 1 and every child run with `NoNewPrivs=1`,
    // so a setuid binary in the image cannot REGAIN privilege - without it the default cap-drop is a
    // paper wall. Read it back from the box's own `/proc/self/status`.
    let status = kern_out(&[
        "box",
        "isobox",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "cat",
        "/proc/self/status",
    ]);
    let status = String::from_utf8_lossy(&status.stdout);
    assert!(
        status.lines().any(|l| {
            let l = l.replace('\t', " ");
            l.starts_with("NoNewPrivs:") && l.trim_end().ends_with('1')
        }),
        "the box must run with NoNewPrivs=1 (a setuid binary must not regain privilege):\n{status}"
    );

    // /proc/kcore is MASKED (bound over `/dev/null`): a read yields NOTHING, so a box cannot page host
    // kernel memory out (KASLR defeat / secret disclosure). Same masking class as `/proc/sys` above.
    // A byte-count + a CONTROL line dodge the empty-pipe race that a bare "stdout is empty" would let
    // pass vacuously: `CONTROL=ok` is always non-empty (so `kern_out`'s retry sees real output and the
    // box provably ran), while `KCORE` must be 0 - an UNMASKED kcore streams gigabytes, so a non-zero
    // count would fail. Empty-because-masked is now distinguished from empty-because-dead-pipe.
    let kcore = kern_out(&[
        "box",
        "isobox",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "echo CONTROL=ok; echo KCORE=$(head -c 4096 /proc/kcore 2>/dev/null | wc -c)",
    ]);
    let kcore = String::from_utf8_lossy(&kcore.stdout);
    assert!(
        kcore.contains("CONTROL=ok"),
        "the kcore probe must run to completion (control line present): {kcore:?}"
    );
    assert!(
        kcore.contains("KCORE=0"),
        "/proc/kcore must read empty in the box (kernel-memory leak guard): {kcore:?}"
    );

    let _ = fs::remove_dir_all(&root);
}

/// **Red-team regression: a raw/packet socket on the HOST netns is refused, even under `--net host`.**
///
/// Under `--net host` a box shares the host network namespace. kern re-adds `CAP_NET_RAW`/
/// `CAP_NET_ADMIN` only over the box's OWN user namespace, so those caps are ineffective against the
/// host-owned netns: opening `AF_PACKET`/`SOCK_RAW` (link-layer sniff/inject) or `AF_INET`/`SOCK_RAW`
/// (raw IP) against host interfaces must fail with `EPERM`. If it did not, a box on the host netns
/// could sniff or spoof every packet the host sees. busybox has no `AF_PACKET` applet, so a static C
/// helper opens the sockets and reports each `errno`.
///
/// The discriminant is built in, so a green can't come from the socket simply being universally
/// blocked or the helper failing to run: in the DEFAULT (private empty netns) the same binary must
/// SUCCEED - the userns-scoped cap IS effective over the box's OWN netns, there is just nothing to
/// sniff there. Only against that positive control is the `--net host` refusal meaningful. If even the
/// private-netns open is refused, the runner grants no `CAP_NET_RAW` at all and the test SKIPs.
#[test]
fn net_host_raw_and_packet_sockets_are_eperm() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    const SRC: &str = r#"
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdio.h>
int main(void) {
    int a = socket(AF_PACKET, SOCK_RAW, 0);
    printf("AF_PACKET fd=%d errno=%d\n", a, a < 0 ? errno : 0);
    int b = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    printf("AF_INET_RAW fd=%d errno=%d\n", b, b < 0 ? errno : 0);
    return 0;
}
"#;
    let Some(helper) = compile_static_helper(SRC, "rawsock") else {
        eprintln!("skip: no static C compiler available");
        return;
    };
    let root = build_rootfs(&busybox, "rawsock");
    place_helper(&helper, &root, "rawsock");
    let rootfs = root.to_str().unwrap();

    // Pull the `(fd, errno)` pair for a given `KEY fd=.. errno=..` line out of the helper's stdout.
    fn probe(out: &str, key: &str) -> Option<(i32, i32)> {
        let line = out.lines().find(|l| l.starts_with(key))?;
        let fd = line
            .split("fd=")
            .nth(1)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        let errno = line
            .split("errno=")
            .nth(1)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        Some((fd, errno))
    }

    // Positive control: in the DEFAULT private netns the raw socket must OPEN (fd >= 0). If it does
    // not, this runner grants no CAP_NET_RAW even in a private userns+netns, so the discriminant
    // cannot be established here - skip rather than assert.
    let priv_out = kern_out(&["box", "rspriv", "--rootfs", rootfs, "--", "/rawsock"]);
    if String::from_utf8_lossy(&priv_out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let priv_s = String::from_utf8_lossy(&priv_out.stdout);
    match probe(&priv_s, "AF_PACKET") {
        Some((fd, _)) if fd >= 0 => {}
        other => {
            eprintln!("skip: no CAP_NET_RAW even in a private netns on this runner ({other:?})");
            let _ = fs::remove_dir_all(&root);
            return;
        }
    }

    // The boundary: under `--net host` the SAME binary must be refused with EPERM on BOTH socket
    // families - the host netns is not the box's to sniff.
    let host_out = kern_out(&[
        "box", "rshost", "--rootfs", rootfs, "--net", "host", "--", "/rawsock",
    ]);
    let host_s = String::from_utf8_lossy(&host_out.stdout);
    let pkt = probe(&host_s, "AF_PACKET");
    let raw = probe(&host_s, "AF_INET_RAW");
    assert!(
        matches!(pkt, Some((fd, e)) if fd < 0 && e == libc::EPERM),
        "AF_PACKET/SOCK_RAW on the host netns must be EPERM, got {pkt:?} from {host_s:?}"
    );
    assert!(
        matches!(raw, Some((fd, e)) if fd < 0 && e == libc::EPERM),
        "AF_INET/SOCK_RAW on the host netns must be EPERM, got {raw:?} from {host_s:?}"
    );

    let _ = fs::remove_dir_all(&root);
}

/// **Red-team regression: the ENTIRE mount API - classic AND the new fd-based family - hard-kills.**
///
/// `mount(2)` is the obvious one, but the fd-based mount API (`fsopen`/`fsconfig`/`fsmount`/
/// `move_mount`/`open_tree`/`fspick`/`mount_setattr`) can remount a box's root writable or unmask a
/// masked `/proc` path just as well. "Denied by the deny-by-default allowlist" would make them
/// `ENOSYS` (safe by construction, but not killed); kern instead puts every one in the seccomp
/// KILL prologue, so an attempt is `SIGSYS`, not a survivable `ENOSYS` the workload can branch on.
/// This asserts each by its ARCH-CORRECT number (`libc::SYS_*`, so it holds on x86_64 and aarch64
/// where the numbers differ), closing the "safe by construction != killed" gap for the whole family.
#[test]
fn mount_api_family_is_hard_killed() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    // A helper that invokes one syscall by number with benign zero args. A KILL vector never
    // returns (SIGSYS reaps it); a benign one returns and the process exits 0. The filter decides on
    // the number alone, so zero args are fine - it is refused before the kernel reads them.
    let Some(helper) = compile_static_helper(SYSCALL_BY_NR_SRC, "mountfam") else {
        eprintln!("skip: no static C compiler available");
        return;
    };
    let root = build_rootfs(&busybox, "mountfam");
    place_helper(&helper, &root, "syscall1");
    let rootfs = root.to_str().unwrap();

    // The whole mount API, classic + fd-based, by arch-correct number.
    let family: [(&str, libc::c_long); 10] = [
        ("mount", libc::SYS_mount),
        ("umount2", libc::SYS_umount2),
        ("pivot_root", libc::SYS_pivot_root),
        ("open_tree", libc::SYS_open_tree),
        ("move_mount", libc::SYS_move_mount),
        ("fsopen", libc::SYS_fsopen),
        ("fsconfig", libc::SYS_fsconfig),
        ("fsmount", libc::SYS_fsmount),
        ("fspick", libc::SYS_fspick),
        ("mount_setattr", libc::SYS_mount_setattr),
    ];

    // Positive control: a benign syscall (getpid) must let the box exit 0 - proving the helper runs
    // and it is the mount family SPECIFICALLY that is killed, not every syscall the helper makes.
    let nr = libc::SYS_getpid.to_string();
    let ok = kern()
        .args(["box", "mf-ctl", "--rootfs", rootfs, "--", "/syscall1", &nr])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&ok.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    assert_eq!(
        ok.status.code(),
        Some(0),
        "positive control (getpid) must exit 0, else the helper itself is being killed: {ok:?}"
    );

    for (name, nr) in family {
        let nr = nr.to_string();
        let killed = kern()
            .args(["box", "mf", "--rootfs", rootfs, "--", "/syscall1", &nr])
            .output()
            .expect("run kern");
        assert_eq!(
            killed.status.code(),
            Some(159),
            "{name} (nr {nr}) must SIGSYS-kill (128+31), not survive: {killed:?}"
        );
    }

    let _ = fs::remove_dir_all(&root);
}

/// **Red-team regression: a foreign-ABI (i386 `int 0x80`) call cannot bypass the seccomp filter.**
///
/// The exhaustive classifier covers x86_64 syscall NUMBERS, but a 32-bit process entering via
/// `int 0x80` runs under `AUDIT_ARCH_I386`, where the numbers differ: i386 `__NR_mount` is 21, and
/// x86_64 nr 21 is `access` (which the allowlist permits). Without an architecture guard, an i386
/// `int 0x80` with `eax=21` would match the filter as `access` and execute `mount` - a full escape on
/// any host with `CONFIG_IA32_EMULATION`. kern's filter validates `AUDIT_ARCH` FIRST and hard-kills
/// any mismatch, so the i386 call is `SIGSYS`, never reinterpreted against the x86_64 table.
///
/// Discriminant: the SAME i386 binary runs to a normal exit on the host (IA32 emulation present, the
/// `mount` merely `EPERM`s) but is SIGSYS-killed inside a box. If the host run does not survive, this
/// kernel has no usable IA32 emulation - the attack precondition is absent - and the test skips.
#[test]
#[cfg(target_arch = "x86_64")]
fn foreign_abi_i386_int80_cannot_bypass_the_seccomp_filter() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    // i386 __NR_mount = 21 via `int 0x80` (x86_64 nr 21 = access, which the allowlist permits), then
    // i386 __NR_exit = 1 with status 0. If the arch guard is present the process dies at the first
    // `int 0x80`; if it is absent the mount is reinterpreted as access, returns, and the process exits 0.
    const ASM: &str = r#"
.code32
.global _start
.text
_start:
    movl $21, %eax
    xorl %ebx, %ebx
    xorl %ecx, %ecx
    xorl %edx, %edx
    int $0x80
    movl $1, %eax
    xorl %ebx, %ebx
    int $0x80
"#;
    let Some(bin) = compile_i386_freestanding(ASM, "i386mount") else {
        eprintln!("skip: cannot assemble a 32-bit binary (no -m32 cc)");
        return;
    };
    // Positive control: the i386 binary must RUN and survive on the host (IA32 emulation usable).
    let host = match Command::new(&bin).output() {
        Ok(o) => o,
        Err(_) => {
            eprintln!("skip: host cannot exec a 32-bit binary (no IA32 emulation)");
            return;
        }
    };
    if !host.status.success() {
        eprintln!("skip: no usable IA32 emulation (i386 probe did not exit 0 on the host)");
        return;
    }
    let root = build_rootfs(&busybox, "i386");
    place_helper(&bin, &root, "i386mount");
    let rootfs = root.to_str().unwrap();
    let out = kern()
        .args(["box", "i386t", "--rootfs", rootfs, "--", "/i386mount"])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    assert_eq!(
        out.status.code(),
        Some(159),
        "an i386 int 0x80 syscall must be SIGSYS-killed by the arch guard (128+31), never \
         reinterpreted against the x86_64 syscall table: {out:?}"
    );

    let _ = fs::remove_dir_all(&root);
}

/// **Red-team regression: an x32-ABI syscall (the `0x40000000` bit) is hard-killed, not number-matched.**
///
/// On x86_64 the x32 ABI reuses the x86_64 `AUDIT_ARCH` but ORs `X32_SYSCALL_BIT` (`0x40000000`) into
/// the syscall number, so a number-only filter would let the x32 alias of a denied syscall slip
/// through. kern's kill prologue (shared by both filters) kills any number with that bit set. This is
/// the executed twin of the i386 arch test: the SAME binary runs `getpid` (nr 39) to a clean exit
/// inside a box, but the x32-flagged form (`0x40000027`) is `SIGSYS`-killed.
#[test]
#[cfg(target_arch = "x86_64")]
fn x32_abi_syscall_is_hard_killed() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let Some(helper) = compile_static_helper(SYSCALL_BY_NR_SRC, "x32") else {
        eprintln!("skip: no static C compiler available");
        return;
    };
    let root = build_rootfs(&busybox, "x32");
    place_helper(&helper, &root, "x32probe");
    let rootfs = root.to_str().unwrap();
    // Positive control: the same syscall WITHOUT the x32 bit (getpid, nr 39) is allowed - exit 0.
    let ok = kern()
        .args(["box", "x32ctl", "--rootfs", rootfs, "--", "/x32probe", "39"])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&ok.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    assert_eq!(
        ok.status.code(),
        Some(0),
        "plain getpid (no x32 bit) must be allowed - positive control: {ok:?}"
    );
    // The x32-flagged form (0x40000000 | 39) must be SIGSYS-killed by the kill prologue's x32 arm.
    let killed = kern()
        .args([
            "box",
            "x32t",
            "--rootfs",
            rootfs,
            "--",
            "/x32probe",
            "0x40000027",
        ])
        .output()
        .expect("run kern");
    assert_eq!(
        killed.status.code(),
        Some(159),
        "an x32-ABI syscall (0x40000000 bit set) must SIGSYS, not be matched as its bare number: {killed:?}"
    );

    let _ = fs::remove_dir_all(&root);
}

/// **Red-team regression: the shared overlay lower is isolating across boxes.**
///
/// An image root uses an overlay whose `lowerdir` (the content-addressed image cache) is shared
/// read-only across boxes; every write lands in a per-box ephemeral upper. This asserts that property
/// end to end on a REAL overlay, offline: build a throwaway local image (a detached `--rootfs` box +
/// `kern commit`, so no registry or network), then run two boxes from it. Box A writes a marker and
/// rewrites a seed file; box B - a fresh box from the SAME image - must see NEITHER, proving A's
/// writes went to its own ephemeral upper and never reached the shared lower or a peer box. The
/// discriminant: the same read (`cat /marker`, `cat /seed`) that returns A's data inside A returns the
/// pristine image inside B. Skip-graceful where a detached box or `kern commit` is unavailable.
#[test]
fn overlay_lower_is_shared_ro_across_boxes() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "ovl");
    // A seed whose ORIGINAL content box B must still see after box A rewrites its own copy.
    fs::write(root.join("seed"), b"original").unwrap();
    let rootfs = root.to_str().unwrap();
    let img = format!("kern-ovl-test-{}:local", std::process::id());

    // Build a local image OFFLINE: a detached box we can commit. Clear any stale name first.
    let _ = kern().args(["rmi", &img]).output();
    let started = kern()
        .args([
            "box",
            "ovl-src",
            "--rootfs",
            rootfs,
            "--detach",
            "--",
            "/bin/busybox",
            "sleep",
            "30",
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&started.stderr).contains("user namespaces")
        || !started.status.success()
    {
        eprintln!(
            "skip: cannot start a detached box here ({})",
            String::from_utf8_lossy(&started.stderr).trim()
        );
        let _ = kern().args(["stop", "ovl-src"]).output();
        let _ = kern().args(["rm", "ovl-src"]).output();
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let committed = kern()
        .args(["commit", "ovl-src", &img])
        .output()
        .expect("run kern");
    // The detached source box has served its purpose regardless of the commit result.
    let _ = kern().args(["stop", "ovl-src"]).output();
    let _ = kern().args(["rm", "ovl-src"]).output();
    if !committed.status.success() {
        eprintln!(
            "skip: kern commit unavailable here ({})",
            String::from_utf8_lossy(&committed.stderr).trim()
        );
        let _ = kern().args(["rmi", &img]).output();
        let _ = fs::remove_dir_all(&root);
        return;
    }

    // Box A: write a distinctive marker and tamper the seed - both must land in A's ephemeral upper.
    // Its stdout is load-bearing (the MARKER_A control + the mountinfo identity), so use `kern_out`,
    // which retries on the empty-pipe race exactly as box B does. A's ops are idempotent (echo > file),
    // so a retry runs a fresh box with the same result.
    let a = kern_out(&[
        "box",
        "ovl-a",
        "--image",
        &img,
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "echo MARKER_A > /marker; echo tampered_by_A > /seed; cat /marker; grep -m1 ' / ' /proc/self/mountinfo",
    ]);
    let a_out = String::from_utf8_lossy(&a.stdout).to_string();

    // Box B: a FRESH box from the SAME image must see neither A's marker nor A's tamper.
    let b = kern_out(&[
        "box",
        "ovl-b",
        "--image",
        &img,
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "if [ -e /marker ]; then echo SEES_MARKER; fi; cat /seed; grep -m1 ' / ' /proc/self/mountinfo",
    ]);
    let b_out = String::from_utf8_lossy(&b.stdout).to_string();

    // Clean up BEFORE asserting, so a failed assertion still leaves no box or image behind.
    let _ = kern().args(["rm", "ovl-a"]).output();
    let _ = kern().args(["rm", "ovl-b"]).output();
    let _ = kern().args(["rmi", &img]).output();
    let _ = fs::remove_dir_all(&root);

    // Positive control: box A actually wrote and read its own marker (else "B sees nothing" is vacuous).
    assert!(
        a_out.contains("MARKER_A"),
        "box A must write and read its own marker (positive control): {a_out:?}"
    );
    // The isolation: none of A's writes crossed the shared lower into a peer box.
    assert!(
        !b_out.contains("SEES_MARKER"),
        "box B must NOT see box A's marker (per-box ephemeral upper): {b_out:?}"
    );
    assert!(
        b_out.contains("original") && !b_out.contains("tampered_by_A"),
        "box B must see the image's pristine seed, not box A's tamper: {b_out:?}"
    );

    // POSITIVE identity of sharing: "B sees nothing" is ALSO true if each box got a private full copy,
    // so the shared-lower claim needs the lowerdir to be the SAME object across boxes while the upperdir
    // differs. Pull `lowerdir=`/`upperdir=` out of each box's own overlay mount line.
    fn field<'a>(mountline: &'a str, key: &str) -> Option<&'a str> {
        mountline
            .split_once(key)
            .map(|(_, rest)| rest.split([',', ' ']).next().unwrap_or(""))
    }
    let (a_lower, b_lower) = (field(&a_out, "lowerdir="), field(&b_out, "lowerdir="));
    let (a_upper, b_upper) = (field(&a_out, "upperdir="), field(&b_out, "upperdir="));
    assert!(
        a_lower.is_some() && a_lower == b_lower,
        "both boxes must overlay the SAME shared lowerdir - one shared RO image store, not a private \
         copy each (a={a_lower:?}, b={b_lower:?})"
    );
    assert!(
        a_upper.is_some() && b_upper.is_some() && a_upper != b_upper,
        "each box must have its OWN ephemeral upperdir (a={a_upper:?}, b={b_upper:?})"
    );
}

/// **Red-team regression: `/dev`, `/sys` and the dangerous `/proc` paths are neutered.**
///
/// Coverage for the "devices" and sysfs half of the /proc-and-devices boundary that the /proc/sys +
/// /proc/kcore assertions do not reach. In a default box: the physical-memory device nodes
/// (`/dev/mem`, `/dev/kmem`) are absent (no host RAM window); `/proc/sysrq-trigger` and
/// `/proc/sys/kernel/core_pattern` are read-only (no host SysRq, no `|/handler` root-on-host core-dump
/// escape); `/sys/kernel/uevent_helper` is absent (no host `call_usermodehelper` as root); and
/// `/proc/kallsyms` exposes no non-zero symbol address (no KASLR defeat).
#[test]
fn box_masks_devices_sysfs_and_sensitive_proc() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "masks");
    let rootfs = root.to_str().unwrap();
    // Each probe prints a `KEY=value` line; a write that SUCCEEDS prints `WROTE`, a refused one `blocked`.
    let script = "\
        echo MEM=$([ -e /dev/mem ] && echo PRESENT || echo absent); \
        echo KMEM=$([ -e /dev/kmem ] && echo PRESENT || echo absent); \
        echo SYSRQ=$( (echo 0 > /proc/sysrq-trigger) 2>/dev/null && echo WROTE || echo blocked); \
        echo COREPAT=$( (echo x > /proc/sys/kernel/core_pattern) 2>/dev/null && echo WROTE || echo blocked); \
        echo UEVENT=$([ -e /sys/kernel/uevent_helper ] && echo PRESENT || echo absent); \
        echo KALLSYMS=$(grep -cE '^[1-9a-f]' /proc/kallsyms 2>/dev/null); \
        echo DONE";
    let out = kern_out(&[
        "box",
        "masks",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        script,
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    let _ = fs::remove_dir_all(&root);
    assert!(s.contains("DONE"), "probe did not run to completion: {s:?}");
    for (needle, why) in [
        ("MEM=absent", "/dev/mem must be absent (no host RAM window)"),
        ("KMEM=absent", "/dev/kmem must be absent"),
        ("SYSRQ=blocked", "/proc/sysrq-trigger must be read-only (no host SysRq)"),
        (
            "COREPAT=blocked",
            "/proc/sys/kernel/core_pattern must be read-only (core_pattern root-on-host escape guard)",
        ),
        (
            "UEVENT=absent",
            "/sys/kernel/uevent_helper must be absent (no host call_usermodehelper)",
        ),
        (
            "KALLSYMS=0",
            "/proc/kallsyms must expose no non-zero symbol address (KASLR-defeat guard)",
        ),
    ] {
        assert!(s.contains(needle), "{why}: got {s:?}");
    }
}

/// **Red-team regression: dropped capabilities are cleared from EVERY set, not just the bounding one.**
///
/// The bounding-set drop is read back with `PR_CAPBSET_READ`, but the claim is that a dropped cap is
/// gone from the effective/permitted/inheritable AND ambient sets too - ambient matters because it
/// survives `execve` by promoting permitted+effective, and `NO_NEW_PRIVS` does not clear it. Under
/// `--cap-drop ALL` every one of `CapEff`/`CapPrm`/`CapInh`/`CapAmb`/`CapBnd` in the box's own
/// `/proc/self/status` must read all-zero. This reads back the sets `PR_CAPBSET_READ` cannot see.
#[test]
fn dropped_caps_are_cleared_from_every_set_including_ambient() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "caps");
    let rootfs = root.to_str().unwrap();
    let out = kern_out(&[
        "box",
        "capsx",
        "--rootfs",
        rootfs,
        "--cap-drop",
        "ALL",
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "grep -E '^Cap(Eff|Prm|Inh|Amb|Bnd):' /proc/self/status",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    let _ = fs::remove_dir_all(&root);
    for cap in ["CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"] {
        let val = cap_hex(&s, cap)
            .unwrap_or_else(|| panic!("{cap} missing from /proc/self/status: {s:?}"));
        assert_eq!(
            val, "0000000000000000",
            "{cap} must be all-zero under --cap-drop ALL (dropped caps cleared from every set): {s:?}"
        );
    }
}

/// **Red-team regression: the DEFAULT box (no `--cap-drop`) drops the 16 dangerous caps.**
///
/// The `--cap-drop ALL` test proves the extreme profile; this proves the SHIPPED default. Each cap in
/// the always-dropped set (`NET_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `SYS_PTRACE`, `SYS_PACCT`,
/// `SYS_ADMIN`, `SYS_BOOT`, `SYS_TIME`, `AUDIT_CONTROL`, `MAC_OVERRIDE`, `MAC_ADMIN`, `SYSLOG`,
/// `WAKE_ALARM`, `AUDIT_READ`, `PERFMON`, `BPF`) must be cleared from BOTH the bounding and the
/// effective set of a plain box, read back from its own `/proc/self/status`. `NET_ADMIN` (12) and
/// `SYS_ADMIN` (21) are now in this default set (converged onto Docker's/Podman's default); they are
/// KEPT only for `--tun`/`--privileged`/`--cap-add`, verified by the sibling tests.
#[test]
fn default_box_drops_the_dangerous_caps() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    // The always-dropped cap numbers (kern's DEFAULT_DROP set); never re-added on a default box.
    const DROPPED: [u32; 16] = [
        12, 16, 17, 19, 20, 21, 22, 25, 30, 32, 33, 34, 35, 37, 38, 39,
    ];
    let root = build_rootfs(&busybox, "defcaps");
    let rootfs = root.to_str().unwrap();
    let out = kern_out(&[
        "box",
        "defcaps",
        "--rootfs",
        rootfs,
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "grep -E '^Cap(Eff|Bnd):' /proc/self/status",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    let _ = fs::remove_dir_all(&root);
    for cap in ["CapEff", "CapBnd"] {
        let hex = cap_hex(&s, cap)
            .unwrap_or_else(|| panic!("{cap} missing from /proc/self/status: {s:?}"));
        let mask =
            u64::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("{cap} value not hex: {hex:?}"));
        for bit in DROPPED {
            assert_eq!(
                (mask >> bit) & 1,
                0,
                "cap bit {bit} must be cleared from {cap} on a default box (got {hex}): {s:?}"
            );
        }
    }
    // Positive control: a cap KEPT by default (CHOWN, bit 0, not in DEFAULT_DROP - needed for apt/apk
    // and chown) must be SET in the bounding set, else an all-zero CapBnd would pass the drop-check
    // vacuously. (SYS_ADMIN/NET_ADMIN can no longer serve as the control: they are dropped by default
    // now, which is the change under test.)
    let bnd_hex = cap_hex(&s, "CapBnd").unwrap_or("");
    let bnd = u64::from_str_radix(bnd_hex, 16).unwrap_or(0);
    assert_eq!(
        bnd & 1,
        1,
        "CHOWN (bit 0) must be retained in CapBnd by default - proves the cap mask is populated, \
         not vacuously empty: {s:?}"
    );
}

/// **The two CONDITIONAL cap keeps hold on a real box.** `--tun` keeps `CAP_NET_ADMIN` (12) so the box
/// can bring its own tunnel interface up (kern brings `lo` up before the drop, so loopback never needed
/// it); `--privileged` keeps `CAP_SYS_ADMIN` (21) for in-namespace `mount`. Each keeps ONLY its own cap
/// (the other stays dropped), so neither flag widens the set beyond what its feature needs. Read back
/// from the box's own `CapBnd`, the bounding set kern imposes.
#[test]
fn tun_keeps_net_admin_and_privileged_keeps_sys_admin_on_a_real_box() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "condcaps");
    let rootfs = root.to_str().unwrap();
    let capbnd = |name: &str, flag: &str| -> u64 {
        let out = kern_out(&[
            "box",
            name,
            "--rootfs",
            rootfs,
            flag,
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            "grep CapBnd /proc/self/status",
        ]);
        let s = String::from_utf8_lossy(&out.stdout).to_string();
        u64::from_str_radix(cap_hex(&s, "CapBnd").unwrap_or("0"), 16).unwrap_or(0)
    };
    let tun = capbnd("condtun", "--tun");
    if tun == 0 {
        eprintln!("skip: box did not start (CapBnd empty - userns unavailable at runtime)");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    assert_eq!(
        (tun >> 12) & 1,
        1,
        "--tun must KEEP NET_ADMIN (bit 12): {tun:#x}"
    );
    assert_eq!(
        (tun >> 21) & 1,
        0,
        "--tun must NOT keep SYS_ADMIN (bit 21): {tun:#x}"
    );
    let privd = capbnd("condprv", "--privileged");
    if privd == 0 {
        eprintln!("skip: --privileged box did not start (CapBnd empty)");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    assert_eq!(
        (privd >> 21) & 1,
        1,
        "--privileged must KEEP SYS_ADMIN (bit 21): {privd:#x}"
    );
    assert_eq!(
        (privd >> 12) & 1,
        0,
        "--privileged must NOT keep NET_ADMIN (bit 12): {privd:#x}"
    );
    // SECURITY-CRITICAL end-to-end: `--security-profile untrusted` (which is `--cap-drop ALL`) plus
    // `--tun` must leave the bounding set with EXACTLY one cap, NET_ADMIN - not a hole that widens the
    // profile. The single kept cap is over the box's own isolated netns, the same shape as a single
    // `--cap-add` the profile already permits.
    let out = kern_out(&[
        "box",
        "conduntrust",
        "--rootfs",
        rootfs,
        "--security-profile",
        "untrusted",
        "--tun",
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "grep CapBnd /proc/self/status",
    ]);
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    let ut = u64::from_str_radix(cap_hex(&s, "CapBnd").unwrap_or("0"), 16).unwrap_or(0);
    assert_eq!(
        ut,
        1u64 << 12,
        "untrusted + --tun must leave EXACTLY NET_ADMIN in CapBnd, nothing else: {ut:#x}"
    );
    let _ = fs::remove_dir_all(&root);
}

/// **Regression (0ab88a1): a `kern build` RUN step must NOT flip the CALLER's own cgroup to
/// group-OOM-kill.** The scope/managed-unit `memory.oom.group=1` write targets the box's OWN scope;
/// a build step (`KERN_BUILD_STEP`) is a best-effort PASSTHROUGH that runs in `kern build`'s inherited
/// cgroup, so writing there would enlarge the whole session's OOM blast radius and never revert. Runs a
/// box with `KERN_BUILD_STEP=1` and asserts THIS process's `memory.oom.group` is untouched. Skip-graceful
/// where the caller's cgroup file is absent/unwritable or not a clean `0` (a pre-existing `1` can't be
/// told from a flip); self-heals so a failing run never leaves the test process in group-kill.
#[test]
fn build_step_box_does_not_touch_the_callers_own_cgroup_oom_group() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let Ok(cg) = fs::read_to_string("/proc/self/cgroup") else {
        eprintln!("skip: /proc/self/cgroup unreadable");
        return;
    };
    let Some(rel) = cg.lines().find_map(|l| l.strip_prefix("0::")) else {
        eprintln!("skip: no cgroup v2 line");
        return;
    };
    let oomg = std::path::Path::new("/sys/fs/cgroup")
        .join(rel.trim().trim_start_matches('/'))
        .join("memory.oom.group");
    // Only meaningful from a clean, writable `0`: writing it back proves any later `1` is the box's doing.
    match fs::read_to_string(&oomg) {
        Ok(s) if s.trim() == "0" && fs::write(&oomg, "0").is_ok() => {}
        _ => {
            eprintln!("skip: caller cgroup memory.oom.group not a writable clean 0");
            return;
        }
    }
    let root = build_rootfs(&busybox, "buildstep");
    let rootfs = root.to_str().unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_kern"))
        .args([
            "box",
            "buildstep",
            "--rootfs",
            rootfs,
            "--memory",
            "64m",
            "--",
            "/bin/busybox",
            "true",
        ])
        .env("KERN_BUILD_STEP", "1")
        .output();
    let after = fs::read_to_string(&oomg)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let _ = fs::remove_dir_all(&root);
    let _ = std::process::Command::new(env!("CARGO_BIN_EXE_kern"))
        .args(["rm", "buildstep"])
        .output();
    // Self-heal BEFORE asserting, so a regression never leaves this test process in group-OOM-kill.
    if after != "0" {
        let _ = fs::write(&oomg, "0");
    }
    assert!(out.is_ok(), "kern box (build step) failed to spawn");
    assert_eq!(
        after, "0",
        "a KERN_BUILD_STEP box must NOT set the caller's own memory.oom.group (now {after})"
    );
}

/// **Red-team regression: a box can neither SEE nor RAISE a cgroup above its own.**
///
/// The box runs in a cgroup namespace, so `/proc/self/cgroup` reads `0::/` - its own delegated cgroup
/// AS the root, every ancestor invisible - where the same read on the host shows the full slice path.
/// And the box's `/sys/fs/cgroup` is mounted read-only, so it cannot raise its own `memory.max` (or any
/// controller) above the delegated cap. Discriminant: the host read shows a real ancestor path; the box
/// read shows `0::/`, and the raise is refused. Skip-graceful where the box is not placed in a cgroup ns.
#[test]
fn box_cannot_see_or_raise_a_parent_cgroup() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    // Positive control: on the host the same read is NOT `0::/` (else `0::/` in the box would be
    // meaningless - it must be the box's namespacing, not a universal value).
    let host_cg = fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    if host_cg.trim() == "0::/" || host_cg.trim().is_empty() {
        eprintln!("skip: host is already at the cgroup-ns root (no discriminant): {host_cg:?}");
        return;
    }
    let root = build_rootfs(&busybox, "cgiso");
    let rootfs = root.to_str().unwrap();
    let out = kern_out(&[
        "box", "cgiso", "--rootfs", rootfs, "--memory", "64m", "--", "/bin/busybox", "sh", "-c",
        "echo CG=$(cat /proc/self/cgroup); \
         echo HASMAX=$([ -e /sys/fs/cgroup/memory.max ] && echo yes || echo no); \
         echo RAISE=$( (echo max > /sys/fs/cgroup/memory.max) 2>/dev/null && echo WROTE || echo blocked); \
         echo PROCS=$( (echo 0 > /sys/fs/cgroup/cgroup.procs) 2>/dev/null && echo WROTE || echo blocked)",
    ]);
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    let _ = fs::remove_dir_all(&root);
    // The box sees only its own cgroup as root - every ancestor is outside the namespace.
    assert!(
        s.contains("CG=0::/\n") || s.trim_end().ends_with("CG=0::/") || s.contains("CG=0::/ "),
        "box /proc/self/cgroup must be the cgroup-ns root 0::/ (ancestors invisible): {s:?}"
    );
    // Where the memory controller is delegated, the box cannot raise its own cap (cgroupfs read-only),
    // and it cannot move a PID between cgroups (`cgroup.procs` read-only) - so it cannot restructure the
    // hierarchy to escape a limit set on a node above its own delegated subtree either.
    if s.contains("HASMAX=yes") {
        assert!(
            s.contains("RAISE=blocked"),
            "box must NOT be able to raise its own memory.max (cgroupfs is read-only): {s:?}"
        );
        assert!(
            s.contains("PROCS=blocked"),
            "box must NOT be able to write cgroup.procs (no PID moves out of the delegated subtree): {s:?}"
        );
    }
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
    // A per-test-unique base: `std::process::id()` is the SAME for every test in this binary (they
    // share one process), so a bare `kern-it-vol-<pid>` would collide with the named-volume test's
    // dir - one test's `remove_dir_all` then races the other's mount ("source … No such file").
    let host = std::env::temp_dir().join(format!("kern-it-volrt-{}", std::process::id()));
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

/// Regression: a box's `/dev/null` (and friends) must be *writable* - `cmd > /dev/null` is
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
    assert!(
        start.status.success(),
        "detached start should succeed: {}",
        String::from_utf8_lossy(&start.stderr)
    );
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
/// by following that symlink - the bind is refused, so a hostile image can't redirect a mount
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

/// SECURITY: `--read-only` must leave NO writable surface - including `/dev` (a separate tmpfs).
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
    // The range can be unusable at runtime even with newuidmap + an /etc/subuid line present -
    // e.g. a CI runner where the helper isn't setuid or there's no matching /etc/subgid. kern then
    // degrades to the single-uid map (either because detect_id_range found nothing, or because the
    // helper failed to apply the range); both paths log "using single-uid map". The ranged-map
    // assertion only applies when the range actually took effect - let kern be the source of truth.
    if String::from_utf8_lossy(&out.stderr).contains("using single-uid map") {
        eprintln!("skip: --uid-range fell back to single-uid (range not usable at runtime)");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let map = String::from_utf8_lossy(&out.stdout);
    let rows = map.lines().filter(|l| !l.trim().is_empty()).count();
    // The ranged map needs newuidmap/newgidmap to actually SUCCEED at runtime. Some CI runners
    // advertise a newuidmap binary plus an /etc/subuid line (so detect_id_range returns Some and no
    // fallback notice is printed) yet the helper still fails - e.g. it isn't setuid, or /etc/subgid
    // has no matching allocation - so the box can't map and produces no uid_map at all. That's not a
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
    // regardless of whether subids exist - the fast, most-isolated default. This is the perf-and-
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
    // `--bind-rootfs` binds the source directly (faster on slow-overlay kernels) - a write inside
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
    // that outside file untouched - kern injects no resolv.conf in bind mode for exactly this reason.
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

/// End-to-end: a `compose` file using the extended box schema (resources + env + read-only)
/// brings the box up - proving every mirror flag `push_box_flags` emits is one `kern box` accepts.
#[test]
fn compose_full_schema_brings_box_up() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "compose");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-cmp-{}", std::process::id()));
    let _ = fs::create_dir_all(&xdg);
    let toml = std::env::temp_dir().join(format!("kern-cmp-{}.toml", std::process::id()));
    fs::write(
        &toml,
        format!(
            "[box.svc]\nrootfs = \"{rootfs}\"\nmemory = \"256m\"\nworkdir = \"/\"\nread_only = true\nenv = [\"KV=1\"]\ncommand = [\"/bin/busybox\", \"sleep\", \"2\"]\n"
        ),
    )
    .unwrap();

    let out = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["compose", toml.to_str().unwrap()])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        let _ = fs::remove_file(&toml);
        return;
    }
    assert!(
        out.status.success(),
        "compose up should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut listed = false;
    for _ in 0..40 {
        let ps = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["ps", "--json"])
            .output()
            .expect("run kern");
        if String::from_utf8_lossy(&ps.stdout).contains("svc") {
            listed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        listed,
        "the composed box should appear in ps (all mirror flags accepted)"
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::remove_file(&toml);
}

/// Regression: `kern exec` must place the exec'd process in the BOX'S cgroup, so a command run
/// via `kern exec` is bound by the box's `--memory`/`--pids` caps (like `docker exec`), not the
/// launcher's ambient cgroup. Before the cgroup-join in `exec_in_box`, a fork bomb or memory hog
/// run via `kern exec` escaped the box's limits entirely (namespaces + seccomp still held; only
/// the resource cap leaked). We compare the exec'd process's own cgroup (`/proc/self/cgroup`)
/// with the box PID 1's (`/proc/1/cgroup`): the join makes them the SAME `kern-box-*` cgroup.
///
/// Skip-graceful on two axes: no busybox / no userns (like the tests above), AND no cgroup
/// delegation - on a best-effort host the box's own PID 1 isn't in a `kern-box-*` cgroup either,
/// so there is nothing for exec to join and nothing to assert. Gating on PID 1's cgroup (an
/// INDEPENDENT signal of "the box got capped here") is what lets a broken join FAIL rather than
/// silently skip on the hosts where the cap actually applies.
#[test]
fn exec_joins_the_box_cgroup_so_resource_caps_apply() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces unavailable");
        return;
    }
    let tag = "cgexec";
    let _ = kern().args(["stop", tag]).output(); // clear any leftover from a prior aborted run
    let root = build_rootfs(&busybox, tag);
    let rootfs = root.to_str().unwrap();

    let start = kern()
        .args([
            "box",
            tag,
            "--rootfs",
            rootfs,
            "--memory",
            "64m",
            "--pids-limit",
            "32",
            "-d",
            "--",
            "/bin/busybox",
            "sleep",
            "30",
        ])
        .output()
        .expect("start detached box");
    if !start.status.success() {
        eprintln!(
            "skip: box did not start ({})",
            String::from_utf8_lossy(&start.stderr).trim()
        );
        let _ = fs::remove_dir_all(&root);
        return;
    }

    // One exec prints the exec'd process's own cgroup AND the box PID 1's cgroup (v2 `0::<path>`).
    let out = kern_out(&[
        "exec",
        tag,
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        "cat /proc/self/cgroup; echo SEP; cat /proc/1/cgroup",
    ]);
    let text = String::from_utf8_lossy(&out.stdout);
    let leaf = |s: &str| -> String {
        s.lines()
            .find_map(|l| l.strip_prefix("0::"))
            .and_then(|p| p.rsplit('/').next())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let mut parts = text.split("SEP");
    let exec_leaf = leaf(parts.next().unwrap_or(""));
    let box_leaf = leaf(parts.next().unwrap_or(""));

    // Stop + clean BEFORE asserting so a failing assert never leaks a running box.
    let _ = kern().args(["stop", tag]).output();
    let _ = fs::remove_dir_all(&root);

    // No cgroup delegation here → the box PID 1 isn't in a `kern-box-*` cgroup, so there is nothing
    // for exec to join. Skip rather than assert (matches the runtime's best-effort fallback).
    if !box_leaf.starts_with("kern-box-") {
        eprintln!("skip: host has no delegated cgroup (box PID 1 cgroup leaf: {box_leaf:?})");
        return;
    }
    assert_eq!(
        exec_leaf, box_leaf,
        "`kern exec` must join the box's cgroup ({box_leaf:?}); the exec'd process was in \
         {exec_leaf:?}, so it would escape the box's --memory/--pids caps"
    );
}

/// Regression: `kern config setup` must write a config that `kern validate` accepts. It emitted
/// backend-less `[[vcpu]]` profiles, which the mandatory-backend rule (0.6.11) rejects, so the
/// starter config kern generated for a host failed its own validator. Runs the real binary with a
/// temp `XDG_CONFIG_HOME`, so it needs no box/userns and works on any host.
#[test]
fn config_setup_generates_a_config_that_validates() {
    let dir = std::env::temp_dir().join(format!("kern-setup-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let setup = kern()
        .env("XDG_CONFIG_HOME", &dir)
        .args(["config", "setup", "--force"])
        .output()
        .expect("run kern config setup");
    let cfg = dir.join("kern/kern.toml");
    if !cfg.exists() {
        eprintln!(
            "skip: config setup wrote no file ({})",
            String::from_utf8_lossy(&setup.stderr).trim()
        );
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    let v = kern()
        .args(["validate", cfg.to_str().unwrap()])
        .output()
        .expect("run kern validate");
    let ok = v.status.success();
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&v.stdout),
        String::from_utf8_lossy(&v.stderr)
    );
    let generated = fs::read_to_string(&cfg).unwrap_or_default();
    let _ = fs::remove_dir_all(&dir);
    assert!(
        ok,
        "`kern config setup` produced a config its own validator rejects:\n{report}\n--- generated ---\n{generated}"
    );
}

/// Every live process whose `comm` is exactly `kern` and whose argv mentions `tag`.
///
/// Matching on `comm` is what makes this safe: a `pgrep -f` style scan also matches the shell or
/// harness whose own command line happens to quote the box name, which is how the leak this test
/// pins was mis-measured twice before it was understood.
fn kern_procs_matching(tag: &str) -> usize {
    let Ok(entries) = fs::read_dir("/proc") else {
        return 0;
    };
    let mut n = 0;
    for e in entries.flatten() {
        let p = e.path();
        let Ok(comm) = fs::read_to_string(p.join("comm")) else {
            continue; // not a pid dir, or the process exited under us
        };
        if comm.trim() != "kern" {
            continue;
        }
        if let Ok(argv) = fs::read(p.join("cmdline")) {
            if String::from_utf8_lossy(&argv).contains(tag) {
                n += 1;
            }
        }
    }
    n
}

#[test]
fn stopping_a_box_leaves_no_timeout_watchdog_behind() {
    // `--timeout N` forks a watchdog in the HOST namespace, before the box's `unshare(CLONE_NEWPID)`,
    // so that it can signal the box's ns-init. It used to `sleep(N)` outright, and the only thing
    // that stopped it early was the supervisor's own `cancel_foreground_timeout`. Kill the
    // supervisor before it reaches that line and the watchdog was orphaned, sleeping out the rest of
    // the deadline: 884 KB and one pid per box, for 24 h at the SDK's 86405 s default, and invisible
    // to `kern ps` because the box itself really was gone. It now waits on a pidfd for the box's
    // exit with the deadline only as a cap, so it leaves as soon as there is nothing left to guard.
    //
    // THE TRIGGER IS A SIGKILL OF THE SUPERVISOR, NOT `kern stop`, and that is the whole design of
    // this test. `kern stop` SIGKILLs the box's pid 1 and then sweeps the supervisor's process
    // group, so whether the supervisor survives long enough to cancel its own watchdog is a race:
    // measured over six trials it leaked 0 of 6 that way, while SIGKILLing the supervisor directly
    // leaked 6 of 6. A test built on the racy path would have passed against the defect. SIGKILL is
    // also not a synthetic case: it is exactly what the Python and Node bindings do (`kern stop`,
    // then `killpg`), which is how fourteen of these accumulated in one evening of running the SDK
    // suites.
    //
    // The deadline itself is asserted elsewhere (`box_run_isolates_and_propagates_exit_code` and
    // the timeout tests). This one is only about what is left running afterwards.
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "wdog");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-xdg-wdog-{}", std::process::id()));
    let _ = fs::create_dir_all(&xdg);
    // Unique per process, so a parallel test's box can never be counted as ours.
    let name = format!("wdog{}", std::process::id());

    // A FOREGROUND box (the watchdog path under test) with a deadline far longer than the test.
    let child = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            &name,
            "--rootfs",
            rootfs,
            "--timeout",
            "300",
            "--",
            "/bin/busybox",
            "sleep",
            "5",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        eprintln!("skip: could not spawn kern");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    };

    // Wait for it to actually be up (registration happens in the forked supervisor).
    let mut up = false;
    for _ in 0..60 {
        if kern_procs_matching(&name) > 0 {
            up = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !up {
        // userns refused at runtime, or the box never started: skip rather than fail.
        eprintln!("skip: the box never came up");
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }

    // SIGKILL the supervisor: it gets no chance to cancel its own watchdog, which is the binding's
    // teardown path and the deterministic form of the defect.
    let _ = child.kill();
    let _ = child.wait(); // reap it, so the supervisor itself is never counted as a leftover

    // The box's workload is a bounded `sleep 5`, so the box is GONE by ~5 s no matter whether killing
    // the supervisor cascaded to it - and a FIXED watchdog (pidfd-driven) then leaves with it. A
    // DEFECTIVE watchdog would sleep out its 300 s deadline and still be here. So poll up to 15 s (well
    // above the box's own exit, well below the 300 s the defect would take): a still-present process at
    // 15 s is the watchdog sleeping past the box, not the box legitimately still being guarded. This is
    // deterministic under heavy parallel load, where the old 5 s window could catch a box whose
    // supervisor-kill cascade had simply not landed yet.
    let mut left = kern_procs_matching(&name);
    for _ in 0..150 {
        if left == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        left = kern_procs_matching(&name);
    }
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
    assert_eq!(
        left, 0,
        "`kern stop` returned but {left} kern process(es) for box `{name}` are still alive: the \
         --timeout watchdog is sleeping out the rest of its deadline instead of leaving with the box"
    );
}

/// A `kern.toml` is not always the user's own file: it travels with a project, a script exports
/// `KERN_CONFIG`, `--config` takes a path. So the strings in it are untrusted input, and the error
/// messages that quote them reach a terminal.
///
/// Measured on 2026-08-04, before this was closed: a `backend` value holding the real bytes
/// `ESC[2K ESC[1A ESC[32m` came out of `kern` unfiltered, so the refusal erased its own line, moved
/// the cursor up one, and repainted in green. A rejection could be made to read as a success. A
/// carriage return did the same to the start of the line. Five fields leaked: the profile name, the
/// size, and the `backend` of all three profile kinds.
///
/// The fix is at the two places an error reaches the user rather than at the sites that format a
/// value, so a message added later is covered without anyone remembering. This test asserts the
/// property end to end, on the real binary, because that is the only place the whole path exists.
#[test]
fn a_hostile_kern_toml_cannot_inject_escapes_into_an_error() {
    let dir = std::env::temp_dir().join(format!("kern-ansi-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let cfg = dir.join("kern.toml");

    // Real control bytes, not the text "\\u001b": an earlier version of this check wrote the escape
    // sequence as literal characters, TOML never turned them into one byte, and it proved nothing.
    let esc = "\u{1b}[2K\u{1b}[1A\u{1b}[32mLOOKS OK\u{1b}[0m";
    let cases: [(&str, String); 3] = [
        (
            "vdisk backend",
            format!("[[vdisk]]\nname = \"p\"\nbackend = \"{esc}\"\nsize = \"8m\"\n"),
        ),
        (
            "vdisk size",
            format!("[[vdisk]]\nname = \"p\"\nbackend = \"ram\"\nsize = \"{esc}\"\n"),
        ),
        (
            "vcpu backend",
            format!("[[vcpu]]\nname = \"p\"\nbackend = \"{esc}\"\ncpus = 1\n"),
        ),
    ];

    for (what, body) in cases {
        if std::fs::write(&cfg, &body).is_err() {
            eprintln!("skip: cannot write {}", cfg.display());
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let kind = if what.starts_with("vcpu") {
            "vcpu"
        } else {
            "vdisk"
        };
        let out = match kern()
            .env("KERN_CONFIG", &cfg)
            .args([
                "box",
                "ansiprobe",
                "--image",
                "alpine:3.19",
                &format!("{kind}:p"),
                "--",
                "true",
            ])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                eprintln!("skip: cannot run kern: {e}");
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
        };

        // stderr AND stdout: an escape is just as effective on either stream.
        for (stream, bytes) in [("stderr", &out.stderr), ("stdout", &out.stdout)] {
            assert!(
                !bytes.contains(&0x1b),
                "{what}: an ESC byte (0x1b) reached {stream}, so a crafted kern.toml can repaint \
                 kern's own output: {:?}",
                String::from_utf8_lossy(bytes)
            );
            assert!(
                !bytes.contains(&b'\r'),
                "{what}: a carriage return reached {stream}, which overwrites the start of the \
                 line: {:?}",
                String::from_utf8_lossy(bytes)
            );
        }
        // The message must still SAY something: scrubbing that emptied the error would pass the
        // assertions above and be worse than the defect.
        assert!(
            !out.stderr.is_empty(),
            "{what}: the box was refused with an empty stderr"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--plan` must resolve profiles against the SAME kern.toml the launch would use.
///
/// It did not. `box_plan` called `config::load(None)`, which reads `$KERN_CONFIG` or the default
/// location, while the launch reads the `--config` path. With a valid profile in the file that was
/// passed, the preview printed `cannot attach: no [[vcpu]] profile named 'slim' in kern.toml` and
/// the launch attached it. That is the worst shape a preview can take: it is believed, and it
/// denies something that will happen.
///
/// The assertion is the discriminant that found it, not the symptom: the two ways of naming a
/// config must produce the SAME preview. A test that only asserted "does not say cannot attach"
/// would pass again the moment a third source is added and forgotten, which is how this arrived.
#[test]
fn the_plan_resolves_the_config_the_launch_would_use() {
    let dir = std::env::temp_dir().join(format!("kern-plan-cfg-{}", std::process::id()));
    let _ = fs::create_dir_all(&dir);
    let toml = dir.join("kern.toml");
    fs::write(
        &toml,
        "[[vcpu]]\nname = \"slim\"\nbackend = \"host\"\ncpus = 1\nmemory = \"128M\"\n\
         [[vdisk]]\nname = \"s\"\nbackend = \"ram\"\nsize = \"8M\"\n",
    )
    .expect("write kern.toml");
    let path = toml.to_string_lossy().to_string();

    let via_flag = kern()
        .args([
            "box",
            "planbox",
            "--config",
            &path,
            "--rootfs",
            "/",
            "vcpu:slim",
            "vdisk:s",
            "--plan",
        ])
        .output()
        .expect("run kern");
    let via_env = kern()
        .args([
            "box",
            "planbox",
            "--rootfs",
            "/",
            "vcpu:slim",
            "vdisk:s",
            "--plan",
        ])
        .env("KERN_CONFIG", &path)
        .output()
        .expect("run kern");

    let pick = |out: &std::process::Output| -> Vec<String> {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.contains("vcpu:") || l.contains("vdisk:"))
            .map(str::trim)
            .map(str::to_string)
            .collect()
    };
    let (flag, env) = (pick(&via_flag), pick(&via_env));
    let _ = fs::remove_dir_all(&dir);

    assert!(
        !flag.is_empty(),
        "--plan printed no profile line at all, so this test guards nothing: {:?}",
        String::from_utf8_lossy(&via_flag.stdout)
    );
    assert_eq!(
        flag, env,
        "`--config <path>` and KERN_CONFIG=<path> named the same file and previewed differently, \
         so --plan is reading a config the launch would not"
    );
    for line in &flag {
        assert!(
            !line.contains("cannot attach"),
            "--plan refused a profile that is declared in the config it was handed: {line}"
        );
    }
}

/// `volume ls --json` must name volumes that EXIST, and must say which ones the other verbs refuse.
///
/// Two defects, both found by planting directories under `volumes/` rather than by reading:
///
///   1. The scan scrubbed control characters out of the name before anything saw it, so the listing
///      reported 3 of 38 names that are not on disk. A script doing `kern volume rm "$name"` then
///      either fails or, when the scrubbed form collides with another volume's real name (a name
///      holding a newline scrubs down to one that may already exist), deletes the WRONG volume.
///      `kern top`'s remove prompt fed the same scrubbed string to its destructive action.
///   2. Once the raw name was reported, the listing contradicted the rest of the CLI: `inspect`,
///      `rm` and `-v` refuse a name outside the creation charset, so `ls` was announcing volumes no
///      other verb would touch. `usable` states that instead of leaving the reader to discover it.
///
/// A control byte must survive as an ESCAPE, never as a raw byte: preserving it keeps the name
/// actionable, escaping it keeps it off a terminal.
#[test]
fn volume_json_reports_names_that_exist_and_flags_the_ones_it_cannot_use() {
    let home = std::env::temp_dir().join(format!("kern-vjson-{}", std::process::id()));
    let vols = home.join("kern").join("volumes");
    let _ = fs::remove_dir_all(&home);
    // `ok-one` is a name kern would itself create; the other two are plantable only from outside.
    let weird = format!("we{}[31mird", '\u{1b}');
    let newline = "two\nlines".to_string();
    for name in ["ok-one".to_string(), weird, newline] {
        let d = vols.join(&name).join("data");
        if fs::create_dir_all(&d).is_err() {
            eprintln!("skip: cannot plant volume dirs under {}", vols.display());
            return;
        }
        if fs::write(vols.join(&name).join("meta.json"), "{\"created\":1}").is_err() {
            eprintln!("skip: cannot write the meta.json sidecar");
            return;
        }
    }
    let out = kern()
        .args(["volume", "ls", "--json"])
        .env("XDG_DATA_HOME", &home)
        .output()
        .expect("run kern");
    let stdout = out.stdout.clone();
    let _ = fs::remove_dir_all(&home);

    assert!(
        !stdout.contains(&0x1b),
        "a raw ESC byte reached stdout: the JSON path emitted a control byte instead of escaping \
         it: {:?}",
        String::from_utf8_lossy(&stdout)
    );
    let text = String::from_utf8_lossy(&stdout);
    assert_eq!(
        text.trim().lines().count(),
        1,
        "the JSON array spans more than one line, so a planted newline reached the output raw: \
         {text:?}"
    );
    assert!(
        text.contains("\\u001b"),
        "the ESC byte was dropped instead of escaped, so the reported name is not the name on \
         disk: {text:?}"
    );
    assert!(
        text.contains("\\n"),
        "the newline was dropped instead of escaped: {text:?}"
    );
    // The creation-charset verdict travels with each entry, and both values are present.
    assert!(
        text.contains("\"usable\":true") && text.contains("\"usable\":false"),
        "`usable` does not distinguish a kern-created name from a planted one: {text:?}"
    );
}

/// `kern exec` reapplies the box's OWN capability drop, not the always-dropped baseline.
///
/// A box created with `--cap-drop ALL` runs its PID 1 at `CapEff 0000000000000000`. Before this fix
/// `kern exec` dropped only the dangerous baseline, so an exec'd process came back holding the
/// 27-capability baseline (`CapEff 00000110bda4ffff`) inside a box whose whole point was to have
/// none. The box's spec is recorded in the registry and rebuilt here, so exec matches PID 1.
///
/// Skip-graceful: no static busybox, or userns unavailable, returns early rather than failing.
#[test]
fn exec_reapplies_the_box_cap_drop_not_the_baseline() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    let root = build_rootfs(&busybox, "capexec");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-capexec-xdg-{}", std::process::id()));
    let _ = fs::create_dir_all(&xdg);

    let start = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            "capbox",
            "--rootfs",
            rootfs,
            "-d",
            "--cap-drop",
            "ALL",
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
    if !start.status.success() {
        eprintln!(
            "skip: detached --cap-drop ALL box did not start here: {}",
            String::from_utf8_lossy(&start.stderr)
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    let capeff = |target: &str| -> String {
        let out = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args([
                "exec",
                "capbox",
                "--",
                "/bin/busybox",
                "sh",
                "-c",
                &format!("grep CapEff /proc/{target}/status"),
            ])
            .output()
            .expect("run kern");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .map(|v| v.trim().to_string())
            .unwrap_or_default()
    };

    let pid1 = capeff("1");
    let exec_self = capeff("self");
    let _ = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["stop", "capbox"])
        .output();
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);

    // If we could not read either (an environment where exec itself is blocked), skip rather than
    // assert on empty strings.
    if pid1.is_empty() || exec_self.is_empty() {
        eprintln!("skip: could not read CapEff through exec here");
        return;
    }
    assert_eq!(
        pid1, "0000000000000000",
        "the box's PID 1 must hold no capabilities under --cap-drop ALL"
    );
    assert_eq!(
        exec_self, "0000000000000000",
        "kern exec must reapply --cap-drop ALL: an exec holding the baseline breaks the contract"
    );
    assert_eq!(
        exec_self, pid1,
        "exec's capability set must match the box's PID 1, not the always-dropped baseline"
    );
}

/// `kern exec` must REFUSE a box whose capability posture cannot be reconstructed: a record from
/// before the posture fields existed is UNKNOWABLE (drop-ALL and default both look empty), so guessing
/// a baseline could enter the box MORE privileged than its PID 1. The box stays visible to `ps`/`stop`;
/// only `exec` gates on it. This is the fail-loud half of the "posture in the registry" contract -
/// `absent != empty`, and absent never silently becomes a default.
///
/// Skip-graceful: no static busybox / userns unavailable returns early rather than failing.
#[test]
fn exec_refuses_a_box_whose_security_profile_was_not_recorded() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    let root = build_rootfs(&busybox, "oldexec");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-oldexec-xdg-{}", std::process::id()));
    let _ = fs::create_dir_all(&xdg);

    let start = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            "oldbox",
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
    if !start.status.success() {
        eprintln!(
            "skip: detached box did not start here: {}",
            String::from_utf8_lossy(&start.stderr)
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Downgrade the on-disk record to a PRE-posture entry: strip the capability + seccomp lines, as a
    // box registered by an older kern would look. The box PROCESS is untouched and still alive, so
    // `find_ref` still resolves it - the gate is purely on the missing posture, not on liveness.
    let insts = xdg.join("kern").join("instances");
    let mut downgraded = false;
    if let Ok(rd) = fs::read_dir(&insts) {
        for e in rd.flatten() {
            let p = e.path();
            let Ok(body) = fs::read_to_string(&p) else {
                continue;
            };
            if !body.contains("name=oldbox") {
                continue;
            }
            let stripped: String = body
                .lines()
                .filter(|l| {
                    !l.starts_with("capdropall=")
                        && !l.starts_with("capdrops=")
                        && !l.starts_with("capadds=")
                        && !l.starts_with("seccompmode=")
                })
                .map(|l| format!("{l}\n"))
                .collect();
            fs::write(&p, stripped).expect("rewrite instance record");
            downgraded = true;
        }
    }
    assert!(
        downgraded,
        "test setup: could not find the box's instance record to downgrade"
    );

    let exec = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["exec", "oldbox", "--", "/bin/busybox", "true"])
        .output()
        .expect("run kern");

    let _ = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["stop", "oldbox"])
        .output();
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);

    assert!(
        !exec.status.success(),
        "exec into a box with no recorded capability profile must FAIL, not silently apply a baseline"
    );
    let err = String::from_utf8_lossy(&exec.stderr);
    assert!(
        err.contains("security profile was recorded") || err.contains("cannot be reconstructed"),
        "the refusal must name the cause; got stderr: {err}"
    );
}

/// The memory cap is a real OOM backstop, not just a number written to the cgroup: a box that
/// allocates past `-m` is OOM-killed (exit 137). Bounded to ~128 MiB so that where the cap does NOT
/// bind (no cgroup delegation - a CI sandbox, WSL2 without cgroup_enable=memory) the box merely
/// allocates 128 MiB and exits 0, which we treat as a skip - never a host-OOMing runaway.
#[test]
fn box_memory_cap_oom_kills_an_over_allocation() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "oomcap");
    let rootfs = root.to_str().unwrap();
    // awk doubles a 1-char string 27 times -> ~128 MiB, well over the 64 MiB cap. Capped, the box is
    // OOM-killed before it gets there; uncapped, it finishes and exits 0.
    let out = kern()
        .args([
            "box",
            "oomcap",
            "--rootfs",
            rootfs,
            "-m",
            "64m",
            "--",
            "/bin/busybox",
            "awk",
            "BEGIN{s=\"x\";for(i=0;i<27;i++){s=s s};print length(s)}",
        ])
        .output()
        .expect("run kern");
    let err = String::from_utf8_lossy(&out.stderr);
    let _ = fs::remove_dir_all(&root);
    if err.contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        return;
    }
    // `memory.oom.group=1` kills the WHOLE box cgroup, and the foreground supervisor is a member of
    // it, so the `kern box` process is itself SIGKILL'd - `code()` is None (signal death), which the
    // shell reports as 137 but `ExitStatus` reports as `signal()==SIGKILL`. Accept either that or a
    // recorded 137 exit; only a clean success (0) means the cap did not bind (skip).
    use std::os::unix::process::ExitStatusExt;
    let oom = out.status.code() == Some(137) || out.status.signal() == Some(libc::SIGKILL);
    match () {
        _ if oom => eprintln!("verified: -m 64m OOM-killed the over-allocation"),
        _ if out.status.success() => {
            eprintln!("skip: memory cap not enforced here (box allocated ~128 MiB uncapped)")
        }
        _ => {
            panic!(
                "expected OOM (137 / SIGKILL) or 0 (uncapped skip), got code={:?} signal={:?} (stderr: {err})",
                out.status.code(),
                out.status.signal()
            )
        }
    }
}

/// `memory.oom.group = 1` is the design promise that an OOM takes the WHOLE box, not one process:
/// kern sets it, and a group-kill leaves no survivor. Two boxes: the first reads the cgroup back and
/// skips where the `memory` controller is not delegated (a CI sandbox, WSL2 without
/// `cgroup_enable=memory`) - there is no backstop to test there; the second races a sleeper child
/// against a parent that allocates past the cap, and proves neither task outlives the kill. Guards
/// the CHANGELOG claim "An OOM kills the whole box (memory.oom.group = 1), not one process" as a
/// test, not prose. The exit is 137 / SIGKILL (the OOM signal); a 143 seen on some boards is the box
/// init being torn down AFTER, a lifecycle artifact, never the OOM itself.
#[test]
fn box_oom_group_kills_the_whole_box_atomically() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "oomgrp");
    let rootfs = root.to_str().unwrap();

    // 1. Read the cgroup back. Where memory IS delegated, kern must have set oom.group=1 and a real
    //    ceiling; where it is NOT, memory.max reads `max` and there is nothing to test - skip.
    let read = kern()
        .args([
            "box",
            "oomgrpread",
            "--rootfs",
            rootfs,
            "-m",
            "64m",
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            "echo GRP=$(cat /sys/fs/cgroup/memory.oom.group 2>/dev/null) \
             MAX=$(cat /sys/fs/cgroup/memory.max 2>/dev/null)",
        ])
        .output()
        .expect("run kern");
    let read_out = String::from_utf8_lossy(&read.stdout);
    if read_out.contains("MAX=max") || !read_out.contains("MAX=") {
        let _ = fs::remove_dir_all(&root);
        eprintln!(
            "skip: memory controller not delegated here ({})",
            read_out.trim()
        );
        return;
    }
    assert!(
        read_out.contains("GRP=1"),
        "kern must set memory.oom.group=1 on a capped box (the whole-box OOM promise): {}",
        read_out.trim()
    );

    // 2. Atomic group-kill: a sleeper child and a post-allocation marker must BOTH vanish when the
    //    parent trips the OOM. With oom.group=1 the kernel SIGKILLs every task in the cgroup at once,
    //    so neither marker is ever printed; with oom.group=0 the sleeper (or the parent line) would
    //    outlive the single-process kill and leak a "SURVIVED" line.
    let out = kern()
        .args([
            "box",
            "oomgrpkill",
            "--rootfs",
            rootfs,
            "-m",
            "64m",
            "--",
            "/bin/busybox",
            "sh",
            "-c",
            "( /bin/busybox sleep 3; echo SURVIVED-CHILD ) & \
             /bin/busybox awk 'BEGIN{s=\"x\";for(i=0;i<27;i++){s=s s};print length(s)}'; \
             echo SURVIVED-PARENT; wait",
        ])
        .output()
        .expect("run kern");
    let err = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let _ = fs::remove_dir_all(&root);
    if err.contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        return;
    }
    use std::os::unix::process::ExitStatusExt;
    if out.status.success() {
        eprintln!("skip: memory cap not enforced here (box allocated uncapped)");
        return;
    }
    // The box did not survive: on a modern kernel the group-kill is SIGKILL (137); on some boards
    // (Arduino UNO Q) the reported code is 143, the box init being torn down AFTER the kill. Either
    // way the box is gone - the promise we actually pin is the ATOMICITY below (no task outlived),
    // not the exact signal. A clean error code (1/2) would mean the workload failed for another
    // reason, so it is not accepted here.
    let killed =
        out.status.signal() == Some(libc::SIGKILL) || matches!(out.status.code(), Some(137 | 143));
    assert!(
        killed,
        "expected the box to be OOM-killed (137 / SIGKILL / 143), got code={:?} signal={:?} (stderr: {err})",
        out.status.code(),
        out.status.signal()
    );
    assert!(
        !stdout.contains("SURVIVED"),
        "oom.group=1 must take the whole box: no task may outlive the kill, but saw: {}",
        stdout.trim()
    );
}

/// `kern cp` round-trips a file host -> box -> host byte-identically, into and out of a detached box.
#[test]
fn box_cp_round_trips_a_file_host_box_host() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "cprt");
    let rootfs = root.to_str().unwrap();
    let up = kern()
        .args([
            "box",
            "cprt",
            "--rootfs",
            rootfs,
            "-d",
            "--",
            "/bin/busybox",
            "sleep",
            "30",
        ])
        .output()
        .expect("run kern");
    let uperr = String::from_utf8_lossy(&up.stderr);
    if uperr.contains("user namespaces") {
        let _ = fs::remove_dir_all(&root);
        eprintln!("skip: userns unavailable at runtime");
        return;
    }
    if !up.status.success() {
        let _ = fs::remove_dir_all(&root);
        eprintln!("skip: box did not start (stderr: {uperr})");
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    let tmp = std::env::temp_dir().join(format!("kern-it-cp-{}", std::process::id()));
    let _ = fs::create_dir_all(&tmp);
    let src = tmp.join("in.bin");
    let dst = tmp.join("out.bin");
    let data: Vec<u8> = (0u32..4096).map(|i| i.wrapping_mul(7) as u8).collect();
    fs::write(&src, &data).unwrap();
    kern()
        .args(["cp", src.to_str().unwrap(), "cprt:/in.bin"])
        .output()
        .ok();
    kern()
        .args(["cp", "cprt:/in.bin", dst.to_str().unwrap()])
        .output()
        .ok();
    let round_trips = fs::read(&dst).ok().as_deref() == Some(data.as_slice());
    kern().args(["stop", "cprt"]).output().ok();
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        round_trips,
        "kern cp host->box->host must be byte-identical"
    );
}

/// `KERN_MAX_CONCURRENT=N` admits exactly N live boxes and refuses the overflow. `#[ignore]`d: the
/// fleet cap is HOST-GLOBAL, so the parallel suite's other boxes would count toward it and make the
/// tally non-deterministic. Run it alone: `cargo test -- --ignored box_fleet_cap`.
#[test]
#[ignore]
fn box_fleet_cap_admits_exactly_n_refuses_the_rest() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "fleetcap");
    let rootfs = root.to_str().unwrap();
    let n = 2;
    let mut admitted = 0;
    for i in 0..(n + 2) {
        let name = format!("fleetcap{i}");
        let out = kern()
            .env("KERN_MAX_CONCURRENT", n.to_string())
            .args([
                "box",
                &name,
                "--rootfs",
                rootfs,
                "-d",
                "--",
                "/bin/busybox",
                "sleep",
                "30",
            ])
            .output()
            .expect("run kern");
        if i == 0 && String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
            let _ = fs::remove_dir_all(&root);
            eprintln!("skip: userns unavailable at runtime");
            return;
        }
        if out.status.success() {
            admitted += 1;
        }
    }
    for i in 0..(n + 2) {
        kern().args(["stop", &format!("fleetcap{i}")]).output().ok();
    }
    let _ = fs::remove_dir_all(&root);
    assert_eq!(
        admitted, n,
        "KERN_MAX_CONCURRENT={n} must admit exactly {n} live boxes, got {admitted}"
    );
}

/// `--landlock-rw` means the same thing on every host: either the kernel enforces the write allowlist,
/// or the box does not start. It is the third member of kern's "enforce or do not run" family
/// (`--require-limits` for cgroup caps, `--apparmor` for the LSM profile) and used to be the only one
/// that degraded silently, handing an operator who wrote it into a script an unconfined box on exactly
/// the hosts whose kernel they were least sure of.
///
/// Both halves of that contract are asserted, and which half runs is decided by the host rather than
/// assumed, so the test is meaningful on a kernel with Landlock AND on one without:
///   * Landlock present  -> a write OUTSIDE the allowlist is denied while one INSIDE it succeeds. The
///     inside-write is the positive control: without it, a box that failed to start for an unrelated
///     reason would look exactly like a box that enforced the rule.
///   * Landlock absent   -> the box is REFUSED, and the message names the flag rather than failing with
///     something generic the operator has to guess at.
#[test]
fn landlock_rw_enforces_the_allowlist_or_refuses_the_box() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "landlock");
    // Two sibling dirs INSIDE the box root: one named in the allowlist, one deliberately not.
    fs::create_dir_all(root.join("allowed")).unwrap();
    fs::create_dir_all(root.join("denied")).unwrap();
    let rootfs = root.to_str().unwrap();

    // `RAN` is emitted before either write and proves the box EXECUTED. Without it, a host where no
    // box can start at all (the GitHub runners restrict unprivileged userns through AppArmor, which
    // `userns_plausible` does not detect) is indistinguishable from a box that started and was denied
    // its own allowlisted write, so the test would either fail on the environment or skip over a real
    // regression. With it, the two are separated: no `RAN` is a SKIP, `RAN` makes both writes
    // meaningful and neither assertion can be dodged.
    let script = "echo RAN; \
                  /bin/busybox touch /allowed/in 2>/dev/null && echo IN-OK; \
                  /bin/busybox touch /denied/out 2>/dev/null && echo OUT-WROTE";
    let out = kern_out(&[
        "box",
        "landlock",
        "--rootfs",
        rootfs,
        "--landlock-rw",
        "/allowed",
        "--",
        "/bin/busybox",
        "sh",
        "-c",
        script,
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let _ = std::process::Command::new(env!("CARGO_BIN_EXE_kern"))
        .args(["rm", "-f", "landlock"])
        .output();
    let _ = fs::remove_dir_all(&root);

    // Ask the same question kern asks, so the expectation is derived from the host, never guessed.
    let landlock_here = kern_isolation::landlock_abi().is_some();
    if landlock_here {
        if !stdout.contains("RAN") {
            // No box can start on this host, so there is nothing to say about Landlock. Skipping with
            // the reason beats failing on the environment, and beats a silent pass.
            eprintln!("skip: the box did not run on this host (stderr={stderr:?})");
            return;
        }
        assert!(
            stdout.contains("IN-OK"),
            "positive control: a write INSIDE the allowlist must succeed. The box ran (RAN), so this \
             is the rule denying a path it was told to permit, not an environment that cannot start \
             boxes. stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            !stdout.contains("OUT-WROTE"),
            "a write OUTSIDE the --landlock-rw allowlist must be denied by the LSM. \
             stdout={stdout:?} stderr={stderr:?}"
        );
    } else {
        // The regression this half exists to catch: the box RAN on a kernel with no Landlock, i.e.
        // it was told to confine writes, could not, and started anyway. `RAN` says it executed, which
        // is exactly the thing that must not happen; the exit status alone would not, because a box
        // can also fail for reasons that have nothing to do with this flag.
        assert!(
            !stdout.contains("RAN"),
            "with no Landlock on this kernel the box must be REFUSED, not run unconfined. \
             stdout={stdout:?} stderr={stderr:?}"
        );
        if !stderr.contains("--landlock-rw") {
            // It did not run, but something else stopped it first (no busybox-compatible rootfs, no
            // userns on this host). Nothing can be concluded about the refusal, so say so.
            eprintln!("skip: the box failed before the Landlock check (stderr={stderr:?})");
            return;
        }
        assert!(
            !out.status.success(),
            "the Landlock refusal must be a non-zero exit, not a message on a successful run. \
             stdout={stdout:?} stderr={stderr:?}"
        );
    }
}
