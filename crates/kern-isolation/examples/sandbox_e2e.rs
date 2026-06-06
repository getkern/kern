//! End-to-end exercise of the embeddable [`kern_isolation::Sandbox`] SDK.
//!
//! Usage: `sandbox_e2e <rootfs-dir>` — runs a series of real sandboxed commands
//! through the fluent builder and prints one `CASE <name> <PASS|FAIL>` line per
//! check. Exits non-zero if any case fails. Requires a runnable rootfs (with
//! `/bin/busybox`) and a locatable `kern` binary (`KERN_BIN` or on `PATH`).
//!
//! This is the live counterpart to the crate's pure unit tests: the unit tests
//! prove the arg translation; this proves the whole spawn → isolate → capture →
//! reap loop against the real `kern` binary.

use kern_isolation::{Sandbox, SeccompMode};

fn main() {
    let rootfs = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: sandbox_e2e <rootfs-dir>");
        std::process::exit(2);
    });

    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut check = |name: &str, ok: bool| {
        if ok {
            pass += 1;
            println!("CASE {name} PASS");
        } else {
            fail += 1;
            println!("CASE {name} FAIL");
        }
    };

    let bb = "/bin/busybox";
    let base = || Sandbox::builder().rootfs(&rootfs);

    // 1. Captures stdout + exit 0.
    match base().build().unwrap().run(bb, &["echo", "hello-sdk"]) {
        Ok(o) => check(
            "capture_stdout",
            o.success() && o.stdout_str() == Some("hello-sdk\n"),
        ),
        Err(e) => {
            eprintln!("capture_stdout errored: {e}");
            check("capture_stdout", false);
        }
    }

    // 2. Non-zero exit code propagates.
    match base().build().unwrap().run(bb, &["false"]) {
        Ok(o) => check("exit_code_propagates", o.exit_code == 1),
        Err(_) => check("exit_code_propagates", false),
    }

    // 3. stderr captured separately from stdout.
    match base()
        .build()
        .unwrap()
        .run(bb, &["sh", "-c", "echo out; echo err 1>&2"])
    {
        Ok(o) => check(
            "stderr_separate",
            o.stdout_str() == Some("out\n") && o.stderr_str() == Some("err\n"),
        ),
        Err(_) => check("stderr_separate", false),
    }

    // 4. Filesystem isolation: the host /home is not visible inside the box.
    match base().build().unwrap().run(
        bb,
        &["sh", "-c", "[ -e /home ] && echo LEAK || echo isolated"],
    ) {
        Ok(o) => check("no_host_home", o.stdout_str() == Some("isolated\n")),
        Err(_) => check("no_host_home", false),
    }

    // 5. Guest env var is delivered.
    match base()
        .env("SDK_TOKEN", "xyzzy")
        .build()
        .unwrap()
        .run(bb, &["sh", "-c", "echo $SDK_TOKEN"])
    {
        Ok(o) => check("env_delivered", o.stdout_str() == Some("xyzzy\n")),
        Err(_) => check("env_delivered", false),
    }

    // 6. stdin is piped in.
    match base()
        .stdin(b"piped-line\n".to_vec())
        .build()
        .unwrap()
        .run(bb, &["cat"])
    {
        Ok(o) => check("stdin_piped", o.stdout_str() == Some("piped-line\n")),
        Err(_) => check("stdin_piped", false),
    }

    // Flood scripts built from POSIX-sh BUILTINS ONLY (echo/while/[/arithmetic) so
    // they run in a bare rootfs where busybox applets like seq/yes/tr don't
    // resolve — otherwise we'd be testing applet availability, not the SDK.
    let line50 = "A".repeat(50);
    let flood_64 = "i=0; while [ $i -lt 2000 ]; do echo AAAAAAAA; i=$((i+1)); done";
    // ~102 KB via 2000 lines of 51 bytes each.
    let flood_100k = format!("i=0; while [ $i -lt 2000 ]; do echo {line50}; i=$((i+1)); done");
    let flood_both = "i=0; while [ $i -lt 2000 ]; do echo AAAAAAAA; i=$((i+1)); done; \
                      i=0; while [ $i -lt 2000 ]; do echo BBBBBBBB 1>&2; i=$((i+1)); done";

    // 7. stdout truncation is flagged when the guest exceeds the cap.
    match base()
        .stdout_limit_bytes(64)
        .build()
        .unwrap()
        .run(bb, &["sh", "-c", flood_64])
    {
        Ok(o) => check(
            "stdout_truncation_flagged",
            o.stdout_truncated && o.stdout.len() <= 64,
        ),
        Err(_) => check("stdout_truncation_flagged", false),
    }

    // 8. A read-only root rejects a write. The write is a shell REDIRECTION
    //    (builtin, no applet) inside a SUBSHELL: a failed redirection aborts a
    //    non-interactive shell (POSIX), so the subshell contains that abort and
    //    the outer shell still reaches the `|| echo ro`. A "touch not found"
    //    can't make this pass vacuously — only a real write-block yields "ro".
    match base().readonly_root().build().unwrap().run(
        bb,
        &[
            "sh",
            "-c",
            "( : > /nope ) 2>/dev/null && echo WROTE || echo ro",
        ],
    ) {
        Ok(o) => check("readonly_root_blocks_write", o.stdout_str() == Some("ro\n")),
        Err(_) => check("readonly_root_blocks_write", false),
    }

    // 9. workdir is honored.
    match base().workdir("/tmp").build().unwrap().run(bb, &["pwd"]) {
        Ok(o) => check("workdir_honored", o.stdout_str() == Some("/tmp\n")),
        Err(_) => check("workdir_honored", false),
    }

    // 10. The seccomp setter is accepted (advisory) and the run still succeeds.
    match base()
        .seccomp(SeccompMode::DenylistHardened)
        .build()
        .unwrap()
        .run(bb, &["true"])
    {
        Ok(o) => check("seccomp_advisory_ok", o.success()),
        Err(_) => check("seccomp_advisory_ok", false),
    }

    // 11. THE deadlock guard: a 1 MiB stdin the guest never reads, WHILE the guest
    //     floods stdout (~102 KB, well past the 64 KiB pipe buffer) via a builtin
    //     loop. With the old ordering (write stdin on the main thread before
    //     starting the stdout drainer) both pipes fill and neither side can
    //     progress — a hang. It must complete and capture the whole flood.
    let big = vec![b'Z'; 1024 * 1024];
    match base()
        .stdin(big)
        .build()
        .unwrap()
        .run(bb, &["sh", "-c", &flood_100k])
    {
        Ok(o) => check(
            "large_unread_stdin_plus_stdout_flood_no_deadlock",
            o.success() && o.stdout.len() >= 90_000 && !o.stdout_truncated,
        ),
        Err(e) => {
            eprintln!("large_stdin errored: {e}");
            check("large_unread_stdin_plus_stdout_flood_no_deadlock", false);
        }
    }

    // 12. Guest floods BOTH streams past the caps via builtin loops — must not
    //     deadlock and both must be flagged truncated.
    match base()
        .stdout_limit_bytes(4096)
        .stderr_limit_bytes(4096)
        .build()
        .unwrap()
        .run(bb, &["sh", "-c", flood_both])
    {
        Ok(o) => check(
            "both_streams_flood_truncates",
            o.stdout_truncated && o.stderr_truncated && o.stdout.len() <= 4096,
        ),
        Err(_) => check("both_streams_flood_truncates", false),
    }

    // 13. A timeout actually kills a runaway. `sleep` is invoked DIRECTLY as a
    //     busybox applet (`/bin/busybox sleep 10`), not via `sh -c "sleep"` —
    //     which would hit the applet-resolution gotcha in a bare rootfs. A 1 s
    //     timeout must kill the 10 s sleep: non-success and a sub-6 s wall time.
    match base()
        .timeout_ms(1000)
        .build()
        .unwrap()
        .run(bb, &["sleep", "10"])
    {
        Ok(o) => check("timeout_kills_runaway", !o.success() && o.wall_ms < 6000),
        Err(_) => check("timeout_kills_runaway", false),
    }

    // 14. Args are passed via execve, not a shell: whitespace/tabs/newlines in an
    //     argument survive verbatim (no word-splitting, no injection).
    match base().build().unwrap().run(bb, &["echo", "a b\tc\nd"]) {
        Ok(o) => check(
            "arg_whitespace_preserved",
            o.stdout_str() == Some("a b\tc\nd\n"),
        ),
        Err(_) => check("arg_whitespace_preserved", false),
    }

    // 15. A non-existent guest command yields a non-zero exit (not a false success).
    match base().build().unwrap().run("/bin/does-not-exist", &[]) {
        Ok(o) => check("missing_command_nonzero", !o.success()),
        Err(_) => check("missing_command_nonzero", false),
    }

    // 16. bind_rootfs: bind the rootfs directly instead of layering an overlay —
    //     the fast path on kernels with slow overlayfs (e.g. the Arduino board).
    //     Must still run and capture.
    match Sandbox::builder()
        .rootfs(&rootfs)
        .bind_rootfs()
        .build()
        .unwrap()
        .run(bb, &["echo", "bound"])
    {
        Ok(o) => check(
            "bind_rootfs_runs",
            o.success() && o.stdout_str() == Some("bound\n"),
        ),
        Err(e) => {
            eprintln!("bind_rootfs errored: {e}");
            check("bind_rootfs_runs", false);
        }
    }

    // 17. Compose from a kern.toml: author a `[[vdisk]]` profile, apply it by
    //     token, and confirm the box actually mounts it at /vdisk/scratch. This
    //     proves .config()/.profile() flow through the SDK → box → real mount.
    let toml_path = format!(
        "{}/kern-sdk-e2e-{}.toml",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let wrote = std::fs::write(
        &toml_path,
        "[[vdisk]]\nname = \"scratch\"\nsize = \"16m\"\n",
    )
    .is_ok();
    if wrote {
        match base()
            .config(&toml_path)
            .profile("vdisk:scratch")
            .build()
            .unwrap()
            .run(
                bb,
                &[
                    "sh",
                    "-c",
                    "[ -d /vdisk/scratch ] && echo HASDISK || echo nodisk",
                ],
            ) {
            Ok(o) => check(
                "config_profile_mounts_vdisk",
                o.stdout_str() == Some("HASDISK\n"),
            ),
            Err(e) => {
                eprintln!("config_profile errored: {e}");
                check("config_profile_mounts_vdisk", false);
            }
        }
        let _ = std::fs::remove_file(&toml_path);
    } else {
        check("config_profile_mounts_vdisk", false);
    }

    eprintln!("sandbox_e2e: {pass} pass / {fail} fail");
    if fail > 0 {
        std::process::exit(1);
    }
}
