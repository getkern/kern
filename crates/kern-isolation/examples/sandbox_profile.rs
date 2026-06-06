//! Extreme end-to-end exercise of the SDK's `kern.toml` compose feature:
//! `.config()` / `.profile()` and the `.warnings()` advisory channel.
//!
//! Usage: `sandbox_profile <rootfs-dir>` — authors real `kern.toml` files and
//! drives the profile resolution through the SDK → box → real mounts, plus the
//! adversarial paths (missing profile, missing config, traversal token) and the
//! informed-override path (`.warnings()`). Prints `CASE <name> <PASS|FAIL>`.

use kern_isolation::Sandbox;

/// Write `body` to a fresh temp path and return it (best-effort; caller removes).
fn write_toml(tag: &str, body: &str) -> Option<String> {
    let p = format!(
        "{}/kern-prof-{}-{}.toml",
        std::env::temp_dir().display(),
        std::process::id(),
        tag
    );
    std::fs::write(&p, body).ok().map(|_| p)
}

fn main() {
    let rootfs = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: sandbox_profile <rootfs-dir>");
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
    let mounted = |o: &kern_isolation::Outcome| o.stdout_str() == Some("Y\n");

    // P1. A single vdisk: profile mounts at /vdisk/<name>.
    if let Some(t) = write_toml("p1", "[[vdisk]]\nname = \"scratch\"\nsize = \"16m\"\n") {
        let r = base()
            .config(&t)
            .profile("vdisk:scratch")
            .build()
            .unwrap()
            .run(
                bb,
                &["sh", "-c", "[ -d /vdisk/scratch ] && echo Y || echo N"],
            );
        check(
            "single_vdisk_profile_mounts",
            matches!(&r, Ok(o) if mounted(o)),
        );
        let _ = std::fs::remove_file(&t);
    }

    // P2. TWO vdisk: profiles → both mounted (profiles accumulate).
    if let Some(t) = write_toml(
        "p2",
        "[[vdisk]]\nname = \"a\"\nsize = \"8m\"\n\n[[vdisk]]\nname = \"b\"\nsize = \"8m\"\n",
    ) {
        let r = base()
            .config(&t)
            .profile("vdisk:a")
            .profile("vdisk:b")
            .build()
            .unwrap()
            .run(
                bb,
                &[
                    "sh",
                    "-c",
                    "[ -d /vdisk/a ] && [ -d /vdisk/b ] && echo Y || echo N",
                ],
            );
        check(
            "two_vdisk_profiles_both_mount",
            matches!(&r, Ok(o) if mounted(o)),
        );
        let _ = std::fs::remove_file(&t);
    }

    // P3. A profile NAME absent from the config → clean failure, never a panic
    //     and never a false success.
    if let Some(t) = write_toml("p3", "[[vdisk]]\nname = \"present\"\nsize = \"8m\"\n") {
        let r = base()
            .config(&t)
            .profile("vdisk:ghost")
            .build()
            .unwrap()
            .run(bb, &["true"]);
        let handled = match r {
            Ok(o) => !o.success(),
            Err(_) => true,
        };
        check("missing_profile_name_errors_clean", handled);
        let _ = std::fs::remove_file(&t);
    }

    // P4. A non-existent config path → clean failure (no panic).
    {
        let r = base()
            .config("/no/such/kern-profile-test.toml")
            .profile("vdisk:x")
            .build()
            .unwrap()
            .run(bb, &["true"]);
        let handled = match r {
            Ok(o) => !o.success(),
            Err(_) => true,
        };
        check("missing_config_file_errors_clean", handled);
    }

    // P5. Informed override: a vcpu: profile sets memory AND an explicit
    //     .memory_limit_bytes() is given. `.warnings()` must flag the shadow, and
    //     the box must still run fine (explicit wins, no crash).
    if let Some(t) = write_toml(
        "p5",
        "[[vcpu]]\nname = \"m\"\nmemory = \"64m\"\nvcpus = 1.0\n",
    ) {
        let sb = base()
            .config(&t)
            .profile("vcpu:m")
            .memory_limit_bytes(128 * 1024 * 1024)
            .build()
            .unwrap();
        let warned = sb.warnings().iter().any(|w| w.contains("memory"));
        let ran = matches!(sb.run(bb, &["echo", "ok"]), Ok(o) if o.stdout_str() == Some("ok\n"));
        check("override_warns_and_still_runs", warned && ran);
        let _ = std::fs::remove_file(&t);
    }

    // P6. A clean profile-only config (no explicit overlap) → NO warnings.
    if let Some(t) = write_toml("p6", "[[vdisk]]\nname = \"clean\"\nsize = \"8m\"\n") {
        let sb = base().config(&t).profile("vdisk:clean").build().unwrap();
        check("clean_config_no_warnings", sb.warnings().is_empty());
        let _ = std::fs::remove_file(&t);
    }

    // P7. A path-traversal token is rejected at build() (never reaches the box).
    {
        let bad = Sandbox::builder()
            .rootfs(&rootfs)
            .profile("vdisk:../../etc")
            .build();
        check("traversal_token_rejected_at_build", bad.is_err());
    }

    // P8. No `.config()` → the profile resolves against the DEFAULT config path
    //     ($XDG_CONFIG_HOME/kern/kern.toml). Author it there and confirm the mount.
    if let Some(cfg_home) = std::env::var_os("XDG_CONFIG_HOME") {
        let dir = format!("{}/kern", cfg_home.to_string_lossy());
        let _ = std::fs::create_dir_all(&dir);
        let p = format!("{dir}/kern.toml");
        if std::fs::write(&p, "[[vdisk]]\nname = \"deflt\"\nsize = \"8m\"\n").is_ok() {
            let r = base() // note: NO .config() — default path is used
                .profile("vdisk:deflt")
                .build()
                .unwrap()
                .run(bb, &["sh", "-c", "[ -d /vdisk/deflt ] && echo Y || echo N"]);
            check(
                "default_config_path_resolves",
                matches!(&r, Ok(o) if mounted(o)),
            );
            let _ = std::fs::remove_file(&p);
        }
    }

    eprintln!("sandbox_profile: {pass} pass / {fail} fail");
    if fail > 0 {
        std::process::exit(1);
    }
}
