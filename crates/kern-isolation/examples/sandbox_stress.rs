//! Extreme stress / adversarial exercise of the [`kern_isolation::Sandbox`] SDK.
//!
//! Usage: `sandbox_stress <rootfs-dir>` - pushes the SDK harder than the
//! functional `sandbox_e2e` suite: concurrent fan-out with output-isolation
//! checks, fd/thread-leak detection over many runs, `Sandbox` reuse, exact
//! truncation boundaries, binary/non-UTF-8 integrity, self-signalled exit codes,
//! timeout-not-fired, and a bad rootfs that must error (not panic). Prints one
//! `CASE <name> <PASS|FAIL>` line each; exits non-zero on any failure.

use kern_isolation::Sandbox;
use std::sync::Arc;

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count())
        .unwrap_or(0)
}

fn main() {
    let rootfs = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: sandbox_stress <rootfs-dir>");
        std::process::exit(2);
    });
    let rootfs = Arc::new(rootfs);

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
    let base = || Sandbox::builder().rootfs(rootfs.as_str());

    // 1. CONCURRENT FAN-OUT (the AI-agent flagship): 24 sandboxes across threads,
    //    each echoing a UNIQUE token. Every one must come back with ITS OWN token
    //    - proof of no cross-talk between concurrent captures (pipes/fds isolated)
    //    and that run() is thread-safe. All must succeed.
    {
        const N: usize = 24;
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let rootfs = Arc::clone(&rootfs);
                std::thread::spawn(move || {
                    let tok = format!("TOK{i}");
                    let out = Sandbox::builder()
                        .rootfs(rootfs.as_str())
                        .build()
                        .unwrap()
                        .run("/bin/busybox", &["echo", &tok]);
                    match out {
                        Ok(o) => o.success() && o.stdout_str() == Some(&format!("{tok}\n")),
                        Err(_) => false,
                    }
                })
            })
            .collect();
        let ok = handles
            .into_iter()
            .filter_map(|h| h.join().ok())
            .collect::<Vec<_>>();
        check(
            "concurrent_fanout_24_no_crosstalk",
            ok.len() == N && ok.iter().all(|&b| b),
        );
    }

    // 2. FD / THREAD LEAK: run 60 times and confirm the process's open-fd count is
    //    stable (the per-run pipes + drain/stdin threads are all reaped). A leak
    //    of a pipe fd per run would blow the count (and eventually EMFILE).
    {
        let s = base().build().unwrap();
        let _ = s.run(bb, &["true"]); // warm up (lazy one-time fds)
        let before = open_fd_count();
        for _ in 0..60 {
            let _ = s.run(bb, &["true"]);
        }
        let after = open_fd_count();
        check("no_fd_leak_over_60_runs", after <= before + 2);
    }

    // 3. SANDBOX REUSE: one built Sandbox, 30 sequential runs, each with distinct
    //    output - no state bleed between runs.
    {
        let s = base().build().unwrap();
        let mut all = true;
        for i in 0..30 {
            let want = format!("R{i}\n");
            match s.run(bb, &["echo", &format!("R{i}")]) {
                Ok(o) => all &= o.stdout_str() == Some(&want),
                Err(_) => all = false,
            }
        }
        check("sandbox_reuse_30_independent", all);
    }

    // 4. EXACT TRUNCATION BOUNDARY: cap C, emit exactly C-1 / C / C+1 bytes. Only
    //    the last must set the truncated flag; the C case must NOT (boundary is
    //    inclusive of C, exclusive of truncation). Guest emits N bytes via a
    //    builtin loop + a partial line, but we keep it simple: `printf`-free -
    //    emit exactly C bytes by echoing a string of C-1 chars (echo adds \n).
    {
        // Cap = 32. A 31-char line + newline = 32 bytes exactly.
        let line31 = "A".repeat(31);
        let line32 = "A".repeat(32); // + newline = 33 → truncated
        let at = base()
            .stdout_limit_bytes(32)
            .build()
            .unwrap()
            .run(bb, &["echo", &line31]);
        let over = base()
            .stdout_limit_bytes(32)
            .build()
            .unwrap()
            .run(bb, &["echo", &line32]);
        let at_ok = matches!(&at, Ok(o) if !o.stdout_truncated && o.stdout.len() == 32);
        let over_ok = matches!(&over, Ok(o) if o.stdout_truncated && o.stdout.len() == 32);
        check("truncation_boundary_exact", at_ok && over_ok);
    }

    // 5. ZERO-BYTE CAP: everything is truncated, capture is empty, and it must not
    //    hang (the drain keeps reading and discarding).
    match base()
        .stdout_limit_bytes(0)
        .build()
        .unwrap()
        .run(bb, &["echo", "anything"])
    {
        Ok(o) => check(
            "zero_cap_empty_truncated_no_hang",
            o.stdout.is_empty() && o.stdout_truncated,
        ),
        Err(_) => check("zero_cap_empty_truncated_no_hang", false),
    }

    // 6. BINARY / NON-UTF-8 INTEGRITY: push raw bytes (NUL, 0xFF, 0xFE) through
    //    stdin → `cat` → stdout. The bytes must survive verbatim; stdout_str()
    //    returns None (invalid UTF-8) but the raw Vec is intact.
    {
        let payload = vec![0u8, 0xFF, 0xFE, b'A', 0u8, 0x80];
        match base()
            .stdin(payload.clone())
            .build()
            .unwrap()
            .run(bb, &["cat"])
        {
            Ok(o) => check(
                "binary_output_integrity",
                o.stdout == payload && o.stdout_str().is_none(),
            ),
            Err(_) => check("binary_output_integrity", false),
        }
    }

    // 7. EXIT-CODE FIDELITY: the SDK must relay an ARBITRARY guest exit code
    //    verbatim (not collapse it to 0/1). `exit` is a shell builtin so it
    //    resolves in a bare rootfs. (A guest that self-signals is NOT a clean
    //    probe here: the box's PID 1 is kernel-protected from an in-namespace
    //    SIGKILL, and the 128+sig path in run() concerns the *kern child* being
    //    signalled, not the guest - kern relays a guest signal as a normal code.)
    match base().build().unwrap().run(bb, &["sh", "-c", "exit 42"]) {
        Ok(o) => check("exit_code_fidelity_42", o.exit_code == 42 && !o.success()),
        Err(_) => check("exit_code_fidelity_42", false),
    }

    // 8. TIMEOUT NOT FIRED: a fast command under a generous timeout runs to normal
    //    success (the timeout must not clip a well-behaved guest).
    match base()
        .timeout_ms(30_000)
        .build()
        .unwrap()
        .run(bb, &["echo", "quick"])
    {
        Ok(o) => check(
            "timeout_not_fired_on_fast_cmd",
            o.success() && o.stdout_str() == Some("quick\n"),
        ),
        Err(_) => check("timeout_not_fired_on_fast_cmd", false),
    }

    // 9. BAD ROOTFS: a non-existent rootfs must fail cleanly - an Err, or an
    //    Ok(Outcome) with a non-zero exit - but NEVER a panic and never a false
    //    success. (If run() panicked, the process would abort before printing.)
    {
        let r = Sandbox::builder()
            .rootfs("/definitely/does/not/exist/kern-stress")
            .build()
            .unwrap()
            .run(bb, &["true"]);
        let handled = match r {
            Ok(o) => !o.success(),
            Err(_) => true,
        };
        check("bad_rootfs_errors_no_panic", handled);
    }

    // 10. MANY ENV VARS: 200 distinct env vars set; a specific one must be
    //     delivered intact to the guest (argv scale + no clobber).
    {
        let mut b = base();
        for i in 0..200 {
            b = b.env(format!("K{i}"), format!("V{i}"));
        }
        match b.build().unwrap().run(bb, &["sh", "-c", "echo $K137"]) {
            Ok(o) => check("many_env_200_delivered", o.stdout_str() == Some("V137\n")),
            Err(_) => check("many_env_200_delivered", false),
        }
    }

    eprintln!("sandbox_stress: {pass} pass / {fail} fail");
    if fail > 0 {
        std::process::exit(1);
    }
}
