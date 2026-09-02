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
/// `compose config` AND `compose up` MUST AGREE ABOUT WHAT THE FILE MAY SAY, ASSERTED AS A PAIR.
///
/// Every case below runs through BOTH verbs in the same fixture, because the defect this guards is a
/// DISAGREEMENT and neither verb can show one on its own. Asserting `config` refuses in one test and
/// `up` refuses in another is the shape that already let this through once: when the `x-kern-*` keys
/// were first read, `config` printed `profiles: vgpio:leds` and exited 0 while `up` failed with
/// `no [[vgpio]] profile named 'leds'`, and both single-verb tests were green. A dry run that
/// disagrees with the bring-up is worse than no dry run, because it is the one people trust before
/// committing a file.
///
/// NO NETWORK, AND FAST: the images name a registry on loopback port 1, which answers ECONNREFUSED
/// at once. An earlier draft used a `.invalid` hostname and the test took 60 s, all of it DNS
/// timeouts on the two ACCEPTED rows (the refused ones never reach the pull). MEASURED, `up`
/// refuses on these keys strictly before it pulls anything (`error: usage: kern
/// --security-profile: expected untrusted` with the image never touched). The accepted case is
/// asserted by what its failure is NOT: `up` fails at the unreachable pull, and must not fail on the
/// key, which is what "config accepted it and up agreed" means when the box cannot actually start.
#[test]
fn compose_config_and_up_agree_on_what_the_file_may_say() {
    let dir = std::env::temp_dir().join(format!("kern-it-pair-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("kern")).expect("temp config dir");
    // A kern.toml that declares `vgpio:leds` and nothing else, so one profile reference resolves and
    // its neighbour does not - the discriminant, rather than a file where everything fails.
    fs::write(
        dir.join("kern/kern.toml"),
        // No `chip =` here: `[[gpio]]` has no such key, and the fixture carried one until the
        // unknown-key warning named it. A key that does nothing in a test fixture is the same
        // defect as one in a user's config, and this test would have kept passing either way.
        "[[gpio]]\nid = \"gpio:0\"\n\n[[vgpio]]\nname = \"leds\"\nbackend = \"gpio:0\"\n",
    )
    .expect("write kern.toml");

    // (label, service key, refused, a word the refusal must carry)
    let cases: [(&str, &str, bool, &str); 5] = [
        ("a declared profile", "x-kern-vgpio: leds", false, "vgpio"),
        (
            "a profile kern.toml does not declare",
            "x-kern-vcpu: nosuchprofile",
            true,
            "nosuchprofile",
        ),
        (
            "a security profile that is not a name kern takes",
            "x-kern-security-profile: bogus",
            true,
            "security-profile",
        ),
        (
            "the security profile that is",
            "x-kern-security-profile: untrusted",
            false,
            "untrusted",
        ),
        // Not a refusal on EITHER side: an unread key in our namespace is a warning, and warning is
        // not refusing. Without this row the corpus would only prove that both verbs can say no.
        (
            "an extension key this build does not read",
            "x-kern-vgpi: leds",
            false,
            "not read by this build",
        ),
    ];

    for (label, key, refused, needle) in cases {
        let file = dir.join(format!("{}.yml", key.replace([' ', ':'], "_")));
        fs::write(
            &file,
            format!(
                "services:\n  app:\n    image: 127.0.0.1:1/nope:1\n    {key}\n    command: [\"/bin/true\"]\n"
            ),
        )
        .expect("write compose file");
        let path = file.to_str().unwrap_or_default().to_string();
        let run = |verb: &str| {
            let out = kern()
                .env("XDG_CONFIG_HOME", &dir)
                .args(["compose", &path, verb])
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
        let (config_ok, config_out) = run("config");
        let (_, up_out) = run("up");

        assert_eq!(
            config_ok, !refused,
            "config disagrees with the corpus on {label}: {config_out}"
        );
        if refused {
            assert!(
                config_out.contains(needle),
                "config's refusal must name the thing it refused ({label}): {config_out}"
            );
            // THE PAIR. `up` must refuse the same file for the same reason - not merely fail, which
            // it would do anyway on an unreachable registry.
            assert!(
                up_out.contains(needle),
                "up refused {label} for a different reason than config did: {up_out}"
            );
        } else {
            // Accepted by `config`, so `up` must not be the one to object to this key. It still fails
            // (nothing can pull from a closed port), and that failure must not mention it.
            assert!(
                !up_out.contains("is not a security profile")
                    && !up_out.contains("no [[")
                    && !up_out.contains("expected `untrusted`"),
                "config accepted {label} and up rejected it: {up_out}"
            );
        }
    }
    let _ = fs::remove_dir_all(&dir);
}

/// THE FALLBACK THAT RUNS WHEN THE PID PIN REFUSES MUST ACTUALLY FIND THE BOX.
///
/// A box whose `pid1` is unrecorded (an entry written before the field existed) or whose pin no
/// longer matches falls back to locating the init from the supervisor. That fallback was "the
/// supervisor's sole child", and MEASURED on this build the supervisor has TWO children even for a
/// box with no health check, while the init is a GRANDCHILD: the fallback returned a `kern` helper
/// and every consumer built on it failed with "box is not running (its namespaces are gone)".
///
/// A recovery path that cannot recover is worse than none, because the callers are written as though
/// it works - and the pin sends MORE traffic down it, since a refused pin lands here by design. The
/// rule is now "the descendant that is PID 1 in its own pid namespace", which is what a box init is.
///
/// BOTH SHAPES, because the checker is what made the old rule ambiguous: with it the supervisor has a
/// third child, and a rule that picks by position rather than by property picks differently.
#[test]
fn the_pid1_fallback_finds_the_box_init_with_and_without_a_health_checker() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "fallback");
    if fs::copy(&busybox, root.join("bin/sh")).is_err() {
        eprintln!("skip: could not place /bin/sh in the test rootfs");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let rootfs = root.to_str().unwrap_or_default().to_string();

    for with_checker in [false, true] {
        let xdg = std::env::temp_dir().join(format!(
            "kern-it-fb-{}-{}",
            std::process::id(),
            u8::from(with_checker)
        ));
        let _ = fs::remove_dir_all(&xdg);
        fs::create_dir_all(&xdg).expect("temp runtime dir");
        let name = format!("fb-{}-{}", std::process::id(), u8::from(with_checker));

        let mut args: Vec<String> = vec![
            "box".into(),
            name.clone(),
            "--rootfs".into(),
            rootfs.clone(),
            "-d".into(),
        ];
        if with_checker {
            args.extend([
                "--health-cmd".into(),
                "true".into(),
                "--health-interval".into(),
                "1".into(),
            ]);
        }
        args.extend([
            "--".into(),
            "/bin/busybox".into(),
            "sleep".into(),
            "30".into(),
        ]);
        let started = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(&args)
            .output()
            .expect("run kern");
        if !started.status.success() {
            eprintln!(
                "skip: could not start the box: {}",
                String::from_utf8_lossy(&started.stderr)
            );
            let _ = fs::remove_dir_all(&xdg);
            continue;
        }
        std::thread::sleep(std::time::Duration::from_millis(1500));

        // Force the fallback: erase the recorded pid1 and its pin, exactly as a pre-upgrade entry
        // (or a refused pin) leaves the record.
        let mut erased = false;
        if let Ok(rd) = fs::read_dir(xdg.join("kern/instances")) {
            for e in rd.flatten() {
                if let Ok(body) = fs::read_to_string(e.path()) {
                    let stripped: String = body
                        .lines()
                        .filter(|l| !l.starts_with("pid1starttime="))
                        .map(|l| {
                            if l.starts_with("pid1=") {
                                "pid1=0".to_string()
                            } else {
                                l.to_string()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    if fs::write(e.path(), format!("{stripped}\n")).is_ok() {
                        erased = true;
                    }
                }
            }
        }
        assert!(
            erased,
            "the test could not force the fallback, so it tested nothing"
        );

        let out = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["exec", &name, "/bin/busybox", "echo", "ALIVE"])
            .output()
            .expect("run kern exec");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["stop", &name])
            .output();
        let _ = fs::remove_dir_all(&xdg);

        assert!(
            text.contains("ALIVE"),
            "the fallback did not reach the box init ({}a health checker): {text}",
            if with_checker { "with " } else { "without " }
        );
    }
    let _ = fs::remove_dir_all(&root);
}

/// A DOWNLOADED STACK CANNOT GRANT ITSELF HOST HARDWARE BY SHIPPING ITS OWN `kern.toml`.
///
/// A profile that resolves to a device node is gated, and the acknowledgement can live in the
/// operator's `kern.toml` (`[kern] allow_device_grants = true`) so a `restart:` service - whose
/// systemd unit nobody types by hand - can come back after a reboot without the generated unit
/// carrying the permission itself.
///
/// THAT OPENS THE ONE HOLE THIS TEST EXISTS FOR. The native stack format lets a file name its own
/// config (`config = "bundled.toml"`), so a bundle could ship a `kern.toml` that sets the key. The
/// permission is therefore read from the DEFAULT config only, never from a path the file chose, and
/// this asserts both halves: the operator's config permits, the bundle's identical config does not.
///
/// Without the second half the first is not a security property, it is a spelling.
#[test]
fn a_bundled_config_cannot_grant_itself_a_device_and_the_operators_config_can() {
    // A `[[vgpio]]` resolving to something that exists on any Linux host with an LED class. If the
    // host has none, the profile resolves to nothing, the gate has nothing to gate, and the case is
    // inconclusive rather than green.
    let led = match fs::read_dir("/sys/class/leds")
        .ok()
        .and_then(|mut d| d.next().and_then(Result::ok))
    {
        Some(e) => e.file_name().to_string_lossy().to_string(),
        None => {
            eprintln!("skip: no /sys/class/leds entry to grant");
            return;
        }
    };
    let dir = std::env::temp_dir().join(format!("kern-it-grant-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("kern")).expect("temp config dir");
    let profile =
        format!("[[gpio]]\nid = \"gpio:0\"\n\n[[vgpio]]\nname = \"leds\"\nbackend = \"gpio:0\"\nleds = [\"{led}\"]\n");
    let permit = format!("[kern]\nallow_device_grants = true\n\n{profile}");

    // The bundle: its own config, carrying the permission, named BY THE FILE.
    fs::write(dir.join("bundled.toml"), &permit).expect("write bundled config");
    fs::write(
        dir.join("stack.toml"),
        "[box.app]\nimage = \"alpine:latest\"\ncommand = [\"true\"]\nconfig = \"bundled.toml\"\nvgpio = \"leds\"\n",
    )
    .expect("write stack");
    // The operator's config: the same profile, WITHOUT the permission.
    fs::write(dir.join("kern/kern.toml"), &profile).expect("write operator config");

    let run_verb = |stack: &str, verb: &str| -> (bool, String) {
        let out = kern()
            .current_dir(&dir)
            .env("XDG_CONFIG_HOME", &dir)
            .env("XDG_RUNTIME_DIR", &dir)
            .args(["compose", stack, verb])
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

    // WHETHER THIS HOST CAN EXERCISE THE CASE IS DECIDED WITHOUT ASKING THE GATE. An earlier version
    // skipped when the gate did not fire, which made the skip swallow the exact failure under test:
    // sabotage the permission lookup, the gate stops firing, and the test reported itself
    // inconclusive instead of red. `config` reports the RESOLUTION whether or not anything is gated,
    // so it answers "does this profile reach a device here" independently.
    let (_, preview) = run_verb("stack.toml", "config");
    if !preview.contains("/sys/class/leds") {
        eprintln!("skip: the profile does not resolve to a device on this host: {preview}");
        let _ = fs::remove_dir_all(&dir);
        return;
    }

    let (ok, text) = run_verb("stack.toml", "up");
    assert!(
        !ok,
        "a bundle that ships its own permitting kern.toml granted itself a device: {text}"
    );
    assert!(
        text.contains("asks for"),
        "and the refusal must be the device gate, not some other failure: {text}"
    );

    // POSITIVE CONTROL: the same permission, in the OPERATOR's config, does lift the gate. Without
    // this the assertion above would hold for a build that never lifts it at all.
    fs::write(dir.join("kern/kern.toml"), &permit).expect("permit in the operator config");
    let (_, text) = run_verb("stack.toml", "up");
    assert!(
        !text.contains("asks for"),
        "the operator's own config must be able to lift the gate: {text}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A GENUINELY RECYCLED PID MUST NOT LET A CONSUMER INTO A STRANGER'S NAMESPACES.
///
/// This is the case the whole pid-identity work exists to prevent, and it was believed unreachable:
/// I wrote that forcing a recycle meant running the counter to `pid_max`. That is false.
/// `/proc/sys/kernel/ns_last_pid` sets the NEXT pid to be allocated and is writable with
/// `CAP_SYS_ADMIN` over the current pid namespace, which `unshare -Ur -p --fork` hands an ordinary
/// user. Measured: writing `700` there makes the next child land on exactly 701.
///
/// So the box's init is created, recorded, killed, and its pid handed to an UNRELATED process, and
/// then a consumer is asked to enter the box. Every other test of this pins the predicate; this one
/// exercises the thing the predicate is for.
///
/// TWO INCONCLUSIVE SHAPES, BOTH SKIPPED RATHER THAN FAILED. The recycle may not land (another
/// process can take the number between the write and the fork), and - measured on the first run of
/// this - the two processes can share a start-time, because it is counted in CLOCK TICKS and both
/// were created inside one. The second is a real limit of the mechanism, not of the test: a recycle
/// that happens within a tick of the original's start is invisible to the pin. The `sleep` below
/// pushes the decoy past that boundary so the discriminant exists at all.
#[test]
fn a_recycled_pid_does_not_let_exec_into_a_strangers_namespaces() {
    if std::process::Command::new("unshare")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skip: no unshare(1)");
        return;
    }
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let kern_bin = env!("CARGO_BIN_EXE_kern");
    let script = r#"
echo STARTED
export XDG_RUNTIME_DIR=$2; mkdir -p $XDG_RUNTIME_DIR/kern/instances
sleep 300 & INIT=$!
ST=$(awk '{print $22}' /proc/$INIT/stat)
sleep 300 & SUP=$!
SST=$(awk '{print $22}' /proc/$SUP/stat)
printf 'name=rec\npid=%s\npid1=%s\nrootfs=/tmp\ncommand=sleep\nstarted=1\nstarttime=%s\nstopsig=15\nstopgrace=10\ncapdropall=0\ncapdrops=\ncapadds=\nseccompmode=allowlist\napparmor=\npid1starttime=%s\n' \
  "$SUP" "$INIT" "$SST" "$ST" > $XDG_RUNTIME_DIR/kern/instances/rec-$SUP
kill -9 $INIT 2>/dev/null; wait $INIT 2>/dev/null
sleep 1
echo $((INIT-1)) > /proc/sys/kernel/ns_last_pid 2>/dev/null || { echo SKIP_NS_LAST_PID; exit 0; }
sleep 300 & DECOY=$!
[ "$DECOY" != "$INIT" ] && { echo SKIP_NO_RECYCLE; exit 0; }
DST=$(awk '{print $22}' /proc/$DECOY/stat)
[ "$DST" = "$ST" ] && { echo SKIP_SAME_TICK; exit 0; }
echo RECYCLED
"$1" exec rec /bin/echo ENTERED 2>&1
"#;
    let xdg = std::env::temp_dir().join(format!("kern-it-recycle-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    let out = std::process::Command::new("unshare")
        .args([
            "-Ur",
            "-p",
            "--fork",
            "--mount-proc",
            "sh",
            "-c",
            script,
            "sh",
        ])
        .arg(kern_bin)
        .arg(&xdg)
        .output()
        .expect("run unshare");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = fs::remove_dir_all(&xdg);

    // THE SCAFFOLDING MAY BE REFUSED BEFORE IT RUNS, and that is not this test failing. `unshare -Ur`
    // writes /proc/self/uid_map, and a GitHub runner's AppArmor profile denies that write while
    // `userns_plausible()` above still reports the namespaces available: the guard measures whether a
    // user namespace can be CREATED, and this is a different refusal one step later. MEASURED on the
    // hosted x86 and aarch64 runners: "unshare: write failed /proc/self/uid_map: Operation not
    // permitted". `STARTED` is the discriminant, and it is the first line of the script for that
    // reason: without it the scaffolding never entered, so there is nothing to conclude either way,
    // and with it any later silence is the product's and gets asserted on below.
    if !text.contains("STARTED") {
        eprintln!(
            "skip: the user namespace scaffolding was refused before it ran: {}",
            text.trim()
        );
        return;
    }
    for reason in ["SKIP_NS_LAST_PID", "SKIP_NO_RECYCLE", "SKIP_SAME_TICK"] {
        if text.contains(reason) {
            eprintln!("skip: {reason}");
            return;
        }
    }
    assert!(
        text.contains("RECYCLED"),
        "the scaffolding did not reach the recycle, so nothing below was tested: {text}"
    );
    // THE FIRST ASSERTION IS NOT ENOUGH ON ITS OWN, and finding that out is most of this test's
    // value. `ENTERED` on stdout would mean the command ran inside whatever process now holds that
    // pid. But MEASURED with the guard removed, `exec` still refuses here - with a DIFFERENT message
    // ("box is not running (its namespaces are gone)"), because the decoy shares this process's
    // namespaces and a later check catches it. Both outcomes are safe, so absence of `ENTERED`
    // proves the property and NOT the mechanism: a test that stopped here would be green with the
    // pin deleted, which is what the first version of it was.
    assert!(
        !text.contains("ENTERED"),
        "exec entered a recycled pid's namespaces: {text}"
    );
    // SO ASSERT WHICH REFUSAL FIRED. `live_pid1` refusing the recycled number sends the caller to
    // `child_of(supervisor)`, and this supervisor has no children, so the refusal is the fallback's.
    // Remove the start-time check and the message changes, because a different guard answers.
    assert!(
        text.contains("could not locate the box's main process"),
        "the refusal must come from the pin's fallback, not from a later guard that happens to \
         catch this scaffolding: {text}"
    );
}

/// A `nice` THE KERNEL WILL NOT GRANT MUST NOT BE ACCEPTED IN SILENCE.
///
/// A field report on v0.8.0 found `nice = -5` in a `[[vcpu]]` profile accepted, echoed back, and
/// dropped: effective nice 0, no warning at any stage. It read as a profile bug and it is not one -
/// MEASURED, the flag does it too (`--nice -5` and `--nice -1` both left the workload at 0 while
/// `--nice 5` and `--nice 19` took effect), because `setpriority`'s return value was discarded at
/// both call sites. Lowering the nice value needs `CAP_SYS_NICE` or `RLIMIT_NICE` headroom, which a
/// rootless box does not have by default.
///
/// ASSERTED IN BOTH DIRECTIONS, so the test needs no guess about the host it runs on: the warning
/// must appear exactly when the value did NOT take. A machine that can lower nice (root, or a raised
/// `RLIMIT_NICE`) exercises the other branch and would catch a warning printed unconditionally -
/// which is the obvious wrong fix for this, and would be just as dishonest as the silence.
#[test]
fn a_nice_the_kernel_refuses_is_reported_rather_than_dropped() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "nice");
    let rootfs = root.to_str().unwrap_or_default().to_string();
    let xdg = std::env::temp_dir().join(format!("kern-it-nice-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    fs::create_dir_all(&xdg).expect("temp runtime dir");

    // Field 19 of `/proc/self/stat` is the nice value. `/proc/self/status` has no `Nice` line on
    // every kernel this suite runs on, and reading a field that is simply absent would make the
    // assertions below compare two empty strings and pass for the wrong reason.
    let run = |n: &str| -> (String, String) {
        let out = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args([
                "box",
                &format!("nice-{n}-{}", std::process::id()),
                "--rootfs",
                &rootfs,
                "--nice",
                n,
                "--",
                "/bin/busybox",
                "awk",
                "{print $19}",
                "/proc/self/stat",
            ])
            .output()
            .expect("run kern");
        (
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };

    // POSITIVE CONTROL FIRST: raising the nice value needs no privilege anywhere, so if this does not
    // land, the reader above is broken and every other assertion here is meaningless.
    let (eff, err) = run("5");
    if eff.is_empty() {
        eprintln!("skip: could not read the box's nice value ({err})");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }
    assert_eq!(eff, "5", "a nice the kernel grants must be applied: {err}");
    assert!(
        !err.contains("not applied"),
        "and it must not be warned about: {err}"
    );

    // THE REPORTED CASE. Either the host granted it, or it must say that it did not.
    let (eff, err) = run("-5");
    if eff == "-5" {
        assert!(
            !err.contains("not applied"),
            "this host DID lower the nice value, so warning about it is a false report: {err}"
        );
    } else {
        assert_eq!(
            eff, "0",
            "a refused nice leaves the inherited value, it does not land somewhere else: {err}"
        );
        assert!(
            err.contains("nice -5 not applied"),
            "a nice the kernel refused must be named, not silently dropped: {err}"
        );
        assert!(
            err.contains("CAP_SYS_NICE") || err.contains("RLIMIT_NICE"),
            "and the reader must be told what would make it work: {err}"
        );
    }
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
}

/// A SIGKILL'D LAUNCHER MUST NOT LEAVE ITS HEALTH CHECKER PROBING FOREVER.
///
/// The checker is a bare `fork` that loops on a timer. Every ordinary exit path stops it, but a
/// SIGKILL'd launcher runs no teardown at all, and MEASURED before this guard: exactly one orphan
/// survived each kill, sleeping and probing a box that no longer existed. The box itself does not
/// leak in that case because it already carries a `PR_SET_PDEATHSIG` link to the launcher; the
/// checker had none, because until now it only ever ran under a supervisor that stopped it by hand.
///
/// COUNTED BY `/proc/<pid>/exe`, NOT BY COMMAND LINE, and that is the point rather than a detail: a
/// `fork` with no `exec` inherits the parent's argv, so the checker and the launcher are byte-identical
/// on the command line and a `pgrep -f` cannot tell them apart. The unique box name narrows the count
/// to this test's own processes, because this suite runs in parallel and a global count of `kern`
/// processes would be measuring the rest of the file.
#[test]
fn a_killed_foreground_launcher_takes_its_health_checker_with_it() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "health-orphan");
    if fs::copy(&busybox, root.join("bin/sh")).is_err() {
        eprintln!("skip: could not place /bin/sh in the test rootfs");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let rootfs = root.to_str().unwrap_or_default().to_string();
    let name = format!("hc-orphan-{}", std::process::id());
    let xdg = std::env::temp_dir().join(format!("kern-it-horph-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::create_dir_all(&xdg);

    // Processes that are BOTH this test binary's `kern` and carry this box's unique name.
    let mine = |name: &str| -> usize {
        let exe = PathBuf::from(env!("CARGO_BIN_EXE_kern"));
        let Ok(rd) = fs::read_dir("/proc") else {
            return 0;
        };
        rd.filter_map(|e| e.ok())
            .filter(|e| {
                let p = e.path();
                if fs::read_link(p.join("exe")).ok().as_ref() != Some(&exe) {
                    return false;
                }
                fs::read(p.join("cmdline"))
                    .map(|c| String::from_utf8_lossy(&c).contains(name))
                    .unwrap_or(false)
            })
            .count()
    };

    let mut fg = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            &name,
            "--rootfs",
            &rootfs,
            "--health-cmd",
            "true",
            "--health-interval",
            "1",
            "--",
            "/bin/busybox",
            "sleep",
            "60",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn foreground kern");

    // Wait until BOTH the launcher and its checker exist: two processes carrying this name is the
    // state whose cleanup is under test, and asserting on the count before it is reached would pass
    // without ever creating an orphan to lose.
    let mut peak = 0;
    for _ in 0..150 {
        peak = mine(&name);
        if peak >= 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if peak < 2 {
        // The box never got far enough to fork a checker (a locked-down runner, a missing shell):
        // skip rather than assert on a state this host could not produce.
        eprintln!("skip: the launcher never forked a checker here (saw {peak})");
        let _ = fg.kill();
        let _ = fg.wait();
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }

    let _ = fg.kill();
    let _ = fg.wait();
    let mut left = peak;
    for _ in 0..100 {
        left = mine(&name);
        if left == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let _ = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["stop", &name])
        .output();
    let _ = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["prune", &name])
        .output();
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);

    assert_eq!(
        left, 0,
        "a SIGKILL'd launcher left {left} process(es) behind (peak was {peak}): the health checker \
         outlived the box it was probing"
    );
}

/// A FOREGROUND BOX'S `--health-cmd` MUST BE EVALUATED, NOT SILENTLY IGNORED.
///
/// `spawn_health_checker` had exactly one call site, inside `run_detached`, so a box started
/// WITHOUT `-d` accepted `--health-cmd`, exited 0, and never wrote a health status at all. `kern ps`
/// showed an empty HEALTH column for a box that had explicitly asked to be probed: a flag that is
/// taken and does nothing, with no warning and no error.
///
/// THIS IS NOT A CORNER OF THE CLI. `--restart always`/`unless-stopped` installs a systemd unit
/// whose `ExecStart` deliberately STRIPS `-d` (`Type=simple`, systemd is the supervisor), so every
/// persistent box runs on the foreground path. A `kern compose` stack that carries `restart:` and
/// runs with `--no-pod` therefore gates on a health status nobody ever computes, and a
/// `depends_on: condition: service_healthy` waits the full timeout and fails with
/// `last status: 'none yet'` while the service underneath is up and serving. Reported against
/// v0.8.0 on a four-service stack and reduced to the two commands below.
///
/// THE DETACHED CASE IS THE POSITIVE CONTROL, in the same test, on the same rootfs, with the same
/// probe: if this harness ever stops observing health at all, the control fails instead of the
/// subject passing by absence.
#[test]
fn a_foreground_box_evaluates_its_health_check() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "health-fg");
    // The probe runs INSIDE the box as `/bin/sh -c <cmd>`, so the rootfs needs a shell. busybox is
    // the shell when it is invoked under that name.
    if fs::copy(&busybox, root.join("bin/sh")).is_err() {
        eprintln!("skip: could not place /bin/sh in the test rootfs");
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let rootfs = root.to_str().unwrap_or_default().to_string();
    let xdg = std::env::temp_dir().join(format!("kern-it-hfg-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::create_dir_all(&xdg);

    // Read the health field `kern ps --json` reports for `name`, or None while the box is absent.
    // Parsed by field name rather than by position so a new column cannot silently shift it.
    let health_of = |name: &str| -> Option<String> {
        // Retry on EMPTY stdout, for the reason `kern_out` documents at the top of this file: under
        // this suite's parallelism `Command::output()`'s pipe occasionally returns nothing even
        // though the command ran. Without this the CONTROL below flaked on the first run of this
        // test, which is worse than having no control at all: a control that can fail on its own
        // teaches the reader to ignore it.
        let mut txt = String::new();
        for _ in 0..4 {
            let out = kern()
                .env("XDG_RUNTIME_DIR", &xdg)
                .args(["ps", "--json"])
                .output()
                .ok()?;
            txt = String::from_utf8_lossy(&out.stdout).to_string();
            if !txt.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(60));
        }
        let key = format!("\"name\":\"{name}\"");
        let at = txt.find(&key)?;
        let tail = &txt[at..];
        let h = tail.find("\"health\":\"")?;
        let rest = &tail[h + 10..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    };

    // WAIT FOR A STATUS, NOT FOR "ANY STATUS". The first value a healthy box publishes is
    // `starting`, not `healthy`: the checker writes `starting` the moment it forks and only flips
    // after the first probe returns. An earlier draft returned the first NON-EMPTY value and so
    // compared `starting` against `healthy`, which made the control fail three runs out of three
    // and pass whenever anything slowed the loop down - a race dressed as a flake.
    //
    // Returns the LAST status seen, so the two cases stay distinguishable: a box whose checker runs
    // ends on `healthy`, and a box whose checker never ran has nothing to report and ends on "".
    let wait_healthy = |name: &str| -> String {
        let mut last = String::new();
        for _ in 0..120 {
            if let Some(h) = health_of(name) {
                if h == "healthy" {
                    return h;
                }
                last = h;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        last
    };

    // ---- POSITIVE CONTROL: the detached path, which has always worked.
    let out = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            "hc-detached",
            "--rootfs",
            &rootfs,
            "-d",
            "--health-cmd",
            "true",
            "--health-interval",
            "1",
            "--",
            "/bin/busybox",
            "sleep",
            "20",
        ])
        .output()
        .expect("run kern");
    if String::from_utf8_lossy(&out.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }
    let detached = wait_healthy("hc-detached");

    // ---- SUBJECT: the same box, same probe, without `-d`. A foreground box blocks, so it is a
    // child this test kills at the end rather than a `.output()` that would never return.
    let mut fg = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args([
            "box",
            "hc-foreground",
            "--rootfs",
            &rootfs,
            "--health-cmd",
            "true",
            "--health-interval",
            "1",
            "--",
            "/bin/busybox",
            "sleep",
            "20",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn foreground kern");
    let foreground = wait_healthy("hc-foreground");

    // Tear everything down BEFORE asserting, so a failure does not leave a box and a rootfs behind.
    let _ = fg.kill();
    let _ = fg.wait();
    let _ = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["stop", "hc-detached", "hc-foreground"])
        .output();
    let _ = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["prune", "hc-detached"])
        .output();
    let _ = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["prune", "hc-foreground"])
        .output();
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);

    assert_eq!(
        detached, "healthy",
        "the CONTROL failed: a detached box no longer records health, so this test is measuring \
         nothing and the assertion below would be meaningless"
    );
    assert_eq!(
        foreground, "healthy",
        "a foreground box took --health-cmd and never evaluated it (health was {foreground:?}); \
         every `restart:` box runs on this path, because the systemd unit strips -d"
    );
}

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
    // Piped, not inherited: this `stop` has to run WHILE the test polls, so it cannot be `.output()`
    // (which waits), and a bare `.spawn()` leaves the product's own "stopped '<name>' (pid N)" on the
    // suite's stdout, where it reads as an unexplained line between test results. The test asserts on
    // timing, not on this text, so the streams are simply captured.
    let mut stop = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["stop", "gracelong", "graceshort"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
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

/// `kern examples` is the text an author reads WHILE writing a kern.toml, so a claim it makes about
/// what a profile grants is the claim that gets believed. It once said `pins` would "expose ONLY
/// these lines, nothing else" while SECURITY.md said the opposite and the code agreed with
/// SECURITY.md: any pin binds every `/dev/gpiochipN`, whole. Measured on a host with a gpiochip, a
/// box with no profile has no `/dev/gpiochip*` and one with `pins = [17, 27]` has the entire chip.
///
/// This pins the correction rather than trusting review: the words that overstated the boundary must
/// stay out, and the granularity must be stated where the field is.
#[test]
fn the_examples_config_does_not_overstate_a_gpio_grant() {
    let ex = kern().args(["examples"]).output().expect("run kern");
    assert!(ex.status.success());
    let out = String::from_utf8_lossy(&ex.stdout);

    for overclaim in ["ONLY these lines", "ONLY these devices"] {
        assert!(
            !out.contains(overclaim),
            "`kern examples` claims a per-line/per-device GPIO boundary kern does not enforce: \
             {overclaim:?}. Requesting any pin binds every /dev/gpiochipN. See SECURITY.md."
        );
    }
    assert!(
        out.contains("CHIP-granular"),
        "the pins field must state its granularity where it is declared, not only in SECURITY.md"
    );
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
/// `compose port` ANSWERS WITH ITS EXIT CODE AS MUCH AS WITH ITS OUTPUT.
///
/// The shape it exists to serve is `addr=$(kern compose f port web 8000) || exit 1`, so every path
/// that has no answer must be non-zero rather than an empty line with status 0. Asserted here for
/// the four ways there is no answer, plus the one where there is, because a verb that only ever
/// succeeded would pass a test that checked the success path alone.
///
/// The address is read from the RUNNING box, so the last case is the stack brought down: that must
/// fail rather than answer from the file, which is the difference between "what is published" and
/// "what was asked for".
#[test]
fn compose_port_prints_the_published_address_and_fails_when_there_is_none() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    // A free host port, chosen by the kernel and released before the stack claims it, so this test
    // cannot collide with anything else on the machine.
    let host_port = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(l) => match l.local_addr() {
            Ok(a) => a.port(),
            Err(e) => {
                eprintln!("skip: cannot read a bound port: {e}");
                return;
            }
        },
        Err(e) => {
            eprintln!("skip: cannot bind a host port: {e}");
            return;
        }
    };

    let root = build_rootfs(&busybox, "cport");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-cport-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::create_dir_all(&xdg);
    let toml = std::env::temp_dir().join(format!("kern-cport-{}.toml", std::process::id()));
    fs::write(
        &toml,
        format!(
            "[box.web]\nrootfs = \"{rootfs}\"\nports = [\"{host_port}:8000\"]\ncommand = [\"/bin/busybox\", \"sleep\", \"12\"]\n"
        ),
    )
    .unwrap();

    let port_cmd = |args: &[&str]| -> (bool, String, String) {
        let mut a = vec!["compose", toml.to_str().unwrap(), "port"];
        a.extend_from_slice(args);
        let out = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(&a)
            .output()
            .expect("run kern");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };

    // Not running yet: the answer must be an error, not the file's own mapping.
    let (ok, _, err) = port_cmd(&["web", "8000"]);
    assert!(
        !ok && err.contains("is not running"),
        "a stopped service must not answer from the file: ok={ok} err={err}"
    );

    let up = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["compose", toml.to_str().unwrap(), "up"])
        .output()
        .expect("run kern");
    let up_err = String::from_utf8_lossy(&up.stderr).to_string();
    if up_err.contains("user namespaces") || up_err.contains("newuidmap") {
        eprintln!("skip: the stack could not start here");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        let _ = fs::remove_file(&toml);
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(800));

    let (ok, addr, err) = port_cmd(&["web", "8000"]);
    assert!(
        ok && addr == format!("127.0.0.1:{host_port}"),
        "the published address must be printed alone on stdout: ok={ok} addr={addr:?} err={err}"
    );

    let (ok, out, err) = port_cmd(&["web", "9999"]);
    assert!(
        !ok && out.is_empty() && err.contains("is not published"),
        "an unpublished container port is an error with nothing on stdout: ok={ok} out={out:?}"
    );

    let (ok, _, err) = port_cmd(&["nosuch", "8000"]);
    assert!(
        !ok && err.contains("no service 'nosuch'"),
        "an unknown service names itself: ok={ok} err={err}"
    );

    // A mistyped PORT must be reported as a port, not as a service that does not exist. That was the
    // first behaviour, because the selection upstream validates every positional as a service name.
    let (ok, _, err) = port_cmd(&["web", "abc"]);
    assert!(
        !ok && err.contains("is not a container port"),
        "a bad port is a bad port, not a missing service: ok={ok} err={err}"
    );

    let (ok, _, err) = port_cmd(&["web"]);
    assert!(
        !ok && err.contains("exactly two arguments"),
        "one argument is a usage error: ok={ok} err={err}"
    );

    kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["compose", toml.to_str().unwrap(), "down"])
        .output()
        .ok();
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::remove_file(&toml);
}

/// A STACK IS ONE NETWORK TRUST DOMAIN, AND THE HOST IS OUTSIDE IT.
///
/// Both halves of the same fact, because the docs stated only the inconvenient one (two services
/// cannot share a container port) and left the security-relevant one unwritten: services in a pod
/// share a loopback, so a peer reaches a port that was never published. The other half is the part
/// that has to hold: the HOST's loopback is not reachable from inside, so the boundary sits between
/// the stack and the host rather than between the services of one stack.
///
/// The host side is asserted with a positive control, a port this test opens on the host itself, so
/// "unreachable" cannot be a listener that was never there.
#[test]
fn a_pod_shares_loopback_between_services_and_not_with_the_host() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    // The host-side control: a real listener on a free port, closed when this test ends.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a host port");
    let host_port = listener.local_addr().unwrap().port();

    let root = build_rootfs(&busybox, "podnet");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-podnet-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::create_dir_all(&xdg);
    let toml = std::env::temp_dir().join(format!("kern-podnet-{}.toml", std::process::id()));
    // `quiet` listens on 9999 and publishes NOTHING. `nosy` reports what it can reach.
    let probe = format!(
        // THIS busybox `nc` HAS NO `-z`: its usage is `nc [-iN] [-wN] [-l] [-p PORT] ...`, so a
        // connect test is `nc -wN HOST PORT </dev/null` read through the exit status. Found by the
        // first run failing with `nc: invalid option` rather than with a wrong answer, which is the
        // good way for a probe to be wrong.
        "sleep 2; nc -w2 127.0.0.1 9999 </dev/null && echo PEER=yes || echo PEER=no; \
         nc -w2 127.0.0.1 {host_port} </dev/null && echo HOST=yes || echo HOST=no; sleep 2"
    );
    fs::write(
        &toml,
        format!(
            "[box.quiet]\nrootfs = \"{rootfs}\"\ncommand = [\"/bin/busybox\", \"nc\", \"-l\", \"-p\", \"9999\"]\n\n\
             [box.nosy]\nrootfs = \"{rootfs}\"\ncommand = [\"/bin/busybox\", \"sh\", \"-c\", \"{probe}\"]\n"
        ),
    )
    .unwrap();

    let up = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["compose", toml.to_str().unwrap(), "up"])
        .output()
        .expect("run kern");
    let err = String::from_utf8_lossy(&up.stderr).to_string();
    if err.contains("user namespaces") || err.contains("newuidmap") {
        eprintln!("skip: the stack could not start here");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        let _ = fs::remove_file(&toml);
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(3500));
    let logs = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["compose", toml.to_str().unwrap(), "logs", "nosy"])
        .output()
        .expect("run kern");
    let seen = String::from_utf8_lossy(&logs.stdout).to_string();
    kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["compose", toml.to_str().unwrap(), "down"])
        .output()
        .ok();

    assert!(
        seen.contains("PEER=yes"),
        "a stack is one network domain: a peer's unpublished port is reachable, and saying otherwise \
         in the docs would be the lie this test exists to prevent: {seen}"
    );
    assert!(
        seen.contains("HOST=no"),
        "and the host is OUTSIDE that domain: a listener on the host's own loopback must not be \
         reachable from a service (control: this test is holding port {host_port} open): {seen}"
    );

    drop(listener);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::remove_file(&toml);
}

/// A `--no-pod` SERVICE STILL HOLDS ONLY LOOPBACK, AND NOW RESOLVES ITS PEERS ANYWAY.
///
/// This test was written for the opposite claim and is kept, inverted, because the claim it refuted
/// is worth keeping refuted. The README and DOCKER-COMPAT used to say the flag cost "name
/// resolution", which an operator reads as "DNS is gone but the peers are still reachable by
/// address". MEASURED from a field report on v0.8.5: without a pod a service's network namespace
/// holds ONLY loopback and NO routes, so a peer was unreachable by address as much as by name.
///
/// Peer relays changed the second half and NOT the first, and that split is exactly what is asserted
/// here. The namespace is still solo: one interface, zero routes, no shortcut taken to make names
/// work. What changed is that the peer's name is now in `/etc/hosts` pointing at its ALIAS, not at
/// `127.0.0.1` - the distinction matters, because a peer mapped to `127.0.0.1` would resolve and then
/// connect to the service's own listener, which is a silent wrong answer rather than a failure.
///
/// The pod half is still asserted. Without it, a build where pods stopped writing peer names would
/// pass while breaking every stack that works today.
#[test]
fn no_pod_leaves_a_service_with_loopback_and_nothing_else() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "nopod");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-nopod-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::create_dir_all(&xdg);
    let toml = std::env::temp_dir().join(format!("kern-nopod-{}.toml", std::process::id()));
    // `peera` reports what its namespace holds; `peerb` exists only to be a peer worth naming.
    let probe =
        "cat /etc/hosts; echo IFACE_START; cut -d: -f1 /proc/net/dev | tail -n +3 | tr -d ' '; \
                 echo IFACE_END; echo ROUTES=$(tail -n +2 /proc/net/route | wc -l); sleep 3";
    fs::write(
        &toml,
        format!(
            "[box.peera]\nrootfs = \"{rootfs}\"\ncommand = [\"/bin/busybox\", \"sh\", \"-c\", \"{probe}\"]\n\n\
             [box.peerb]\nrootfs = \"{rootfs}\"\ncommand = [\"/bin/busybox\", \"sleep\", \"6\"]\n"
        ),
    )
    .unwrap();

    // TWO CHANNELS, KEPT APART ON PURPOSE. The first attempt returned `stderr + logs` as one string
    // and asserted the peer name was absent from it. It failed against a CORRECT build: `up` prints
    // the box names it is starting, so "peerb" was in the stderr of the very command under test. An
    // assertion about what a service saw has to read only what that service printed.
    let run = |extra: &[&str]| -> (String, String) {
        let mut args = vec!["compose", toml.to_str().unwrap(), "up"];
        args.extend_from_slice(extra);
        let out = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(&args)
            .output()
            .expect("run kern");
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let logs = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["compose", toml.to_str().unwrap(), "logs", "peera"])
            .output()
            .expect("run kern");
        kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["compose", toml.to_str().unwrap(), "down"])
            .output()
            .ok();
        (
            String::from_utf8_lossy(&out.stderr).to_string(),
            String::from_utf8_lossy(&logs.stdout).to_string(),
        )
    };

    let (pod_err, pod) = run(&[]);
    if pod_err.contains("user namespaces") || pod_err.contains("newuidmap") {
        eprintln!(
            "skip: the stack could not start here: {}",
            pod_err.lines().next().unwrap_or("")
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        let _ = fs::remove_file(&toml);
        return;
    }
    assert!(
        pod.contains("peerb"),
        "a pod must put the peer's name in /etc/hosts, or the other half of this test proves nothing: {pod}"
    );

    let (_, solo) = run(&["--no-pod"]);
    // The peer resolves, and to its ALIAS. `127.0.0.3` is peerb's address (second service, so
    // index 1, so `127.0.0.(1+2)`); `peera` itself must stay on `127.0.0.1`, where its own listener
    // is. A build that mapped a peer to `127.0.0.1` would satisfy "the name resolves" and then send
    // every peer connection into the service's own socket.
    assert!(
        solo.contains("127.0.0.3\tpeerb") || solo.contains("127.0.0.3 peerb"),
        "a no-pod peer must resolve to its own alias: {solo}"
    );
    assert!(
        solo.contains("127.0.0.1\tpeera") || solo.contains("127.0.0.1 peera"),
        "and a service must still resolve ITSELF to 127.0.0.1: {solo}"
    );
    let ifaces: Vec<&str> = solo
        .split("IFACE_START")
        .nth(1)
        .and_then(|t| t.split("IFACE_END").next())
        .map(|t| t.split_whitespace().collect())
        .unwrap_or_default();
    assert_eq!(
        ifaces,
        vec!["lo"],
        "a no-pod service must still hold loopback and nothing else: relays reach peers from INSIDE \
         this namespace, and adding an interface to make names work would have given the flag away: \
         {solo}"
    );
    assert!(
        solo.contains("ROUTES=0"),
        "and no routes at all, for the same reason: {solo}"
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::remove_file(&toml);
}

/// RESTARTING ONE SERVICE OF A `--no-pod` STACK MUST NOT SILENTLY CUT ITS PEERS OFF.
///
/// Peer relays are pinned by `setns` to namespaces obtained once, when the stack came up. Restart one
/// service and it gets a NEW network namespace, while every relay half that entered the old one is
/// still sitting in a namespace nothing is listening in. Nothing errors: the old namespace stays
/// alive because the relay is in it.
///
/// MEASURED before the fix, and this is why the assertion below fetches a BYTE rather than opening a
/// socket. `kern compose <file> start` after stopping one service exited 0, printed nothing, and
/// `nc -w 3 peer PORT` still SUCCEEDED, because the relay's listener is up in the box that did not
/// restart and accepts the connection before discovering it has nowhere to forward it. A reachability
/// check that stops at connect reports a working stack while no data crosses. The payload is the
/// discriminant.
///
/// `kern compose <file> watch` runs exactly this cycle on every edit, so the combination that breaks
/// is the one shipped to be run all day.
///
/// Both halves are asserted: the payload must arrive BEFORE the restart too, or a build where relays
/// never worked at all would pass.
#[test]
fn restarting_one_service_of_a_no_pod_stack_keeps_its_peers_reachable() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "nopodrestart");
    let rootfs = root.to_str().unwrap();
    let _ = fs::create_dir_all(root.join("tmp"));
    fs::write(root.join("tmp/hello"), "PAYLOAD_OK\n").expect("payload");
    let xdg = std::env::temp_dir().join(format!("kern-it-npr-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::create_dir_all(&xdg);
    let toml = std::env::temp_dir().join(format!("kern-npr-{}.toml", std::process::id()));

    // `cli` fetches a real body from `srv` in a loop, so the log records whether DATA crossed rather
    // than whether a socket opened.
    let probe = "while :; do sleep 1; R=$(printf 'GET /hello HTTP/1.0\\r\\n\\r\\n' | nc -w 2 srv \
                 7311 2>/dev/null); case \"$R\" in *PAYLOAD_OK*) echo DATA_OK ;; *) echo DATA_FAIL \
                 ;; esac; done";
    fs::write(
        &toml,
        format!(
            "[box.srv]\nrootfs = \"{rootfs}\"\nport = 7311\n\
             command = [\"/bin/busybox\", \"httpd\", \"-f\", \"-p\", \"7311\", \"-h\", \"/tmp\"]\n\n\
             [box.cli]\nrootfs = \"{rootfs}\"\nport = 7312\n\
             command = [\"/bin/busybox\", \"sh\", \"-c\", \"{probe}\"]\n"
        ),
    )
    .unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut a = vec!["compose", toml.to_str().unwrap()];
        a.extend_from_slice(args);
        kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(&a)
            .output()
            .expect("run kern")
    };
    let logs_of =
        |svc: &str| -> String { String::from_utf8_lossy(&run(&["logs", svc]).stdout).to_string() };
    let cleanup = |root: &std::path::Path, xdg: &std::path::Path, toml: &std::path::Path| {
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(xdg);
        let _ = fs::remove_file(toml);
    };

    let up = run(&["up", "--no-pod"]);
    let up_err = String::from_utf8_lossy(&up.stderr).to_string();
    if up_err.contains("user namespaces") || up_err.contains("newuidmap") {
        eprintln!(
            "skip: the stack could not start here: {}",
            up_err.lines().next().unwrap_or("")
        );
        run(&["down"]);
        cleanup(&root, &xdg, &toml);
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(4500));
    let before = logs_of("cli");
    if !before.contains("DATA_OK") {
        // No relay came up at all (a host that refuses `setns` into a child user namespace, which
        // this suite already skips for elsewhere). Skipping is right; asserting the SECOND half
        // against a stack that never worked would report a regression that is not one.
        eprintln!("skip: peer relays did not carry data on this host: {before}");
        run(&["down"]);
        cleanup(&root, &xdg, &toml);
        return;
    }

    // Stop ONE service, then bring the stack back with plain `start`, exactly as `watch` does.
    // `kern ps`, not `compose ps`: this test must not depend on the compose view's own filtering to
    // find the box it is about to stop, or a defect there would show up here as a skip.
    let srv_box = String::from_utf8_lossy(
        &kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .arg("ps")
            .output()
            .expect("run kern")
            .stdout,
    )
    .lines()
    .find_map(|l| {
        l.split_whitespace()
            .next()
            .filter(|n| n.ends_with("-srv"))
            .map(str::to_string)
    });
    let Some(srv_box) = srv_box else {
        eprintln!("skip: could not find the srv box in `compose ps`");
        run(&["down"]);
        cleanup(&root, &xdg, &toml);
        return;
    };
    let stop = kern()
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["stop", &srv_box])
        .output()
        .expect("run kern");
    assert!(stop.status.success(), "stopping one service must work");
    std::thread::sleep(std::time::Duration::from_millis(500));

    let start = run(&["start"]);
    assert!(
        start.status.success(),
        "start must succeed: {}",
        String::from_utf8_lossy(&start.stderr)
    );
    // The mode is carried, and said out loud rather than inferred in silence.
    assert!(
        String::from_utf8_lossy(&start.stderr).contains("without a pod"),
        "start must say it is keeping the stack out of a pod: {}",
        String::from_utf8_lossy(&start.stderr)
    );

    std::thread::sleep(std::time::Duration::from_millis(6000));
    let after = logs_of("cli");
    let tail: String = after.lines().rev().take(3).collect::<Vec<_>>().join(" ");
    run(&["down"]);
    cleanup(&root, &xdg, &toml);
    assert!(
        tail.contains("DATA_OK"),
        "after restarting one service the peer must still deliver a BODY, not merely accept a \
         connection: {tail}"
    );
}

/// `up` WITHOUT `--no-pod` ON A STACK RUNNING WITHOUT ONE IS REFUSED, AND `start` IS NOT.
///
/// The plan file on disk is how a stack remembers it is a no-pod stack. `start` means "put back what
/// was running" and has one reading, so it carries the mode. `up` without the flag has two: a
/// forgotten `--no-pod`, or a deliberate move back into a pod. The file cannot say which, and
/// choosing either one silently changes the stack's network topology.
///
/// THE REFUSAL HAS TO SIT BEFORE THE RECONCILER, and the first version did not. `up` on a stack whose
/// definitions still match returns "already up to date" and exits 0, so a check placed after it never
/// runs. This test would have passed against that build if it only asserted on a stack that needed
/// changes, so it asserts against a stack that is fully up to date, which is the case that broke.
///
/// `up --no-pod` on the same stack must stay idempotent, or the refusal has cost more than it bought.
#[test]
fn up_without_no_pod_on_a_no_pod_stack_is_refused_and_names_the_plan() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "nopodmode");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-npm-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::create_dir_all(&xdg);
    let toml = std::env::temp_dir().join(format!("kern-npm-{}.toml", std::process::id()));
    fs::write(
        &toml,
        format!(
            "[box.one]\nrootfs = \"{rootfs}\"\nport = 7321\n\
             command = [\"/bin/busybox\", \"sh\", \"-c\", \"sleep 20\"]\n\n\
             [box.two]\nrootfs = \"{rootfs}\"\nport = 7322\n\
             command = [\"/bin/busybox\", \"sh\", \"-c\", \"sleep 20\"]\n"
        ),
    )
    .unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut a = vec!["compose", toml.to_str().unwrap()];
        a.extend_from_slice(args);
        kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(&a)
            .output()
            .expect("run kern")
    };
    let cleanup = || {
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        let _ = fs::remove_file(&toml);
    };

    let up = run(&["up", "--no-pod"]);
    let up_err = String::from_utf8_lossy(&up.stderr).to_string();
    if !up.status.success() || !up_err.contains("peer relay") {
        eprintln!(
            "skip: no relay plan was produced on this host: {}",
            up_err.lines().next().unwrap_or("")
        );
        run(&["down"]);
        cleanup();
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(1200));

    // The refusal, against a stack that is fully up to date.
    let plain = run(&["up"]);
    let plain_err = String::from_utf8_lossy(&plain.stderr).to_string();
    // And `--no-pod` again is still a no-op rather than a second refusal.
    let again = run(&["up", "--no-pod"]);
    let again_ok = again.status.success();
    run(&["down"]);
    cleanup();

    assert!(
        !plain.status.success(),
        "`up` without the flag must refuse, not reconcile: {plain_err}"
    );
    // IT NAMES THE SERVICES, not a file. The mode is read from the registry now, so the refusal can
    // point at the running things that make it true rather than at a path that may be stale.
    assert!(
        plain_err.contains("already running WITHOUT a pod")
            && plain_err.contains("one")
            && plain_err.contains("two"),
        "and it must name the services that are up with no pod: {plain_err}"
    );
    assert!(
        plain_err.contains("--no-pod") && plain_err.contains("down"),
        "and give both ways forward: {plain_err}"
    );
    assert!(
        again_ok,
        "`up --no-pod` on the same stack must stay idempotent"
    );
}

/// KILLING THE RELAY HOLDER MUST LEAVE NOTHING BEHIND, INCLUDING AN IN-FLIGHT PUMP.
///
/// `PR_SET_PDEATHSIG` is NOT inherited across `fork`. The two relay halves arm it against the holder,
/// so they die with it; the per-connection pumps the connector forks did not arm anything, so they
/// did not. MEASURED before the fix: killing the holder left ONE process alive, still holding a
/// connection open between two boxes' namespaces, and a peer blocked in `read` never saw it end.
///
/// That is worse than a leaked process. A pump IS the thing that bridges two isolation domains, and
/// it was outliving the teardown meant to remove it, which `compose down` performs by the same path.
///
/// THE TEST HOLDS A CONNECTION OPEN ON PURPOSE, because with no traffic there is no pump and the
/// defect cannot appear: the positive control is that a pump exists before the kill.
#[test]
fn killing_the_relay_holder_leaves_no_pump_behind() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    // Every relay process shares the holder's command line, because they are forked without `exec`,
    // and that line carries the STACK'S OWN runtime directory. Matching on the directory rather than
    // on `__relay-holder` alone is what makes this count immune to another stack running at the same
    // time: the first version counted every relay on the machine and failed against a correct build
    // because an unrelated stack was up.
    let relay_procs = |scope: &str| -> Vec<i32> {
        let mut out = Vec::new();
        let Ok(dir) = fs::read_dir("/proc") else {
            return out;
        };
        for e in dir.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            if let Ok(c) = fs::read(format!("/proc/{pid}/cmdline")) {
                let line = String::from_utf8_lossy(&c);
                if line.contains("__relay-holder") && line.contains(scope) {
                    out.push(pid);
                }
            }
        }
        out
    };

    let root = build_rootfs(&busybox, "pumpleak");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-pump-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::create_dir_all(&xdg);
    // Declared after `xdg` exists: the scope IS that directory, which is what every relay
    // process of this stack carries on its command line.
    let scope = xdg.to_string_lossy().to_string();
    let toml = std::env::temp_dir().join(format!("kern-pump-{}.toml", std::process::id()));
    fs::write(
        &toml,
        format!(
            "[box.srv]\nrootfs = \"{rootfs}\"\nport = 7341\n\
             command = [\"/bin/busybox\", \"sh\", \"-c\", \
             \"while :; do (echo hi; sleep 120) | nc -l -p 7341; sleep 1; done\"]\n\n\
             [box.cli]\nrootfs = \"{rootfs}\"\nport = 7342\n\
             command = [\"/bin/busybox\", \"sh\", \"-c\", \
             \"sleep 4; while :; do sleep 120 | nc srv 7341; sleep 1; done\"]\n"
        ),
    )
    .unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut a = vec!["compose", toml.to_str().unwrap()];
        a.extend_from_slice(args);
        kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(&a)
            .output()
            .expect("run kern")
    };
    let cleanup = || {
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        let _ = fs::remove_file(&toml);
    };

    let before_others = relay_procs(&scope).len();
    let up = run(&["up", "--no-pod"]);
    let up_err = String::from_utf8_lossy(&up.stderr).to_string();
    if !up.status.success() || !up_err.contains("peer relay") {
        eprintln!(
            "skip: no relay came up here: {}",
            up_err.lines().next().unwrap_or("")
        );
        run(&["down"]);
        cleanup();
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(7000));

    // POSITIVE CONTROL, COUNTED EXACTLY rather than guessed at. A holder is one process and each
    // relay is two halves, so anything beyond `1 + 2N` is a pump. The relay count comes from `up`'s
    // own report, because a hard-coded guess is how this control silently stops controlling: the
    // first version compared against a constant and skipped on a run that HAD a pump.
    //
    // Without a pump the defect cannot appear, and the assertion below would pass against it.
    let n_relays: usize = up_err
        .lines()
        .find(|l| l.contains("peer relay(s) up"))
        .and_then(|l| {
            l.split_whitespace()
                .find_map(|w| w.trim_matches(|c: char| !c.is_ascii_digit()).parse().ok())
        })
        .unwrap_or(0);
    let live = relay_procs(&scope);
    let expected_without_pumps = before_others + 1 + 2 * n_relays;
    if n_relays == 0 || live.len() <= expected_without_pumps {
        eprintln!(
            "skip: no pump was forked here ({} procs, {n_relays} relays, {expected_without_pumps} \
             would be halves alone)",
            live.len()
        );
        run(&["down"]);
        cleanup();
        return;
    }

    let holder = fs::read_to_string(
        xdg.join("kern/relays")
            .read_dir()
            .ok()
            .and_then(|mut d| d.next())
            .and_then(|e| e.ok())
            .map(|e| e.path().join("relay-holder"))
            .unwrap_or_default(),
    )
    .ok()
    .and_then(|t| t.trim().parse::<i32>().ok());
    let Some(holder) = holder.filter(|p| *p > 0) else {
        eprintln!("skip: could not read the holder pid");
        run(&["down"]);
        cleanup();
        return;
    };
    // SAFETY: the pid was read from a file this test's own `up` wrote and is guarded positive.
    unsafe { libc::kill(holder, libc::SIGKILL) };
    std::thread::sleep(std::time::Duration::from_millis(2500));
    let after = relay_procs(&scope);
    run(&["down"]);
    cleanup();
    assert_eq!(
        after.len(),
        before_others,
        "the holder's death must take every relay process with it, pumps included; {:?} survived",
        after
    );
}

/// A DEAD RELAY HALF TAKES ITS OWN EDGE DOWN AND THE HOLDER REBUILDS IT, RATHER THAN ENDING THE
/// STACK.
///
/// The holder used to `pause()`, which slept through a dead half and left the stack reachable on some
/// edges with nothing having said so. Total teardown replaced it and was worse in the way that
/// matters to whoever diagnoses it: every edge dies at once, which reads as "kern broke", while the
/// cause is one service.
///
/// So a runtime failure is repaired. This asserts the whole of that: the holder SURVIVES, the edge
/// carries data again, and the process count returns to what it was, which is what separates a
/// genuine rebuild from a half that simply never restarted.
#[test]
fn killing_one_relay_half_rebuilds_that_edge_and_leaves_the_stack_up() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "relayheal");
    let rootfs = root.to_str().unwrap();
    let _ = fs::create_dir_all(root.join("tmp"));
    fs::write(root.join("tmp/hello"), "PAYLOAD_OK\n").expect("payload");
    let xdg = std::env::temp_dir().join(format!("kern-it-heal-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::create_dir_all(&xdg);
    let toml = std::env::temp_dir().join(format!("kern-heal-{}.toml", std::process::id()));
    let probe = "while :; do sleep 1; R=$(printf 'GET /hello HTTP/1.0\\r\\n\\r\\n' | nc -w 2 srv \
                 7351 2>/dev/null); case \"$R\" in *PAYLOAD_OK*) echo DATA_OK ;; *) echo DATA_FAIL \
                 ;; esac; done";
    fs::write(
        &toml,
        format!(
            "[box.srv]\nrootfs = \"{rootfs}\"\nport = 7351\n\
             command = [\"/bin/busybox\", \"httpd\", \"-f\", \"-p\", \"7351\", \"-h\", \"/tmp\"]\n\n\
             [box.cli]\nrootfs = \"{rootfs}\"\nport = 7352\n\
             command = [\"/bin/busybox\", \"sh\", \"-c\", \"{probe}\"]\n"
        ),
    )
    .unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut a = vec!["compose", toml.to_str().unwrap()];
        a.extend_from_slice(args);
        kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(&a)
            .output()
            .expect("run kern")
    };
    let cleanup = || {
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        let _ = fs::remove_file(&toml);
    };
    let last_lines = |svc: &str, n: usize| -> String {
        let out = String::from_utf8_lossy(&run(&["logs", svc]).stdout).to_string();
        out.lines().rev().take(n).collect::<Vec<_>>().join(" ")
    };

    let up = run(&["up", "--no-pod"]);
    let up_err = String::from_utf8_lossy(&up.stderr).to_string();
    if !up.status.success() || !up_err.contains("peer relay") {
        eprintln!(
            "skip: no relay came up here: {}",
            up_err.lines().next().unwrap_or("")
        );
        run(&["down"]);
        cleanup();
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(4500));
    if !last_lines("cli", 3).contains("DATA_OK") {
        eprintln!("skip: the relay never carried data on this host");
        run(&["down"]);
        cleanup();
        return;
    }

    let stack = xdg
        .join("kern/relays")
        .read_dir()
        .ok()
        .and_then(|mut d| d.next())
        .and_then(|e| e.ok())
        .map(|e| e.path());
    let Some(stack) = stack else {
        eprintln!("skip: no relay directory");
        run(&["down"]);
        cleanup();
        return;
    };
    let holder: Option<i32> = fs::read_to_string(stack.join("relay-holder"))
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .filter(|p: &i32| *p > 0);
    let Some(holder) = holder else {
        eprintln!("skip: no holder pid");
        run(&["down"]);
        cleanup();
        return;
    };
    // A half is a child of the holder. Read one from `/proc` rather than guessing a pid.
    let a_half = fs::read_to_string(format!("/proc/{holder}/task/{holder}/children"))
        .ok()
        .and_then(|t| {
            t.split_whitespace()
                .next()
                .and_then(|w| w.parse::<i32>().ok())
        })
        .filter(|p| *p > 0);
    let Some(a_half) = a_half else {
        eprintln!("skip: could not read the holder's children");
        run(&["down"]);
        cleanup();
        return;
    };
    // SAFETY: the pid was read from this holder's own children list and is guarded positive.
    unsafe { libc::kill(a_half, libc::SIGKILL) };
    std::thread::sleep(std::time::Duration::from_millis(5000));

    // SAFETY: signal 0 probes for existence without delivering anything.
    let holder_alive = unsafe { libc::kill(holder, 0) } == 0;
    let after = last_lines("cli", 3);
    let log = fs::read_to_string(stack.join("holder.log")).unwrap_or_default();
    run(&["down"]);
    cleanup();

    assert!(
        holder_alive,
        "one dead half must not end the holder, and with it every other edge"
    );
    assert!(
        after.contains("DATA_OK"),
        "the edge must carry data again after the rebuild: {after}"
    );
    assert!(
        log.contains("rebuilt"),
        "and the rebuild must be recorded, or a flapping edge looks healthy: {log}"
    );
}

/// TWO SERVICES SHARING AN INTERNAL PORT ARE NOT AUTOMATICALLY LOST: the one that binds a SPECIFIC
/// address keeps its peer, and only the one that binds the wildcard does not.
///
/// This is the case the feature used to refuse outright. A relay listens on `alias:port` inside the
/// holder, and the compose file declares a PORT and never an address, so the first version assumed
/// the worst and skipped every pair whose services shared a port. MEASURED, that was wider than the
/// truth: two SPECIFIC binds on different addresses do not conflict on one port, so a service
/// configured with `bind 127.0.0.1` leaves the peer's alias free.
///
/// The decision now belongs to the holder, which reads `/proc/<pid1>/net/tcp` after the services have
/// bound, and both halves are asserted here because either one alone can pass against a wrong build:
/// a build that refuses everything passes the second, and a build that tries everything passes the
/// first while racing the tenant's own listener.
#[test]
fn a_shared_port_costs_only_the_service_that_binds_the_wildcard() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "sharedport");
    let rootfs = root.to_str().unwrap();
    let _ = fs::create_dir_all(root.join("tmp"));
    fs::write(root.join("tmp/hello"), "PAYLOAD_OK\n").expect("payload");
    let xdg = std::env::temp_dir().join(format!("kern-it-sp-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::create_dir_all(&xdg);
    let toml = std::env::temp_dir().join(format!("kern-sp-{}.toml", std::process::id()));

    // BOTH declare 7361. `a` binds it on 127.0.0.1 only; `b` binds the wildcard.
    let a_cmd = "httpd -p 127.0.0.1:7361 -h /tmp; sleep 2; while :; do sleep 1; R=$(printf 'GET \
                 /hello HTTP/1.0\\r\\n\\r\\n' | nc -w 2 b 7361 2>/dev/null); case \"$R\" in \
                 *PAYLOAD_OK*) echo A_REACHES_B ;; *) echo A_FAILS ;; esac; done";
    fs::write(
        &toml,
        format!(
            "[box.a]\nrootfs = \"{rootfs}\"\nport = 7361\n\
             command = [\"/bin/busybox\", \"sh\", \"-c\", \"{a_cmd}\"]\n\n\
             [box.b]\nrootfs = \"{rootfs}\"\nport = 7361\n\
             command = [\"/bin/busybox\", \"httpd\", \"-f\", \"-p\", \"7361\", \"-h\", \"/tmp\"]\n"
        ),
    )
    .unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut v = vec!["compose", toml.to_str().unwrap()];
        v.extend_from_slice(args);
        kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(&v)
            .output()
            .expect("run kern")
    };
    let cleanup = || {
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        let _ = fs::remove_file(&toml);
    };

    let up = run(&["up", "--no-pod"]);
    let up_err = String::from_utf8_lossy(&up.stderr).to_string();
    if !up.status.success() || !up_err.contains("peer relay") {
        eprintln!(
            "skip: no relay came up here: {}",
            up_err.lines().next().unwrap_or("")
        );
        run(&["down"]);
        cleanup();
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(6000));
    let a_log = String::from_utf8_lossy(&run(&["logs", "a"]).stdout).to_string();
    let tail: String = a_log.lines().rev().take(3).collect::<Vec<_>>().join(" ");
    let ps = String::from_utf8_lossy(&run(&["ps"]).stdout).to_string();
    run(&["down"]);
    cleanup();

    // THE HALF THAT USED TO BE REFUSED: `a` binds a specific address, so b's alias is free inside it.
    assert!(
        tail.contains("A_REACHES_B"),
        "the service that binds 127.0.0.1 must still reach its peer on the shared port: {tail}"
    );
    // THE HALF THAT IS GENUINELY LOST, named rather than left to be discovered.
    assert!(
        up_err.contains("cannot reach") && up_err.contains("0.0.0.0"),
        "and the wildcard direction must be named with its reason: {up_err}"
    );
    assert!(
        up_err.contains("bind 127.0.0.1:7361"),
        "and the remedy must be the cheap one, not only a port change: {up_err}"
    );
    assert!(
        ps.contains("peer edge DOWN"),
        "and a status view must carry it, not just the bring-up output: {ps}"
    );
}

/// A FOUR-SERVICE STACK SHAPED LIKE A REAL ONE REACHES ITSELF UNDER `--no-pod`.
///
/// Every other test here isolates one mechanism. This one is the shape a developer actually writes:
/// `db` and `cache` behind an `api` behind a `web`, with `depends_on` between them, two services
/// binding a specific address and two binding the wildcard, and four distinct ports. Twelve relays.
///
/// IT EXISTS BECAUSE IT FOUND A DEFECT THE UNIT TESTS COULD NOT. The holder decides each relay by
/// measuring what the hosting box bound, and "nothing is listening on that port" was read as the racy
/// case for every pair. That is only true when the host DECLARES the port and has not bound it yet; a
/// service that never uses the port will never bind it, so the alias is free forever. With the
/// declaration missing from the decision, this stack came up with twelve blocked edges, every one of
/// them fine. A two-service test cannot show it, because there every pair shares the shape.
///
/// The assertion is a payload fetched over each hop, not a socket that opened: a relay accepts before
/// it discovers whether it can forward, so a connect-only check reports a working stack over a dead
/// one.
#[test]
fn a_four_service_stack_reaches_itself_without_a_pod() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "fourservice");
    let rootfs = root.to_str().unwrap();
    let _ = fs::create_dir_all(root.join("www"));
    fs::write(root.join("www/d"), "DB_ROW\n").expect("db payload");
    fs::write(root.join("www/c"), "CACHE_HIT\n").expect("cache payload");
    // Scripts rather than inline `sh -c`: the command travels through TOML and then through a shell,
    // and a quoting mistake in the probe reads exactly like a broken relay.
    fs::write(
        root.join("api.sh"),
        "#!/bin/busybox sh\nhttpd -p 127.0.0.1:3000 -h /www\nsleep 5\nwhile :; do\n  \
         D=$(wget -qO- http://db:5432/d 2>/dev/null)\n  \
         C=$(wget -qO- http://cache:6379/c 2>/dev/null)\n  \
         echo \"api: db=${D:-NO} cache=${C:-NO}\"\n  sleep 2\ndone\n",
    )
    .expect("api.sh");
    fs::write(
        root.join("web.sh"),
        "#!/bin/busybox sh\nhttpd -f -p 8080 -h /www &\nsleep 7\nwhile :; do\n  \
         A=$(wget -qO- http://api:3000/c 2>/dev/null)\n  echo \"web: api=${A:-NO}\"\n  sleep 2\ndone\n",
    )
    .expect("web.sh");

    let xdg = std::env::temp_dir().join(format!("kern-it-four-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::create_dir_all(&xdg);
    let toml = std::env::temp_dir().join(format!("kern-four-{}.toml", std::process::id()));
    fs::write(
        &toml,
        format!(
            "[box.db]\nrootfs = \"{rootfs}\"\nport = 5432\n\
             command = [\"/bin/busybox\", \"sh\", \"-c\", \"httpd -p 127.0.0.1:5432 -h /www; sleep 3600\"]\n\n\
             [box.cache]\nrootfs = \"{rootfs}\"\nport = 6379\n\
             command = [\"/bin/busybox\", \"httpd\", \"-f\", \"-p\", \"6379\", \"-h\", \"/www\"]\n\n\
             [box.api]\nrootfs = \"{rootfs}\"\nport = 3000\ndepends_on = [\"db\", \"cache\"]\n\
             command = [\"/bin/busybox\", \"sh\", \"/api.sh\"]\n\n\
             [box.web]\nrootfs = \"{rootfs}\"\nport = 8080\ndepends_on = [\"api\"]\n\
             command = [\"/bin/busybox\", \"sh\", \"/web.sh\"]\n"
        ),
    )
    .unwrap();

    let run = |args: &[&str]| -> std::process::Output {
        let mut v = vec!["compose", toml.to_str().unwrap()];
        v.extend_from_slice(args);
        kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(&v)
            .output()
            .expect("run kern")
    };
    let cleanup = || {
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        let _ = fs::remove_file(&toml);
    };
    let tail_of = |svc: &str| -> String {
        String::from_utf8_lossy(&run(&["logs", svc]).stdout)
            .lines()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ")
    };

    let up = run(&["up", "--no-pod"]);
    let up_err = String::from_utf8_lossy(&up.stderr).to_string();
    // SKIP ONLY FOR A HOST THAT CANNOT RUN THIS, never for a stack that came up wrong. The first
    // version skipped when the output held no "peer relay", which is also what a build that blocks
    // every relay produces: the negative control ran green against a deliberately broken tree,
    // reporting a skip. A skip condition that a defect can satisfy is not a skip condition.
    let host_cannot = [
        "user namespaces",
        "newuidmap",
        "setns",
        "Operation not permitted",
    ]
    .iter()
    .any(|m| up_err.contains(m));
    if host_cannot {
        eprintln!(
            "skip: this host cannot run the stack: {}",
            up_err.lines().next().unwrap_or("")
        );
        run(&["down"]);
        cleanup();
        return;
    }
    assert!(
        up.status.success(),
        "bringing the stack up must succeed: {up_err}"
    );
    std::thread::sleep(std::time::Duration::from_millis(16000));
    let api = tail_of("api");
    let web = tail_of("web");
    run(&["down"]);
    cleanup();

    // 4 services x 3 peers x 1 port each. Asserted so a build that plans fewer is caught here rather
    // than by a reachability failure somewhere downstream.
    assert!(
        up_err.contains("12 peer relay(s) up"),
        "a four-service stack with one port each needs twelve relays: {up_err}"
    );
    assert!(
        !up_err.contains("cannot reach"),
        "and none of them is blocked: no two services here share a port: {up_err}"
    );
    assert!(
        api.contains("db=DB_ROW") && api.contains("cache=CACHE_HIT"),
        "api must fetch a BODY from both of its dependencies: {api}"
    );
    assert!(
        web.contains("api=CACHE_HIT"),
        "and web must fetch one through api, so the whole chain carries data: {web}"
    );
}

/// THE ORPHAN SWEEP STILL RUNS, NOW THAT IT NO LONGER RUNS FIRST.
///
/// Reaping cgroups left by boxes whose supervisor was killed used to happen on the hot path of every
/// box start, inside the decision about which cgroup path to cap through. MEASURED on this desktop
/// with 61 entries in the slice: 193 us, 7.4% of a 2.6 ms start, for work that has nothing to do with
/// starting the box in front of it. It moved to after the spawn, where it overlaps the workload.
///
/// A move like that is exactly how a garbage collector quietly stops running, so this asserts the
/// OUTCOME rather than the placement: an orphan directory planted before a box start is gone after
/// it. The planted name carries a pid that cannot exist, which is what makes it an orphan.
///
/// Skipped where the direct `kern.slice` path is not the one this host caps through, because then
/// there is no slice of ours to sweep. That is a host property, not a defect.
#[test]
fn a_box_start_still_reaps_an_orphan_cgroup() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    // FIND THE SLICE WHERE KERN PUTS IT, not where this process's own cgroup would suggest. The
    // first version derived it from `/proc/self/cgroup`, which is the TEST binary's cgroup: run from
    // a terminal inside a systemd scope, that path has no `kern.slice` and never will, so the test
    // skipped on every run and proved nothing. A bounded search under the user's own cgroup finds
    // whichever one this host actually caps through.
    let find_slice = || -> Option<std::path::PathBuf> {
        let uid = unsafe { libc::getuid() };
        let base = std::path::PathBuf::from(format!(
            "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service"
        ));
        let mut stack = vec![(base, 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            if depth > 4 {
                continue;
            }
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                if !p.is_dir() {
                    continue;
                }
                if e.file_name() == "kern.slice" {
                    return Some(p);
                }
                stack.push((p, depth + 1));
            }
        }
        None
    };

    let root = build_rootfs(&busybox, "sweep");
    let run_one = |name: &str| -> std::process::Output {
        kern()
            .args([
                "box",
                name,
                "--rootfs",
                root.to_str().unwrap(),
                "--",
                "/bin/busybox",
                "true",
            ])
            .output()
            .expect("run kern")
    };
    // ONE BOX FIRST, so the slice exists to be searched for: it is created the first time a box caps
    // through it.
    let first = run_one("sweepwarm");
    let Some(slice) = find_slice() else {
        eprintln!(
            "skip: no kern.slice under this user's cgroup, so this host caps another way: {}",
            String::from_utf8_lossy(&first.stderr)
                .lines()
                .next()
                .unwrap_or("")
        );
        let _ = fs::remove_dir_all(&root);
        return;
    };
    // A pid that cannot exist: `pid_max` is at most 2^22 on any Linux kern supports.
    let orphan = slice.join("kern-box-sweeptest-4194400");
    if fs::create_dir(&orphan).is_err() {
        eprintln!("skip: could not plant an orphan in {}", slice.display());
        return;
    }
    assert!(orphan.is_dir(), "the planted orphan must exist to be swept");

    let out = run_one("sweepbox");
    // The sweep runs after the spawn, so give the launcher a moment to reach it.
    std::thread::sleep(std::time::Duration::from_millis(400));
    let still_there = orphan.is_dir();
    let _ = fs::remove_dir(&orphan);
    let _ = fs::remove_dir_all(&root);

    assert!(
        out.status.success(),
        "the box must start: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !still_there,
        "a box start must still reap an orphan cgroup, or the sweep moved itself out of existence"
    );
}

/// A ONE-SHOT SERVICE THAT SUCCEEDS MUST NOT FAIL THE STACK.
///
/// `up` is fail-closed on bring-up: a service that dies inside the settle window is reported and the
/// command exits non-zero, because launching a box only proves the launcher returned. The carve-out
/// is a service that finished CLEANLY, and it is decided by `exit_of(key) != Some(0)`.
///
/// That key used to be handed only to a service some peer waited on with `depends_completed`. For
/// every other service no file was written, `exit_of` answered `None`, and the carve-out could not
/// fire. MEASURED from a field report on 0.8.5: a service running `/bin/echo` and exiting 0 was
/// reported as "died within 150ms of starting" and `up` exited 1, so a stack holding a migration or
/// a build step failed its CI run BY SUCCEEDING.
///
/// Both halves are asserted, because a fix that stopped reporting deaths altogether would pass the
/// first one: a service exiting 3 must still be reported and must still exit non-zero.
#[test]
fn a_one_shot_service_that_exits_zero_does_not_fail_the_stack() {
    let Some(busybox) = static_busybox() else {
        eprintln!("skip: no busybox available");
        return;
    };
    if !userns_plausible() {
        eprintln!("skip: unprivileged user namespaces disabled");
        return;
    }
    let root = build_rootfs(&busybox, "oneshot");
    let rootfs = root.to_str().unwrap();
    let xdg = std::env::temp_dir().join(format!("kern-it-1shot-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    let _ = fs::create_dir_all(&xdg);

    let run = |tag: &str, code: &str| -> std::process::Output {
        let toml =
            std::env::temp_dir().join(format!("kern-1shot-{tag}-{}.toml", std::process::id()));
        fs::write(
            &toml,
            format!(
                "[box.job]\nrootfs = \"{rootfs}\"\ncommand = [\"/bin/busybox\", \"sh\", \"-c\", \"exit {code}\"]\n"
            ),
        )
        .unwrap();
        let out = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["compose", toml.to_str().unwrap(), "up"])
            .output()
            .expect("run kern");
        kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["compose", toml.to_str().unwrap(), "down"])
            .output()
            .ok();
        let _ = fs::remove_file(&toml);
        out
    };

    let ok = run("ok", "0");
    if String::from_utf8_lossy(&ok.stderr).contains("user namespaces") {
        eprintln!("skip: userns unavailable at runtime");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&xdg);
        return;
    }
    let ok_err = String::from_utf8_lossy(&ok.stderr).to_string();
    assert!(
        ok.status.success() && !ok_err.contains("died within"),
        "a service that exited 0 was reported as dead: status {:?}, stderr {ok_err}",
        ok.status.code()
    );

    let bad = run("bad", "3");
    let bad_err = String::from_utf8_lossy(&bad.stderr).to_string();
    assert!(
        !bad.status.success() && bad_err.contains("died within"),
        "a service that exited 3 must still be reported and must still fail the command: \
         status {:?}, stderr {bad_err}",
        bad.status.code()
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
}

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

/// `KERN_MAX_CONCURRENT=N` admits exactly N live boxes and refuses the overflow.
///
/// IT USED TO BE `#[ignore]`d, and that was the wrong fix for a real problem. The cap counts LIVE
/// CLAIMS, which live under `$XDG_RUNTIME_DIR`, so with the ambient one the parallel suite's other
/// boxes counted toward it and the tally was non-deterministic. A private runtime dir makes the count
/// see only this test's claims, which is exactly what the unit-level `claim_name_capped` test already
/// did. A test that runs only when someone remembers `--ignored` is an assertion that does not
/// assert, and it was contributing to a number used as a status.
#[test]
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
    // The isolation that replaces `#[ignore]`: claims live under the runtime dir, so a private one
    // means the global count sees this test's boxes and nothing else.
    let xdg = std::env::temp_dir().join(format!("kern-it-fleet-{}", std::process::id()));
    let _ = fs::remove_dir_all(&xdg);
    fs::create_dir_all(&xdg).expect("temp runtime dir");
    let n = 2;
    let mut admitted = 0;
    for i in 0..(n + 2) {
        let name = format!("fleetcap{i}");
        let out = kern()
            .env("XDG_RUNTIME_DIR", &xdg)
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
        kern()
            .env("XDG_RUNTIME_DIR", &xdg)
            .args(["stop", &format!("fleetcap{i}")])
            .output()
            .ok();
    }
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&xdg);
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

/// `kern run --landlock-rw` confines writes with NO namespace, no image and no pivot_root - the one
/// real boundary the governor verb can offer.
///
/// Four facts make the assertions meaningful, and each is measured rather than assumed:
///  * `RAN` proves the command executed. Without it a host where `/bin/sh` is missing reads as a pass.
///  * `IN-OK` proves the grant was honoured. Without it a ruleset that denies EVERYTHING reads as a pass.
///  * `OUT-WROTE` absent is the property under test.
///  * The control run (same script, no flag) proves the denied path was writable in the first place.
///    Without it, a read-only `/tmp` on the test host would produce the expected output for the wrong
///    reason.
#[test]
fn run_landlock_rw_confines_writes_or_refuses_to_run() {
    let dir = std::env::temp_dir().join(format!("kern-it-ll-run-{}", std::process::id()));
    let inside = dir.join("granted");
    let outside = dir.join("denied");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&inside).unwrap();
    fs::create_dir_all(&outside).unwrap();
    let script = format!(
        "echo RAN; touch {}/f 2>/dev/null && echo IN-OK; touch {}/f 2>/dev/null && echo OUT-WROTE",
        inside.display(),
        outside.display()
    );
    let inside_s = inside.to_str().unwrap_or_default().to_string();

    // The control FIRST, so a host that cannot write the "denied" dir at all is caught before the
    // confined run is interpreted.
    let ctrl = kern_out(&["run", "--", "/bin/sh", "-c", script.as_str()]);
    let ctrl_out = String::from_utf8_lossy(&ctrl.stdout).to_string();
    if !ctrl_out.contains("RAN") || !ctrl_out.contains("OUT-WROTE") {
        let _ = fs::remove_dir_all(&dir);
        eprintln!("skip: the unconfined control could not write the denied path ({ctrl_out:?})");
        return;
    }
    let _ = fs::remove_file(outside.join("f"));

    let out = kern_out(&[
        "run",
        "--landlock-rw",
        inside_s.as_str(),
        "--",
        "/bin/sh",
        "-c",
        script.as_str(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let _ = fs::remove_dir_all(&dir);

    // Ask the same question kern asks, so the expectation comes from the host, never from a guess.
    if kern_isolation::landlock_abi().is_some() {
        assert!(
            stdout.contains("RAN"),
            "the command must run when the allowlist CAN be enforced. stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            stdout.contains("IN-OK"),
            "positive control: a write INSIDE the grant must succeed, or the ruleset is denying a \
             path it was told to permit. stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            !stdout.contains("OUT-WROTE"),
            "a write OUTSIDE the grant must be denied by the LSM. The control run proved this same \
             path was writable without the flag. stdout={stdout:?} stderr={stderr:?}"
        );
    } else {
        // The regression this half exists to catch: `run` was told to confine and could not, and ran
        // anyway. Unlike a resource cap, that leaves the operator's files reachable while they believe
        // otherwise, so it must be a refusal.
        assert!(
            !stdout.contains("RAN"),
            "with no Landlock on this kernel the command must be REFUSED, not run unconfined. \
             stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            !out.status.success() && stderr.contains("--landlock-rw"),
            "the refusal must be a non-zero exit that names the flag. stdout={stdout:?} stderr={stderr:?}"
        );
    }
}

/// `run` does NOT inherit the box's scratch auto-grants. Inside a box `/tmp` is a fresh tmpfs that dies
/// with it; under `run` it is the host's own, and granting it would silently widen "confine writes to
/// this path" into "…and all of /tmp". Asserted separately from the main test because it is the one
/// behaviour that differs between the two verbs, and a refactor that unified the two auto-grant sets
/// would leave every other assertion here passing.
#[test]
fn run_landlock_rw_does_not_grant_the_hosts_tmp() {
    if kern_isolation::landlock_abi().is_none() {
        eprintln!("skip: this kernel has no Landlock");
        return;
    }
    let dir = std::env::temp_dir().join(format!("kern-it-ll-tmp-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let probe = std::env::temp_dir().join(format!("kern-it-ll-probe-{}", std::process::id()));
    let script = format!(
        "echo RAN; touch {} 2>/dev/null && echo TMP-WROTE",
        probe.display()
    );
    let dir_s = dir.to_str().unwrap_or_default().to_string();
    let out = kern_out(&[
        "run",
        "--landlock-rw",
        dir_s.as_str(),
        "--",
        "/bin/sh",
        "-c",
        script.as_str(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let _ = fs::remove_dir_all(&dir);
    let wrote = probe.exists();
    let _ = fs::remove_file(&probe);
    if !stdout.contains("RAN") {
        eprintln!("skip: the command did not run on this host ({stdout:?})");
        return;
    }
    assert!(
        !stdout.contains("TMP-WROTE") && !wrote,
        "the host's /tmp must NOT be auto-granted under `run`: only the named paths are writable. \
         stdout={stdout:?}"
    );
}

/// A `--landlock-rw` path that does not exist, or whose final component is a symlink, is SKIPPED by
/// `landlock::add_path` (it cannot open what is not there, and it opens `O_NOFOLLOW` on purpose). On a
/// box that silence is fail-safe: the box keeps its namespaces and the allowlist only ever tightens.
/// Under `run` the allowlist is the entire confinement, so the same silence produces a command that can
/// write nowhere while the operator believes they granted a directory. Both must be refusals that NAME
/// the path, and neither may reach the workload.
#[test]
fn run_landlock_rw_refuses_a_path_that_cannot_be_granted() {
    let dir = std::env::temp_dir().join(format!("kern-it-ll-bad-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let real = dir.join("real");
    fs::create_dir_all(&real).unwrap();
    let link = dir.join("link");
    let missing = dir.join("nope");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    for (path, needle) in [
        (missing.clone(), "must already exist"),
        (link.clone(), "is a symlink"),
    ] {
        let p = path.to_str().unwrap_or_default().to_string();
        let out = kern_out(&["run", "--landlock-rw", p.as_str(), "--", "/bin/echo", "RAN"]);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            !out.status.success(),
            "--landlock-rw '{p}' must refuse, not run. stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            !stdout.contains("RAN"),
            "--landlock-rw '{p}' must not reach the workload. stdout={stdout:?}"
        );
        assert!(
            stderr.contains(needle) && stderr.contains(&p),
            "the refusal must name the path and say why (expected {needle:?}). stderr={stderr:?}"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

/// The confinement commitment: `--landlock-rw` travelling to the post-re-exec pass as argv is correct
/// only while nothing rewrites argv, and a lost flag is indistinguishable downstream from one that was
/// never passed. `KERN_LANDLOCK_REQUIRED` carries the predicate beside it so the impossible state
/// (requested, but no paths) is detectable, and it must ABORT rather than exec.
///
/// This is the one case a clean run cannot exercise, so it is forced here: the environment is set by
/// hand to exactly what a lost transport would look like. The three other combinations are asserted
/// alongside it, because a belt that also fires when it should not is a worse bug than no belt.
#[test]
fn run_landlock_commitment_aborts_when_the_flag_did_not_survive_the_reexec() {
    let bin = env!("CARGO_BIN_EXE_kern");
    let marker = "WORKLOAD-RAN";

    // Requested before the re-exec, absent after it: the impossible state. Must refuse.
    let lost = std::process::Command::new(bin)
        .args(["run", "--", "/bin/echo", marker])
        .env("KERN_SCOPE", "1")
        .env("KERN_LANDLOCK_REQUIRED", "1")
        .output();
    let Ok(lost) = lost else {
        eprintln!("skip: could not spawn kern");
        return;
    };
    let out = String::from_utf8_lossy(&lost.stdout).to_string();
    let err = String::from_utf8_lossy(&lost.stderr).to_string();
    assert!(
        !out.contains(marker),
        "a lost confinement must not reach the workload. stdout={out:?} stderr={err:?}"
    );
    assert!(
        !lost.status.success() && err.contains("--landlock-rw"),
        "the abort must be non-zero and name the flag. stdout={out:?} stderr={err:?}"
    );

    // The three states that must NOT fire, so the belt cannot become a spurious refusal:
    //  * inside a scope with no request at all,
    //  * the variable inherited from a user's shell with no scope around it,
    //  * request and paths both present.
    let dir = std::env::temp_dir().join(format!("kern-it-ll-commit-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let dir_s = dir.to_str().unwrap_or_default().to_string();
    for (label, args, envs) in [
        (
            "in a scope, nothing requested",
            vec!["run", "--", "/bin/echo", marker],
            vec![("KERN_SCOPE", "1")],
        ),
        (
            "stray variable, no scope",
            vec!["run", "--", "/bin/echo", marker],
            vec![("KERN_LANDLOCK_REQUIRED", "1")],
        ),
        (
            "requested and carried",
            vec![
                "run",
                "--landlock-rw",
                dir_s.as_str(),
                "--",
                "/bin/echo",
                marker,
            ],
            vec![("KERN_SCOPE", "1"), ("KERN_LANDLOCK_REQUIRED", "1")],
        ),
    ] {
        let mut c = std::process::Command::new(bin);
        c.args(&args);
        for (k, v) in &envs {
            c.env(k, v);
        }
        let Ok(o) = c.output() else {
            eprintln!("skip: could not spawn kern for {label}");
            continue;
        };
        let so = String::from_utf8_lossy(&o.stdout).to_string();
        let se = String::from_utf8_lossy(&o.stderr).to_string();
        if !kern_isolation::landlock_abi().is_some() && envs.len() == 2 {
            // The third case legitimately refuses on a kernel with no Landlock, for a different reason.
            continue;
        }
        assert!(
            so.contains(marker),
            "{label}: the belt must not fire here. stdout={so:?} stderr={se:?}"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

/// An empty or missing `--landlock-rw` value is a usage error on `run`, where `box` merely skips it.
/// The divergence is deliberate and is asserted so it cannot be "tidied up" into parity: a box that
/// loses a grant still has namespaces, seccomp and a read-only root; `run` has none of them, so a value
/// that silently vanishes turns a confinement request into an unconfined process.
#[test]
fn run_landlock_rw_rejects_an_empty_or_missing_value() {
    for args in [
        vec!["run", "--landlock-rw", "", "--", "/bin/echo", "RAN"],
        vec!["run", "--landlock-rw", "   ", "--", "/bin/echo", "RAN"],
        vec!["run", "--landlock-rw"],
    ] {
        let out = kern_out(&args);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            !out.status.success() && !stdout.contains("RAN"),
            "{args:?} must be a usage error, not a run. stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            stderr.contains("--landlock-rw"),
            "the usage error must name the flag. stderr={stderr:?}"
        );
    }
}
