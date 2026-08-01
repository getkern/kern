//! `kern doctor` - a rootless-sandbox preflight. Answers "will `kern box` work on this machine, and
//! which optional features are available?" with PASS / WARN / FAIL lines and a fix hint for each.
//!
//! It only *reads* the environment (sysctls, `/proc`, `PATH`) plus one real unprivileged-userns
//! self-test - no mutation, no privilege. FAIL = boxes won't run; WARN = an optional feature is
//! degraded/unavailable but the core sandbox still works.

use crate::error::Error;
use crate::ui::Palette;

/// One check outcome.
enum R {
    Ok(String),
    Warn(String, String), // message, hint
    Fail(String, String),
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
        return R::Ok("caps go direct into kern.slice: no per-box systemd round trip".into());
    }
    if !kern_isolation::user_systemd_present() {
        // No user manager means no transient scope to pay for, which on WSL2 is why a box costs 4.2 ms
        // there WITH its cap enforced: the direct path was never optional, it was the only one.
        return R::Ok("no systemd user manager here: no per-box scope is paid at all".into());
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
        return R::Ok(NO_SCOPE.into());
    }
    let mut s: Vec<f64> = (0..3).filter_map(|_| once()).collect();
    if s.is_empty() {
        return R::Ok(NO_SCOPE.into());
    }
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let ms = s[s.len() / 2];
    R::Warn(
        format!(
            "this session is outside the systemd user manager, so every box pays a transient scope to enforce its caps: at least {ms:.1} ms here, on top of the box itself"
        ),
        "pay it ONCE: `systemd-run --user --scope bash`, then run kern inside that shell. Caps stay enforced and boxes take the direct kern.slice path (measured: 91.9 -> 35.5 ms per box on an Arduino UNO Q, 11.7 -> 3.0 on a Raspberry Pi 5)".into(),
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
        return R::Ok(
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
        return R::Ok(
            "running as root: boxes go to the system manager, so a detached box is not tied to a login session".into(),
        );
    }
    let Some(user) = current_username() else {
        return R::Ok("could not resolve the current user name to check systemd lingering".into());
    };
    if std::path::Path::new(&format!("/var/lib/systemd/linger/{user}")).exists() {
        return R::Ok(
            "systemd lingering is on: a detached box outlives the session that started it".into(),
        );
    }
    R::Warn(
        "systemd lingering is OFF for this user, so a DETACHED box dies when your last session ends: \
         systemd stops `user@<uid>.service` and every box scope under it, and removes the \
         /run/user/<uid> registry with it (measured on a Raspberry Pi 5: box, port and `kern logs` all \
         gone 20 s after logout)"
            .into(),
        format!("`sudo loginctl enable-linger {user}` - one command, once per machine, and detached boxes then survive logout (this is the same requirement rootless podman documents)"),
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

pub fn doctor() -> Result<(), Error> {
    let p = Palette::detect();
    let mut results: Vec<R> = vec![
        // Core: can we create an unprivileged user namespace at all?
        check_userns(),
        check_apparmor_userns(),
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
    results.extend(check_tools());
    results.push(check_kernel());

    println!("{b}kern doctor{z}", b = p.b, z = p.z);
    let (mut ok, mut warn, mut fail) = (0u32, 0u32, 0u32);
    for r in &results {
        match r {
            R::Ok(m) => {
                ok += 1;
                println!("  {g}✔{z} {m}", g = p.g, z = p.z);
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
            "{g}ready{z} - {ok} ok, {warn} warning(s). `kern box` will run here.",
            g = p.g,
            z = p.z
        );
        println!(
            "  {d}try it:{z} {b}kern box hello --image alpine -- echo 'hello from a box'{z}",
            d = p.d,
            b = p.b,
            z = p.z
        );
    } else {
        println!(
            "{r}not ready{z} - {fail} blocker(s), {warn} warning(s), {ok} ok. Fix the ✘ items above.",
            r = p.r,
            z = p.z
        );
    }
    Ok(())
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
fn overlay_mount_cost_ms() -> Option<f64> {
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
                return None;
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
        let t = std::ffi::CString::new(base.join("merged").as_os_str().as_bytes()).ok()?;
        let o = std::ffi::CString::new(format!(
            "lowerdir={0}/lower,upperdir={0}/upper,workdir={0}/work",
            base.display()
        ))
        .ok()?;
        targets.push(t);
        optses.push(o);
    }

    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        let _ = crate::commands::remove_tree_forced(&dir);
        return None;
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
        return None;
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
    if n != buf.len() as isize || !libc::WIFEXITED(st) || libc::WEXITSTATUS(st) != 0 {
        return None;
    }
    let mut us = [0u64; N];
    for (k, slot) in us.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&buf[k * 8..k * 8 + 8]);
        *slot = u64::from_ne_bytes(w);
    }
    us.sort_unstable();
    Some(us[N / 2] as f64 / 1000.0)
}

fn can_create_userns() -> bool {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
        unsafe { libc::_exit(if rc == 0 { 0 } else { 1 }) };
    }
    if pid < 0 {
        return false;
    }
    let mut st = 0i32;
    crate::eintr::waitpid(pid, &mut st, 0);
    libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
}

/// The load-bearing check - the one that actually gates whether boxes run here.
fn check_userns() -> R {
    if can_create_userns() {
        R::Ok("unprivileged user namespaces: enabled".into())
    } else {
        R::Fail(
            "unprivileged user namespaces: DISABLED - kern boxes need them".into(),
            "enable: sysctl -w kernel.unprivileged_userns_clone=1 (Debian) - see the AppArmor check below on Ubuntu".into(),
        )
    }
}

/// Ubuntu 23.10+ restricts unprivileged userns via AppArmor even when the namespace sysctls allow it.
fn check_apparmor_userns() -> R {
    match read_int("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
        Some(1) => R::Warn(
            "AppArmor restricts unprivileged user namespaces (Ubuntu 23.10+)".into(),
            "if boxes fail with EPERM: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 (or add an AppArmor profile for the kern binary)".into(),
        ),
        _ => R::Ok("AppArmor: not restricting unprivileged user namespaces".into()),
    }
}

fn check_max_userns() -> R {
    match read_int("/proc/sys/user/max_user_namespaces") {
        Some(n) if n > 0 => R::Ok(format!("max_user_namespaces: {n}")),
        Some(_) => R::Fail(
            "max_user_namespaces is 0 - user namespaces are capped off".into(),
            "sysctl -w user.max_user_namespaces=10000".into(),
        ),
        None => R::Ok("max_user_namespaces: (default)".into()),
    }
}

fn check_cgroup() -> R {
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
    // So ask the question the runtime asks. `memory_cap_enforceable()` is the predicate `box` itself
    // gates its warning on, which is what the comment here used to claim and was not.
    if !kern_isolation::user_systemd_present() {
        return if kern_isolation::memory_cap_enforceable() {
            R::Ok(
                "cgroup v2, no systemd --user manager needed: caps enforced in the current cgroup"
                    .into(),
            )
        } else {
            R::Warn(
                "cgroup v2 present, no systemd --user manager, and the `memory` controller is not available in this cgroup - `--memory`/`--pids-limit` will not bind".into(),
                "boxes still run and the isolation holds; caps need `memory` enabled in this tree's `cgroup.subtree_control`".into(),
            )
        };
    }
    // A scope alone isn't enough: the box's `memory.max` only enforces if the **memory controller**
    // is actually delegated to the user manager. Some distros (notably Raspberry Pi OS) delegate only
    // `cpu`+`pids`, so `--memory` silently no-ops - check for it rather than over-claiming.
    let ctrls = delegated_controllers();
    if ctrls.is_empty() {
        // Couldn't read the delegated set - don't over- or under-claim.
        R::Ok("cgroup v2 + systemd --user scope: memory/pids/cpu caps where delegated".into())
    } else if ctrls.iter().any(|c| c == "memory") {
        // A DELEGATED controller is not the same as an ENFORCEABLE knob, and this row used to
        // generalise from one to all three. On an Arduino UNO Q's Android kernel `cgroup.controllers`
        // lists `cpu`, yet no `cpu.max` exists anywhere in the chain: the controller is there with only
        // its *weight* interface, so `--cpus` is a share and not a ceiling. Reporting "resource caps
        // enforced" there is the tool telling a comfortable lie about a knob it never looked at.
        if cpu_bandwidth_interface_present() {
            R::Ok(
                "cgroup v2 + systemd --user scope: resource caps enforced (memory delegated)"
                    .into(),
            )
        } else {
            R::Warn(
                "memory/pids caps are enforced, but this kernel's `cpu` controller has no bandwidth interface (`cpu.max`) - `--cpus` is a SHARE here, not a ceiling".into(),
                "needs CONFIG_CFS_BANDWIDTH=y; memory and pids caps are unaffected".into(),
            )
        }
    } else {
        R::Warn(
            format!(
                "systemd --user scope present but the `memory` controller isn't delegated (only: {}) - `--memory` won't be enforced (`--cpus`/`--pids-limit` may still work)",
                ctrls.join(" ")
            ),
            "enable it: /etc/systemd/system/user@.service.d/delegate.conf → [Service] Delegate=memory pids cpu cpuset, then reboot (common on Raspberry Pi OS)".into(),
        )
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
        // Available is not the same as cheap, and on one board the difference is the whole benchmark.
        match overlay_mount_cost_ms() {
            Some(ms) if ms >= 5.0 => R::Warn(
                format!(
                    "overlayfs works but costs {ms:.0} ms per mount on this kernel, which is most of a box's start time"
                ),
                "measured constant here: same cost with an EMPTY lowerdir and with everything on tmpfs, so it is not your disk or your image. `--bind-rootfs` skips it (91.9 -> 11.3 ms per box on an Arduino UNO Q) but binds the source directly: mutable and shared between boxes, where the overlay root is per-box and leaves the source untouched".into(),
            ),
            _ => R::Ok("overlayfs: available (default box rootfs strategy)".into()),
        }
    } else {
        R::Warn(
            "overlayfs not listed in /proc/filesystems".into(),
            "kern falls back to `--bind-rootfs` (mutable, shared) where overlay is unavailable"
                .into(),
        )
    }
}

fn check_uid_range() -> R {
    let user = std::env::var("USER").unwrap_or_default();
    let has_helper = which("newuidmap") && which("newgidmap");
    let has_subid = std::fs::read_to_string("/etc/subuid")
        .map(|s| s.lines().any(|l| l.starts_with(&format!("{user}:"))))
        .unwrap_or(false);
    if has_helper && has_subid {
        R::Ok("--uid-range / --user / --ssh: newuidmap + /etc/subuid present".into())
    } else {
        R::Warn(
            "newuidmap/newgidmap or /etc/subuid missing - `--uid-range`, non-root `--user`, `--ssh` fall back".into(),
            "install uidmap and add a subuid/subgid allocation for your user to enable multi-uid boxes".into(),
        )
    }
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
            "tmpfs fallback used without it",
        ),
        tool_opt(
            "sshd",
            "kern box --ssh",
            "install openssh-server in your images",
        ),
        tool_opt(
            "sshfs",
            "-v sshfs:// network volumes",
            "install sshfs, or use nfs/smb",
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
        Some(v) => R::Ok(format!(
            "Landlock: ABI v{v} (--landlock-rw enforces a write allowlist)"
        )),
        None => R::Warn(
            "Landlock: absent - --landlock-rw is accepted but CANNOT confine writes here".into(),
            "the box still gets namespaces + seccomp; a kernel with CONFIG_SECURITY_LANDLOCK=y \
             (and `lsm=...,landlock` if your distro gates it) is needed for the path allowlist"
                .into(),
        ),
    }
}

fn tool_req(bin: &str, what: &str, hint: &str) -> R {
    if which(bin) {
        R::Ok(format!("{bin}: found ({what})"))
    } else {
        R::Fail(format!("{bin}: MISSING - needed for {what}"), hint.into())
    }
}

fn tool_opt(bin: &str, what: &str, hint: &str) -> R {
    if which(bin) {
        R::Ok(format!("{bin}: found ({what})"))
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
    R::Ok(format!("kernel: {ver}"))
}

// ── helpers ──

fn read_int(path: &str) -> Option<i64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Is `bin` on `PATH`? (No spawn - just a path probe.)
fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).exists()))
        .unwrap_or(false)
}
