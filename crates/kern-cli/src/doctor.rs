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

pub fn doctor() -> Result<(), Error> {
    let p = Palette::detect();
    let mut results: Vec<R> = vec![
        // Core: can we create an unprivileged user namespace at all?
        check_userns(),
        check_apparmor_userns(),
        check_max_userns(),
        // Resource enforcement (cgroup v2 + delegation).
        check_cgroup(),
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
        unsafe { libc::waitpid(pid, &mut st, 0) };
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
        crate::config::default_path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "-".into())
            .as_str(),
    );
    Ok(())
}

/// Actually try to create an unprivileged user namespace in a throwaway child (so a failure can't
/// affect us) - more truthful than reading any single sysctl, which varies by distro (Debian's
/// `unprivileged_userns_clone`, Ubuntu's AppArmor gate, …). Returns whether it succeeded.
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
    unsafe { libc::waitpid(pid, &mut st, 0) };
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
    // A systemd --user manager gives kern a delegated scope for the box. Same predicate the box
    // start itself uses, so doctor can't report an availability the runtime would disagree with.
    if !kern_isolation::user_systemd_present() {
        return R::Warn(
            "cgroup v2 present but no systemd --user manager - resource caps are best-effort".into(),
            "on a host with neither systemd-user nor a delegated cgroup, `--memory`/`--pids-limit` may not bind".into(),
        );
    }
    // A scope alone isn't enough: the box's `memory.max` only enforces if the **memory controller**
    // is actually delegated to the user manager. Some distros (notably Raspberry Pi OS) delegate only
    // `cpu`+`pids`, so `--memory` silently no-ops - check for it rather than over-claiming.
    let ctrls = delegated_controllers();
    if ctrls.is_empty() {
        // Couldn't read the delegated set - don't over- or under-claim.
        R::Ok("cgroup v2 + systemd --user scope: memory/pids/cpu caps where delegated".into())
    } else if ctrls.iter().any(|c| c == "memory") {
        R::Ok("cgroup v2 + systemd --user scope: resource caps enforced (memory delegated)".into())
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
        R::Ok("overlayfs: available (default box rootfs strategy)".into())
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
    ]
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
