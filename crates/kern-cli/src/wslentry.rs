//! In kern's own WSL distro, kern started as root becomes an ordinary user before it does anything.
//!
//! WHY. MEASURED on 2026-11-18 in the distro `install.ps1` creates (Alpine, `systemd=false`, login
//! `root`): kern ran as root, so a box's uid 0 was the distro's uid 0, and a process that escaped a
//! box held every capability, `/mnt/c` read-write and the other distributions' disks under `/dev`.
//! Root was there for the caps: with no systemd nothing delegates a cgroup subtree to a user, and a
//! rootless kern could not cap a box.
//!
//! WHY HERE AND NOT AT BOOT. MEASURED in a throwaway distro the same day: a `[boot] command` can
//! create and delegate the subtree and move the distro's init into it, and every later `wsl -d`
//! session is still born at the root of the distro's cgroup namespace. Something privileged has to
//! place each kern process, and kern started as root (the distro's login, and what `kern.exe` runs)
//! is exactly that. So, before anything else:
//!
//! 1. a subtree of this distro's own, `kern-wsl-<id>.slice/user@<uid>.service`, is made and handed
//!    to the user as systemd would delegate one, with this process in a leaf of it and kern's box
//!    anchor (`kern.slice/kern-boxes.service`) beside the leaf, where the existing cap path finds it
//!    by its `user@<uid>.service` name;
//! 2. a runtime directory of the user's own, `/run/user/<uid>`, not WSLg's `/mnt/wslg/runtime-dir`,
//!    which every distribution shares, so two kerns with one uid would share one box registry;
//! 3. root's terminal is handed off (`wslrelay`): kern goes on in a session of its own on a new
//!    terminal, with no descriptor root's shell left open, while a root parent relays;
//! 4. the identity is dropped to the user (groups, gid, uid, all three ids), verified, and kern is
//!    executed again as that user, so nothing it memoised or opened as root survives the switch.
//!
//! ONLY IN THAT DISTRO. The marker `/etc/kern/wsl-user` names the user and is honoured only when it
//! is a regular root-owned file nobody else can write: only root can have made it, and root is the
//! identity being given up. Anywhere else this is one failed `stat` and nothing more.
//!
//! `kern self-update` stays root: it replaces `/usr/local/bin/kern`, which the user cannot write,
//! and it starts no box. `KERN_WSL_AS_ROOT=1` keeps root for an operator who asks for it. A marker
//! that is there and cannot be trusted is a refusal, never root.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The marker naming the user kern becomes in its WSL distro.
pub(crate) const MARKER: &str = "/etc/kern/wsl-user";

/// An account from `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Account {
    pub(crate) name: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) home: PathBuf,
}

/// The account `name` in a passwd text. Refuses uid 0: becoming root is not giving it up.
pub(crate) fn account_in(passwd: &str, name: &str) -> Option<Account> {
    passwd.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 || f[0] != name {
            return None;
        }
        let uid = f[2].parse::<u32>().ok().filter(|u| *u != 0)?;
        let gid = f[3].parse::<u32>().ok()?;
        Some(Account {
            name: name.to_string(),
            uid,
            gid,
            home: PathBuf::from(f[5]),
        })
    })
}

/// The supplementary groups `name` is listed in, in a group text, plus its primary group.
pub(crate) fn groups_in(group: &str, name: &str, primary: u32) -> Vec<u32> {
    let mut out = vec![primary];
    for line in group.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 4 {
            continue;
        }
        if f[3].split(',').any(|m| m.trim() == name) {
            if let Ok(g) = f[2].parse::<u32>() {
                if !out.contains(&g) {
                    out.push(g);
                }
            }
        }
    }
    out
}

/// The user a marker file names, when the marker may be trusted: a regular file, owned by root,
/// writable by nobody else, holding one plain account name.
pub(crate) fn trusted_marker_user(meta: &std::fs::Metadata, text: &str) -> Option<String> {
    let mode = meta.permissions().mode();
    if !meta.file_type().is_file() || meta.uid() != 0 || mode & 0o022 != 0 {
        return None;
    }
    plain_account_name(text)
}

/// One plain account name (`[a-z0-9_-]`, at most 32), the only thing a marker may hold.
fn plain_account_name(text: &str) -> Option<String> {
    let name = text.trim();
    let plain = !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    plain.then(|| name.to_string())
}

/// Should this invocation keep root? `self-update` replaces a root-owned binary and starts no box.
pub(crate) fn keeps_root(args: &[std::ffi::OsString], as_root_flag: bool) -> bool {
    // `__verify-release` reads a file and its signature and starts no box: install.ps1 runs it as the
    // distro's login user (root) on a copy in /tmp, which a move to the kern user would refuse.
    as_root_flag
        || args
            .get(1)
            .is_some_and(|a| a == "self-update" || a == "__verify-release")
}

/// The leaf this process moves into, under the delegation root. A cgroup with processes cannot give
/// controllers to its children, so the boxes' anchor is its sibling, never its child.
const ENTRY_LEAF: &str = "kern-entry.scope";

/// Enable the controllers a box needs for `dir`'s children, each one on its own: a batch that names
/// one `dir` cannot give fails whole. Best effort, as everywhere else on this path.
fn enable_controllers(dir: &Path) {
    let have = std::fs::read_to_string(dir.join("cgroup.controllers")).unwrap_or_default();
    for c in ["cpu", "memory", "pids", "io"] {
        if have.split_whitespace().any(|h| h == c) {
            let _ = std::fs::write(dir.join("cgroup.subtree_control"), format!("+{c}"));
        }
    }
}

fn chown(path: &Path, uid: u32, gid: u32) {
    let _ = std::os::unix::fs::chown(path, Some(uid), Some(gid));
}

/// Hand a cgroup directory to the user the way systemd delegates one: the directory and the three
/// files that let its owner move processes and give controllers below it.
fn delegate(dir: &Path, uid: u32, gid: u32) {
    chown(dir, uid, gid);
    for f in ["cgroup.procs", "cgroup.subtree_control", "cgroup.threads"] {
        chown(&dir.join(f), uid, gid);
    }
}

/// Build the delegated subtree and move this process into its leaf. `false` when any step did not
/// take: kern then runs as the user without a placed cgroup, and the box path says the caps are not
/// enforced, as it does on any host that cannot cap.
fn place_in_delegated_subtree(acct: &Account) -> bool {
    let base = Path::new("/sys/fs/cgroup");
    if !base.join("cgroup.controllers").is_file() {
        return false;
    }
    // ONE SUBTREE PER DISTRO, never the shared `user.slice/user-<uid>.slice`. MEASURED in the field
    // on 2026-11-18: WSL distros share the VM's cgroup tree, every kern distro's user is uid 1000, so
    // two distros built the SAME `user@1000.service` and the same box anchor, and a `kern build` in
    // one killed the boxes of the other. The cap code finds the root by its `user@<uid>.service` name
    // above the current cgroup (`kern_isolation::user_delegation_root`), so the slice it sits in may
    // be this distro's own.
    let Some(id) = instance_id() else {
        return false;
    };
    let slice = base.join(format!("kern-wsl-{id}.slice"));
    let root = slice.join(format!("user@{}.service", acct.uid));
    let leaf = root.join(ENTRY_LEAF);
    let kern_slice = root.join(kern_isolation::KERN_SLICE_NAME);
    let anchor = kern_slice.join(kern_isolation::KERN_ANCHOR_UNIT);
    if std::fs::create_dir_all(&leaf).is_err() || std::fs::create_dir_all(&anchor).is_err() {
        return false;
    }
    for dir in [base, slice.as_path(), root.as_path()] {
        enable_controllers(dir);
    }
    enable_controllers(&kern_slice);
    for dir in [&root, &leaf, &kern_slice, &anchor] {
        delegate(dir, acct.uid, acct.gid);
    }
    std::fs::write(leaf.join("cgroup.procs"), std::process::id().to_string()).is_ok()
}

/// This distro's own id, `/etc/kern/instance-id`: 16 random hex digits, made on the first run as root
/// and kept. A distro imported from the same rootfs as another gets its own on its first start, so no
/// two share a cgroup subtree.
const INSTANCE_ID: &str = "/etc/kern/instance-id";

fn instance_id() -> Option<String> {
    let valid = |t: &str| {
        let t = t.trim();
        (t.len() == 16 && t.bytes().all(|b| b.is_ascii_hexdigit())).then(|| t.to_ascii_lowercase())
    };
    if let Ok(m) = std::fs::symlink_metadata(INSTANCE_ID) {
        if m.file_type().is_file() && m.uid() == 0 {
            if let Some(id) = std::fs::read_to_string(INSTANCE_ID)
                .ok()
                .as_deref()
                .and_then(valid)
            {
                return Some(id);
            }
        }
    }
    let mut raw = [0u8; 8];
    let mut f = std::fs::File::open("/dev/urandom").ok()?;
    std::io::Read::read_exact(&mut f, &mut raw).ok()?;
    let id: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    // Written beside it and renamed into place, so a reader never sees half a file.
    let tmp = format!("{INSTANCE_ID}.{}", std::process::id());
    std::fs::write(&tmp, format!("{id}\n")).ok()?;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644));
    std::fs::rename(&tmp, INSTANCE_ID).ok()?;
    Some(id)
}

/// `/run/user/<uid>`, mode 0700, the user's. `None` when it exists and belongs to someone else.
fn runtime_dir(acct: &Account) -> Option<PathBuf> {
    let dir = PathBuf::from(format!("/run/user/{}", acct.uid));
    let _ = std::fs::create_dir_all("/run/user");
    // `/run/user` ITSELF MUST BE TRAVERSABLE. MEASURED on a distro upgraded from a root kern: an
    // earlier kern running as root had created `/run/user/0` with its parents 0700, so the user could
    // not reach its own `/run/user/<uid>`, and kern put its state and box scratch under /tmp instead.
    // Only the root-owned parent is touched, only in kern's distro, and only to give back the 0755
    // every system has there; the user's own directory keeps its 0700.
    if let Ok(m) = std::fs::symlink_metadata("/run/user") {
        if m.file_type().is_dir() && m.uid() == 0 && m.permissions().mode() & 0o005 != 0o005 {
            let _ = std::fs::set_permissions("/run/user", std::fs::Permissions::from_mode(0o755));
        }
    }
    if !dir.exists() {
        std::fs::create_dir(&dir).ok()?;
        chown(&dir, acct.uid, acct.gid);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok()?;
    }
    let meta = std::fs::symlink_metadata(&dir).ok()?;
    (meta.file_type().is_dir() && meta.uid() == acct.uid).then_some(dir)
}

/// Drop to `acct`: groups first, then gid, then uid, each with all three ids, and prove root is gone.
fn drop_identity(acct: &Account, groups: &[u32]) -> Result<(), String> {
    let gids: Vec<libc::gid_t> = groups.iter().map(|g| *g as libc::gid_t).collect();
    // SAFETY: `gids` outlives the call; the three set*id calls take plain integers.
    unsafe {
        if libc::setgroups(gids.len(), gids.as_ptr()) != 0 {
            return Err(format!("setgroups: {}", std::io::Error::last_os_error()));
        }
        if libc::setresgid(acct.gid, acct.gid, acct.gid) != 0 {
            return Err(format!("setresgid: {}", std::io::Error::last_os_error()));
        }
        if libc::setresuid(acct.uid, acct.uid, acct.uid) != 0 {
            return Err(format!("setresuid: {}", std::io::Error::last_os_error()));
        }
        // Root must be unreachable now, not merely not current.
        if libc::getuid() != acct.uid || libc::geteuid() != acct.uid || libc::setuid(0) == 0 {
            return Err("the identity did not change".to_string());
        }
    }
    Ok(())
}

/// The whole entry: called first thing in `main`. Returns only when kern is to go on as it is (not
/// root, not in kern's distro, or told to keep root); otherwise it executes kern again as the user,
/// or stops with the reason when it cannot give root up.
pub(crate) fn enter_as_user_if_kern_distro() {
    // SAFETY: getuid/geteuid take no arguments.
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
        return;
    }
    let Ok(meta) = std::fs::symlink_metadata(MARKER) else {
        return;
    };
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if keeps_root(&args, kern_common::env_flag("KERN_WSL_AS_ROOT")) {
        return;
    }
    // THE DIRECTORIES TOO: a valid marker in a directory anyone may write is a marker anyone may
    // replace. MEASURED in the test round: with `/etc/kern` at 777, kern trusted the file and said
    // nothing. Each ancestor must be a root-owned directory nobody else can write.
    // A GROUP-WRITABLE DIRECTORY OF GROUP ROOT IS STILL ROOT'S: the build-4 rootfs shipped `/` at 775
    // `root:root` (MEASURED, a fresh install refused every command), and only root is in group 0.
    let bad_dir = Path::new(MARKER).ancestors().skip(1).find(|d| {
        !std::fs::symlink_metadata(d).is_ok_and(|m| {
            let mode = m.permissions().mode();
            m.file_type().is_dir()
                && m.uid() == 0
                && mode & 0o002 == 0
                && (mode & 0o020 == 0 || m.gid() == 0)
        })
    });
    if let Some(d) = bad_dir {
        eprintln!(
            "kern: {} is not a root-owned directory that only root can write, so {MARKER} in it \
             cannot be trusted: refusing to run as root in kern's WSL distro (as root: `chown \
             root:root {} && chmod go-w {}`, or set KERN_WSL_AS_ROOT=1 to keep root)",
            d.display(),
            d.display(),
            d.display()
        );
        std::process::exit(125);
    }
    let Some(name) = std::fs::read_to_string(MARKER)
        .ok()
        .and_then(|t| trusted_marker_user(&meta, &t))
    else {
        // REFUSED, NOT IGNORED. MEASURED in the test round: a world-writable marker, or a symlink in
        // its place, was ignored with a warning and kern then ran as ROOT, so tampering with the file
        // that makes kern give root up made it keep root. A marker that is there and cannot be
        // trusted is the same as a marker naming a missing user: stop.
        eprintln!(
            "kern: {MARKER} is not a root-owned regular file, in directories and a file writable by \
             root alone, naming one user: refusing to run as root in kern's WSL distro (restore it with `chmod 755 /etc/kern && printf 'kern\\n' > \
             {MARKER} && chmod 644 {MARKER}` as root, or set KERN_WSL_AS_ROOT=1 to keep root)"
        );
        std::process::exit(125);
    };
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let Some(acct) = account_in(&passwd, &name) else {
        eprintln!("kern: {MARKER} names '{name}', which /etc/passwd does not have (or is root): refusing to run as root");
        std::process::exit(125);
    };
    let group = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let groups = groups_in(&group, &acct.name, acct.gid);
    // The home the rootfs build could not hand over (no chown in an unprivileged build).
    if let Ok(h) = std::fs::symlink_metadata(&acct.home) {
        if h.file_type().is_dir() && h.uid() == 0 {
            chown(&acct.home, acct.uid, acct.gid);
        }
    }
    // THE BINARY'S OWN PATH, read while still root: after the identity changes the process is not
    // dumpable and its `/proc/self` links may refuse to be read. Executed by that path with the
    // original `argv[0]`, so `ps` shows `kern`: through `/proc/self/exe` every kern process of the
    // distro was listed as `exe` (MEASURED in the test VM).
    let exe = crate::selfupdate::this_exe().unwrap_or_else(|_| PathBuf::from("/proc/self/exe"));
    // ROOT'S TERMINAL STAYS ROOT'S (`wslrelay`): from here on this process has a terminal and a
    // session of its own and none of the descriptors root's shell left open; a root parent relays.
    if let Err(why) = crate::wslrelay::hand_off_terminal() {
        eprintln!("kern: {why}: refusing to run kern in its WSL distro with root's terminal");
        std::process::exit(125);
    }
    let placed = place_in_delegated_subtree(&acct);
    let run = runtime_dir(&acct);
    if let Err(why) = drop_identity(&acct, &groups) {
        eprintln!(
            "kern: cannot stop being root ({why}): refusing to run as root in kern's WSL distro"
        );
        std::process::exit(125);
    }
    crate::set_global_env("HOME", &acct.home);
    crate::set_global_env("USER", &acct.name);
    crate::set_global_env("LOGNAME", &acct.name);
    match &run {
        Some(dir) => crate::set_global_env("XDG_RUNTIME_DIR", dir),
        None => crate::unset_global_env("XDG_RUNTIME_DIR"),
    }
    // Root's own XDG locations are not the user's.
    for var in [
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
    ] {
        if crate::global_env(var).is_some_and(|v| Path::new(&v).starts_with("/root")) {
            crate::unset_global_env(var);
        }
    }
    if !placed {
        eprintln!(
            "kern: warning: could not place kern in the cgroup subtree delegated to '{}': boxes \
             start, and say their caps are not enforced",
            acct.name
        );
    }
    // ROOT'S FOLDERS ARE NOT THE USER'S. MEASURED on WSL (0.51.3 and 0.56.0): after `wsl -d kern` and
    // `cd ~`, the login's home is `/root` (700), and `kern build .` there answered "build context '.'
    // is not a directory". Said here, where the identity changes, so every verb names the real cause.
    // SAFETY: a NUL-terminated literal; `access` checks with the real ids, which are the user's now.
    if unsafe { libc::access(c".".as_ptr(), libc::R_OK | libc::X_OK) } != 0 {
        let here = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".to_string());
        eprintln!(
            "kern: warning: '{}' cannot read this folder ({here}): in this distro kern works as that \
             user, so a build, a compose file or a mount from here fails. Work in {} or in a folder \
             on C:\\ (/mnt/c/...)",
            acct.name,
            acct.home.display()
        );
    }
    let mut again = std::process::Command::new(&exe);
    again.args(args.iter().skip(1));
    if let Some(arg0) = args.first() {
        std::os::unix::process::CommandExt::arg0(&mut again, arg0);
    }
    let err = std::os::unix::process::CommandExt::exec(&mut again);
    eprintln!("kern: cannot start again as '{}': {err}", acct.name);
    std::process::exit(125);
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\nkern:x:1000:1000:kern:/home/kern:/bin/sh\nfake:x:0:0::/:/bin/sh\nbad:x:abc:1::/:/bin/sh\n";

    #[test]
    fn the_account_is_read_from_passwd_and_never_root() {
        assert_eq!(
            account_in(PASSWD, "kern"),
            Some(Account {
                name: "kern".into(),
                uid: 1000,
                gid: 1000,
                home: PathBuf::from("/home/kern"),
            })
        );
        assert_eq!(
            account_in(PASSWD, "root"),
            None,
            "becoming root is not giving it up"
        );
        assert_eq!(
            account_in(PASSWD, "fake"),
            None,
            "a second uid-0 account is root too"
        );
        assert_eq!(account_in(PASSWD, "bad"), None);
        assert_eq!(account_in(PASSWD, "missing"), None);
        assert_eq!(
            account_in("kern:x:1000\n", "kern"),
            None,
            "a short line is not an account"
        );
    }

    #[test]
    fn groups_are_the_primary_plus_the_ones_listing_the_user() {
        let g = "kern:x:1000:\nvideo:x:44:kern,other\nrender:x:105:other\ndisk:x:6:\naudio:x:29: kern \n";
        assert_eq!(groups_in(g, "kern", 1000), vec![1000, 44, 29]);
        assert_eq!(groups_in("", "kern", 1000), vec![1000]);
    }

    #[test]
    fn a_marker_is_trusted_only_when_only_root_could_have_written_it() {
        let dir = std::env::temp_dir().join(format!("kern-marker-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("wsl-user");
        let _ = std::fs::write(&f, "kern\n");
        let _ = std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644));
        let meta = std::fs::symlink_metadata(&f).ok();
        let _ = std::fs::remove_dir_all(&dir);
        let Some(meta) = meta else {
            return;
        };
        // The test runs as an ordinary user, so this file is NOT root's: refused whatever it says.
        if meta.uid() != 0 {
            assert_eq!(trusted_marker_user(&meta, "kern\n"), None);
        }
        assert_eq!(plain_account_name("kern\n"), Some("kern".to_string()));
        for bad in [
            "",
            "Kern",
            "ke rn",
            "../root",
            "kern\nroot",
            &"a".repeat(33),
        ] {
            assert_eq!(plain_account_name(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn only_self_update_the_signature_check_or_the_flag_keeps_root() {
        let a = |v: &[&str]| v.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        assert!(keeps_root(&a(&["kern", "self-update"]), false));
        assert!(keeps_root(&a(&["kern", "__verify-release"]), false));
        assert!(!keeps_root(&a(&["kern", "box", "__verify-release"]), false));
        assert!(keeps_root(&a(&["kern", "ps"]), true));
        assert!(!keeps_root(&a(&["kern", "ps"]), false));
        assert!(!keeps_root(&a(&["kern", "box", "self-update"]), false));
        assert!(!keeps_root(&a(&["kern"]), false));
    }
}
