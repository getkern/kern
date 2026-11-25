//! Networks prepared ahead: a box on Docker's default network (a NAT of its own) enters a user and
//! network namespace whose NAT is already up, instead of starting pasta and waiting for it.
//!
//! WHY. Since a box reaches the internet by default, as a Docker container does, every such box
//! paid for pasta's start on its critical path: the box waits at its gate until pasta has the
//! namespace configured. MEASURED (23/11, `kern run --rm alpine true`, interleaved medians): this
//! desktop 14.7 ms against 4.1 with `--net none`; the VPS 93 ms against 39; and pasta alone, on a
//! namespace made with `unshare -Urn`, 11.6-13.1 ms whatever its options (`--no-dhcp`, `-4`, no NDP,
//! its AVX2 build called directly: 0.6 ms at most). The time is pasta's own start-up work, so kern
//! cannot make it shorter, only move it off the path. A box joining a namespace whose NAT was ready
//! started in 3.5 ms and reached the internet.
//!
//! WHAT A SLOT IS. A pod holder (`kern __pod-holder`, the process `kern pod create` uses, with the
//! same capability probe, so a host that refuses a box's namespaces refuses a slot too) with pasta
//! attached exactly as a box's own NAT is attached (`pod::attach_own_outbound`: same interface,
//! address, gateway and TCP rules), in `$XDG_RUNTIME_DIR/kern/netpool/<id>`.
//!
//! THE GUARANTEE DOES NOT CHANGE. A slot serves exactly ONE box and goes with it; it is never
//! handed to a second one. What moves is WHEN the namespace and its NAT were made, not what the
//! box can observe: the box still has its own hostname, its own `/etc/hosts` and its own resolvers
//! (`SandboxSpec::net_slot`), its own mount, pid, UTS and IPC namespaces, and the uid map the
//! in-place path would have built (a slot is taken only when its map is the one the box would
//! get). Anything else takes the in-place path, unchanged: see [`kind_for`].
//!
//! LIFETIME. The holder must outlive the box: pasta watches `/proc/<holder>/ns`, so a holder that
//! ended under a running box would take its network with it. The process that runs the box releases
//! the slot once the box is over ([`NetSlot::release`]). One killed before it can is covered by
//! the holder itself: [`sweep`] removes the directory of a slot whose claimer is gone, and a holder
//! whose directory is gone exits once no other process is left in its network namespace
//! (`hold_until_the_pod_is_gone`), so a box still running keeps its network.

use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};

/// The slot is complete and nobody has it.
const READY: &str = "ready";
/// The one box that has it: `pid:starttime` of its claimer. Made with `link`, so two claimers
/// cannot both succeed.
const CLAIMED: &str = "claimed";
/// [`Kind::as_str`] of the uid map the holder ACTUALLY built (read back from it, not assumed).
const KIND: &str = "kind";
/// `pid:starttime` of the holder.
const HOLDER: &str = "holder";
/// The holder's network namespace inode: with the start time, what makes the pid an identity.
const NETNS: &str = "netns";
/// `pid:starttime` of the process building the slot, until it is ready.
const BUILDER: &str = "builder";
/// When a slot could not be made, so the next boxes do not each spawn a builder that fails the same
/// way (a host without pasta, a restricted user namespace).
const FAILED: &str = ".failed";
/// How long a failure stops new attempts.
const FAILED_BACKOFF: std::time::Duration = std::time::Duration::from_secs(300);
/// Slots kept ready per kind. One serves a box started after the previous one's slot was refilled;
/// a burst beyond it takes the in-place path, as before.
const TARGET: usize = 1;
/// The longest a holder may take to report its namespaces, as `pod create` allows.
const HOLDER_READY_MS: i32 = 10_000;

/// The uid map of a slot's user namespace, which is the box's: a box enters a slot only when the
/// map is the one the in-place path would have built for it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    /// The single-uid self-map.
    Single,
    /// The caller's subordinate range, through `newuidmap`/`newgidmap`.
    Range,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Range => "range",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "single" => Some(Self::Single),
            "range" => Some(Self::Range),
            _ => None,
        }
    }
}

/// `KERN_NET_POOL=0` turns the pool off (every box takes the in-place path), for a measurement or a
/// host where idle namespaces are not wanted.
fn enabled() -> bool {
    crate::global_env("KERN_NET_POOL").is_none_or(|v| v != "0")
}

fn root() -> Option<PathBuf> {
    crate::registry::runtime_subdir_public("netpool").ok()
}

/// `pid:starttime`, the identity the registry and the pods record.
fn identity(pid: i32) -> String {
    format!("{pid}:{}", crate::registry::proc_starttime(pid))
}

/// The pid of an identity written by [`identity`], when that process is still the one recorded.
fn alive(marker: &str) -> Option<i32> {
    let (pid, start) = marker.trim().split_once(':')?;
    let pid: i32 = pid.parse().ok()?;
    let start: u64 = start.parse().ok()?;
    (pid > 0 && start != 0 && crate::registry::proc_starttime(pid) == start).then_some(pid)
}

fn read(dir: &Path, file: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(file)).ok()
}

/// The slot kind this box may take, or `None` for the in-place path.
///
/// READ FROM THE SPEC THE IN-PLACE PATH WOULD RUN, not recomputed from the command line, so the two
/// cannot disagree about the box: the uid map is `spec.uid_range` as the isolation layer reads it,
/// and the network is the box's own NAT (`own_outbound`) with nothing joined or shared.
///
/// LEFT OUT, each for a reason: real root with a bind volume (its idmapped binds are built by
/// another function on the pod path; without one, root's box is mapped by the same `detect_id_range`
/// on both); `--privileged` (nesting); `in_place_only`, which the caller sets for a box with a
/// restart policy (every attempt is a new namespace today, and a slot would carry one across
/// attempts) and for an interactive one (it leaves through `process::exit`, where nothing would
/// release the slot); a range that was asked for and cannot be built (the in-place path says so,
/// and a slot would not).
pub(crate) fn kind_for(
    spec: &kern_isolation::SandboxSpec,
    own_outbound: bool,
    privileged: bool,
    in_place_only: bool,
) -> Option<Kind> {
    if !enabled()
        || !own_outbound
        || privileged
        || in_place_only
        || spec.pod_holder.is_some()
        || spec.share_net
        || !spec.pod_bridges.is_empty()
        || spec.ipc_from.is_some()
        || (!spec.idmap_binds.is_empty() && kern_isolation::is_initial_root())
    {
        return None;
    }
    if !spec.uid_range.is_on() {
        return Some(Kind::Single);
    }
    kern_isolation::id_range_available().then_some(Kind::Range)
}

/// A prepared network this process has claimed for one box.
pub(crate) struct NetSlot {
    dir: PathBuf,
    holder: i32,
    pin: Option<crate::pidfd::PidFd>,
    /// Released on drop: an error between the claim and the box ends it here. Cleared by
    /// [`NetSlot::hand_over`] in a launcher whose box lives on in another process.
    armed: bool,
}

impl NetSlot {
    /// The holder whose user and network namespaces the box enters (`SandboxSpec::pod_holder`).
    pub(crate) fn holder(&self) -> i32 {
        self.holder
    }

    /// The box this slot was taken for has ended: its pasta, its holder and its directory go.
    pub(crate) fn release(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        // Stops a pasta that could not watch the namespace, and removes the directory.
        crate::pod::release_own_outbound(&self.dir);
        if let Some(p) = &self.pin {
            p.send_signal(libc::SIGKILL);
        }
    }

    /// The supervisor a launcher forked takes the slot over: the claim names IT from now on, so
    /// [`sweep`] sees a live claimer for as long as the box is supervised. Best effort: a sweep that
    /// already removed the directory leaves the holder holding for the box all the same.
    pub(crate) fn adopt(&self) {
        let _ = std::fs::write(self.dir.join(CLAIMED), identity(std::process::id() as i32));
    }

    /// A launcher whose box runs on in a supervisor it forked: that process releases the slot.
    pub(crate) fn hand_over(&mut self) {
        self.armed = false;
    }
}

impl Drop for NetSlot {
    fn drop(&mut self) {
        self.release();
    }
}

/// Take a ready slot of `kind`, or `None` (the box then starts its own NAT, as before). Asks for a
/// replacement either way, in the background.
pub(crate) fn claim(kind: Kind) -> Option<NetSlot> {
    let got = claim_one(kind);
    refill_in_background(kind);
    got
}

fn claim_one(kind: Kind) -> Option<NetSlot> {
    let root = root()?;
    let me = identity(std::process::id() as i32);
    let entries = std::fs::read_dir(&root).ok()?;
    for e in entries.flatten() {
        let dir = e.path();
        let is_slot = e.file_name().to_str().is_some_and(|n| !n.starts_with('.'));
        if !is_slot || !dir.join(READY).exists() {
            continue;
        }
        if read(&dir, KIND).and_then(|k| Kind::parse(&k)) != Some(kind) {
            continue;
        }
        // ONE WINNER: `link` fails with EEXIST when another claimer's file is already there.
        let mine = dir.join(format!("claim.{}", std::process::id()));
        if std::fs::write(&mine, &me).is_err() {
            continue;
        }
        let won = std::fs::hard_link(&mine, dir.join(CLAIMED)).is_ok();
        let _ = std::fs::remove_file(&mine);
        if !won {
            continue;
        }
        let _ = std::fs::remove_file(dir.join(READY));
        // THE HOLDER IS STILL THE ONE THAT WAS PREPARED: same start time, same network namespace.
        let holder = read(&dir, HOLDER).and_then(|h| alive(&h));
        let netns: Option<u64> = read(&dir, NETNS).and_then(|n| n.trim().parse().ok());
        let Some(holder) =
            holder.filter(|h| netns.is_some() && crate::pod::ns_inode(*h, "net") == netns)
        else {
            let _ = std::fs::remove_dir_all(&dir);
            continue;
        };
        let pin = crate::pidfd::PidFd::open(holder);
        if pin.is_none() {
            let _ = std::fs::remove_dir_all(&dir);
            continue;
        }
        return Some(NetSlot {
            dir,
            holder,
            pin,
            armed: true,
        });
    }
    None
}

/// Start `kern __netpool-fill <kind>` detached from this process: off the box's path, no thread in
/// the launcher (its own `unshare` needs it single-threaded), no child left for it to reap.
fn refill_in_background(kind: Kind) {
    let Some(root) = root() else {
        return;
    };
    if recently_failed(&root, kind) {
        return;
    }
    if ready_count(&root, kind) >= TARGET {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    // Everything the grandchild needs, built BEFORE the fork: it only calls `execve`.
    let Ok(path) = std::ffi::CString::new(exe.as_os_str().as_encoded_bytes()) else {
        return;
    };
    let args: Vec<std::ffi::CString> = ["kern", "__netpool-fill", kind.as_str()]
        .iter()
        .filter_map(|a| std::ffi::CString::new(*a).ok())
        .collect();
    // The secrets of the box that triggered this stay out of a process that outlives it.
    let env: Vec<std::ffi::CString> = crate::global_env_all()
        .into_iter()
        .filter(|(k, _)| !k.to_string_lossy().starts_with(crate::secret::ENV_PREFIX))
        .filter_map(|(k, v)| {
            let mut kv = k.into_encoded_bytes();
            kv.push(b'=');
            kv.extend(v.into_encoded_bytes());
            std::ffi::CString::new(kv).ok()
        })
        .collect();
    let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = env.iter().map(|e| e.as_ptr()).collect();
    envp.push(std::ptr::null());
    // SAFETY: `fork` in a single-threaded launcher; the children only call async-signal-safe
    // functions (`fork`, `dup2`, `close_range`, `setsid`, `execve`, `_exit`) on data built above.
    let middle = unsafe { libc::fork() };
    match middle {
        -1 => {}
        0 => {
            // SAFETY: as above.
            if unsafe { libc::fork() } == 0 {
                crate::commands::detach_from_the_caller();
                // SAFETY: NUL-terminated arrays of pointers into CStrings that outlive the call.
                unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            }
            // SAFETY: `_exit` skips the launcher's atexit handlers and buffers, which are not ours.
            unsafe { libc::_exit(0) };
        }
        pid => {
            let mut status = 0;
            // SAFETY: waiting for the child this function just forked, which exits at once.
            unsafe { libc::waitpid(pid, &mut status, 0) };
        }
    }
}

fn recently_failed(root: &Path, kind: Kind) -> bool {
    std::fs::metadata(root.join(format!("{FAILED}-{}", kind.as_str())))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < FAILED_BACKOFF)
}

fn ready_count(root: &Path, kind: Kind) -> usize {
    std::fs::read_dir(root)
        .map(|rd| {
            rd.flatten()
                .filter(|e| {
                    let d = e.path();
                    d.join(READY).exists()
                        && read(&d, KIND).and_then(|k| Kind::parse(&k)) == Some(kind)
                })
                .count()
        })
        .unwrap_or(0)
}

/// Wait, bounded, until a prepared network is ready or none is coming, for `kern bench`, which times
/// boxes back to back: without it half of them met a pool still refilling and the series was two
/// populations (measured: median 8.9 ms between a 3.0 ms minimum and a 16.4 ms p90, and an A/A
/// interval of +-10 ms). Returns at once when the pool is off, has a slot, or its last fill failed; a
/// box that takes no slot (another uid map, a bind as root) waits only `GRACE`, the time a filler
/// needs to take its lock, and the caller does not time the wait.
pub(crate) fn settle() {
    const GRACE: std::time::Duration = std::time::Duration::from_millis(20);
    const BOUND: std::time::Duration = std::time::Duration::from_secs(1);
    if !enabled() {
        return;
    }
    let Some(root) = root() else {
        return;
    };
    let started = std::time::Instant::now();
    loop {
        let ready = ready_count(&root, Kind::Single) + ready_count(&root, Kind::Range);
        let failed = recently_failed(&root, Kind::Single) || recently_failed(&root, Kind::Range);
        let elapsed = started.elapsed();
        if ready > 0 || failed || elapsed >= BOUND || (elapsed >= GRACE && !filling(&root)) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// Is a filler at work: does one hold a `.fill-<kind>.lock`?
fn filling(root: &Path) -> bool {
    [Kind::Single, Kind::Range].iter().any(|k| {
        std::fs::File::open(root.join(format!(".fill-{}.lock", k.as_str())))
            .ok()
            // SAFETY: `flock` on a descriptor this function owns; a shared lock taken is dropped
            // with the file at the end of the closure.
            .is_some_and(
                |f| unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0,
            )
    })
}

/// Is the pool on, for a report that says how its boxes were timed.
pub(crate) fn is_enabled() -> bool {
    enabled()
}

/// The slots, ready and claimed, for `kern info`: `(ready single, ready range, in use)`.
pub(crate) fn counts() -> (usize, usize, usize) {
    let Some(root) = root() else {
        return (0, 0, 0);
    };
    let used = std::fs::read_dir(&root)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().join(CLAIMED).exists())
                .count()
        })
        .unwrap_or(0);
    (
        ready_count(&root, Kind::Single),
        ready_count(&root, Kind::Range),
        used,
    )
}

/// `kern __netpool-fill <kind>` (hidden): make slots of `kind` until [`TARGET`] are ready. One filler
/// per kind at a time (a lock), so a burst of boxes asks for slots without making a slot each.
pub(crate) fn fill_verb(kind: &str) -> i32 {
    let Some(kind) = Kind::parse(kind) else {
        return 2;
    };
    let Some(root) = root() else {
        return 1;
    };
    let lock_path = root.join(format!(".fill-{}.lock", kind.as_str()));
    let Ok(lock) = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
    else {
        return 1;
    };
    // SAFETY: `flock` on a descriptor this process owns.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return 0; // another filler of this kind is at work
    }
    sweep(&root);
    while ready_count(&root, kind) < TARGET {
        match build(&root, kind) {
            Ok(()) => {}
            Err(why) => {
                let _ = std::fs::write(root.join(format!("{FAILED}-{}", kind.as_str())), why);
                return 1;
            }
        }
    }
    let _ = std::fs::remove_file(root.join(format!("{FAILED}-{}", kind.as_str())));
    0
}

/// Remove what nobody will use: a slot whose holder is gone, a claimed slot whose claimer is gone,
/// and a slot whose builder died half way.
fn sweep(root: &Path) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let dir = e.path();
        if e.file_name().to_str().is_none_or(|n| n.starts_with('.')) || !dir.is_dir() {
            continue;
        }
        if dir.join(CLAIMED).exists() {
            release_if_orphaned(&dir);
            continue;
        }
        let gone = if dir.join(READY).exists() {
            read(&dir, HOLDER).and_then(|h| alive(&h)).is_none()
        } else {
            read(&dir, BUILDER).and_then(|b| alive(&b)).is_none()
        };
        if gone {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

/// Release every claimed slot whose claimer is gone, for `kern stop` and `kern rm -f`: a supervisor
/// they SIGKILL never reaches [`NetSlot::release`]. MEASURED: after `kern rm -f` of a detached box on
/// a slot, the slot stayed claimed with its holder and pasta (about 32 MB) until the holder's own
/// watchdog ended it, up to a minute later. One `read_dir` of the pool when nothing is orphaned.
pub(crate) fn release_orphans() {
    let Some(root) = root() else {
        return;
    };
    let Ok(rd) = std::fs::read_dir(&root) else {
        return;
    };
    for e in rd.flatten() {
        let dir = e.path();
        if dir.join(CLAIMED).exists() {
            release_if_orphaned(&dir);
        }
    }
}

/// End every slot nobody has claimed, for `kern uninstall`: the holders and their pasta go now rather
/// than when their watchdog notices the directory is gone (up to a minute). A claimed slot is left
/// to its box.
pub(crate) fn discard_ready() {
    let Some(root) = root() else {
        return;
    };
    let Ok(rd) = std::fs::read_dir(&root) else {
        return;
    };
    for e in rd.flatten() {
        let dir = e.path();
        if !dir.join(READY).exists() || dir.join(CLAIMED).exists() {
            continue;
        }
        let holder = read(&dir, HOLDER).and_then(|h| alive(&h));
        let netns: Option<u64> = read(&dir, NETNS).and_then(|n| n.trim().parse().ok());
        let _ = std::fs::remove_dir_all(&dir);
        if let (Some(holder), Some(netns)) = (holder, netns) {
            if crate::pod::ns_inode(holder, "net") == Some(netns)
                && !netns_has_others(holder, netns)
            {
                if let Some(pin) = crate::pidfd::PidFd::open(holder) {
                    pin.send_signal(libc::SIGKILL);
                }
            }
        }
    }
}

/// A claimed slot whose claimer is gone: its directory goes, and its holder (with the pasta that
/// watches it) is ended NOW when no other process is left in its network namespace. A box still
/// running there keeps its holder, which ends by itself once the box does (see the module doc).
fn release_if_orphaned(dir: &Path) {
    if read(dir, CLAIMED).and_then(|c| alive(&c)).is_some() {
        return;
    }
    let holder = read(dir, HOLDER).and_then(|h| alive(&h));
    let netns: Option<u64> = read(dir, NETNS).and_then(|n| n.trim().parse().ok());
    let _ = std::fs::remove_dir_all(dir);
    let (Some(holder), Some(netns)) = (holder, netns) else {
        return;
    };
    if crate::pod::ns_inode(holder, "net") != Some(netns) || netns_has_others(holder, netns) {
        return;
    }
    if let Some(pin) = crate::pidfd::PidFd::open(holder) {
        pin.send_signal(libc::SIGKILL);
    }
}

/// Is any process other than `holder` in the network namespace `netns`? A process this user cannot
/// inspect cannot be one of its boxes, so an unreadable entry is not counted.
fn netns_has_others(holder: i32, netns: u64) -> bool {
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return true; // cannot tell: keep the holder, its own watchdog decides
    };
    rd.flatten().any(|e| {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else {
            return false;
        };
        pid != holder && crate::pod::ns_inode(pid, "net") == Some(netns)
    })
}

/// Make one slot of `kind`: the holder, its NAT, then the `ready` mark. `Err` with the reason.
fn build(root: &Path, kind: Kind) -> Result<(), String> {
    let id = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let dir = root.join(&id);
    std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
        .create(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let _ = std::fs::write(dir.join(BUILDER), identity(std::process::id() as i32));
    let fail = |why: String, holder: Option<i32>| -> String {
        let _ = std::fs::remove_dir_all(&dir);
        if let Some(h) = holder {
            // SAFETY: the holder this function spawned and nobody else has seen.
            unsafe { libc::kill(h, libc::SIGKILL) };
            crate::eintr::reap(h);
        }
        why
    };
    let holder = spawn_holder(&dir, kind).map_err(|why| fail(why, None))?;
    let netns = crate::pod::ns_inode(holder, "net")
        .ok_or_else(|| fail("the holder has no network namespace".into(), Some(holder)))?;
    // THE MAP THE HOLDER BUILT, read back: a range it could not build is a single map, and a box
    // expecting a range must not be given it.
    let built = std::fs::read_to_string(format!("/proc/{holder}/uid_map"))
        .ok()
        .map(|m| {
            let ids: u64 = m
                .lines()
                .filter_map(|l| l.split_whitespace().nth(2)?.parse::<u64>().ok())
                .sum();
            if ids > 1 {
                Kind::Range
            } else {
                Kind::Single
            }
        })
        .ok_or_else(|| fail("the holder's uid map is unreadable".into(), Some(holder)))?;
    if built != kind {
        return Err(fail(
            format!(
                "asked for a {} map and the holder built a {} one",
                kind.as_str(),
                built.as_str()
            ),
            Some(holder),
        ));
    }
    let _ = std::fs::write(dir.join(HOLDER), identity(holder));
    let _ = std::fs::write(dir.join(NETNS), netns.to_string());
    let _ = std::fs::write(dir.join(KIND), kind.as_str());
    crate::pod::attach_own_outbound(&dir, holder).map_err(|why| fail(why, Some(holder)))?;
    let _ = std::fs::remove_file(dir.join(BUILDER));
    // LAST, and atomically: a claimer sees a slot only once everything above is in place.
    let tmp = dir.join(".ready");
    std::fs::write(&tmp, b"")
        .and_then(|()| std::fs::rename(&tmp, dir.join(READY)))
        .map_err(|e| fail(format!("ready mark: {e}"), Some(holder)))?;
    // The holder is detached (its own process group); this process does not wait for it.
    Ok(())
}

/// Spawn `kern __pod-holder` for a slot and wait, bounded, for its `pod-ready`. Its pid.
fn spawn_holder(dir: &Path, kind: Kind) -> Result<i32, String> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate kern: {e}"))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("__pod-holder")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .env("KERN_POD_DIR", dir);
    for (k, _) in crate::global_env_all()
        .into_iter()
        .filter(|(k, _)| k.to_string_lossy().starts_with(crate::secret::ENV_PREFIX))
    {
        cmd.env_remove(k);
    }
    match kind {
        Kind::Range => {
            cmd.env(
                "KERN_POD_UID_RANGE",
                kern_isolation::UidRange::ImageDefault.as_env(),
            );
        }
        Kind::Single => {
            cmd.env_remove("KERN_POD_UID_RANGE");
        }
    }
    cmd.env_remove("KERN_POD_BRIDGE");
    let mut child = cmd.spawn().map_err(|e| format!("pod holder: {e}"))?;
    let pid = i32::try_from(child.id()).map_err(|_| "pod holder: pid out of range".to_string())?;
    let ready = child
        .stdout
        .take()
        .is_some_and(|out| reads_ready_line(OwnedFd::from(out)));
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        return Err("the pod holder did not report its namespaces ready".into());
    }
    // Detached: the holder lives on in its own process group, and its exit is reaped by init.
    std::mem::forget(child);
    Ok(pid)
}

/// Read `pod-ready\n` from the holder within [`HOLDER_READY_MS`], with `poll` rather than a thread.
fn reads_ready_line(fd: OwnedFd) -> bool {
    let mut got = Vec::with_capacity(16);
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(HOLDER_READY_MS as u64);
    let mut file = std::fs::File::from(fd);
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return false;
        }
        let mut pfd = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = i32::try_from(left.as_millis()).unwrap_or(HOLDER_READY_MS);
        if crate::eintr::poll(std::slice::from_mut(&mut pfd), ms) <= 0 {
            return false;
        }
        let mut buf = [0u8; 64];
        match file.read(&mut buf) {
            Ok(0) | Err(_) => return false,
            Ok(n) => got.extend_from_slice(buf.get(..n).unwrap_or(&[])),
        }
        if let Some(end) = got.iter().position(|b| *b == b'\n') {
            return got.get(..end) == Some(b"pod-ready".as_slice());
        }
        if got.len() > 64 {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One claimer wins a slot: the claim is a `link` onto one name, and a second fails on EEXIST.
    #[test]
    fn a_slot_has_one_claimer() {
        let d = std::env::temp_dir().join(format!("kern-netpool-claim-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("dir");
        let a = d.join("claim.1");
        let b = d.join("claim.2");
        std::fs::write(&a, "1:1").expect("a");
        std::fs::write(&b, "2:2").expect("b");
        assert!(std::fs::hard_link(&a, d.join(CLAIMED)).is_ok());
        assert!(std::fs::hard_link(&b, d.join(CLAIMED)).is_err());
        assert_eq!(
            std::fs::read_to_string(d.join(CLAIMED)).expect("read"),
            "1:1"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// An identity is a live process only with its own start time.
    #[test]
    fn an_identity_is_the_pid_and_its_start_time() {
        let me = std::process::id() as i32;
        assert_eq!(alive(&identity(me)), Some(me));
        assert_eq!(alive(&format!("{me}:1")), None);
        assert_eq!(alive("0:5"), None);
        assert_eq!(alive("garbage"), None);
    }

    #[test]
    fn a_kind_reads_back_what_it_writes() {
        for k in [Kind::Single, Kind::Range] {
            assert_eq!(Kind::parse(k.as_str()), Some(k));
        }
        assert_eq!(Kind::parse("bridge"), None);
    }
}
