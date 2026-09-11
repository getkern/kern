//! `kern pod` - a **pod** is a set of boxes that share ONE loopback network, so services reach each
//! other by name on `127.0.0.1` (like a Kubernetes pod). A hidden **holder** process (`kern
//! __pod-holder`, [`kern_isolation::run_pod_holder`]) owns the pod's user+net namespace; each
//! `kern box --pod <name>` box `setns`es into it. A shared `/etc/hosts` (bind-mounted into every pod
//! box) maps each member name → `127.0.0.1`, updated as members join. Pod members are co-trusted
//! (they share the user+net ns); the pod is the network trust unit.
//!
//! **Outbound** is OPTIONAL: if `pasta` (passt) is installed, `create` attaches it to the pod net ns
//! for rootless NAT'd internet access + DNS (unless `--no-outbound`); without pasta the pod is
//! loopback-only (inter-service only; publish to the host with `-p` on a box). kern itself needs no
//! extra dependency to run - pasta only unlocks pod egress.

use crate::error::Error;
use std::io::{BufRead, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;

/// `<XDG_RUNTIME_DIR|/run/user/uid>/kern/pods`.
pub(crate) fn pods_root() -> PathBuf {
    crate::registry::assert_registry_child("pods"); // classification chokepoint (see registry.rs)
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })));
    base.join("kern/pods")
}

/// A pod's private directory (`…/pods/<name>`): holds the `holder` pid file and the shared `hosts`.
fn pod_dir(name: &str) -> PathBuf {
    pods_root().join(name)
}

/// Path of a pod's shared `/etc/hosts` (bind-mounted into every member box).
pub fn hosts_path(name: &str) -> PathBuf {
    pod_dir(name).join("hosts")
}

/// Path of a pod's `/etc/resolv.conf` - present only when the pod has OUTBOUND (a `pasta` NAT was
/// set up); bind-mounted into member boxes so DNS works. `None`/absent → loopback-only pod.
pub fn resolv_path(name: &str) -> PathBuf {
    pod_dir(name).join("resolv.conf")
}

/// A pid out of one of a pod dir's small state files (`holder`, `pasta.pid`).
///
/// `None` unless the file holds a POSITIVE integer, and that guard belongs here rather than at each
/// call site because every caller eventually reaches `kill`: `kill(0, ...)` signals the caller's own
/// process group and `kill(-1, ...)` signals every process it may signal, so a degenerate value in
/// one of these files must never leave this function. It used to be re-checked at four call sites
/// and explained in four comments, which is four chances to add a fifth reader and forget.
fn read_pid_file(path: &std::path::Path) -> Option<i32> {
    let raw = std::fs::read_to_string(path).ok()?;
    // `pid` or `pid:starttime`; the identity half is read by [`recorded_holder_starttime`].
    let pid: i32 = raw.trim().split(':').next()?.parse().ok()?;
    if pid <= 0 {
        return None; // 0 is the caller's own process group, -1 is everything it may signal
    }
    if pid == 1 {
        // Nonsense in a pod's pidfile. Rootless it would only earn an EPERM, but a value that
        // cannot be right should not leave the reader on the strength of a permission check.
        return None;
    }
    if pid == std::process::id() as i32 {
        // A clobbered pidfile naming kern ITSELF, which would make teardown SIGKILL the process
        // doing the teardown. Reachable by exactly the same corruption the battery already tests
        // with a stranger's pid, and it was the one value that case did not cover.
        return None;
    }
    Some(pid)
}

/// Is this pod's `pasta` still the live process we recorded?
///
/// Verified by `comm` rather than by liveness alone: passt re-execs into an ISA variant
/// (`pasta.avx2`, never the bare name) and a recorded pid can be reused once it dies. Same guard
/// `teardown` applies below, for the same reason.
fn pasta_alive(name: &str) -> bool {
    read_pid_file(&pod_dir(name).join("pasta.pid")).is_some_and(pid_is_pasta)
}

/// The network sentence for an EXISTING pod, for a caller reporting on one it did not just create
/// (a `compose up` that REUSED a pod has no `create` line above its summary).
///
/// A BOOL WAS THE WRONG SHAPE AND IT SHIPPED. The first version of this returned "does it have
/// outbound", and the caller printed "NO outbound (install `passt`/`pasta`)" for every false. So a
/// user on Fedora whose pasta was INSTALLED and refused to start read, two lines under kern's own
/// correct "pasta IS installed but did not start", an instruction to install it. Reported as #6
/// within hours of the release that introduced it. The comment above the caller even said `pod
/// create` distinguishes five states; the code beneath it collapsed them to two.
///
/// So this returns the sentence, not a flag: the wording lives in one place, and a caller cannot
/// map a state onto the wrong message because it never sees the states. "pasta is on PATH" and
/// "pasta is running for THIS pod" are asked separately, because the difference between them is
/// exactly what the bad message got wrong.
///
/// The three facts are read here and decided in [`network_sentence`], which is pure and therefore
/// testable: the previous version reached the filesystem inside every arm, so no test could reach
/// the arms at all, and the wrong-arm defect below shipped unexercised.
///
/// `which_pasta` walks PATH, and is only consulted for the case where nothing else has answered, so
/// it is evaluated lazily rather than on every summary line.
pub fn network_summary(name: &str) -> String {
    let alive = pasta_alive(name);
    let resolv = resolv_path(name).is_file();
    let installed = !alive && !resolv && which_pasta().is_some();
    network_sentence(alive, resolv, installed).into()
}

/// `installed` is consulted ONLY when `!alive && !resolv`; every other arm is decided before it is
/// read, which is why the caller may pass `false` for it without looking.
///
/// KNOWN RESIDUAL, ON RECORD RATHER THAN FIXED. The `(true, true)` arm says "outbound to the
/// internet" from a live pasta plus a written `resolv.conf`, which is a proxy for reachability and
/// not a measurement of it: a `resolv.conf` naming a nameserver that cannot be reached produces
/// that sentence with DNS broken. It is the same proxy shape the other arms were fixed to avoid.
///
/// It stays for two reasons. The precise version would make a status line perform a DNS
/// resolution, with its own timeout and its own failure modes, on a path whose whole job is to
/// print what is already known. And the sentence is approximately true where it is wrong: outbound
/// IS up, which is what the reader is asking. The failure needs a resolver that kern itself wrote
/// into the pod to be unreachable, which is rarer than the cost of getting it exactly right: the
/// string is keyed on by `says_outbound` in `scripts/certify-issue6.sh` and `states_outbound` in
/// `scripts/acceptance-matrix.sh`, so narrowing the wording moves three copies to close it.
fn network_sentence(alive: bool, resolv: bool, installed: bool) -> &'static str {
    match (alive, resolv) {
        (true, true) => "services reach each other by name + outbound to the internet (pasta)",
        (true, false) => {
            "outbound is up but DNS is not - the pod can reach an IP and cannot resolve a name"
        }
        // pasta WROTE this resolv.conf, so it started for this pod and has since exited: crashed,
        // OOM-killed, or caught a teardown that raced. The arm below must not absorb this case. It
        // says "the `pod create` line says why it refused", and nothing refused: create succeeded
        // and printed no reason, so that sentence sends the reader to look for an explanation that
        // was never printed. Same defect class as #6's visible symptom, one arm over, in the
        // function written to fix it.
        //
        // No new marker is needed to tell the two apart, because `setup_outbound` only reaches the
        // `resolv.conf` write after every failure path has already returned: the file existing IS
        // the record that pasta once came up.
        //
        // TWO THINGS STOP IT SURVIVING AN EARLIER POD OF THE SAME NAME, and this used to cite only
        // the first. `teardown` removes the directory, and removes the state files one by one if
        // that fails. And `create`, reclaiming a dead leftover dir, calls `remove_dir_all` and then
        // `DirBuilder::create`, which returns `AlreadyExists` and fails the whole create if the
        // removal did not take. So a stale directory cannot be silently reused even when teardown's
        // cleanup failed: the second gate refuses rather than inheriting it.
        (false, true) => {
            "outbound is DOWN - pasta started for this pod and has since exited (create reported \
             no problem, so look for a crash, an OOM kill, or a racing teardown)"
        }
        (false, false) if installed => {
            "loopback-only - services reach each other; pasta is installed but is not running for \
             this pod (the `pod create` line says why it refused)"
        }
        (false, false) => {
            "loopback-only - services reach each other; NO outbound (install `passt`/`pasta` for \
             egress)"
        }
    }
}

/// The inode of `/proc/<pid>/ns/<kind>` - a namespace's stable identity. Used to detect PID reuse:
/// a recorded holder PID is only trusted if its net ns inode still matches the one from create time.
fn ns_inode(pid: i32, kind: &str) -> Option<u64> {
    std::fs::metadata(format!("/proc/{pid}/ns/{kind}"))
        .ok()
        .map(|m| std::os::unix::fs::MetadataExt::ino(&m))
}

/// The holder PID for pod `name` if the pod exists, its holder is still alive, AND its net ns is the
/// SAME one recorded at create (guards against the PID being reused by an unrelated process after the
/// holder died - otherwise a box could `setns` into a stranger's namespace). Else `None`.
pub fn holder_pid(name: &str) -> Option<i32> {
    let dir = pod_dir(name);
    let pid = read_pid_file(&dir.join("holder"))?;
    if unsafe { libc::kill(pid, 0) } != 0 {
        return None; // holder gone
    }
    // Verify the net ns identity matches what we recorded - reject a reused PID.
    let want: u64 = std::fs::read_to_string(dir.join("netns"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if ns_inode(pid, "net") == Some(want) {
        Some(pid)
    } else {
        None
    }
}

/// The argv token that makes a process kern's own pod holder. One definition: `create` spawns the
/// holder with it and [`holder_to_reap`] recognises it, so the two cannot drift.
const HOLDER_ARGV: &str = "__pod-holder";

/// Marker file: this pod's pasta was started WITH the netns watch, i.e. the first attempt in
/// [`setup_outbound`] succeeded and no retry was needed. Empty, because its existence is the fact.
///
/// WRITTEN FOR THE HEALTHY CASE, AND THE POLARITY IS THE POINT. It records the pasta that exits by
/// itself when the namespace goes; every other pasta needs `teardown` to confirm its exit before
/// the pidfile naming it is deleted. So ABSENCE means escalate, by construction.
///
/// The first version recorded the opposite, `pasta.nowatch` on the retry, and absence then meant
/// "do not escalate". That write is best-effort, because it must not fail a pod whose NAT is up,
/// so a failed write produced exactly the leak the marker exists to prevent: a pasta with no
/// watch, no escalation, and a pidfile about to be deleted. The costs are not symmetric. An
/// unnecessary escalation costs a poll loop that exits on its first check; a missing one costs a
/// userspace NAT that nothing can name for the rest of the session.
const PASTA_WATCHED: &str = "pasta.watched";

/// The boot this pod dir belongs to, as `/proc/sys/kernel/random/boot_id`.
///
/// BOTH HALVES OF `pid:starttime` ARE BOOT-RELATIVE, and that is the flaw this closes. The pid space
/// resets at boot and the start-time is ticks since boot, so a marker written before a reboot names
/// a process that cannot exist while describing it in numbers a NEW process can coincidentally
/// match: start-time granularity is `USER_HZ`, typically 100 Hz, so any two processes started in the
/// same centisecond share a value. A recorded pair therefore cannot tell "this is my process" from
/// "this is a stranger who inherited both numbers across a reboot", and the consequence of guessing
/// wrong is a SIGKILL to an arbitrary process.
///
/// REACHABLE, NOT THEORETICAL. `pods_root` is `$XDG_RUNTIME_DIR/kern/pods`, falling back to
/// `/run/user/<uid>`, which systemd hosts clear at boot. But `XDG_RUNTIME_DIR` is the user's to set,
/// and a value pointing anywhere persistent makes the whole pod store outlive a reboot.
///
/// ONE FILE SERVES BOTH MARKERS, rather than a third field in each, because `holder` and `pasta.id`
/// share a format and would need the same change twice. A mismatch means every pid in this dir
/// belongs to a boot that is over: nothing recorded here survived, so the safe action and the
/// correct action are the same one, which is to reap nothing and treat the pod as gone.
const POD_BOOT: &str = "boot";

/// What [`record_pod_boot`] writes when `boot_id` cannot be read: a positive fact about the host
/// rather than an absence to be interpreted.
///
/// WHY IT CANNOT COLLIDE, WRITTEN DOWN RATHER THAN LEFT TO BE RE-DERIVED. This is a sentinel living
/// in the same namespace as the real values, which is the shape that has bitten this project three
/// times: `0` reaching `kill` as the caller's own process group, `0` meaning unlimited where a real
/// cap was meant, and `st = 0` after a failed `waitpid` reading as "exited cleanly". Each was safe
/// until it was not. Here it is safe for a STRUCTURAL reason and not a lucky one: a `boot_id` is a
/// UUID, whose alphabet is hex digits and `-`, and this string contains neither a hex-only body nor
/// the shape. No boot id can ever equal it, so the two namespaces do not actually overlap.
const POD_BOOT_UNAVAILABLE: &str = "unavailable";

/// kern's OWN identity record for the pod's pasta: `pid:starttime`, the same format and the same
/// primitive as the holder marker.
///
/// It is a second file rather than a richer `pasta.pid` because `pasta.pid` is not kern's to shape:
/// pasta writes it itself, under `-P`, and its format is pasta's. Recording identity beside it keeps
/// the two halves of the pod's state symmetric - `holder` carries `pid:starttime`, `pasta.id` now
/// does too - and [`read_pid_file`] already parses that format for both.
const PASTA_ID: &str = "pasta.id";

/// How long to wait for pasta to write the pidfile it was given under `-P`, and how the wait grows.
///
/// pasta daemonizes: the parent kern waited on has exited by the time the spawn returns, and the
/// pidfile is written by the child that survives it. The two are not ordered, so the read is polled
/// rather than assumed. Failing to record identity is not fatal - it falls back to the `comm` check
/// that was the only guard before - so this is bounded and biased towards the fast case.
///
/// THE BACKOFF IS NOT COSMETIC, IT WAS MEASURED. A flat 2 ms first sleep cost `pod create` 1.6 ms
/// of its 15.9 (12 alternated pairs against the shipped binary), because the file is usually there
/// within a few hundred microseconds and the flat wait paid a full step to find out. Starting at
/// 250 us and doubling to a 4 ms ceiling keeps the common case near the true latency and still
/// reaches the same total budget for a pasta that is genuinely slow.
const PASTA_PID_POLL_FIRST: std::time::Duration = std::time::Duration::from_micros(250);
const PASTA_PID_POLL_CEIL: std::time::Duration = std::time::Duration::from_millis(4);
const PASTA_PID_POLL_BUDGET: std::time::Duration = std::time::Duration::from_millis(50);

/// How long [`stop_pasta`] waits for a no-watch pasta to leave before SIGKILL. pasta was measured
/// leaving about 30 ms after SIGTERM, so this is eight times its observed exit.
const PASTA_STOP_BUDGET_MS: u64 = 250;

/// Does this raw `/proc/<pid>/cmdline` belong to a kern pod holder?
///
/// POSITION, NOT PRESENCE, and the first version of this got it wrong. A cmdline is NUL-separated
/// argv, so matching "any argument equals the marker" already rejects `--flag=__pod-holder` and
/// `__pod-holder-ish`. It does NOT reject `kern box x -- echo __pod-holder`, where the marker is a
/// whole argument belonging to the WORKLOAD, and the test written to assert that case is what caught
/// it. Since the answer decides a `SIGKILL`, presence anywhere is too weak.
///
/// `create` spawns the holder as `<kern> __pod-holder`, so the marker is argv[1] and nowhere else,
/// and argv[0] must name a `kern`. Both are required: argv[1] alone would accept
/// `grep __pod-holder /proc/1/cmdline`, and argv[0] alone accepts every other kern subcommand.
/// argv[0]'s file name rather than its full path, so a holder started by a kern that has since been
/// reinstalled elsewhere is still recognised as one.
///
/// "NAMES A KERN" IS NOT THE SAME AS "IS LITERALLY CALLED kern", and comparing only against the
/// literal was a guess about how this binary is installed. `create` spawns the holder with
/// `std::env::current_exe()`, so argv[0] is whatever the installed file is actually called, and a
/// distribution or a user is free to call it something else. MEASURED: with the binary copied to
/// `getkern`, a holder whose netns inode could not be read was never identified and survived
/// `pod rm` for the life of the session, which is the same leak this function was added to close.
///
/// So both names are accepted: the literal, which also covers a holder started by a kern that has
/// since been reinstalled under a different name, and our own file name, which covers every name
/// the binary is actually shipped under.
fn cmdline_is_holder(cmdline: &[u8]) -> bool {
    let mut argv = cmdline.split(|c| *c == 0);
    let Some(arg0) = argv.next() else {
        return false;
    };
    let base = match arg0.iter().rposition(|c| *c == b'/') {
        Some(i) => &arg0[i + 1..],
        None => arg0,
    };
    let names_a_kern = base == b"kern" || Some(base) == self_exe_file_name().as_deref();
    names_a_kern && argv.next() == Some(HOLDER_ARGV.as_bytes())
}

/// This binary's own file name, for [`cmdline_is_holder`]. `None` if `current_exe` cannot be read,
/// in which case only the literal name is accepted: fewer processes recognised is the safe
/// direction, because the answer decides a `SIGKILL`.
fn self_exe_file_name() -> Option<Vec<u8>> {
    let exe = std::env::current_exe().ok()?;
    let name = exe.file_name()?;
    Some(std::os::unix::ffi::OsStrExt::as_bytes(name).to_vec())
}

/// Does this pid's argv carry kern's holder marker? IO wrapper over [`cmdline_is_holder`]; an
/// unreadable `/proc/<pid>/cmdline` (the process died, or it is another user's) answers no, because
/// "cannot read it" is not "it is ours".
/// DEPRECATED, AND ITS POPULATION IS SHRINKING TO ZERO. Since the `pid:starttime` holder marker
/// landed this is reached only from the `None` arm of [`holder_to_reap`], i.e. for a bare-pid marker
/// written by an older kern into a runtime dir that has survived the upgrade. Any pod created by a
/// current binary records the start-time and never takes this branch.
///
/// REMOVAL CONDITION, stated so this is not a back-compat path with no expiry: it can be deleted
/// once a bare marker can no longer be produced by a supported version, which is one release after
/// the marker became unconditional. The value it reads is argv, which the process it examines
/// controls, so what is being retired is a forgeable check - the reason to give it a date rather
/// than leave it to be noticed.
fn is_holder_argv(pid: i32) -> bool {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| cmdline_is_holder(&b))
        .unwrap_or(false)
}

/// Is `pid` recorded as the holder of some OTHER live pod? Used to refuse killing a sibling pod's
/// holder that happens to have recycled the number.
fn claimed_by_another_pod(pid: i32, except: &str) -> bool {
    let Ok(rd) = std::fs::read_dir(pods_root()) else {
        return false;
    };
    rd.flatten().any(|e| {
        let n = e.file_name();
        let other = n.to_string_lossy();
        other != except && read_pid_file(&e.path().join("holder")) == Some(pid)
    })
}

/// The holder to KILL, which is a different question from the one [`holder_pid`] answers.
///
/// `holder_pid` asks "may a box `setns` into this?", where any doubt must be a no, and that is right
/// for its callers. Its `None` therefore covers five situations and only two of them mean there is
/// nothing to kill:
///
///   the `holder` file is unreadable   -> a live holder may exist, and is about to become unnameable
///   the pid is <= 0                   -> nothing to kill
///   `kill(pid, 0)` fails              -> the process is already gone
///   the `netns` file is unreadable    -> cannot tell whose it is
///   the recorded netns inode differs  -> provably a stranger, and must NOT be killed
///
/// `teardown` used that `None` and then removed the directory anyway, so "cannot tell" became a
/// holder running for the life of the session with the only record of it deleted. MEASURED, not
/// imagined: one integration run left SEVEN behind, and two of them survived `kern pod rm` because
/// their directory was already gone and nothing could name them again.
///
/// So this identifies the PROCESS rather than trusting the inode alone. The netns inode stays the
/// fast path; the recorded start-time answers when it could not.
///
/// THE START-TIME IS THE IDENTITY, and argv is not. argv is forgeable: any process of this user can
/// make its own `/proc/self/cmdline` read `kern\0__pod-holder\0`, and the only other guard was a
/// scan of pod dirs, which by construction cannot see a pod whose dir has already been removed. The
/// start-time comes from the kernel, cannot be rewritten by the process, and differs for whatever
/// inherits the pid, so it answers the question the three previous name checks kept approximating.
///
/// A marker with no start-time has nothing to verify it against, so it falls back to argv rather
/// than leaking the holder outright.
///
/// WHERE ONE CAN COME FROM, checked by opening every writer rather than assumed: `create` is the
/// only production writer and it always writes `pid:starttime`, so this version cannot produce
/// one. A bare marker therefore means an older kern within this session, a hand edit, or a WRITE
/// THAT WAS TRUNCATED, which an external reviewer pointed out and which "an older kern" did not
/// cover. The last of those is the uncomfortable one: a torn write reaches the forgeable argv path
/// without anybody upgrading anything. It stays anyway, because the alternative is refusing to
/// reap and leaking the holder for certain, and the forgery still requires the attacker to hold
/// the pid that the truncated file names.
fn holder_to_reap(name: &str) -> Option<i32> {
    if let Some(pid) = holder_pid(name) {
        return Some(pid); // identity confirmed by the recorded netns inode
    }
    let dir = pod_dir(name);
    // The boot check comes before the pid is even read: after a reboot the number in this file
    // addresses a process that cannot be ours, and both remaining branches would compare
    // boot-relative values against a live stranger. See [`POD_BOOT`].
    if !pod_boot_is_current(&dir) {
        return None;
    }
    let pid = read_pid_file(&dir.join("holder"))?;
    if unsafe { libc::kill(pid, 0) } != 0 {
        return None;
    }
    match recorded_holder_starttime(&dir) {
        Some(want) => (crate::registry::proc_starttime(pid) == want).then_some(pid),
        // Back-compat only: a bare-pid marker predating this format.
        None => (is_holder_argv(pid) && !claimed_by_another_pod(pid, name)).then_some(pid),
    }
}

/// This boot's identity, or `None` when it cannot be read.
///
/// `boot_id` rather than `btime` from `/proc/stat`: it is a UUID regenerated per boot, so it cannot
/// collide across boots the way a wall-clock second can on a host whose clock steps backwards.
fn current_boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// What this pod dir's boot record permits. FOUR STATES, ONE MEANING EACH.
///
/// ONLY ONE OF THEM NEEDS A CURRENT READ, and that is the strongest property of this shape: the
/// answers live on disk. A host whose `boot_id` becomes unreadable between create and teardown
/// therefore degrades to a refusal rather than to a wrong verdict.
enum PodBoot {
    /// Written during the boot that is running now, OR no record at all. Absence is permissive and
    /// permanently so: a dir with no [`POD_BOOT`] predates this record, and refusing to reap it
    /// would leak a holder and a pasta that really are ours for the life of the session, which is
    /// the exact harm the marker exists to prevent, inflicted by the marker.
    Attributable,
    /// A different boot id, or a real one that cannot be compared because `boot_id` is unreadable
    /// NOW. Either way this pid belongs to a boot that is over, or to one we cannot prove is this
    /// one. A torn write lands here by construction.
    NotThisBoot,
    /// [`POD_BOOT_UNAVAILABLE`]: the host could not read `boot_id` when the pod was created, so
    /// nothing in this dir can be attributed to a boot AT ALL.
    ///
    /// THIS USED TO BE PERMISSIVE, AND THAT WAS THE DEFECT. The reasoning was that a host which
    /// cannot evaluate the guard should not lose the ability to tear pods down. But it makes the
    /// state in which kern knows the LEAST the only one that authorises a kill on `pid:starttime`
    /// alone - and both of those fields are boot-relative, which is the entire reason this record
    /// exists. Measured by an external reviewer on WSL2, varying only this file against a live
    /// stranger whose `pid:starttime` matched: every unknown state was conservative except the one
    /// string kern writes itself, and there the stranger was killed in three runs out of three.
    ///
    /// It is the same shape as the enforcement warning that read the supervisor's cgroup: a guard
    /// defaulting to "everything is fine" from a read that never succeeded.
    ///
    /// THE TRADE, TAKEN DELIBERATELY. Refusing here leaks a pasta on every teardown on such a host.
    /// That leak is visible and recoverable and its pid can be printed; killing a stranger's process
    /// is silent and final. `boot_id` has existed since 2.6.19, so this branch is rare, and paying a
    /// rare visible leak to remove a rare silent kill is the trade this project has taken every
    /// other time it has been offered.
    Unattributable,
}

/// Read this pod dir's boot record. See [`PodBoot`] for what each answer means.
fn pod_boot(dir: &std::path::Path) -> PodBoot {
    let Ok(recorded) = std::fs::read_to_string(dir.join(POD_BOOT)) else {
        return PodBoot::Attributable; // no record: a pod from before this existed
    };
    let recorded = recorded.trim();
    if recorded == POD_BOOT_UNAVAILABLE {
        return PodBoot::Unattributable;
    }
    match current_boot_id() {
        None => PodBoot::NotThisBoot, // a real boot id was recorded and cannot be compared against
        Some(now) if recorded == now => PodBoot::Attributable,
        Some(_) => PodBoot::NotThisBoot,
    }
}

/// May this pod dir's recorded pids be signalled at all? The predicate the decision paths use.
fn pod_boot_is_current(dir: &std::path::Path) -> bool {
    matches!(pod_boot(dir), PodBoot::Attributable)
}

/// Record the boot this pod dir belongs to. Written once at create, atomically, for the same reason
/// the holder marker is: a torn value must read as a mismatch and never as a match.
///
/// CALLED FIRST, AHEAD OF EVERY FALLIBLE STEP IN `create`, and that ordering claim lives HERE rather
/// than at the call site on purpose. It was written at the call site once; when the call moved, the
/// comment stayed with the LOCATION and not with the CALL, and went on describing an ordering sixty
/// lines from the one it named. A claim about when a function runs belongs to the function, which
/// travels with it.
///
/// What the ordering buys: between the `mkdir` that claims the pod dir and this call there must be
/// nothing that can return early, because every such path exits with the DIRECTORY ALREADY CREATED
/// and no record in it - the one state [`pod_boot_is_current`] cannot distinguish from a legacy dir.
/// Two `?` returns used to sit in that gap.
///
/// FAIL-FAST, UNLIKE EVERY OTHER MARKER WRITE HERE, and the ordering above is why. Writing this before the holder marker is what guarantees a dir can never hold a pid without
/// the boot that pid belongs to - but a `let _ =` write that ERRORS and lets creation proceed
/// produces exactly the unqualified marker the ordering exists to prevent, and
/// [`pod_boot_is_current`] then trusts it as legacy. A failure to write is therefore a failure to
/// create the pod.
///
/// An unreadable `boot_id` WRITES [`POD_BOOT_UNAVAILABLE`] rather than nothing, and that sentinel is
/// what keeps "absent" meaning one thing.
///
/// Leaving the file out was the first cut, and it merged two states that need opposite answers: a
/// dir from a kern that predates this record, and a dir from a current kern on a host that cannot
/// read `boot_id`. Both read as absent, so any rule for one is wrong for the other - which is why
/// the question of what to do with an absent record could be argued both ways indefinitely. With the
/// sentinel, absent means NOTHING WROTE HERE, and the host that genuinely cannot evaluate the guard
/// says so on disk instead of being inferred from a gap.
///
/// Failing `pod create` on such a host is not the alternative: that trades a defect nobody has hit
/// for a product that does not run, and failing `pod rm` later is the same trade arriving worse,
/// with the pods already created and now unreapable.
fn record_pod_boot(dir: &std::path::Path) -> Result<(), Error> {
    let id = current_boot_id().unwrap_or_else(|| POD_BOOT_UNAVAILABLE.to_string());
    let tmp = dir.join("boot.new");
    std::fs::write(&tmp, id).map_err(|e| Error::Sandbox(format!("pod boot record: {e}")))?;
    // Same directory, so the rename is the atomic replace it looks like.
    std::fs::rename(&tmp, dir.join(POD_BOOT)).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        Error::Sandbox(format!("pod boot record: {e}"))
    })
}

/// The WHOLE `pasta.id` record as `(pid, starttime)`, or `None` when there is none: a pod created
/// before this record existed, or one whose write did not land.
///
/// BOTH HALVES, not just the start-time. The pid this record names and the pid teardown acts on come
/// from DIFFERENT FILES - `pasta.id` is kern's, `pasta.pid` is pasta's - so reading only the
/// start-time compares a number from one file against a process identified by the other, and the two
/// can disagree. The holder marker does not have this shape: its pid and its start-time are the two
/// halves of one file, so `read_pid_file` already refuses a record with an empty pid.
///
/// Found by a test asserting that no partial write parses: `":1082818"` read as a valid start-time
/// while naming no process at all.
/// WHY THE RECORD CARRIES A PID AT ALL, since `pasta.pid` already names one: it is what re-couples
/// two files into one identity. An identity assembled from two sources where only one is validated
/// is the defect this shape had - kern's start-time paired with pasta's pid, and nothing asserting
/// the two describe the same process. Dropping the pid here as redundant would restore it.
fn recorded_pasta_identity(dir: &std::path::Path) -> Option<(i32, u64)> {
    let raw = std::fs::read_to_string(dir.join(PASTA_ID)).ok()?;
    let (pid, started) = raw.trim().split_once(':')?;
    let pid: i32 = pid.parse().ok()?;
    if pid <= 0 {
        return None;
    }
    Some((pid, started.parse().ok()?))
}

/// Does ANOTHER pod's `pasta.pid` name this pid? The pasta-side twin of [`claimed_by_another_pod`],
/// and it closes the case that made it necessary here.
///
/// Every pasta on the host has `comm == "pasta"`, so the family check cannot tell one pod's NAT from
/// another's. If pod A's recorded pid has been recycled onto pod B's pasta, A's teardown would find
/// a live process whose `comm` says pasta, SIGTERM it, and - with no [`PASTA_WATCHED`] marker -
/// escalate to SIGKILL on B's working NAT. The holder side has been guarded against exactly this
/// since the marker landed; this side had nothing.
fn claimed_by_another_pasta(pid: i32, except: &str) -> bool {
    let Ok(rd) = std::fs::read_dir(pods_root()) else {
        return false;
    };
    rd.flatten().any(|e| {
        let n = e.file_name();
        let other = n.to_string_lossy();
        other != except && read_pid_file(&e.path().join("pasta.pid")) == Some(pid)
    })
}

/// Record `pid:starttime` for the pasta just started for this pod. Best-effort throughout: every
/// failure leaves the record absent, which is the state [`pasta_to_signal`] already handles.
fn record_pasta_identity(dir: &std::path::Path) {
    let pidfile = dir.join("pasta.pid");
    let mut waited = std::time::Duration::ZERO;
    let mut step = PASTA_PID_POLL_FIRST;
    loop {
        if let Some(pid) = read_pid_file(&pidfile) {
            let started = crate::registry::proc_starttime(pid);
            // A zero start-time means `/proc/<pid>/stat` could not be read or parsed, and writing
            // `pid:0` would be worse than writing nothing: teardown would compare against a value
            // no live process can have and decline to signal a pasta that is really ours.
            if started != 0 {
                // ATOMIC, for the reason the holder marker is: a torn `471621:` parses as absent
                // and silently drops the pod to the weaker fallback, which is indistinguishable
                // from an old-format record. `.new` + rename in the same directory removes the
                // ambiguity, so a bare record provably means an older kern and nothing else.
                let tmp = dir.join("pasta.id.new");
                if std::fs::write(&tmp, format!("{pid}:{started}")).is_ok()
                    && std::fs::rename(&tmp, dir.join(PASTA_ID)).is_err()
                {
                    let _ = std::fs::remove_file(&tmp);
                }
            }
            return;
        }
        if waited >= PASTA_PID_POLL_BUDGET {
            return; // no record; `pasta_to_signal` falls back, which is the prior behaviour
        }
        std::thread::sleep(step);
        waited += step;
        step = (step * 2).min(PASTA_PID_POLL_CEIL);
    }
}

/// The pasta this pod may signal, or `None` when the recorded pid is not the process kern started.
///
/// Mirrors [`holder_to_reap`] deliberately, including the shape of the fallback: identity by
/// start-time when it was recorded, and the weaker pair of checks only for a pod that predates the
/// record. The weaker branch is the one the recycled-pid case lives in, so it carries the
/// cross-pod claim check rather than the family check alone.
fn pasta_to_signal(name: &str, dir: &std::path::Path, pid: i32) -> Option<i32> {
    if pid <= 0 {
        return None;
    }
    if !pod_boot_is_current(dir) {
        return None; // every pid recorded here belongs to a boot that is over
    }
    match recorded_pasta_identity(dir) {
        // The record must name THIS pid and that pid must still carry the recorded start-time. A
        // record naming a different pid is not evidence about this one, so it decides nothing and
        // must not silently authorise: it refuses.
        Some((want_pid, want_start)) => {
            (want_pid == pid && crate::registry::proc_starttime(pid) == want_start).then_some(pid)
        }
        // NO RECORD: a pod dir from before `pasta.id` existed, which is this branch's whole
        // population. Three checks, and all three are needed: `comm` says "a pasta", the argv says
        // "ours", the scan says "not another pod's". A missing holder file leaves nothing to tie the
        // process to this pod, so it declines rather than falling back to the two weaker halves.
        None => (pid_is_pasta(pid)
            && read_pid_file(&dir.join("holder")).is_some_and(|h| pasta_argv_names_pod(pid, h))
            && !claimed_by_another_pasta(pid, name))
        .then_some(pid),
    }
}

/// The process state out of a `/proc/<pid>/stat` body, or `None` if it does not parse.
///
/// The state is the first field AFTER the last `)`, never the third whitespace-separated token:
/// `comm` is parenthesised and may itself contain spaces and parentheses, so splitting from the left
/// misparses any process whose name has one. Split out as a pure function so that case is testable
/// without a process that has such a name.
fn stat_state(stat: &str) -> Option<&str> {
    stat.rsplit_once(')')?.1.split_whitespace().next()
}

/// Is this pid a zombie - exited, not yet reaped?
///
/// `comm` outlives the process it named until the parent reaps it, unlike `cmdline`, which empties.
/// So a pasta that has already died still passes the family check, takes a SIGTERM nothing receives,
/// and then - because `kill(pid, 0)` succeeds on a zombie - runs the full escalation budget before a
/// SIGKILL that also does nothing. The outcome was always correct; the cost was 250 ms of polling
/// spent on a process that had already gone.
fn proc_is_zombie(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| stat_state(&s).map(|st| st == "Z"))
        .unwrap_or(false)
}

/// The start-time half of the `pid:starttime` holder marker, or `None` for a bare-pid marker.
fn recorded_holder_starttime(dir: &std::path::Path) -> Option<u64> {
    let raw = std::fs::read_to_string(dir.join("holder")).ok()?;
    raw.trim().split_once(':')?.1.parse().ok()
}

/// Is a concurrent `pod create` still mid-startup for this dir? True iff the `starting` marker names
/// a live PID **whose kernel start-time still matches** - so a stale marker whose pid was reused by an
/// unrelated process reads as dead, not as a live starter. Used only to make two racing
/// `pod create <same>` safe: the mkdir loser must not reclaim the dir while the winner's holder is
/// still coming up (its `holder` pid isn't written yet).
fn starter_alive(dir: &std::path::Path) -> bool {
    let Ok(marker) = std::fs::read_to_string(dir.join("starting")) else {
        return false;
    };
    let marker = marker.trim();
    // `pid:starttime` (new) or a bare `pid` (older marker) - parse whichever is present.
    let (pid_s, want_start) = marker.split_once(':').unwrap_or((marker, ""));
    let Ok(pid) = pid_s.parse::<i32>() else {
        return false;
    };
    // `kill(0, 0)` and `kill(-1, 0)` both SUCCEED, so a marker holding 0 or -1 would read as a live
    // process; with a bare-pid marker the back-compat arm below then answers `true` outright.
    if pid <= 0 {
        return false;
    }
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false; // no such live process
    }
    match want_start.parse::<u64>() {
        Ok(s) => crate::registry::proc_starttime(pid) == s, // reject a reused pid
        Err(_) => true, // bare-pid marker: liveness only (back-compat)
    }
}

/// `kern pod create <name> [--no-outbound] [--uid-range]` - spawn the pod's namespace holder + seed its
/// hosts, and (unless `--no-outbound`, and if pasta is installed) attach pasta for internet egress.
/// Publish a service with `-p` on its member box. `uid_range` maps a subordinate uid RANGE into the
/// pod's shared user namespace (via the holder) instead of the single-uid self-map - needed when the
/// pod hosts OCI images that drop privilege in their entrypoint (postgres/redis/…). `kern compose`
/// passes `ImageDefault` when the stack has image boxes and `Requested` when a service asked in as
/// many words; a pod of root-only services stays single-uid (faster, more isolated).
pub fn create_with_range(
    name: &str,
    want_outbound: bool,
    uid_range: kern_isolation::UidRange,
    bridge: Option<&str>,
) -> Result<(), Error> {
    validate_name(name)?;
    let dir = pod_dir(name);
    let _ = std::fs::create_dir_all(pods_root()); // ensure the parent exists (recursive)

    // ATOMICALLY claim the pod by a NON-recursive 0700 mkdir: two concurrent `pod create <same>`
    // can't both proceed (the loser gets AlreadyExists). Private (0700): another local user must not
    // read/alter a pod's hosts or holder pid. A leftover dead pod dir (holder gone) is reclaimed.
    if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            // A live holder means a real, running pod. A live `starting` marker means a CONCURRENT
            // `pod create` is mid-startup (it won the mkdir but hasn't written its holder pid yet).
            // In BOTH cases refuse: never stomp an in-progress claim, or we'd orphan the winner's
            // holder. Only a genuinely dead leftover (no holder AND no live starter) is reclaimed.
            //
            // The winner writes its `starting` marker microseconds after winning the mkdir - but on a
            // slow host that gap widens to milliseconds, so a naive single check here can race in and
            // see neither holder nor starter *before* the winner marks itself. Poll briefly (bounded)
            // before concluding the dir is dead: a live winner appears within a few ms; a genuinely
            // dead leftover (creator crashed pre-marker) stays empty and is reclaimed after the wait.
            let claimed = || holder_pid(name).is_some() || starter_alive(&dir);
            let mut alive = claimed();
            for _ in 0..20 {
                if alive {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
                alive = claimed();
            }
            if alive {
                return Err(Error::Sandbox(format!("pod '{name}' already exists")));
            }
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(|e| Error::Sandbox(format!("pod dir: {e}")))?;
        } else {
            return Err(Error::Sandbox(format!("pod dir: {e}")));
        }
    }
    // First after the claim, and nothing fallible may be inserted above it: see `record_pod_boot`,
    // which owns that argument so it cannot be separated from the call again.
    record_pod_boot(&dir)?;
    // Mark this claim as in-progress with OUR `pid:starttime`, BEFORE the (slow) holder startup, so a
    // concurrent loser above sees a live starter and backs off instead of reclaiming a half-built pod.
    // The start-time pins the pid's identity (as the registry does for supervisors) so a stale marker
    // whose pid was later reused by an unrelated process can't wedge `pod create` shut.
    let me = unsafe { libc::getpid() };
    let _ = std::fs::write(
        dir.join("starting"),
        format!("{me}:{}", crate::registry::proc_starttime(me)),
    );
    // Seed the shared /etc/hosts. Every member box bind-mounts this; members are appended on join.
    // BYTE-IDENTICAL to `LOCALHOST_SEED` in the isolation crate, including `localhost` being on the
    // IPv4 line only: the two files are the same fact, and a pod member and a standalone box must
    // not disagree about what `localhost` resolves to. See that constant for the measurement.
    std::fs::write(
        hosts_path(name),
        "127.0.0.1\tlocalhost\n::1\tip6-localhost ip6-loopback\n",
    )
    .map_err(|e| Error::Sandbox(format!("pod hosts: {e}")))?;

    // Spawn the holder: a detached `kern __pod-holder` that unshares + holds the pod user+net ns and
    // prints `pod-ready` once its namespaces are set up. We read that line, then record its PID.
    let self_exe = std::env::current_exe()
        .map_err(|e| Error::Sandbox(format!("cannot locate the kern binary: {e}")))?;
    let mut cmd = std::process::Command::new(self_exe);
    cmd.arg("__pod-holder")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .process_group(0); // its own session/group so it survives this command exiting
                           // WHERE THE POD LIVES, so the holder can stop holding when the pod stops existing. Without it a
                           // holder that outlives its own directory - a deleted runtime dir, a `/run/user/<uid>` cleaned on
                           // logout, a test harness removing its temporary tree - keeps a user and net namespace alive that
                           // nothing can name, address or remove, for the life of the session. MEASURED: 140 such holders
                           // and 116 `pasta` beside them, the oldest 5.8 hours old. See `hold_until_the_pod_is_gone`, which
                           // treats a missing variable as "hold forever" so an older holder keeps its old behaviour.
    cmd.env("KERN_POD_DIR", pod_dir(name));
    if uid_range.is_on() {
        // Tell the holder to map a subordinate uid range (so member OCI images can drop privilege),
        // and WHY, so it only reports an unavailable range the caller actually asked for.
        cmd.env("KERN_POD_UID_RANGE", uid_range.as_env());
    }
    // A BRIDGE POD, where each member keeps its own network namespace and loopback. Passed by
    // environment for the reason the uid range is: the holder is a forked process and this is the
    // channel that already exists for telling it what kind of pod it is holding.
    if let Some(cidr) = bridge {
        cmd.env("KERN_POD_BRIDGE", cidr);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::Sandbox(format!("pod holder: {e}")))?;
    let pid = child.id() as i32;
    // Wait for the holder's `pod-ready` line, but BOUNDED: a holder that wedges during namespace setup
    // (a host/kernel quirk) must NOT hang `pod create` - and with it the whole `compose up` - forever.
    // A reader thread does the blocking `read_line`; if no answer arrives within the timeout we treat
    // the holder as failed, kill it, and error, instead of an unbounded wait on a child's readiness.
    let ready = child.stdout.take().is_some_and(|mut out| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            std::io::BufReader::new(&mut out).read_line(&mut line).ok();
            let _ = tx.send(line.trim() == "pod-ready"); // receiver may be gone on timeout - ignore
        });
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .unwrap_or(false)
    });
    if !ready {
        // DO NOT GUESS A CAUSE THE HOLDER ALREADY NAMED. This said "unprivileged user namespaces may
        // be unavailable" whatever went wrong, and the holder's stderr is INHERITED, so its own
        // diagnosis is already on the reader's terminal one line above. MEASURED on a host where user
        // namespaces work perfectly: `pod create --bridge 127.0.0.0/8` printed the holder's exact
        // refusal and then this sentence, which sent the reader to look at a kernel setting that had
        // nothing to do with it.
        //
        // The two cases are distinguishable and mean different things: a holder that EXITED decided
        // something and said why, while one still running after the timeout is wedged and said
        // nothing, which is the only case where a host-capability guess is worth making.
        let exited = child.try_wait().ok().flatten().is_some();
        let _ = child.kill();
        let _ = std::fs::remove_dir_all(&dir); // also drops the `starting` marker
        return Err(Error::Sandbox(
            if exited {
                "the pod holder exited before the pod was ready - it printed the reason above"
            } else {
                "the pod holder never signalled ready and is still running after 10s: namespace \
                 setup is wedged on this host (unprivileged user namespaces may be unavailable). \
                 `kern doctor` reports what this host allows"
            }
            .into(),
        ));
    }
    // Record the holder PID + its net ns inode (identity, to reject a later PID reuse). Write the
    // inode FIRST so a concurrent lookup never sees a holder pid without its verifier.
    if let Some(ino) = ns_inode(pid, "net") {
        let _ = std::fs::write(dir.join("netns"), ino.to_string());
    }
    // `pid:starttime`, the same marker shape `starting` already uses. The start-time is what makes
    // this an IDENTITY rather than a number: it is assigned by the kernel, cannot be rewritten by
    // the process, and differs for whatever inherits the pid later. Three versions of a name-based
    // check preceded it (`comm`, then argv presence, then argv position plus our own file name),
    // and each fixed one hole and kept the class, which is the signal that the name was the wrong
    // key. Measured against the last of them: after a package-style `mv` over the binary,
    // `/proc/self/exe` reads `... (deleted)`, so `current_exe`'s file name stops matching during
    // exactly the upgrade window in which teardown matters.
    // WRITTEN ATOMICALLY, and not for the reason it usually is. A torn write of twenty bytes on a
    // tmpfs is not a likely failure; what matters is that a PARTIAL write produces a bare `pid`
    // with no start-time, which is indistinguishable from the marker an older kern wrote, and
    // `holder_to_reap` sends that form down the argv path it otherwise never takes. The comment
    // there says "back-compat only", and until this rename that claim was false: the forgeable
    // path was reachable with nobody upgrading anything. One `rename` makes the sentence true.
    let holder_marker = format!("{pid}:{}", crate::registry::proc_starttime(pid));
    let holder_tmp = dir.join("holder.new");
    std::fs::write(&holder_tmp, holder_marker)
        .map_err(|e| Error::Sandbox(format!("pod holder pid: {e}")))?;
    // Same directory, so the rename is within one filesystem and is the atomic replace it looks
    // like. A failure here leaves `holder.new` behind, which no reader looks for and `teardown`
    // removes with the directory.
    std::fs::rename(&holder_tmp, dir.join("holder"))
        .map_err(|e| Error::Sandbox(format!("pod holder pid: {e}")))?;
    let _ = std::fs::remove_file(dir.join("starting")); // claim complete: holder pid is now recorded
                                                        // The holder is detached (own process group, reparented to init on our exit) and runs until
                                                        // `kern pod rm`. `forget` just drops our `Child` handle without any wait/kill (std never reaps or
                                                        // signals on drop) - the stdout pipe was already `.take()`n, so nothing leaks.
    std::mem::forget(child);
    // OUTBOUND (default, opt-out with `--no-outbound`): if `pasta` (passt) is installed, attach it to
    // the pod net ns for NAT'd internet egress + DNS. Best-effort: absent/failed → loopback-only.
    // `None` means "not attempted" (`--no-outbound`), and each `Some` is a real outcome. The
    // alternative was a dummy `Outbound` value standing in for "not consulted", which is a lie the
    // type would then carry to every reader of the match below.
    let outbound = want_outbound.then(|| setup_outbound(name, pid));
    println!("created pod '{name}'");
    println!(
        "  add boxes: kern box <name> --pod {name} -d -- …  (publish a service with -p on its box)"
    );
    // One line per CAUSE. This was one line for five different states, and the one it printed told
    // a user with pasta installed to install pasta.
    match outbound {
        None => {
            println!("  network: loopback-only (--no-outbound) - services reach each other; no egress")
        }
        Some(Outbound::Up) => {
            println!("  network: services reach each other by name + outbound to the internet (pasta)")
        }
        Some(Outbound::NotInstalled) => println!(
            "  network: loopback-only - services reach each other; NO outbound (install `passt`/`pasta` for egress)"
        ),
        Some(Outbound::Failed(why)) => println!(
            "  network: loopback-only - services reach each other; pasta IS installed but did not \
             start: {why}"
        ),
        Some(Outbound::NoDns) => println!(
            "  network: outbound is up but DNS is not - the pod can reach an IP and cannot resolve \
             a name (kern could not write the pod's resolv.conf)"
        ),
    }
    Ok(())
}

/// Attach `pasta` (passt) to the pod's net ns for NAT'd outbound + DNS, and seed the pod's
/// `resolv.conf`. Returns `true` only when outbound AND DNS are actually up (so `create`'s message
/// is honest). Best-effort: no pasta / any failure → `false` (the pod stays loopback-only). pasta
/// backgrounds itself and exits automatically when the net ns is freed (at `pod rm`).
/// pasta's automatic port mapping, OFF in all four directions.
///
/// pasta defaults every one of these to `auto`, which is not merely redundant with kern's own
/// publishing - it breaks it:
///
///  * `-t auto` (host → ns) re-scans host-bound ports on a timer and binds the matching port INSIDE
///    the pod net ns. kern's forwarder binds the HOST side of every `-p`, so ~1-2 s after a box
///    starts pasta claims that port in the ns and the service trying to listen there gets EADDRINUSE.
///    Measured on the shipped binary: a service binding within ~1 s won the race, one binding at >=2 s
///    always lost - i.e. every real app (node, django, postgres) failed to serve its own published
///    port while `compose up` still reported success. A silent partial failure, at runtime.
///  * `-T auto` (ns → host) would publish in-pod ports on the host with no `-p` at all, contradicting
///    kern's EXPLICIT-PUBLISH model: a port reaches the host because a `-p` said so, never because
///    a service happened to bind it. Off by construction rather than by timing. (The bind ADDRESS a
///    `-p` gets is Docker's `0.0.0.0` now; what has not changed is that something has to say `-p`.)
///
/// Publishing stays entirely kern's job ([`crate::ports`] → `fork_forwarders`: bind the host port,
/// `setns` into the box per connection). pasta is left doing exactly what it is here for: NAT'd
/// egress + DNS.
const PASTA_NO_PORT_MAP: [&str; 8] = ["-t", "none", "-u", "none", "-T", "none", "-U", "none"];

/// The exact argv passed to `pasta` for a pod, as a pure function of the pod dir + holder PID, so the
/// invariants above are unit-testable without spawning anything. `--config-net` copies the host's
/// addresses/routes into the ns tap and NATs outbound; pasta then daemonizes (the spawned process
/// exits once setup is done). `-q` quiets it, `-P` records its PID for teardown.
///
/// `watch_netns == false` adds `--no-netns-quit`, which is the SECOND attempt and never the first.
/// STRACED, not assumed: with the watch on, pasta opens the netns file, the userns file, AND the
/// DIRECTORY that holds them, in that order, immediately before it touches `/dev/net/tun`:
///
///   openat("/proc/<holder>/ns/user", O_RDONLY) = 6
///   openat("/proc/<holder>/ns/net",  O_RDONLY) = 6
///   openat("/proc/<holder>/ns",      O_RDONLY) = 16   <- only for the quit watch
///   openat("/dev/net/tun",           O_RDWR)   = 18
///
/// With `--no-netns-quit` the third line is gone and the fourth takes its place at the same point in
/// the sequence. That open is what a Fedora 43 host under Lima refused with `netns dir open:
/// Permission denied, exiting`, leaving the pod loopback-only (#6).
///
/// "AND NOTHING ELSE" WAS WRONG, and it said so here until an external reviewer asked for the trace
/// that was never taken: the first pass filtered on `openat`, so it could only ever have found an
/// open. Diffing the FULL syscall set of both runs, the flag removes four things, not one:
///
///   openat("/proc/<holder>/ns", …)    the directory the watch would monitor
///   fstatfs                            whether that filesystem can be watched at all
///   timerfd_create + timerfd_settime   the polling fallback when it cannot
///
/// All four are the watch and nothing but the watch, so the claim the retry rests on still holds.
/// The claim that was made is not the claim that was measured, which is the difference this note
/// exists to record. (No `inotify_*` in either run on this host: passt took the timer fallback.)
///
/// WHAT THE FLAG COSTS. pasta no longer exits by itself when the netns disappears, so `teardown`
/// becomes the only thing that reaps it. That is why the pasta kill there is no longer conditional
/// on the holder still being alive: with the watch off, a holder that dies outside teardown would
/// otherwise leave pasta running forever.
fn pasta_args(dir: &std::path::Path, holder: i32, watch_netns: bool) -> Vec<std::ffi::OsString> {
    let mut a: Vec<std::ffi::OsString> = Vec::with_capacity(16);
    a.push("--config-net".into());
    a.push("-q".into());
    a.push("-P".into());
    a.push(dir.join("pasta.pid").into());
    a.extend(PASTA_NO_PORT_MAP.iter().map(Into::into));
    if !watch_netns {
        a.push("--no-netns-quit".into());
    }
    a.push("--userns".into());
    a.push(format!("/proc/{holder}/ns/user").into());
    a.push("--netns".into());
    a.push(format!("/proc/{holder}/ns/net").into());
    a
}

/// Does this pasta stderr name the netns-directory open, the one thing `--no-netns-quit` removes?
///
/// NARROW ON PURPOSE. Retrying on any failure would hide the real ones behind a second attempt that
/// changes an unrelated variable; this matches pasta's own string for the single operation the flag
/// elides, so a pod that fails for any other reason still fails once, loudly, with its own message.
///
/// AN EXTERNAL REVIEWER READ THE OTHER PERMISSION STRINGS OUT OF THE BINARY and asked whether these
/// should retry too:
///
///   Couldn't open network namespace %s: %s
///   Couldn't open user namespace %s: %s
///   setns() failed entering netns: %s
///
/// They should not, and the trace says why rather than the argument: `/proc/<holder>/ns/net` and
/// `/proc/<holder>/ns/user` are opened in BOTH runs, with the watch and without it, and `setns` is
/// not part of the watch at all. A host that refuses those refuses them identically on the retry, so
/// widening the match would spend a second attempt that cannot succeed and would bury the real
/// reason under a second copy of itself. The narrowness is the measurement, not caution.
fn is_netns_dir_denial(stderr: &str) -> bool {
    stderr.contains("netns dir open")
}

/// pasta's stderr as ONE reportable sentence.
///
/// Scrubbed like every other borrowed string kern prints: pasta is a local binary and not the threat
/// model that `crate::ui::scrub` was written for, but the filter is free and the alternative is one
/// unscrubbed path that the next reader has to reason about.
///
/// EVERY line, not the first. pasta's message is the whole diagnosis and taking one line of it is
/// wrong whenever the first line is not the error. Measured on WSL2, where pasta prints five lines
/// and the first is informational:
///
///   Started as root, will change to nobody.        <- what kern used to report
///   No interfaces with usable IPv6 routes
///   Couldn't pick external interface: disabling IPv6
///   Could not open /proc/self/uid_map: Permission denied   <- the actual cause
///   Couldn't configure user mappings
///
/// A reader given only the first line is told something true and useless, and would go looking at
/// privilege dropping instead of uid maps. Joined with "; " and capped, so a pasta that decides to
/// be verbose cannot flood the line either.
fn pasta_reason(stderr: &[u8]) -> String {
    let joined = String::from_utf8_lossy(stderr)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    crate::ui::scrub(if joined.is_empty() {
        "no output"
    } else {
        &joined
    })
    .chars()
    .take(300)
    .collect::<String>()
}

/// Why a pod did or did not get outbound. One `bool` used to cover all of these, and `create`
/// printed the same "install `passt`/`pasta` for egress" line for every one of them - including to
/// someone who had `pasta` installed and whose real problem was that it refused to start. Measured
/// on WSL2 with `/usr/bin/pasta` present: the pod came up loopback-only and was told to install the
/// thing it already had, while pasta's own explanation went to `/dev/null`.
enum Outbound {
    /// NAT and DNS are both up.
    Up,
    /// No `pasta` on PATH: the one case the old message actually described.
    NotInstalled,
    /// `pasta` is installed and did not start. Carries its first line of stderr when it produced
    /// one, because that line is the only thing here that says WHY.
    Failed(String),
    /// The NAT attached but the pod's `resolv.conf` could not be written: addresses work, names do
    /// not. Reporting this as "no outbound" was wrong in the other direction.
    NoDns,
}

/// How long pasta gets to return before it is treated as wedged.
///
/// pasta daemonises and normally returns in about 30 ms, so ten seconds is not a deadline it can
/// miss by being slow. It matches the bound `create` already puts on the holder handshake, so both
/// spawns in this file now fail the same way rather than one of them not failing at all.
const PASTA_SPAWN_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

/// `Command::output`, but it gives up.
///
/// WHAT THIS IS AND IS NOT, because the first version of this comment claimed more than had been
/// measured. `output()` waits for the pipes to reach EOF and then reaps, so it can be held open by
/// a daemonising child that inherits the write end rather than by a child that fails to exit.
/// Measured on a live pod: real pasta closes every descriptor and calls `setsid`, so the recorded
/// pasta has an EMPTY `/proc/<pid>/fd` and its own session. The pipe therefore reaches EOF and the
/// normal path returns in about 30 ms. A hang through the inherited pipe was NOT observed here.
///
/// What was observed is that the wait is unbounded, so anything that does wedge, before daemonising
/// or during it, hangs `kern pod create` with nothing printed and no way out but Ctrl-C, and
/// through `compose up` that is a whole stack. The SHIPPED v0.9.2 hangs the same way, so the SELinux
/// retry did not introduce it; the retry doubles the number of chances to meet it. This bound is
/// insurance against that class, not a fix for a failure seen in the field.
///
/// A CONSEQUENCE WORTH KNOWING: because pasta calls `setsid`, a timeout can no longer reach a pasta
/// that has already daemonised, and it should not try to. If the direct child wedges AFTER the
/// daemon is up, the NAT is working and this reports failure. Nothing kills the working daemon,
/// which is the safe half of that trade, and `pasta_alive` still reads the truth from the pidfile.
///
/// The wait happens on a thread so the pipes are drained concurrently, which is what `output()`
/// does and what keeps a chatty child from deadlocking against a full pipe buffer.
///
/// PRECONDITION: A TIMEOUT LEAKS A THREAD, a `Child` and two pipe fds, for the life of the
/// PROCESS. The thread stays blocked in `wait_with_output` until the `SIGKILL` lands, and if the
/// signal never lands it stays blocked forever.
///
/// "Bounded because `pod create` is short-lived" was the first version of this line and it was
/// wrong, which an external reviewer caught by reading the callers rather than this function.
/// `compose up` reaches here through `create_with_range` at `commands/compose.rs` and then keeps
/// going: it starts every box and waits on the health gates. So the bound is THIS KERN
/// INVOCATION, and the longest one is a compose bring-up, not a `pod create` that returns as soon
/// as pasta is attached.
///
/// What does bound it, and is worth stating because it was not: AT MOST ONE PER INVOCATION. A
/// timeout returns `Err`, and `setup_outbound`'s retry fires only on `Ok` carrying the netns-dir
/// refusal, so a timed-out attempt is never followed by a second one. Each `pod create` creates
/// one pod, so a single leaked thread is the ceiling however long the process then runs.
///
/// Do not call this from a daemon without fixing that first.
fn output_within(
    cmd: &mut std::process::Command,
    limit: std::time::Duration,
) -> std::io::Result<std::process::Output> {
    // Its own process group, which is no longer about the kill: that was the reason when this
    // signalled `-pid`, and it does not any more. It stays because it detaches the child from
    // kern's group, so a Ctrl-C on kern's terminal does not also interrupt a pasta that is coming
    // up. `create` gives the holder its own group for the same reason.
    let child = cmd.process_group(0).spawn()?;
    let pid = child.id() as i32;
    // A pidfd PINS the process: while it is open the kernel will not recycle the number. That
    // closes the interleaving where the thread's `wait_with_output` completes, the pid is freed and
    // handed to an unrelated process, and `recv_timeout` expires microseconds later and signals it.
    // Nothing serialises those two, so the window is real rather than theoretical. `-1` on kernels
    // older than 5.3, where the fallback below accepts that window rather than doing nothing.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let outcome = rx.recv_timeout(limit);
    let result = match outcome {
        Ok(result) => result,
        Err(_) => {
            // THE PROCESS, AND ONLY THE PROCESS. An earlier version also sent `kill(-pid,
            // SIGKILL)` to sweep up anything the child had started.
            //
            // THE MEASURED REASON IT IS GONE: pasta calls `setsid`, so it has left the child's
            // process group before there is anything to sweep. Checked on a live pod against two
            // passt generations, `0^20250919` on Fedora 43 and `0.0~git20230309` on Debian 12,
            // both reporting `pgrp == session == pid` with `ppid` 1. The only thing the group
            // kill ever caught was a grandchild of a test stub that is a shell script, which is a
            // shape pasta does not have. The artefact was the justification.
            //
            // THERE IS ALSO A SAFETY ARGUMENT, AND IT IS NOT SETTLED, so it is not the reason.
            // It runs: a pidfd pins a `struct pid`, so the NUMBER cannot be reused, but a process
            // GROUP is a different object, and once the group empties its number is free for a
            // new leader while the pidfd still pins the old process. An external reviewer then
            // pointed out that the second half may be false BECAUSE the first is true: if the
            // pidfd holds the number out of the allocator, nothing can take it as a pid, and so
            // nothing can become a leader with that pgid. Neither of us has read the allocator.
            //
            // The removal survives either answer, which is why it stands on the measurement
            // instead. Note the consequence: with the group signal gone, the surviving kill goes
            // through the pidfd and targets the fd rather than the number, so whether a pidfd
            // pins the number is no longer load-bearing here either.
            unsafe {
                if pidfd >= 0 {
                    // Exact, and immune to reuse: the fd names the process, not the number.
                    libc::syscall(libc::SYS_pidfd_send_signal, pidfd, libc::SIGKILL, 0, 0);
                } else {
                    // No pidfd (kernel < 5.3): the number is unpinned and could in principle
                    // have been reused. That is the ordinary risk of signalling by pid, which is
                    // far smaller than the group signal this replaced.
                    libc::kill(pid, libc::SIGKILL);
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "pasta did not return within {}s and was killed",
                    limit.as_secs()
                ),
            ))
        }
    };
    if pidfd >= 0 {
        unsafe { libc::close(pidfd) };
    }
    result
}

fn setup_outbound(name: &str, holder: i32) -> Outbound {
    setup_outbound_in(&pod_dir(name), holder)
}

/// Attach a rootless NAT to the namespaces of `target_pid`, keeping its state in `dir`.
///
/// PARAMETERISED ON (DIRECTORY, PID) RATHER THAN ON A POD NAME, because the same mechanism now has
/// two users: a pod's holder, and a single box held at its pre-exec gate. The pod wrapper above is
/// the only thing that knows about pod directories, so nothing about this function has to.
///
/// EXTRACTED, NOT REWRITTEN. Everything here was already load-bearing for pods: the captured stderr
/// (pasta's message is the whole diagnosis), the ONE narrow retry for the netns-directory denial,
/// the `PASTA_WATCHED` marker that records the case teardown need NOT chase, and the `pid:starttime`
/// identity that keeps teardown from signalling a recycled pid. A second implementation for boxes
/// would be a second set of those decisions to keep in step.
///
/// `target_pid` must be a process whose `/proc/<pid>/ns/{user,net}` the caller keeps alive for the
/// duration of this call. For a box that is the gate: PID 1 is blocked on a read with its namespaces
/// fully built, so the pid cannot be recycled and the namespaces cannot vanish underneath pasta.
fn setup_outbound_in(dir: &std::path::Path, holder: i32) -> Outbound {
    let Some(pasta) = which_pasta() else {
        return Outbound::NotInstalled;
    };
    let dir = dir.to_path_buf();
    // stderr is CAPTURED, not discarded: when pasta refuses, its message is the whole diagnosis.
    let spawn = |watch_netns: bool| {
        output_within(
            std::process::Command::new(&pasta)
                .args(pasta_args(&dir, holder, watch_netns))
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped()),
            PASTA_SPAWN_LIMIT,
        )
    };
    match spawn(true) {
        // The first attempt kept its netns watch, so this pasta exits by itself when the namespace
        // goes and `teardown` need not wait for it. Best-effort: if the write fails, teardown
        // escalates, which is slower and never wrong. That asymmetry is why the marker records the
        // HEALTHY case rather than the dangerous one.
        Ok(o) if o.status.success() => {
            let _ = std::fs::write(dir.join(PASTA_WATCHED), b"");
            record_pasta_identity(&dir);
        }
        Ok(o) if is_netns_dir_denial(&String::from_utf8_lossy(&o.stderr)) => {
            // ONE narrower retry, and only for this refusal. pasta opens the netns's DIRECTORY
            // solely to watch it and quit when it disappears; `--no-netns-quit` drops that open and
            // nothing else (straced, see `pasta_args`). A host whose policy refuses that open still
            // permits the netns and userns FILES, so the NAT itself is reachable without the watch.
            //
            // Attempted rather than assumed to be the whole story: if the second attempt also fails,
            // BOTH reasons are reported. Reporting only the second would hide the first, and the
            // first is the one that names the operation a policy refused.
            let first = pasta_reason(&o.stderr);
            match spawn(false) {
                // Nothing is recorded here ON PURPOSE. A retried pasta has no watch, never exits
                // on its own, and is exactly the case `teardown` must confirm; the absence of
                // [`PASTA_WATCHED`] is what tells it so, and a marker that has to be written for
                // the dangerous case can fail to be written. See the constant.
                Ok(o2) if o2.status.success() => {
                    // Identity IS recorded here, unlike [`PASTA_WATCHED`]. The two answer different
                    // questions: the watch marker says whether this pasta will leave on its own, and
                    // its absence must stay the dangerous-case default; the identity record says
                    // WHICH process teardown may signal, and a retried pasta is the one that most
                    // needs it, because it is the one teardown escalates to SIGKILL.
                    record_pasta_identity(&dir);
                }
                Ok(o2) => {
                    return Outbound::Failed(format!(
                        "{first}; retried without the netns watch and it also failed: {}",
                        pasta_reason(&o2.stderr)
                    ));
                }
                Err(e) => {
                    return Outbound::Failed(format!(
                        "{first}; the retry without the netns watch could not be spawned: {e}"
                    ));
                }
            }
        }
        Ok(o) => return Outbound::Failed(pasta_reason(&o.stderr)),
        Err(e) => return Outbound::Failed(e.to_string()),
    }
    // Seed the pod resolv.conf with the host's real (non-loopback) nameservers - reachable through
    // the NAT, so split-horizon/LAN DNS keeps working. Only if the host has NONE that are usable from
    // the ns (e.g. systemd-resolved's 127.0.0.53 stub) do we fall back to a public resolver.
    let mut resolv = String::new();
    for ns in host_nameservers() {
        resolv.push_str(&format!("nameserver {ns}\n"));
    }
    // DNS is only "up" if we actually wrote the resolv.conf the box will bind - else don't claim it.
    // Distinguished from "no outbound at all": the NAT is attached either way, so a box can reach an
    // IP but not resolve a name, and saying "no outbound" would send the reader after the wrong
    // thing entirely.
    // WRITTEN NEXT TO THE OTHER STATE, not at a path derived from a pod name: `resolv_path(name)` is
    // `pod_dir(name)/resolv.conf`, so the same file for a box lives in the box's own directory. The
    // caller binds it wherever it belongs.
    if std::fs::write(dir.join("resolv.conf"), resolv).is_ok() {
        Outbound::Up
    } else {
        Outbound::NoDns
    }
}

/// The nameservers a NAT'd namespace should use, derived from the host.
///
/// The host's REAL (non-loopback) nameservers, which are reachable through the NAT, so split-horizon
/// and LAN DNS keep working. A host that has only a local stub (systemd-resolved's `127.0.0.53`)
/// offers nothing usable from inside a namespace, and the fallback is a public resolver rather than
/// an empty file: an empty `resolv.conf` makes glibc try `127.0.0.1`, which is the box's own
/// loopback and answers nothing.
///
/// SHARED BY THE POD AND THE PER-BOX PATH, because a stack must not resolve names differently
/// depending on which wiring it was started with. The pod writes these into a file it binds; a
/// `--no-pod` box receives the same list as `--dns` arguments and writes its own.
///
/// Never empty: the caller can rely on getting at least one resolver.
#[must_use]
pub fn host_nameservers() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Ok(host) = std::fs::read_to_string("/etc/resolv.conf") {
        for l in host.lines() {
            if let Some(ns) = l.strip_prefix("nameserver ") {
                // A resolv.conf value is a single token; take it and drop any trailing comment.
                let ns = ns.split_whitespace().next().unwrap_or("");
                // A LITERAL, because it travels into a `--dns` argument and then into a file glibc
                // parses: a value carrying whitespace or anything but an address would be dropped
                // silently by the resolver, which is the failure mode this whole path exists to
                // avoid.
                if !ns.starts_with("127.")
                    && !ns.is_empty()
                    && ns.parse::<std::net::IpAddr>().is_ok()
                    && !out.iter().any(|o| o == ns)
                {
                    out.push(ns.to_string());
                }
            }
        }
    }
    if out.is_empty() {
        out.push("1.1.1.1".to_string()); // host has only a local stub -> public fallback
    }
    out
}

/// Stop every per-box NAT recorded under a stack's `outbound/` tree. Returns how many were signalled.
///
/// THE TEARDOWN USED TO DELETE THE EVIDENCE INSTEAD OF ACTING ON IT. `kill_holder` removed
/// `outbound/` with `remove_dir_all`, and that subtree is where every box's `pasta.pid` and
/// `pasta.id` live: the processes were never signalled, and the files that identified them were
/// destroyed in the same call, so nothing could ever find them again.
///
/// IT DID NOT SHOW because a NAT that kept its netns watch exits by itself when the box's namespace
/// goes, so a healthy stack looked clean. The population it lost was the OTHER one: a host that
/// refuses the netns-directory open makes pasta fall back to `--no-netns-quit`, and that process has
/// no watch and waits to be signalled by exactly the pid file teardown had just deleted. MEASURED on
/// this machine: 27 such processes, every one from a box whose service runs as a non-root user - the
/// case where that open is refused - some of them hours old.
///
/// IDENTITY IS CHECKED BEFORE ANY SIGNAL, and the check is the start time and not just the pid,
/// because a pid recorded minutes ago may belong to something else now. Two levels, strongest first:
///
///   * `pasta.id` holds `pid:starttime`, written by kern; the process must still carry that exact
///     start time. A pid that was recycled fails this and is left alone.
///   * with no record - a stack from a kern that predates `pasta.id` - the pid file is read and the
///     process must at least be A pasta by its `comm`. Weaker, and it is the same fallback
///     `pasta_to_signal` already applies for the same population.
///
/// `pod_boot_is_current` is NOT consulted here, and that is deliberate rather than an omission: it
/// reads a marker `pod create` writes into a POD's directory, and these directories are created by
/// `attach_box_outbound`, which writes no such marker. Asking would refuse every box NAT there is.
/// The start-time check is what makes a stale record safe, and it does not need the boot to say so.
pub fn stop_stack_outbound_nats(stack_dir: &std::path::Path) -> usize {
    let Ok(entries) = std::fs::read_dir(stack_dir.join("outbound")) else {
        return 0; // a pod stack, or a directory already gone: nothing recorded, nothing to stop
    };
    let mut signalled: Vec<i32> = Vec::new();
    for e in entries.filter_map(Result::ok) {
        let dir = e.path();
        if !dir.is_dir() {
            continue;
        }
        let pid = match recorded_pasta_identity(&dir) {
            Some((pid, started)) => {
                if crate::registry::proc_starttime(pid) == started {
                    Some(pid)
                } else {
                    None // recycled, or long gone: this record is not evidence about a live process
                }
            }
            None => read_pid_file(&dir.join("pasta.pid")).filter(|p| pid_is_pasta(*p)),
        };
        let Some(pid) = pid else { continue };
        // SAFETY: `pid` is positive (`read_pid_file` and `recorded_pasta_identity` both refuse
        // anything else), so this signals one process and never a group or everything.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        signalled.push(pid);
    }
    if !signalled.is_empty() {
        // The same budget `stop_pasta` uses: pasta was measured leaving about 30 ms after SIGTERM.
        std::thread::sleep(std::time::Duration::from_millis(PASTA_STOP_BUDGET_MS));
        for pid in &signalled {
            // SAFETY: same argument; `kill(pid, 0)` only asks whether it is still there.
            unsafe {
                if libc::kill(*pid, 0) == 0 {
                    libc::kill(*pid, libc::SIGKILL);
                }
            }
        }
    }
    signalled.len()
}

/// Does this `-P` argument name a pidfile in kern's own layout?
///
/// THE SHAPE AND NOT THE ROOT, and the difference is what makes the sweep useful. Matching against
/// THIS process's runtime directory only recognises debris left under the same `XDG_RUNTIME_DIR`,
/// and the debris that actually accumulates comes from runs under a different one: a test harness
/// with its own temporary tree, a user whose runtime directory was recreated, a stack started from a
/// different session. MEASURED: 18 orphans stayed behind a root-anchored check that a shape check
/// reaps.
///
/// THE SHAPE IS NARROW. Both forms end in `pasta.pid` and sit under a `kern/` directory, in one of
/// the two subtrees kern writes NAT state into. It is combined with two other conditions at the call
/// site - the binary is `pasta`, and the namespace it watches is GONE - and a pasta whose namespace
/// is gone is doing nothing for anybody, so a false positive would have to be a `pasta` someone else
/// runs, from a path shaped exactly like kern's, already pointing at a dead namespace.
fn pidfile_path_is_kerns(path: &str) -> bool {
    if !path.ends_with("/pasta.pid") {
        return false;
    }
    // `<…>/kern/pods/<pod>/pasta.pid` or `<…>/kern/relays/<stack>/outbound/<svc>/pasta.pid`.
    path.contains("/kern/pods/") || (path.contains("/kern/relays/") && path.contains("/outbound/"))
}

/// Terminate every kern NAT whose namespace is gone, and report how many. Called by `kern gc`.
///
/// WHAT LEAKS, AND WHY THE WATCH IS NOT ENOUGH. A NAT is a `pasta` attached to one box's or one
/// pod's namespaces. The first attempt keeps pasta's own netns watch, so it exits when the namespace
/// goes; a host that refuses the netns-DIRECTORY open falls back to `--no-netns-quit`, and that one
/// has no watch at all and exists until teardown signals it through its pid file. If teardown never
/// runs - the stack was killed, the bring-up failed after the NAT was attached, the runtime
/// directory was deleted - nothing ever signals it.
///
/// MEASURED on this machine before this existed: 27 such processes, every one of them from a box
/// whose service runs as a non-root user, which is exactly the case where the directory open is
/// refused (see `PR_SET_DUMPABLE` in kern-isolation). They had been running for hours.
///
/// TWO CONDITIONS, BOTH REQUIRED, because this signals processes by scanning `/proc` and the cost of
/// being wrong is killing something that is not ours:
///
///   1. THE PROCESS IS OURS. Its `-P` pidfile argument must point inside kern's own runtime
///      directory. A `pasta` a user runs for their own reasons names a path somewhere else and is
///      never touched.
///   2. ITS NAMESPACE IS GONE. Only the `--netns /proc/<pid>/ns/net` form is read, and only when
///      `/proc/<pid>` no longer exists. Any other spelling of the argument, or a pid that is still
///      there, leaves the process alone.
///
/// A pid that is alive but RECYCLED cannot be distinguished here and does not need to be: the test
/// is that the pid is GONE, and a recycled pid is present, so the answer is "leave it".
pub fn sweep_orphan_nats() -> usize {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    let me = std::process::id() as i32;
    let mut victims: Vec<i32> = Vec::new();
    for e in entries.filter_map(Result::ok) {
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let argv: Vec<&[u8]> = raw.split(|c| *c == 0).filter(|a| !a.is_empty()).collect();
        let Some(arg0) = argv.first() else { continue };
        // The BINARY must be pasta, read from argv[0]'s file name: a command that merely mentions
        // pasta in a later argument is not one.
        let base = match arg0.iter().rposition(|c| *c == b'/') {
            Some(i) => &arg0[i + 1..],
            None => &arg0[..],
        };
        if base != b"pasta" && base != b"passt" {
            continue;
        }
        // CONDITION 1: ours.
        let mut ours = false;
        let mut watched: Option<i32> = None;
        for (i, a) in argv.iter().enumerate() {
            if *a == b"-P" || *a == b"--pid" {
                if let Some(path) = argv.get(i + 1).and_then(|p| std::str::from_utf8(p).ok()) {
                    ours = pidfile_path_is_kerns(path);
                }
            }
            // CONDITION 2: the namespace it watches, in the one form this reads.
            if *a == b"--netns" {
                if let Some(ns) = argv.get(i + 1).and_then(|p| std::str::from_utf8(p).ok()) {
                    watched = ns
                        .strip_prefix("/proc/")
                        .and_then(|r| r.split('/').next())
                        .and_then(|p| p.parse::<i32>().ok());
                }
            }
        }
        let (true, Some(target)) = (ours, watched) else {
            continue;
        };
        if std::path::Path::new(&format!("/proc/{target}")).exists() {
            continue; // the namespace's process is still there
        }
        victims.push(pid);
    }
    // SIGTERM, then SIGKILL only what is still there after the same budget `stop_pasta` uses.
    // pasta was measured leaving about 30 ms after SIGTERM; this is eight times that.
    for pid in &victims {
        // SAFETY: `pid` was parsed from a `/proc` entry and is positive, so this signals exactly one
        // process and never a group (`kill(0, …)`) or everything (`kill(-1, …)`).
        unsafe { libc::kill(*pid, libc::SIGTERM) };
    }
    if !victims.is_empty() {
        std::thread::sleep(std::time::Duration::from_millis(PASTA_STOP_BUDGET_MS));
        for pid in &victims {
            // SAFETY: same argument as above; `kill(pid, 0)` only asks whether it is still there.
            unsafe {
                if libc::kill(*pid, 0) == 0 {
                    libc::kill(*pid, libc::SIGKILL);
                }
            }
        }
    }
    victims.len()
}

/// Attach a rootless NAT to a BOX's namespaces, so a `--no-pod` service reaches the internet.
///
/// THE CALLER MUST HOLD THE BOX AT ITS PRE-EXEC GATE. pasta is attached by opening
/// `/proc/<pid>/ns/{user,net}`, so the pid must be alive and un-recycled for the duration, and the
/// workload must not yet have run or it would observe a namespace that has no route one instant and
/// a route the next. The gate gives exactly that: PID 1 blocked on a read with every namespace built.
///
/// Returns `Ok(())` when the NAT is up, and the reason otherwise. `pasta` missing is a reason like
/// any other here rather than a silent skip: a `--no-pod` stack that expected egress and has none
/// fails in the workload, far from the cause.
pub fn attach_box_outbound(dir: &std::path::Path, pid1: i32) -> Result<(), String> {
    if std::fs::create_dir_all(dir).is_err() {
        return Err(format!("could not create {}", dir.display()));
    }
    match setup_outbound_in(dir, pid1) {
        // `NoDns` is success HERE, unlike for a pod: the box writes its own `/etc/resolv.conf` from
        // the `--dns` arguments it was given at launch, so the file this function could not write is
        // one nothing reads. Reporting it as a failure would refuse egress that is working.
        Outbound::Up | Outbound::NoDns => Ok(()),
        Outbound::NotInstalled => Err("pasta (passt) is not installed".to_string()),
        Outbound::Failed(why) => Err(why),
    }
}

/// Locate the `pasta` binary (part of passt), or `None` if it isn't installed.
fn which_pasta() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join("pasta"))
            .find(|p| p.is_file())
    })
}

/// Append a member to a pod's shared `/etc/hosts` (name → `127.0.0.1`) if not already present, so
/// every member box can resolve it. Idempotent.
pub fn add_member(name: &str, member: &str) -> Result<(), Error> {
    let hp = hosts_path(name);
    let body = std::fs::read_to_string(&hp).unwrap_or_default();
    let line = format!("127.0.0.1\t{member}\n");
    if body.lines().any(|l| {
        let mut it = l.split_whitespace();
        it.next() == Some("127.0.0.1") && it.next() == Some(member)
    }) {
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&hp)
        .map_err(|e| Error::Sandbox(format!("pod hosts: {e}")))?;
    f.write_all(line.as_bytes())
        .map_err(|e| Error::Sandbox(format!("pod hosts: {e}")))?;
    Ok(())
}

/// `kern pod ls` - list pods (name, member count, alive/dead holder).
/// The pods on disk, sorted, as (name, member count, holder alive).
///
/// Split out of [`list`] so the human table and `--json` read the SAME scan. Two scanners is how
/// `kern validate` and `kern config list` once gave two verdicts about one file, and a pod that
/// shows `up` in the table and `"alive": false` in JSON would be the same defect with a worse
/// blast radius, because only one of the two is what a script acts on.
fn rows() -> Vec<(String, usize, bool)> {
    let root = pods_root();
    // MEMBERS COME FROM THE REGISTRY, NOT FROM THE SHARED `hosts` FILE. Counting hosts lines beyond
    // the two localhost seeds was right until aliases existed: `kern box --pod` adds ONE entry (the
    // box name, `add_member` in `start.rs`) while a compose service adds TWO (the qualified
    // `<pod>-<service>` and the bare alias, `add_member` in `compose.rs`), so this and `--json` both
    // reported exactly DOUBLE for every compose stack. MEASURED on the shipped v0.9.1 binary: 1, 2
    // and 3 services read 2, 4 and 6 here while `kern ps` read 1, 2 and 3.
    //
    // The comment on this function says the human table and `--json` were unified so they cannot
    // disagree. They could not, and both were wrong: a THIRD view (`kern ps`, which filters
    // `registry::list()` on `pod`) had the right answer and was never reconciled with them. Unifying
    // two readers is not the same as reading the right thing, so this now reads what `ps` reads.
    //
    // Scanned ONCE, outside the loop: `list()` walks the registry dir, and doing it per-pod would
    // make `pod ls` O(pods x boxes) for a number both views already have.
    let live = crate::registry::list();
    let mut rows: Vec<(String, usize, bool)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&root) {
        for e in rd.flatten() {
            if !e.path().is_dir() {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            let alive = holder_pid(&name).is_some();
            let members = live.iter().filter(|i| i.pod == name).count();
            rows.push((name, members, alive));
        }
    }
    rows.sort();
    rows
}

/// `kern pod ls --json`: one array, one line, empty when there are no pods.
///
/// `[]` and not the human "no pods - create one with ..." line: a script that has to special-case a
/// sentence to learn there is nothing there is parsing prose. The name is escaped because it is a
/// directory name on disk.
pub fn list_json() -> Result<(), Error> {
    let out = kern_common::json_array(&rows(), |(name, members, alive)| {
        format!(
            "{{\"name\":{},\"boxes\":{},\"alive\":{}}}",
            kern_common::json_str(name),
            members,
            alive,
        )
    });
    println!("{out}");
    Ok(())
}

pub fn list() -> Result<(), Error> {
    let rows = rows();
    if rows.is_empty() {
        println!("no pods - create one with `kern pod create <name>`");
        return Ok(());
    }
    let p = crate::ui::Palette::detect();
    println!(
        "{d}{:<24} {:>7}  STATUS{z}",
        "POD",
        "BOXES",
        d = p.d,
        z = p.z
    );
    for (name, members, alive) in &rows {
        let status = if *alive { "up" } else { "dead" };
        println!("{}{}{:<24}{} {:>7}  {status}", p.b, p.c, name, p.z, members);
    }
    Ok(())
}

/// Does this `/proc/<pid>/comm` belong to the `pasta`/`passt` family? passt re-execs into an
/// ISA-optimized variant, so `comm` is `pasta.avx2` (or `passt.avx512`, …) - never the bare `pasta`.
/// Matching by family prefix is what keeps the teardown's PID-reuse check from silently leaking the
/// NAT daemon (the bug where `comm == "pasta"` never matched → pasta survived every `pod rm`).
///
/// THE FAMILY IS `<base>` OR `<base>.<variant>`, not "anything starting with pasta". A bare
/// `starts_with` also accepts `pastafarian`, which an external reviewer pointed out, and the
/// teardown now signals a recorded pid unconditionally rather than only while the holder lives, so
/// the guard carries more weight than it did. The variant is always introduced by a `.`, so
/// requiring that separator costs one comparison and removes the whole class of unrelated names
/// that merely share a prefix.
/// THE TWO NAMES ACCEPT EACH OTHER, AND THAT IS DELIBERATE. `pasta` and `passt` are the same
/// binary under two names (pasta is passt in its namespace mode), so a process whose `comm` reads
/// `passt` satisfies a check written for `pasta` and the reverse. It reads like a bug to anyone
/// sweeping this file, which is why it is stated here rather than left to be re-derived.
fn is_pasta_comm(comm: &str) -> bool {
    ["pasta", "passt"]
        .iter()
        .any(|base| comm == *base || comm.strip_prefix(base).is_some_and(|r| r.starts_with('.')))
}

/// Does this pasta's argv name THIS pod's netns? The fallback's only tie between a process and the
/// pod that started it that a coincidence cannot satisfy.
///
/// `comm` says "a pasta", never "OUR pasta": every pasta on the host answers to it, and podman uses
/// pasta too, so the stranger is not hypothetical. `claimed_by_another_pasta` covers other kern pods
/// and nothing else. What is left is argv, which for a pasta kern spawned contains
/// `--netns /proc/<holder>/ns/net`, built by [`pasta_args`] from THIS pod's holder pid.
///
/// FORGEABLE IN PRINCIPLE, AND THAT IS ACCEPTED HERE. A process can set its own argv, so this would
/// not stop an adversary. It is not aimed at one: the case is a coincidence, a recycled pid landing
/// on something that happens to be called pasta, and a coincidence does not also arrange to carry
/// our holder's pid in its arguments. The strong path (`pasta.id`) is what answers an adversary, and
/// this branch exists only for pod dirs written before that record did.
///
/// Measured before it existed, with `ns_last_pid` under `unshare -Ur -p --fork`
/// (`scripts/pid-recycle-pasta.py`): a stranger renamed to `pasta` that inherited the recorded pid
/// was signalled by a teardown that never started it.
fn pasta_argv_names_pod(pid: i32, holder: i32) -> bool {
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let want = format!("/proc/{holder}/ns/net");
    // NUL-separated, and compared as a WHOLE argument rather than as a substring: a match inside a
    // longer string would accept `/proc/999/ns/net.bak` for holder 999.
    raw.split(|b| *b == 0).any(|arg| arg == want.as_bytes())
}

/// Is this pid, right now, a pasta? Identity by `comm`, read at the moment it is asked rather than
/// cached, because a pid outlives the process that held it.
fn pid_is_pasta(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| is_pasta_comm(c.trim()))
        .unwrap_or(false)
}

/// Stop the pod's pasta.
///
/// The `pid > 0` check is belt and braces: [`read_pid_file`] is what actually guarantees it, and
/// this repeats it because the argument is an `i32` and the next caller may not come from a file.
/// `kill(0, ...)` signals the caller's own process group and `kill(-1, ...)` signals every process
/// it may signal, so a degenerate value must never reach `kill`, not even to probe.
///
/// ESCALATION IS PER-POD, AND THE ARGUMENT FOR DECLINING IT EVERYWHERE HAS EXPIRED. It was
/// declined on the grounds that a lost SIGTERM is harmless because pasta notices the namespace
/// vanish and leaves on its own. That is true of a pasta with the netns watch, and FALSE of one
/// started with `--no-netns-quit` by the SELinux retry in `setup_outbound`: it has no watch, it
/// never self-exits, this signal is the only thing that will ever stop it, and `teardown` deletes
/// the pidfile straight after, so a missed signal leaves a userspace NAT running for a namespace
/// that is gone, unnameable for the rest of the session.
///
/// Certifying the retry on five Enforcing distributions made that the NORMAL path there, not an
/// edge, so the two now have different leak semantics and teardown must not treat them alike.
///
/// The cost was measured and is why it is not unconditional: waiting for the exit and following
/// with SIGKILL takes `pod rm` from 1.8 ms to 33 ms (five runs each, same binary), because pasta
/// takes about 30 ms to leave after SIGTERM. So `create` records [`PASTA_WATCHED`] when the
/// first attempt keeps its watch, and every pod without that record pays. A pod whose pasta watches its namespace is unchanged at
/// 1.8 ms, and the 31 ms lands exactly where the leak it prevents is possible.
///
/// The `pid > 0` check is belt and braces: [`read_pid_file`] is what actually guarantees it, and
/// this repeats it because the argument is an `i32` and the next caller may not come from a file.
fn stop_pasta(name: &str, dir: &std::path::Path, pid: i32, escalate: bool) {
    if pasta_to_signal(name, dir, pid).is_none() {
        return;
    }
    // CAPTURED ONCE, NOT RE-READ. The re-verification before the SIGKILL guards against the pid
    // being recycled during the budget, but re-reading `pasta.id` would also pick up a record
    // REWRITTEN during it: `pod create <same name>` inside those 250 ms replaces the file, and a
    // re-read would then authorise the kill against the NEW pod's pasta. Comparing against the
    // value captured before the SIGTERM keeps the question "is this still the process I decided to
    // signal", which is the only question the escalation may ask.
    let captured = recorded_pasta_identity(dir);
    unsafe { libc::kill(pid, libc::SIGTERM) };
    if !escalate {
        return;
    }
    // Backs off from 1 ms so a pasta that leaves promptly costs about that, rather than a full
    // poll interval. 250 ms total: pasta was measured leaving in about 30 ms after SIGTERM, so
    // this is eight times its observed exit and not a deadline it can miss by being slow.
    let (mut waited, mut step) = (0u64, 1u64);
    while waited < PASTA_STOP_BUDGET_MS {
        if unsafe { libc::kill(pid, 0) } != 0 {
            return; // gone
        }
        // `kill(pid, 0)` SUCCEEDS on a zombie, so the probe above cannot end this loop for a pasta
        // that has exited and not been reaped: without this the budget runs to the end, 250 ms
        // spent waiting for a process that already left. Checked after the signal probe, not
        // before, because the common case is a live pasta and that path must not pay a second read.
        if proc_is_zombie(pid) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(step));
        waited += step;
        step = (step * 2).min(32);
    }
    // Still there after the budget. RE-VERIFY IDENTITY before escalating: a quarter of a second is
    // long enough for the pid to have been recycled by something unrelated, and SIGKILL to a
    // stranger is not recoverable.
    let still_ours = match captured {
        // Identity was recorded: the pid must be the one named and must still carry the start-time
        // captured above.
        Some((want_pid, want_start)) => {
            want_pid == pid && crate::registry::proc_starttime(pid) == want_start
        }
        // No record: the same weaker pair the decision used, re-asked. `claimed_by_another_pasta`
        // is re-run rather than captured because another pod can only have ACQUIRED a claim during
        // the budget, and a claim that appeared is a reason to stop, never a reason to proceed.
        None => {
            pod_boot_is_current(dir)
                && pid_is_pasta(pid)
                && read_pid_file(&dir.join("holder")).is_some_and(|h| pasta_argv_names_pod(pid, h))
                && !claimed_by_another_pasta(pid, name)
        }
    };
    if still_ours {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

/// Tear a pod down: kill its pasta NAT daemon (verified by PID + `comm` family prefix), then its holder, then wipe
/// its state dir. Returns `(existed, member_count)`. Silent - callers do the messaging so `pod rm`
/// and `compose down` can each say the right thing. Member boxes keep their own (already-joined)
/// namespaces until they exit; only the holder is freed.
pub fn teardown(name: &str) -> (bool, usize) {
    // Validate BEFORE building the path: `pod_dir` is `pods/<name>`, and an unvalidated `name` like
    // `../../x` would make `remove_dir_all` escape the pod store and wipe an unrelated directory. Only
    // `create` validated before; `pod rm` / `compose down` reach here with raw input, so guard here
    // too (all callers). An invalid name simply matches no pod.
    if validate_name(name).is_err() {
        return (false, 0);
    }
    let dir = pod_dir(name);
    if !dir.is_dir() {
        return (false, 0);
    }
    // Members from the REGISTRY, and BEFORE anything is killed. Same defect and same fix as `rows()`
    // above: a compose member writes TWO `hosts` lines (qualified name + alias) and a `kern box
    // --pod` member writes one, so the old shared-hosts count doubled for a compose stack and was
    // right for a hand-made pod. Read first because `list()` prunes dead entries as it scans: taking
    // it after the holder dies would race the members that exit with it and report a low number for
    // the same teardown that a caller is about to print.
    let members = crate::registry::list()
        .iter()
        .filter(|i| i.pod == name)
        .count();
    // Kill pasta FIRST, while the holder still owns the net ns - so its recorded PID is unambiguously
    // pasta (killing the holder frees the ns → pasta auto-exits → PID-reuse window). Verify via comm
    // (pasta runs in the HOST net ns, so the holder's ns-inode guard can't cover it).
    //
    // UNCONDITIONAL, and it was not. This used to run only `if holder.is_some()`, on the assumption
    // that a dead holder means pasta already noticed the netns vanish and left. That assumption is
    // no longer safe: a pod whose pasta was started with `--no-netns-quit` (the retry in
    // `setup_outbound`, for hosts that refuse the netns-dir open) does NOT watch the namespace and
    // does not exit on its own, so gating on a live holder would leak it for the life of the
    // session. The `comm` check below is what makes killing safe when the holder is already gone: it
    // is the guard against the recycled PID that the old gate was standing in for.
    // `holder_to_reap`, not `holder_pid`: the second says whether a box may join this namespace, and
    // its `None` also covers "could not tell", which is exactly the case that used to leak a live
    // holder one line before the directory naming it was deleted.
    let holder = holder_to_reap(name);
    if let Some(pp) = read_pid_file(&dir.join("pasta.pid")) {
        // THE LEAK IS SAID OUT LOUD, because the branch is otherwise invisible from either side: the
        // pasta keeps running and nothing explains why. A pod created on a host that could not read
        // `boot_id` cannot have its pids attributed across a possible reboot, so kern declines to
        // signal them and names what it left behind instead of leaving it to be discovered.
        if matches!(pod_boot(&dir), PodBoot::Unattributable) && unsafe { libc::kill(pp, 0) } == 0 {
            eprintln!(
                "kern: note: pod '{name}' recorded no boot id when it was created, so its pasta \
                 (pid {pp}) cannot be attributed across a possible reboot and was left running. \
                 Stop it with `kill {pp}` once you have confirmed it is this pod's."
            );
        }
        // A pasta with no watch will never leave on its own, so its exit is confirmed before the
        // pidfile that names it is deleted. Every other pod pays nothing for this.
        // ESCALATE UNLESS THE POD IS RECORDED AS WATCHED. Absence covers both "the retry was
        // used" and "the marker write failed", and both need the confirmation, so the default
        // falls on the safe side rather than the fast one.
        stop_pasta(name, &dir, pp, !dir.join(PASTA_WATCHED).exists());
    }
    if let Some(pid) = holder {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    // THE RESULT IS NOT DISCARDED, because another statement depends on it. `network_sentence`
    // reads "no live pasta AND a resolv.conf" as "pasta started and has since exited", and the
    // argument that the file cannot be left over from an earlier pod of the same name is exactly
    // this removal succeeding. If it fails (EBUSY on something still mounted, a permissions
    // problem, a file another process holds), the directory survives with its `resolv.conf`, and a
    // pod re-created under the same name reports a crash that never happened.
    //
    // The individual files are removed as a fallback so the state that drives the message is gone
    // even when the directory itself cannot be. Whatever remains is left for `create` to find.
    //
    // `pasta.pid` IS REMOVED LAST, and the order is load-bearing rather than tidy. If the signal
    // above did not take, that file is the only thing that can still name the process; deleting it
    // first would make the pasta unreachable for good, while leaving it means the next `pod rm`
    // can try again. Free, and it costs nothing when the removal succeeds, which is the normal
    // case and does not reach this branch at all.
    //
    // THE ORDER IS NOW COUPLED TO A POLICY, AND THE COUPLING IS THE FRAGILE PART. Naming the pasta
    // is no longer enough on its own: [`pasta_to_signal`] also reads [`POD_BOOT`] and [`PASTA_ID`],
    // both of which appear in this list ABOVE `pasta.pid` and can therefore be gone while it
    // remains. The retry still works only because BOTH degrade permissively when absent - `POD_BOOT`
    // missing reads as a legacy dir, `PASTA_ID` missing falls back to the `comm` check plus the
    // cross-pod scan. If either is ever made to REFUSE on absence, this ordering stops delivering
    // what it promises and a pasta becomes unreachable exactly in the case the ordering exists for.
    // Stated here rather than left to be re-derived, because the change that would break it happens
    // in another function and would look correct there.
    if std::fs::remove_dir_all(&dir).is_err() {
        for stale in [
            "resolv.conf",
            "holder",
            "netns",
            "hosts",
            PASTA_WATCHED,
            PASTA_ID,
            POD_BOOT,
            "pasta.pid",
        ] {
            let _ = std::fs::remove_file(dir.join(stale));
        }
    }
    (true, members)
}

/// `kern pod rm <name>` - tear the pod down; still-running member boxes keep going until they exit.
pub fn remove(names: &[String]) -> Result<(), Error> {
    if names.is_empty() {
        return Err(Error::Usage("pod rm <name>..."));
    }
    let mut missing = Vec::new();
    for name in names {
        let (existed, members) = teardown(name);
        if !existed {
            missing.push(name.clone());
            eprintln!("kern: no pod named '{name}'");
            continue;
        }
        println!("removed pod '{name}'");
        if members > 0 {
            println!("  ({members} member box(es) keep running until they exit; `kern stop` them)");
        }
    }
    // A `pod rm <name>` that removed NOTHING (every name was missing) must exit non-zero, so a script
    // can tell the removal failed - parity with `config rm` / `volume rm` on an unknown name.
    if missing.len() == names.len() {
        return Err(Error::NotRunning(format!(
            "no pod named '{}'",
            missing.join("', '")
        )));
    }
    Ok(())
}

/// `kern __pod-holder` (hidden): become the pod's namespace holder - never returns.
pub fn run_holder() -> ! {
    kern_isolation::run_pod_holder()
}

/// Pod names share the box-name charset (used as a directory + hostnames): `[A-Za-z0-9_.-]`, ≤64,
/// no traversal. Rejects anything that could escape `pods/` or corrupt `/etc/hosts`.
fn validate_name(name: &str) -> Result<(), Error> {
    // The shared [`kern_common::valid_resource_name`] rule (one definition for volumes/secrets/pods/
    // profiles): also rejects a leading `-` and any `..` substring, which the old local rule missed.
    if kern_common::valid_resource_name(name) {
        Ok(())
    } else {
        Err(Error::Sandbox(format!(
            "invalid pod name '{name}' (use letters, digits, '_', '-', '.'; no leading '-'/'.' or '..'; max 64)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_names_reject_traversal_and_bad_chars() {
        for ok in ["web", "my-app", "db_1", "v1.2"] {
            assert!(validate_name(ok).is_ok(), "{ok} should be valid");
        }
        for bad in [
            "",
            "../evil",
            "a/b",
            ".hidden",
            "has space",
            &"x".repeat(65),
        ] {
            assert!(validate_name(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn a_pod_dir_from_a_previous_boot_reaps_nothing() {
        // The test the reviewer said needs no reboot: write a boot id that cannot be this boot's
        // and assert that BOTH markers refuse, including the fallback, which is the branch a stale
        // dir would otherwise reach with a live stranger's pid in it.
        let root = pods_root();
        if std::fs::create_dir_all(&root).is_err() {
            eprintln!("skip: no writable pods root");
            return;
        }
        let name = format!("boot-{}", std::process::id());
        let dir = root.join(&name);
        let _ = std::fs::remove_dir_all(&dir);
        if std::fs::create_dir_all(&dir).is_err() {
            eprintln!("skip: cannot build the fixture");
            return;
        }
        let Ok(mut child) = std::process::Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            eprintln!("skip: cannot spawn a helper process");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        };
        let pid = child.id() as i32;
        let started = crate::registry::proc_starttime(pid);

        // A record that would otherwise MATCH: same pid, correct start-time. Only the boot differs.
        let _ = std::fs::write(dir.join(PASTA_ID), format!("{pid}:{started}"));
        let _ = std::fs::write(dir.join("holder"), format!("{pid}:{started}"));

        // Absence of the boot record keeps the previous behaviour: identity alone decides, and here
        // it matches, so the pid IS signalled. This is the control - without it the assertion below
        // could pass because the fixture never resolved, rather than because the boot refused it.
        assert_eq!(
            pasta_to_signal(&name, &dir, pid),
            Some(pid),
            "control: with no boot record, a matching start-time is signalled"
        );

        let _ = std::fs::write(dir.join(POD_BOOT), "00000000-0000-0000-0000-000000000000");
        assert!(
            !pod_boot_is_current(&dir),
            "a boot id of all zeros is not this boot"
        );
        assert_eq!(
            pasta_to_signal(&name, &dir, pid),
            None,
            "a pid recorded in a previous boot is never signalled, matching start-time or not"
        );
        assert_eq!(
            holder_to_reap(&name),
            None,
            "the same guard covers the holder marker, which shares the format"
        );

        // And the current boot restores it, so the guard is the boot id and not the file's presence.
        if let Some(now) = current_boot_id() {
            let _ = std::fs::write(dir.join(POD_BOOT), now);
            assert!(pod_boot_is_current(&dir));
            assert_eq!(pasta_to_signal(&name, &dir, pid), Some(pid));
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_boot_record_that_cannot_be_evaluated_refuses_rather_than_defaults() {
        // The third state, and the one that used to be folded into "absent". A dir that HAS a boot
        // record was written by a kern that could read `boot_id`; if the read fails now, the only
        // signal that a reboot happened is gone, and the primary path would go on comparing
        // start-times that are themselves boot-relative.
        //
        // The unreadable case is reached by pointing the reader at a path that cannot be read,
        // which is what a masked `/proc/sys` produces, rather than by unmounting procfs under a
        // running test.
        let root = pods_root();
        if std::fs::create_dir_all(&root).is_err() {
            eprintln!("skip: no writable pods root");
            return;
        }
        let name = format!("bootstate-{}", std::process::id());
        let dir = root.join(&name);
        let _ = std::fs::remove_dir_all(&dir);
        if std::fs::create_dir_all(&dir).is_err() {
            eprintln!("skip: cannot build the fixture");
            return;
        }

        // 1. Absent: permissive, and it must stay so or every legacy pod leaks.
        assert!(
            pod_boot_is_current(&dir),
            "a dir with no boot record predates the record and is reaped as before"
        );

        // 2. Present and equal to this boot: reaped.
        let Some(now) = current_boot_id() else {
            eprintln!("skip: boot_id unreadable on this host, which is the case under test");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        };
        let _ = std::fs::write(dir.join(POD_BOOT), &now);
        assert!(pod_boot_is_current(&dir), "this boot's record is current");

        // 3. Present and different: refused.
        let _ = std::fs::write(dir.join(POD_BOOT), "00000000-0000-0000-0000-000000000000");
        assert!(
            !pod_boot_is_current(&dir),
            "a record from another boot must never be reaped"
        );

        // 4. Present and empty, the torn write: reads as different, refused.
        let _ = std::fs::write(dir.join(POD_BOOT), "");
        assert!(
            !pod_boot_is_current(&dir),
            "a torn boot record lands on the safe side"
        );

        // 5. The sentinel: a host that could not read `boot_id` at create time said so, and that
        // is a positive fact rather than a gap. Permissive, and it must NOT depend on whether the
        // read succeeds now - the whole point is that the answer is on disk.
        // 5. THE SENTINEL REFUSES. It says the host could not read `boot_id` when the pod was
        // created, so nothing here can be attributed to a boot at all - which makes it the state
        // where kern knows the LEAST. Trusting it authorised a kill on `pid:starttime` alone, and
        // both of those are boot-relative, which is the entire reason this record exists.
        let _ = std::fs::write(dir.join(POD_BOOT), POD_BOOT_UNAVAILABLE);
        assert!(
            !pod_boot_is_current(&dir),
            "the state in which kern knows the least must not be the one that authorises a kill"
        );
        assert!(
            matches!(pod_boot(&dir), PodBoot::Unattributable),
            "and it is its own state, not folded into 'a different boot': teardown prints the pid \
             it left running only for this one"
        );
        // And it is distinguishable from every real boot id, which is what makes it safe to key on.
        assert_ne!(
            POD_BOOT_UNAVAILABLE,
            now.as_str(),
            "the sentinel must never collide with a boot id"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_torn_pasta_record_falls_back_and_never_matches() {
        let root = pods_root();
        if std::fs::create_dir_all(&root).is_err() {
            eprintln!("skip: no writable pods root");
            return;
        }
        let name = format!("torn-{}", std::process::id());
        let dir = root.join(&name);
        let _ = std::fs::remove_dir_all(&dir);
        if std::fs::create_dir_all(&dir).is_err() {
            eprintln!("skip: cannot build the fixture");
            return;
        }
        // Every shape a partial or legacy write can leave. None may parse as a start-time, because
        // a value that parsed would be compared against a live process and could match.
        for raw in [
            "471621:",
            "471621",
            "",
            "471621:notanumber",
            ":1082818",
            "\n",
        ] {
            let _ = std::fs::write(dir.join(PASTA_ID), raw);
            assert_eq!(
                recorded_pasta_identity(&dir),
                None,
                "{raw:?} must read as no record, not as a start-time"
            );
        }
        // A whole record still parses, so the assertions above are not passing vacuously.
        let _ = std::fs::write(dir.join(PASTA_ID), "471621:1082818");
        assert_eq!(recorded_pasta_identity(&dir), Some((471_621, 1_082_818)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stat_state_survives_a_comm_with_spaces_and_parentheses() {
        // The state is the token after the LAST `)`. A left-to-right split takes field 3, which is
        // the state only when `comm` contains no whitespace: the two lines below are exactly the
        // shapes that break it, and both are legal process names.
        let plain = "42 (pasta) S 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 0 0";
        assert_eq!(stat_state(plain), Some("S"));
        let nasty = "42 (pas ta (x)) Z 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 0 0";
        assert_eq!(
            stat_state(nasty),
            Some("Z"),
            "a comm with a space and a nested paren must not shift the field"
        );
        assert_eq!(stat_state("no parenthesis here"), None);
    }

    #[test]
    fn a_pasta_pid_claimed_by_another_pod_is_not_signalled() {
        // The defect this closes: two pods, both with a pasta, both `comm == "pasta"`. If A's
        // recorded pid has been recycled onto B's pasta, the family check alone says yes and A's
        // teardown kills B's NAT.
        let root = pods_root();
        if std::fs::create_dir_all(&root).is_err() {
            eprintln!("skip: no writable pods root");
            return;
        }
        let a = format!("claim-a-{}", std::process::id());
        let b = format!("claim-b-{}", std::process::id());
        let (da, db) = (root.join(&a), root.join(&b));
        let _ = std::fs::remove_dir_all(&da);
        let _ = std::fs::remove_dir_all(&db);
        if std::fs::create_dir_all(&da).is_err() || std::fs::create_dir_all(&db).is_err() {
            eprintln!("skip: cannot build the fixture");
            return;
        }
        // A live pid that is NOT this process: `read_pid_file` refuses kern's own pid outright, so
        // the fixture has to be a real third party or the claim check never sees it. Found by this
        // test failing on the first attempt, which used `std::process::id()`.
        let Ok(mut child) = std::process::Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            eprintln!("skip: cannot spawn a helper process");
            let _ = std::fs::remove_dir_all(&da);
            let _ = std::fs::remove_dir_all(&db);
            return;
        };
        let other = child.id() as i32;
        let _ = std::fs::write(db.join("pasta.pid"), format!("{other}\n"));

        assert!(
            claimed_by_another_pasta(other, &a),
            "pod B's pasta.pid names this pid, so pod A must not claim it"
        );
        assert!(
            !claimed_by_another_pasta(other, &b),
            "a pod does not claim a pid against itself"
        );
        // And the decision built on it declines. This helper's `comm` is `sleep`, so the family
        // check would refuse it too; the assertion that carries the meaning is the pair above.
        assert_eq!(
            pasta_to_signal(&a, &da, other),
            None,
            "a pid another pod claims is never signalled"
        );
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&da);
        let _ = std::fs::remove_dir_all(&db);
    }

    #[test]
    fn a_recorded_pasta_start_time_rejects_a_recycled_pid() {
        let root = pods_root();
        if std::fs::create_dir_all(&root).is_err() {
            eprintln!("skip: no writable pods root");
            return;
        }
        let name = format!("ident-{}", std::process::id());
        let dir = root.join(&name);
        let _ = std::fs::remove_dir_all(&dir);
        if std::fs::create_dir_all(&dir).is_err() {
            eprintln!("skip: cannot build the fixture");
            return;
        }
        let me = std::process::id() as i32;
        let real = crate::registry::proc_starttime(me);

        // The recorded start-time matches: the pid IS the recorded process, and identity decides
        // without ever consulting `comm` - which for this test process does not say pasta.
        let _ = std::fs::write(dir.join(PASTA_ID), format!("{me}:{real}"));
        assert_eq!(recorded_pasta_identity(&dir), Some((me, real)));
        assert_eq!(
            pasta_to_signal(&name, &dir, me),
            Some(me),
            "identity confirmed by start-time is sufficient on its own"
        );

        // The same pid with a different start-time is a DIFFERENT process wearing a reused number.
        let _ = std::fs::write(dir.join(PASTA_ID), format!("{me}:{}", real.wrapping_add(1)));
        assert_eq!(
            pasta_to_signal(&name, &dir, me),
            None,
            "a start-time that does not match must never be signalled"
        );

        // A bare record with no start-time falls back, and the fallback refuses this pid because
        // its `comm` is not in the pasta family.
        let _ = std::fs::write(dir.join(PASTA_ID), format!("{me}"));
        assert_eq!(recorded_pasta_identity(&dir), None);
        assert_eq!(pasta_to_signal(&name, &dir, me), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_pid_file_refuses_every_value_that_must_not_reach_kill() {
        let dir = std::env::temp_dir().join(format!("kern-pidfile-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("p");
        let read = |v: &str| {
            std::fs::write(&f, v).expect("write the pid file");
            read_pid_file(&f)
        };

        // `kill(0, ..)` signals the caller's own process group, `kill(-1, ..)` everything it may
        // signal. Neither may ever leave this function.
        for bad in [
            "0",
            "-1",
            "-999",
            "not-a-pid",
            "",
            "  ",
            "9999999999999999999999",
        ] {
            assert_eq!(read(bad), None, "{bad:?} must not be read as a pid");
        }
        // pid 1 is nonsense in a pod's pidfile, and must not be excused by the EPERM it would earn.
        assert_eq!(read("1"), None, "pid 1 must not be read as a pid");
        // KERN ITSELF. A clobbered pidfile naming the process doing the teardown would make it
        // SIGKILL itself, and this was the one value the pid-file battery did not cover.
        let me = std::process::id();
        assert_eq!(read(&me.to_string()), None, "our own pid must be refused");
        assert_eq!(
            read(&format!("{me}:12345")),
            None,
            "our own pid is refused in the pid:starttime form too"
        );

        // The forms that ARE pids, including the marker with its start-time half.
        assert_eq!(read("4242"), Some(4242));
        assert_eq!(read("4242:99887766"), Some(4242));
        assert_eq!(read(" 4242:99887766 \n"), Some(4242));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_holder_marker_carries_a_start_time_that_a_reused_pid_cannot_match() {
        let dir = std::env::temp_dir().join(format!("kern-holder-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        // No start-time: an older kern's marker, and there is nothing to verify against.
        std::fs::write(dir.join("holder"), "4242").expect("write");
        assert_eq!(recorded_holder_starttime(&dir), None);

        // With one, it is read back exactly. This is the value `holder_to_reap` compares against
        // `proc_starttime`, and it is the whole identity: the kernel assigns it, the process
        // cannot rewrite it, and whatever inherits the pid later has a different one. argv could
        // do none of those three, which is why three versions of a name check kept leaking.
        std::fs::write(dir.join("holder"), "4242:99887766").expect("write");
        assert_eq!(recorded_holder_starttime(&dir), Some(99887766));

        // Our own live pid with a WRONG start-time is a reused pid, not our holder.
        let me = std::process::id() as i32;
        let real = crate::registry::proc_starttime(me);
        assert_ne!(real, 0, "this test needs a readable /proc/self/stat");
        std::fs::write(dir.join("holder"), format!("{me}:{}", real.wrapping_add(1)))
            .expect("write");
        assert_ne!(
            recorded_holder_starttime(&dir),
            Some(crate::registry::proc_starttime(me)),
            "a mismatched start-time must not read as the same process"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn output_within_returns_a_fast_command_and_gives_up_on_a_wedged_one() {
        // The fast path must be untouched: the output still comes back, stderr included.
        let mut ok = std::process::Command::new("/bin/sh");
        ok.arg("-c")
            .arg("echo out; echo err >&2")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let got = output_within(&mut ok, std::time::Duration::from_secs(10))
            .expect("a command that exits immediately must return its output");
        assert!(got.status.success());
        assert_eq!(String::from_utf8_lossy(&got.stdout).trim(), "out");
        assert_eq!(String::from_utf8_lossy(&got.stderr).trim(), "err");

        // The wedged path: `Command::output` would wait forever here, which is what hung
        // `kern pod create`. Measured, not asserted from the clock alone: it must come back as a
        // timeout AND it must come back quickly.
        let start = std::time::Instant::now();
        let mut wedged = std::process::Command::new("/bin/sh");
        wedged
            .arg("-c")
            .arg("sleep 60")
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let err = output_within(&mut wedged, std::time::Duration::from_millis(300))
            .expect_err("a command that never returns must not be waited on forever");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(20),
            "it gave up, but only after {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn network_sentence_does_not_blame_a_refusal_that_never_happened() {
        // THE ARM THAT WAS MISSING, found by an external reviewer reading the four arms rather
        // than running anything. `resolv.conf` is written only after pasta has already started, so
        // "pasta is not alive AND its resolv.conf exists" means it came up and later died: crashed,
        // OOM-killed, or caught by a racing teardown. It used to fall into the "installed but not
        // running" arm, which tells the reader `pod create` explains why it refused. Nothing
        // refused, create succeeded, and no such line was ever printed, so the message sent the
        // reader after an explanation that does not exist. Same shape as #6's symptom, one arm
        // over, in the function written to fix #6.
        let died = network_sentence(false, true, true);
        assert!(
            !died.contains("refused"),
            "a pasta that started and died was never refused: {died}"
        );
        assert!(
            !died.contains("install"),
            "it is installed, and #6 was exactly this wrong remedy: {died}"
        );
        assert!(died.contains("has since exited"), "{died}");
        // `installed` must not change that verdict: the resolv.conf already settled it.
        assert_eq!(died, network_sentence(false, true, false));

        // The refusal arm keeps its sentence, and only for the state that produced it.
        let refused = network_sentence(false, false, true);
        assert!(refused.contains("says why it refused"), "{refused}");
        assert!(!refused.contains("install `passt`"), "{refused}");

        // Genuinely absent pasta is the only arm that may say "install".
        let absent = network_sentence(false, false, false);
        assert!(absent.contains("install `passt`"), "{absent}");

        // The two healthy arms are distinct, and only the fully-healthy one claims the internet.
        let up = network_sentence(true, true, false);
        let nodns = network_sentence(true, false, false);
        assert!(up.contains("outbound to the internet"), "{up}");
        assert!(nodns.contains("cannot resolve"), "{nodns}");
        assert_ne!(up, nodns);

        // All five reachable states say five different things: the collapse into two is what
        // shipped as #6, so distinctness is the property under test, not the wording.
        let all = [died, refused, absent, up, nodns];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b, "two states share a sentence");
            }
        }
    }

    #[test]
    fn pasta_comm_matches_isa_variants_not_strangers() {
        // Regression: the teardown once compared `comm == "pasta"` and never matched the real
        // `pasta.avx2`, so the NAT daemon leaked on every `pod rm` / `compose down`.
        for ok in [
            "pasta",
            "passt",
            "pasta.avx2",
            "passt.avx512",
            "pasta.avx2\n".trim(),
        ] {
            assert!(is_pasta_comm(ok), "{ok} should match the pasta family");
        }
        // A shared PREFIX is not membership of the family, and the teardown now signals a recorded
        // pid whether or not the holder is still alive, so a name that merely starts with `pasta`
        // must not be enough. `pastafarian` was named by an external reviewer; the rest are the same
        // shape. The variant separator is always `.`, so anything else after the base is a stranger.
        for no in [
            "bash",
            "sleep",
            "kern",
            "past",
            "asta",
            "",
            "pas",
            "pastafarian",
            "passthrough",
            "pasta_helper",
            "pasta-avx2",
            "pastad",
        ] {
            assert!(!is_pasta_comm(no), "{no} must NOT match");
        }
    }

    #[test]
    fn pasta_argv_disables_automatic_port_mapping() {
        // REGRESSION GUARD for a runtime silent partial failure: pasta defaults `-t/-u/-T/-U` to
        // `auto`, and `-t auto` periodically binds host-bound ports INSIDE the pod net ns. Since kern's
        // own forwarder binds the host side of every `-p`, pasta would steal the published port from
        // the service ~1-2 s after start (measured: bind at >=2 s always got EADDRINUSE) while
        // `compose up` still reported success. All four MUST stay explicitly `none`.
        // BOTH modes, because the retry path in `setup_outbound` builds this argv too and a guard
        // that covers only the first attempt stops covering the run that a Fedora host actually gets.
        for watch_netns in [true, false] {
            let argv = pasta_args(
                std::path::Path::new("/run/user/1000/kern/pods/demo"),
                4242,
                watch_netns,
            );
            let flat: Vec<String> = argv
                .iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect();
            for dir_flag in ["-t", "-u", "-T", "-U"] {
                let at = flat.iter().position(|a| a == dir_flag);
                let Some(at) = at else {
                    panic!("pasta argv must pin {dir_flag} explicitly, got {flat:?}");
                };
                assert_eq!(
                    flat.get(at + 1).map(String::as_str),
                    Some("none"),
                    "{dir_flag} must be 'none' (pasta's default is 'auto', which steals published \
                     ports); watch_netns={watch_netns}"
                );
            }
            // The rest of the contract the teardown and egress depend on.
            assert!(flat.contains(&"--config-net".to_string()), "NAT'd egress");
            let pidfile = flat
                .iter()
                .position(|a| a == "-P")
                .and_then(|i| flat.get(i + 1));
            assert_eq!(
                pidfile.map(String::as_str),
                Some("/run/user/1000/kern/pods/demo/pasta.pid"),
                "teardown reads this exact path to kill pasta"
            );
            let ns = flat
                .iter()
                .position(|a| a == "--netns")
                .and_then(|i| flat.get(i + 1));
            assert_eq!(ns.map(String::as_str), Some("/proc/4242/ns/net"));
            let us = flat
                .iter()
                .position(|a| a == "--userns")
                .and_then(|i| flat.get(i + 1));
            assert_eq!(us.map(String::as_str), Some("/proc/4242/ns/user"));
        }
    }

    /// The holder is identified by argv POSITION, because the answer decides a `SIGKILL`.
    ///
    /// `teardown` reaps a live holder whose netns inode could not be checked, which is the case that
    /// leaked one process per pod; this is what says the process is kern's own. The first version
    /// asked only whether ANY argument equalled the marker, and this test is what showed that
    /// `kern box x -- echo __pod-holder` satisfies it: a whole argument, belonging to the workload.
    #[test]
    fn holder_is_identified_by_argv_position_not_by_presence() {
        let cmd = |args: &[&str]| {
            let mut v = Vec::new();
            for a in args {
                v.extend_from_slice(a.as_bytes());
                v.push(0);
            }
            v
        };
        // The real thing, however kern was installed.
        assert!(cmdline_is_holder(&cmd(&[
            "/usr/local/bin/kern",
            "__pod-holder"
        ])));
        assert!(cmdline_is_holder(&cmd(&["kern", "__pod-holder"])));
        assert!(cmdline_is_holder(&cmd(&[
            "./target/debug/kern",
            "__pod-holder"
        ])));
        // A holder carries nothing after the marker today; a future flag must not unmake it one.
        assert!(cmdline_is_holder(&cmd(&["kern", "__pod-holder", "--x"])));

        for argv in [
            // THE ONE THAT BROKE THE FIRST VERSION: the marker is the WORKLOAD's own argument.
            vec!["kern", "box", "x", "--", "echo", "__pod-holder"],
            // argv[1] is right and the program is not kern.
            vec!["grep", "__pod-holder", "/proc/1/cmdline"],
            vec!["/usr/bin/pkill", "__pod-holder"],
            // kern, and any other subcommand.
            vec!["kern", "box", "app"],
            vec!["kern", "ps"],
            vec!["kern"],
            // Substrings, which the token split already rejected and must keep rejecting.
            vec!["kern", "--flag=__pod-holder"],
            vec!["kern", "__pod-holder-ish"],
            vec!["kern", "x__pod-holder"],
            // A binary whose name merely ends with or extends kern.
            vec!["/usr/bin/mykern", "__pod-holder"],
            vec!["kernel", "__pod-holder"],
        ] {
            assert!(
                !cmdline_is_holder(&cmd(&argv)),
                "{argv:?} must not read as the pod holder"
            );
        }
        // Degenerate inputs: empty, only separators, and a buffer with no separator at all.
        assert!(!cmdline_is_holder(b""));
        assert!(!cmdline_is_holder(b"\0\0\0"));
        assert!(!cmdline_is_holder(b"__pod-holder"));
        assert!(!cmdline_is_holder(b"kern"));

        // OUR OWN FILE NAME COUNTS, whatever it happens to be, and under `cargo test` that is the
        // test binary rather than `kern` - which is exactly the point. `create` spawns the holder
        // with `current_exe()`, so argv[0] is the installed file's name, and comparing only against
        // the literal was a guess about how kern is installed. Measured with the binary copied to
        // `getkern`: the holder survived `pod rm` whenever its netns inode could not be read.
        if let Some(me) = self_exe_file_name() {
            let mut argv = me.clone();
            argv.push(0);
            argv.extend_from_slice(HOLDER_ARGV.as_bytes());
            assert!(
                cmdline_is_holder(&argv),
                "a holder started by THIS binary must be recognised as one"
            );
            // The marker is still required: the name alone must not be enough.
            assert!(!cmdline_is_holder(&me));
        }
    }

    /// `--no-netns-quit` appears on the RETRY and never on the first attempt, and the retry is
    /// entered only for the one refusal it removes.
    ///
    /// The flag has a cost (pasta stops reaping itself when the namespace goes), so a build that
    /// passed it unconditionally would leak a pasta on every host, not only the ones that need it.
    /// The two directions are asserted separately because "present when needed" and "absent
    /// otherwise" are two claims, and the defect that motivated all of this was one condition
    /// standing in for two.
    #[test]
    fn no_netns_quit_is_the_retry_only_and_matches_only_its_own_refusal() {
        let dir = std::path::Path::new("/run/user/1000/kern/pods/demo");
        let has = |watch: bool| {
            pasta_args(dir, 4242, watch)
                .iter()
                .any(|a| a == "--no-netns-quit")
        };
        assert!(
            !has(true),
            "the first attempt must keep pasta's netns watch"
        );
        assert!(has(false), "the retry must drop it, or the refusal recurs");

        // pasta's own string for the open that the flag elides, as reported in #6.
        assert!(is_netns_dir_denial(
            "netns dir open: Permission denied, exiting"
        ));
        // Every other failure must fail once, with its own message, and never be retried behind a
        // second attempt that changed an unrelated variable. These are real pasta stderr lines.
        for other in [
            "Couldn't open user namespace /proc/1/ns/user: Permission denied",
            "Could not open /proc/self/uid_map: Permission denied",
            "TUNSETIFF failed: Device or resource busy",
            "No routable interface for IPv6: IPv6 is disabled",
            "",
        ] {
            assert!(
                !is_netns_dir_denial(other),
                "{other:?} must not trigger the netns-watch retry"
            );
        }
    }

    #[test]
    fn starter_alive_false_for_dead_or_absent() {
        // A cleaned-up temp dir with no `starting` marker → not alive.
        let dir = std::env::temp_dir().join(format!("kern-pod-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        assert!(!starter_alive(&dir), "no marker → not alive");
        // A marker naming an impossible pid → not alive (kill(pid,0) fails).
        std::fs::write(dir.join("starting"), "2147483646").unwrap();
        assert!(!starter_alive(&dir), "dead/absent pid → not alive");
        // Our own live pid, bare (back-compat marker) → alive.
        let me = std::process::id();
        std::fs::write(dir.join("starting"), me.to_string()).unwrap();
        assert!(starter_alive(&dir), "our live bare pid → alive");
        // `pid:starttime` with the CORRECT start-time → alive (the winner's real marker).
        let st = crate::registry::proc_starttime(me as i32);
        std::fs::write(dir.join("starting"), format!("{me}:{st}")).unwrap();
        assert!(
            starter_alive(&dir),
            "live pid + matching start-time → alive"
        );
        // Same live pid but a WRONG start-time → treated as a reused pid → not a live starter.
        std::fs::write(dir.join("starting"), format!("{me}:{}", st.wrapping_add(1))).unwrap();
        assert!(
            !starter_alive(&dir),
            "start-time mismatch → reused pid → not alive"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod nat_sweep_tests {
    use super::pidfile_path_is_kerns;

    /// THE SWEEP'S OWNERSHIP TEST, WHICH DECIDES WHETHER A PROCESS GETS A SIGNAL.
    ///
    /// `sweep_orphan_nats` scans `/proc` and terminates what it finds, so the cost of a false
    /// positive is signalling something that is not kern's. This predicate is one of the three
    /// conditions that guard it (the others: the binary is `pasta`, and the namespace it watches no
    /// longer exists), and it is the only one that can be got wrong by being too generous.
    ///
    /// THE NEGATIVES ARE THE POINT. A path that merely mentions kern, a pidfile of another program
    /// under a kern directory, and a kern-shaped path that is not a NAT must all be refused.
    #[test]
    fn only_a_kern_nat_pidfile_is_recognised_as_ours() {
        for good in [
            "/run/user/1000/kern/pods/proj-abc123/pasta.pid",
            "/tmp/harness/kern/pods/tmp-1/pasta.pid",
            "/run/user/1000/kern/relays/proj-abc123/outbound/web/pasta.pid",
            "/var/tmp/x/kern/relays/s/outbound/db/pasta.pid",
        ] {
            assert!(pidfile_path_is_kerns(good), "{good} is one of ours");
        }
        for bad in [
            // Not a NAT pidfile at all.
            "/run/user/1000/kern/pods/proj/holder",
            "/run/user/1000/kern/pods/proj/pasta.id",
            // A pasta someone else runs, wherever it keeps its pidfile.
            "/run/user/1000/pasta.pid",
            "/home/alex/pasta.pid",
            "/tmp/pasta.pid",
            // Under a kern directory but not in a subtree kern puts NAT state in: the shape has to
            // match, not merely the word.
            "/run/user/1000/kern/scratch/box/pasta.pid",
            "/run/user/1000/kern/logs/pasta.pid",
            // A relays path with no `outbound/`: that tree holds the relay plan, not a NAT.
            "/run/user/1000/kern/relays/proj/pasta.pid",
            // The word appears, the shape does not.
            "/home/alex/my-kern-notes/pasta.pid",
            "",
        ] {
            assert!(!pidfile_path_is_kerns(bad), "{bad} must NOT be signalled");
        }
    }
}
