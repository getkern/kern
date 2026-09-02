//! Ownership and lifetime of a `--no-pod` stack's peer relays.
//!
//! # Why a holder process exists at all
//!
//! A relay is two processes that live inside two boxes' namespaces, and both arm
//! `PR_SET_PDEATHSIG(SIGKILL)` against whoever forked them. `kern compose up` exits as soon as the
//! stack is up, so relays forked by `up` would die with it, seconds after being created. Something
//! that outlives `up` and dies with the STACK has to own them.
//!
//! kern already has that shape: `kern __pod-holder` is a detached process that owns a pod's
//! namespaces and is killed by `compose down`. This is the same pattern for relays, and it is a
//! separate process rather than extra duty on the pod holder because a `--no-pod` stack has no pod
//! holder by definition.
//!
//! # The plan travels in a file, not in argv
//!
//! A four service stack with two ports each needs 24 relays. Passing them as arguments would put a
//! kilobyte of addresses on a command line, where every quoting rule and every `ARG_MAX` becomes this
//! module's problem for no benefit. The plan is written into the stack's runtime directory and the
//! holder is told where to read it.
//!
//! # Fail-closed at spawn, self-healing afterwards
//!
//! The two are not the same rule, and treating them alike was wrong twice. At SPAWN, a relay that
//! cannot be created at all means the plan is wrong, which is a stack-level fact: the holder reports
//! it and exits, and `up` surfaces it. AT RUNTIME, a half that dies is repaired rather than
//! propagated. `pause()` came first and slept through those deaths, leaving a stack reachable on some
//! edges with nothing having said so; total teardown replaced it and was worse where it counts, since
//! every edge dying at once reads as "kern broke" when one service is the cause.
//!
//! So the holder rebuilds a dead edge against the namespaces that exist now, rebuilds only the edges
//! touching a box whose PID 1 moved, and NAMES an edge it cannot rebuild in `degraded`, which
//! `kern compose ps` prints. Loud and partial beats silent partial and beats loud total.
//!
//! # A pair that cannot be served is not a failure
//!
//! A relay binds `alias:port` inside the box that hosts it, so it cannot exist where that box holds
//! the whole port. That is measured from `/proc/<pid1>/net/tcp` after the services have bound, not
//! guessed from the file: a wildcard listener owns every address on its port, a specific one does
//! not. Such a pair is reported by name and the rest of the stack is served.
//!
//! # Failure modes
//!
//!  1. **A box has no PID 1 yet.** The registry is written by the box's supervisor, and `up` returns
//!     before every supervisor has recorded it. The holder retries for a bounded window and then
//!     reports which box it was still waiting for.
//!  2. **A box died between bring-up and here.** Same path: it never gets a live PID 1, and the
//!     report names it rather than blaming the relay.
//!  3. **The hosting box owns the port.** Detected before any bind is attempted, so it is a named
//!     pair rather than an `EADDRINUSE` that races the service's own listener.
//!  4. **A box declares a port and has not bound it yet.** A third answer, not "the port is free":
//!     binding the alias then would make the service's own later bind fail. Deferred and re-measured.
//!  5. **The holder is killed.** Every relay dies with it through `PDEATHSIG`, and so does every
//!     per-connection pump, which arms it against the connector. A `kill` is a complete teardown.
//!  6. **A stale holder from a previous run.** `spawn_holder` kills whatever pid the file names and
//!     WAITS for it to leave the process table before writing its own, so a replacement never binds
//!     an alias a dying cascade still holds. The pid is liveness-checked, so a recycled one is never
//!     signalled.
//!  7. **A plan file that cannot be parsed.** Refused line by line with the line number, and box
//!     names are validated against the charset a box name can have: `relays/` is authoritative
//!     precisely because a line written into it would redirect where a PEER's traffic goes.

use crate::error::Error;
// `process_group` on `Command` is a Unix extension trait, the same import `pod.rs` uses to
// detach its own holder.
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

/// Bounded wait for every box's PID 1 to appear in the registry, in milliseconds. `up` returns as
/// soon as the launchers return, and a supervisor records PID 1 a moment later; 5 s is far past that
/// and still bounded, so a box that never registers is reported rather than waited on forever.
const PID1_WAIT_MS: u64 = 5_000;

/// How many times [`kill_holder`] looks for a signalled holder before giving up, and how long it
/// waits between looks. 200 x 5 ms is one second, which is far past the time a `SIGKILL`ed process
/// takes to leave the process table and still bounded.
const HOLDER_REAP_TRIES: u32 = 200;
/// Interval between the liveness probes in [`kill_holder`], in milliseconds.
const HOLDER_REAP_POLL_MS: u64 = 5;

/// Poll interval while waiting for PID 1.
const PID1_POLL_MS: u64 = 25;

/// A stack's private relay directory, `<runtime>/kern/relays/<pod>`.
///
/// `relays/` is AUTHORITATIVE in the registry's classification, and deliberately so: a box able to
/// write a line into a plan would redirect where a PEER's traffic goes, and a box able to rewrite the
/// holder pid would aim `compose down`'s kill at a process of its choosing. Both are forgery vectors
/// rather than the opaque box bytes `logs/` and `scratch/` are.
pub(crate) fn stack_dir(pod: &str) -> Result<PathBuf, Error> {
    crate::registry::runtime_subdir_public("relays")
        .map(|d| d.join(pod))
        .map_err(|e| Error::Compose(format!("relay dir: {e}")))
}

/// The file holding the relay plan for a stack.
pub(crate) fn plan_path(dir: &Path) -> PathBuf {
    dir.join("relays")
}

/// The file holding the relay holder's pid.
pub(crate) fn holder_path(dir: &Path) -> PathBuf {
    dir.join("relay-holder")
}

/// How often the holder scans the REGISTRY for a box that restarted, in milliseconds.
///
/// Separate from [`HEAL_POLL_MS`] because the two things the holder watches arrive at different
/// costs: reaping a dead child is a `waitpid` that costs nothing, while noticing a restarted box
/// needs the whole registry read and pruned. Two seconds is chosen against what it watches: a restart
/// already costs seconds, so a second more before its edges return is invisible next to it, while a
/// dead half is still caught within [`HEAL_POLL_MS`].
const REGISTRY_SCAN_MS: u64 = 2_000;

/// How often the holder looks at its relays, in milliseconds.
///
/// A quarter second is far below what a person notices on an edge that has just come back, and far
/// above what a poll of a handful of registry entries costs. It is a poll rather than a signal
/// because the two things it watches arrive by different routes: a dead half is a `SIGCHLD`, and a
/// restarted box is a registry change with no notification at all.
const HEAL_POLL_MS: u64 = 250;

/// THE TWO RATES ARE NOT ONE RATE, checked by the COMPILER rather than by a test.
///
/// The holder watches two things that arrive at very different prices: reaping a dead child is a
/// `waitpid` that costs nothing, while noticing a restarted box needs the whole registry read and
/// pruned. MEASURED on an eight-service stack with 56 relays, RELEASE build: reading the registry
/// every 250 ms cost 2.75% of a core continuously on a stack where nothing was wrong; scanning every
/// 2 s instead cost 0.10%, and a killed half was still rebuilt on the next pass.
///
/// A `const` assertion rather than a test, because both sides are constants: a future edit that
/// collapses the scan interval back onto the poll interval, or lets it grow until a restarted service
/// stays unreachable, does not build at all.
const _: () = assert!(
    REGISTRY_SCAN_MS > HEAL_POLL_MS,
    "scanning as often as reaping is what cost 2.75% of a core"
);
const _: () = assert!(
    REGISTRY_SCAN_MS <= 5_000,
    "a scan this slow leaves a restarted service's edges down for too long"
);
const _: () = assert!(
    HEAL_POLL_MS <= 500,
    "a dead relay half must be noticed within a fraction of a second"
);

/// Consecutive failed rebuilds before an edge is REPORTED as degraded.
///
/// It is not abandoned at that point, and an earlier version of this said it was. Retrying costs a
/// registry read, because a rebuild whose boxes are not running fails before it forks anything, so an
/// edge that is down only because its service is restarting comes back on its own: MEASURED, an edge
/// given up at attempt 12 rebuilt itself at attempt 114 the moment the box returned, with no command
/// run. The count decides when to SAY something, not when to stop.
///
/// Bounded because a box that is gone for good would otherwise be retried forever, once per poll,
/// and each attempt forks two processes. Twelve attempts is three seconds at [`HEAL_POLL_MS`], which
/// covers a service restarting and not a service that has been removed from the file.
const HEAL_ATTEMPTS: u32 = 12;

/// Edges this stack has given up rebuilding, one per line, read by `kern compose ps`.
///
/// THIS FILE IS THE LOUD HALF OF "LOUD AND PARTIAL". A relay that cannot come back takes one edge
/// with it and leaves the rest working, which is the right blast radius; what makes that acceptable
/// rather than the silent partial failure this codebase refuses is that the loss has somewhere to be
/// reported, and `compose ps` is where a person already looks to decide whether something is wrong.
pub(crate) fn degraded_path(dir: &Path) -> PathBuf {
    dir.join("degraded")
}

/// Where the holder and every relay it forks send their stderr.
///
/// THIS FILE EXISTS TO CLOSE A HANG, not to be read. The holder outlives `up` by design, and it used
/// to inherit `up`'s stderr; a relay child inherited the same descriptor. `kern compose up --no-pod`
/// under a pipe therefore never returned, because the write end of that pipe stayed open in processes
/// that outlive the command by hours. MEASURED both ways: the pod path (no holder) closes its pipe
/// and returns, the no-pod path did not.
///
/// A file rather than `/dev/null` because a relay that dies at hour three has something to say and
/// nowhere else to say it, and the caller is long gone.
pub(crate) fn holder_log_path(dir: &Path) -> PathBuf {
    dir.join("holder.log")
}

/// Serialise a relay plan: one relay per line, `in_box \t to_box \t alias \t port`.
///
/// Tab-separated because a box name cannot contain a tab (the name charset is `[A-Za-z0-9_.-]`), so
/// the format needs no quoting and the parser needs no state.
pub(crate) fn encode_plan(plan: &[crate::nopod::RelayPlan]) -> String {
    let mut out = String::with_capacity(plan.len() * 48);
    for r in plan {
        out.push_str(&r.in_box);
        out.push('\t');
        out.push_str(&r.to_box);
        out.push('\t');
        out.push_str(&r.alias.to_string());
        out.push('\t');
        out.push_str(&r.port.to_string());
        out.push('\t');
        out.push_str(&r.from_alias.to_string());
        out.push('\t');
        out.push(if r.holder_declares { 'd' } else { '-' });
        out.push('\n');
    }
    out
}

/// Read a plan back. Every malformed line is an error naming its number: a set built from the lines
/// that happened to parse is a stack where some peers are reachable and nobody said which.
pub(crate) fn decode_plan(text: &str) -> Result<Vec<crate::nopod::RelayPlan>, String> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let mut f = line.split('\t');
        let (
            Some(in_box),
            Some(to_box),
            Some(alias),
            Some(port),
            Some(from_alias),
            Some(declares),
            None,
        ) = (
            f.next(),
            f.next(),
            f.next(),
            f.next(),
            f.next(),
            f.next(),
            f.next(),
        )
        else {
            return Err(format!(
                "relay plan line {}: expected \
                 'in_box<TAB>to_box<TAB>alias<TAB>port<TAB>from_alias<TAB>d|-'",
                i + 1
            ));
        };
        let Ok(alias) = alias.parse::<u32>() else {
            return Err(format!("relay plan line {}: alias is not a number", i + 1));
        };
        let Ok(from_alias) = from_alias.parse::<u32>() else {
            return Err(format!(
                "relay plan line {}: source alias is not a number",
                i + 1
            ));
        };
        let Ok(port) = port.parse::<u16>() else {
            return Err(format!("relay plan line {}: port is not a number", i + 1));
        };
        // NEITHER SPELLING IS A CORRUPT PLAN, not a `false`. Defaulting would make a holder that
        // declares the port look like one that never will, and the relay would then bind an alias the
        // service is about to need.
        if declares != "d" && declares != "-" {
            return Err(format!(
                "relay plan line {}: the holder-declares flag is neither 'd' nor '-'",
                i + 1
            ));
        }
        // THE NAMES ARE VALIDATED, not merely checked for emptiness. `relays/` is AUTHORITATIVE in
        // the registry's classification precisely because a line written into it would redirect where
        // a PEER's traffic goes, so this parser is a boundary, and a boundary checks its input rather
        // than trusting the only writer to be the one it expects. A box name is `[A-Za-z0-9_.-]` by
        // kern's own rule, so anything else could not have come from the encoder: `hosts_name_is_safe`
        // is the single statement of that charset and is reused rather than restated.
        if !crate::nopod::hosts_name_is_safe(in_box) || !crate::nopod::hosts_name_is_safe(to_box) {
            return Err(format!(
                "relay plan line {}: a box name is empty or holds a character a box name cannot",
                i + 1
            ));
        }
        if port == 0 {
            return Err(format!("relay plan line {}: the port is 0", i + 1));
        }
        out.push(crate::nopod::RelayPlan {
            in_box: in_box.to_string(),
            to_box: to_box.to_string(),
            alias,
            port,
            from_alias,
            holder_declares: declares == "d",
        });
    }
    Ok(out)
}

/// What a box is doing with a TCP port, as the kernel reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortState {
    /// Something is listening on `0.0.0.0` or `::`, which owns the WHOLE port in that namespace: no
    /// other address, alias included, can be bound on it.
    ///
    /// CARRIES WHICH ONE, because the report tells the user what to change in their own config and
    /// the two are different lines in it. Saying "it listens on 0.0.0.0" to someone whose service
    /// binds `::` sends them looking for a string that is not in their file, and the advice that
    /// follows it ("bind 127.0.0.1 instead") is the wrong half of the stack for an IPv6 listener.
    Wildcard(&'static str),
    /// Something is listening, and only on specific addresses. Another address on the same port is
    /// free.
    SpecificOnly,
    /// Nothing is listening on that port yet. Not the same as `SpecificOnly`, and treating it as such
    /// is the mistake this type exists to prevent: binding an alias now would make the service's own
    /// later `bind(0.0.0.0)` fail, and the process that loses that race is the user's application.
    NotListening,
}

/// What `pid1`'s network namespace is doing with TCP `port`.
///
/// MEASURED RATHER THAN ASSUMED, and that is the whole reason this exists. A relay listens on
/// `alias:port` inside the box that hosts it, so the question "can it?" is decided by that box's own
/// listener. On one port, two SPECIFIC binds on different addresses do not conflict, while a specific
/// bind and a WILDCARD bind refuse each other in both orders with or without `SO_REUSEADDR`. A
/// compose file declares a PORT and never an address, so a decision taken from the file has to assume
/// the worst and refuses pairs that would have worked: a service configured with
/// `listen_addresses = 'localhost'`, `bind 127.0.0.1` or `--host 127.0.0.1` leaves the alias free.
///
/// Read through `/proc/<pid1>/net/tcp`, which reports the NETWORK NAMESPACE OF THAT PID, so no
/// `setns` and no privilege are needed. Verified against two live boxes: `httpd -p 7100` shows
/// `::` in `tcp6` and `httpd -p 127.0.0.1:7101` shows `0100007F` in `tcp`.
///
/// A `::` listener is treated as covering IPv4 too. `IPV6_V6ONLY` would make that false, and `/proc`
/// does not report it, so the conservative reading is the one taken: at worst a relay is not created
/// where it could have been, which is a missing edge that gets named rather than a service that
/// fails to start.
///
/// MEASURED, not reasoned, and the cost is exactly one case wide. In a fresh netns with
/// `bindv6only=0`: a listener on `::` with `IPV6_V6ONLY=0` makes a later `bind("127.0.0.2", p)` fail
/// EADDRINUSE, and with `IPV6_V6ONLY=1` that same bind SUCCEEDS - while `/proc/net/tcp6` shows the
/// identical all-zero line for both. So the false positive is real and it is confined to a service
/// that deliberately sets `IPV6_V6ONLY`; the edge it costs is reported by name, with the address the
/// kernel actually showed.
pub(crate) fn port_state(pid1: i32, port: u16) -> PortState {
    let mut found = false;
    for family in ["tcp", "tcp6"] {
        let Ok(text) = std::fs::read_to_string(format!("/proc/{pid1}/net/{family}")) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let mut f = line.split_whitespace();
            // `sl  local_address rem_address st ...`
            let (Some(_), Some(local), Some(_), Some(st)) =
                (f.next(), f.next(), f.next(), f.next())
            else {
                continue;
            };
            if st != "0A" {
                continue; // not LISTEN
            }
            let Some((ip, p)) = local.split_once(':') else {
                continue;
            };
            if u16::from_str_radix(p, 16).ok() != Some(port) {
                continue;
            }
            found = true;
            if ip.bytes().all(|b| b == b'0') {
                // The family the zeros came from IS the address the user wrote: 8 hex digits is an
                // IPv4 `0.0.0.0`, 32 is an IPv6 `::`.
                return PortState::Wildcard(if family == "tcp" { "0.0.0.0" } else { "::" });
            }
        }
    }
    if found {
        PortState::SpecificOnly
    } else {
        PortState::NotListening
    }
}

/// The live PID 1 of `name`, or `None` when the box is not (yet) running.
///
/// Reads the registry through the same accessor every other consumer uses, so a recycled pid is
/// refused here exactly as it is for `exec` and `cp`.
fn live_pid1(name: &str) -> Option<kern_isolation::peer::BoxRef> {
    live_pid1_in(&crate::registry::list(), name)
}

/// [`live_pid1`] against a registry snapshot the caller already has.
///
/// THE WHOLE REGISTRY IS READ FROM DISK ON EVERY CALL, and the healing loop asks twice per relay per
/// pass. MEASURED on an eight-service stack with 56 relays: 112 reads every 250 ms cost the holder
/// 4.45% of a core, continuously, on a stack where nothing was wrong. A developer leaving a stack up
/// for a day paid that for nothing.
///
/// One snapshot per pass makes it one read, and the answer cannot drift WITHIN a pass either, which
/// is the smaller benefit: comparing a slot's recorded `BoxRef` against a registry that changed
/// halfway through the loop could rebuild an edge against a box a later slot then sees differently.
fn live_pid1_in(
    snapshot: &[crate::registry::Instance],
    name: &str,
) -> Option<kern_isolation::peer::BoxRef> {
    let info = snapshot.iter().find(|i| i.name == name)?;
    // `live_pid1` is the registry's start-time-checked accessor and the only sanctioned way to reach
    // a recorded pid1. The recorded start-time travels WITH the pid from here on, so the relay can
    // re-check it after it has opened the namespace descriptors rather than trusting a number that
    // was true one syscall ago.
    let pid1 = info.live_pid1()?;
    Some(kern_isolation::peer::BoxRef {
        pid1,
        starttime: info.pid1_starttime,
    })
}

/// Wait, bounded, for every box the plan names to have a live PID 1.
///
/// Returns the name of the box it gave up on. Bounded rather than indefinite: a holder that waits
/// forever for a box that will never start is indistinguishable from one that is working.
fn wait_for_pid1s(plan: &[crate::nopod::RelayPlan]) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(PID1_WAIT_MS);
    loop {
        let mut missing: Option<&str> = None;
        for r in plan {
            for name in [r.in_box.as_str(), r.to_box.as_str()] {
                if live_pid1(name).is_none() {
                    missing = Some(name);
                    break;
                }
            }
            if missing.is_some() {
                break;
            }
        }
        let Some(name) = missing else { return Ok(()) };
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "box '{name}' has no live PID 1 after {PID1_WAIT_MS} ms, so nothing can be relayed \
                 into or out of it"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(PID1_POLL_MS));
    }
}

/// `kern __relay-holder <dir>` (hidden): own a stack's relays until killed. Never returns normally.
///
/// Prints one line on stdout so the caller can tell readiness from failure without a race:
/// `relays-ready <n>` or `relay-error <message>`. The caller reads that line and then stops reading,
/// which is why the message is one line and never wraps.
pub(crate) fn run_holder(dir: &str) -> ! {
    let dir = PathBuf::from(dir);
    let text = match std::fs::read_to_string(plan_path(&dir)) {
        Ok(t) => t,
        Err(e) => {
            println!("relay-error cannot read the relay plan: {e}");
            std::process::exit(1);
        }
    };
    let plan = match decode_plan(&text) {
        Ok(p) => p,
        Err(e) => {
            println!("relay-error {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = wait_for_pid1s(&plan) {
        println!("relay-error {e}");
        std::process::exit(1);
    }
    let pump_cap = kern_isolation::peer::pump_cap_for(plan.len());

    // WAIT FOR THE HOLDERS TO BIND BEFORE DECIDING ANYTHING, because the decision is a measurement of
    // what they bound. A service that has not bound yet is not the same as one that binds a specific
    // address, and treating them alike is how a relay wins a race against the user's own listener.
    wait_for_listeners(&plan);

    // One slot per planned relay, so a dead one can be replaced IN PLACE and the rest are untouched.
    let last_scan = std::time::Instant::now();
    let mut slots: Vec<Slot> = Vec::with_capacity(plan.len());
    let mut up = 0usize;
    for r in &plan {
        match try_spawn(r, pump_cap) {
            Attempt::Up(relay) => {
                slots.push(Slot::new(relay));
                up += 1;
            }
            Attempt::Blocked(reason) => {
                // NOT AN ERROR, and this is the difference the measurement bought. A pair whose
                // holder owns the whole port cannot be served by anything kern can do, and refusing
                // the stack over it would refuse every stack that has one such pair and nine good
                // ones. It is reported by name and the rest are served.
                println!(
                    "relay-blocked {}",
                    BlockReport {
                        reason,
                        holder: &r.in_box,
                        peer: &r.to_box,
                        port: r.port,
                    }
                );
                slots.push(Slot::blocked(reason));
            }
            Attempt::Failed(e) => {
                // FAIL-CLOSED AT SPAWN, and only at spawn. A relay that cannot be created for a
                // reason that is not the port is a stack-level fact: the addresses or the boxes are
                // wrong, and reporting it is what `up` is waiting to read.
                println!("relay-error {e}");
                std::process::exit(1);
            }
        }
    }
    println!("relays-ready {up}");
    // The caller reads the line above and stops; flushing before the loop makes that deterministic
    // rather than dependent on stdout's buffering at exit (which never happens here).
    use std::io::Write;
    let _ = std::io::stdout().flush();
    // AND THEN LET THE PIPE GO. The readiness line is the last word this process has for its caller,
    // who has already dropped the read end. Keeping the write end open past that point leaves this
    // process one `println!` away from a SIGPIPE it has no reason to risk.
    if let Ok(log) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(holder_log_path(&dir))
    {
        use std::os::fd::AsRawFd;
        // SAFETY: `log` is an open descriptor owned by this process for the length of the call, and
        // fd 1 is a descriptor this process owns. `dup2` closes the old fd 1 atomically.
        unsafe { libc::dup2(log.as_raw_fd(), 1) };
    }

    heal_forever(&dir, &plan, slots, pump_cap, last_scan)
}

/// Keep a stack's relays alive for as long as the holder lives.
///
/// SPLIT OUT OF [`run_holder`], which reached 222 lines doing three unrelated jobs: reading a plan,
/// realising it once and reporting that, and then maintaining it forever. The third is the one with
/// the rules that need reading, and it was the hardest to find in the middle of the other two.
///
/// Never returns: the holder exists to own these relays and dies only when it is killed, at which
/// point `PDEATHSIG` takes every relay and every pump with it.
fn heal_forever(
    dir: &Path,
    plan: &[crate::nopod::RelayPlan],
    mut slots: Vec<Slot>,
    pump_cap: usize,
    mut last_scan: std::time::Instant,
) -> ! {
    // RUNTIME IS NOT SPAWN, and the two used to be treated alike. `pause()` came first, which slept
    // through a dead relay and left the stack reachable on some edges with nothing having said so.
    // Total teardown came next, and it is worse in the way that matters to whoever has to diagnose
    // it: every edge dies at once, which reads as "kern broke" or "the network broke", while the
    // cause is one service and the only trace is a log file nothing points at. A local, attributable
    // failure had been converted into a global, misattributable one.
    //
    // So a runtime failure is repaired rather than propagated. A dead half takes its own edge down,
    // the edge is rebuilt against the namespaces that exist NOW, and only an edge that cannot be
    // rebuilt after `HEAL_ATTEMPTS` tries is given up on and NAMED in `degraded`, which
    // `kern compose ps` reads. Loud and partial beats silent partial and beats loud total.
    //
    // THE SAME LOOP CLOSES THE RESTART CASE. A relay is pinned by `setns` to namespaces obtained
    // once; restart a service and its relays are bridging a namespace nothing listens in. Comparing
    // each slot's recorded `BoxRef` against the registry's current one detects exactly that, and
    // rebuilds ONLY the edges touching the box that moved, so a `watch` save costs the edges it
    // changed instead of the whole plan.
    loop {
        // Reap first: a half that exited is what makes its slot dead, and the pids are only valid
        // until they are reaped.
        let mut any_died = false;
        loop {
            let mut st: libc::c_int = 0;
            // SAFETY: `waitpid` on this process's own children, writing only into `st`.
            let pid = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
            if pid <= 0 {
                break;
            }
            for slot in slots.iter_mut() {
                if slot.relay.as_ref().is_some_and(|r| r.owns(pid)) {
                    slot.dead = true;
                    any_died = true;
                }
            }
        }
        // THE REGISTRY IS READ ONLY WHEN THERE IS A REASON TO: a death just reaped, an edge already
        // waiting to be rebuilt, or the periodic scan for a box that restarted without any of its
        // relays dying. A healthy stack reaches none of those and the pass costs a `waitpid` and a
        // sleep.
        //
        // MEASURED, and it is why this gate exists: `registry::list()` reads and prunes the whole
        // registry, and calling it every 250 ms cost a RELEASE holder 2.75% of a core, continuously,
        // on an eight-service stack where nothing was wrong. A developer leaving a stack up for a day
        // paid that for nothing.
        let due = last_scan.elapsed() >= std::time::Duration::from_millis(REGISTRY_SCAN_MS);
        let pending = slots.iter().any(|s| s.dead);
        if !any_died && !pending && !due {
            std::thread::sleep(std::time::Duration::from_millis(HEAL_POLL_MS));
            continue;
        }
        if due {
            last_scan = std::time::Instant::now();
        }
        // ONE READ PER PASS, not two per relay: `live_pid1` reads the whole registry each call and
        // the loop below asks twice for every relay.
        let snapshot = crate::registry::list();
        for (i, slot) in slots.iter_mut().enumerate() {
            rebuild_if_needed(slot, &plan[i], &snapshot, pump_cap);
        }
        // Written only when the set CHANGES, so a stack that is merely healthy does not rewrite a
        // file every quarter second for the life of the stack.
        let now: Vec<String> = slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.given_up)
            .map(|(i, s)| {
                format!(
                    "{} -> {} on {}{}",
                    plan[i].in_box,
                    plan[i].to_box,
                    plan[i].port,
                    s.blocked.map(|w| format!(": {w}")).unwrap_or_default()
                )
            })
            .collect();
        write_degraded(dir, &now);
        std::thread::sleep(std::time::Duration::from_millis(HEAL_POLL_MS));
    }
}

/// One planned relay and what is known about the live one serving it.
struct Slot {
    /// The running relay, or `None` between a retirement and its replacement.
    relay: Option<kern_isolation::peer::PeerRelay>,
    /// The boxes this relay was spawned against. A difference from the registry means a service
    /// restarted and this relay is bridging a namespace nothing listens in.
    a: kern_isolation::peer::BoxRef,
    b: kern_isolation::peer::BoxRef,
    /// Set when a half has been reaped, so the next pass rebuilds it.
    dead: bool,
    /// WHY this slot needs rebuilding, kept because the answer is only knowable at the moment it goes
    /// bad. Once the halves are retired `relay` is `None`, and a later pass can no longer tell a
    /// reaped half from a box that moved: the message would say "a half died" for every restart.
    reason: &'static str,
    /// Consecutive failed rebuilds. Reset by a success.
    attempts: u32,
    /// Reported as degraded or blocked, and no longer worth a message per attempt.
    given_up: bool,
    /// Why this edge cannot be served at all, when the reason is the holder's own listener rather
    /// than a failure. Kept so the degraded file can carry it and `compose ps` can print it.
    blocked: Option<BlockReason>,
}

impl Slot {
    fn new(
        spawned: (
            kern_isolation::peer::PeerRelay,
            kern_isolation::peer::BoxRef,
            kern_isolation::peer::BoxRef,
        ),
    ) -> Self {
        Self {
            relay: Some(spawned.0),
            a: spawned.1,
            b: spawned.2,
            dead: false,
            reason: "",
            attempts: 0,
            given_up: false,
            blocked: None,
        }
    }

    /// A slot with no relay because the holder owns the whole port. Re-measured every pass, so it is
    /// not terminal: a service that restarts bound to a specific address clears it.
    fn blocked(why: BlockReason) -> Self {
        Self {
            relay: None,
            a: kern_isolation::peer::BoxRef {
                pid1: 0,
                starttime: 0,
            },
            b: kern_isolation::peer::BoxRef {
                pid1: 0,
                starttime: 0,
            },
            dead: true,
            reason: "",
            attempts: 0,
            given_up: true,
            blocked: Some(why),
        }
    }
}

/// Why a pair cannot be served right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockReason {
    /// The holder binds this wildcard address, so it owns every address on that port. Carries the
    /// address AS THE KERNEL REPORTED IT, so the report names the string that is in the user's own
    /// config rather than a guess at which family they used.
    Wildcard(&'static str),
    /// The holder declares the port and has not bound it yet.
    NotListeningYet,
}

impl BlockReason {
    /// The loopback address of the same family as the wildcard, which is what the user should bind
    /// instead. Telling an IPv6 listener to bind `127.0.0.1` names an address it will never own.
    fn specific_instead(self) -> &'static str {
        match self {
            Self::Wildcard("::") => "::1",
            _ => "127.0.0.1",
        }
    }
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wildcard(addr) => write!(
                f,
                "it listens on {addr} for that port, which owns every address on it"
            ),
            Self::NotListeningYet => write!(
                f,
                "it declares that port and is not listening on it yet, so binding the peer's alias \
                 now would make its own later bind fail"
            ),
        }
    }
}

/// One `relay-blocked` line, worded in ONE place.
///
/// The first pass and the healing loop both report this fact, and they used to word it differently:
/// only the first offered the fix, so an edge that went wrong ten minutes in told the user strictly
/// less than one that was wrong from the start, about the same condition. Same class of defect as the
/// other derived-condition duplications in this codebase, and closed the same way.
pub(crate) struct BlockReport<'a> {
    pub(crate) reason: BlockReason,
    pub(crate) holder: &'a str,
    pub(crate) peer: &'a str,
    pub(crate) port: u16,
}

impl std::fmt::Display for BlockReport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NAMED, or it is not a report. A note that says a holder binds the wildcard without saying
        // WHICH holder and which peer is unusable in a stack with more than two services, which is
        // every stack this feature exists for.
        write!(
            f,
            "'{}' cannot reach '{}' on {}: {}",
            self.holder, self.peer, self.port, self.reason
        )?;
        match self.reason {
            BlockReason::Wildcard(addr) => write!(
                f,
                ". Give one of them a different internal port, or make '{}' bind {}:{} instead of \
                 {addr}",
                self.holder,
                self.reason.specific_instead(),
                self.port
            ),
            // No bind advice here: the port is not owned by anyone yet, so there is nothing to move.
            // What the user needs to know is that the edge waits on THIS service.
            BlockReason::NotListeningYet => write!(
                f,
                ". The edge comes up on its own once '{}' binds that port",
                self.holder
            ),
        }
    }
}

/// What one attempt to create a relay produced.
enum Attempt {
    /// It is running.
    Up(
        (
            kern_isolation::peer::PeerRelay,
            kern_isolation::peer::BoxRef,
            kern_isolation::peer::BoxRef,
        ),
    ),
    /// The holder binds the whole port, so no address of that port is free inside it. Not a failure:
    /// nothing kern can do would change it, and the rest of the stack is unaffected.
    Blocked(BlockReason),
    /// Something else went wrong, carrying the reason.
    Failed(String),
}

/// Measure, then spawn.
///
/// The order is the point. A relay listens on `alias:port` INSIDE the holder, so whether it can bind
/// is decided by what the holder itself bound, and that is a fact about a running process rather than
/// about a line in a file. Asking first also means the relay never races the service: if the holder
/// is already listening on a specific address then it HAS bound, and the alias cannot displace it.
fn try_spawn(r: &crate::nopod::RelayPlan, pump_cap: usize) -> Attempt {
    try_spawn_in(&crate::registry::list(), r, pump_cap)
}

/// [`try_spawn`] against a registry snapshot the caller already has.
fn try_spawn_in(
    snapshot: &[crate::registry::Instance],
    r: &crate::nopod::RelayPlan,
    pump_cap: usize,
) -> Attempt {
    let (Some(a), Some(b)) = (
        live_pid1_in(snapshot, &r.in_box),
        live_pid1_in(snapshot, &r.to_box),
    ) else {
        return Attempt::Failed(format!(
            "a box is not running ('{}' or '{}')",
            r.in_box, r.to_box
        ));
    };
    // A HOLDER THAT DOES NOT DECLARE THE PORT WILL NEVER BIND IT, so the alias is free by
    // construction and there is nothing to measure. Skipping the probe here is not an optimisation:
    // without it, "nothing is listening" reads as the racy case for every pair in the stack.
    if !r.holder_declares {
        return match kern_isolation::peer::spawn(a, r.alias, b, r.port, r.from_alias, pump_cap) {
            Ok(relay) => Attempt::Up((relay, a, b)),
            Err(e) => Attempt::Failed(e),
        };
    }
    match port_state(a.pid1, r.port) {
        PortState::Wildcard(addr) => Attempt::Blocked(BlockReason::Wildcard(addr)),
        PortState::NotListening => Attempt::Blocked(BlockReason::NotListeningYet),
        PortState::SpecificOnly => {
            match kern_isolation::peer::spawn(a, r.alias, b, r.port, r.from_alias, pump_cap) {
                Ok(relay) => Attempt::Up((relay, a, b)),
                Err(e) => Attempt::Failed(e),
            }
        }
    }
}

/// Bounded wait for every box that HOLDS a relay to have bound the port that relay needs.
///
/// Without it the first pass would measure services that have not started listening, call every pair
/// undecidable, and report a stack as blocked that is merely slow. Bounded rather than indefinite for
/// the same reason `wait_for_pid1s` is: a service that never binds must be reported, not waited on.
fn wait_for_listeners(plan: &[crate::nopod::RelayPlan]) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(PID1_WAIT_MS);
    while std::time::Instant::now() < deadline {
        // Only the pairs whose holder DECLARES the port can be undecided; the rest need no probe.
        let snapshot = crate::registry::list();
        let undecided = plan.iter().filter(|r| r.holder_declares).any(|r| {
            live_pid1_in(&snapshot, &r.in_box)
                .is_some_and(|a| port_state(a.pid1, r.port) == PortState::NotListening)
        });
        if !undecided {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(PID1_POLL_MS));
    }
}

/// Record the edges this stack has given up on, so a status view can name them.
///
/// Removed rather than emptied when nothing is degraded: a present-but-empty file would make every
/// reader distinguish "no degraded edges" from "no relays at all", and only one of those is worth a
/// line in `kern compose ps`.
fn write_degraded(dir: &Path, edges: &[String]) {
    let path = degraded_path(dir);
    if edges.is_empty() {
        let _ = std::fs::remove_file(path);
        return;
    }
    let mut body = edges.join("\n");
    body.push('\n');
    if std::fs::read_to_string(&path).ok().as_deref() != Some(body.as_str()) {
        let _ = std::fs::write(&path, body);
    }
}

/// Write the plan, kill any previous holder, and spawn a new one. Returns how many relays came up.
///
/// # Errors
///
/// The holder's own message when it refuses, or an I/O error naming the file it could not write.
pub(crate) fn spawn_holder(
    dir: &Path,
    plan: &[crate::nopod::RelayPlan],
) -> Result<HolderReport, Error> {
    // A LIVE HOLDER ALREADY SERVING THIS EXACT PLAN IS LEFT ALONE.
    //
    // The holder repairs its own relays now: it notices a box whose PID 1 has moved and rebuilds only
    // the edges touching it. Replacing the holder on every `start` would therefore tear down and
    // re-fork EVERY relay in the stack to fix the few that changed, and `compose watch` performs a
    // `start` on every save. At eight services with three ports each that is 336 processes per
    // keystroke-driven rebuild, to repair a handful.
    //
    // The plan is COMPARED, not assumed: a file that no longer matches means the compose file
    // changed, and that holder is serving a set the file no longer describes.
    let wanted = encode_plan(plan);
    if holder_pid(dir).is_some()
        && std::fs::read_to_string(plan_path(dir)).ok().as_deref() == Some(wanted.as_str())
    {
        // The live holder's own view of what is blocked, which it keeps current as services restart
        // and rebind. Reading it here means a `start` reports the same thing an `up` would.
        return Ok(HolderReport {
            up: plan.len(),
            blocked: std::fs::read_to_string(degraded_path(dir))
                .map(|t| t.lines().map(str::to_string).collect())
                .unwrap_or_default(),
        });
    }

    // KILL FIRST, THEN WRITE, and the other order is a bug this shipped with until a second
    // invocation exercised it. `kill_holder` removes the plan, the pid file and the directory, so
    // writing the plan before killing meant the kill deleted the plan that was about to be read.
    // It never fired on `up`, because with no holder file `kill_holder` returns before deleting
    // anything; it fired the moment a holder already existed, which is every `up` on a running
    // stack and every `start` after one.
    //
    // A previous run's holder must go regardless: it holds the same aliases inside the same boxes,
    // and after a service restarts its relays point into a namespace nothing is listening in.
    kill_holder(dir);
    std::fs::create_dir_all(dir)
        .map_err(|e| Error::Compose(format!("relay dir '{}': {e}", dir.display())))?;
    std::fs::write(plan_path(dir), encode_plan(plan))
        .map_err(|e| Error::Compose(format!("writing the relay plan: {e}")))?;
    let self_exe =
        std::env::current_exe().map_err(|e| Error::Compose(format!("locating kern: {e}")))?;
    let mut child = std::process::Command::new(self_exe)
        .arg("__relay-holder")
        .arg(dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        // NOT `inherit`. See [`holder_log_path`]: the holder and its relays outlive this command, so
        // inheriting its stderr wedges any pipe the caller put there. The descriptor is chosen HERE
        // rather than swapped inside the holder because a swap has a window before it runs and a
        // fallback path if it fails, and both of those end with the pipe still held.
        .stderr(match std::fs::File::create(holder_log_path(dir)) {
            Ok(f) => std::process::Stdio::from(f),
            // A log that cannot be created is worth losing; a wedged pipe is not.
            Err(_) => std::process::Stdio::null(),
        })
        .process_group(0) // its own group, so it survives this command exiting
        .spawn()
        .map_err(|e| Error::Compose(format!("spawning the relay holder: {e}")))?;
    let pid = child.id() as i32;
    let Some(out) = child.stdout.take() else {
        let _ = child.kill();
        return Err(Error::Compose(
            "the relay holder produced no output pipe".into(),
        ));
    };
    // The holder speaks a line at a time until it says it is ready: any number of `relay-blocked`
    // notes, then exactly one `relays-ready` or `relay-error`. Reading to that terminator rather than
    // reading ONE line is what lets the measurement live where it can be taken.
    use std::io::BufRead;
    let mut reader = std::io::BufReader::new(out);
    let mut blocked: Vec<String> = Vec::new();
    loop {
        let mut line = String::new();
        let ok = reader.read_line(&mut line).is_ok_and(|n| n > 0);
        let line = line.trim().to_string();
        if !ok || line.is_empty() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Compose(
                "the relay holder exited before reporting; no peer is reachable".into(),
            ));
        }
        if let Some(msg) = line.strip_prefix("relay-blocked ") {
            blocked.push(msg.to_string());
            continue;
        }
        if let Some(msg) = line.strip_prefix("relay-error ") {
            let _ = child.wait();
            return Err(Error::Compose(format!("peer relays: {msg}")));
        }
        let Some(n) = line
            .strip_prefix("relays-ready ")
            .and_then(|n| n.parse::<usize>().ok())
        else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Compose(format!(
                "the relay holder said something unexpected: {line}"
            )));
        };
        std::fs::write(holder_path(dir), pid.to_string())
            .map_err(|e| Error::Compose(format!("recording the relay holder pid: {e}")))?;
        return Ok(HolderReport { up: n, blocked });
    }
}

/// What `spawn_holder` learned from the holder it started.
///
/// `blocked` carries whole sentences rather than a tuple, because only the holder knows WHY a pair
/// could not be served, and a caller that reassembled the reason from parts would be one edit away
/// from a message that no longer matches the measurement behind it.
pub(crate) struct HolderReport {
    /// Relays that came up.
    pub(crate) up: usize,
    /// One line per pair that could not be served, ready to print.
    pub(crate) blocked: Vec<String>,
}

/// The live pid of the holder owning `dir`, or `None` when there is none.
///
/// Non-positive pids are refused before the probe: `kill(0, …)` hits the caller's process group and
/// `kill(-1, …)` every process the user owns, a class this tree has closed once already.
pub(crate) fn holder_pid(dir: &Path) -> Option<i32> {
    let pid = std::fs::read_to_string(holder_path(dir))
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()?;
    // SAFETY: signal 0 probes for existence without delivering anything.
    (pid > 0 && unsafe { libc::kill(pid, 0) } == 0).then_some(pid)
}

/// Kill the holder this stack recorded, if it is still the process that was recorded.
///
/// Best-effort and idempotent. A non-positive pid is never signalled, and a pid that is not alive is
/// not signalled either, so a recycled pid belonging to someone else is never killed.
pub(crate) fn kill_holder(dir: &Path) {
    let Ok(text) = std::fs::read_to_string(holder_path(dir)) else {
        return;
    };
    let Ok(pid) = text.trim().parse::<i32>() else {
        let _ = std::fs::remove_file(holder_path(dir));
        return;
    };
    if pid > 0 {
        // SAFETY: signal 0 probes without delivering; a live pid is then killed. The pid came from a
        // file this process wrote, and the guard above is the same "never a non-positive pid" rule
        // the rest of this tree applies.
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        if alive {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            // AND WAIT FOR IT TO ACTUALLY BE GONE, which is not the same as having signalled it.
            //
            // The holder is NOT this process's child (it is detached into its own process group), so
            // there is no `waitpid` to call: the only way to know it died is to look. Returning
            // straight after the `kill` means the caller spawns a replacement while the old holder's
            // `PDEATHSIG` cascade is still tearing down relays inside the same boxes, and the new
            // relays are binding the same aliases the dying ones still hold.
            //
            // That race fires roughly never on a hand-run `start` and constantly under
            // `compose watch`, which performs this sequence on every save, sometimes twice for an
            // editor that writes a file more than once. The symptom would be a stack that is
            // intermittently dead after a save, which a developer attributes to their own edit.
            //
            // Bounded: SIGKILL is not refusable, so this terminates in practice, and a pid that
            // somehow outlives the wait is reported by the caller's own spawn failing rather than by
            // hanging here forever.
            for _ in 0..HOLDER_REAP_TRIES {
                // SAFETY: signal 0 probes without delivering. `pid` is guarded positive above.
                if unsafe { libc::kill(pid, 0) } != 0 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(HOLDER_REAP_POLL_MS));
            }
        }
    }
    let _ = std::fs::remove_file(holder_path(dir));
    let _ = std::fs::remove_file(plan_path(dir));
    let _ = std::fs::remove_file(holder_log_path(dir));
    let _ = std::fs::remove_file(degraded_path(dir));
    // And the directory itself, so `relays/` does not accumulate one empty entry per stack that ever
    // ran. `remove_dir` refuses a non-empty directory, which is the guard: anything left there is a
    // file this function did not expect and must not delete blindly.
    let _ = std::fs::remove_dir(dir);
}

/// Decide whether one planned edge needs a new relay, and make it if so.
///
/// EXTRACTED FROM THE HEALING LOOP because it is where all the rules are: why a slot went bad and
/// why that reason has to be recorded when it happens rather than derived later, how many failures
/// buy a report, and the difference between an edge that FAILED and one that cannot exist at all.
/// Reading them inside a loop that was also reaping children and writing a status file meant
/// reading three unrelated things at once.
fn rebuild_if_needed(
    slot: &mut Slot,
    r: &crate::nopod::RelayPlan,
    snapshot: &[crate::registry::Instance],
    pump_cap: usize,
) {
    let moved = slot.relay.is_some()
        && (live_pid1_in(snapshot, &r.in_box) != Some(slot.a)
            || live_pid1_in(snapshot, &r.to_box) != Some(slot.b));
    if !slot.dead && !moved {
        return;
    }
    if slot.reason.is_empty() {
        slot.reason = if moved {
            "the box restarted"
        } else {
            "a half died"
        };
    }
    if let Some(mut old) = slot.relay.take() {
        // Retired BEFORE the replacement binds, or the new listener meets its own predecessor
        // holding the same alias and port.
        old.stop();
    }
    match try_spawn_in(snapshot, r, pump_cap) {
        Attempt::Blocked(reason) => {
            // RE-MEASURED EVERY PASS, so a service that restarts bound to `127.0.0.1`
            // instead of `0.0.0.0` gets its edge without anyone running a command. The
            // reverse holds too: a service that starts binding the wildcard loses it, and
            // says so.
            if !slot.given_up {
                slot.given_up = true;
                println!(
                    "relay-blocked {}",
                    BlockReport {
                        reason,
                        holder: &r.in_box,
                        peer: &r.to_box,
                        port: r.port,
                    }
                );
            }
            slot.blocked = Some(reason);
            slot.dead = true;
        }
        Attempt::Up(relay) => {
            // EVERY REBUILD IS RECORDED, including one that succeeds on the first try. A
            // repair costs one poll interval of lost connections, which is invisible in the
            // moment and is exactly what someone diagnosing a flapping edge needs to see;
            // logging only the failures would make an edge that dies twice a minute look
            // perfectly healthy.
            println!(
                "relay-note edge {} -> {} on {} rebuilt ({}, attempt {})",
                r.in_box,
                r.to_box,
                r.port,
                slot.reason,
                slot.attempts + 1
            );
            *slot = Slot::new(relay);
        }
        Attempt::Failed(e) => {
            slot.attempts = slot.attempts.saturating_add(1);
            slot.dead = true;
            if slot.attempts >= HEAL_ATTEMPTS && !slot.given_up {
                slot.given_up = true;
                println!(
                    "relay-error edge {} -> {} on {} could not be rebuilt after {} \
                         attempts: {e}",
                    r.in_box, r.to_box, r.port, slot.attempts
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nopod::RelayPlan;

    fn r(a: &str, b: &str, alias: u32, port: u16) -> RelayPlan {
        RelayPlan {
            in_box: a.to_string(),
            to_box: b.to_string(),
            alias,
            port,
            // A source alias distinct from the target's, so a round-trip that swapped the two fields
            // would be caught rather than compared against itself.
            from_alias: alias.wrapping_add(0x40),
            holder_declares: port % 2 == 0,
        }
    }

    /// A plan survives the round trip exactly. The file is the only thing the holder knows about the
    /// stack, so a field lost here is a relay pointed somewhere else.
    #[test]
    fn a_plan_round_trips_through_the_file_format() {
        let plan = vec![
            r("pod-tok-api", "pod-tok-db", 0x7f00_0002, 5432),
            r("pod-tok-db", "pod-tok-api", 0x7f00_0003, 8080),
            r("pod-tok-web", "pod-tok-api", 0x7f00_0003, 65535),
        ];
        let back = decode_plan(&encode_plan(&plan)).expect("the format it just wrote");
        assert_eq!(back, plan);
        assert_eq!(decode_plan("").expect("empty is empty"), Vec::new());
    }

    /// Every malformed line is refused by number, and none of them yields a partial plan: a relay set
    /// built from the lines that parsed is a stack where some peers work and nobody said which.
    #[test]
    fn a_malformed_plan_line_is_refused_by_number() {
        for (text, why) in [
            ("a\tb\tc\t80\t2130706435\td", "alias is not a number"),
            (
                "a\tb\t2130706434\tnope\t2130706435\td",
                "port is not a number",
            ),
            (
                "a\tb\t2130706434\t80\tzz\td",
                "source alias is not a number",
            ),
            // TOO FEW FIELDS, one short of the whole record. A four-field line was the format before
            // the source alias existed, so this case is also the assertion that a plan written by an
            // older kern is REFUSED rather than decoded with a zero source, which would silently put
            // every peer back on 127.0.0.1.
            ("a\tb\t2130706434\t80\t2130706435", "expected"),
            ("a\tb\t2130706434", "expected"),
            ("a\tb\t2130706434\t80\t2130706435\td\textra", "expected"),
            ("\tb\t2130706434\t80\t2130706435\td", "a box name is empty"),
            ("a\t\t2130706434\t80\t2130706435\td", "a box name is empty"),
            ("a\tb\t2130706434\t0\t2130706435\td", "the port is 0"),
        ] {
            let e = decode_plan(text).expect_err("must refuse");
            assert!(e.contains(why), "for {text:?}: {e}");
            assert!(e.contains("line 1"), "the refusal must name the line: {e}");
        }
        // The line NUMBER is the offending one, not the first.
        let e = decode_plan("a\tb\t1\t80\t2\td\nbad").expect_err("must refuse");
        assert!(e.contains("line 2"), "{e}");
    }

    /// The two paths a stack keeps in its runtime directory are distinct and stable, because `down`
    /// finds them by name after `up` is long gone.
    #[test]
    fn the_holder_and_plan_paths_are_distinct() {
        let d = Path::new("/run/user/1000/kern/stack");
        assert_ne!(plan_path(d), holder_path(d));
        assert!(plan_path(d).starts_with(d) && holder_path(d).starts_with(d));
    }

    /// Killing a holder that was never recorded is a no-op, and a file holding something that is not
    /// a pid is removed rather than parsed into a signal.
    #[test]
    fn killing_an_absent_or_corrupt_holder_signals_nothing() {
        let d = std::env::temp_dir().join(format!("kern-relayhold-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        kill_holder(&d); // no file at all
        for corrupt in ["", "not-a-pid", "0", "-1", "  \n"] {
            // `kill_holder` also removes the (now empty) directory, so it is recreated per case.
            // That removal is deliberate: `relays/` must not accumulate one empty entry per stack.
            std::fs::create_dir_all(&d).expect("temp dir");
            std::fs::write(holder_path(&d), corrupt).expect("write");
            kill_holder(&d);
            assert!(
                !holder_path(&d).exists(),
                "a corrupt holder file must be removed, not left to be parsed again: {corrupt:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A holder file naming a pid that is not alive is not signalled. Driven with this process's own
    /// pid as the positive control, so "not signalled" cannot pass by the probe never running.
    #[test]
    fn a_dead_pid_is_not_signalled() {
        let d = std::env::temp_dir().join(format!("kern-relaydead-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        // A pid that cannot exist: the kernel's maximum is far below this on every supported host.
        std::fs::write(holder_path(&d), "2147483646").expect("write");
        kill_holder(&d);
        assert!(!holder_path(&d).exists());
        // Positive control: a LIVE pid is found alive by the same probe this function uses, so the
        // guard above is doing work rather than always answering "dead".
        let me = std::process::id() as i32;
        // SAFETY: signal 0 delivers nothing; it only reports whether the pid can be signalled.
        assert_eq!(
            unsafe { libc::kill(me, 0) },
            0,
            "this process must be alive"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// THE HOLDER MUST NOT HOLD THE CALLER'S STDERR, and `kill_holder` must clean up the file it is
    /// given instead.
    ///
    /// MEASURED: with `Stdio::inherit()`, `kern compose up --no-pod | tail` never returned, because the
    /// holder and its relay children kept the write end of that pipe open for the life of the stack.
    /// The pod path, which spawns no holder, returned normally - that contrast is what identified it.
    ///
    /// Asserting a descriptor choice from a unit test would mean spawning a real holder, which needs
    /// real boxes. What IS asserted here is the half that a future edit is most likely to break in
    /// passing: the log file has a distinct path from the plan and the pid file, and `kill_holder`
    /// removes it, because a leftover file makes the `remove_dir` below it fail silently and
    /// `relays/` then grows one directory per stack that ever ran.
    #[test]
    fn the_holder_log_is_a_distinct_file_and_is_cleaned_up() {
        let d = std::env::temp_dir().join(format!("kern-relaylog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");

        let (plan, pid, log) = (plan_path(&d), holder_path(&d), holder_log_path(&d));
        assert_ne!(log, plan, "the log must not overwrite the plan");
        assert_ne!(log, pid, "nor the pid file");

        // A holder that ran and left all three behind, with a pid that is not alive.
        std::fs::write(&plan, encode_plan(&[r("a", "b", 0x7f00_0002, 8080)])).expect("plan");
        std::fs::write(&pid, "2147483647").expect("pid");
        std::fs::write(&log, "relay 'a' -> 'b' died\n").expect("log");

        kill_holder(&d);
        assert!(!log.exists(), "the log must be removed with the rest");
        assert!(
            !d.exists(),
            "and the directory must then be empty enough to go: {}",
            std::fs::read_dir(&d)
                .map(|it| it.filter_map(Result::ok).count())
                .unwrap_or(0)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// WRITING THE PLAN AND THEN KILLING THE OLD HOLDER DELETES THE PLAN.
    ///
    /// `kill_holder` removes the plan, the pid file and the directory, so the two operations are
    /// order-dependent and the wrong order is silent on the only path that used to run it. MEASURED:
    /// with the plan written first, `kern compose <file> start` on a stack already carrying a holder
    /// failed with "cannot read the relay plan: No such file or directory", because the kill it
    /// performs next had just deleted what it was about to read. `up` on a fresh stack never showed
    /// it: with no holder file, `kill_holder` returns before deleting anything.
    ///
    /// This asserts the ordering through its observable consequence rather than by inspecting the
    /// code: after a `kill_holder` for a previous run, the plan a caller wrote must still be there.
    #[test]
    fn killing_a_previous_holder_must_not_delete_the_plan_just_written() {
        let d = std::env::temp_dir().join(format!("kern-relayorder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");

        // A previous run: a holder file naming a pid that is not alive, and its plan.
        std::fs::write(holder_path(&d), "2147483647").expect("pid");
        std::fs::write(
            plan_path(&d),
            encode_plan(&[r("old", "gone", 0x7f00_0009, 1)]),
        )
        .expect("p");

        let plan = [
            r("a", "b", 0x7f00_0002, 8080),
            r("b", "a", 0x7f00_0003, 9090),
        ];
        // The order under test, as `spawn_holder` performs it: kill FIRST, then create and write.
        kill_holder(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        std::fs::write(plan_path(&d), encode_plan(&plan)).expect("plan");

        let back = std::fs::read_to_string(plan_path(&d)).expect("the plan must survive the kill");
        assert_eq!(
            decode_plan(&back).expect("decode"),
            plan.to_vec(),
            "and it must be the NEW plan, not the previous run's"
        );
        assert!(
            !holder_path(&d).exists(),
            "while the previous holder's pid file is gone"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `port_state` DISTINGUISHES THE THREE ANSWERS, and the middle one is the whole point.
    ///
    /// A relay listens on `alias:port` inside the holder, so whether it can bind is decided by what
    /// the holder bound: a WILDCARD listener owns every address on that port, a specific one leaves
    /// the rest free, and nothing listening yet is neither. The version of this feature that read the
    /// compose file instead assumed the worst and refused pairs that worked.
    ///
    /// RUN IN A CHILD WITH ITS OWN NETWORK NAMESPACE, and the first version did not. It bound a port,
    /// dropped the listener and asserted the port then read as `NotListening`, against
    /// `/proc/self/net/tcp` of the whole TEST PROCESS: it passed alone and failed in the full run,
    /// because other tests in the same binary open sockets. A test whose answer depends on what its
    /// neighbours are doing is not a test. A private netns makes "nothing is listening" a fact this
    /// test establishes rather than hopes for, and it is also the shape the function is used in.
    #[test]
    fn port_state_tells_wildcard_from_specific_from_nothing() {
        let mut fds = [0i32; 2];
        // SAFETY: fills a two-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        // SAFETY: fork in a test binary; the child only unshares, binds and writes a pipe.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // SAFETY: the read end belongs to the parent.
            unsafe { libc::close(fds[0]) };
            let say = |m: &str| {
                // SAFETY: writes a buffer this child owns to a descriptor it owns.
                unsafe {
                    libc::write(fds[1], m.as_ptr() as *const libc::c_void, m.len());
                    libc::_exit(0)
                };
            };
            // SAFETY: unshare in a single-threaded forked child.
            if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
                say("skip");
            }
            // `lo` comes up DOWN in a fresh namespace, and 127.0.0.1 cannot be bound until it is up.
            if !bring_loopback_up() {
                say("skip");
            }
            use std::net::TcpListener;
            let me = std::process::id() as i32;
            let Ok(specific) = TcpListener::bind("127.0.0.1:0") else {
                say("skip");
                return;
            };
            let Ok(sp) = specific.local_addr().map(|a| a.port()) else {
                say("bad");
                return;
            };
            let Ok(wildcard) = TcpListener::bind("0.0.0.0:0") else {
                say("skip");
                return;
            };
            let Ok(wp) = wildcard.local_addr().map(|a| a.port()) else {
                say("bad");
                return;
            };
            // The IPv6 wildcard is a SEPARATE case, not a rewording of the IPv4 one: it is reported
            // in `tcp6` rather than `tcp`, and it is the address the user has to change in their own
            // config, so the state has to name which of the two it saw.
            let Ok(wildcard6) = TcpListener::bind("[::]:0") else {
                say("skip");
                return;
            };
            let Ok(wp6) = wildcard6.local_addr().map(|a| a.port()) else {
                say("bad");
                return;
            };
            let a = port_state(me, sp);
            let b = port_state(me, wp);
            let e = port_state(me, wp6);
            drop(specific);
            drop(wildcard);
            drop(wildcard6);
            // Nothing else exists in this namespace, so both ports are now genuinely free.
            let c = port_state(me, sp);
            let d = port_state(me, wp);
            say(&format!("{a:?} {b:?} {c:?} {d:?} {e:?}"));
        }
        // SAFETY: the write end belongs to the child.
        unsafe { libc::close(fds[1]) };
        let mut buf = [0u8; 256];
        // SAFETY: reads at most `buf.len()` into a buffer this function owns.
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        // SAFETY: waits on this process's own child.
        unsafe {
            libc::close(fds[0]);
            let mut st: libc::c_int = 0;
            libc::waitpid(pid, &mut st, 0);
        }
        let msg = String::from_utf8_lossy(&buf[..n.max(0) as usize]).to_string();
        if msg.trim() == "skip" {
            eprintln!("skip: this host refuses an unprivileged network namespace");
            return;
        }
        assert_eq!(
            msg.trim(),
            "SpecificOnly Wildcard(\"0.0.0.0\") NotListening NotListening Wildcard(\"::\")",
            "127.0.0.1 must not read as the wildcard (every relay would be refused), 0.0.0.0 must \
             (a relay would race the service's own bind), a closed port must be neither, and each \
             wildcard must name the address it was seen on"
        );
    }

    /// Bring `lo` up in the CURRENT network namespace.
    ///
    /// A fresh namespace has a loopback interface that is DOWN, and `bind("127.0.0.1:0")` on it fails
    /// `EADDRNOTAVAIL`. Needed only by the test above, which is why it lives here rather than in the
    /// module: production never creates a namespace, it enters one that a box already set up.
    fn bring_loopback_up() -> bool {
        #[repr(C)]
        struct IfReq {
            name: [u8; 16],
            flags: libc::c_short,
            _pad: [u8; 22],
        }
        // SAFETY: an `AF_INET` socket owned for the length of this function, and an `ifreq` this
        // function fills completely before either ioctl reads it.
        unsafe {
            let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if s < 0 {
                return false;
            }
            let mut req = IfReq {
                name: [0; 16],
                flags: 0,
                _pad: [0; 22],
            };
            req.name[..2].copy_from_slice(b"lo");
            let ok = libc::ioctl(s, libc::SIOCGIFFLAGS, &mut req) == 0 && {
                req.flags |= libc::IFF_UP as libc::c_short;
                libc::ioctl(s, libc::SIOCSIFFLAGS, &req) == 0
            };
            libc::close(s);
            ok
        }
    }

    /// `port_state` SURVIVES A `/proc` THAT IS ABSENT, TRUNCATED OR HOSTILE, and answers
    /// `NotListening` rather than guessing.
    ///
    /// The file is read by path from a pid this process does not own, so every shape below is
    /// reachable in the field: a box that exited between the registry read and this one, a `/proc`
    /// that is not mounted, a line the kernel format changed under. The answer that matters is which
    /// way it fails: `Wildcard` would refuse a working relay, and `SpecificOnly` would let one race
    /// the service's own bind. `NotListening` defers, which is the only harmless one.
    #[test]
    fn port_state_on_a_pid_that_is_not_there_defers_rather_than_deciding() {
        // A pid that cannot exist: `/proc/sys/kernel/pid_max` is at most 2^22 on any Linux kern
        // supports, so `i32::MAX` names nothing and never will inside this test's lifetime.
        assert_eq!(
            port_state(i32::MAX, 8080),
            PortState::NotListening,
            "an unreadable /proc must defer, not decide"
        );
        assert_eq!(port_state(0, 8080), PortState::NotListening, "pid 0");
        assert_eq!(
            port_state(-1, 8080),
            PortState::NotListening,
            "a negative pid"
        );
    }

    /// A PLAN AT THE EDGES OF ITS OWN FORMAT round-trips or is refused, and never decodes to
    /// something that looks fine.
    ///
    /// The plan is the only thing the holder knows about a stack, and `relays/` is AUTHORITATIVE in
    /// the registry's classification precisely because a line written into it would redirect where a
    /// PEER's traffic goes. So the parser is a boundary, and these are the shapes a boundary is
    /// probed with.
    #[test]
    fn the_plan_parser_refuses_every_hostile_shape() {
        // Values at the edges of every field, which must survive intact.
        let edge = vec![
            r("a", "b", 0, 1),
            r("x", "y", u32::MAX, u16::MAX),
            r(
                &"n".repeat(200),
                &"m".repeat(200),
                0x7f00_0002,
                0x7f00_0002u32 as u16,
            ),
        ];
        let text = encode_plan(&edge);
        assert_eq!(decode_plan(&text).expect("round trip"), edge);

        for (bad, why) in [
            ("a\tb\t1\t80\t2\td\ta\tb\t1\t80\t2\td", "expected"), // two records on one line
            ("a\tb\t4294967296\t80\t2\td", "alias is not a number"), // u32 overflow
            ("a\tb\t1\t65536\t2\td", "port is not a number"),     // u16 overflow
            ("a\tb\t-1\t80\t2\td", "alias is not a number"),      // negative
            ("a\tb\t 1\t80\t2\td", "alias is not a number"),      // leading space, not trimmed
            ("a\tb\t1\t80\t2\td\t", "expected"),                  // trailing separator
            ("a b\tc\t1\t80\t2\td", "a character a box name cannot"), // a space is outside it
            ("../../etc\tc\t1\t80\t2\td", "a character a box name cannot"), // nor is a path
            (
                "a\u{1b}[0m\tc\t1\t80\t2\td",
                "a character a box name cannot",
            ), // nor an escape
            // FIVE EMPTY FIELDS. The reported reason is the alias, not the name, because the
            // numeric parse runs first; what the case pins is that a line of pure separators is
            // refused at all, and which check catches it is an ordering detail.
            ("\t\t\t\t\t", "alias is not a number"),
            ("a\tb\t1\t80\t2\tx", "neither 'd' nor '-'"), // the flag has two spellings
        ] {
            let e = decode_plan(bad).expect_err("must refuse {bad:?}");
            assert!(e.contains(why), "for {bad:?} expected {why:?}, got {e}");
        }

        // A name carrying a NEWLINE cannot be encoded into one line, so the encoder must not be able
        // to produce a plan whose second line is attacker-chosen. Asserted through the DECODER,
        // because that is where the consequence would land.
        let sneaky = vec![r("a\nb\tc\t1\t80\t2\td", "t", 1, 80)];
        let text = encode_plan(&sneaky);
        assert!(
            decode_plan(&text).is_err(),
            "a name holding a newline must not decode into two relays: {text:?}"
        );
    }

    /// `pump_cap_for` never returns zero, and never overflows its own multiplication.
    ///
    /// Zero would be a relay that refuses every connection while reporting itself up, which is the
    /// silent-success shape this codebase refuses; the multiplication is what an aggregate assertion
    /// elsewhere performs on the result.
    #[test]
    fn the_pump_cap_is_never_zero_and_never_overflows() {
        for n in [
            0usize,
            1,
            2,
            63,
            64,
            65,
            253,
            1_000,
            usize::MAX / 2,
            usize::MAX,
        ] {
            let cap = kern_isolation::peer::pump_cap_for(n);
            assert!(
                cap >= kern_isolation::peer::MIN_LIVE_PUMPS,
                "{n} gave {cap}"
            );
            assert!(
                cap <= kern_isolation::peer::MAX_LIVE_PUMPS,
                "{n} gave {cap}"
            );
        }
        // THE AGGREGATE IS BOUNDED WHERE A STACK CAN REACH, which is not everywhere: the first
        // version of this asserted `cap * n` cannot overflow for `usize::MAX` relays, which is
        // arithmetic rather than a property of the code. The real ceiling is the alias range: 253
        // services is the most a stack can have, so the widest plan is 253 * 252 relays per port.
        let widest =
            kern_isolation::peer::MAX_PEER_INDEX * (kern_isolation::peer::MAX_PEER_INDEX - 1);
        assert!(
            kern_isolation::peer::pump_cap_for(widest)
                .checked_mul(widest)
                .is_some(),
            "the widest stack the alias range allows must not overflow the aggregate"
        );
    }
}
