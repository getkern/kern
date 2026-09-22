//! kern - a fast, rootless container runtime and sandbox, no daemon.
//!
//! This binary is intentionally THIN: it parses argv into a [`cli::Command`] and dispatches.
//! Real subcommand logic lives in `commands/`, and the sandbox in `sandbox/`. There is NO
//! `include!()` mega-module - every file is a real `mod` with `pub(crate)` boundaries.
//!
//! See README.md / ARCHITECTURE.md for the roadmap. Commands and flags may still change before 1.0.

/// One process-wide lock serializing every test that mutates a global env var (`XDG_DATA_HOME`,
/// `HOME`, …). `std::env::set_var` is process-global, so tests in DIFFERENT modules (e.g. `volume` and
/// `builds`, which both repoint `XDG_DATA_HOME`) must share ONE lock or they race. Poison is recovered
/// (`into_inner`) so one panicking test doesn't cascade-fail every later env test.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The threads currently holding [`TEST_ENV_LOCK`], so a read can ask whether ITS OWN thread does.
///
/// A `Mutex` cannot answer "do I hold you": `try_lock` answers "does anyone", which is a different
/// question and the wrong one. So the guard registers the thread that took it and removes it on drop,
/// and [`global_env`] asks that set. A `Vec` and not a single slot because it holds MORE than one
/// thread whenever a guarded test spawns workers: see [`env_guard_inherited`].
#[cfg(test)]
pub(crate) static ENV_LOCK_HOLDERS: std::sync::Mutex<Vec<std::thread::ThreadId>> =
    std::sync::Mutex::new(Vec::new());

/// Take [`TEST_ENV_LOCK`] and witness it, for the whole of the caller's body.
///
/// 🔴 EVERY TEST THAT TOUCHES THE ENVIRONMENT CALLS THIS, and [`global_env`] panics at the point of
/// use if it did not. That is the whole design: a static check of this rule was walked through EIGHT
/// TIMES OUT OF EIGHT by an independent test (a comment mentioning the lock satisfied it, an alias
/// renamed a resolver out of sight, a variable held the variable's name, a resolver was passed as a
/// function pointer, attributes pushed `#[test]` out of the lookback, and a helper one hop away hid
/// the rest), and two more holes were mine: parsing Rust with regular expressions is a losing game
/// against someone who is trying. The check that cannot be walked through is the one AT THE READ.
///
/// 🔴 REENTRANT ON PURPOSE: a thread that already holds it gets a guard that does nothing.
///
/// A `std::sync::Mutex` is not reentrant, and taking it twice on one thread is a deadlock with no
/// message: the test binary simply stops. That is not hypothetical here. It happened TWICE in one
/// session, the first time because a static check reported eight tests that were already holding the
/// lock through an alias it could not see, the second because helpers like `reg_guard` take it for
/// their caller. Both times a test binary sat for over ten minutes and looked slow rather than stuck.
///
/// So the rule this function enforces is "the lock is held for this body", not "this body takes the
/// lock", and asking for it when you already have it is free and correct. The nesting is bounded by
/// the call graph; the outermost guard is the one that releases.
#[cfg(test)]
pub(crate) fn env_guard() -> EnvGuard {
    let me = std::thread::current().id();
    if ENV_LOCK_HOLDERS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&me)
    {
        return EnvGuard {
            lock: None,
            deregister: false,
        };
    }
    let g = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    ENV_LOCK_HOLDERS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(me);
    EnvGuard {
        lock: Some(g),
        deregister: true,
    }
}

/// For a thread SPAWNED inside a guarded body: the parent holds the lock, this thread inherits it.
///
/// A guard registers the thread that took it, and a thread the test spawns is not that thread, so a
/// contention test whose workers resolve a state path trips the assertion while being perfectly
/// safe: no sibling test can flip the variable, because the parent is holding the lock for all of
/// them. This is the explicit way to say that, and it refuses when NOBODY holds the lock.
///
/// ⚠️ It cannot check that the holder is this thread's own parent, because a thread does not know who
/// spawned it: a worker whose parent holds nothing, running while an UNRELATED test holds the lock,
/// would be let through. That is a narrower hole than the one this file closes and it needs a test
/// written to exploit it, but it is a hole and it is not worth pretending otherwise. The honest
/// summary is "the environment is serialised while this runs", not "my parent holds it".
#[cfg(test)]
pub(crate) fn env_guard_inherited() -> EnvGuard {
    let mut holders = ENV_LOCK_HOLDERS.lock().unwrap_or_else(|e| e.into_inner());
    assert!(
        !holders.is_empty(),
        "env_guard_inherited() in a thread whose parent does not hold TEST_ENV_LOCK: there is \
         nothing to inherit, and the value this thread reads is whatever a sibling test last wrote"
    );
    holders.push(std::thread::current().id());
    drop(holders);
    // It did not take the mutex, so it must not release it, but it DID register and must therefore
    // de-register: a `ThreadId` is recycled once its thread is gone, and a stale registration would
    // let some later, unrelated thread read the environment with the assertion satisfied by a
    // worker that finished minutes ago.
    EnvGuard {
        lock: None,
        deregister: true,
    }
}

/// The witness half of [`env_guard`]: holds the lock, and un-registers the thread when it goes.
///
/// Three shapes, and the middle one is why `deregister` exists: the owner (took the mutex and
/// registered), the reentrant guard (registered by an OUTER guard on this same thread, so it must
/// not un-register or every read after the inner scope would fail on a lock that IS held), and the
/// inherited guard (registered itself in a spawned thread, took no mutex, and must un-register).
#[cfg(test)]
pub(crate) struct EnvGuard {
    /// `Some` only for the thread that actually took the mutex, which is the one that releases it.
    lock: Option<std::sync::MutexGuard<'static, ()>>,
    /// Whether this guard is the one that registered the current thread. False for the reentrant
    /// case, where an outer guard on the SAME thread is still the registration's owner.
    deregister: bool,
}

#[cfg(test)]
impl Drop for EnvGuard {
    fn drop(&mut self) {
        if !self.deregister {
            return;
        }
        let me = std::thread::current().id();
        ENV_LOCK_HOLDERS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|t| *t != me);
        // The lock is released AFTER the de-registration, so no thread can see itself as a holder
        // while another one is already past `lock()`.
        self.lock = None;
    }
}

/// THE ONE PLACE THIS CRATE READS A PROCESS-GLOBAL ENVIRONMENT VARIABLE.
///
/// Identical to `std::env::var_os` in a release build. In a test build it refuses to answer a thread
/// that does not hold [`TEST_ENV_LOCK`], because the answer would be whatever a sibling test last
/// wrote: `cargo test` runs the crate's tests as threads in ONE process, and the environment is one
/// table for all of them. The failure it prevents is not a flake, it is a red against production that
/// is correct, which costs an afternoon to attribute and has cost several.
///
/// The same chokepoint shape as `registry::assert_registry_child`, and for the same reason: a rule
/// enforced where the thing happens cannot be routed around by naming it differently.
/// THE ONE PLACE THIS CRATE WRITES A PROCESS-GLOBAL ENVIRONMENT VARIABLE.
///
/// The read chokepoint below is only half the rule: a write with no lock moves the value under a
/// reader that DOES hold it, which is the same race seen from the other side. So writes are witnessed
/// too, and by the same registration, which is why a test that writes must take the guard even when
/// it never reads anything back.
///
/// Uniform over production and tests on purpose. A production function that writes the environment is
/// single-threaded before an `execve` and has nothing to race with, but a TEST that calls it is a
/// thread among others, and that is exactly the case worth catching. In a release build this is
/// `std::env::set_var` and nothing else.
///
/// # Safety
/// Same contract as `std::env::set_var`: no other thread may be reading the environment concurrently.
/// Under test that is what the assertion enforces; in production the callers are pre-`execve` paths.
#[allow(clippy::disallowed_methods)] // this IS the chokepoint
pub(crate) fn set_global_env<K: AsRef<std::ffi::OsStr>, V: AsRef<std::ffi::OsStr>>(
    name: K,
    value: V,
) {
    #[cfg(test)]
    assert_env_lock_held(&name.as_ref().to_string_lossy());
    // SAFETY: see the contract above; the test build proves the serialisation, the release build
    // reaches here only from single-threaded pre-exec paths.
    unsafe { std::env::set_var(name, value) };
}

/// The removal half of [`set_global_env`], with the same contract.
#[allow(clippy::disallowed_methods)] // this IS the chokepoint
pub(crate) fn unset_global_env<K: AsRef<std::ffi::OsStr>>(name: K) {
    #[cfg(test)]
    assert_env_lock_held(&name.as_ref().to_string_lossy());
    // SAFETY: as [`set_global_env`].
    unsafe { std::env::remove_var(name) };
}

/// The witness question, asked by all three chokepoints.
#[cfg(test)]
fn assert_env_lock_held(name: &str) {
    let me = std::thread::current().id();
    let held = ENV_LOCK_HOLDERS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&me);
    assert!(
        held,
        "this test touched the process-global `{name}` without holding TEST_ENV_LOCK, so it is \
         racing every other test in this binary. Take the lock for the whole body:\n    \
         let _g = crate::env_guard();"
    );
}

/// The WHOLE table, for the one caller that needs every name rather than one: witnessed the same.
///
/// Collected rather than returned as an iterator on purpose. `std::env::vars_os` borrows the
/// environment for as long as the iterator lives, and a caller that holds it across a write gets
/// undefined behaviour; taking the snapshot here bounds that to this function, where the assertion
/// above has just established that nothing else may be writing.
#[allow(clippy::disallowed_methods)] // this IS the chokepoint
pub(crate) fn global_env_all() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    #[cfg(test)]
    assert_env_lock_held("<the whole environment>");
    std::env::vars_os().collect()
}

/// [`global_env`] for the callers that want `String` and `VarError`, with the same witness.
///
/// A second entry point rather than an adapter at 40 call sites: `std::env::var` and
/// `std::env::var_os` differ in their return type and in nothing else that matters here, and making
/// every caller convert would have turned a rename into forty small edits, which is where mistakes
/// come from.
#[allow(clippy::disallowed_methods)] // this IS the chokepoint
pub(crate) fn global_env_str(name: &str) -> Result<String, std::env::VarError> {
    #[cfg(test)]
    assert_env_lock_held(name);
    std::env::var(name)
}

#[allow(clippy::disallowed_methods)] // this IS the chokepoint
pub(crate) fn global_env(name: &str) -> Option<std::ffi::OsString> {
    #[cfg(test)]
    assert_env_lock_held(name);
    std::env::var_os(name)
}

mod auth;
mod boxcp;
mod builds;
mod caps;
mod cli;
mod commands;
mod completions;
// The compose-file parser now lives in its own CLI-free crate (so it can be fuzzed in isolation).
// Aliased so the existing `crate::compose::` call sites (orchestration in `commands/`) stay unchanged.
use kern_compose as compose;
mod config;
mod dockerfile;
mod dockerignore;
mod doctor;
mod egress;
mod eintr;
mod error;
mod gpu;
mod listing;
/// Peer addressing and hosts files for a `--no-pod` stack.
mod network;
mod nopod;
mod openat2;
mod pod;
mod ports;
mod pty;
mod registry;
/// Ownership and lifetime of a `--no-pod` stack's peer relays.
mod relayhold;
mod runstats;
mod sandbox;
mod secret;
mod systemd;
mod toml_surgery;
mod tui;
mod ui;
mod vdisk;
mod volume;

use std::process::ExitCode;

fn main() -> ExitCode {
    // Rust ignores SIGPIPE by default, so a broken pipe (`kern … | head`, `| grep -q`, quitting a
    // pager) makes the next `println!` return EPIPE and PANIC → SIGABRT (exit 134) with an ugly
    // backtrace. Restore the default disposition so a closed reader just terminates us cleanly with
    // SIGPIPE, like every other Unix tool. Done before any output.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    // Stamp process entry as early as possible: `kern run` measures entry→exec against it to record its
    // own per-run setup latency (the honest "~1 ms" shown in `kern top`'s Runs tab). Cheap and harmless
    // on every other subcommand.
    runstats::mark_start();
    // Scope-readiness signal: if we are the kern re-exec'd INSIDE a transient systemd scope, reaching
    // `main` under `KERN_SCOPE_READY_FD` proves `systemd-run` reached the user manager and re-exec'd us,
    // so the box is NOT going to die on the exec cliff. Write one byte and close the pipe; the outer
    // parent (see `reexec_in_scope_if_possible`) reads it to tell "scope up" from "systemd-run died
    // before starting the box" and, on the latter, falls back to the best-effort in-process cgroup path
    // instead of leaving the box dead. Done at the earliest point, before any subcommand can exit first,
    // and the marker is removed so the box workload never inherits it or the closed fd number. Safe
    // single-threaded env mutation at process entry (no other thread yet).
    if let Some(v) = global_env("KERN_SCOPE_READY_FD") {
        // Honour it ONLY as the genuine scope re-exec (KERN_SCOPE set) and only for a non-std fd, so a
        // `KERN_SCOPE_READY_FD` planted in the environment cannot make kern write a stray byte to or
        // close its own stdout/stderr or an arbitrary descriptor. See `commands::ready_fd_to_signal`.
        if let Some(fd) =
            commands::ready_fd_to_signal(kern_common::env_flag("KERN_SCOPE"), Some(v.as_os_str()))
        {
            let b = [1u8];
            unsafe {
                libc::write(fd, b.as_ptr().cast(), 1);
                libc::close(fd);
            }
        }
        unset_global_env("KERN_SCOPE_READY_FD");
    }
    // Inside our own transient scope: move kern's processes into a leaf of their own, so the box can be
    // capped in a sibling cgroup whose whole-box OOM kill takes the workload and NOT the supervisor that
    // records its exit code. Must run HERE - before any fork, because cgroup v2 refuses to enable
    // controllers for a cgroup's children while that cgroup still holds processes. A no-op off the scope
    // path and on a scope that is not ours; fail-safe (see `prepare_delegated_scope`).
    kern_isolation::prepare_delegated_scope();
    // Detect invocation *as* `docker` / `docker-compose` (via a symlink or wrapper) and rewrite the
    // argv into kern's own dialect before dispatch. Pure argument translation - no daemon, no
    // docker.sock. When invoked normally (`kern …`), this is a couple of cheap string checks.
    // `args_os()`, NOT `args()`: `std::env::args()` PANICS on a non-UTF-8 argument, so a box name or a
    // `-v` path carrying invalid UTF-8 bytes (a truncated multibyte char, a raw `0xFF`) crashed kern
    // before it could reject the input. Convert lossily instead - an invalid arg becomes a string with
    // U+FFFD replacement chars, which then fails the name/path validators cleanly with a message rather
    // than aborting. (A workload argument that was genuinely non-UTF-8 is corrupted rather than crashing;
    // that is an extreme edge for a containerised command, and never panicking is the harder guarantee.)
    let mut raw = std::env::args_os();
    let arg0 = raw.next().unwrap_or_default();
    let args: Vec<String> = raw.map(|a| a.to_string_lossy().into_owned()).collect();
    let invoked = std::path::Path::new(&arg0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    // KERN IS NOT DOCKER, AND DOES NOT ANSWER TO ITS NAME. Until 2026-09-19 a symlink called
    // `docker` made this binary rewrite a `docker …` argv into kern's own and run it. That was
    // removed, name and all: the compatibility kern offers is with the FORMAT and the FLAGS -
    // `kern box` already takes `-p`, `-e`, `-v`, `-it`, `-m`, `--cpus`, and `kern compose` reads a
    // `docker-compose.yml` unchanged - not with the other tool's identity. Being invoked as
    // `docker` added nothing a caller could not get by typing `kern`, and it cost what borrowed
    // names always cost: a benchmark on this machine measured kern and published the row under
    // Docker's name at 4.2 ms, next to a real podman at 285 ms, because `docker --version`
    // answered for kern.
    //
    // `invoked` is still read, for the one thing argv[0] legitimately decides below.
    let _ = invoked;
    // Map the result to an exit code in exactly ONE place (the lib/command layer returns
    // `Result`, never calls `process::exit` itself).
    match cli::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        // A WORKLOAD'S OWN STATUS, adopted verbatim and printed nowhere: `compose run` is
        // transparent about what the command it ran did. `as u8` is the whole range a process exit
        // status has; a code outside it cannot be produced by `WEXITSTATUS`.
        Err(error::Error::Workload(code)) => ExitCode::from(code as u8),
        Err(e) => {
            // These two lines are the ONLY place an error reaches the user, so they are where the
            // control characters come off. An error message can carry a string kern did not write:
            // a `backend` value out of a `kern.toml`, a size, a profile name, a registry's reply.
            // Measured on 2026-08-04: a config whose `backend` held ESC[2K ESC[1A ESC[32m made the
            // refusal erase its own line, move the cursor up and repaint in green, so a rejection
            // could be made to read as a success. That class was closed for the registry path and
            // never for this one.
            //
            // Scrubbed HERE rather than at the ~27 sites that format a config value, because the
            // next message added would not be.
            //
            // `scrub_message` AND NOT `scrub`, and the difference is a defect this line used to
            // carry. The comment here read "no error message in this CLI is multi-line (checked
            // across every `Error::*` construction), so dropping control characters joins nothing".
            // That was true when it was written and is not any more. Measured on this tree:
            // `kern volume rm nonesiste1 nonesiste2` builds `"2 volume(s) not removed:\n  ..."` and
            // reached the user as
            //
            //   error: 2 volume(s) not removed:  no volume named 'a'  no volume named 'b'
            //
            // one run-on line, because `scrub` dropped the newlines that made it a list. Two more
            // constructions have the same shape today (a compose bring-up that lists the services
            // that died, and the invalid-port-spec list).
            //
            // The newline now survives and every continuation line is INDENTED, so a hostile value
            // still cannot forge a line at column 0, where kern's own `error:`/`hint:` prefixes
            // live. See `ui::scrub_message`.
            eprintln!("error: {}", ui::scrub_message(&e.to_string()));
            if let Some(hint) = e.hint() {
                eprintln!("hint: {}", ui::scrub_message(&hint));
            }
            ExitCode::FAILURE
        }
    }
}
