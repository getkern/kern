//! kern - a fast, rootless sandbox & virtual resource runtime.
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
/// Peer addressing and hosts files for a `--no-pod` stack.
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
mod shim;
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
    if let Some(v) = std::env::var_os("KERN_SCOPE_READY_FD") {
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
        std::env::remove_var("KERN_SCOPE_READY_FD");
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
    let mut args: Vec<String> = raw.map(|a| a.to_string_lossy().into_owned()).collect();
    let invoked = std::path::Path::new(&arg0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if (invoked == "docker" || invoked == "docker-compose") && !shim::argv_already_translated() {
        if invoked == "docker-compose" {
            args.insert(0, "compose".to_string());
        }
        match shim::translate(&args) {
            Ok(translated) => args = translated,
            Err(e) => {
                eprintln!("error: {}", ui::scrub(&e.to_string()));
                return ExitCode::FAILURE;
            }
        }
    }
    // Record what kern DECIDED to run. The scope re-exec replays this, not `env::args()`: through a
    // symlink named `docker` the raw argv would arrive at the second pass untranslated, with an
    // `argv[0]` that `current_exe()` has already resolved back to `kern`. See `shim::EFFECTIVE`.
    shim::set_effective(&args);

    // Map the result to an exit code in exactly ONE place (the lib/command layer returns
    // `Result`, never calls `process::exit` itself).
    match cli::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
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
            // next message added would not be. No error message in this CLI is multi-line (checked
            // across every `Error::*` construction), so dropping control characters joins nothing,
            // and a clean message is byte-identical after the filter.
            eprintln!("error: {}", ui::scrub(&e.to_string()));
            if let Some(hint) = e.hint() {
                eprintln!("hint: {}", ui::scrub(&hint));
            }
            ExitCode::FAILURE
        }
    }
}
