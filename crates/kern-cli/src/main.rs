//! kern - a fast, lightweight sandbox & virtual resource manager.
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
mod error;
mod openat2;
mod pod;
mod ports;
mod pty;
mod registry;
mod runstats;
mod sandbox;
mod secret;
mod shim;
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
    // Detect invocation *as* `docker` / `docker-compose` (via a symlink or wrapper) and rewrite the
    // argv into kern's own dialect before dispatch. Pure argument translation - no daemon, no
    // docker.sock. When invoked normally (`kern …`), this is a couple of cheap string checks.
    let mut raw = std::env::args();
    let arg0 = raw.next().unwrap_or_default();
    let mut args: Vec<String> = raw.collect();
    let invoked = std::path::Path::new(&arg0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if invoked == "docker" || invoked == "docker-compose" {
        if invoked == "docker-compose" {
            args.insert(0, "compose".to_string());
        }
        match shim::translate(&args) {
            Ok(translated) => args = translated,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    // Map the result to an exit code in exactly ONE place (the lib/command layer returns
    // `Result`, never calls `process::exit` itself).
    match cli::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            if let Some(hint) = e.hint() {
                eprintln!("hint: {hint}");
            }
            ExitCode::FAILURE
        }
    }
}
