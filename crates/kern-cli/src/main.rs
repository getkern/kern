//! kern — a fast, lightweight sandbox & virtual resource manager.
//!
//! This binary is intentionally THIN: it parses argv into a [`cli::Command`] and dispatches.
//! Real subcommand logic lives in `commands/`, and the sandbox in `sandbox/`. There is NO
//! `include!()` mega-module — every file is a real `mod` with `pub(crate)` boundaries.
//!
//! See README.md / ARCHITECTURE.md for the roadmap. Commands and flags may still change before 1.0.

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
mod doctor;
mod error;
mod openat2;
mod pod;
mod ports;
mod pty;
mod registry;
mod sandbox;
mod secret;
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
    let args: Vec<String> = std::env::args().skip(1).collect();
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
