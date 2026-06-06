//! kern — a fast, lightweight OCI container / sandbox runtime.
//!
//! This binary is intentionally THIN: it parses argv into a [`cli::Command`] and dispatches.
//! Real subcommand logic lives in `commands/`, and the sandbox in `sandbox/`. There is NO
//! `include!()` mega-module — every file is a real `mod` with `pub(crate)` boundaries.
//!
//! 0.1 scaffold (see README.md / ARCHITECTURE.md for the roadmap). The CLI/config surface is
//! NOT frozen until 1.0.

mod cli;
mod commands;
mod error;
mod sandbox;

use std::process::ExitCode;

fn main() -> ExitCode {
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
