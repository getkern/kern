//! Subcommand implementations. One responsibility per function; the roadmap promotes each
//! `Pending` verb (box/run/pull/compose) to its own module here.

use crate::cli::GlobalOpts;
use crate::error::Error;

pub fn version() -> Result<(), Error> {
    println!("kern {}", kern_common::VERSION);
    Ok(())
}

pub fn help() -> Result<(), Error> {
    println!(
        "\
kern {ver} — a fast, lightweight sandbox & virtual resource manager

USAGE:
    kern [--no-gpu] <COMMAND> [ARGS]

COMMANDS:
    box        Run a command in a sandbox            (roadmap)
    run        Run with resource limits             (roadmap)
    pull       Pull an OCI image                    (roadmap)
    compose    Orchestrate boxes from a TOML file   (roadmap)

OPTIONS:
    --no-gpu       Never load any GPU driver interposer (off by default)
    -V, --version  Print version
    -h, --help     Print this help

This is a 0.1 scaffold; the CLI/config surface is NOT frozen until 1.0.
See https://github.com/getkern/kern",
        ver = kern_common::VERSION
    );
    Ok(())
}

/// A recognised runtime verb that lands in a later 0.x release.
pub fn pending(name: &'static str, opts: &GlobalOpts) -> Result<(), Error> {
    let _ = opts; // GPU-off is the only behaviour at 0.1
    Err(Error::NotYetImplemented(name))
}
