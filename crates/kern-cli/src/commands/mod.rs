//! Subcommand implementations. One responsibility per function; the roadmap promotes each
//! `Pending` verb (box/run/pull/compose) to its own module here.

use crate::cli::GlobalOpts;
use crate::error::Error;
use crate::sandbox::SandboxCtx;
use kern_common::BoxName;

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

    box <name> --plan   Print the ordered isolation step sequence (no privileges)

OPTIONS:
    --no-gpu       Never load any GPU driver interposer (off by default)
    -V, --version  Print version
    -h, --help     Print this help

The CLI/config surface is NOT frozen until 1.0.
See https://github.com/getkern/kern",
        ver = kern_common::VERSION
    );
    Ok(())
}

/// `kern box <name> --plan` — show the ordered mount/pivot/remount sequence the sandbox setup
/// would perform. Privilege-free: it records the sequence via the isolation seam rather than
/// executing it, so it works anywhere and exercises the 0.2 step-sequence + mount-ordering
/// typestate end to end.
pub fn box_plan(name: &str) -> Result<(), Error> {
    let name = BoxName::parse(name).map_err(Error::InvalidBox)?;
    let ctx = SandboxCtx::new(name);
    println!("isolation plan for box '{}':", ctx.name.as_str());
    for (i, step) in ctx.plan().iter().enumerate() {
        println!("  {}. {step}", i + 1);
    }
    Ok(())
}

/// A recognised runtime verb that lands in a later 0.x release.
pub fn pending(name: &'static str, opts: &GlobalOpts) -> Result<(), Error> {
    let _ = opts; // GPU-off is the only behaviour wired so far
    Err(Error::NotYetImplemented(name))
}
