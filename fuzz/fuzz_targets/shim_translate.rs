#![no_main]
//! Fuzz the `docker` -> `kern` argv translator. It rewrites UNTRUSTED argv (from user scripts or a
//! `docker` symlink) into kern's own argv. It must NEVER panic - no out-of-bounds slice, no unbounded
//! allocation, no arithmetic overflow - however malformed or adversarial the input. Included by path
//! because the translator is self-contained (std-only) and lives in the `kern` binary crate.
#[path = "../../crates/kern-cli/src/shim.rs"]
mod shim;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Interpret the bytes as a NUL-separated argv (lossy UTF-8), capped to a sane arg count so the
    // fuzzer spends its budget on parser logic, not on giant allocations.
    let argv: Vec<String> = data
        .split(|b| *b == 0)
        .take(64)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    let _ = shim::translate(&argv);
});
