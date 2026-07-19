// Embed kern in Rust: the `kern-isolation` crate's fluent Sandbox builder.
//
// `Sandbox::builder()...build()?.run(cmd, args)?` assembles a `kern box ...` invocation, runs it
// with piped stdio, and hands back a structured `Outcome` (exit code, captured stdout/stderr with
// truncation flags, wall time, best-effort resource figures). It shells out to the `kern` binary as
// a privilege-separation layer - it does NOT re-implement isolation in Rust. Secure by default: a
// fresh box gets an isolated (loopback-only) netns, seccomp always-on, env NOT inherited.
//
// HOW TO RUN - the crate is internal to the kern workspace (`publish = false`), so depend on it by
// git or path from a small binary crate:
//
//     # Cargo.toml
//     [dependencies]
//     kern-isolation = { git = "https://github.com/getkern/kern" }   # or: path = "crates/kern-isolation"
//
//     # then drop this file in src/main.rs and:
//     KERN_BIN=./target/release/kern cargo run --release
//
// (kern-isolation locates the `kern` binary via $KERN_BIN, then $PATH.)

use kern_isolation::{ResourceSource, Sandbox};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A locked-down box: no network, read-only root, half a core, 256 MB, killed after 5 s.
    let out = Sandbox::builder()
        .image("alpine") // auto-pulled and cached, like `kern box --image alpine`
        .no_network() // isolated loopback-only netns (also the default)
        .readonly_root() // remount the root read-only after pivot_root
        .memory_limit_bytes(256 * 1024 * 1024)
        .cpus(0.5)
        .pids_limit(128) // fork-bomb ceiling
        .timeout_ms(5_000) // SIGKILL a runaway after 5 s
        .env("LANG", "C")
        .build()?
        .run("sh", &["-c", "echo hello from a kern box; id -u; nproc"])?;

    // `Outcome` is structured - exactly what an agent platform / scheduler needs to decide next.
    println!("success : {}", out.success()); // exit_code == 0
    println!("exit    : {}", out.exit_code);
    println!("wall_ms : {}", out.wall_ms);
    // stdout_text() carries the truncation flag so partial output can't be acted on by accident.
    let view = out.stdout_text();
    println!("stdout  : {:?}  (truncated={})", view.text, view.truncated);
    if !out.stderr.is_empty() {
        println!("stderr  : {:?}", out.stderr_str());
    }

    // Resource figures are Option + carry their source. On the public runtime the source is
    // RusageFallback (getrusage(RUSAGE_CHILDREN)) - honest signal that they're not per-box-exact.
    match out.resource_source {
        ResourceSource::Cgroup => println!("resource: from the box's own cgroup (per-box accurate)"),
        ResourceSource::RusageFallback => {
            println!("resource: getrusage fallback (not per-box exact - see Outcome docs)")
        }
        ResourceSource::Unavailable => println!("resource: unavailable"),
    }
    if let Some(mem) = out.peak_memory_bytes {
        println!("peak_mem: ~{} KiB", mem / 1024);
    }

    Ok(())
}
