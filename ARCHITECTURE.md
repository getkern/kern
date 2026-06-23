# Architecture

This documents the structure and the deliberate design choices, so the repo reads as a
designed project, not a script.

## Workspace

```
crates/
  kern-cli/        the `kern` binary (published as `getkern`); thin main + cli + commands/ + sandbox/
  kern-common/     shared newtypes (BoxName, …) — units can't be mixed up
  kern-oci/        OCI pull / layer extraction / whiteout (security-critical path-safety)
  kern-isolation/  namespace / cgroup / mount primitives + the characterization seam
```

The GPU layer (interception + cooperative governor) is **deferred to 0.9** and is additive;
the **CUDA-on-non-NVIDIA** cross-vendor piece lives in a **separate repository, off by
default**, so the core carries zero EULA exposure.

## Design choices (and why)

- **Real `mod`s, no `include!()`.** The binary uses ordinary modules with `pub(crate)`
  boundaries and a command enum + `match` dispatch. (An older internal tree concatenated files
  via `include!()` to feed a build-time string-obfuscation pass; that justification disappears
  once the source is public, so the obfuscation — if kept — belongs in a `build.rs`/macro
  codegen step decoupled from file layout, never in the module structure.)
- **The sandbox is a sequence of steps against a seam.** Mount/pivot/remount operations go
  through the `kern_isolation::MountOps` trait. A `Recorder` impl captures the exact ordered
  call list so a test asserts it byte-identical before/after a refactor — the *refactor-safety*
  net for breaking up the (historically ~2900-line) setup function. This does **not** replace
  the real-syscall correctness tests that actually mount/pivot and assert escape-blocked.
- **Mount-ordering as a typestate (roadmap 0.2).** `Rootfs<Mounted>` → `create_old_root()` →
  `Rootfs<OldRootReady>` → `into_readonly()` makes "remount read-only before `.old_root`
  exists" a *compile error*, not a runtime bug.
- **GPU backends as a closed enum (roadmap 0.9).** `enum Backend { Cuda, Hip, Vulkan }` with
  exhaustive `match` — the compiler forces every vendor to be handled; `Box<dyn>` only if/when
  third-party backends are allowed.
- **One driver proxy (roadmap 0.9).** `GovernedDriver<D: RealDriver>` checks the quota then
  forwards via the public API — a single, inspectable interception boundary (the auditability
  story).
- **Errors:** `Result`-based in libraries (the 0.x target is `thiserror` enums), mapped to an
  exit code in exactly one place in the binary. Post-fork, pre-exec child code stays
  `exit()`-based by necessity (you cannot unwind a `Result` across `fork`).
- **Zero-heap on hot paths, opt-in only.** Where it matters (per-syscall buffers), stack
  buffers; never as premature optimization elsewhere.

## Tests

Four layers (Rust-standard): unit (inline `#[cfg(test)]`), integration (`tests/`, black-box
binary), the characterization seam (deterministic, privilege-free), and real-syscall
correctness tests (skip-graceful where namespaces/HW are unavailable). CI x86 stays
always-green via skip-graceful gates; ARM and real-GPU tests run on self-hosted runners. See
`CONTRIBUTING.md`.
