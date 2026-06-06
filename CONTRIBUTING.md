# Contributing to kern

Thanks for considering a contribution. kern is security-critical (it runs untrusted images as
a sandbox), so the bar on the sandbox/OCI paths is high — and the tests are the proof.

## Before you start

- **CLA required.** All contributions are under the [CLA](CLA.md) (a bot will ask on your
  first PR). This keeps relicensing/stewardship options open for the project.
- Read `ARCHITECTURE.md`. Match the surrounding code's idioms.

## Workflow

```sh
cargo build
cargo test            # unit + integration + characterization (skip-graceful for HW)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

CI runs the above on x86 plus `cargo-audit` / `cargo-deny`. ARM and real-GPU tests run on
self-hosted runners; locally they **skip gracefully** when the precondition is absent.

## Tests are not optional

- **Unit** tests go inline (`#[cfg(test)] mod tests`) next to the code (private logic).
- **Integration/CLI** tests go in `crates/<crate>/tests/`.
- **Anything touching the sandbox path** must keep the **characterization** assertion
  (recorded mount/pivot sequence) green AND, where it changes behaviour, add/keep a
  **real-syscall** correctness test (escape-blocked / canary-unreadable).
- **Security fixtures must be synthetic, minimal, and self-contained** — no private paths, no
  real-world exploit payloads. See `kern-oci`'s symlink-escape regression for the template.

## Reporting security issues

Do **not** open a public issue — see `SECURITY.md`.

## Scope reminder

The GPU VRAM cap is cooperative by design; don't file "the cap is bypassable" as a security
bug (it's documented, out of scope). See `SECURITY.md`.
