# Contributing to kern

Thanks for considering a contribution. kern is security-critical (it runs untrusted images as
a sandbox), so the bar on the sandbox/OCI paths is high, and the tests are the proof.

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

CI runs the above on x86 plus `cargo-audit` / `cargo-deny`. ARM is manually validated on real
boards (not yet in CI, tracked in the issues); hardware-dependent tests **skip gracefully** when
the precondition is absent.

## Tests are not optional

- **Unit** tests go inline (`#[cfg(test)] mod tests`) next to the code (private logic).
- **Integration/CLI** tests go in `crates/<crate>/tests/`.
- **Anything touching the sandbox path** must keep the **characterization** assertion
  (recorded mount/pivot sequence) green AND, where it changes behaviour, add/keep a
  **real-syscall** correctness test (escape-blocked / canary-unreadable).
- **Security fixtures must be synthetic, minimal, and self-contained**: no private paths, no
  real-world exploit payloads. See `kern-oci`'s symlink-escape regression for the template.

## Changing a flag or config key (deprecation policy)

The CLI/config surface isn't frozen pre-1.0, but changes still must not break a user's scripts
without warning. This is **blocking** on review, same as tests:

- **Rename with identical semantics** → keep the old name as a **deprecated alias**. Parse it to
  the same `Command` field and emit a single stderr warning (`warning: --old is deprecated; use
  --new`). Keep it for **≥ 2 minor releases**, then remove. Record it under **Deprecated** in the
  CHANGELOG when introduced and **Removed** when dropped.
- **Rename/repurpose with divergent semantics** → do **not** alias it (a silent reinterpretation
  corrupts behaviour). **Reject the old name with a `Usage` error** that explains the difference
  and names the replacement. The `--memory-swap` → `--memory-swap-max` rejection in
  `cli.rs` is the reference implementation; mirror its message shape (`X is not supported (why);
  use Y`).
- A new flag must land with a parser test asserting it populates the right `Command` field, and a
  rejection must land with a test asserting the `Usage` error (see `cpu_ram_flag_freeze`).

## Reporting security issues

Do **not** open a public issue, see `SECURITY.md`.

## Scope reminder

The GPU VRAM cap is cooperative by design; don't file "the cap is bypassable" as a security
bug (it's documented, out of scope). See `SECURITY.md`.
