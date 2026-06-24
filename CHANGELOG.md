# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to SemVer.
Pre-1.0: the CLI and config surface are NOT frozen; minor versions may break them.

## [0.2.0] — Sandbox hardening

### Added
- `kern-isolation`: **mount-ordering typestate** `Rootfs<Mounted>` → `create_old_root()` →
  `Rootfs<OldRootReady>` → `into_readonly()`. Remounting the root read-only before pivoting in
  is now a **compile error**, not a sandbox-escape bug.
- `kern-isolation`: `MountMode` enum (overlay / bind / tmpfs) driving the initial root mount.
- `kern-cli`: `SandboxCtx` step sequence wired to the typestate.
- `kern box <name> --plan` — print the ordered isolation sequence (mount → pivot → read-only).
  Privilege-free; uses the validated `BoxName` newtype (rejects path traversal).

### Changed
- `overlay_ro_sequence` is now driven through the typestate; the characterization golden is
  **byte-identical** (the refactor changed no observable behaviour).

### Security
- `BoxName` hardened to a conservative charset (`[A-Za-z0-9_.-]`, no leading `-` or `.`, max 64
  chars). Blocks path traversal, NUL, whitespace, control characters, shell metacharacters and
  argument-injection by construction. Fuzzed with 40+ hostile inputs: zero crashes/panics.

## [0.1.0] — Foundation

### Added
- Workspace foundation: `kern-cli` (binary `kern`), `kern-common`, `kern-oci`, `kern-isolation`.
- Module-based CLI (no `include!()`): command parsing/dispatch + `--no-gpu` global flag.
- `kern-oci`: whiteout path-safety helper with a symlink-escape regression test.
- `kern-isolation`: the `MountOps` characterization seam (refactor-safety net).
- Project docs: README, SECURITY, ARCHITECTURE, CONTRIBUTING, CLA, CODE_OF_CONDUCT.
- CI: build + test + clippy + fmt + cargo-audit + cargo-deny on x86 (skip-graceful for HW).

[0.2.0]: https://github.com/getkern/kern/commits/main
[0.1.0]: https://github.com/getkern/kern/releases/tag/v0.1.0
