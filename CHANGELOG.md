# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to SemVer.
Pre-1.0: the CLI and config surface are NOT frozen; minor versions may break them.

## [Unreleased]

### Added
- Workspace foundation: `kern-cli` (binary `kern`), `kern-common`, `kern-oci`, `kern-isolation`.
- Module-based CLI (no `include!()`): command parsing/dispatch + `--no-gpu` global flag.
- `kern-oci`: whiteout path-safety helper with a symlink-escape regression test.
- `kern-isolation`: the `MountOps` characterization seam (refactor-safety net).
- Project docs: README, SECURITY, ARCHITECTURE, CONTRIBUTING, CLA, CODE_OF_CONDUCT.
- CI: build + test + clippy + fmt + cargo-audit + cargo-deny on x86 (skip-graceful for HW).

[Unreleased]: https://github.com/getkern/kern/commits/main
