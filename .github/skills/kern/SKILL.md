---
name: kern
description: Build, run, configure, and troubleshoot containers or code sandboxes with getkern/kern. Use for Kern CLI, Compose migration, Dockerfile builds, and kern-sandbox Python integration; not generic Linux kernel development.
license: Apache-2.0
---

# Kern

Work with the user's installed Kern version and project files. Kern is a rootless, daemonless Linux container runtime. Docker-compatible formats do not imply a Docker Engine API, socket, or identical behavior. `kern run` runs a host process; use `kern box` for container workloads.

## Establish the environment

- Inspect existing Dockerfiles, Compose files, Kern TOML, and the requested workload before choosing changes.
- Check `kern --version`, `kern doctor`, and `kern <verb> --help` for the relevant command. Record the actual host and execution environment. Windows needs WSL2; macOS needs a Linux VM.
- If Kern is absent, follow the current [official installation guide](https://github.com/getkern/kern/blob/main/docs/INSTALL.md) for that Linux environment. Do not assume Docker Desktop supplies Kern or replace the user's runtime.
- Match documentation to the installed release. References capture a 2026-09-08 inspection of moving upstream documentation; recheck version-sensitive options before relying on them.

## Choose the relevant workflow

- For CLI lifecycle, builds, Compose migration, networking, or diagnosis, read [runtime.md](references/runtime.md).
- For Python code execution or long-lived sandboxes, read [python.md](references/python.md).
- For provenance and the requested highest-starred Docker skill comparison, read [sources.md](references/sources.md).
- For a proposed change to the Kern repository, read [upstream-contribution.md](references/upstream-contribution.md) before preparing a pull request.

## Deliver and verify

Make the smallest changes that satisfy the workload. Preserve persistent data and the user's development or production context. For cleanup, identify the exact workload and data affected; do not use broad prune/reset operations as a troubleshooting default.

Validate relevant configuration and run a representative workload in the actual target environment when available. Check intended persistence, connectivity, and limits. Distinguish configuration validation, static review, and executed verification; report unavailable runtime checks explicitly.
