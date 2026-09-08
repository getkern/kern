# Kern runtime and Compose

Read this for CLI operations, builds, Docker migration, and troubleshooting. Verify syntax against the installed release; use the [official README](https://github.com/getkern/kern) and [Docker compatibility matrix](https://github.com/getkern/kern/blob/main/docs/DOCKER-COMPAT.md) for the particular feature.

## Small starting points

```sh
kern --version
kern doctor
kern box dev --image alpine -it -- sh
kern compose stack.toml config
kern compose stack.toml up
kern validate ~/.config/kern/kern.toml
```

The `box` example creates/runs a named workload. Compose assumes an existing `stack.toml`; select the user's real file. The final command validates the named Kern configuration, not arbitrary Compose files. Inspect command help before adding flags; do not mechanically substitute `kern` for `docker`.

## Migration decisions

Kern does not expose the Docker Engine API or Docker socket and is not a CRI or multi-host orchestration replacement. Identify workloads using those interfaces before proposing migration. Check each required Dockerfile instruction and Compose feature in the compatibility matrix. Unsupported Compose keys may be ignored; accepted syntax alone does not establish equivalent behavior.

Compose defaults to a pod with a shared network namespace and trust domain. Services using the same internal port can conflict even when published host ports differ. Address service listening ports or choose a supported topology after checking implications. `--no-pod` has relay and wildcard-bind caveats; it is not a universal compatibility fix. Validate actual service connectivity and outbound access.

Outbound networking from the default Compose pod requires working `pasta`, not merely a binary detected by `kern doctor`. Build caching operates at whole-build granularity, not Docker-style per-layer reuse. Do not promise equivalent cache behavior from copied Dockerfile optimizations.

`x-kern-*` extensions carry Kern-specific grants or constraints that Docker ignores. A file shared between engines needs separate verification of security and runtime behavior.

## Isolation and resources

For workloads requiring it, verify `--security-profile untrusted` support; it bundles a read-only root filesystem and dropping all capabilities. Account for application write locations. When enforced resource limits are required, use supported limits with `--require-limits`: it fails closed if cgroup enforcement is unavailable. Verify cgroup v2 delegation. Do not describe requested limits as enforced without environment support. Host mounts expose host data and containers share the kernel; neither rootless execution nor memory limits make arbitrary mounts safe or bound workspace disk growth.

## Diagnose from evidence

Capture version, doctor result, exact failing command, relevant redacted configuration, and bounded logs or inspection output using supported CLI commands. Separate image/build errors, process exit, port conflicts, egress failure, permissions, and unavailable enforcement. Correct the observed failure rather than resetting runtime state.

The inspected changelog has released v0.9.2 (2026-09-06) and an Unreleased section. v0.9.2 includes a single-service Compose egress fix. Automatic retry involving SELinux and `pasta` was listed under Unreleased: check the actual release before assuming availability. Consult [CHANGELOG.md](https://github.com/getkern/kern/blob/main/CHANGELOG.md) for version-dependent behavior.
