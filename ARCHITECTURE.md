# Architecture

This documents the structure and the deliberate design choices, so the repo reads as a
designed project, not a script.

## How it works

```text
   kern  ·  one static binary, no daemon        box · run · compose · exec · pull · top …
     │
     ▼
   runtime  (kern-isolation)
     ├─ namespaces   user · pid · net · mnt · uts · ipc
     ├─ rootfs       OCI overlay → pivot_root   (typestate: Mounted → OldRootReady → ReadOnly)
     ├─ devices      fresh /dev · vgpio passthrough · -v volumes (symlink-safe)
     ├─ cgroups v2   MemoryMax · CPUQuota · TasksMax
     ├─ seccomp      always-on denylist (+ wrong-arch / x32)
     └─ supervisor   fork → PID 1 → reap → exec / stats / stop
     │
     ▼
   images  (kern-oci)   registry v2 · sha256 per blob · in-process tar vetting
```

A `kern box` is one short-lived process tree: no daemon, no shared state.

1. **Namespaces.** `unshare` into a fresh user + PID + UTS + IPC namespace (and, by default, an
   isolated loopback-only net namespace; `--net` shares the host's, opt-in, flagged in the status
   panel). A single-uid map makes your uid root *inside* the box only; `--uid-range` opts into a full
   sub-id range.
2. **Root filesystem.** An **overlay** by default (image = read-only lower, a private upper takes
   writes); `--read-only` remounts it read-only *after* a self-pivot (`pivot_root(".", ".")`), which
   works even where a bind remount-RO is denied (some Android-kernel boards). Nothing is written into
   the rootfs, so many boxes share one read-only rootfs concurrently. (`--bind-rootfs` swaps the
   overlay for a direct bind: faster on a slow overlayfs, at the cost of a mutable shared source.)
3. **Devices, volumes & secrets.** A fresh `/dev` with the safe nodes (`+ /dev/net/tun` on `--tun`);
   `-v` volumes bound in with targets resolved **symlink-safely**, confined to the new root; secrets
   on a RAM `/run/secrets` (`0400`); `vdisk:`/`vgpio:` mounting exactly their declared disk/peripherals.
4. **Lockdown.** A clean env (no host secrets leak in), capabilities stripped to least-privilege, an
   optional `--user` drop, an always-on **seccomp** denylist (incl. wrong-arch + x32; an opt-in
   deny-by-default **allowlist** via `--security-profile untrusted` / `KERN_SECCOMP=allowlist`), and
   cgroup caps:

`kern box <name> --plan` prints the exact sequence for your invocation, without running it: that
output is generated from the code, so it cannot drift the way a description here would.
See **[SECURITY.md](SECURITY.md)** for where each boundary is real, cooperative, or opt-in.

## Workspace

```
crates/
  kern-cli/        the `kern` binary (published as `getkern`); thin main + cli + commands/ + sandbox/
  kern-common/     shared newtypes (BoxName, …), units can't be mixed up
  kern-oci/        OCI pull / layer extraction / whiteout (security-critical path-safety)
  kern-isolation/  namespace / cgroup / mount primitives + the characterization seam
```

A GPU layer is **deferred to a later phase** and is additive: nothing in the core changes to accommodate
it: no GPU is touched today, because there is no GPU code here. This document will describe it when there is
something to describe.

## Design choices (and why)

- **Real `mod`s, no `include!()`.** The binary uses ordinary modules with `pub(crate)`
  boundaries and a command enum + `match` dispatch, a real module tree, not a concatenated
  script.
- **The sandbox is a sequence of steps against a seam.** Mount/pivot/remount operations go
  through the `kern_isolation::MountOps` trait. A `Recorder` impl captures the exact ordered
  call list so a test asserts it byte-identical before/after a refactor, the *refactor-safety*
  net for the setup sequence. This does **not** replace the real-syscall correctness tests that
  actually mount/pivot and assert escape-blocked.
- **Mount-ordering as a typestate.** `Rootfs<Mounted>` → `create_old_root()` →
  `Rootfs<OldRootReady>` → `into_readonly()` makes "remount read-only before `.old_root`
  exists" a *compile error*, not a runtime bug.
- **GPU backends as a closed enum (roadmap).** `enum Backend { Cuda, Hip, Vulkan }` with
  exhaustive `match`, the compiler forces every vendor to be handled; `Box<dyn>` only if/when
  third-party backends are allowed.
- **One driver proxy (roadmap).** `GovernedDriver<D: RealDriver>` checks the quota then
  forwards via the public API, a single, inspectable interception boundary (the auditability
  story).
- **Errors:** `Result`-based in libraries (the target is `thiserror` enums), mapped to an
  exit code in exactly one place in the binary. Post-fork, pre-exec child code stays
  `exit()`-based by necessity (you cannot unwind a `Result` across `fork`).
- **Zero-heap on hot paths, opt-in only.** Where it matters (per-syscall buffers), stack
  buffers; never as premature optimization elsewhere.

## Tests

Four layers (Rust-standard): unit (inline `#[cfg(test)]`), integration (`tests/`, black-box
binary), the characterization seam (deterministic, privilege-free), and real-syscall
correctness tests (skip-graceful where namespaces/HW are unavailable). CI x86 stays
always-green via skip-graceful gates on both x86 and a native aarch64 runner; the specific boards
(Pi, Jetson, UNO Q) are also validated by hand, and the real-GPU tests land with the GPU layer
(roadmap). See
`CONTRIBUTING.md`.
