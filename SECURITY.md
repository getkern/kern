# Security Policy

kern runs untrusted images inside a sandbox and (optionally, from 0.9) interposes on the GPU
driver. It *will* receive security reports — here is the model and how to report.

## Reporting a vulnerability

**Please do not open a public issue for security bugs.** Report privately via GitHub Security
Advisories ("Report a vulnerability" on the repo) or email the maintainer listed on the GitHub
profile. You'll get an acknowledgement and a coordinated-disclosure timeline.

## Threat model

**In scope — kernel-enforced isolation must hold:**
- A malicious OCI image / `--rootfs` must not read or write host files outside the rootfs
  (path traversal, cross-layer symlink escape, whiteout-through-symlink, tar traversal).
- A box must not see or affect host processes, mounts, or other boxes (PID/mount/net ns).
- Resource limits (cgroups: memory/pids) must hold; fork bombs / OOM must be contained.
- seccomp must block the dangerous syscall set unconditionally.

**Explicitly OUT of scope (cooperative, by design — not a boundary):**
- **The GPU VRAM cap (0.9+) is cooperative.** It governs honest workloads via the public
  driver API; an adversarial app bypasses it (absolute-path `dlopen`, static link, raw
  ioctls). On consumer NVIDIA there is no userspace hard cap; a kernel-enforced cap exists
  only on AMD/Intel via the `dmem` cgroup controller. Do not treat the GPU cap as a security
  boundary or a multi-tenant billing mechanism on consumer NVIDIA.

## Hardening posture

- Zero vendor-binary modification; the GPU shim uses only the public driver API and is
  disable-able with `--no-gpu`.
- GNU tar >= 1.27 enforced for layer extraction; tar layers validated before extraction
  (no `..`, no absolute paths, size caps); escaping symlinks sanitized.
- Always-on seccomp blocks the dangerous syscall set regardless of flags.

## Supported versions

Pre-1.0: only the latest 0.x is supported. Security fixes land on `main`.
