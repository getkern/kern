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

## Current status (0.4 — honest)

What is **enforced now** by `kern box`:
- user + PID + network (loopback-only) + UTS + IPC + mount namespaces;
- `pivot_root` into the rootfs (the default root is a writable overlay whose scratch is discarded
  on exit; `--read-only` remounts the root **read-only** — and the mount ordering, read-only only
  *after* the pivot, is compile-enforced by a typestate);
- **least-privilege capabilities**: 13 never-needed dangerous caps (module load, raw I/O,
  `SYS_TIME`, `SYSLOG`, `BPF`, `PERFMON`, MAC/audit admin, `SYS_BOOT`, …) are dropped from the
  effective/permitted/inheritable **and** the bounding set just before exec, so neither the
  workload nor a setuid/file-capability binary can wield them (they're namespaced anyway — this
  shrinks the surface against cap-gated kernel bugs);
- always-on **seccomp** denylist (~25 syscalls: kexec(+`_file_load`) / module load-unload /
  ptrace + `process_vm_readv`/`writev` / reboot / swap / the classic **and** new mount API /
  `pivot_root` / `setns` / `unshare` / `bpf` / `perf_event_open` / `userfaultfd` / `syslog`),
  wrong-arch syscalls killed.

Resource caps (memory + tasks): when a systemd **user** manager is present, `kern box` re-execs
inside a transient `systemd-run --user --scope` with `MemoryMax`/`TasksMax`, so fork-bomb / OOM
are cgroup-enforced. Without it, a best-effort cgroup v2 path applies where the hierarchy is
delegated, else it is skipped gracefully — so on a host with **neither** systemd-user nor a
delegated cgroup, containment is not guaranteed.

Opt-in flags that **relax** isolation (off by default — you ask for them):
- **`--net`** shares the **host network namespace** instead of the isolated loopback-only one.
  The box gains outbound connectivity, but there is then **no network isolation**: it can reach
  host `localhost` services, the host's networks, **and every abstract-namespace UNIX socket**
  (those live in the network namespace, not the filesystem — e.g. X11, some D-Bus/runtime
  sockets), and bind host-visible addresses. Use it for trusted build/fetch steps, not for
  untrusted code.
- **`-v src:dst`** binds a host path into the box. A writable volume is a hole through the
  sandbox by design — the box can modify those host files (use `:ro` for read-only). `kern`
  rejects a non-existent source and resolves it to an absolute, symlink-free path first.
- **`kern exec`** joins a running box's namespaces; it is restricted to the user who started the
  box (joining its user namespace requires being that namespace's owner) and the exec'd process
  is given the same seccomp filter.
- **`-p [ip:]host:box`** publishes a box port on the host via a rootless forwarder. It **binds
  `127.0.0.1` by default** (reachable only from the host); `-p 0.0.0.0:H:B` binds all interfaces
  and exposes the box's service to the LAN — a deliberate, warned-about choice. The forwarder runs
  in the host network namespace (it has to, to bind the host port); the box itself stays in its own
  isolated network namespace.

OCI pull (`kern pull` / `--image`):
- **Integrity**: each blob is verified to hash to its `sha256:` digest (via `sha256sum`) before
  use — defends against a compromised/MITM registry and corrupt downloads, beyond TLS.
- **Layer vetting**: absolute paths, `..` traversal, device nodes, hardlink targets that escape
  the rootfs, and a 2 GiB decompression-bomb cap are all rejected before anything is written.
- **Isolated-staging, no-follow merge**: each layer extracts into a fresh staging dir, then
  merges into the rootfs refusing to traverse any symlink — the cross-layer escape class is
  closed structurally (not by trusting tar). The guard is a lexical check, which is sound here
  because extraction is single-threaded (no concurrency across the image's own layers) and the
  cache/scratch dirs are created **mode 0700 and owned by the user**, so no other local user can
  race a symlink into the paths. Whiteouts (incl. opaque dirs) are applied under the same guard.

## Hardening posture

- Zero vendor-binary modification; the GPU shim uses only the public driver API and is
  disable-able with `--no-gpu`.
- GNU tar >= 1.27 enforced for layer extraction; tar layers validated before extraction
  (no `..`, no absolute paths, size caps); escaping symlinks sanitized.
- Always-on seccomp blocks the dangerous syscall set regardless of flags.

## Supported versions

Pre-1.0: only the latest 0.x is supported. Security fixes land on `main`.
