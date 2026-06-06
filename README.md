# kern

A fast, lightweight **sandbox & virtual resource manager** — give any workload its own
governed slice of the machine: CPU, memory, process and filesystem.

Kernel-enforced (user namespaces + cgroups v2 + seccomp + pivot_root/overlayfs), no daemon,
tiny footprint. The same model is designed to extend to GPUs and other devices.

> **Status: 0.1 — early.** This is the foundation: the workspace, the module/test architecture,
> and the first hardened pieces (OCI whiteout path-safety, the sandbox characterization seam).
> The full runtime lands as it grows (see **[Direction](#direction)**). **The CLI and config
> surface are NOT frozen until 1.0.**

## What it is

`kern box` / `kern run` / `kern pull`: pull an OCI image and run a command inside a sandbox
isolated with Linux user namespaces, cgroups v2, seccomp, and `pivot_root`/overlayfs — no
daemon, ~1 process, started in milliseconds.

**Design goals** (validated in development against Docker on the reference implementation;
reproducible here as the runtime lands per the roadmap):

| | kern (goal) | Docker |
|---|---|---|
| cold start | ~3 ms | ~310 ms |
| memory / container | ~1 MB | ~6 MB |
| 10k containers | ~1.2 s | — |
| daemon | none | dockerd |

## Scope — read this first (honesty over hype)

- **CPU / memory / process / filesystem isolation** is kernel-enforced (namespaces + cgroups
  + seccomp). That is the load-bearing guarantee — the one kern actually makes.
- **Cross-arch:** validated by **manual runs** on x86_64, NVIDIA Jetson (L4T/aarch64),
  Raspberry Pi 5, and an Android-Debian aarch64 board. Automated ARM CI is tracked in the
  issues — at 0.1, "ARM works" is manual-validated, not CI-proven.

## Build & try

```sh
cargo build --release
./target/release/kern --help
```

## Direction

kern starts as a small, fast sandbox/OCI runtime and grows deliberately from there. Early
work is about the runtime and getting its isolation provably correct; over time it grows
into a broader resource manager — the set of resources it governs is driven by what proves
useful, not a fixed list.

See `ARCHITECTURE.md` for the design and `CONTRIBUTING.md` to get involved.

## License

[Apache-2.0](LICENSE). Contributions require the [CLA](CLA.md).
