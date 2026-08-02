<div align="center">

<img src="assets/brand/kern-logo.png" width="260" alt="kern">

# kern

**A fast, rootless sandbox and virtual resource runtime for any workload, including untrusted and AI-generated code.**

**A real, kernel-enforced container in 3.4 ms, out of one 1.83 MB binary with no daemon.**

<p align="center">
  <img src="assets/kern-demo.gif" width="720" alt="Terminal: 'kern box app --image alpine -- echo hello from a real container' prints the greeting, then reports that kern started in 3.4 ms against docker run's 291 ms. A real OCI image, rootless, a 1.83 MB binary, no daemon, on an Intel i7-14700KF, Linux 7.0.">
</p>

<sub>**0 RAM at rest** · no daemon, no socket, nothing to start · one static binary, `libc` the only dependency</sub>

[![CI](https://github.com/getkern/kern/actions/workflows/ci.yml/badge.svg)](https://github.com/getkern/kern/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%C2%B7%20Windows%20(WSL2)%20%C2%B7%20ARM%20boards-informational.svg)](docs/INSTALL.md)
[![Release](https://img.shields.io/github/v/release/getkern/kern?label=release&color=brightgreen)](https://github.com/getkern/kern/releases/latest)

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
kern box dev --image alpine -it -- sh
```

</div>

---

## What kern is

kern runs Linux workloads in real, kernel-enforced sandboxes: user, PID, mount, network, UTS and IPC
namespaces, an overlay or read-only root pivoted in, an always-on seccomp filter, and cgroup v2
limits. It pulls OCI images, builds them, runs them, and gets out of the way. No background daemon,
one short-lived process per box.

It has **two verbs**. `kern box` wraps a process in a full isolated slice. `kern run` caps a resource
on a process you launch yourself, with no sandbox. Isolation is simply the first resource kern
manages; the same model slices CPU (`vcpu:`), memory, disk (`vdisk:`) and devices (`vgpio:`) per
process, defined once in a `kern.toml` and attached by name. See
[docs/RESOURCES.md](docs/RESOURCES.md).

<p align="center">
  <img src="assets/demo.svg" width="780" alt="Terminal demo: a kern.toml defines reusable vcpu/vdisk/vgpio (device) profiles; 'kern box train --image alpine vcpu:heavy vdisk:scratch' attaches a 4-vCPU, 8 GB, 2 GB-scratch rootless isolated slice in a few ms (docker run takes ~289 ms); 'kern run vcpu:heavy -- ffmpeg' caps a heavy transcode with no sandbox; 'kern box iot --image alpine vgpio:sensor' exposes only /dev/i2c-1 and nothing else; piping a request into 'kern box fn --image python' runs it in a fresh isolated box per request (serverless style); 'kern compose stack.toml up' brings up a multi-box stack; 'kern top' is the live TUI for boxes, profiles and volumes: CPU, memory, disk and devices, sliced per box, in one ~1.8 MB static binary, no daemon.">
</p>

## What kern is not

- **Not a hypervisor.** The boundary is the Linux kernel: namespaces, capabilities, seccomp and
  cgroups. A kernel privilege-escalation bug is an escape. For actively hostile, multi-tenant code
  from strangers, reach for a microVM (Firecracker, Kata) or gVisor. kern's ground is your own or
  semi-trusted code: CI jobs, build steps, dev sandboxes, an agent's tool-calls under your
  supervision.
- **Not free of the userns trade.** kern's isolation is built on an unprivileged user namespace, and
  userns has been a fertile source of kernel LPE bugs. Running untrusted code in a box hands it that
  surface to probe. [SECURITY.md](SECURITY.md) states this first, before any claim.
- **Not a Docker Engine reimplementation.** kern speaks Docker's *formats*, images and
  `docker-compose.yml` and Dockerfiles, not its API. No overlay networks, no plugin ecosystem, no
  Swarm. Full matrix: [docs/DOCKER-COMPAT.md](docs/DOCKER-COMPAT.md).
- **Not a Kubernetes runtime.** It does not implement CRI. For that, use containerd or CRI-O.
- **Not shipping GPU slices.** They are on the [roadmap](ROADMAP.md) and there is no GPU code in this
  edition, so there is nothing here to trust or to attack yet.

What it does not know or does not do yet is written down in [OPEN_ITEMS.md](OPEN_ITEMS.md) rather
than left for you to find: an unattributed gap in a startup measurement, why the seccomp filter is
still a denylist, which fleet limit is a guard rail instead of a boundary.

## Install

**🐧 Linux and ARM boards** (Raspberry Pi · Jetson · Arduino UNO Q). One line; auto-detects `x86-64` / `aarch64`:

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

Served from **github.com** (read the script first if you like). It downloads the release binary for
your arch and verifies the sha256 before installing. No Rust toolchain required.
(`getkern.dev/install.sh` is a short alias.)

**From source**, if you would rather build it yourself or want a target we do not publish a binary for:

```sh
cargo install --git https://github.com/getkern/kern getkern --locked
```

**🪟 Windows.** One line in PowerShell (no Docker Desktop, no Ubuntu):

```powershell
irm https://raw.githubusercontent.com/getkern/kern/main/install.ps1 | iex
```

Needs a Linux kernel with unprivileged user namespaces and cgroup v2. `kern doctor` tells you
whether boxes will run here before you try. Boards, WSL2, checksums and the long form:
[docs/INSTALL.md](docs/INSTALL.md).

## Quickstart

```sh
kern box dev --image alpine -it -- sh              # a throwaway shell in a real OCI image
kern run --memory 256M --cpus 0.5 -- ./crunch      # cap a process, no sandbox
kern box svc --image alpine -d -p 8080:80 \        # a service: published, restarted, health-checked
  --restart --health-cmd 'wget -qO- localhost:80' -- httpd -f
kern ps                                            # what is running, with PORTS and HEALTH
kern exec svc -it -- sh                            # shell into it
kern top                                           # live TUI: boxes, CPU/RAM, profiles, volumes
kern compose stack.toml up                         # a multi-box stack, kern TOML or compose.yml
```

Untrusted code, with the defaults doing the work:

```sh
kern box job --image python:3.12-slim --read-only --cap-drop ALL --memory 256m -- python3 /w/x.py
```

No network unless you ask, a read-only root, dangerous capabilities dropped, seccomp always on.
Ninety runnable examples, each doing one thing: [examples/](examples/).

## kern vs Docker vs Podman

| | kern | Docker | Podman |
|---|---|---|---|
| Daemon | **no** | yes (`dockerd` + `containerd`) | no |
| Rootless | **yes**, always | opt-in | yes |
| Cold start, bare box | **2.1 ms** | ~294 ms | ~281 ms |
| Cold start, from an OCI image | **3.4 ms** | ~294 ms | ~281 ms |
| Resident memory, nothing running | **0** | 154 to 160 MB | 0 |
| Footprint | **one 1.83 MB binary** | daemon stack | multi-binary install |
| OCI images, pull / build / push | yes | yes | yes |
| `docker-compose.yml` | yes, read as-is | yes | partial |
| Overlay networks, Swarm, CRI | **no** | yes | partial |
| GPU | on the roadmap | yes | yes |

## Performance

Measured 2026-08-01 on an Intel i7-14700KF, Linux 7.0.0, against the runtimes installed there. Every
number below comes from one script you can run yourself, `python3 examples/benchmark.py`.

| | kern | bubblewrap | runc | podman | docker |
|---|---:|---:|---:|---:|---:|
| Cold start (bare box) | **2.2 ms** | 3.0 ms | 13.2 ms | 281.5 ms | 294.4 ms |
| 200 boxes in parallel | **0.09 s** | 0.19 s | 0.30 s | 41.8 s | 16.6 s |

A thousand simultaneous boxes take 0.65 s, all 1000 of them. One more live box costs 0.35 MB of real
memory. `exec` into a running box is 0.79 ms against Docker's 43.3.

kern is in the fastest tier and does not win single-shot latency outright: bubblewrap is 0.8 ms
behind and the physical floor for `unshare` + `exec` is 1 to 2 ms. The gap that matters is to the
engines, ~132x, and bubblewrap is a launcher with no images, caps or lifecycle. Method, per-phase
breakdown, board numbers and the caveats: **[BENCHMARKS.md](BENCHMARKS.md)**.

## Security

Namespaces, a `pivot_root`, 13 dangerous capabilities dropped before exec, an always-on seccomp
denylist of 33 syscalls, cgroup v2 limits, and a deny-by-default `/dev`. Where a boundary is
cooperative rather than kernel-enforced, [SECURITY.md](SECURITY.md) says so and names the bypass.

You do not have to take it on trust: [pentest/](pentest/) holds four adversarial suites that assert
those boundaries against the kernel rather than against kern's own reporting, and they run without a
registry account or a network.

```sh
sh pentest/run-with-local-registry.sh ./target/release/kern pentest/pentest-ports.sh
```

Report a vulnerability privately via GitHub Security Advisories or hello@getkern.dev.

## Documentation

| | |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | install on Linux, WSL2 and ARM boards, with checksums |
| [docs/RESOURCES.md](docs/RESOURCES.md) | `vcpu:` / `vdisk:` / `vgpio:` and the two-verb model |
| [docs/CONFIG.md](docs/CONFIG.md) | the `kern.toml` schema, field by field |
| [docs/DOCKER-COMPAT.md](docs/DOCKER-COMPAT.md) | what of Docker works, what does not, and where it differs |
| [docs/STORAGE.md](docs/STORAGE.md) · [docs/EGRESS.md](docs/EGRESS.md) | volumes and the egress allowlist |
| [BENCHMARKS.md](BENCHMARKS.md) · [EDGE.md](EDGE.md) | measurements, and running on a Pi, Jetson or UNO Q |
| [SECURITY.md](SECURITY.md) · [OPEN_ITEMS.md](OPEN_ITEMS.md) | the threat model, and the known gaps |
| [ARCHITECTURE.md](ARCHITECTURE.md) · [CHANGELOG.md](CHANGELOG.md) | how it is built, and what changed |
| [examples/](examples/) · [blog/](blog/) | ninety runnable scripts, and longer write-ups |

Embed it from Python or Node with [`kern-sandbox`](bindings/python/README.md): a fresh box per call,
network off by default, hard caps, and a timeout the binding enforces.

## Status

**0.6.32.** Everything above works today and is tested: 692 Rust, 69 Python and 56 Node tests,
clippy-clean, `cargo-deny`-clean. Semver, pre-1.0: the CLI and config surface can still change
between minor versions, always called out in [CHANGELOG.md](CHANGELOG.md). Releases are signed tags
and timestamped to Bitcoin ([provenance/](provenance/)).

## Contributing

Issues and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) has the workflow and the
gates; contributions are covered by the [CLA](CLA.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [TRADEMARK.md](TRADEMARK.md).
