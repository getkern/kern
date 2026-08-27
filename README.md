<div align="center">

<img src="assets/brand/kern-logo.png" width="260" alt="kern">

**kern:** A fast, rootless sandbox and virtual resource runtime for any workload, including untrusted and AI-generated code.

**A real, kernel-enforced container in ~3.5 ms, out of one 1.52 MB binary with no daemon.**

<p align="center">
  <img src="assets/kern-demo.gif" width="720" alt="Terminal: 'kern box app --image alpine -- echo hello from a real container' prints the greeting, then reports that kern started in 3.5 ms against docker run's 297 ms. A real OCI image, rootless, a 1.52 MB binary, no daemon, on an Intel i7-14700KF, Linux 7.0.">
</p>

<sub>**0 RAM at rest** · no daemon, no socket, nothing to start · one static binary, `libc` its only Rust dependency</sub>

[![CI](https://github.com/getkern/kern/actions/workflows/ci.yml/badge.svg)](https://github.com/getkern/kern/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%C2%B7%20Windows%20(WSL2)%20%C2%B7%20ARM%20boards-informational.svg)](docs/INSTALL.md)

</div>

```sh
# install the release binary (static, 1.52 MB, checksum-verified by the script)
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh

# a throwaway shell in a real OCI image: rootless, kernel-enforced, a few ms
kern box dev --image alpine -it -- sh
```

<sub>No native Windows: use WSL2. [Install](#install).</sub>

---

## What kern is

**One binary that manages resources, of which isolation is the first.** That is why there is no
single row for kern in a comparison table: it is a container runtime, a sandbox, a resource slicer
and a stack runner at once, in 1.52 MB with no daemon.

- **A real container.** Real OCI images: `pull`, `build` from a Dockerfile, `commit`, `push`,
  `save`/`load`. A box from an image starts in ~3.5 ms.
- **A sandbox, always rootless.** User, PID, mount, network, UTS and IPC namespaces, an overlay or
  read-only root pivoted in, a deny-by-default seccomp allowlist and cgroup v2 limits. One flag,
  `--security-profile untrusted`, is the whole hardened bundle.
- **Resource profiles, not just isolation.** CPU (`vcpu:`), memory, disk (`vdisk:`) and devices
  (`vgpio:`), declared once in a `kern.toml` and attached by name. `kern run` applies the same caps
  to a process on the host, with no sandbox at all, plus `--landlock-rw <path>` to confine that
  process's writes with the kernel's own LSM. [docs/RESOURCES.md](docs/RESOURCES.md)
- **Stacks, in kern's own format or in Docker's.** `kern compose <file> up` takes a `kern-compose.toml`
  (`[box.NAME]` tables, with the resource profiles above) or the `docker-compose.yml` you already have,
  with no conversion step. One stack to one pod, services reaching each other by name.
- **The tools around them.** `ps`, `logs`, `exec`, `stats`, `inspect`, `wait`, `top` (a live TUI),
  `doctor`, plus a Python and Node SDK and an MCP server for agents. The Python binding also plugs
  into LangChain twice: as a code tool, and as an execution policy for its shell middleware, where it
  is a peer of the Docker one. [bindings/python/README.md](bindings/python/README.md)

Its entire Rust dependency tree is `libc`: JSON and OCI manifests are parsed by hand, and `pull`
shells out to the `curl` and `tar` already on the machine rather than linking a TLS stack. (1.52 MB
is the size-optimized release build; a plain `cargo install` from source is 1.91 MB.)

<p align="center">
  <img src="assets/demo.svg" width="780" alt="Terminal demo: a kern.toml defines reusable vcpu/vdisk/vgpio (device) profiles; 'kern box train --image alpine vcpu:heavy vdisk:scratch' attaches a 4-vCPU, 8 GB, 2 GB-scratch rootless isolated slice in a few ms (docker run takes ~297 ms); 'kern run vcpu:heavy -- ffmpeg' caps a heavy transcode with no sandbox; 'kern box iot --image alpine vgpio:sensor' exposes only /dev/i2c-1 and nothing else; piping a request into 'kern box fn --image python' runs it in a fresh isolated box per request (serverless style); 'kern compose stack.toml up' brings up a multi-box stack; 'kern top' is the live TUI for boxes, profiles and volumes: CPU, memory, disk and devices, sliced per box, in one 1.52 MB static binary, no daemon.">
</p>

## What kern is not

- **Not a hypervisor.** The boundary is the Linux kernel, so a kernel privilege-escalation bug is an
  escape. Docker and Podman share that condition, which is why gVisor and Firecracker exist.

  Read with the tagline, that is one line seen from both sides: untrusted and AI-generated code is
  what kern is FOR, because you chose to run it and own the blast radius (agent tool-calls, CI jobs,
  build steps, code cells). What it is not for is hostile code from strangers, multi-tenant, on a
  kernel you serve other tenants from. kern does start rootless always, where Docker's is opt-in.
- **Not free of the userns trade.** Its isolation is built on an unprivileged user namespace, a
  fertile source of kernel LPE bugs. [SECURITY.md](SECURITY.md) states this before any claim.
- **Not a wall around what you mount in.** `-v $HOME:/host` gives the box your home directory: a
  mount is a trust decision you make, not a boundary kern enforces. `--net host` and `--privileged`
  are opt-outs by name. (The one path kern refuses to bind is its own runtime registry.)
- **Not a Docker Engine reimplementation.** It speaks Docker's *formats*, not its API: no overlay
  networks, no plugins, no Swarm. Matrix: [docs/DOCKER-COMPAT.md](docs/DOCKER-COMPAT.md).
- **Not a Kubernetes runtime.** No CRI. Use containerd or CRI-O.
- **Not shipping GPU slices.** On the [roadmap](ROADMAP.md), with no GPU code in this edition, so
  there is nothing here to trust or to attack yet.

What it does not know or does not do yet is in [OPEN_ITEMS.md](OPEN_ITEMS.md) rather than left for
you to find.

## Install

kern needs a Linux kernel with unprivileged user namespaces and cgroup v2. It runs on **Linux, WSL2
and ARM boards** (Raspberry Pi · Jetson · Arduino UNO Q); there is **no native Windows** build, use
WSL2 (kern ships a pre-baked WSL rootfs).

The quickest route is the release binary: one static file, no toolchain, and the script verifies its
SHA256 before installing it.

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

It picks `x86_64` or `aarch64` for you, installs to `~/.local/bin` (`/usr/local/bin` as root, or
`KERN_INSTALL_DIR`), and refuses to install a download whose checksum does not match. Verifying by
hand instead is two lines:

```sh
curl -fsSLO https://github.com/getkern/kern/releases/latest/download/kern-x86_64-unknown-linux-musl.tar.gz{,.sha256}
sha256sum -c kern-x86_64-unknown-linux-musl.tar.gz.sha256 && tar xzf kern-x86_64-unknown-linux-musl.tar.gz
```

**From source** is the other route, and the whole dependency tree is one crate (`libc`), so it is
short: clone, build and install took 36 s on a desktop (i7-14700KF), longer on a small ARM board.

```sh
# if you do not have Rust yet
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

cargo install --git https://github.com/getkern/kern getkern --locked
```

That puts `kern` in `~/.cargo/bin`, which rustup adds to your `PATH` (open a new shell, or
`source "$HOME/.cargo/env"`, if `kern` is not found).

The release also ships an `aarch64` binary, a Windows `.exe` shim and a pre-baked WSL rootfs, each
with its own `.sha256`; the tag is GPG-signed and independently timestamped ([provenance/](provenance/)).

`kern doctor` tells you whether boxes will run here before you try. Boards, WSL2 and the long form:
[docs/INSTALL.md](docs/INSTALL.md). Common questions (Docker, bubblewrap, youki, E2B, Windows, the
threat model): [docs/FAQ.md](docs/FAQ.md).

## Quickstart

```sh
kern box dev --image alpine -it -- sh              # a throwaway shell in a real OCI image
kern run --memory 256M --cpus 0.5 -- ./crunch      # cap a process, no sandbox
kern box svc --image nginx:alpine -d -p 8080:80 \  # a service: published, restarted, health-checked
  --restart --health-cmd 'wget -qO- localhost:80' -- nginx -g 'daemon off;'
kern ps                                            # what is running, with PORTS and HEALTH
kern exec svc -it -- sh                            # shell into it
kern stop svc                                      # its signal, its grace, then the code it exited with
kern top                                           # live TUI: boxes, CPU/RAM, profiles, volumes
kern compose stack.toml up                         # a multi-box stack (examples/) or a compose.yml
kern compose stack.toml down                       # and take it down again
```

Untrusted code, one flag for the bundle:

```sh
kern box job --image python:3.12-slim --security-profile untrusted --memory 256m \
  -v ./job:/w -- python3 /w/x.py
```

`--security-profile untrusted` is the seccomp **allowlist** + `--cap-drop ALL` + `--read-only` in one
opt-in flag (spell them out by hand if you prefer); add `--require-limits` to refuse to start unless the
memory/pids caps are actually enforced. No network unless you ask, dangerous capabilities dropped,
seccomp always on. Ninety runnable examples, each doing one thing: [examples/](examples/).

Every read verb also answers in JSON, so nothing has to parse a table:

```sh
kern ps --json | jq '.[] | select(.health == "unhealthy") | .name'
kern volume ls --json          # ps · images · stats · inspect · builds · pod ls · config list · diff
```

## Your Docker Compose stack, without Docker Desktop

kern speaks `docker-compose.yml`. Point it at the stack you already have and `kern compose up` runs it
with no daemon and no Docker Desktop, the same on Linux, WSL2 and ARM boards.

```yaml
# compose.yaml - a real stack, unchanged
services:
  db:
    image: postgres:alpine
    environment: { POSTGRES_PASSWORD: secret, POSTGRES_DB: app }
  web:
    image: adminer
    ports: ["8080:8080"]
    depends_on: [db]
```

```sh
kern compose compose.yaml up
```

Both official images start, `web` reaches `db` by service name, and the port is published to the host.
Warm (images cached) the web tier serves in **~0.3 s**, and the stack costs only what postgres and adminer
actually use (~66 MB here) with **zero daemon** on top, where Docker Desktop is a background VM before your
first container.

Official images that drop to a non-root user (postgres, redis, ...) want `uidmap` and a `/etc/subuid`
line, and outbound image pulls want `pasta`; both are one `apt install` on a dev box, and `kern doctor`
names either if it is missing. This is the local dev loop, not a production orchestrator: no Swarm, no
overlay networks.

## Embed it: Python & Node

Run agent or LLM-generated code from your own program with
**[`kern-sandbox`](bindings/python/README.md)**, a thin, dependency-free wrapper over the `kern`
binary. Every call runs in a fresh isolated box: network off, memory and pid caps, capabilities
dropped, output bounded, and a timeout the binding itself enforces.

```sh
pip install kern-sandbox        # PyPI   · needs the `kern` binary above, on PATH or $KERN_BIN
npm  install kern-sandbox       # npm    · same
```

```python
from kern_sandbox import run_code

r = run_code("import platform; print(platform.python_version())")
print(r.stdout)          # ran in a fresh box; a timeout / OOM / blocked escape is data on r.fault
```

- **Faults are data, not exceptions**: a timeout, OOM-kill or blocked syscall is a field on the
  result, not a raise. A fresh box per call by default; `Sandbox` keeps a workspace across calls and
  a warm `kernel()` keeps one interpreter for sub-millisecond cells (weaker isolation, by choice).
- **Rich results without a Jupyter kernel**: the last expression, `display()` and matplotlib figures
  come back captured, like a notebook cell.
- Ships an **MCP server** (`kern-mcp`): a dependency-free stdio server that gives Claude Desktop,
  Cursor or any MCP client a local code interpreter. Point the client at it:

```json
{ "mcpServers": { "kern": { "command": "kern-mcp" } } }
```

Tools: `run_code` (python/bash/node), `write_file`, `read_file`, `list_files`. Each call is a fresh
network-off box; files persist across calls in a workspace on disk. Setup command, image and the
other options: [bindings/python/README.md](bindings/python/README.md).

Full API, Python and Node: [bindings/python/README.md](bindings/python/README.md) ·
[bindings/node/README.md](bindings/node/README.md).

## Resource profiles

A slice is declared once in `~/.config/kern/kern.toml` and attached by name, to a sandboxed box or a
bare process, with the same token.

Three kinds: `vcpu:` (CPU and memory), `vdisk:` (a size-capped scratch disk) and `vgpio:` (device
nodes). Two of them, and the anchors they are carved from:

```toml
[[cpu]]                     # the host budget a slice is carved from
id    = "cpu:0"
cores = 8.0

[[vcpu]]                    # 1.5 cores and 512 MiB  ->  attach as  vcpu:heavy
name    = "heavy"
backend = "cpu:0"
cpus    = 1.5
memory  = "512m"

[[gpio]]                    # a controller anchor
id = "gpio:0"

[[vgpio]]                   # exactly one device node ->  attach as  vgpio:sensor
name    = "sensor"
backend = "gpio:0"
i2c     = ["/dev/i2c-1"]
```

```sh
kern validate ~/.config/kern/kern.toml       # check it before anything runs
kern box train --image alpine vcpu:heavy vdisk:scratch -- ./train.sh
kern run vcpu:heavy -- ./train.sh            # the same slice, no sandbox
kern box iot --image alpine vgpio:sensor -- ls /dev
```

Profiles compose: several attach to one box, and an explicit flag beats a profile's own value. Every
key is spelled like its CLI flag, so `cpus` is `--cpus` and `memory` is `--memory`. A backend naming
no declared pool is refused when the config is read, not when the box runs.
[docs/RESOURCES.md](docs/RESOURCES.md) has the field-by-field schema.

A `vdisk:` is a RAM-backed tmpfs when kern runs rootless, whatever its backend says, and an
ext4-on-loop image with a real quota when it runs privileged. kern says which one you got, per
profile, rather than letting you assume, and the size cap is enforced either way.

**`vgpio:` is chip-granular, not per-line.** Asking for `pins` binds the whole `/dev/gpiochipN`, and
that character device exposes every line of that controller. `pins = [17]` does not restrict the box
to line 17: the kernel has no per-line mount boundary, so the pin list is cooperative metadata rather
than a boundary. Naming a device node, as `i2c` above does, grants that node and nothing else.

## kern vs Docker vs Podman

| | kern | Docker | Podman |
|---|---|---|---|
| Daemon | **no** | yes (`dockerd` + `containerd`) | no |
| Rootless | **yes**, always | opt-in | yes |
| Cold start, bare box | **~2.3 ms** | ~297 ms | ~293 ms |
| Cold start, from an OCI image | **~3.5 ms** | ~297 ms | ~293 ms |
| Stop a service (init handles SIGTERM) | **~1.9 ms** | ~310 ms | ~380 ms |
| Resident memory, nothing running | **0** | 154 to 160 MB | 0 |
| Footprint | **one 1.52 MB binary** | daemon stack | multi-binary install |
| OCI images, pull / build / push | yes | yes | yes |
| `docker-compose.yml` | yes, read as-is | yes | partial |
| Overlay networks, Swarm, CRI | **no** | yes | partial |
| GPU | on the roadmap | yes | yes |

## Performance

Intel i7-14700KF, Linux 7.0.0, the release binary, one script you can run yourself:
`python3 examples/benchmark.py`. Yours will differ with your CPU, kernel and filesystem.

| | kern | bubblewrap | runc | podman | docker |
|---|---:|---:|---:|---:|---:|
| Cold start (bare box) | **~2.3 ms** | ~2.3 ms | ~18.6 ms | ~293 ms | ~297 ms |
| 200 boxes in parallel | **~0.11 s** | ~0.16 s | ~0.35 s | ~44.8 s | ~16.2 s |

Three thousand at once take ~2.2 s, and a live box costs ~0.3 MB of memory.

Two honest notes. **Nobody wins single-shot latency outright**: the floor for `unshare` + `exec` is
1 to 2 ms, so the whole top tier sits inside its own noise, and bubblewrap is a launcher with no
images, caps or lifecycle. The gap that means something is to the *engines*, two orders of magnitude
above.

Method, per-phase breakdown, board numbers and every caveat: **[BENCHMARKS.md](BENCHMARKS.md)**.

## Security

Namespaces, a `pivot_root`, 16 dangerous capabilities dropped before exec, an always-on seccomp
**allowlist** by default (moby's own default filter minus kern's 35 escape syscalls, which stay
hard-killed; a syscall outside the vetted set returns `ENOSYS`, and the wider denylist is the opt-out
via `KERN_SECCOMP=denylist`), cgroup v2 limits (`--require-limits` refuses to start unless they bind),
and a deny-by-default `/dev`. Where a boundary is cooperative rather than kernel-enforced,
[SECURITY.md](SECURITY.md) says so and names the bypass.

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
| [docs/INSTALL.md](docs/INSTALL.md) | install on Linux, WSL2 and ARM boards, from source |
| [docs/DOCKER-COMPAT.md](docs/DOCKER-COMPAT.md) | what of Docker works, what does not, and where it differs |
| [docs/RESOURCES.md](docs/RESOURCES.md) · [docs/CONFIG.md](docs/CONFIG.md) · [docs/STORAGE.md](docs/STORAGE.md) · [docs/EGRESS.md](docs/EGRESS.md) | the two-verb model, the `kern.toml` schema, volumes and egress |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) · [SECURITY.md](SECURITY.md) · [OPEN_ITEMS.md](OPEN_ITEMS.md) | the threat model (structured, then per-mechanism), and the known gaps |
| [BENCHMARKS.md](BENCHMARKS.md) · [EDGE.md](EDGE.md) | measurements, and running on a Pi, Jetson or UNO Q |
| [examples/](examples/) · [blog/](blog/) | ninety runnable scripts, and longer write-ups |
| [bindings/python/README.md](bindings/python/README.md) · [bindings/node/README.md](bindings/node/README.md) | the `kern-sandbox` SDK: embed kern in Python or Node |

## Status

**The core is done. Everything above works today:** 848 Rust, 327 Python and 61 Node tests,
clippy-clean, `cargo-deny`-clean, on real hardware: Linux, WSL2, Raspberry Pi 5, Jetson Orin Nano,
Arduino UNO Q. **v0.7.0 is the first published release.** The CLI and config surface can still
change, always called out in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Issues and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) has the workflow and the
gates; contributions are covered by the [CLA](CLA.md).

## Maintainer

Alessandro Polito, [@realexhub](https://github.com/realexhub), Italy. Commits up to and including
v0.7.0 carry [@getkerndev](https://github.com/getkerndev), the account the project was published
from.

**The commits are not signed; the release TAG is.** That is what to verify:
`git verify-tag v0.7.0` against the key in [provenance/](provenance/), whose fingerprint is in
[SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [TRADEMARK.md](TRADEMARK.md).
