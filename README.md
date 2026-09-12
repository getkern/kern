<div align="center">

<img src="assets/brand/kern-logo.png" width="260" alt="kern">

**kern:** a fast, rootless sandbox and virtual resource runtime. Run any workload in a real container, including an agent's tool-call or AI-generated code.

**A real, kernel-enforced container in ~3.5 ms, out of one static binary with no daemon.**

<p align="center">
  <img src="assets/kern-demo.gif" width="720" alt="Terminal: 'kern box app --image alpine -- echo hello from a real container' prints the greeting, then reports that kern started in 3.5 ms. A real OCI image, rootless, a static binary, no daemon, on an Intel i7-14700KF, Linux 7.0.">
</p>

<sub>**0 RAM at rest** · no daemon, no socket, nothing to start · one static binary, `libc` its only Rust dependency</sub>

[![CI](https://github.com/getkern/kern/actions/workflows/ci.yml/badge.svg)](https://github.com/getkern/kern/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Runs on](https://img.shields.io/badge/runs%20on-Linux%20%C2%B7%20ARM%20boards%20%C2%B7%20Windows%20via%20WSL2%20%C2%B7%20macOS%20via%20a%20Linux%20VM-informational.svg)](docs/INSTALL.md)

</div>

```sh
# install the release binary (static, checksum-verified by the script)
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh

# a throwaway shell in a real OCI image: rootless, kernel-enforced, a few ms
kern box dev --image alpine -it -- sh
```

```powershell
# Windows: the same binary under WSL2, and the script sets WSL2 up for you
irm https://raw.githubusercontent.com/getkern/kern/main/install.ps1 | iex
```

```sh
# macOS, two steps: a Linux VM, then kern inside it
brew install colima && colima start && colima ssh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh   # inside the VM
```

<sub>Runs on Linux and ARM boards directly, on Windows through WSL2 and on a Mac through colima, Lima or OrbStack: the same binary and the same CLI under a Linux kernel. [Install](#install).</sub>

---

## What kern is

**One binary that manages resources, of which isolation is the first.** That is why there is no
single row for kern in a comparison table: it is a container runtime, a sandbox, a resource slicer
and a stack runner at once, in one static binary with no daemon.

- **A real container.** Real OCI images: `pull`, `build` from a Dockerfile, `commit`, `push`,
  `save`/`load`. A box from an image starts in ~3.4 ms.
- **Sandbox an AI agent, one container per tool-call.** The command it just decided to run, the
  snippet the model just wrote, a notebook cell, a CI step. kern starts a box, runs it, deletes it,
  fast enough that per-call isolation is the default. Network off unless you ask, memory and PID
  caps the kernel enforces, capabilities dropped, seccomp deny-by-default, timeout applied from the
  outside.
  <br>**Typed faults, not stack archaeology.** Timeout, OOM-kill, blocked syscall, missing command:
  each returned next to stdout and the exit code. Branch on it and keep going.
  <br>**One binary, no daemon.** Wire it from Python, Node, LangChain, or any MCP client
  [below](#run-an-agents-code-python-node-langchain-mcp-pi). And
  [what it is not](#what-kern-is-not), because the boundary is the Linux kernel.
- **Rootless, always.** User, PID, mount, network, UTS and IPC namespaces, an overlay or
  read-only root pivoted in, a deny-by-default seccomp allowlist and cgroup v2 limits. One flag,
  `--security-profile untrusted`, is the whole hardened bundle.
- **Resource profiles, not just isolation.** CPU (`vcpu:`), memory, disk (`vdisk:`) and devices
  (`vgpio:`), declared once in a `kern.toml` and attached by name. `kern run` applies the same caps
  to a process on the host, with no sandbox at all, plus `--landlock-rw <path>` to confine that
  process's writes with the kernel's own LSM. [docs/RESOURCES.md](docs/RESOURCES.md)
- **Stacks, in kern's own format or in the one you already have.** `kern compose <file> up` takes a
  `stack.toml` (`[box.NAME]` tables, with the resource profiles above) or a `docker-compose.yml`, with
  no conversion step. One stack to one pod, services reaching each other by name.
- **The tools around them.** `ps`, `logs`, `exec`, `stats`, `inspect`, `wait`, `top` (a live TUI),
  `doctor`. The Python binding also plugs into LangChain twice: as a code tool, and as an execution
  policy for its shell middleware.

Its entire Rust dependency tree is `libc`: JSON and OCI manifests are parsed by hand, and `pull`
shells out to the `curl` and `tar` already on the machine rather than linking a TLS stack.

<p align="center">
  <img src="assets/demo.svg" width="780" alt="Terminal demo: a kern.toml defines reusable vcpu/vdisk/vgpio (device) profiles; 'kern box train --image alpine vcpu:heavy vdisk:scratch' attaches a 4-vCPU, 8 GB, 2 GB-scratch rootless isolated slice in a few ms; 'kern run vcpu:heavy -- ffmpeg' caps a heavy transcode with no sandbox; 'kern box iot --image alpine vgpio:sensor' exposes only /dev/i2c-1 and nothing else; piping a request into 'kern box fn --image python' runs it in a fresh isolated box per request (serverless style); 'kern compose stack.toml up' brings up a multi-box stack; 'kern top' is the live TUI for boxes, profiles and volumes: CPU, memory, disk and devices, sliced per box, in one static binary, no daemon.">
</p>

## Install

### The binary

A box is made of Linux kernel features, so kern runs where there is a Linux kernel: **Linux and ARM
boards** (Raspberry Pi · Jetson · Arduino UNO Q) directly, **Windows through WSL2** with a pre-baked
rootfs and an installer that sets WSL2 up for you, and **a Mac inside a Linux VM** (colima, Lima,
OrbStack, UTM), where it is the ordinary Linux kern: same binary, same CLI, same behaviour as your CI
box.

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

One static file, no toolchain. The script picks `x86_64` or `aarch64`, installs to `~/.local/bin`,
and refuses a download whose SHA256 does not match. From source instead, the whole dependency tree is
one crate:

```sh
cargo install --git https://github.com/getkern/kern getkern --locked
```

Debian and Ubuntu, Fedora, the RHEL family (Rocky, CentOS Stream), openSUSE, WSL2, and ARM boards:
any distribution with unprivileged user namespaces and cgroup v2. Each release runs the full suite on
those, in real VMs and on the boards, before it ships.

[docs/INSTALL.md](docs/INSTALL.md) has the rest: verifying the checksum by hand, `KERN_INSTALL_DIR`,
the Windows and Mac guests step by step, and what the resource caps do on a default VM.

### The SDK, to call kern from Python or Node

`kern-sandbox` ([PyPI](https://pypi.org/project/kern-sandbox/),
[npm](https://www.npmjs.com/package/kern-sandbox)) needs the binary above, so install that first:

```sh
pip install kern-sandbox
npm  install kern-sandbox
```

Both packages are the wrapper alone: they find `kern` on your PATH, or wherever `$KERN_BIN` points.
The two are released on their own clocks, so check what you have when a call does something the
changelog says it should not:

```sh
kern --version
python3 -c "import kern_sandbox; print(kern_sandbox.__version__)"
```

What it is for is [further down](#run-an-agents-code-python-node-langchain-mcp-pi); the
[changelog](CHANGELOG.md) names the release each fix landed in.

## Quickstart

```sh
kern box dev --image alpine -it -- sh                  # a shell in a real OCI image
kern box svc --image nginx:alpine -d -p 8080:80        # a service, published
kern box job --image python:3.12-slim --security-profile untrusted -- python3 /w/x.py
kern compose stack.toml up                             # a whole stack, one command
```

`--security-profile untrusted` is the seccomp allowlist plus `--cap-drop ALL` plus `--read-only`, in
one flag. `kern ps` and `kern top` show what is running; every verb that lists or inspects also answers
`--json`, so nothing has to parse a table. One runnable example per thing kern does:
[examples/](examples/).

## Run an agent's code: Python, Node, LangChain, MCP, pi

The bindings are how **your program** calls kern. The code **inside** the box can be in any language,
because the box is an OCI image: Python, Node, Go and Rust all run with the same command and a
different `--image`, and so does anything else that ships one.


An agent needs somewhere to run what the model just wrote. **`kern-sandbox`** is that place: a thin,
dependency-free wrapper over the `kern` binary, called from your own program.
[Installed above](#the-sdk-to-call-kern-from-python-or-node); the API is in
[bindings/python/](bindings/python/README.md) and [bindings/node/](bindings/node/README.md).

```python
from kern_sandbox import run_code

r = run_code("import platform; print(platform.python_version())")
print(r.stdout)          # ran in a fresh box; a timeout / OOM / blocked escape is data on r.fault
```

Every call is a fresh isolated box: network off, memory and pid caps, capabilities dropped, output
bounded, and a timeout the binding enforces itself. A timeout, an OOM-kill or a blocked syscall comes
back as a typed `fault` on the result rather than as an exception. `code_stderr` is that result's
stderr without kern's own notes, which is what belongs in a context window.

It also ships **`kern-mcp`**, a dependency-free stdio server that gives Claude Desktop or Cursor a
local code interpreter, and the server is stdio, so the same one line points a client at a box on
another machine.

```json
{ "mcpServers": { "kern": { "command": "kern-mcp" } } }
```

The rest is on the pages that own it, none of it repeated here: the full API, the rich-result capture,
prewarming and the LangChain integration in
[bindings/python/README.md](bindings/python/README.md) and
[bindings/node/README.md](bindings/node/README.md); every `KERN_MCP_*` variable and the remote form in
[docs/MCP.md](docs/MCP.md); and, for the [pi](https://github.com/earendil-works/pi) coding agent,
[`kern-pi`](https://www.npmjs.com/package/kern-pi) routing its `bash`, `read`, `write`, `edit`, `ls`,
`grep` and `find` into a box, with a README that states which half is the kernel's boundary and which
is a path check, in [integrations/pi/](integrations/pi/).

## Run a whole stack: your `docker-compose.yml`, unchanged

One file, one command. kern reads its own format, and it reads the `docker-compose.yml` you already
have, unchanged.

```toml
# stack.toml - one table per service, keys spelled like the `kern box` flags
[box.db]
image = "postgres:alpine"
env   = ["POSTGRES_PASSWORD=secret", "POSTGRES_DB=app"]

[box.web]
image      = "adminer"
ports      = ["8080:8080"]
depends_on = ["db"]
```

```sh
kern compose stack.toml up            # or point it at your compose.yaml instead
kern compose stack.toml ps            # what is running, and what each service publishes
kern compose stack.toml port web 8080 # the host address serving that port, read from the running box
```

`kern compose <file> watch` is the fourth one, left out of the block above because it needs a service
with a `build:` context and the file here has none: pointed at a stack that builds, it rebuilds and
restarts that one service when its context changes.

Both official images start, `web` reaches `db` by service name, and the port is published. A compose
file can also name kern's own things in the spec's extension namespace (`x-kern-vcpu`,
`x-kern-security-profile`) and still run anywhere else unchanged, because the spec has
every runtime ignore an `x-` field. A typo inside one is reported rather than dropped.

**Each service gets its own network namespace, and they meet on a bridge,** which is the arrangement
a Docker user already has: a service's `127.0.0.1` is its own, two services may listen on the same
container port, and peers reach each other by name at their addresses. A single-service stack keeps
one namespace, because there is nobody to separate it from. When `networks:` leave two services with
nothing in common, kern honours that separation with a namespace per service and no bridge between
them, announcing what it costs (a relay hop between the peers that do share a network). `--pod`
forces one shared namespace, which is faster and refuses a file it cannot express rather than running
it with the separation dropped; `--bridge` and `--no-pod` ask for the other two explicitly.

Official images that drop to a non-root user want `uidmap` and an `/etc/subuid` line, and outbound
pulls want `pasta`; `kern doctor` names either if it is missing. This is the local dev loop, not a
production orchestrator. [docs/DOCKER-COMPAT.md](docs/DOCKER-COMPAT.md)

**On a server you reached over `ssh`, run kern inside a scope once.** An ordinary ssh session sits
outside the systemd user manager on every distribution we measured, and a box's caps live in a cgroup
that session cannot write into: the stack comes up and is capped correctly, but `kern compose … exec`
refuses, because entering the box would step outside those caps. One line fixes it for the whole
session and keeps the caps enforced:

```sh
systemd-run --user --scope bash     # then run kern in that shell
```

`kern doctor` reports which cap path a host takes. On Ubuntu 23.10 and newer there is one more thing
to do first, once, with root: see [docs/INSTALL.md](docs/INSTALL.md#requirements-and-limitations).

## Resource profiles

A slice is declared once in `~/.config/kern/kern.toml` and attached by name, to a sandboxed box or a
bare process, with the same token. Three kinds: `vcpu:` (CPU and memory), `vdisk:` (a size-capped
scratch disk) and `vgpio:` (device nodes).

```toml
# ~/.config/kern/kern.toml - declared once, attached by name
[[cpu]]                     # the host budget a slice is carved from
id    = "cpu:0"
cores = 8.0

[[vcpu]]                    # 1.5 cores and 512 MiB  ->  attach as  vcpu:heavy
name    = "heavy"
backend = "cpu:0"
cpus    = 1.5
memory  = "512m"

[[disk]]                    # the physical disk a scratch slice is carved from
id   = "data"
path = "/var/lib/kern/volumes"

[[vdisk]]                   # 2 GiB of scratch  ->  attach as  vdisk:scratch
name    = "scratch"
backend = "data"
size    = "2g"
```

```sh
kern validate ~/.config/kern/kern.toml       # check it before anything runs
kern box train --image alpine vcpu:heavy vdisk:scratch -- ./train.sh
kern run vcpu:heavy -- ./train.sh            # the same slice, no sandbox
```

Profiles compose, an explicit flag beats a profile's own value, and every key is spelled like its CLI
flag. A backend naming no declared pool is refused when the config is read, not when the box runs.

Two things this says out loud rather than letting you assume. A `vdisk:` is a RAM-backed tmpfs when
kern runs rootless, whatever its backend says, and an ext4-on-loop image with a real quota when it
runs privileged; kern reports which one you got, and the size cap binds either way. And **`vgpio:` is
chip-granular, not per-line**: asking for `pins` binds the whole `/dev/gpiochipN`, which exposes every
line of that controller, so `pins = [17]` is cooperative metadata rather than a boundary. Naming a
device node grants that node and nothing else. [docs/RESOURCES.md](docs/RESOURCES.md)

## What a container costs, and what kern does not have

All three columns measured on one host, same workload, same day: an Intel i7-14700KF running Linux
7.0.0, with the method in [BENCHMARKS.md](BENCHMARKS.md).

| | kern | Docker | Podman |
|---|---|---|---|
| Daemon | **no** | yes (`dockerd` + `containerd`) | no |
| Rootless | **yes**, always | opt-in | yes |
| Cold start, bare box | **~2.4 ms** | ~288 ms | ~297 ms |
| Cold start, from an OCI image | **~3.4 ms** | ~288 ms | ~297 ms |
| Stop a service (init handles SIGTERM) | **~2.3 ms** | ~162 ms | ~194 ms |
| Resident memory, nothing running | **0** | 154 to 160 MB | 0 |
| Footprint | **one static binary** | daemon stack | multi-binary install |
| OCI images, pull / build / push | yes | yes | yes |
| `docker-compose.yml` | yes, read as-is ([how the network is wired](#run-a-whole-stack-your-docker-composeyml-unchanged)) | yes | partial |
| Overlay networks, Swarm, CRI | **no** | yes | partial |
| GPU passed into the container | no | yes | yes |

## Performance

Intel i7-14700KF, Linux 7.0.0, the release binary, alternating batches on an idle machine.

| | kern | bubblewrap | runc | podman | docker |
|---|---:|---:|---:|---:|---:|
| Cold start (bare box) | **~2.4 ms** | ~2.6 ms | ~13.1 ms | ~297 ms | ~288 ms |
| 200 boxes in parallel | **~0.11 s** | ~0.13 s | ~0.29 s | ~43.1 s | ~16.7 s |

kern is ahead of bubblewrap by about 9%, and that gap is small enough that it only holds up under a
method: **[BENCHMARKS.md](BENCHMARKS.md)** has the alternation, the 240 batches, the aarch64 boards,
why the release binary and not a local build, and every caveat. The gap that means something is the
one to the engines, two orders of magnitude above.

## Security

Namespaces, a `pivot_root`, 16 dangerous capabilities dropped before exec, an always-on seccomp
**allowlist** (moby's default filter minus kern's 35 escape syscalls, which stay hard-killed; anything
outside the vetted set returns `ENOSYS`), cgroup v2 limits that
`--require-limits` refuses to start without, and a deny-by-default `/dev`. Where a boundary is
cooperative rather than kernel-enforced, [SECURITY.md](SECURITY.md) says so and names the bypass.

You do not have to take it on trust. [pentest/](pentest/) holds five adversarial suites that assert
those boundaries against the kernel rather than against kern's own reporting, with no registry
account and no network:

```sh
sh pentest/run-with-local-registry.sh ./target/release/kern pentest/pentest-ports.sh
```

Report a vulnerability privately via GitHub Security Advisories or hello@getkern.dev.

## Documentation

| Document | What is in it |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | install on Linux, WSL2 and ARM boards, from source |
| [docs/MCP.md](docs/MCP.md) | the MCP server: tools, every `KERN_MCP_*` variable, and running it over ssh or WSL so the sandbox sits on another machine |
| [docs/DOCKER-COMPAT.md](docs/DOCKER-COMPAT.md) | what of Docker works, what does not, and where it differs |
| [docs/RESOURCES.md](docs/RESOURCES.md) · [docs/CONFIG.md](docs/CONFIG.md) · [docs/EGRESS.md](docs/EGRESS.md) | the two-verb model with volumes and vdisks, the `kern.toml` schema, and egress |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) · [SECURITY.md](SECURITY.md) · [docs/GPU-CLAIMS.md](docs/GPU-CLAIMS.md) | the threat model (structured, then per-mechanism), and why a userspace VRAM cap is not a boundary |
| [ROADMAP.md](ROADMAP.md) | what is missing or unmeasured today, and what may come |
| [BENCHMARKS.md](BENCHMARKS.md) · [EDGE.md](EDGE.md) | measurements, and running on a Pi, Jetson or UNO Q |
| [examples/](examples/) · [blog/](blog/) | 92 runnable scripts, and longer write-ups |
| [bindings/python/README.md](bindings/python/README.md) · [bindings/node/README.md](bindings/node/README.md) | the `kern-sandbox` SDK: embed kern in Python or Node |

## Status

**The core is done and the CLI is frozen.** 1319 Rust, 484 Python and 95 Node tests, clippy-clean and
`cargo-deny`-clean, on Linux, WSL2, Raspberry Pi 5, Jetson Orin Nano and Arduino UNO Q.

A script written against the CLI keeps working: no verb, flag or `--json` field changes meaning
inside a patch release. What changed in each one is in the [changelog](CHANGELOG.md).

## What kern is not

- **Not a hypervisor.** The boundary is the Linux kernel, so a kernel privilege-escalation bug is an
  escape. kern is for code you chose to run and whose blast radius you own, not for hostile code from
  strangers on a kernel you serve other tenants from.
- **Not free of the userns trade.** Its isolation is built on an unprivileged user namespace, a
  fertile source of kernel LPE bugs. [SECURITY.md](SECURITY.md) says so before any claim.
- **Not a wall around what you mount in.** `-v $HOME:/host` gives the box your home directory.
  `--net host` and `--privileged` are opt-outs by name.
- **Not a Docker Engine reimplementation.** The *formats*, not the API: no overlay networks, no
  plugins, no Swarm. [docs/DOCKER-COMPAT.md](docs/DOCKER-COMPAT.md)
- **Not a Kubernetes runtime.** No CRI. Use containerd or CRI-O.
- **Not shipping GPU slices.** On the [roadmap](ROADMAP.md). `kern doctor` reports what a VRAM cap
  would be worth per GPU; on consumer hardware that is a cooperative quota,
  NOT a boundary against malicious code. Nothing intercepts a driver call and nothing caps a GPU.

Known gaps: [ROADMAP.md](ROADMAP.md#known-gaps-and-what-would-settle-them).

## Contributing

Issues and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) has the workflow and the
gates; contributions are covered by the [CLA](CLA.md).

## Maintainer

Alessandro Polito, [@realexhub](https://github.com/realexhub), Italy. Earlier commits carry
[@getkerndev](https://github.com/getkerndev), the account the project was published from.

## License

Apache-2.0. See [LICENSE](LICENSE) and [TRADEMARK.md](TRADEMARK.md).
