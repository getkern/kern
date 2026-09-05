<div align="center">

<img src="assets/brand/kern-logo.png" width="260" alt="kern">

**kern:** A fast, rootless sandbox and virtual resource runtime for any workload, including untrusted and AI-generated code.

**A real, kernel-enforced container in ~3.5 ms, out of one static binary with no daemon.**

<p align="center">
  <img src="assets/kern-demo.gif" width="720" alt="Terminal: 'kern box app --image alpine -- echo hello from a real container' prints the greeting, then reports that kern started in 3.5 ms against docker run's 297 ms. A real OCI image, rootless, a static binary, no daemon, on an Intel i7-14700KF, Linux 7.0.">
</p>

<sub>3.5 ms rounds a measured 3.4 up: a box **from an OCI image**, on one machine and one workload. A **bare box** is ~2.4 ms. Both numbers appear below, and [BENCHMARKS.md](BENCHMARKS.md) is how they were measured</sub>

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

<sub>No native Windows: use WSL2. No native macOS: run it in a Linux VM. [Install](#install).</sub>

---

## What kern is

**One binary that manages resources, of which isolation is the first.** That is why there is no
single row for kern in a comparison table: it is a container runtime, a sandbox, a resource slicer
and a stack runner at once, in one static binary with no daemon.

- **A real container.** Real OCI images: `pull`, `build` from a Dockerfile, `commit`, `push`,
  `save`/`load`. A box from an image starts in ~3.4 ms.
- **The sandbox an AI agent can afford to use on every call.** An agent's tool-call, a model's
  generated snippet, a notebook cell, a CI step: code that runs before anyone reads it. kern gives
  each call **its own box in ~2.4 ms** and throws it away after, which is cheap enough that "one
  sandbox per tool-call" stops being a design you argue about and becomes the default. Network off,
  memory and PID caps the kernel enforces, capabilities dropped, a deny-by-default seccomp allowlist,
  and the timeout applied from OUTSIDE the box, so code that hangs cannot outlive it.
  <br>**Your loop reads a field, not a stack trace.** A timeout, an OOM-kill, a blocked syscall and a
  command that was not in the image each arrive as a typed `fault` on the result, beside stdout and
  the exit code. The agent branches on a value and keeps going, instead of parsing text to work out
  whether the sandbox stopped the run or the code did.
  <br>Python, Node, LangChain and MCP: [below](#run-an-agents-code-python-node-mcp). For code written
  to attack you rather than merely unread, read [What kern is not](#what-kern-is-not) first: the
  boundary is the Linux kernel.
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
  <img src="assets/demo.svg" width="780" alt="Terminal demo: a kern.toml defines reusable vcpu/vdisk/vgpio (device) profiles; 'kern box train --image alpine vcpu:heavy vdisk:scratch' attaches a 4-vCPU, 8 GB, 2 GB-scratch rootless isolated slice in a few ms (docker run takes ~297 ms); 'kern run vcpu:heavy -- ffmpeg' caps a heavy transcode with no sandbox; 'kern box iot --image alpine vgpio:sensor' exposes only /dev/i2c-1 and nothing else; piping a request into 'kern box fn --image python' runs it in a fresh isolated box per request (serverless style); 'kern compose stack.toml up' brings up a multi-box stack; 'kern top' is the live TUI for boxes, profiles and volumes: CPU, memory, disk and devices, sliced per box, in one static binary, no daemon.">
</p>

## Install

kern needs a Linux kernel with unprivileged user namespaces and cgroup v2. It runs on **Linux, WSL2
and ARM boards** (Raspberry Pi · Jetson · Arduino UNO Q); there is **no native Windows** build, use
WSL2 (kern ships a pre-baked WSL rootfs).

**On a Mac** there is no native build either, and there will not be one: macOS has no namespaces and
no cgroups. kern runs on a Mac **inside a Linux VM** (colima, Lima, OrbStack, UTM, or one you already run), where it is the ordinary Linux kern, same binary and same CLI as your CI box.
Verified on Apple Silicon with an Ubuntu 24.04 guest. Read
[docs/INSTALL.md](docs/INSTALL.md) first: two obstacles are certain there, and the resource caps do
not bite on a default guest.

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

### Two versions, and they move separately

The `kern` binary is versioned by its git tag and `kern-sandbox` by its own release, so the two can
be out of step and it matters which way. **The SDK drives the binary as a subprocess**, so a binding
newer than the binary asks for behaviour the binary does not have yet.

Today `install.sh` gives you the latest **release**, and `pip install kern-sandbox` gives you the
latest **SDK**. If the release predates a fix the SDK relies on, that shows up as behaviour this
README describes and your machine does not do. The [CHANGELOG](CHANGELOG.md) is where the two are
reconciled: an entry names the release it landed in.

To see what you actually have:

```sh
kern --version                                   # the binary; `0.0.0` means you built it from source
python3 -c "import kern_sandbox; print(kern_sandbox.__version__)"
```

One case is worth calling out because it is measured rather than theoretical: `--egress-allow` on a
kernel WITHOUT policy routing (`ip rule list` fails, which is common on ARM boards) needs a binary
newer than **v0.9.0**, or the box starts with a proxy nothing can reach. Everything else in this
README works on v0.9.0.

`kern doctor` tells you whether boxes will run here before you try. Boards, WSL2 and the long form:
[docs/INSTALL.md](docs/INSTALL.md). Common questions (Docker, bubblewrap, youki, E2B, Windows, the
threat model): [docs/FAQ.md](docs/FAQ.md).

## Quickstart

```sh
kern box dev --image alpine -it -- sh       # a shell in a real OCI image
kern box svc --image nginx:alpine -d -p 8080:80    # a service, published
kern run --memory 256M --cpus 0.5 -- ./crunch      # cap a process, no sandbox
kern ps                                     # what runs, with PORTS and HEALTH
kern top                                    # live TUI: boxes, profiles, volumes
kern compose stack.toml up                  # a whole stack, one command
```

Untrusted code, one flag:

```sh
kern box job --image python:3.12-slim --security-profile untrusted -- python3 /w/x.py
```

`--security-profile untrusted` is the seccomp **allowlist** + `--cap-drop ALL` + `--read-only`
in one flag. No network unless you ask, and seccomp is on either way. One runnable example per
thing kern does: [examples/](examples/).

Every read verb also answers in JSON, so nothing has to parse a table:

```sh
kern ps --json | jq '.[] | select(.health == "unhealthy") | .name'
```

## Run an agent's code: Python, Node, MCP

An agent needs somewhere to run what the model just wrote. **[`kern-sandbox`](bindings/python/README.md)**
is that place: a thin, dependency-free wrapper over the `kern` binary, called from your own program.

```sh
pip install kern-sandbox        # PyPI · needs the `kern` binary above, on PATH or $KERN_BIN
npm  install kern-sandbox       # npm  · same
```

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
[docs/MCP.md](docs/MCP.md); and pi's `bash`, `read`, `write`, `edit`, `ls`, `grep` and `find` routed
into a box, with a README that states which half is the kernel's boundary and which is a path check,
in [integrations/pi/](integrations/pi/).

## Stacks

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
kern compose stack.toml up          # or point it at your compose.yaml instead
kern compose stack.toml watch       # rebuild + restart a service when its build context changes
kern compose stack.toml port web 80 # the host address serving that port, read from the running box
```

Both official images start, `web` reaches `db` by service name, and the port is published. A compose
file can also name kern's own things in the spec's extension namespace (`x-kern-vcpu`,
`x-kern-security-profile`) and still run under Docker unchanged, because every other runtime ignores
an `x-` field. A typo inside one is reported rather than dropped.

**One constraint comes with the speed:** a stack is one pod on one network namespace, so two services
cannot both listen on the same container port even when their published ports differ. `up` refuses
the collision by name before starting anything, and `--no-pod` lifts it by giving each service its
own namespace with peers reachable by name.

Official images that drop to a non-root user want `uidmap` and an `/etc/subuid` line, and outbound
pulls want `pasta`; `kern doctor` names either if it is missing. This is the local dev loop, not a
production orchestrator. [docs/DOCKER-COMPAT.md](docs/DOCKER-COMPAT.md)

## Resource profiles

A slice is declared once in `~/.config/kern/kern.toml` and attached by name, to a sandboxed box or a
bare process, with the same token. Three kinds: `vcpu:` (CPU and memory), `vdisk:` (a size-capped
scratch disk) and `vgpio:` (device nodes).

```toml
[[cpu]]                     # the host budget a slice is carved from
id    = "cpu:0"
cores = 8.0

[[vcpu]]                    # 1.5 cores and 512 MiB  ->  attach as  vcpu:heavy
name    = "heavy"
backend = "cpu:0"
cpus    = 1.5
memory  = "512m"
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

## kern vs Docker vs Podman

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
| `docker-compose.yml` | yes, read as-is ([one caveat](#stacks)) | yes | partial |
| Overlay networks, Swarm, CRI | **no** | yes | partial |
| GPU | on the roadmap | yes | yes |

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
**allowlist** by default (moby's own default filter minus kern's 35 escape syscalls, which stay
hard-killed; a syscall outside the vetted set returns `ENOSYS`, and the wider denylist is the opt-out
via `KERN_SECCOMP=denylist`), cgroup v2 limits (`--require-limits` refuses to start unless they bind),
and a deny-by-default `/dev`. Where a boundary is cooperative rather than kernel-enforced,
[SECURITY.md](SECURITY.md) says so and names the bypass.

You do not have to take it on trust: [pentest/](pentest/) holds five adversarial suites that assert
those boundaries against the kernel rather than against kern's own reporting, and they run without a
registry account or a network.

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

**The core is done and the CLI is frozen.** 1059 Rust, 458 Python and 93 Node tests, clippy-clean and
`cargo-deny`-clean, on Linux, WSL2, Raspberry Pi 5, Jetson Orin Nano and Arduino UNO Q.

Scripts written against the CLI keep working: no verb, no flag and no `--json` field changes meaning
inside a patch release. **v0.9.0 changes one exit code**, which is why it is a minor bump and not a
patch: `kern box --plan` now exits 1 when a profile it named cannot attach, where it used to print the
refusal and exit 0. A script that read the preview is unaffected; one that chained on `&&` now stops
where it should have. That, and everything else in the release, is in the
[0.9.0 notes](CHANGELOG.md#v090---2026-09-04).

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
