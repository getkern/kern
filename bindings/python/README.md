<div align="center">

<img src="https://raw.githubusercontent.com/getkern/kern/main/assets/brand/kern-logo.png" width="220" alt="kern">

# Kern Sandbox

**Run AI-generated code in a container, not in your home directory.**

[![PyPI](https://img.shields.io/pypi/v/kern-sandbox?label=PyPI&color=0b7285)](https://pypi.org/project/kern-sandbox/)
[![npm](https://img.shields.io/npm/v/kern-sandbox?label=npm&color=0b7285)](https://www.npmjs.com/package/kern-sandbox)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-0b7285.svg)](https://pypi.org/project/kern-sandbox/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/getkern/kern/blob/main/LICENSE)

<sub>rootless · no daemon · no socket · no VM · no cloud · no account</sub>

<sub>**Works with** any MCP client (Cursor · Claude Code · Claude Desktop · LM Studio · Zed · Windsurf) · LangChain · [pi](https://github.com/earendil-works/pi)</sub>

**[The runtime](https://github.com/getkern/kern)** ·
**[MCP server](https://github.com/getkern/kern/blob/main/docs/MCP.md)** ·
**[Security model](https://github.com/getkern/kern/blob/main/SECURITY.md)** ·
**[Benchmarks](https://github.com/getkern/kern/blob/main/BENCHMARKS.md)**

</div>

An agent's tool-call, a generated snippet, a notebook cell: code that runs before anyone has read it
should not run next to your SSH keys.

```bash
# the runtime: one static binary, checksum-verified by the script
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh

# if the venv line fails, your distribution ships it separately:
#     sudo apt install python3-venv
python3 -m venv .venv && . .venv/bin/activate
pip install kern-sandbox
```

```python
import kern_sandbox as kern

r = kern.run_code("print(sum(range(100)))")
print(r.stdout, r.fault)   # 4950  None
```

That call started a container from an OCI image, ran the code with **no network**, memory and PID
caps and a deadline applied from outside, and threw the container away before returning. The next
call gets a new one. Two things, not one: the isolation is the binary's, this package is the API in
front of it.

## The result says who stopped the run

A timeout, an OOM-kill or a blocked syscall arrives as a **typed field**, so your loop branches on a
value instead of parsing a traceback.

<p align="center">
  <img src="https://raw.githubusercontent.com/getkern/kern/main/assets/kern-sandbox-faults.png" width="860" alt="A Python session: run_code returns ('4950', 0, None); a call with timeout_s=3 returns fault.type 'timeout' and exit 137; a call allocating 400 MB under memory_mb=128 returns 'oom' and 137; and a call that opens a URL with the network off returns fault None and exit 1, because the code raised and the sandbox did nothing.">
</p>

`fault` is `None` when the **code** failed and the sandbox did nothing, which is the case an agent
loop usually gets wrong. It is set for `timeout`, `oom`, `killed`, `escape_blocked`, `exec_failed`
and `startup_failed`. Read from a pipe kern writes rather than from stdout, so code that prints
`[exit 0]` cannot fake it.

**Branch on `fault`, not on `exit_code`**: a box that never ran exits 1 like a script that did.

## From an MCP client

```json
{ "mcpServers": { "kern": { "command": "uvx", "args": ["--from", "kern-sandbox", "kern-mcp"] } } }
```

The model writes code, kern runs it on your machine, charts come back as images it can see. Works in
Cursor, LM Studio and Claude Desktop. The client spawns the server from **its own** PATH, so a venv
is invisible to it: `uvx` above installs nothing, `pipx install kern-sandbox` is the other way.
Tools, environment variables and transports: [docs/MCP.md](https://github.com/getkern/kern/blob/main/docs/MCP.md).

## Safe by default

A bare `Sandbox()` has no network, no host mounts, seccomp on, capabilities dropped and a
**mandatory** timeout. Every relaxation is a named argument (`image`, `setup`, `memory_mb`, `cpus`,
`timeout_s`, `network`, `mounts`, `workspace`, `prewarm`, and a dozen more).

Three that have surprised people, all measured:

- **Mounts over sensitive sources are refused even if you ask**: the host's own directories, anything
  with `.ssh`/`.aws`/`.kube` in its path, and kern's own state. No opt-out. Mount a copy.
- **`network=True` includes the host's loopback**, where unauthenticated services live. A test read
  the host's SSH banner off `127.0.0.1:22`. `egress_allow` is the middle setting and is route-level.
- **The caps bind only where your host delegates a cgroup.** A desktop session has one; a bare root
  shell or WSL2 without systemd often does not, and there `memory_mb` is accepted and never bites.
  `kern doctor` says which you have; `require_limits=True` makes it fatal instead of quiet.

## How fast

<p align="center">
  <img src="https://raw.githubusercontent.com/getkern/kern/main/assets/kern-sandbox-vs.png" width="880" alt="Horizontal bar chart on a log scale, milliseconds per call: kern-sandbox with a prewarm pool 0.7 ms, kern-sandbox 14.5 ms, llm-sandbox with its session kept alive 77 ms, podman run --rm 286 ms, docker run --rm 292.8 ms, and Docker Sandboxes (sbx) into an already running sandbox 421 ms. Measured on an Intel i7-14700KF, Linux 7.0.0, rootless, 2026-09-21.">
</p>

<sub>**The number to quote is 14.5 ms, the default path**, one tool-call end to end on an
i7-14700KF. The box itself is 4.9 ms; most of the rest is CPython starting inside, which is a Python
cost. The 0.7 ms bar is a prewarm burst and falls back to 14.5 when the pool cannot keep up. And
`print(1)` flatters every runtime here: `import json,re` measures 47.3 ms against 320.8, 7x rather
than 20x. Measure your own machine and take the p50.</sub>

## What it is not

kern is a **kernel-boundary** sandbox for your own or semi-trusted code: namespaces, cgroups and
seccomp, not a microVM. If your code is actively hostile, or belongs to someone else, use a microVM
(Firecracker, Kata) or gVisor. That is a different job and costs what a machine costs: about half a
second per command there against 14.5 ms here. Full statement:
[SECURITY.md](https://github.com/getkern/kern/blob/main/SECURITY.md).

**`pip install kern-sandbox` does not install the sandbox.** It drives a `kern` binary on `PATH` or
in `$KERN_BIN`, and that is a second thing to keep current. If a verdict looks wrong, print
`kern --version` first.

## More

Charts and mime-typed results without a Jupyter kernel, the full API, `kernel()` for a warm
interpreter, snapshots, the LangChain tool and its
[shell policy](https://github.com/getkern/kern/blob/main/bindings/python/LANGCHAIN-SHELL.md), and the
measured sharp edges:
[SANDBOX-NOTES.md](https://github.com/getkern/kern/blob/main/bindings/python/SANDBOX-NOTES.md).
Node and TypeScript get the same API: [`kern-sandbox`](https://www.npmjs.com/package/kern-sandbox).

Linux with unprivileged user namespaces and cgroup v2, Python 3.9+. Windows via WSL2. On a Mac it
installs but cannot run, and says so: use a Linux VM.
[Install notes](https://github.com/getkern/kern/blob/main/docs/INSTALL.md).

Apache-2.0.
