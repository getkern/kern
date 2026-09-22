<div align="center">

<img src="https://raw.githubusercontent.com/getkern/kern/main/assets/brand/kern-logo.png" width="220" alt="kern">

# Kern Sandbox

**Your model writes the code. This runs it where it cannot touch your machine.**

[![PyPI](https://img.shields.io/pypi/v/kern-sandbox?label=PyPI&color=0b7285)](https://pypi.org/project/kern-sandbox/)
[![npm](https://img.shields.io/npm/v/kern-sandbox?label=npm&color=0b7285)](https://www.npmjs.com/package/kern-sandbox)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-0b7285.svg)](https://pypi.org/project/kern-sandbox/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/getkern/kern/blob/main/LICENSE)

<sub>rootless · no daemon · no socket · no VM · no cloud · no account</sub>

<sub>**Works with** MCP clients · LangChain · pi · Python and Node</sub>

**[The runtime](https://github.com/getkern/kern)** ·
**[MCP server](https://github.com/getkern/kern/blob/main/docs/MCP.md)** ·
**[Security model](https://github.com/getkern/kern/blob/main/SECURITY.md)** ·
**[Benchmarks](https://github.com/getkern/kern/blob/main/BENCHMARKS.md)**

</div>

An agent's tool-call, a generated snippet, a notebook cell, a CI step: it arrives, you run it, and
nobody has read it first.

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

<p align="center">
  <img src="https://raw.githubusercontent.com/getkern/kern/main/assets/kern-sandbox-demo.gif" width="860" alt="A Python session: run_code returns ('4950', None); the same call on an infinite loop with timeout_s=3 returns fault.type 'timeout' and exit 137; and a 400 MiB allocation under memory_mb=128 returns 'oom' and 137. One box per call, no network, caps and a deadline, gone when it returns.">
</p>

`docker run` gives you exit 137 and leaves you to guess whether that was your timeout, the OOM killer
or something else. This tells you. Every row was run:

| the code | `fault.type` | `exit_code` |
|---|---|---|
| `print(sum(range(100)))` | `None` | 0 |
| `while True: pass`, `timeout_s=3` | **`timeout`** | 137 |
| `bytearray(400*1024*1024)`, `memory_mb=128` | **`oom`** | 137 |
| `urlopen(...)`, network off | `None` | 1 |

The last row is the one a loop gets wrong: the network was off, so the **code** raised and the
sandbox did nothing. `fault` is read from a pipe kern writes rather than from stdout, so code that
prints `[exit 0]` cannot fake it. Also `killed`, `escape_blocked`, `exec_failed`, `startup_failed`.

## Works with

| | |
|---|---|
| **Any MCP client** | Cursor, Claude Code, Claude Desktop, LM Studio, Zed, Windsurf. The package ships `kern-mcp`, a dependency-free stdio server: the model writes code, kern runs it here, charts come back as images it can see. Per-client config in [docs/MCP.md](https://github.com/getkern/kern/blob/main/docs/MCP.md) |
| **LangChain** | `kern_code_tool()` is a `StructuredTool` your agent can call, and a sandbox fault comes back labelled for the model. There is a shell execution policy too: [LANGCHAIN-SHELL.md](https://github.com/getkern/kern/blob/main/bindings/python/LANGCHAIN-SHELL.md) |
| **[pi](https://github.com/earendil-works/pi)** | [`kern-pi`](https://www.npmjs.com/package/kern-pi) routes its `bash`, `read`, `write`, `edit`, `ls`, `grep` and `find` into a box, your working directory at `/workspace`: [integrations/pi](https://github.com/getkern/kern/tree/main/integrations/pi) |
| **Python and Node** | the same API on both registries: `pip install kern-sandbox` and [`npm i kern-sandbox`](https://www.npmjs.com/package/kern-sandbox) |

```json
{ "mcpServers": { "kern": { "command": "uvx", "args": ["--from", "kern-sandbox", "kern-mcp"] } } }
```

A client spawns the server from **its own** PATH, so a venv is invisible to it: `uvx` above installs
nothing, `pipx install kern-sandbox` is the other way. From macOS or Windows the client is one hop
away and it is still one line (`"command": "wsl"`, or `"command": "ssh"` to a VM or a board).

## Safe by default

A bare `Sandbox()` has no network, no host mounts, seccomp on, capabilities dropped and a
**mandatory** timeout. Every relaxation is a named argument (`image`, `setup`, `memory_mb`, `cpus`,
`timeout_s`, `network`, `mounts`, `workspace`, `prewarm`, and a dozen more).

Two that have surprised people, both measured:

- **Mounts over sensitive sources are refused even if you ask**: the host's own directories, anything
  with `.ssh`/`.aws`/`.kube` in its path, and kern's own state. No opt-out. Mount a copy.
- **`network=True` includes the host's loopback**, where unauthenticated services live. A test read
  the host's SSH banner off `127.0.0.1:22`. `egress_allow` is the middle setting and is route-level.

## How fast

<p align="center">
  <img src="https://raw.githubusercontent.com/getkern/kern/main/assets/kern-sandbox-vs.png" width="880" alt="Horizontal bar chart on a log scale, milliseconds per call: kern-sandbox with a prewarm pool 0.7 ms, kern-sandbox 14.5 ms, llm-sandbox with its session kept alive 77 ms, podman run --rm 286 ms, docker run --rm 292.8 ms, and Docker Sandboxes (sbx) into an already running sandbox 421 ms. Measured on an Intel i7-14700KF, Linux 7.0.0, rootless, 2026-09-21.">
</p>

<sub>**The number to quote is 14.5 ms, the default path**, one tool-call end to end on an
i7-14700KF. The box itself is 4.9 ms; most of the rest is CPython starting inside, which is a Python
cost. The 0.7 ms bar is a prewarm burst and falls back to 14.5 when the pool cannot keep up. And
`print(1)` flatters every runtime here: `import json,re` measures 47.3 ms against 320.8, 7x rather
than 20x. Measure your own machine and take the p50.</sub>

## Compared to what you are probably doing

| | |
|---|---|
| **a venv** | isolates imports, not the process: the code still has your files, your keys and your network |
| **`docker run` per call** | the same idea with a daemon and a socket in front of it, at 292.8 ms against 14.5 ms on the same machine. That socket is root-equivalent |
| **bubblewrap, nsjail** | the building blocks kern uses. They do not resolve images, do not apply cgroup caps, and give you no verdict: you get an exit code and work out the rest |
| **a microVM (Firecracker, Kata) or gVisor** | a stronger boundary than this one, and the right answer when the code is actively hostile. It costs what a machine costs: about half a second per command |
| **E2B, Modal, Daytona** | the same job in someone else's cloud, with an account and your code leaving the machine |

## Current limitations

- **Not a boundary against deliberately hostile code.** This is namespaces, cgroups and seccomp: a
  kernel boundary, for your own or semi-trusted code. If the code is actively hostile, or belongs to
  someone else, use a microVM (Firecracker, Kata) or gVisor. That is a different job and costs what a
  machine costs: about half a second per command there against 14.5 ms here. Full statement in
  [SECURITY.md](https://github.com/getkern/kern/blob/main/SECURITY.md).
- **Linux only.** Windows works through WSL2; on a Mac the package installs and refuses to run,
  because macOS has no namespaces and no cgroups. Use a Linux VM.
- **The caps bind only where your host delegates a cgroup.** `kern doctor` says whether yours does,
  and `require_limits=True` turns a silent no into a refusal to start.
- **Nothing bounds the workspace.** It is a host directory, so a job can fill your disk. Point
  `workspace=` at a filesystem you have sized.
- **No `--user`**, so an image that refuses to run as root (postgres, some databases) has no answer
  here yet.
- **`pip install kern-sandbox` does not install the sandbox.** It drives a `kern` binary on `PATH` or
  in `$KERN_BIN`, a second thing to keep current. If a verdict looks wrong, print `kern --version`.

## More

Charts and mime-typed results without a Jupyter kernel, the full API, `kernel()` for a warm
interpreter, snapshots, and the measured sharp edges:
[SANDBOX-NOTES.md](https://github.com/getkern/kern/blob/main/bindings/python/SANDBOX-NOTES.md).

Requires unprivileged user namespaces and cgroup v2, and Python 3.9+:
[install notes](https://github.com/getkern/kern/blob/main/docs/INSTALL.md). Apache-2.0.
