<div align="center">

<img src="https://raw.githubusercontent.com/getkern/kern/main/assets/brand/kern-logo.png" width="220" alt="kern">

# Kern Sandbox

**Your model writes the code. This runs it where it can't reach your files unless you hand them
over.**

<sub>**Works with** Claude Code · Cursor · Claude Desktop · LM Studio · LangChain · pi</sub>

[![CI](https://github.com/getkern/kern/actions/workflows/ci.yml/badge.svg)](https://github.com/getkern/kern/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/getkern/kern/blob/main/LICENSE)
[![PyPI](https://img.shields.io/pypi/v/kern-sandbox?label=pypi%20kern-sandbox&color=blue)](https://pypi.org/project/kern-sandbox/)
[![npm](https://img.shields.io/npm/v/kern-sandbox?label=npm%20kern-sandbox&color=blue)](https://www.npmjs.com/package/kern-sandbox)

<sub>rootless · no daemon · no socket · no VM · no cloud · no account</sub>

**[The runtime](https://github.com/getkern/kern)** ·
**[MCP server](https://github.com/getkern/kern/blob/main/docs/MCP.md)** ·
**[Security model](https://github.com/getkern/kern/blob/main/SECURITY.md)** ·
**[Benchmarks](https://github.com/getkern/kern/blob/main/BENCHMARKS.md)**

</div>

An agent's tool-call, a generated snippet, a notebook cell, a CI step: code nobody has read, run in
a container of its own.

```bash
# if the venv line fails: sudo apt install python3-venv
python3 -m venv .venv && . .venv/bin/activate
pip install -U kern-sandbox   # on Linux x86_64 and aarch64, this brings kern with it
```

On a Mac, run it inside a Linux VM, with your code:
[macOS](https://github.com/getkern/kern/blob/main/docs/INSTALL.md#macos).

```python
import kern_sandbox as kern

r = kern.run_code("print(sum(range(100)))")
print(r.stdout, r.fault)   # 4950  None
```

That ran in a fresh container from an OCI image, with **no network**, memory and PID caps and a
deadline set from outside, and the container was thrown away before the call returned.

- **Cheap enough for every call**: a hundred calls are a hundred containers, nothing left behind.
- **State when you want it**: a `Sandbox()` you keep open shares `/workspace`; `kernel()` keeps one
  warm interpreter where variables carry too.
- **Imports compiled once**: the image's standard library is precompiled the first time you use it
  and mounted READ-ONLY into later boxes, so `import json, re` is about 3x cheaper.
  `pyc_cache=False` turns it off.
- **One install**: the Linux wheels carry the `kern` binary, so the venv has `kern doctor` and
  `kern ps` too.

A hallucinated `rm -rf ~` hits the container's own `/root`, mounted read-only. A step that hangs or
runs out of memory comes back as a value your loop can branch on.

## The basics, one call each

Each block starts from `import kern_sandbox as kern` and prints what the comment says.

<!-- tabs -->

<!-- tab: files.py -->

**Give it a file, get a file back.** A `Sandbox()` has a `/workspace` you and the code both see.

```python
job = """
import csv
rows = list(csv.DictReader(open("in.csv")))
hottest = max(rows, key=lambda row: int(row["temp"]))
open("out.txt", "w").write(hottest["city"])
"""
with kern.Sandbox() as sb:
    sb.write_file("in.csv", "city,temp\nRome,24\nOslo,9\n")
    sb.run_code(job)
    print(sb.read_file("out.txt"))   # b'Rome'
```

<!-- tab: state.py -->

**Keep variables between steps.** `kernel()` is one warm interpreter, like a notebook.

```python
with kern.Sandbox() as sb, sb.kernel() as k:
    k.run_code("x = 40")
    r = k.run_code("print(x + 2)")
    print(r.stdout)   # 42
```

<!-- tab: package.py -->

**Install a package first.** `setup=` runs once, with network; your code still runs without.

```python
with kern.Sandbox(setup="pip install numpy") as sb:
    r = sb.run_code("import numpy as np; print(np.pi)")
    print(r.stdout)   # 3.141592653589793
```

<!-- tab: network.py -->

**Let it reach one host.** No network by default. `egress_allow` opens the hosts you name and
nothing else; `network=True` opens everything, your own loopback included.

```python
code = ("import urllib.request as u; "
        "print(u.urlopen('https://pypi.org').status)")
r = kern.run_code(code)
print(r.exit_code)   # 1: no network
r = kern.run_code(code, egress_allow=["pypi.org"])
print(r.stdout)      # 200
```

<!-- tab: shell.py -->

**Run a shell command.**

```python
r = kern.run_code("uname -s && python3 --version", language="bash")
print(r.stdout)   # Linux, then the image's Python 3.12
```

<!-- tab: chart.py -->

**Get a chart back.** A matplotlib figure open when the code ends comes back as a PNG on
`r.results`; `fig` or `display(fig)` draws one the code holds. In a `kernel()` a figure is closed
once its cell returned it, as in Jupyter.

```python
plot = """
import matplotlib.pyplot as plt
plt.plot([1, 4, 9, 16])
plt.show()
"""
with kern.Sandbox(setup="pip install matplotlib") as sb:
    r = sb.run_code(plot)
    open("chart.png", "wb").write(r.results[0].png)
```

<!-- /tabs -->

## The result says who stopped the run

Exit 137 alone does not say whether it was your timeout or the OOM killer. `fault` does. Every row
was run:

| the code | `fault.type` | `exit_code` |
|---|---|---|
| `print(sum(range(100)))` | `None` | 0 |
| `while True: pass`, `timeout_s=3` | **`timeout`** | 137 |
| `bytearray(400<<20)`, `memory_mb=128` | **`oom`** | 137 |
| `urlopen(...)`, network off | `None` | 1 |
| `print(1)` on `alpine:3.19`, no python3 | **`exec_failed`** | 127 |
| `print(1)` on an image that is not there | **`startup_failed`** | 1 |

In the fourth row the **code** raised and the sandbox did nothing. `fault` is read from a pipe kern
writes, not from stdout, so code that prints `[exit 0]` can't fake it. Also `killed`,
`workspace_full` and `escape_blocked`. These values and exit codes are stable: one changes only to
correct an outcome reported wrong, and that release's
[CHANGELOG](https://github.com/getkern/kern/blob/main/CHANGELOG.md) entry says so first.

## Works with

- **Any MCP client**: Claude Code, Cursor, Claude Desktop, LM Studio, Zed. The package ships
  `kern-mcp`, a stdio server; charts come back as images the model can see. One session backs the
  connection, so files carry between tool calls and variables do not, unless `KERN_MCP_KERNEL=1`:
  [docs/MCP.md](https://github.com/getkern/kern/blob/main/docs/MCP.md).
- **LangChain**: `kern_code_tool()` is a `StructuredTool`, and a fault comes back labelled for the
  model. Shell policy:
  [LANGCHAIN-SHELL.md](https://github.com/getkern/kern/blob/main/bindings/python/LANGCHAIN-SHELL.md).
- **[pi](https://github.com/earendil-works/pi)**: [`kern-pi`](https://www.npmjs.com/package/kern-pi)
  routes its file and shell tools into a box, your working directory at `/workspace`.
- **Python and Node**: the same API, `pip install kern-sandbox` and
  [`npm i kern-sandbox`](https://www.npmjs.com/package/kern-sandbox).

```json
{
  "mcpServers": {
    "kern": { "command": "uvx", "args": ["--from", "kern-sandbox", "kern-mcp"] }
  }
}
```

A client spawns the server from **its own** PATH, so it cannot see a venv: `uvx` fetches the
package, kern included on Linux, or use `pipx install kern-sandbox`. From macOS or Windows, swap the
command for `wsl` or `ssh`.

## Safe by default

A bare `Sandbox()` runs `python:3.12-slim` with a 30 second deadline, no network, no host mounts,
seccomp on and capabilities dropped. The timeout is **mandatory**: no value disables it. Every
relaxation is a named argument.

- **A compromised dependency** is stopped by the filesystem and the network. **A prompt-injected
  agent** runs the code you asked for, so the defence is that credentials are never in the box.
- **Mounts over sensitive sources are refused, with no opt-out**: the host's own directories, kern's
  own state, and 17 credential directories by name (`.ssh`, `.aws`, `.kube`, `.gnupg`, `.netrc`,
  `.npmrc`, `.git-credentials` and the rest), plus `~/.config/gh` and `~/.config/gcloud`. Mount a
  copy.
- **`network=True` includes the host's loopback**, where unauthenticated services live: a test read
  the host's SSH banner off `127.0.0.1:22`. `egress_allow` is the route-level middle setting.

## How fast

Most of a call's cost is CPython starting inside the box, not the box. A
[precompiled image](https://github.com/getkern/kern/tree/main/examples/precompiled-image) removes
the stock image's compile step, and a prewarm pool serves calls from boxes already started. Method
and numbers: [BENCHMARKS.md](https://github.com/getkern/kern/blob/main/BENCHMARKS.md).

## Current limitations

- **Not a boundary against deliberately hostile code.** Namespaces, cgroups and seccomp are for your
  own or semi-trusted code. For hostile or someone else's code, use a microVM or gVisor:
  [SECURITY.md](https://github.com/getkern/kern/blob/main/SECURITY.md).
- **Caps bind only where your host delegates a cgroup.** `kern doctor` says whether yours does;
  `require_limits=True` refuses to start rather than run uncapped.
- **The workspace is bounded only if you ask.** It is a host directory, so by default a job can fill
  your disk. `workspace_max_bytes` is measured while a call runs and stops the box with a
  `workspace_full` fault. The overshoot depends on what the tree costs to walk: ~1.2x for a few
  files, ~13x for 50,000. A measurement and a kill, not a refusal from the filesystem.
- **A directory the box closes to the host comes back at `0o500`.** The host walks the workspace to
  report changes, so read and search are restored on directories it owns, never write, and a warning
  says how many. A file at mode 0 is left alone.
- **A non-root `user=` shares the workspace through a POSIX ACL.** It needs a filesystem with ACLs
  and a host range in `/etc/subuid`. A file that account closes on purpose (`mkstemp`'s 0600,
  `mkdtemp`'s 0700) is reached through a short-lived box running as that account, one box start per
  access.
- **Not inside a container without `--privileged`, and not on Google Colab.** A box mounts a fresh
  `/proc`, which the kernel allows only where an unmasked `/proc` exists; a container masks its own,
  so the box stops at `mount(proc) failed: Permission denied`. Measured on Colab, kernel 6.6.122.
- **The binary ships with the package only on Linux x86_64 and aarch64.** Elsewhere pip picks the
  wheel without it, and the package drives a `kern` on `PATH` or in `$KERN_BIN`, installed with the
  [install script](https://github.com/getkern/kern/blob/main/docs/INSTALL.md). `$KERN_BIN` always
  wins over the bundled one.

## More

The full API, mime-typed results, snapshots and the measured sharp edges:
[SANDBOX-NOTES.md](https://github.com/getkern/kern/blob/main/bindings/python/SANDBOX-NOTES.md).

Linux with unprivileged user namespaces and cgroup v2, Python 3.9+. Windows through WSL2; on a Mac,
inside a Linux VM, where the same `pip install` is the whole install:
[install notes](https://github.com/getkern/kern/blob/main/docs/INSTALL.md). Apache-2.0.
