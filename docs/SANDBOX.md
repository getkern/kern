# Kern Sandbox: running a model's code from Python or Node

Your model writes the code. This runs it where it can't touch your machine: a real Linux container
per call, thrown away when the call returns.

`kern-sandbox` is the SDK in front of the `kern` binary. Two things, not one: the isolation is the
binary's, the package is the API. The same API ships for Python and for Node.

```sh
# the runtime: one static binary, checksum-verified by the script
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh

# if the venv line fails, your distribution ships it separately: sudo apt install python3-venv
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
call gets a new one.

## When you would use this

**Your model just wrote a script and you are about to run it.** Paste it into `run_code` instead of
your terminal. It runs in a container built from an image, so there is no home directory of yours in
there to delete and no key to read: a hallucinated `rm -rf ~` removes the container's own `/root`.

**An agent writing and running code in a loop.** Give it the LangChain tool or the MCP server. Each
step gets its own container, so nothing step 3 left behind is waiting for step 12, and a step that
hangs or runs out of memory comes back as a value your loop can branch on.

**Analysis you did not write.** A chart comes back as an image the model can see, and a failure
comes back labelled, so you can tell a bug in the code from the sandbox stopping it.

## The result says who stopped the run

`docker run` gives you exit 137 and leaves you to guess whether that was your timeout, the OOM
killer or something else. This tells you, as a typed field beside stdout and the exit code, so an
agent loop branches on a value instead of parsing a traceback.

| the code | `fault.type` | `exit_code` |
|---|---|---|
| `print(sum(range(100)))` | `None` | 0 |
| `while True: pass`, `timeout_s=3` | `timeout` | 137 |
| `bytearray(400<<20)`, `memory_mb=128` | `oom` | 137 |
| `urlopen(...)`, network off | `None` | 1 |

The last row is the one a loop gets wrong: the network was off, so the **code** raised and the
sandbox did nothing. `fault` is read from a pipe kern writes rather than from stdout, so code that
prints `[exit 0]` can't fake it. The other values are `killed`, `escape_blocked`, `exec_failed` and
`startup_failed`.

## Safe by default

A bare `Sandbox()` has no network, no host mounts, seccomp on, capabilities dropped and a
**mandatory** timeout. Every relaxation is a named argument. Two that have surprised people, both
measured:

- **Mounts over sensitive sources are refused even if you ask**: the host's own directories,
  anything with `.ssh`, `.aws` or `.kube` in its path, and kern's own state. No opt-out. Mount a
  copy of what the code needs.
- **`network=True` includes the host's loopback**, where unauthenticated services live. A test read
  the host's SSH banner off `127.0.0.1:22`. [`egress_allow`](EGRESS.md) is the middle setting and
  is route-level, so a client that cannot speak to an HTTP proxy has no path out at all.

The caps bind only where your host delegates a cgroup. `kern doctor` says whether yours does, and
`require_limits=True` turns a silent no into a refusal to start. See
[Install](INSTALL.md#requirements-and-limitations).

## Choose how much survives between calls

Three levels, one argument apart.

| | per call | files carry | variables carry |
|---|---:|---|---|
| `kern.run_code(...)`, one-shot | 12.6 ms | no | no |
| a `Sandbox()` you keep open | 6.9 ms | **yes** | no |
| `s.kernel()` | 0.05 ms | **yes** | **yes** |

The first two give every call its own container; what they share is the `/workspace` directory, so
a file one call writes the next one finds, while `x = 41` is gone with the process. `kernel()` is
one long-lived box with a warm interpreter, so everything persists and the calls share one process.

```python
with kern.Sandbox(image="python:3.12-slim") as s:
    s.run_code("open('/workspace/f','w').write('ok')")   # a fresh container, file kept
    with s.kernel() as k:
        k.run_code("x = 41")
        k.run_code("print(x)")                           # 41
```

Measured on an Intel i7-14700KF with a
[precompiled image](https://github.com/getkern/kern/tree/main/examples/precompiled-image), 40 calls
each. On the stock `python:3.12-slim` the first two rows cost about three times as much and the
third does not change, because there the interpreter starts once.

## From an MCP client

The package ships `kern-mcp`, a dependency-free stdio server, so the model writes code, kern runs it
on your machine, and charts come back as images it can see. It works in any MCP client: Cursor,
Claude Code, Claude Desktop, LM Studio, Zed, Windsurf.

```json
{ "mcpServers": { "kern": { "command": "uvx", "args": ["--from", "kern-sandbox", "kern-mcp"] } } }
```

A client spawns the server from **its own** PATH, so a venv is invisible to it: `uvx` above installs
nothing, `pipx install kern-sandbox` is the other way. Per-client config, every `KERN_MCP_*`
variable and the remote form are in [the MCP page](MCP.md).

## What it is not

This is a **kernel boundary**: namespaces, cgroups and seccomp, for your own or semi-trusted code.
If the code is actively hostile, or belongs to someone else, use a microVM (Firecracker, Kata) or
gVisor. That is a different job and costs what a machine costs: about half a second per command
there against about 14 ms here. The full statement is the [threat model](THREAT_MODEL.md).

And `pip install kern-sandbox` does not install the sandbox: it drives a `kern` binary on `PATH` or
in `$KERN_BIN`, which is a second thing to keep current.

## The rest

The full API, `kernel()` for a warm interpreter, snapshots, mime-typed results without a Jupyter
kernel, the LangChain tool and its shell policy, the benchmarks and the measured sharp edges all
live with the package:
[bindings/python](https://github.com/getkern/kern/tree/main/bindings/python) on GitHub, and
[`kern-sandbox`](https://pypi.org/project/kern-sandbox/) on PyPI and
[npm](https://www.npmjs.com/package/kern-sandbox).
