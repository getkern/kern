# Kern Sandbox: running a model's code from Python or Node

Your model writes the code. This runs it where it can't touch your machine: a real Linux container
per call, and a hundred of them cost 1.4 s in total. How much survives between calls is
[your choice](#choose-how-much-survives-between-calls).

**Works with** Claude Code, Cursor, Claude Desktop, LM Studio, LangChain and pi.

`kern-sandbox` is the SDK in front of the `kern` binary: the isolation is the binary's, the package
is the API. On Linux `x86_64` and `aarch64` the package brings the binary with it, from PyPI and
from npm alike.

In a terminal:

```sh
# if the venv line fails, your distribution ships it separately: sudo apt install python3-venv
python3 -m venv .venv && . .venv/bin/activate
pip install -U kern-sandbox
```

On a Mac, all of it goes inside a Linux VM: [macOS](INSTALL.md#macos).

Then in a Python file:

```python
import kern_sandbox as kern

r = kern.run_code("print(sum(range(100)))")
print(r.stdout, r.fault)   # 4950  None
```

That call started a container from an OCI image, ran the code with **no network**, memory and PID
caps and a deadline applied from outside, and threw the container away before returning. The next
call gets a new one, and you can [keep state across them](#choose-how-much-survives-between-calls)
when you want it.

## When you would use this

**Your model just wrote a script and you are about to run it.** Paste it into `run_code` instead of
your terminal. It runs in a container built from an image, so there is no home directory of yours in
there to delete and no key to read. A hallucinated `rm -rf ~` resolves to the container's own
`/root`, which is mounted read-only, so it fails there too.

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
`startup_failed`. They and the exit codes are stable: one changes only to correct an outcome that was
reported wrong, and the release that does it says so first in its
[CHANGELOG](https://github.com/getkern/kern/blob/main/CHANGELOG.md) entry.

## Safe by default

**Two threats, and the second is not covered by the first.** A compromised dependency is stopped by
the filesystem and the network: no network unless you ask, a read-only root, and only the paths you
name. A prompt-injected agent is not, because it runs the code you asked for. The defence there is
that the credentials were never in the box at all, which is why mounts over them are refused rather
than discouraged.

A bare `Sandbox()` has no network, no host mounts, seccomp on, capabilities dropped and a
**mandatory** timeout. Every relaxation is a named argument. Two that have surprised people, both
measured:

- **Mounts over sensitive sources are refused even if you ask**: the host's own directories, kern's
  own state, and 17 credential directories by name (`.ssh`, `.aws`, `.kube`, `.gnupg`, `.netrc`,
  `.npmrc`, `.git-credentials` and the rest), plus `~/.config/gh` and `~/.config/gcloud`. Mount a
  copy of what the code needs.
- **`network=True` includes the host's loopback**, where unauthenticated services live. A test read
  the host's SSH banner off `127.0.0.1:22`. [`egress_allow`](EGRESS.md) is the middle setting and
  is route-level, so a client that cannot speak to an HTTP proxy has no path out at all.

The caps bind only where your host delegates a cgroup. `kern doctor` says whether yours does, and
`require_limits=True` turns a silent no into a refusal to start. See
[Install](INSTALL.md#requirements-and-limitations).

**`user="node"` runs every box as that account of the image**, a name or a number, `"1000:1000"`
included; an image that declares `USER` runs as it with no argument. A non-root account is a uid of
kern's range on disk (`node`, 1000 in the box, is 100999 on a host whose range starts at 100000), so
opening the sandbox starts one box as that account to learn its uid, and the workspace gets a POSIX
ACL naming it. `read_file`, `write_file`, `list_files`, `result.files`, `workspace_max_bytes`,
`snapshot`, `restore` and the cleanup at exit keep working on what the account creates. What it closes
on purpose, a 0600 file or a 0700 directory, is reached through a short-lived box of the same image
running as that account, its owner, one box start per access. The workspace needs a filesystem with ACLs, and the Node binding needs `setfacl`. It costs one
box when the sandbox opens and the uid range on every box: about a millisecond a call, measured.

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

Measured with a
[precompiled image](https://github.com/getkern/kern/tree/main/examples/precompiled-image), 40 calls
each. On the stock `python:3.12-slim` the first two rows cost about three times as much and the
third does not change, because there the interpreter starts once.

Pick the top row unless you need the others. A hundred one-shot calls are a hundred containers and
**1.36 s in total** on the stock image, after which `kern ps -a` lists nothing and the state
directory is the same size it was: the reason to move down the table is that you want the state, not
that you are avoiding a cost.

`Sandbox(name="agent-1", workspace=..., persist=True)` keeps one box alive across calls and across
processes: every call runs in it with `kern exec`, and a second process naming the same sandbox
finds what the first left in `/tmp`. It keeps the BOX, not the interpreter: a call still starts a
fresh `python3`, so measured on one host it costs 11.4 ms against 13.9 for a fresh box, and
`sbx.kernel()` is the fast path (0.22 ms a cell, state in memory). It is not a fresh box: `/tmp`
accumulates, the PID namespace is shared, and a box built under another posture is refused instead
of adopted. It ends after `persist_ttl_s` (an hour by
default) or at `destroy()`. Node spells it `persist: true`.

## Move a sandbox to another machine

Every box a sandbox starts has a read-only root, so what a session builds up lives in its
workspace: the files the code wrote, and `.deps`, where `setup=` installs packages. `snapshot()`
writes that workspace to one archive and `restore()` puts it back, here or on another host:

```python
with kern.Sandbox(image="python:3.12-slim", setup="pip install orjson") as a:
    a.run_code("open('/workspace/state.json','w').write('{}')")
    a.snapshot("/tmp/ckpt.tar.gz")

# later, or elsewhere
with kern.Sandbox(image="python:3.12-slim") as b:
    b.restore("/tmp/ckpt.tar.gz")
```

What it does not carry: running processes and a `kernel()`'s variables, which end with the session;
and the image, which the other host pulls by name. An image that exists only locally (from
`kern build` or `kern commit`) travels with `kern save <image> -o image.tar` and
`kern load -i image.tar`.

The archive records the image and CPU its `.deps` were installed for. A compiled package there only
imports under the same Python, libc and CPU, so `restore()` into a different image warns, and
`setup=` run again in the new sandbox rebuilds the packages for it. Symlinks, FIFOs and devices are not
archived and `snapshot()` lists any it left out, because `restore()` writes only regular files and
directories. What a restored file keeps is its **bytes, its modification time and its owner
permission bits**, so a tool that decides by timestamp (`make`, `tsc --incremental`, Python's own
bytecode check on `.deps`) sees the tree the snapshot captured; an empty directory is kept as well.
Group and other bits are not carried: on a workspace shared with a `user=` account those bits are the
POSIX ACL's mask, and the ACL does not travel in an archive. Ownership is never carried, and the two
bindings write and read one format, so an archive either of them writes restores identically in both.
In Node, `snapshot`/`restore` need `KERN_SANDBOX_SNAPSHOT=1`.

A `kern box` started from the CLI, whose root is writable, moves the same way at the image level:
`kern commit <box> <image>`, then `kern save` and `kern load` as above, then `kern box --image <image>`
on the other host.

## From an MCP client

The package ships `kern-mcp`, a dependency-free stdio server, so the model writes code, kern runs it
on your machine, and charts come back as images it can see. It works in any MCP client: Claude
Code, Cursor, Claude Desktop, LM Studio, Zed.

```json
{ "mcpServers": { "kern": { "command": "uvx", "args": ["--from", "kern-sandbox", "kern-mcp"] } } }
```

A client spawns the server from **its own** PATH, so a venv is invisible to it: `uvx` above installs
nothing, `pipx install kern-sandbox` is the other way. Per-client config, every `KERN_MCP_*`
variable and the remote form are in [the MCP page](MCP.md).

**The server is the middle row of the table above**, and the choice is already made for you: one
session backs the whole connection, so a file one tool call writes the next one finds, while each
call is still a fresh box and variables are gone with it. `KERN_MCP_KERNEL=1` makes it the bottom
row, and the tool description tells the model which of the two is in force, so it does not have to
guess whether to re-import.

## What it is not

This is a **kernel boundary**: namespaces, cgroups and seccomp, for your own or semi-trusted code.
If the code is actively hostile, or belongs to someone else, use a microVM (Firecracker, Kata) or
gVisor. That is a different job and costs what a machine costs: about half a second per command
there against about 14 ms here. The full statement is the [threat model](THREAT_MODEL.md).

The binary comes with the Python package only on Linux `x86_64` and `aarch64`. Anywhere else, and
for Node, the package drives a `kern` on `PATH` or in `$KERN_BIN`, a second thing to keep current.

## The rest

The full API, `kernel()` for a warm interpreter, snapshots, mime-typed results without a Jupyter
kernel, the LangChain tool and its shell policy, the benchmarks and the measured sharp edges all
live with the package:
[bindings/python](https://github.com/getkern/kern/tree/main/bindings/python) on GitHub, and
[`kern-sandbox`](https://pypi.org/project/kern-sandbox/) on PyPI and
[npm](https://www.npmjs.com/package/kern-sandbox).
