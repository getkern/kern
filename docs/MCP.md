# `kern-mcp`: a local code interpreter for any MCP client

The model writes code, kern runs it on your machine in a fresh box per call, and charts come back as
images the client can render.

```json
{ "mcpServers": { "kern": { "command": "kern-mcp" } } }
```

`kern-mcp` ships in the Python package and speaks
[Model Context Protocol](https://modelcontextprotocol.io) over stdio. It is dependency-free: the
standard library and `kern_sandbox`, nothing else.

| client | where the block goes |
|---|---|
| **Cursor** | Settings, MCP, add a server. The editor opens `mcp.json`. |
| **LM Studio** 0.3.17+ | the **Program** tab, then Install, Edit `mcp.json`. LM Studio follows Cursor's notation, so the block is identical. |
| **Claude Desktop** | `claude_desktop_config.json`, same shape. |
| **Claude Code** | `claude mcp add kern -- kern-mcp`, or the same block in `.mcp.json` at the project root. |

**That config works when the client and kern are on the same machine, which means a Linux one.** The
client spawns `kern-mcp` where IT runs, and `kern-mcp` needs a `kern` binary beside it; kern is
Linux-only, because it is namespaces and cgroups. From macOS or Windows use the `ssh` or `wsl` line
below instead.

**A `pip install` into a virtual environment is invisible to the client**, which spawns `kern-mcp` from
its own PATH. `pipx install kern-sandbox` puts it somewhere the client can see, or install nothing and
name the package rather than the command (`uvx kern-mcp` fails: there is no `kern-mcp` on PyPI). On
Linux `x86_64` and `aarch64` the package brings the `kern` binary with it, so this line is the whole
install:

```json
{ "mcpServers": { "kern": { "command": "uvx", "args": ["--from", "kern-sandbox", "kern-mcp"] } } }
```

## The tools

| tool | what it does |
|---|---|
| `run_code` | run a snippet in a fresh, **network-off** box. `language` is `python` (default), `bash`, `sh` or `node`, and **the image must provide the interpreter**. Rich results (last expression, `display()`, matplotlib figures) come back as content |
| `write_file` | write text to a workspace-relative path, `..`-safe and symlink-safe |
| `read_file` | read a UTF-8 workspace file; size-capped so a box cannot flood the client |
| `list_files` | list regular files in the workspace, excluding the internal deps dir |

**Every `run_code` reply says which kern ran it**, as `[exit 0 in kern 0.32.0]`, folded into the frame
that was already there. The reason is not the isolation, which holds: a client with a sandbox of its own
can answer "run this in the sandbox" from its own shell and report success, and nothing in the
conversation contradicts it because no call was ever made. A reply carrying this stamp came through a
binary that identified itself as kern, and a cell that prints the frame itself gets it labelled as its
own words.

**An argument a tool does not have is refused, not dropped.** Every schema is
`additionalProperties: false`: a call carrying `image` or `network` comes back `-32602` naming what was
ignored, and nothing runs. A model told that code ran under a posture it did not get has no way to
correct itself.

**File state persists across calls** through a workspace directory on disk; in-memory state does not,
because each call is a fresh box. The one exception is `KERN_MCP_KERNEL`, which the tool description
tells the model about at `tools/list` time.

## Configuration

Every knob is an environment variable in the client's `env` block. There is no config file.

| variable | default | what it does |
|---|---|---|
| `KERN_MCP_IMAGE` | `ghcr.io/getkern/kern-sandbox:0.2.44`, pinned by digest | the OCI image every box runs |
| `KERN_MCP_SETUP` | none | a one-time `pip install ...` in a **network-on** box that dies afterwards. The only moment the network is on |
| `KERN_MCP_MEMORY_MB` | `1024` | hard RAM cap per box |
| `KERN_MCP_TIMEOUT` | `60` | per-call wall-clock deadline |
| `KERN_MCP_WORKSPACE` | a temp dir | persist file state at this path instead |
| `KERN_MCP_PROFILES` | none | comma-separated `kern.toml` profiles, e.g. `vcpu:heavy,vgpio:sensors`. `vgpio:` gives an agent a board's devices (i2c, serial, spi); a GPU comes through `KERN_MCP_GPUS` below |
| `KERN_MCP_PREWARM` | `1` | how many boxes are kept started in advance. A call claims one instead of starting its own, dropping the per-call cost from ~38 ms to ~1.6 ms **without** changing what a call gets: each prewarmed box serves exactly one cell and is destroyed |
| `KERN_MCP_KERNEL` | off | `1` routes Python through ONE warm interpreter. Unlike prewarming this DOES change the contract: state persists between calls |
| `KERN_MCP_TMPFS_MB` | `64` | scratch at `/tmp`, charged to the box's own memory cap |
| `KERN_MCP_WORKSPACE_MAX_MB` | `0` (no cap) | a size in MiB for the workspace, measured **while a call runs**, so one runaway cell is stopped mid-call |
| `KERN_MCP_USER` | the image's own `USER` | the account the code runs as, e.g. `node` or `1000`. A non-root one shares the workspace through a POSIX ACL: [Safe by default](SANDBOX.md#safe-by-default) |
| `KERN_MCP_GPUS` | none | NVIDIA cards for every box this server starts: `2` (how many), `all`, `device=0,1` (which), or `device=GPU-<uuid>` (a card by the UUID the driver publishes). It is the OPERATOR's knob and not a tool argument, so a model cannot ask for hardware: whoever starts the server decides once. A granted card is not a boundary against the code in the box, so grant one only to code you would trust with the card |
| `KERN_MCP_QUIET` | on | `0` restores kern's non-fatal notes, which otherwise land in the model's output as if the cell had printed them |
| `KERN_BIN` | `kern` on `PATH` | where the binary is |

**`KERN_MCP_SETUP` is the one knob that opens the network, and the default image is why it is rarely
needed.** The most ordinary request ("plot this") needs matplotlib, and the image has it: python 3.12
with numpy, pandas and matplotlib, plus node 22, for `x86_64` and `aarch64`. The tag is pinned to a
digest and kern verifies it, so moving the tag does not change what a server runs.

The image is 145 MB against 46 for `python:3.12-slim`, and the server starts downloading it when the
client starts the server. A call arriving first waits for the download and then gets its whole deadline:
measured from an empty cache, 23.7 s on `x86_64` and 45.1 s on a Jetson for that first call, and under
0.1 s after it. `KERN_MCP_IMAGE=python:3.12-slim` restores the previous default, and the image builds
locally from this repository:

```sh
kern build -t kern-sandbox:local -f images/sandbox/Dockerfile images/sandbox
export KERN_MCP_IMAGE=kern-sandbox:local
```

**`0` is a sentinel on three of them, and unsetting is not the same thing.** `KERN_MCP_MEMORY_MB=0`
sends **no `--memory` flag at all**, which is the only way to let a `vcpu:` profile's own `memory=`
apply; unsetting yields the 1024 default, an explicit flag, which then shadows the profile.
`KERN_MCP_TMPFS_MB=0` means no scratch, putting `/tmp` back in the read-only root.
`KERN_MCP_PREWARM=0` holds no boxes in advance. Every other path turns the value into a positive int,
so without the sentinel "off" cannot be spelled. Garbage and negative values fall back to the default:
a typo is not a decision.

## The workspace, and how to bound it

`KERN_MCP_TMPFS_MB` bounds `/tmp`, which is a tmpfs charged to the box's memory cap. **The workspace is
a host directory**, written directly by the box, and by default nothing bounds it. Measured on 0.31.0,
one call, no cap: **8,115 MB on disk in 10 seconds**. At that rate the 60-second default is tens of
gigabytes in a single cell. On WSL those bytes land in the distro's virtual disk, which **grows and does
not shrink** when the files are deleted.

**`KERN_MCP_WORKSPACE_MAX_MB` bounds it.** The cap used to be checked only BETWEEN calls, which bounds
what accumulates and nothing a single cell does; the SDK now measures the workspace **while the call
runs** and stops the box when it crosses, with a fault that names the cap (`workspace_full`) rather than
reading as a timeout or an OOM. Three things to know:

- **the overshoot is what the workspace costs to MEASURE**, not a fixed interval. The interval scales
  to the headroom, and between two walks of the tree a cheap probe re-checks the eight biggest files and
  every directory's fingerprint, so a workspace with many files is still walked rarely without the cap
  going blind between walks. An interval can never be shorter than one walk, which is where what gets
  past it comes from. MEASURED with the headroom held at 50 MiB and only the pre-existing file count
  varied: 1.26x the cap at 0 files, 1.32x at 1,000, 4.12x at 10,000 and 12.88x at 50,000 (Node pays more
  per walk: 1.30x, 1.80x, 8.40x, 12.80x). The `workspace_full` fault repeats those figures;
- **it is still not a kernel boundary**: a measurement and a kill, not a refusal from the filesystem;
- **a non-root `KERN_MCP_USER` keeps the old behaviour** for any directory the box account closed to the
  host: there is nothing to measure mid-call, so the cap falls back to the between-calls check rather
  than killing on a number it could not take.

**A directory the box closes to the host gets its owner bits back.** The server walks the workspace
after every call, so `os.chmod("d", 0)` on a directory the host owns is repaired to `0o500` (read and
search, never write) and a warning says how many directories were touched. In short, a mode-0 directory
does not survive a call. Before this, one `chmod` raised out of the reporting path and ended the
session. A directory created by a non-root `KERN_MCP_USER` is left exactly as it is, and so is a **file**
at mode 0 on every path, because a file's mode can be the data. Full account:
[SANDBOX.md](SANDBOX.md#the-one-thing-the-host-changes-in-your-workspace).

**The stronger option is a sized filesystem**, where the cell gets `ENOSPC`, a kernel answer rather than
a cooperative one. Without root, use one that already exists: `$XDG_RUNTIME_DIR` is a per-user tmpfs
sized by the login manager.

```sh
KERN_MCP_WORKSPACE="$XDG_RUNTIME_DIR/kern-mcp"
```

Measured: `/run/user/1000` is a 3.1 GB tmpfs, and a cell writing past it stopped at **3190 MiB with
ENOSPC**. ⚠️ Two real costs: it is **RAM-backed**, so those bytes are memory and not disk, and it is
**cleared when the session's last login goes away**. With root, make one: a loopback image, an XFS or
ext4 project quota, a dedicated volume. A non-superuser cannot: `mount -t tmpfs -o size=64m` answers
`must be superuser to use mount`, measured.

And the lever that needs nothing: **the per-call deadline bounds the write by rate times time.** At
~810 MB/s, `KERN_MCP_TIMEOUT=10` bounds a runaway cell to about 8 GB. It is blunt, since it also kills
slow legitimate work, but on a default `/tmp` inside the root filesystem it is the only bound available.

## The server is stdio, so it travels

MCP holds one stdio pipe open for the life of the session, and nothing in the protocol cares what
carries it. **A box on another machine, over ssh:**

```json
{ "mcpServers": { "kern": { "command": "ssh", "args": ["you@linux-host", "kern-mcp"] } } }
```

**A Linux box from a Windows host, over WSL:**

```json
{ "mcpServers": { "kern": { "command": "wsl", "args": ["-d", "Ubuntu", "--", "kern-mcp"] } } }
```

The agent runs where you are; the sandbox runs where the box is. For another machine that is the whole
integration: `pip install kern-sandbox` there, a key you already have, and one line in a config file.

Three properties come from using ssh rather than a `--remote` flag built here. Authentication and
encryption arrive for free. **Nothing listens**: no HTTP endpoint, no bearer token, no new surface in
[THREAT_MODEL.md](THREAT_MODEL.md). And the two boundaries stay separate: ssh decides WHO may run code,
kern decides what that code may touch.

### What it costs

Measured on loopback against a user-owned `sshd`, key auth, no sudo, one call at a time with a pause
between, which is what an agent does. Medians.

```
ssh handshake, once per session               172 ms
session start (server up, initialized)        200 ms

                                     per call   state between calls
a fresh box per call                   37.8 ms   none
a fresh box, PREWARMED (the default)    1.6 ms   none
KERN_MCP_KERNEL=1                       0.9 ms   PERSISTS
```

The handshake and session start are paid **once**. Prewarming removes ~36 ms of the per-call cost while
the other columns stay identical: **a prewarmed call gets the same thing a cold call gets** - same
stdout, exit status, rich results, file diff, truncation, faults and network posture, with a test for
each.

**The pool is a budget, not a rate.** It is built on the first `tools/call`, so the first call of a
session is cold whatever the setting is; after that it holds up to `KERN_MCP_PREWARM` boxes and refills
in the background at about 70 ms a slot. A client that calls with no pause drains the budget and pays
the cold price for the rest: measured with a burst of 8, `N=4` gave 1.2, 0.8, 0.4, 0.4 ms and then 22.6,
14.0, 14.5, 13.5. With calls 150 ms apart `N=1` is already at the floor, so 1 is the default. A bigger
number buys a longer burst, never a higher rate, and a benchmark that does not pause is timing the cold
path.

One observable does differ: the interpreter is older than the call, so code reading its own start time
out of `/proc/self/stat` sees ~0 s cold and up to five minutes warm. No boundary moves with it.

The warm kernel is 0.7 ms faster still, and that is not why you would choose it: it is a different
promise, one resident interpreter where variables and imports survive. Take it when the session is a
conversation with one notebook.

**What those numbers do not include**: this is loopback, so a real link adds one round trip per call,
tens of milliseconds on a LAN and small next to a model's thinking time. Prewarming also trades idle
memory for latency. **What does not degrade**: a workspace holding 5000 files moves the cold marginal
from 12 ms to 16 ms and `list_files` from 28 ms to 47 ms; a megabyte of stdout adds 5 ms.

## Six questions clients ask, measured

| question | answer |
|---|---|
| Do the server's environment variables reach the box? | **No.** With four cloud tokens set in the server process, a cell dumping its environment saw ten variables, all from the image, and none of the four. There is no knob for passing any in |
| Can the client mount a host directory? | **No.** The only host path inside a box is the workspace. Point `KERN_MCP_WORKSPACE` at a repository and the agent can write anything in that tree, including a `.mcp.json` that configures this server on the next restart. The SDK refuses `$HOME`, `/etc`, `/root`, any path holding a credential directory, and kern's own state |
| Several calls at once? | **Serialised.** Three back-to-back `run_code` calls each sleeping a second came back in 3.0 s, in order, each seeing the previous one's files |
| Do two clients see each other? | **No.** Each client spawns its own server with its own workspace: two sessions had different inodes and the second could not read the first's file. Both were removed at exit |
| Does `KERN_MCP_QUIET` hide the verdict? | **No**, and it must not. With quiet on, a cell that blew the memory cap still came back `isError: true` with `[exit 137, sandbox fault: oom: ...]`. Quiet suppresses notes, never a fault |
| Is `KERN_MCP_SETUP` paid once or per call? | **Once**, at server start: with `KERN_MCP_SETUP=pip install tabulate`, the first call importing it took 1294 ms and the second 120 ms |

## What this is not

It is not a hosted sandbox: no account, no API key, no egress, because the code runs on a machine you
control. E2B, Modal and Daytona answer the same need with a network round trip to someone else's.

It is not a way around the box's limits either. Everything in [RESOURCES.md](RESOURCES.md) applies:
`memory_mb` bounds the cgroup rather than the workload's usable memory, scratch is charged to that same
cap, and each call is a fresh box unless `KERN_MCP_KERNEL=1`, so anything a later call must find belongs
in the workspace. The `run_code` description states whichever of those two contracts is in force, and
only that one.
