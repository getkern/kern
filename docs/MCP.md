# `kern-mcp`: a local code interpreter for any MCP client

`kern-mcp` ships in the Python package (`pip install kern-sandbox`) and speaks
[Model Context Protocol](https://modelcontextprotocol.io) over stdio, newline-delimited JSON-RPC 2.0.
It is dependency-free: it imports the standard library and `kern_sandbox`, nothing else.

The model writes code, kern runs it on your machine in a fresh box per call, and charts come back as
images the client can render.

```json
{ "mcpServers": { "kern": { "command": "kern-mcp" } } }
```

## The tools

| tool | what it does |
|---|---|
| `run_code` | run a snippet in a fresh, **network-off** box. `language` is `python` (default), `bash`, `sh` or `node`, and **the image must provide the interpreter**: the enum is what the runner accepts, not a promise about the image. Rich results (last expression, `display()`, matplotlib figures) come back as content |
| `write_file` | write text to a workspace-relative path, `..`-safe and symlink-safe |
| `read_file` | read a UTF-8 workspace file; the read is size-capped so a box cannot flood the client |
| `list_files` | list regular files in the workspace, excluding the internal deps dir |

**File state persists across calls** through a workspace directory on disk; in-memory state does not,
because each call is a fresh box. That is the same model the SDK documents, and the one exception is
`KERN_MCP_KERNEL`, which the tool description tells the model about at `tools/list` time.

## Configuration, and where the surprises are

Every knob is an environment variable in the client's `env` block. There is no config file.

| variable | default | what it does |
|---|---|---|
| `KERN_MCP_IMAGE` | `python:3.12-slim` | the OCI image every box runs |
| `KERN_MCP_SETUP` | none | a one-time `pip install ...` in a **network-on** box that dies afterwards. The only moment the network is on |
| `KERN_MCP_MEMORY_MB` | `1024` | hard RAM cap per box |
| `KERN_MCP_TIMEOUT` | `60` | per-call wall-clock deadline |
| `KERN_MCP_WORKSPACE` | a temp dir | persist file state at this path instead |
| `KERN_MCP_PROFILES` | none | comma-separated `kern.toml` profiles, e.g. `vcpu:heavy,vgpio:sensors`. `vgpio:` is the only way to give an agent a hardware device |
| `KERN_MCP_PREWARM` | `1` | how many boxes are kept started in advance, each holding a booted interpreter that has run nothing. A call claims one instead of starting its own, so the per-call cost drops from ~38 ms to ~1.6 ms **without** changing what a call gets: each prewarmed box serves exactly one cell and is destroyed. `0` turns it off |
| `KERN_MCP_KERNEL` | off | `1` routes Python through ONE warm interpreter. Unlike prewarming, this DOES change the contract: state persists between calls. [What it costs](#what-it-costs) compares them |
| `KERN_MCP_TMPFS_MB` | `64` | scratch at `/tmp`, charged to the box's own memory cap |
| `KERN_MCP_QUIET` | on | `0` restores kern's non-fatal notes, which otherwise land in the model's output as if the cell had printed them |
| `KERN_BIN` | `kern` on `PATH` | where the binary is |

**`0` is a sentinel on three of them, and unsetting is not the same thing.**

- `KERN_MCP_MEMORY_MB=0` sends **no `--memory` flag at all**, which is the only way to let a `vcpu:`
  profile's own `memory=` apply. Unsetting the variable yields the 1024 default, which is an explicit
  flag, and kern's "explicit flag wins over a profile" rule then shadows the profile's value. Without
  the sentinel a profile's memory is unreachable from MCP, because every other path produces an int.
- `KERN_MCP_TMPFS_MB=0` means no scratch at all, putting `/tmp` back inside the read-only root.
- `KERN_MCP_PREWARM=0` holds no boxes in advance and restores the previous per-call cost exactly.

They need the sentinel for one shared reason: every other path here turns the value into a positive
int, so without it "off" cannot be spelled and an operator who typed `0` silently gets the default.

Garbage and negative values fall back to the default on both, deliberately: a typo is not a decision.

## The server is stdio, so it travels

MCP holds one stdio pipe open for the life of the session. Nothing in the protocol cares what carries
that pipe, so **any transport that carries stdio is a transport for `kern-mcp`**, and the client
config is one line either way.

**A box on another machine, over ssh:**

```json
{ "mcpServers": { "kern": { "command": "ssh", "args": ["pi@raspberrypi", "kern-mcp"] } } }
```

**A Linux box from a Windows host, over WSL:**

```json
{ "mcpServers": { "kern": { "command": "wsl", "args": ["-d", "Ubuntu", "--", "kern-mcp"] } } }
```

The agent runs where you are; the sandbox runs where the box is. For an ARM board that is the whole
integration: `pip install kern-sandbox` and a `kern` binary on the board, a key you already have, and
one line in a config file.

### What it costs

Measured on loopback against a user-owned `sshd` on port 2222, key auth, no sudo. An INTERACTIVE
session: one call at a time with a pause between, which is what an agent does. Medians, every row
asserting it received and matched every response.

```
ssh handshake, once per session               172 ms
session start (server up, initialized)        200 ms

                                     per call   state between calls
a fresh box per call                   37.8 ms   none
a fresh box, PREWARMED (the default)    1.6 ms   none
KERN_MCP_KERNEL=1                       0.9 ms   PERSISTS
```

The handshake and the session start are paid **once**, because the pipe stays open for the session.
What repeats is the per-call column, and prewarming removes ~36 ms of it while the middle and right
columns stay identical: **a prewarmed call gets the same thing a cold call gets.** Each prewarmed box
serves exactly one cell and is then destroyed. Same stdout, same exit status, same rich results, same
file diff, same truncation, same faults, same network posture: there is a test for each.

One observable does differ, and the honest form of the claim says so: the interpreter is older than
the call. Code that reads its own start time out of `/proc/self/stat` sees ~0 s on a cold call and up
to five minutes on a warm one. No boundary moves with it - the mounts, capabilities, network, memory
cgroup and one-cell lifetime are the same - so this matters to a benchmark that times itself from
process start, and to nothing else.

The warm kernel is 0.7 ms faster still and that is not why you would choose it. It is a different
promise: one resident interpreter, so variables and imports survive between calls. Take it when the
session is a conversation with one notebook, not when each call must start clean.

**Where prewarming stops helping, since it is a pool and not magic.** A slot refills in about 70 ms.
So `KERN_MCP_PREWARM=N` buys **N back-to-back calls** at ~1 ms and then falls back to the cold cost
until the pool catches up. Measured with a burst of 8 and no pauses: `N=4` gave 1.2, 0.8, 0.4, 0.4 ms
and then 22.6, 14.0, 14.5, 13.5. With calls 150 ms apart or more, `N=1` is already at the floor. An
agent pauses to think, so 1 is the default; raise it only if something drives the server in bursts.

**What those numbers do not include, stated rather than left to be found.** This is loopback: no
network latency, and the same CPU at both ends. A real link adds one round trip per call, which is
tens of milliseconds on a LAN and still small next to a model's own thinking time. Prewarming holds
one booted interpreter per slot for the life of the session, so it trades idle memory for latency.

**What does not degrade.** A workspace holding 5000 files moves the cold marginal from 12 ms to
16 ms and `list_files` from 28 ms to 47 ms; a megabyte of stdout from one call adds 5 ms. There is no
cliff in either, so neither the workspace nor the output size is worth managing for speed.

### Why ssh rather than a transport of our own

Three properties come from using the tool that already exists, and none of them would come from a
`--remote` flag built here:

- **Authentication and encryption arrive for free**, with key management the operator already has.
- **Nothing listens.** There is no HTTP endpoint to expose, no bearer token to leak, and no new
  network surface in [THREAT_MODEL.md](THREAT_MODEL.md).
- **The two boundaries stay separate and both hold.** ssh decides WHO may run code; kern decides what
  that code may touch once it runs. Different mechanisms answering different questions, and neither
  doing the other's job.

`ssh host kern-mcp` is already the minimal form. A wrapper around it would add surface without adding
reach.

## What this is not

It is not a hosted sandbox. There is no account, no API key and no egress: the code runs on a machine
you control, which is the point. E2B, Modal and Daytona answer the same need with a network round
trip to someone else's machine.

It is not a way around the box's limits either. Everything in
[docs/RESOURCES.md](RESOURCES.md) applies: `memory_mb` bounds the cgroup rather than the workload's
usable memory, scratch is charged to that same cap, and each call is a fresh box, so anything a later
call must find belongs in the workspace.
