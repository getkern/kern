# Kern Sandbox as a LangChain shell execution policy

LangChain's shell middleware wants a **session**: one long-lived shell an agent writes commands
into, so `cd` and `export` persist the way a terminal does. That is an extension point, and this
plugs into it as a peer of `DockerExecutionPolicy` rather than as a wrapper beside it.

The other shape, one box per call with file state on the workspace, is `kern_code_tool()` in the
[package README](https://github.com/getkern/kern/blob/main/bindings/python/README.md).

```bash
pip install 'kern-sandbox[langchain-shell]'
```

```python
from langchain.agents.middleware import ShellToolMiddleware
from kern_sandbox.langchain import kern_execution_policy

middleware = ShellToolMiddleware(execution_policy=kern_execution_policy())
```

Everything below was measured on one host. Numbers move with hardware; the shapes do not.
`langchain>=1.3` is required, and the floor is measured: 1.3.0 works, 1.2.0 has no such base class.

## Coming from `DockerExecutionPolicy`

A 32-command battery through langchain's own `ShellSession` comes back identical between the two,
with one flag:

```python
kern_execution_policy(match_docker_capabilities=True)
```

The default drops every capability (measured `CapEff: 0000000000000000`), a stronger posture than a
Docker container, and that breaks two ordinary things Docker allows: `chown` to another uid, and
`apt-get update`, since apt drops privileges to `_apt` and needs SETUID and SETGID. The flag adds
back exactly the fourteen a container keeps, and the box then reports `CapEff: 00000000a80425fb`,
byte for byte what Docker reports. The descriptor limit is matched without asking: a box would
otherwise inherit the host's `nofile`, 1048576 here against a container's 1024 soft.

**Three differences remain and no option closes them**, which is worth knowing before you spend an
afternoon looking for the flag:

- **Raw sockets, so `ping` and `traceroute`.** `CAP_NET_RAW` is in the effective set with the flag
  above, and measurably so, but with `network_enabled` the box shares the host's network namespace,
  and a capability held in a nested user namespace does not apply to a namespace owned by the
  initial one. That is a kernel rule about rootless containers rather than a kern decision: a
  rootful Docker daemon can, this cannot. DNS, TCP and HTTP are unaffected.
- **`mount`** dies on the seccomp filter where Docker returns `permission denied`, because a
  deny-by-default allowlist is what kern is.
- **The setuid bit** is not visible on files, because the rootfs is mounted `nosuid`.

## What it costs

Same image pre-pulled in both runtimes, through langchain's own abstraction, split by phase because
a composite number hides where the difference is. n=16, and the **first** session is reported
separately from the rest, because that is the one a reader is right to suspect was chosen for
convenience.

    phase                      kern      docker
    start up, FIRST session  14.5 ms   159.6 ms      11x
    start up, steady state    4.1 ms   157.4 ms      38x
    round-trip                0.05 ms    0.15 ms      3x
    tear down                 1.1 ms    63.4 ms      59x

**Quote the 11x.** The gap between the first session and the rest is not the image cache, which was
the obvious guess and the wrong one: eight fresh processes each measuring only their own first
session came back at 12 to 25 ms and none fell to 4. It is per-process warm-up on the client side,
and kern's own start is small enough that ten milliseconds of it dominates, while Docker's 157 ms
makes the same ten noise. So the steady-state figure flatters kern and the first-session one does
not, and the first is what anyone running the snippet will see.

Read the rest honestly too: **once a session is up the per-command cost is the same for any
practical purpose**, both round-trips well under a millisecond. The difference is in creating and
destroying sessions, which an agent does per task rather than per command. This is kern rootless
with no daemon against Docker with its daemon already running, the default configuration of each.

Taken at a load average of 0.8 and re-taken at 22.8 with the same result, so these do not need a
quiet machine: under heavy disk write everything roughly doubled and the ratios held.

That last row matters more than it looks, because **the middleware restarts the whole session on
every command timeout** and one ordinary mistake makes timeouts routine. One restart is a `stop()`
plus a full `spawn()`: 5.4 ms here against 219.6 ms (p50, n=9). A model that writes twenty
timing-out commands in a row spends 0.11 s in restarts, or 4.4 s. Nothing counts or caps those
restarts, in either runtime.

## Defaults, and three differences from the Docker policy

`--net none`, `--cap-drop ALL`, a 512 MiB memory cap, a 256-process ceiling and a reaping init.

- **The default image can run the default shell.** The middleware's default is `/bin/bash`, and
  alpine does not ship it; `python:3.12-alpine3.19`, the Docker policy's own default, cannot start
  it at all.
- **Environment variables go through an anonymous `memfd`, not `-e` flags**, because a session is
  long-lived and `-e SECRET=...` sits in the host's world-readable process table for its whole life.
  It is **not** secrecy from another process of the same user: kern holds the descriptor, so
  `/proc/<kern-pid>/fd/N` stays readable by anything running as you, measured rather than assumed.
  Same exposure as a 0600 file while the session lives, none after.
- **A workspace path containing a colon still works.** A colon separates SRC from DST in a mount, so
  such a path cannot be expressed at all; it is mounted through a colon-free alias that resolves on
  the host too.

`mount_workspace` decides whether the workspace is bind-mounted at all. `auto` (the default) mirrors
the Docker policy and skips the mount for the ephemeral directory the middleware creates when the
caller supplied none; `always` mounts it regardless, `never` runs with no mount and a working
directory of `/`.

```python
kern_execution_policy(mount_workspace="always", image="python:3.12-slim", memory_bytes=1 << 30)
```

## Two vocabularies, both accepted

`command_timeout`, `max_output_bytes`, `startup_timeout` and `termination_timeout` are langchain's
names, kept so this stays a drop-in peer of `DockerExecutionPolicy`. `Sandbox` spells the same ideas
`timeout_s` and `memory_mb`. Both reach the policy, and the unit converts with the name:

```python
kern_execution_policy(timeout_s=17, memory_mb=256)                   # this package's names
kern_execution_policy(command_timeout=17, memory_bytes=268435456)    # langchain's, the same policy
```

`network`/`network_enabled`, `pids`/`pids_limit` and `cap_drop`/`drop_all_capabilities` pair up the
same way. Passing both halves is a `TypeError` rather than a silent winner, and an unknown name is
refused with the accepted spelling in the message.

## Two things that bite an agent running for hours

Both were **measured identically through `DockerExecutionPolicy`**, so they are what a shell session
and a bind mount are rather than anything this policy adds.

**A command can desynchronise the session.** The middleware writes a marker after every command and
reads until it comes back; a `cat` with no arguments swallows that marker and echoes it as ordinary
output, and from there every command times out while the model is handed the text of its own
instructions. The middleware recovers by restarting, so the cost is one timeout plus the silent loss
of everything the session had accumulated.

It is worse than lost state, and the asymmetry is the reason: a `restart: true` payload re-runs
`startup_commands`, a timeout does not, so whatever a caller put there as a guard stops applying.
Measured on a stock 1.3.17 with no sandbox backend at all: `ulimit -f 100` comes back `unlimited`,
`umask 0077` comes back `0002`, and a `readonly` variable is gone and no longer readonly, while the
session keeps answering. Reported upstream as
[langchain-ai/langchain#39953](https://github.com/langchain-ai/langchain/issues/39953).

**The model is told the command timed out, not that its state is gone.** It reads as "this one
failed, the others did not", so the model carries on with relative paths that no longer resolve, and
the next failure looks like a missing file. The only place a model reliably reads is the tool
description:

```python
ShellToolMiddleware(
    execution_policy=kern_execution_policy(),
    tool_description=DEFAULT_TOOL_DESCRIPTION + (
        "\n\nIf a command times out the shell is restarted and all session state is lost: "
        "the working directory, exported variables, and any background processes."
    ),
)
```

Nothing accumulates on this side across those restarts: twelve cycles leave no environment, no alias
and no descriptor behind.

**If the host removes the workspace under a live session**, the mount points at an inode with no
name and nothing reports it. `pwd` answers, `ls` returns an empty listing with status 0, and writes
fail without the caller noticing; only reading a file back surfaces it. A workspace that is already
missing, or that is a file, is refused at `spawn`, which is the only point this policy gets to look.

The workspace has **no disk ceiling**: it is a host directory, and file state persisting is the
point. Bound it yourself if that matters where you run.
