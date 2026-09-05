# kern-sandbox as a LangChain shell execution policy

This is the long version, moved out of the package README so that page stays readable. It covers the
LangChain **shell middleware** integration: a long-lived session an agent writes commands into, as
opposed to the one-box-per-call code tool, which the README covers.

Everything here is measured on one host. Numbers move with hardware; the shapes do not.

The tool above gives an agent a **cell**: one box per call, file state carried on the workspace.
LangChain's shell middleware wants the other shape, a **session**: one long-lived shell it writes
commands into, so `cd` and `export` persist the way a terminal does. That is an extension point, and
kern plugs into it as a peer of the Docker policy rather than as a wrapper beside it.

```bash
pip install 'kern-sandbox[langchain-shell]'
```

```python
from langchain.agents.middleware import ShellToolMiddleware
from kern_sandbox.langchain import kern_execution_policy

middleware = ShellToolMiddleware(execution_policy=kern_execution_policy())
```

**Coming from `DockerExecutionPolicy`?** A 32-command battery through langchain's own `ShellSession`
comes back identical between the two, with one flag:

```python
kern_execution_policy(match_docker_capabilities=True)
```

The default here drops every capability (`CapEff` all zeros), which is a stronger posture than a Docker
container and breaks two ordinary things Docker allows: `chown` to another uid, and `apt-get update`,
since apt drops privileges to the `_apt` user and needs SETUID and SETGID. That flag adds back exactly
the fourteen a container keeps, and the box then reports `CapEff: 00000000a80425fb`, byte for byte what
Docker reports. The descriptor limit is matched without asking: a kern box would inherit the host's
`nofile`, measured at 1048576, against a container's 1024 soft and 524288 hard, and that is a difference
nobody chose, so it is set rather than documented.

Three differences remain and no option closes them, which is worth knowing before you spend an
afternoon looking for the flag:

- **Raw sockets, so `ping` and `traceroute`.** `CAP_NET_RAW` is in the effective set with the flag
  above, and measurably so, but with `network_enabled` the box shares the host's network namespace, and
  a capability held in a nested user namespace does not apply to a namespace owned by the initial one.
  That is a kernel rule about rootless containers rather than a kern decision: a rootful Docker daemon
  can, this cannot. DNS, TCP and HTTP go through the ordinary socket API and are unaffected.
- **`mount`** dies on the seccomp filter where Docker returns `permission denied`, because a
  deny-by-default allowlist is what kern is.
- **The setuid bit** is not visible on files, because the rootfs is mounted `nosuid`.

Measured on one host, same image pre-pulled in both runtimes, through langchain's own abstraction, and
split by phase because a composite number hides where the difference is. n=16, and the **first**
session reported separately from the rest because that is the one a reader is right to suspect was
chosen for convenience:

    phase                      kern      docker
    start up, FIRST session  14.5 ms   159.6 ms      11x
    start up, steady state    4.1 ms   157.4 ms      38x
    round-trip                0.05 ms    0.15 ms      3x
    tear down                 1.1 ms    63.4 ms      59x

Measured at a load average of 0.8 and re-measured at 22.8 with the same result: tear-down came back
at 1.1 ms and 63.4 ms both times, steady-state start at 4.1 and 4.0. These are not numbers that need a
quiet machine. One run taken while a large install was still writing to disk came out roughly double
across the board, which is worth saying because it is the shape of every benchmark that disagrees with
this one: the ratio held there too.

**Quote the 11x.** The gap between the first session and the rest is not the image cache, which was
the obvious guess and the wrong one: eight fresh processes each measuring only their own first session
came back at 12 to 25 ms and none of them fell to 4, so it is per-process warm-up on the client side
(imports, the first subprocess, the allocator). kern's own start is small enough that roughly ten
milliseconds of that dominates it; Docker's is 157 ms, so the same ten are noise, which is why its two
rows barely differ. The steady-state figure therefore flatters kern and the first-session one does not,
and the first is also what anyone running the snippet will actually see.

Read the rest honestly too: **once a session is up, the per-command cost is the same for any practical
purpose**, both round-trips being well under a millisecond. The difference is in creating and
destroying sessions, which is what an agent does per task rather than per command. This is kern
rootless with no daemon against Docker with its daemon already running, the default configuration of
each.

That last point is not academic, because **the middleware restarts the whole session on every command
timeout** and one ordinary mistake makes timeouts routine (see below). One restart is a `stop()` plus a
full `spawn()`: 5.4 ms here against 219.6 ms (p50, n=9). A model that writes twenty timing-out commands
in a row therefore spends 0.11 s in restarts, or 4.4 s, on top of the timeouts themselves. Nothing
counts or caps those restarts, in either runtime.

Defaults are the posture, since this is the path whose whole purpose is running commands an agent
wrote: `--net none`, `--cap-drop ALL` (measured `CapEff: 0000000000000000`), a 512 MiB memory cap, a
256-process ceiling and a reaping init. Three deliberate differences from the Docker policy:

- **The default image can run the default shell.** The middleware's default is `/bin/bash`, and alpine
  does not ship it; `python:3.12-alpine3.19`, the Docker policy's own default, cannot start it at all.
- **Environment variables go through an anonymous `memfd`, not `-e` flags.** A session is
  long-lived, and `-e SECRET=...` sits in the host's world-readable process table for its whole life.
  The anonymous file has no name on any filesystem, so nothing leaks and a `kill -9` leaves nothing
  behind. It is **not** secrecy from another process of the same user: kern holds the descriptor for
  the session, so `/proc/<kern-pid>/fd/N` stays readable by anything running as you (measured over the
  whole lifecycle, not assumed). Same exposure as a 0600 file while the session lives, none after.
- **A workspace path containing a colon still works.** A colon separates SRC from DST in a mount, so
  such a path cannot be expressed at all; it is mounted through a colon-free alias that resolves on
  the host too, keeping one absolute path meaning the same thing inside the box and out.

`mount_workspace` decides whether the workspace is bind-mounted at all. `auto` (the default) mirrors
the Docker policy and skips the mount for the ephemeral directory the middleware creates when the caller
supplied none, so nothing of the host is exposed for a directory about to be deleted; `always` mounts it
regardless, `never` runs with no mount and a working directory of `/`.

```python
kern_execution_policy(mount_workspace="always", image="python:3.12-slim", memory_bytes=1 << 30)
```

### Two vocabularies, both accepted

`command_timeout`, `max_output_bytes`, `startup_timeout` and `termination_timeout` are langchain's
own field names, inherited from the policy base this class subclasses. Renaming them would stop it
being a drop-in peer of `DockerExecutionPolicy`, which is the point. `Sandbox` spells the same two
ideas `timeout_s` and `memory_mb`, because that is this package's surface.

Both spellings reach the policy, and the unit converts with the name:

```python
kern_execution_policy(timeout_s=17, memory_mb=256)          # this package's names
kern_execution_policy(command_timeout=17, memory_bytes=268435456)   # langchain's, the same policy
```

`network`/`network_enabled`, `pids`/`pids_limit` and `cap_drop`/`drop_all_capabilities` pair up the
same way. Passing both halves of a pair is a `TypeError` rather than a silent winner, and an unknown
name is refused with the accepted spelling in the message.

The workspace has **no disk ceiling**, the same as for the code tool above: it is a host directory, and
file state persisting is the point. Bound it yourself if that matters where you run.

Two behaviours worth knowing before an agent runs for hours, both **measured identically through
`DockerExecutionPolicy`**, so they are what a shell session and a bind mount are rather than anything
this policy adds:

- **A command can desynchronise the session.** The middleware writes a marker after every command and
  reads until it comes back; a `cat` with no arguments swallows that marker and echoes it as ordinary
  output, and from there each command times out while the model is handed the text of its own
  instructions. The middleware recovers by restarting the session, so the cost is one timeout plus the
  silent loss of everything the session had accumulated (`cd`, `export`, background processes).

  It is worse than accumulated state, and the asymmetry is the reason: a `restart: true` payload
  re-runs `startup_commands`, a timeout does not. So whatever a caller put there as a guard stops
  applying. Measured on a stock 1.3.17 with no sandbox backend at all: `ulimit -f 100` comes back
  `unlimited`, `umask 0077` comes back `0002`, and a `readonly` variable is gone and no longer
  readonly, while the session keeps answering. Reported upstream as
  [langchain-ai/langchain#39953](https://github.com/langchain-ai/langchain/issues/39953).

  **The model is told the command timed out, not that its state is gone**, and that is the part worth
  guarding against: a per-command message reads as "this one failed, the others did not", so the model
  carries on with relative paths that no longer resolve and credentials it no longer has. The next
  failure looks like a missing file rather than a lost session, and it confidently goes looking for the
  file. The only place a model reliably reads is the tool description, so pass one that says so:

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
  and no descriptor behind, and repeated sessions do not grow the interpreter's exit handlers.
- **If the host removes the workspace under a live session**, the mount points at an inode with no
  name and nothing reports it. `pwd` answers, `ls` returns an empty listing with status 0, and writes
  fail without the caller noticing; only reading a file back surfaces it. A workspace that is already
  missing (or that is a file) is refused at `spawn`, which is the only point this policy gets to look.

`langchain>=1.3` is required for this one (the middleware lives in the umbrella package, not in
`langchain-core`), and the floor is measured: 1.3.0 works, 1.2.0 has no such base class.
