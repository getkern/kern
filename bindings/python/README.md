# kern-sandbox

**[kern](https://getkern.dev)** is a fast, rootless sandbox and virtual resource
runtime for any workload, including untrusted and AI-generated code: a real, kernel-enforced box
that starts in **~3.5 ms** from an OCI image, out of one **1.52 MB** binary, with no daemon.
**kern-sandbox**
is its Python binding: run untrusted or agent-generated code in a fresh, isolated box, straight from Python.

On PyPI: [`pip install kern-sandbox`](https://pypi.org/project/kern-sandbox/). For Node / TypeScript, the
same package is on npm: [`kern-sandbox`](https://www.npmjs.com/package/kern-sandbox).

```python
import kern_sandbox as kern

# one-shot
r = kern.run_code("import sys; print(sys.version)")
print(r.stdout, r.success)

# a session: FILE state persists across steps (a workspace on disk); each step is a fresh box.
# rich results are captured like a Jupyter cell (no Jupyter kernel): the last expression, any
# display(), and every matplotlib figure land in result.results as mime-typed values.
with kern.Sandbox(setup="pip install pandas matplotlib") as sbx:
    sbx.write_file("data.csv", "a,b\n1,2\n3,4\n")
    r = sbx.run_code("import pandas as pd; pd.read_csv('data.csv').describe()")
    r.results[0].html   # the DataFrame as an HTML table (also .text)

    r = sbx.run_code("import matplotlib; matplotlib.use('Agg')\n"
                     "import matplotlib.pyplot as p; p.plot([1, 4, 9])")
    png = next((x.png for x in r.results if x.png), None)   # chart PNG bytes, auto-captured (no savefig)
```

A thin, safe wrapper around the [`kern`](https://github.com/getkern/kern) binary, it shells out to
`kern box`, it does **not** re-implement isolation in Python. Each `run_code`/`run` spawns a fresh,
ephemeral kernel sandbox (user namespace + seccomp + cgroups). See [Performance](#performance) for
measured numbers.

## The model: file-state persists, processes are ephemeral

- **File state persists between steps** via a `/workspace` directory on disk, shared into every box.
  Write a file in one `run_code`, read it in the next.
- **Processes are ephemeral**: each call is a *fresh* box. **In-memory REPL state does NOT persist**,
  a `x = 40` set in one call is gone in the next. Write to disk if you need continuity (agents should
  anyway: it survives crashes and is inspectable).

This is deliberate. It keeps the cold-start/density win (hundreds of ephemeral boxes, not hundreds of
resident interpreters holding RAM) instead of a cloud-session model. When you *do* want in-memory state
across steps (a REPL, a notebook, an agent loop), open a `kernel()` (see below): one warm interpreter
that keeps state, with an explicit isolation trade. The default `run_code` stays ephemeral.

## Why this and not a cloud sandbox

E2B / Modal / Daytona run code in cloud microVMs, control plane, API key, KVM, network latency.
**kern-sandbox runs on your own machine, in CI, on an edge box**: no daemon, no cloud, no account,
no KVM. The sandbox for an agent's dev loop, a CI step, or an air-gapped host.

## Performance

Measured on one x86_64 desktop (Intel i7-14700KF, Linux 7.0.0, rootless, cgroup delegated),
`python:3.12-slim`, re-measured on 2026-08-23 against the released binary and this SDK. p50 over 25
calls after a discarded warmup, every row from the same session. Not aspirational. Your hardware will
differ, measure and claim your own number.

**Single call, sequential** (p50):

| call (p50) | `enforce_limits=False` | default (`enforce_limits=True`) |
| --- | --- | --- |
| `run(["true"])` (bare box) | 3.7 ms | 3.8 ms |
| `run_code("print(1)")` (+ Python interpreter start) | 13.1 ms | 13.5 ms |
| `docker run --rm python:3.12-slim python3 -c` | n/a | 290 ms |

For reference, `kern box --image python:3.12-slim` **natively** (no Python wrapper) is 3.85 ms on the
same machine in the same session, so the binding's own cost is inside the run-to-run spread here: one
subprocess, two reader threads, and the flags the binding adds that the native run does not (`--ro`,
the caps, the workspace mount). It was **0.23 ms** when this table was first measured; it is not
something to quote to three decimals.

That figure was **+3.9 ms in an earlier binding**, and almost all of it was one line of CPython. The binding
enforced its own deadline with `Popen.wait(timeout=...)`, which does not block on the child: it polls
on an exponential backoff whose wake-ups land at 0.5, 1.5, 3.5, 7.5, 15.5 and 31.5 ms. A bare box
finishing at 4.0 ms was therefore not noticed until 7.5, and a `run_code` finishing at 13.6 not until
15.5, which is why the old table read 7.56 and 16.0 and why 200 identical calls used to land on three
discrete values instead of a distribution. The wait is now a `poll(2)` on a pidfd, which becomes
readable the moment the box exits, so there is nothing left to round up to.

**`enforce_limits=False` is no longer a speed knob, and the two columns above are the evidence.**
It sets `KERN_NO_SCOPE=1`, which skips the per-box cgroup scope. That used to be a `systemd-run`
round trip and cost several milliseconds, which is where "about twice as fast" came from. kern now
applies the caps directly in its own delegated slice, and the difference measured
here is **0.19 ms, a ratio of 1.05×**, against giving up hard memory and PID enforcement. On a host
where cgroups cannot be delegated at all the old cost does return, so the option stays; on a normal
delegated host, turning it off buys nothing and costs the caps. **Leave it on.**

`run_code` runs *Python code*, so it pays the **CPython interpreter start** on top of the box, that's
a Python cost, not kern's, and it is why `run_code` is ~13.5 ms against the bare box's ~3.5. Even so:
**~13.5 ms against `docker run --rm python:3.12-slim python3 -c` at ~290 ms is about 21× faster** for
the same task, and we quote the number you get from `run_code`, never the bare-box best case dressed up
as the code-execution number.

The image is part of the claim, not decoration: the same call on `python:3.12-alpine` reads ~17 ms,
because that interpreter starts slower, and a table that mixed the two would compare kern against
itself. Every row here is `python:3.12-slim`, including docker's.

**Concurrency**: 100 concurrent `run_code` calls on one `Sandbox`, 100/100 succeeded, zero leaked
boxes, measured in the same session as the table above:

| 100 concurrent `run_code` | wall | per-call p50 | per-call p95 |
| --- | --- | --- | --- |
| default (`enforce_limits=True`) | 0.30 s | 211 ms | 241 ms |
| `enforce_limits=False` (best-effort caps) | 0.31 s | 210 ms | 237 ms |

The gap is **1.03× on wall clock**, with the default marginally ahead, which is to say the two are
the same to within the noise of the measurement. The same conclusion holds under load as it does
sequentially: turning enforcement off is not a density win any more. It was one when caps meant a
`systemd-run` scope per call; they no longer do. **Leave the default on.** Note that a
per-call p50 of 211 ms here is queueing, not latency: 100 boxes are competing for the machine, and
the wall clock, 0.30 s for all 100, is the figure that describes it.

Concurrent calls on one `Sandbox` are now safe and were not in an earlier binding: every call wrote the
same host-side `--env-file` path, so two in flight at once fought over it. In Python the loser got a
`FileExistsError` out of `run_code` (11 of 40 calls, measured); in Node one call deleted the file
while kern was still starting for another, and that box died with
`cannot read --env-file '...': No such file or directory`. The file is now named per call.

## Safe by default

A bare `Sandbox()` has **no network, no host mounts, seccomp on, dangerous caps dropped, and a
mandatory finite timeout**. Every relaxation is an explicit, named argument.

```python
Sandbox(
    image="python:3.12-slim",   # OCI image (default: a small Python base)
    setup="pip install pandas", # the ONLY network window, a separate net-on setup box; run_code is net-off
    workspace=None,             # None → temp dir, deleted on __exit__; a path → persists across sessions
    memory_mb=512,
    cpus=None,                  # CPU cap in cores (e.g. 1.5); None = uncapped
    pids=256,                   # fork-bomb ceiling
    timeout_s=30,               # MANDATORY per-call wall-clock limit
    network=False,              # RELAXES ISOLATION, True shares the host network for every run
    mounts=None,                # {host_src: box_target} or {src: (target, "ro")}; sensitive sources refused
    profiles=None,              # reusable kern.toml profiles: ["vcpu:heavy", "vgpio:leds", "vdisk:scratch"]
    max_output_bytes=64 << 20,  # cap on captured stdout/stderr EACH; overflow discarded, result.truncated set
    deps_readonly=False,        # True → run_code can't modify setup= deps (blocks cross-run poisoning)
    enforce_limits=True,        # hard-enforce caps via a systemd scope; False = best-effort, faster under load
    security_profile=None,      # "untrusted" = seccomp allowlist + cap-drop ALL + read-only root, one opt-in
    apparmor=None,              # a PRE-LOADED AppArmor profile the box enters on exec (Docker's
                                # --security-opt apparmor=), an LSM layer over seccomp; kern fails the box
                                # CLOSED if the profile isn't loaded on the host.
    require_limits=False,       # True = FAIL-CLOSED: refuse to start unless memory/pids caps are enforced.
                                # NOT enforce_limits (which only picks the cap PATH: scope vs best-effort);
                                # mutually exclusive with the KERN_ALLOW_UNCAPPED env (forwarded to kern).
    cap_drop=("ALL","..."),  # capabilities dropped from every box; default drops ALL.
                            # kern always drops 16 dangerous ones; this drops the rest,
                            # which were held over the box's own user namespace. Pass
                            # cap_drop=() to keep them (needed only if the workload binds
                            # a port below 1024 INSIDE the box).
    track_files=True,           # populate result.files by diffing the workspace each call (O(files)); a long
)                               # session that accretes files slows run_code -> set False (result.files [], O(1))
```

Host mounts over sensitive sources (`/`, `/etc`, `$HOME`, the docker socket, …) are **refused even if
you ask**. Captured output is **bounded** (`max_output_bytes` each), a flooding box can't OOM the host.

**Resource profiles (`profiles=`)** attach reusable slices you defined once in
`~/.config/kern/kern.toml`: `vcpu:NAME` (a CPU + memory slice), `vdisk:NAME` (a size-capped scratch
disk), and `vgpio:NAME` (a specific GPIO/I2C/SPI device set, the **only** way to grant the box
hardware, for edge/robotics agents). Each token is strictly validated (`prefix:alphanumeric-name`), so
a profile entry can never smuggle another flag:

```python
with kern.Sandbox(profiles=["vcpu:heavy", "vgpio:sensors"]) as sbx:
    sbx.run_code("import board  # only /dev/i2c-1 from the vgpio:sensors profile is visible")
```

A `vcpu:` profile can carry both `cpus=` and `memory=`. **Precedence:** `memory_mb`/`cpus` are passed as
explicit flags, and kern's "explicit flag wins over profile" rule means they **override** the profile's
own values. Since `memory_mb` defaults to `512`, that default **shadows** a profile's `memory=`; pass
`memory_mb=None` (and/or `cpus=None`) to let the profile's slice apply, or set the value you want.

**Network policy:** the network is on **only** during `setup=` (a separate box that dies when setup
ends); every `run_code` runs network-off. There is no per-call network override, `network=True` is a
session-level, explicit choice.

**Dependencies (`setup=`)** install into `<workspace>/.deps` (on `PYTHONPATH`). By default that dir is
writable, so code run in a session *can* modify the deps a later step in the **same session** sees
(sessions are isolated from each other, distinct workspace). If you run untrusted code and need dep
integrity across steps, pass `deps_readonly=True`.

The setup box runs under the **same `memory_mb` cap** as your `run_code` calls. A heavy install
(`pip install pandas numpy matplotlib`, `torch`, ...) can OOM-kill setup (exit -9) at the default
512 MB, raise `memory_mb` for the session (e.g. `memory_mb=1536`) when you install a large stack.

## Results, and what a fault means

```python
@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    fault: SandboxFault | None   # set ONLY when the SANDBOX acted; None for ordinary user-code failures
    files: list[FileInfo]        # workspace files created/modified this step (.deps excluded)
    results: list[Result]        # rich mime-typed values: last expression, display(), matplotlib figures
    truncated: bool              # stdout/stderr hit max_output_bytes and the overflow was discarded
    success: bool                # exit_code == 0 AND fault is None
```

**A Python exception in your code is NOT a fault**: it's `exit_code != 0`, a traceback in `stderr`,
`fault is None`. `fault` is set only when the sandbox stopped the code:

- `timeout`, the call exceeded `timeout_s` (the binding owns and enforces this deadline).
- `escape_blocked`, a syscall was blocked by the seccomp filter (SIGSYS).
- `oom`, the box was SIGKILLed and a `memory_mb` cap was **in force**: a breached `memory.max` is the
  cgroup OOM-killer (kern sets `memory.oom.group=1`, so the whole box dies at once). "In force" is not
  guessed: kern reports, on an unforgeable per-box channel (the 2nd byte of `KERN_STARTED_FD`, not the
  workload's stderr), whether the cap actually bound. So a newer kern makes this an *enforced-cap* OOM.
- `killed`, the box was SIGKILLed but it is **not** attributed to a cgroup OOM: either no `memory_mb`
  cap was set, or kern reported the cap did **not** bind here (no cgroup delegation), so the SIGKILL is
  host memory pressure or an external kill rather than the box's own ceiling. Against an older kern that
  does not send the enforcement byte, a SIGKILL with a `memory_mb` cap set falls back to `oom`.

A box that fails to **start** (kern exits 125: a mount refused at runtime, an unmappable `--user`, a
seccomp/AppArmor/cgroup setup error, or a pull/image error) is **raised** as a `SandboxError`, not
returned as a fault, because the code never ran.

## API

- `kern.run_code(code, **kwargs)`, one-shot: a throwaway `Sandbox` under the hood. Returns an `ExecutionResult`.
- `Sandbox(...).run_code(code, language="python"|"bash"|"node")`, run code on the session workspace (fresh box).
- `Sandbox(...).run(argv_list)`, run an arbitrary command (an **argv list**, never a shell string).
- `Sandbox(...).write_file(path, data)` / `.read_file(path)` / `.list_files(subdir="")`, workspace I/O,
  confined to `/workspace` (symlink- and `..`-safe).
- `Sandbox(...).snapshot(dest)` / `.restore(src)`, a portable `.tar.gz` FILESYSTEM checkpoint of the
  workspace (not a memory snapshot). `restore` refuses absolute, `..` and symlink members.

## Returning charts, rich results, live output, and checkpoints

**Rich results (the "code interpreter" pattern).** Like a Jupyter cell, `run_code` captures rich,
mime-typed values into `result.results` (a list of `Result`), with **no Jupyter kernel**: it captures
the value of the code's **last bare expression**, every **`display(obj)`** call, and **every open
matplotlib figure automatically** (no `savefig` needed). Each `Result.data` maps a MIME type to its
payload; convenience accessors: `.png`/`.jpeg` (bytes), `.html`, `.svg`, `.markdown`, `.json`, `.text`.

```python
with kern.Sandbox(setup="pip install matplotlib pandas") as sbx:
    r = sbx.run_code("import matplotlib; matplotlib.use('Agg')\n"
                     "import matplotlib.pyplot as plt; plt.plot([1, 4, 9])")
    png = next((x.png for x in r.results if x.png), None)   # figure PNG bytes; send to the model

    r = sbx.run_code("import pandas as pd; pd.DataFrame({'a': [1, 2]})")
    r.results[0].html                  # the DataFrame as an HTML table (also .text for plain)
```

Capture never touches `stdout`/`stderr`/`exit_code`; a statement that returns `None` (e.g. `print(...)`)
produces no result. You can still write an artifact to the workspace and `read_file` it if you prefer.

**Warm kernel (kill the interpreter boot).** Each `run_code` starts a **fresh** interpreter, so it pays
the CPython boot (~12 ms) every call. When you run many cells that share state (a REPL, a notebook, an
agent's tool loop), open a `kernel()`: ONE warm interpreter in a long-lived box, fed cells over a pipe.
In-memory state persists across cells and the per-cell cost drops from ~14 ms to **sub-millisecond**
(~300x). Same rich `results` capture as `run_code`.

```python
with kern.Sandbox() as sbx, sbx.kernel() as k:
    k.run_code("import numpy as np; a = np.arange(1_000_000)")   # imports paid once
    r = k.run_code("a.sum()")                                    # 'a' is still here; ~sub-ms
    print(r.results[0].text)                                     # 499999500000
```

The trade vs `run_code`: cells in a kernel share one process and one box, so it is call-fast but not
call-isolated (still network-off and resource-capped like any box; a fresh session or kernel is clean).
An uncaught error is confined (rc=1, traceback on `stderr`, the kernel keeps serving); a per-cell
`timeout_s` tears the kernel down (a running cell cannot be interrupted without killing the interpreter),
after which the kernel refuses further cells with a clear error.

**Per-call overrides.** `run_code(...)` and `run(...)` accept `timeout_s`, `on_stdout` and `on_stderr`
as per-call arguments that override the session defaults for that one call (`timeout_s=None` inherits
the session's; a callback defaults to the session's, an explicit `None` disables it for the call).

**Live output.** Pass `on_stdout` / `on_stderr` callbacks to stream each chunk as it arrives (the full
capped output is still in `result.stdout`). The callback is best-effort, not lossless: a slow callback
drops chunks rather than applying backpressure to the box.

```python
kern.run_code("for i in range(3): print(i)", on_stdout=lambda b: print(b.decode(), end=""))
```

**Checkpoints.** `snapshot`/`restore` (or reusing a `workspace=` path) resume the file state of a
session later or on another host, cheaply and without a running VM.

## Use it from Claude Desktop / Cursor (MCP)

The package ships **`kern-mcp`**, a dependency-free [Model Context Protocol](https://modelcontextprotocol.io)
stdio server that exposes the sandbox as a **local** code-interpreter tool: the model writes code, kern
runs it on your machine, and charts come back as images the model can see. Point any MCP client at it:

```json
{
  "mcpServers": {
    "kern": {
      "command": "kern-mcp",
      "env": { "KERN_MCP_SETUP": "pip install numpy pandas matplotlib" }
    }
  }
}
```

Tools: `run_code` (python/bash/node), `write_file`, `read_file`, `list_files`. File state persists across
calls (a workspace on disk); each call is a fresh, **network-off** box. Optional env: `KERN_MCP_IMAGE`,
`KERN_MCP_SETUP` (a one-time `pip install`), `KERN_MCP_MEMORY_MB`, `KERN_MCP_TIMEOUT`, `KERN_MCP_WORKSPACE`
(persist the workspace), `KERN_MCP_PROFILES` (comma-separated kern.toml profiles, e.g.
`vcpu:heavy,vgpio:sensors`, the only way to grant an edge agent a hardware device set). Run it standalone
with `python -m kern_sandbox.mcp`.

Two knobs change what the model is told, so they are worth naming: `KERN_MCP_KERNEL=1` routes Python
through one persistent warm interpreter, which makes in-memory state persist across calls and is the one
case where "a fresh box per call" above stops being true (the tool description says so to the model as
well, rather than leaving it to guess). `KERN_MCP_QUIET=0` restores kern's non-fatal notes, which are off
by default so a tool call returns only the cell's own output.

## Use it from LangChain

`kern_sandbox.langchain` turns a session into a tool an agent can call. `langchain-core` is an optional
extra and is imported only when you build the tool, so the package itself stays dependency-free.

```bash
pip install 'kern-sandbox[langchain]'
```

```python
from kern_sandbox.langchain import kern_code_tool

tool = kern_code_tool(memory_mb=512, timeout_s=30)
agent = create_agent(model, [tool])
```

The tool holds one session, so a file written by one call is there for the next, and each call still runs
in a fresh box. What comes back is written for a model to act on: stdout, the value of a trailing bare
expression, and **the traceback when the code raises**, which is what the agent needs in order to fix it.
A sandbox fault is labelled as such (`[sandbox: timeout]`, `oom`, `escape_blocked`) so the model does not
try to debug code that was killed for asking for 4 GB. Output is capped at `max_chars` (8000 by default,
head and tail) because the sandbox caps capture at 64 MiB, which protects the host and not a context
window.

Everything a box prints is untrusted text on its way into a model's context, so the rendering strips
terminal escapes and control characters, and neutralises the framing above wherever the **code** produced
it: a cell that prints `[sandbox: oom]` would otherwise claim, byte for byte, that the sandbox killed it.
Ordinary prompt injection is **not** filtered and cannot be at this layer, because a run whose output is
`[system] ignore your instructions` is a run that printed a string, and no filter separates that from a
program legitimately printing the same characters. Deciding what a model may act on belongs above this.

Capped: wall clock (enforced even against a workload that traps `SIGTERM`), memory, processes, the code
coming in (`max_code_bytes`) and the text going back. **Not capped: the workspace on disk.** It is a host
directory bind-mounted into every box, which is what makes file state persist, and nothing bounds it: a
cell writing in chunks put 400 MB on the host with `memory_mb=128`, since a memory cap only stops the
version that builds the payload in RAM first. Where that matters, pass a `workspace=` on a filesystem you
have already bounded (a size-mounted tmpfs, or a path under a quota).

The tool description is generated from the session, so the memory cap, the deadline and whether there is
any network are stated to the model as they actually are. Startup failures (no `kern` on `PATH`, an image
that will not pull) raise instead of being returned: an agent cannot fix those by rewriting its code, and
handing it the message only buys a retry loop against a broken host.

Pass `language="bash"` or `language="node"` for the other two, or your own open `Sandbox` as the first
argument when you want to own its lifetime.

## Use it as a LangChain execution policy (the shell middleware)

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

## Threat model (honest)

kern is a **kernel-boundary** sandbox for **your own or semi-trusted** code. Its default seccomp
filter is a **deny-by-default allowlist** (moby's own default filter minus kern's 35 escape syscalls):
suitable for semi-trusted agent code, **not** a hard boundary against deliberately hostile
multi-tenant code. For that, use a microVM (Firecracker / Kata) or gVisor. The wider denylist is the
opt-out (`KERN_SECCOMP=denylist`), and `security_profile="untrusted"` bundles the allowlist with
`--cap-drop ALL` + `--read-only`. See the project
[SECURITY.md](https://github.com/getkern/kern/blob/main/SECURITY.md).

## Requirements

The `kern` binary on `PATH` (or set `$KERN_BIN`). A Linux kernel with unprivileged user namespaces +
cgroup v2; on Windows it runs under WSL2. Python 3.9+.

**On a Mac this package installs but cannot run**, and it says so instead of looking for a download
that does not exist: kern is Linux-only, because macOS has no namespaces and no cgroups. Run your code
inside a Linux VM (colima, Lima, OrbStack, UTM), install `kern` and this package there, and everything
works as on Linux. Verified on Apple Silicon with an Ubuntu 24.04 guest.
[Install notes for macOS](https://github.com/getkern/kern/blob/main/docs/INSTALL.md).

## License

Apache-2.0.
