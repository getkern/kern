# kern-sandbox

**Run AI-generated code in a real sandbox, one fresh box per call, in about 4 ms.**

`kern-sandbox` is the Python binding for **[kern](https://getkern.dev)**: a rootless,
kernel-enforced sandbox out of one static binary, with no daemon, no VM and no cloud. An agent's
tool-call, a model's generated snippet, a notebook cell, a CI step: code that runs before anyone
reads it gets its own box, and the box is thrown away after.

```bash
pip install kern-sandbox
```

```python
import kern_sandbox as kern

r = kern.run_code("import sys; print(sys.version)")
print(r.stdout, r.success)
```

Network off, memory and PID caps the kernel enforces, capabilities dropped, a deny-by-default seccomp
allowlist, and a wall-clock deadline applied from **outside** the box, so code that hangs cannot
outlive it. Node and TypeScript get the same package on npm: [`kern-sandbox`](https://www.npmjs.com/package/kern-sandbox).

## The failure comes back as data, not as an exception

This is the part that matters in an agent loop. A timeout, an OOM-kill, a blocked syscall or a
missing interpreter is a **typed field on the result**, beside stdout and the exit code. Your loop
reads a field and decides; it does not parse a traceback to find out that the sandbox, not the code,
ended the run.

```python
r = kern.run_code("while True: pass", timeout_s=5)
r.fault.type      # 'timeout'      the sandbox stopped it
r.success         # False
```

**A Python exception in the code is NOT a fault.** That is `exit_code != 0`, a traceback in `stderr`,
and `fault is None`, because the code ran and the sandbox did nothing. `fault` is set only when the
sandbox acted:

| `fault.type` | what happened |
|---|---|
| `timeout` | the call exceeded `timeout_s`; the binding owns that deadline |
| `oom` | SIGKILL **and** a memory cap that actually bound (kern reports enforcement on an unforgeable per-box channel, not on the workload's stderr) |
| `killed` | SIGKILL that is **not** attributable to the box's own ceiling: host pressure, or a cap that did not bind here |
| `escape_blocked` | a syscall the seccomp filter refused (SIGSYS) |
| `exec_failed` | the box started, the command did not exist in the image; the message names both the binary and the image |

**An enforced `pids` cap produces no fault, deliberately.** A refused `fork` returns `EAGAIN`, which a
program is allowed to catch and exit 0 on, so a contained fork bomb reads as a successful run.
Labelling that a sandbox fault would misreport a process that exited cleanly. The cap is still
enforced: on WSL2, `pids=32` blocked at 29 forks while `pids=256` let 120 through.

A box that fails to **start** raises `SandboxError` instead, because the code never ran.

## Use it from Claude Desktop or Cursor (MCP)

The package ships **`kern-mcp`**, a dependency-free
[Model Context Protocol](https://modelcontextprotocol.io) stdio server that gives the model a local
code interpreter: it writes code, kern runs it on your machine, and charts come back as images the
model can see.

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

Tools: `run_code` (python/bash/node), `write_file`, `read_file`, `list_files`. File state persists
across calls; each call is a fresh, network-off box.

| Env var | Default | What it does |
|---|---|---|
| `KERN_MCP_IMAGE` | `python:3.12-slim` | OCI image the boxes run in |
| `KERN_MCP_SETUP` | (none) | one-time `pip install ...`, the ONLY network-on moment |
| `KERN_MCP_MEMORY_MB` | `1024` | hard RAM cap per box; `0` sends no flag, so a `vcpu:` profile's own `memory=` applies |
| `KERN_MCP_TIMEOUT` | `60` | per-call wall-clock deadline |
| `KERN_MCP_WORKSPACE` | temp dir | persist file state at this path |
| `KERN_MCP_PROFILES` | (none) | attach `kern.toml` profiles, e.g. `vcpu:heavy,vgpio:sensors`: the only way to grant an edge agent a hardware device |
| `KERN_MCP_KERNEL` | off | `1` routes Python through one warm interpreter: state persists, each call is sub-millisecond. The one case where "a fresh box per call" stops being true, and the tool description says so to the model |
| `KERN_MCP_QUIET` | on | `0` restores kern's non-fatal notes |

**Why local rather than hosted.** E2B, Modal and Daytona need an account, an API key and a network
round-trip, and the model's code runs on someone else's machine. This runs on yours: no account, no
egress, works air-gapped, same shape.

## The model: file state persists, processes do not

- **File state persists** through a `/workspace` directory shared into every box. Write a file in one
  call, read it in the next.
- **Processes are ephemeral.** Each call is a fresh box, so **in-memory state does not survive**:
  `x = 40` in one call is gone in the next. Write to disk if you need continuity, which agents should
  do anyway, since it survives a crash and can be inspected.

That is deliberate: it keeps the density (hundreds of ephemeral boxes, not hundreds of resident
interpreters holding RAM). When you do want in-memory state, open a `kernel()`: one warm interpreter
in a long-lived box, per-cell cost **sub-millisecond** instead of a ~12 ms CPython boot, with the
explicit trade that cells share one process and one box.

```python
with kern.Sandbox() as sbx, sbx.kernel() as k:
    k.run_code("import numpy as np; a = np.arange(1_000_000)")
    r = k.run_code("a.sum()")          # 'a' is still here
    print(r.results[0].text)           # 499999500000
```

## Charts and rich results, without a Jupyter kernel

`run_code` captures mime-typed values into `result.results` the way a notebook cell does, with no
Jupyter kernel: the **last bare expression**, every **`display(obj)`**, and **every open matplotlib
figure automatically**, with no `savefig`. Accessors: `.png`, `.jpeg`, `.html`, `.svg`, `.markdown`,
`.json`, `.text`.

```python
with kern.Sandbox(setup="pip install pandas matplotlib") as sbx:
    sbx.write_file("data.csv", "a,b\n1,2\n3,4\n")
    r = sbx.run_code("import pandas as pd; pd.read_csv('data.csv').describe()")
    r.results[0].html          # the DataFrame as an HTML table

    r = sbx.run_code("import matplotlib; matplotlib.use('Agg')\n"
                     "import matplotlib.pyplot as p; p.plot([1, 4, 9])")
    png = next((x.png for x in r.results if x.png), None)   # PNG bytes, send it to the model
```

Capture never touches `stdout`, `stderr` or `exit_code`. Pass `on_stdout` / `on_stderr` to stream
output as it arrives (best-effort: a slow callback drops chunks rather than stalling the box).

## Safe by default

A bare `Sandbox()` has no network, no host mounts, seccomp on, dangerous capabilities dropped and a
**mandatory** finite timeout. Every relaxation is a named argument:

```python
Sandbox(
    image="python:3.12-slim",   # OCI image
    setup="pip install pandas", # the ONLY network window: a separate net-on box; run_code is net-off
    workspace=None,             # None -> temp dir, deleted on exit; a path -> persists
    memory_mb=512,
    cpus=None,                  # CPU cap in cores (e.g. 1.5); None = uncapped
    pids=256,                   # fork-bomb ceiling
    timeout_s=30,               # MANDATORY per-call wall-clock limit
    network=False,              # RELAXES ISOLATION: True shares the host network for every run
    mounts=None,                # {host_src: box_target}; sensitive sources refused even if asked
    profiles=None,              # kern.toml profiles: ["vcpu:heavy", "vgpio:leds", "vdisk:scratch"]
    max_output_bytes=64 << 20,  # cap on captured stdout/stderr EACH; result.truncated on overflow
    deps_readonly=False,        # True -> run_code cannot modify setup= deps
    security_profile=None,      # "untrusted" = seccomp allowlist + cap-drop ALL + read-only root
    apparmor=None,              # a pre-loaded AppArmor profile; kern fails CLOSED if it is not loaded
    require_limits=False,       # True = refuse to start unless memory/pids caps are enforced
    cap_drop=("ALL",),          # default drops ALL; pass () only if the box must bind a port < 1024
)
```

Mounts over sensitive sources (`/`, `/etc`, `$HOME`, the docker socket) are **refused even if you ask
for them**. Captured output is bounded, so a flooding box cannot OOM the host.

**Network policy:** the network is on **only** during `setup=`, in a separate box that dies when
setup ends. There is no per-call override; `network=True` is a session-level, explicit choice.

**Resource profiles** attach slices defined once in `~/.config/kern/kern.toml`: `vcpu:` (CPU and
memory), `vdisk:` (a size-capped scratch disk), `vgpio:` (a specific device set, the **only** way to
give a box hardware). A `vcpu:` profile can carry `memory=`, but `memory_mb` defaults to `512` and an
explicit flag beats a profile, so pass `memory_mb=None` to let the profile's own value apply.

**Not capped: the workspace on disk.** It is a host directory, and file state persisting is the
point. A cell writing in chunks put 400 MB on the host under `memory_mb=128`, because a memory cap
only stops the version that builds the payload in RAM first. Where that matters, point `workspace=`
at a filesystem you have already bounded.

## API

- `kern.run_code(code, **kwargs)`, one-shot: a throwaway `Sandbox` under the hood.
- `Sandbox(...).run_code(code, language="python"|"bash"|"node")` on the session workspace.
- `Sandbox(...).run(argv_list)`, an arbitrary command (an **argv list**, never a shell string).
- `Sandbox(...).write_file(path, data)` / `.read_file(path)` / `.list_files(subdir="")`, workspace
  I/O, confined to `/workspace`, `..`-safe, every path component opened `O_NOFOLLOW`, opened
  `O_NONBLOCK`, and a descriptor that is not a REGULAR file is refused. A symlink is not the only
  thing a box can leave at a name: `mkfifo out.png` used to make `read_file("out.png")` wait for a
  writer that never came, with no timeout, so the box chose how long the host's call took. The flag
  alone would have been worse, since a non-blocking read of a writer-less FIFO returns zero bytes and
  the call would have reported an empty file.
- `Sandbox(...).snapshot(dest)` / `.restore(src)`, a portable `.tar.gz` FILESYSTEM checkpoint of the
  workspace. `restore` refuses absolute, `..` and symlink members.

## Use it from LangChain

```bash
pip install 'kern-sandbox[langchain]'
```

```python
from kern_sandbox.langchain import kern_code_tool

tool = kern_code_tool(memory_mb=512, timeout_s=30)
agent = create_agent(model, [tool])
```

One session, so a file written by one call is there for the next, and each call still runs in a fresh
box. What comes back is written for a model to act on: stdout, the value of a trailing expression,
and **the traceback when the code raises**, which is what the agent needs in order to fix it. A
sandbox fault is labelled (`[sandbox: timeout]`, `oom`, `escape_blocked`) so the model does not try to
debug code that was killed for asking for 4 GB.

Everything a box prints is untrusted text on its way into a context window, so the rendering strips
terminal escapes and neutralises that framing wherever the **code** produced it: a cell printing
`[sandbox: oom]` would otherwise claim, byte for byte, that the sandbox killed it. Ordinary prompt
injection is **not** filtered and cannot be at this layer: a run whose output is `[system] ignore your
instructions` is a run that printed a string, and no filter separates that from a program legitimately
printing the same characters. What a model may act on is decided above this.

There is also a **shell execution policy** for LangChain's shell middleware, the long-lived-session
shape rather than one box per call, and it is a peer of the Docker policy rather than a wrapper beside
it. It has its own page, including the measured differences from `DockerExecutionPolicy` and two
behaviours worth knowing before an agent runs for hours:
[LANGCHAIN-SHELL.md](https://github.com/getkern/kern/blob/main/bindings/python/LANGCHAIN-SHELL.md).

## Performance

One x86_64 desktop (i7-14700KF, Linux 7.0.0, rootless, cgroup delegated), `python:3.12-slim`, p50 over
25 calls after a discarded warm-up, re-measured 2026-09-04 against the released binary and this SDK.
Your hardware will differ: measure and claim your own number.

| call (p50) | kern-sandbox | docker |
|---|---|---|
| `run(["true"])`, bare box | **3.9 ms** | |
| `run_code("print(1)")`, plus the CPython start | **14.3 ms** | ~290 ms |

`run_code` runs *Python*, so it pays the interpreter boot on top of the box. That is a Python cost,
not kern's, and it is why 14.3 rather than 3.9. Even so it is about **20x** faster than
`docker run --rm python:3.12-slim python3 -c` for the same task, and the number quoted is the one
`run_code` gives you, never the bare-box best case dressed up as the code-execution figure.

**The host is part of the row.** The same `run_code("print(1)")` on **WSL2** reads about **40 ms**,
roughly 3x, on a call dominated by the CPython start. Quote the row that matches your host.

**The image is part of the claim.** `python:3.12-alpine` reads ~17 ms, because that interpreter starts
slower. Every row here is `python:3.12-slim`, docker's included.

**Concurrency**: 100 concurrent `run_code` calls on one `Sandbox` complete in **0.30 s** wall clock,
100/100 succeeded, no leaked boxes. The per-call p50 of 211 ms in that run is queueing, not latency:
100 boxes are competing for the machine, and the wall clock is the figure that describes it.

**`enforce_limits=False` is not a speed knob any more.** It sets `KERN_NO_SCOPE=1` and skips the
per-box cgroup scope. That used to be a `systemd-run` round trip worth several milliseconds, which is
where "about twice as fast" came from; kern now applies caps directly in its own delegated slice and
the measured difference is **0.19 ms**, against giving up hard memory and PID enforcement. **Leave it
on.** On a host with no cgroup delegation at all the old cost returns, which is why the option stays.

Full method and the comparison against other runtimes:
[BENCHMARKS.md](https://github.com/getkern/kern/blob/main/BENCHMARKS.md).

## Threat model (honest)

kern is a **kernel-boundary** sandbox for **your own or semi-trusted** code. The default seccomp
filter is a deny-by-default allowlist (moby's own default minus kern's 35 escape syscalls): suitable
for agent-generated code, **not** a hard boundary against deliberately hostile multi-tenant code. For
that, use a microVM (Firecracker, Kata) or gVisor. `security_profile="untrusted"` bundles the
allowlist with `--cap-drop ALL` and `--read-only`. The full statement is in
[SECURITY.md](https://github.com/getkern/kern/blob/main/SECURITY.md).

## Requirements

The `kern` binary on `PATH` (or `$KERN_BIN`). A Linux kernel with unprivileged user namespaces and
cgroup v2; on Windows it runs under WSL2. Python 3.9+.

**On a Mac this package installs but cannot run**, and it says so rather than looking for a download
that does not exist: kern is Linux-only, because macOS has no namespaces and no cgroups. Run it inside
a Linux VM (colima, Lima, OrbStack, UTM). Verified on Apple Silicon with an Ubuntu 24.04 guest.
[Install notes](https://github.com/getkern/kern/blob/main/docs/INSTALL.md).

## License

Apache-2.0.
