# kern-sandbox

**[kern](https://github.com/getkern/kern)** is a fast, rootless sandbox and virtual resource
runtime for any workload, including untrusted and AI-generated code: a real, kernel-enforced box
that starts in **3.4 ms** from an OCI image, out of one **1.58 MB** binary, with no daemon.
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
`python:3.12-slim`, on 2026-08-02. p50 over 25 calls after a discarded warmup, every row from
the same session. Not aspirational. Your hardware will differ, measure and claim your own number.

**Single call, sequential** (p50):

| call (p50) | `enforce_limits=False` | default (`enforce_limits=True`) |
| --- | --- | --- |
| `run(["true"])` (bare box) | 4.03 ms | 4.22 ms |
| `run_code("print(1)")` (+ Python interpreter start) | 13.55 ms | 13.87 ms |
| `docker run --rm python:3.12-slim python3 -c` | n/a | 285 ms |

For reference, `kern box --image python:3.12-slim` **natively** (no Python wrapper) is 3.80 ms on the
same machine in the same session, so the 4.03 ms bare-box row is that plus **0.23 ms** of wrapper:
one subprocess, two reader threads, and the flags the binding adds that the native run does not
(`--ro`, the caps, the workspace mount).

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
a Python cost, not kern's, and it is why `run_code` is 13.9 ms against the bare box's 4.2. Even so:
**13.9 ms against Docker's 285 ms is about 20× faster** for the same task, and we quote the number you
get from `run_code`, never the bare-box best case dressed up as the code-execution number.

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
                            # kern always drops 14 dangerous ones; this drops the rest,
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
- `oom`, the box was SIGKILLed and a `memory_mb` cap was in effect: a breached `memory.max` is the
  cgroup OOM-killer (kern sets `memory.oom.group=1`, so the whole box dies at once). The signal is the
  `--memory` flag *we* set, not the workload's stderr, so it costs no security discipline to claim it.
- `killed`, the box was SIGKILLed with **no** memory cap set, so the cause is ambiguous (host memory
  pressure, an external kill) and the binding will not attribute it to OOM.

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

## License

Apache-2.0.
