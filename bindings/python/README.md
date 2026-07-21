# kern-sandbox

Run LLM/agent-generated code in a fast, **local**, daemonless kernel sandbox from Python.

```python
import kern_sandbox as kern

# one-shot
r = kern.run_code("import sys; print(sys.version)")
print(r.stdout, r.success)

# a session: FILE state persists across steps (a workspace on disk); each step is a fresh box
with kern.Sandbox(setup="pip install pandas matplotlib") as sbx:
    sbx.write_file("data.csv", "a,b\n1,2\n3,4\n")
    r = sbx.run_code("import pandas as pd; print(pd.read_csv('data.csv').shape)")   # (2, 2)
    sbx.run_code(
        "import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as p; "
        "p.plot([1, 4, 9]); p.savefig('out.png')"
    )
    png = sbx.read_file("out.png")   # bytes of the plot the previous step created
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
resident interpreters holding RAM) instead of a cloud-session model. If you need in-memory Jupyter-style
state, this isn't that, and that's the point.

## Why this and not a cloud sandbox

E2B / Modal / Daytona run code in cloud microVMs, control plane, API key, KVM, network latency.
**kern-sandbox runs on your own machine, in CI, on an edge box**: no daemon, no cloud, no account,
no KVM. The sandbox for an agent's dev loop, a CI step, or an air-gapped host.

## Performance

Measured on one x86_64 laptop (kern 0.6.5, `python:3.12-slim`), not aspirational. Your hardware will
differ, measure and claim your own number.

**Single call, sequential** (p50):

| call (p50) | `enforce_limits=False` | default (`enforce_limits=True`) |
| --- | --- | --- |
| `run(["true"])` (bare box) | ~3.5 ms | ~7.5 ms |
| `run_code("print(1)")` (+ Python interpreter start) | ~16 ms | ~32 ms |
| `docker run python:3.12-slim python3 -c` | n/a | ~344 ms |

For reference, `kern box` **natively** (no Python wrapper) is ~1.9 ms, the ~3.5 ms bare-box row is that
plus the wrapper's subprocess + reader-thread overhead.

`run_code` runs *Python code*, so it pays the **CPython interpreter start** (~12 ms) on top of the box,
that's a Python cost, not kern's, and it's why `run_code` is ~16 ms, not the bare box's ~3.5 ms. Even so:
**~16 ms vs Docker's ~344 ms is about 20× faster** for the same task, and we quote the number you get from
`run_code`, never the bare-box best case dressed up as the code-execution number.

**Concurrency**: the default hard-enforces caps via a per-call systemd scope, which **contends under
heavy parallelism**. 100 concurrent `run_code` calls, 100/100 succeeded, zero leaked boxes, but:

| 100 concurrent `run_code` | wall | per-call p50 | per-call p95 |
| --- | --- | --- | --- |
| default (`enforce_limits=True`) | ~0.58 s | ~510 ms | ~550 ms |
| `enforce_limits=False` (best-effort caps) | ~0.12 s | ~59 ms | ~89 ms |

If you fire many boxes concurrently and can accept best-effort (not hard-enforced) resource caps, set
`enforce_limits=False` for the ~5× density win. The default stays hard-enforced and safe.

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
)
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

**Network policy:** the network is on **only** during `setup=` (a separate box that dies when setup
ends); every `run_code` runs network-off. There is no per-call network override, `network=True` is a
session-level, explicit choice.

**Dependencies (`setup=`)** install into `<workspace>/.deps` (on `PYTHONPATH`). By default that dir is
writable, so code run in a session *can* modify the deps a later step in the **same session** sees
(sessions are isolated from each other, distinct workspace). If you run untrusted code and need dep
integrity across steps, pass `deps_readonly=True`.

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
    success: bool                # exit_code == 0 AND fault is None
```

**A Python exception in your code is NOT a fault**: it's `exit_code != 0`, a traceback in `stderr`,
`fault is None`. `fault` is set only when the sandbox stopped the code:

- `timeout`, the call exceeded `timeout_s` (the binding owns and enforces this deadline).
- `escape_blocked`, a syscall was blocked by the seccomp filter (SIGSYS).
- `killed`, the box was SIGKILLed, not by our deadline (message notes it's *likely* OOM; the binding
  can't read the box cgroup to confirm, so it won't claim `oom` as the type).
- `startup_failed`, kern couldn't start the box (best-effort, from kern's own diagnostics).

## API

- `kern.run_code(code, **kwargs)`, one-shot: a throwaway `Sandbox` under the hood. Returns an `ExecutionResult`.
- `Sandbox(...).run_code(code, language="python"|"bash"|"node")`, run code on the session workspace (fresh box).
- `Sandbox(...).run(argv_list)`, run an arbitrary command (an **argv list**, never a shell string).
- `Sandbox(...).write_file(path, data)` / `.read_file(path)` / `.list_files(subdir="")`, workspace I/O,
  confined to `/workspace` (symlink- and `..`-safe).
- `Sandbox(...).snapshot(dest)` / `.restore(src)`, a portable `.tar.gz` FILESYSTEM checkpoint of the
  workspace (not a memory snapshot). `restore` refuses absolute, `..` and symlink members.

## Returning charts, rich results, live output, and checkpoints

**Rich results (the "code interpreter" pattern).** Like a Jupyter/E2B cell, `run_code` captures rich,
mime-typed values into `result.results` (a list of `Result`), with **no Jupyter kernel**: it captures
the value of the code's **last bare expression**, every **`display(obj)`** call, and **every open
matplotlib figure automatically** (no `savefig` needed). Each `Result.data` maps a MIME type to its
payload; convenience accessors: `.png`/`.jpeg` (bytes), `.html`, `.svg`, `.markdown`, `.json`, `.text`.

```python
with kern.Sandbox(setup="pip install matplotlib pandas") as sbx:
    r = sbx.run_code("import matplotlib; matplotlib.use('Agg')\n"
                     "import matplotlib.pyplot as plt; plt.plot([1, 4, 9])")
    png = r.results[0].png              # PNG bytes of the figure, auto-captured; send to the model

    r = sbx.run_code("import pandas as pd; pd.DataFrame({'a': [1, 2]})")
    r.results[0].html                  # the DataFrame as an HTML table (also .text for plain)
```

Capture never touches `stdout`/`stderr`/`exit_code`; a statement that returns `None` (e.g. `print(...)`)
produces no result. You can still write an artifact to the workspace and `read_file` it if you prefer.

**Live output.** Pass `on_stdout` / `on_stderr` callbacks to stream each chunk as it arrives (the full
capped output is still in `result.stdout`). The callback is best-effort, not lossless: a slow callback
drops chunks rather than applying backpressure to the box.

```python
kern.run_code("for i in range(3): print(i)", on_stdout=lambda b: print(b.decode(), end=""))
```

**Checkpoints.** `snapshot`/`restore` (or reusing a `workspace=` path) resume the file state of a
session later or on another host, cheaply and without a running VM.

## Threat model (honest)

kern is a **kernel-boundary** sandbox for **your own or semi-trusted** code. The seccomp filter is a
**denylist**: suitable for semi-trusted agent code, **not** a hard boundary against deliberately
hostile multi-tenant code. For that, use a microVM (Firecracker / Kata) or gVisor. A deny-by-default
allowlist mode is on the roadmap. See the project
[SECURITY.md](https://github.com/getkern/kern/blob/main/SECURITY.md).

## Requirements

The `kern` binary on `PATH` (or set `$KERN_BIN`). Linux only.

## License

Apache-2.0.
