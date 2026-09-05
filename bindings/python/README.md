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

## Your loop reads a field, not a stack trace

This is the part that matters in an agent loop. A timeout, an OOM-kill, a blocked syscall or a
missing interpreter each arrive as a **typed field on the result**, beside stdout and the exit code.
The agent branches on a value and keeps going, instead of parsing a traceback to work out whether the
sandbox stopped the run or the code did.

```python
r = kern.run_code("while True: pass", timeout_s=5)
r.fault.type      # 'timeout'      the sandbox stopped it
r.success         # False
```

Every call returns an `ExecutionResult`:

```python
@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    fault: SandboxFault | None   # set ONLY when the SANDBOX acted
    files: list[FileInfo]        # workspace files created or modified this step (.deps excluded)
    results: list[Result]        # rich mime-typed values: last expression, display(), matplotlib
    truncated: bool              # output hit max_output_bytes and the overflow was discarded
    success: bool                # exit_code == 0 AND fault is None
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

Tools: `run_code` (python/bash, and node on an image that has it), `write_file`, `read_file`,
`list_files`. File state persists across calls; each call is a fresh, network-off box. The tool
schema names the configured image and says which interpreters it provides, so the model is not left
to infer that from the enum.

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
| `KERN_MCP_TMPFS_MB` | `64` | scratch at `/tmp`, charged to the box's own memory cap; `0` removes it and puts `/tmp` back inside the read-only root |

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

`sbx.kernel()` returns a `Kernel`, and a refused mount raises `MountRefused` rather than the generic
`SandboxError`, so a caller can tell "you asked for something this sandbox will not do" from "the
sandbox broke".

```python
with kern.Sandbox() as sbx, sbx.kernel() as k:
    k.run_code("import numpy as np; a = np.arange(1_000_000)")
    r = k.run_code("a.sum()")          # 'a' is still here
    print(r.results[0].text)           # 499999500000
```

## Prewarming: a box ready before the call arrives

`prewarm=N` keeps N boxes started in advance, each holding a booted interpreter that has run nothing.
A `run_code` then claims one instead of paying for a box start plus a CPython boot. Measured on this
machine, `python:3.12-slim`, six calls each:

| | first call | p50 |
|---|---:|---:|
| default | 30.9 ms | 14.2 ms |
| `prewarm=4` | 0.9 ms | **0.8 ms** |

The refill happens on a worker thread while your agent thinks, so it is off the caller's clock. That
also says when it buys nothing: if calls arrive faster than the pool refills, the pool empties and you
are back to the default cost. N is the burst you want covered, not a throughput setting.

Each prewarmed box serves ONE call and is thrown away, so the isolation is exactly what it was: a
fresh box per call, network off, the same caps. What changes is when the box was created, not how many
calls share it. That is the difference from `kernel()`, which deliberately shares one process across
cells and says so.

```python
with kern.Sandbox(image="python:3.12-slim", prewarm=4) as sbx:
    r = sbx.run_code("print(1)")     # served from the pool
```

The pool key includes the image, the caps and the profiles, so a session with different settings never
receives a box built for another one.

## Run pi's coding tools in a box

[`integrations/pi`](https://github.com/getkern/kern/tree/main/integrations/pi) is an extension for
[pi](https://github.com/earendil-works/pi) that routes its built-in `bash`, `read`, `write`, `edit`,
`ls`, `grep` and `find` tools through this SDK into a kern box. Your working directory is mounted at
`/workspace`, so edits write through to the host and everything else a command touches dies with the
box. pi's default posture is no sandbox at all: it runs as the user who launched it.

The two halves are not confined by the same thing, and the extension's README states which is which:
`bash` runs INSIDE the box (namespaces, seccomp allowlist, cgroup caps), while `read` and the staging
half of `write` are host filesystem calls guarded by this SDK's `O_NOFOLLOW` plus the `/proc/self/fd`
containment check. Needs Linux, the `kern` binary, and Node 22 or newer.

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
    tmpfs=None,                 # None -> 64 MiB of scratch at /tmp; {} -> none; {"/tmp": "512m"}
    profiles=None,              # kern.toml profiles: ["vcpu:heavy", "vgpio:leds", "vdisk:scratch"]
    max_output_bytes=64 << 20,  # cap on captured stdout/stderr EACH; result.truncated on overflow
    deps_readonly=True,         # run_code cannot modify setup= deps; False re-opens it
    security_profile=None,      # "untrusted" = seccomp allowlist + cap-drop ALL + read-only root
    apparmor=None,              # a pre-loaded AppArmor profile; kern fails CLOSED if it is not loaded
    require_limits=False,       # True = refuse to start unless memory/pids caps are enforced
    cap_drop=("ALL",),          # default drops ALL; pass () only if the box must bind a port < 1024
)
```

Mounts over sensitive sources (`/`, `/etc`, `$HOME`, the docker socket) are **refused even if you ask
for them**, and so is a `tmpfs` that would COVER a `mounts` bind: mounts stack, kern puts the
tmpfs on top whatever the argument order, and the bind's files would be present on the host and
invisible in the box. "Cover" is the mountpoint relation, not a string compare, so a tmpfs at `/tmp`
is refused against a bind at `/tmp` **and** at `/tmp/sub`. The other direction is legal and is not
refused: `mounts={host: "/tmp"}` with `tmpfs={"/tmp/scratch": "8m"}` gives a persistent `/tmp` with a
bounded ephemeral subtree, and both halves work. Captured output is bounded, so a flooding box cannot OOM the host.

**`setup=` output is read-only to your code, by default.** `.deps` is what `setup=` installed, so
`run_code` mounts it read-only and a cell cannot change what the next cell imports. This closes a
cross-call vector that is not obvious: `.pyc` files are validated on the source's timestamp and size,
so a cell could rewrite a dependency's BYTECODE, re-paste the legitimate 16-byte header, leave the
`.py` untouched, and the next `import` would run it, invisibly to both `result.files` and
`list_files()`. Not a sandbox escape, since both cells are your untrusted workload; what it protects
is the assumption that `import x` in call N+1 runs the `x` call N could see.

The setup box compiles the bytecode before the mount closes, so the default costs nothing: without
that step a session whose setup skipped compilation paid +40 ms on every call, forever
(250 ms against 290, measured on `requests`). Pass `deps_readonly=False` if a workload legitimately
writes into `.deps` at run time, and note that it will get `EROFS` rather than a silent failure.

**`egress_allow` is the middle setting between the two, and the one an agent usually wants.**
`network=False` gives the run phase no network at all and `network=True` gives it the host's; an
allowlist gives it a named few:

```python
kern.Sandbox(egress_allow=["pypi.org", "files.pythonhosted.org"])
```

The box stays in its own network namespace and reaches the internet only through kern's filtering
proxy, which permits those domains and nothing else, so a workload can fetch from an index you chose
and cannot exfiltrate elsewhere. Mutually exclusive with `network=True`. The `setup=` box keeps full
network to install dependencies; the allowlist governs the untrusted run phase, which is the phase
that runs code you did not read.

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

**Writable paths: `/workspace`, `/tmp` and `/dev/shm`.** The box root is read-only, so `/tmp` is a
64 MiB tmpfs the binding mounts for you. Two things break without it, and both are quiet: a write
naming `/tmp` fails with `EROFS`, and `tempfile` falls back to the current directory, putting scratch
into your persistent workspace where `list_files` then reports it. The bytes are charged to the box's
own memory cgroup, so filling `/tmp` is an OOM of the box and never the host disk. Resize it with
`tmpfs={"/tmp": "512m"}`, remove it with `tmpfs={}`, or bind your own directory at `/tmp` through
`mounts` and the default steps aside (including a `:ro` bind, which leaves `/tmp` read-only: that is
your call, not an accident). **The unit is required and the target may not contain a `:`.** kern's CLI
takes both spellings and means the opposite of what you do: a bare `"64"` is 64 BYTES, `"0"` is
UNLIMITED, and `["/scratch:9g"]` mounts `/scratch` at 9 GiB rather than a directory by that name. All
three measured, all three refused here with the reason. A size larger than `memory_mb` is refused
for the same family of reason: `df` would report it to a program that preflights, which then plans
against a number that OOM-kills it. The binding's own default is clamped to half the cap instead.

**`memory_mb` bounds the cgroup, not the workload's usable memory.** The cap is shared with
memory-backed filesystems in the same box, and one of them is not bounded at all, so a box sized for
a job can still be killed by a path the caller never mentioned. Measured: 200 MiB written to
`/dev/shm` under `memory_mb=128` OOM-kills the box no matter what `/tmp` is clamped to, while the
same 200 MiB to `/tmp` returns ENOSPC and the box lives.

`/dev/shm` is the one this SDK does not control: it is present in every box, it is a tmpfs with **no
size at all** (measured at 15.6 GB, half of host RAM), and `tmpfs={"/dev/shm": ...}` is refused by
kern because it would shadow the hardened `/dev`. It is charged to `memory_mb` like any tmpfs, so the
memory cap is the only thing bounding it. **The runtime now takes `kern box --shm-size SIZE`**, and it
reports the size the box actually has rather than the host's; this binding does not expose it yet, so
from here the cap is still the only bound. Its apparent size is a fact about the HOST rather than
about your box: no `size=` means the
kernel's tmpfs default, half of host RAM, so the same code sees 2 GB on a 4 GB board and 64 GB on a
128 GB server while `memory_mb` says 128. `mounts={host_dir: "/dev/shm"}` IS accepted and STACKS on top
of kern's own mount rather than replacing it (the last mount is the one that resolves), and it is a real workaround rather than only an access fact: measured through the
bind, `multiprocessing.shared_memory` and a `multiprocessing.Queue` (POSIX semaphores) both still
work, because `shm_open` is a path-based open and neither asserts on the filesystem type. Two costs
come with it. A plain directory swaps an unbounded RAM path for an unbounded DISK one, so to bound it
you bind a host directory that is itself a sized tmpfs. And it has no tmpfs lifetime: a file written
to `/dev/shm` in the box is **still on the host after the box dies**, which is a residue class the
real mount does not have. And Python's
`multiprocessing` uses `/dev/shm` by default, so this is not a corner. The first sentence of this
paragraph said "and nothing else" until a test that pins the writable set per security profile said
otherwise.

**Scratch does not survive a call, except in a `kernel()`.** Each `run_code` is a fresh box, so `/tmp`
is fresh too while the workspace persists. A `kernel()` is one long-lived box and the opposite holds:
its `/tmp` accumulates. Measured at 10 MiB per step under the 64 MiB default, ten `run_code` calls all
pass and ten kernel cells fail from the seventh with `OSError: [Errno 28]`. A read-only `/tmp` failed loudly at the moment of the mistake; now a tool that
writes state to the workspace and a lock to `/tmp` writes both, and the next call finds the state
pointing at a path that is gone. Put anything a later call must find in the workspace. The `setup=` box is the exception: an install needs unbounded
scratch, so the default is not applied there (an explicit `tmpfs=` still is).

**Toolchains in the box.** npm, Go, Rust and .NET cache under `$HOME`, and `$HOME` is inside the
read-only root. The scratch at `/tmp` is half the answer; `HOME` is the other half, and no error says
so. Go reports `failed to initialize build cache at /root/.cache`, which is true and does not mention
`HOME`. npm is worse: a failed `mkdir /root/.npm` reaches the user as
`Invalid response body while trying to fetch https://registry.npmjs.org/express`, which reads as a
network fault and is not one. Measured on `node:22`: neither -> exit 2, `HOME` alone with a read-only
`/tmp` -> still exit 2, both -> exit 0.

```python
Sandbox(
    image="golang:1.23-alpine",
    env={"HOME": "/workspace"},   # npm's ~/.npm, Go's ~/.cache, Rust's CARGO_HOME, .NET's NuGet
    tmpfs={"/tmp": "512m"},       # scratch; 64 MiB fits a small install, a real one needs more
)
```

That message is verbatim from a box, and the recipe above is what makes the same build print its
output. **Point `HOME` at the workspace, not at the scratch**: `npm install webpack webpack-cli
typescript eslint` needs 81 MiB of cache, so `HOME=/tmp` fails with `ENOSPC` against the 64 MiB
default while `HOME=/workspace` succeeds. One small package fits either way, which is why testing
with `express` proves nothing.

**Two numbers inside a box describe the host, not your box, and a program will act on them.** `df`
reports a tmpfs's own size, and `nproc` reports the host's CPU count: measured under `cpus=0.5`,
`nproc` says 28 while `cpu.max` says `50000 100000`, so `make -j$(nproc)` starts 28 jobs against half
a core and a `pids` ceiling. The same shape reaches SQLite, which spills `CREATE INDEX` into `/tmp`:
a 309 MB database on the workspace fails with `database or disk is full` while `df /workspace` shows
202 GB free, and by the time you look, `/tmp` is empty again because SQLite cleaned up. Point
`TMPDIR` at the workspace, or raise the scratch, when the job sorts more than it can hold.

**`setup=` installs Python packages into the workspace, not system packages into the image.** The root
is read-only, so a package manager cannot run at all: `apk add git` answers `ERROR: Unable to lock
database: Read-only file system`, and `apt-get install` fails the same way. If the job needs `git`,
`make` or a compiler, that is a choice of `image=`, not something `setup=` can add.

**`max_output_bytes` limits what you RECEIVE, not what the job costs.** Measured: past the cap the
output is discarded and the process keeps running to the end, so a marker file written after the noisy
part is there and `exit_code` is 0 with `truncated=True`. A runaway producer therefore runs until
`timeout_s`, and the two caps are per-stream, so a failure on stderr survives a flood on stdout.

**A JVM's heap and this scratch add up to less than the cap by luck, not by design.** The JVM takes
1/4 of the cgroup (measured: `MaxHeapSize 134217728` under `memory_mb=512`) and the scratch clamp
takes at most 1/2, and 3/4 fits. Write `-Xmx` at 3/4 of `memory_mb`, which people do, and the
composition breaks: neither side knows about the other, and `/dev/shm` is in the same budget with no
bound at all.

**`track_files` reports the workspace, and only the workspace.** A job whose product lands in `/tmp`
reports nothing changed while having produced output. Measured: writing `/workspace/a` and `/tmp/b`
in one call reports `['a']`.

**Nothing in `/tmp` survives a `snapshot`.** A tmpfs is on no layer, so a marker written to the
scratch is gone after `restore` while the workspace marker is there. A `setup=` that stages files in
`/tmp` loses them.

**matplotlib works and complains.** It falls back to a temporary `MPLCONFIGDIR` because `$HOME` is not
writable, so the figure is produced AND stderr carries `mkdir -p failed for path
/root/.config/matplotlib: [Errno 30] Read-only file system`. `exit_code == 0` is green for a run the
user will report as broken. Pass `env={"MPLCONFIGDIR": "/tmp"}`, which is what the MCP server already
does.

**Server images need three things, and each announces itself separately.** Measured on
`nginx:alpine`: `open("/run/nginx.pid") failed (30: Read-only file system)`, then
`chown(...) failed (1: Operation not permitted)`, then it serves.

```python
Sandbox(image="nginx:alpine",
        tmpfs={"/run": "1m", "/var/cache/nginx": "16m", "/var/log/nginx": "4m"},
        cap_drop=())   # CAP_CHOWN is in the default drop, and nginx chowns its cache
```

`cap_drop=()` **widens the default posture**, and it is the only recipe here that does: measured,
`CapEff` goes from `0000000000000000` to `00000110bd84efff`. Under `security_profile="untrusted"` it
does not, because the bundle wins over the option (`CapEff` stays zero even with `cap_drop=()`), so a
server image and that bundle are mutually exclusive today. Both facts are pinned by the posture test.

Name the REAL mountpoint: `/var/run` is a symlink to `/run` on Alpine, and a tmpfs at the alias
leaves the path the program opens untouched. And a server that refuses to run as root (postgres:
`initdb: error: cannot be run as root`) has no answer here yet, because this binding does not expose
kern's `--user`. Rust, .NET and anything else with a package cache want the same two places for the same
reason. `HOME` stays the caller's decision because a build cache in `/workspace` is a host directory
nothing bounds; point it at a `tmpfs={"/home": "512m"}` instead if you want it capped and thrown away
with the box.

## API

- `kern.run_code(code, **kwargs)`, one-shot: a throwaway `Sandbox` under the hood.
- `Sandbox(...).run_code(code, language="python"|"bash"|"sh"|"node")` on the session workspace. The
  enum is what the runner accepts, **not a promise about the image**: the default `python:3.12-slim`
  ships `python`, `bash` and `sh` and no `node`, and asking for a missing interpreter returns an
  `exec_failed` fault naming the binary and the image. **`bash` runs bash and `sh` runs the POSIX
  shell**, which are different languages: `[[ ]]`, arrays and `pipefail` are bash. Alpine has no bash
  at all, so ask for `sh` where the image may not carry one.
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
