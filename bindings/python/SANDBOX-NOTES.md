# Kern Sandbox: the operational notes

The long tail, kept out of the package README so that page stays short. Every item was measured on a
real box and cost somebody an afternoon. None of it is needed to run your first call.

Read it when a box does something you did not expect: a build that fails with a network error that is
not one, a `df` that lies, output that vanishes, a chart that renders and complains anyway.

## Writable paths, scratch and `HOME`

The box root is read-only. Three paths are writable: **`/workspace`** (a host directory, persists),
**`/tmp`** (a 64 MiB tmpfs the binding mounts for you) and **`/dev/shm`**.

Without that `/tmp` two things break quietly: a write naming `/tmp` fails with `EROFS`, and
`tempfile` falls back to the current directory, putting scratch into your persistent workspace. The
bytes are charged to the box's own memory cgroup, so filling `/tmp` OOMs the box and never the host
disk. Resize with `tmpfs={"/tmp": "512m"}`, remove with `tmpfs={}`, or bind your own directory there.

**Scratch does not survive a call, except in a `kernel()`.** Each `run_code` is a fresh box, so `/tmp`
is fresh too while the workspace persists. A `kernel()` is one long-lived box and the opposite holds:
its `/tmp` accumulates. Measured at 10 MiB per step under the 64 MiB default, ten `run_code` calls
pass and ten kernel cells fail from the seventh with `OSError: [Errno 28]`. Put anything a later call
must find in the workspace. The `setup=` box is exempt, because an install needs unbounded scratch.

**Toolchains cache under `$HOME`, and `$HOME` is inside the read-only root.** No error says so. Go
reports `failed to initialize build cache at /root/.cache`, which is true and does not mention
`HOME`. npm is worse: a failed `mkdir /root/.npm` reaches you as `Invalid response body while trying
to fetch https://registry.npmjs.org/express`, which reads as a network fault and is not one. Measured
on `node:22`: neither, exit 2; `HOME` alone with a read-only `/tmp`, still exit 2; both, exit 0.

```python
Sandbox(
    image="golang:1.23-alpine",
    env={"HOME": "/workspace"},   # npm's ~/.npm, Go's ~/.cache, Rust's CARGO_HOME, .NET's NuGet
    tmpfs={"/tmp": "512m"},       # scratch; 64 MiB fits a small install, a real one needs more
)
```

**Point `HOME` at the workspace, not at the scratch.** `npm install webpack webpack-cli typescript
eslint` needs 81 MiB of cache, so `HOME=/tmp` fails with `ENOSPC` against the 64 MiB default while
`HOME=/workspace` succeeds. One small package fits either way, which is why testing with `express`
proves nothing. If you want it capped and thrown away with the box, point it at a
`tmpfs={"/home": "512m"}` instead.

**Name the REAL mountpoint.** `/var/run` is a symlink to `/run` on Alpine, and a tmpfs at the alias
leaves the path the program opens untouched.

**The tmpfs rules.** The unit is required and a target may not contain a `:`. kern's CLI takes both
spellings and means the opposite of what you do: a bare `"64"` is 64 BYTES, `"0"` is UNLIMITED, and
`["/scratch:9g"]` mounts a size rather than a directory. All three are refused here, with the reason.
A size larger than `memory_mb` is refused too, because `df` would report it to a program that
preflights against it. A `tmpfs` that would COVER a `mounts` bind is refused, since the bind's files
would then be on the host and invisible in the box; the other direction is legal.

**`/dev/shm` cannot be resized and can be replaced.** `tmpfs={"/dev/shm": ...}` is refused because it
would shadow the hardened `/dev`, and its apparent size describes the HOST.
`mounts={host_dir: "/dev/shm"}` is accepted, at two costs: a plain directory swaps an unbounded RAM
path for an unbounded DISK one, and a file written there is still on the host after the box dies.
Measured: 200 MiB to `/dev/shm` under `memory_mb=128` OOM-kills the box, while the same 200 MiB to
`/tmp` returns `ENOSPC` and the box lives. Python's `multiprocessing` uses `/dev/shm` by default, so
this is not a corner.

**`setup=` installs Python packages into the workspace, not system packages into the image.** The
root is read-only, so a package manager cannot run at all: `apk add git` answers `ERROR: Unable to
lock database: Read-only file system`. If the job needs `git`, `make` or a compiler, that is a choice
of `image=`.

**Nothing in `/tmp` survives a `snapshot`.** A tmpfs is on no layer, so a marker written to the
scratch is gone after `restore` while the workspace marker is there.

## The numbers a box reads describe the HOST

**`nproc` and `df` do not know about your caps.** Measured under `cpus=0.5`, `nproc` says 28 while
`cpu.max` says `50000 100000`, so `make -j$(nproc)` starts 28 jobs against half a core and a `pids`
ceiling. Anything that sizes itself from a cgroup-unaware API is in the same family: Go's
`GOMAXPROCS`, some JVMs, `ray`-style CPU detection.

**Nothing bounds the WORKSPACE.** `memory_mb` bounds RAM and the tmpfs mounts charged to it; the
workspace is a host directory charged to your disk. Measured under `memory_mb=128`: a cell writing a
400 MiB file to the workspace returns `exit_code 0, fault=None`, and `shutil.disk_usage("/workspace")`
inside the box reports the host's 110 GiB free, so a job that preflights its own output size is told
yes. With the default workspace the damage is temporary, since it is a temp directory removed on
close. With `workspace=` it is not: measured, a 300 MiB file is still there after close. No option
caps it, so bound it outside the box: a quota, an LVM volume, or a sized tmpfs you mount yourself.

**SQLite spills `CREATE INDEX` into `/tmp`.** A 309 MB database on the workspace fails with `database
or disk is full` while `df /workspace` shows 202 GB free, and by the time you look `/tmp` is empty
again because SQLite cleaned up. Point `TMPDIR` at the workspace, or raise the scratch.

**A JVM's heap and this scratch add up to less than the cap by luck, not by design.** The JVM takes
1/4 of the cgroup (measured: `MaxHeapSize 134217728` under `memory_mb=512`) and the scratch clamp
takes at most 1/2, and 3/4 fits. Write `-Xmx` at 3/4 of `memory_mb`, which people do, and the
composition breaks: neither side knows about the other.

## Faults: what is one, and what is not

**The taxonomy is kern's, not Python's.** `fault` comes from a descriptor kern writes at teardown, so
a compiled program gets the same verdicts as a cell. Measured: a Node process past a 128 MiB cap
returns `oom`; a Go program returns `oom`, and so does the **Go compiler itself** when 128 MiB is not
enough to build; `node -e "setTimeout(...)"` past the deadline returns `timeout`. A shell cannot
absorb the kill: `./hog || echo handled` still came back `exit_code 137, fault.type "oom"`, because
the OOM takes the whole cgroup. Language-specific helpers add the RICH side, not the verdict.

**A toolchain that cannot start looks exactly like code that failed.** Measured on the same Go
program under the same cap: without `HOME`, `go run` fails with `failed to initialize build cache`
and the call is `exit_code 1, fault=None`, which is correct, the sandbox did nothing; with
`env={"HOME": "/workspace"}` the same command is `exit_code 137, fault.type "oom"`. Give a toolchain
`HOME` and scratch before reading anything into a clean exit 1.

**An enforced `pids` cap produces no fault, deliberately.** A refused `fork` returns `EAGAIN`, which a
program may catch and exit 0 on, so a contained fork bomb reads as a successful run. Labelling that a
sandbox fault would misreport a process that exited cleanly. The cap is still enforced: on WSL2,
`pids=32` blocked at 29 forks while `pids=256` let 120 through.

**A fault ends a `kernel()`, and only the workspace comes back.** A killed cell takes the interpreter
with it. Measured with `memory_mb=128`: cell A sets `x = 41` and writes `keep.txt`, cell B allocates
until the cap bites, and from there the two front ends differ on purpose. The SDK RAISES on the next
call (`kernel is dead: a prior cell ended it (oom)`), because a fresh interpreter handed back in
silence would answer questions about state that no longer exists. The MCP server cannot raise at a
model, so it opens a fresh kernel and says so on the reply. Either way `fault` is the signal: if it
is not `None`, the names are gone and the files are not.

**Two cases RAISE instead of returning a `startup_failed` result.** Every other refusal is a value on
the result: measured on a typo'd image tag, `exit_code` 1, `fault.type` `startup_failed`, and kern's
`error: registry: ... manifest unknown` in `stderr`. The exceptions are kern exiting **125**, its
box-not-started code (a refused mount, an unmappable `--user`, a seccomp or cgroup setup error), and
**any** failure to start a `kernel()`, where the box is the session rather than one call.

**`setup=` runs under the same `memory_mb` as your cells, and a pip install needs more.** Measured
with `setup="pip install pandas matplotlib"`: at `memory_mb=64` the setup box is OOM-killed before
any of your code runs and `__enter__` raises `SandboxError: setup failed (exit 137)`; at 256 it
succeeds. A killed setup also leaves pip's `pip-unpack-*` directories in the workspace.

**The cap is a property of the SESSION, not of a call.** `Sandbox.run_code` takes `timeout_s` but not
`memory_mb`; the module-level `kern.run_code` takes both, because it builds a one-shot Sandbox. So an
agent that reads `fault == "oom"` and wants more memory opens a NEW Sandbox on the SAME `workspace=`,
which is the cheap move: measured, the first session paid 16.2 s for the pip install, the second and
third started in 364 ms and 756 ms because `.deps` was already there.

## Output

**`max_output_bytes` limits what you RECEIVE, not what the job costs.** Past the cap the output is
discarded and the process keeps running to the end, so a marker file written after the noisy part is
there and `exit_code` is 0 with `truncated=True`. A runaway producer runs until `timeout_s`. The two
caps are per-stream, so a failure on stderr survives a flood on stdout.

**`stderr` is one stream shared by kern and your code**, so a note about an undelegated cgroup
arrives interleaved with the program's output. Right for a human at a terminal, wrong for anything
that puts `stderr` into a prompt. `code_stderr` is the same string without kern's own lines,
`runtime_notes` holds exactly what was taken out, and `stderr` still holds both in order. The
LangChain tool and the MCP server use `code_stderr`.

**`track_files` reports the workspace, and only the workspace.** A job whose product lands in `/tmp`
reports nothing changed while having produced output. Measured: writing `/workspace/a` and `/tmp/b`
in one call reports `['a']`.

**matplotlib works and complains.** It falls back to a temporary `MPLCONFIGDIR` because `$HOME` is
not writable, so the figure is produced AND stderr carries `mkdir -p failed for path
/root/.config/matplotlib`. `exit_code == 0` is green for a run the user will report as broken. Pass
`env={"MPLCONFIGDIR": "/tmp"}`, which is what the MCP server already does.

## Network

**`network=True` puts the box in the host's network namespace, so the host's own `127.0.0.1` is in
reach.** Measured with a server bound to the host's loopback: from a box with `network=True` a
request returned the body. That is what sharing a namespace means, and it is worth saying out loud
because the services on a developer machine's loopback are the unguarded ones: a model runner, a
notebook, a database with trust auth, a cloud-agent socket. Network is a session-level choice with no
per-call override for this reason.

**`egress_allow` is route-level.** Measured in the box: a raw socket to an IP returns `ENETUNREACH`,
DNS does not resolve at all, and an HTTP request to a domain outside the list comes back `Tunnel
connection failed: 403 Forbidden`, localhost included. Nothing leaves except through the proxy, which
is why a client that cannot speak to an HTTP proxy (Postgres, MySQL, Redis) has no path out at all.

## Mounts that are refused

The README names the three groups. This is the enumeration, read from the shipped code.

- Absolute sources: `/`, `/boot`, `/dev`, `/etc`, `/proc`, `/root`, `/sys`, `/run/docker.sock`,
  `/var/run/docker.sock`.
- Credential directories, refused as a COMPONENT anywhere in the source because they live under a
  per-user home: `.ssh`, `.aws`, `.gnupg`, `.kube`, `.docker`, `.azure`, `.oci`, `.terraform.d`,
  `.password-store`, `.netrc`, `.git-credentials`, `.pypirc`, `.npmrc`, `.databrickscfg`, `.boto`,
  `.s3cfg`, `.rclone.conf`.
- Under `.config`, refused as a consecutive pair because the child name alone is too generic
  (`~/projects/gh/src` is ordinary work): `gcloud`, `gh`, `doctl`, `rclone`.
- kern's own state: `$XDG_RUNTIME_DIR/kern`, the image cache, the config dir and the data dir that
  holds every named volume, each resolved per call so a moved `XDG_RUNTIME_DIR` moves the refusal.

**Why the component rule exists.** The absolute set alone refused `$HOME` and ACCEPTED `$HOME/.ssh`:
measured, a box mounted with `mounts={"~/.ssh": "/x"}` listed `id_ed25519`. Refusing the parent while
allowing its most sensitive child is the wrong way round, and it is the exact path a prompt-injected
agent gets steered down.

**Deliberately NOT refused: `.cargo`, `.m2`, `.gem`.** Each holds one credential file next to a
package cache people legitimately mount, such as `~/.cargo/registry` for an offline build. Naming the
residual gap beats a refusal nobody keeps: mounting `~/.cargo` still exposes `credentials.toml`.

## Images

**The image decides more than the runtime does.** `run_code` importing two standard-library modules
measures **46.8 ms** on the default `python:3.12-slim` against 13.8 ms for one that imports nothing:
that tag ships 164 `.py` files in the standard library and 9 `.pyc`, so every import compiles its
source. Precompiling is one line and is worth **29 ms**, more than the box, the interpreter start and
every runtime flag combined.

```dockerfile
FROM python:3.12-slim
RUN python3 -m compileall -q -j 0 /usr/local/lib/python3.12
```

Build it once and pass `image="my-python"`. The default stays the stock tag, because an SDK that
silently required a custom image would be worse than one that costs 29 ms and says so.

**The first image read is not small.** Measured on a Raspberry Pi 5, an arm64 image pulled and
unpacked for the first time took **38 s** against **0.1 s** once warm. That is the usual cause of a
`startup_failed` whose `stderr` shows kern still building the box: a short `timeout_s` fires while
the pull is running. Run it again; if the second call is fast it was the cold read.

**Pin the image by DIGEST when a run has to be reproducible later.**
`image="alpine@sha256:4bcff6..."` works and is cached by digest; two runs of the same digest gave
byte-identical stdout, while `alpine:latest` on the same machine gave a different release entirely
(3.22.1 against 3.24.1). A wrong digest is refused at the registry. What kern does NOT record is the
digest a tag resolved to, so a compliance record has to carry the digest in the reference you ran.

**Server images need three things, and each announces itself separately.** Measured on
`nginx:alpine`: `open("/run/nginx.pid") failed (30: Read-only file system)`, then `chown(...) failed
(1: Operation not permitted)`, then it serves.

```python
Sandbox(image="nginx:alpine",
        tmpfs={"/run": "1m", "/var/cache/nginx": "16m", "/var/log/nginx": "4m"},
        cap_drop=())   # CAP_CHOWN is in the default drop, and nginx chowns its cache
```

`cap_drop=()` **widens the default posture**, and it is the only recipe here that does: measured,
`CapEff` goes from `0000000000000000` to `00000110bd84efff`. Under `security_profile="untrusted"` it
does not, because the bundle wins over the option, so a server image and that bundle are mutually
exclusive today. A server that refuses to run as root (postgres: `initdb: error: cannot be run as
root`) has no answer here yet, because this binding does not expose kern's `--user`.

## Prewarm, `kernel()` and profiles

**The prewarm pool speeds up `run_code` and leaves `run()` alone.** A prewarmed box holds a BOOTED
INTERPRETER, so what the pool removes is the interpreter's cost and not the box's. Measured:
`run(["true"])` reads **4.74 ms with the pool against 4.67 ms without**, the same number twice. Time
the wrong call and prewarming looks like a no-op.

**The pool covers a burst, not a rate**, and it refills on a worker thread.

| shape | p50 |
|---|---|
| 8 calls with `prewarm=8`, all served by the pool | **0.81 ms** (min 0.61, max 1.54) |
| 16 calls in a tight loop with `prewarm=8` | first 8: **0.70 ms**, next 8: **13.70 ms** |
| one call every 2 s with `prewarm=4`, an agent's pace | **0.86 ms** (max 1.10) |

The fall is a cliff rather than a slope, and a single p50 over a mixed run reads 12.6 ms and
describes neither regime. The pool's key includes the image, the caps and the profiles, so a session
never receives a box built for another one. Each prewarmed box still serves ONE call.

**The bytecode route `deps_readonly` closes.** `run_code` mounts `.deps` read-only, so a cell cannot
change what the next cell imports. A `.pyc` is validated on the source's timestamp and size, so a
cell could rewrite a dependency's bytecode, leave the `.py` untouched, and the next `import` would
run it, invisibly to `result.files`. The setup box compiles before the mount closes, so the default
costs nothing.

**Resource profiles** attach slices defined once in `~/.config/kern/kern.toml`: `vcpu:` (CPU and
memory), `vdisk:` (a size-capped scratch disk), `vgpio:` (a device set, the **only** way to give a
box hardware). An explicit flag beats a profile, so pass `memory_mb=None` to let a `vcpu:` profile's
own `memory=` apply.

