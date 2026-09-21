# kern-sandbox: the operational notes

The long tail, moved out of the package README so that page stays a landing page. Every item here was
measured on a real box and cost somebody an afternoon; none of it is needed to run your first call.

Read it when a box does something you did not expect: a build that fails with a network error that is
not one, a `df` that lies, output that vanishes past a cap, a chart that renders and complains anyway.

**Scratch does not survive a call, except in a `kernel()`.** Each `run_code` is a fresh box, so `/tmp`
is fresh too while the workspace persists. A `kernel()` is one long-lived box and the opposite holds:
its `/tmp` accumulates. Measured at 10 MiB per step under the 64 MiB default, ten `run_code` calls all
pass and ten kernel cells fail from the seventh with `OSError: [Errno 28]`. A read-only `/tmp` failed loudly at the moment of the mistake; now a tool that
writes state to the workspace and a lock to `/tmp` writes both, and the next call finds the state
pointing at a path that is gone. Put anything a later call must find in the workspace. The `setup=` box is the exception: an install needs unbounded
scratch, so the default is not applied there (an explicit `tmpfs=` still is).

**A fault ends a `kernel()`, and only the workspace comes back.** A cell that is killed (OOM, timeout,
a blocked syscall) takes the interpreter with it. Measured with `memory_mb=128`: cell A sets `x = 41` and
writes `keep.txt`, cell B allocates until the cap bites (`exit_code` 137, `fault.type == "oom"`), and from
there the two front ends differ on purpose. In the SDK the next `run_code` RAISES `kernel is dead: a prior
cell ended it (oom). Files written to the workspace are still there; names and imports from the earlier
cells are gone`, because a fresh interpreter handed back in silence would answer questions about state
that no longer exists. The MCP server cannot raise at a model, so it opens a fresh kernel and says so on
the reply for the cell that died; through it, cell C reads `x still there? False` with `keep.txt`
unchanged. Either way `fault` is the signal: if it is not `None`, the names are gone and the files are not,
so re-run the setup cell.

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

**The fault taxonomy is kern's, not Python's, and it does not care what the workload is written in.**
`fault` comes from a descriptor kern writes at teardown, so a compiled program gets the same verdicts as a
cell. Measured: a Node process allocating past a 128 MiB cap returns `exit_code 137, fault.type "oom"` and
`node -e "setTimeout(...)"` past the deadline returns `timeout`; a Go program built and run in the box
returns `oom`, the **Go compiler itself** returns `oom` when 128 MiB is not enough to build, and a Go
sleeper past the deadline returns `timeout`. A shell that tries to absorb the kill cannot:
`./hog || echo handled` still came back `exit_code 137, fault.type "oom"`, because the OOM kills the whole
cgroup rather than one process. What language-specific helpers add is the RICH side (a matplotlib figure,
the value of a trailing expression), not the verdict.

The trap that makes a non-Python workload look fault-free is the one two paragraphs up. Measured on the
same Go program under the same cap: without `HOME`, `go run` fails with
`failed to initialize build cache at /root/.cache: mkdir /root/.cache: read-only file system` and the call
is `exit_code 1, fault=None`, which is correct, the sandbox did nothing; with `env={"HOME": "/workspace"}`
the same command is `exit_code 137, fault.type "oom"`. A toolchain that cannot start looks exactly like
code that failed, so give it `HOME` and scratch before reading anything into a clean exit 1.

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

**Nothing bounds the WORKSPACE, and `df` inside the box agrees with the host.** `memory_mb` bounds RAM
and the tmpfs mounts that are charged to it; the workspace is a host directory and is charged to your
disk. Measured under `memory_mb=128`: a cell writing a 400 MiB file to the workspace returns
`exit_code 0, fault=None` (`track_files` reports `fat.bin`), and `shutil.disk_usage("/workspace").free`
inside the box reports **110 GiB**, which is the host's free space, so a job that preflights its own
output size is told yes. With the default workspace the damage is temporary, since it is a temp
directory removed when the `Sandbox` closes. With `workspace=` it is not: measured, a 300 MiB file is
still there after close and the host's free space dropped by 300 MiB. No option here caps it, and
`max_output_bytes`/`timeout_s` do not help, so bound it outside the box: a workspace on a filesystem you
size (a quota, an LVM volume, a sized tmpfs you mount there yourself), and check what the last run left
before starting the next. This is the same shape as `nproc` and `df` reporting the host under a `cpus`
cap, one page down: the numbers a box reads describe the machine, not the box.

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


**`network=True` puts the box in the host's network namespace, so the host's own `127.0.0.1` is in
reach.** Measured with a server bound to the host's loopback: from a box with `network=True` a request to
`http://127.0.0.1:<port>/` returned the body. That is what sharing a namespace means, and it is worth
saying out loud because the services on a developer machine's loopback are the unguarded ones: a model
runner, a notebook, a database with trust auth, an auto-grader, a cloud-agent socket. Under
`network=False` the same request is refused (the box has its own loopback) and under `egress_allow` it
comes back `403` from the proxy, localhost included. Network is a session-level choice with no per-call
override for this reason.

**Pin the image by DIGEST when a run has to be reproducible later.** `image="alpine@sha256:4bcff6..."`
works and is cached by digest; two runs of the same digest gave byte-identical stdout, while
`alpine:latest` on the same machine gave a different release entirely (3.22.1 against 3.24.1). A wrong
digest is refused at the registry (`manifest digest mismatch ... refusing`). What kern does NOT record is
the digest a tag resolved to: `kern images --json` lists names, sizes and pull times, so a forensic or
compliance record has to carry the digest in the reference you ran.

**An enforced `pids` cap produces no fault, deliberately.** A refused `fork` returns `EAGAIN`, which a
program is allowed to catch and exit 0 on, so a contained fork bomb reads as a successful run.
Labelling that a sandbox fault would misreport a process that exited cleanly. The cap is still
enforced: on WSL2, `pids=32` blocked at 29 forks while `pids=256` let 120 through.

## Moved here from the README, because a first call does not need them

**Writable paths: `/workspace`, `/tmp` and `/dev/shm`.** The box root is read-only, so `/tmp` is a
64 MiB tmpfs the binding mounts for you. Without it two things break quietly: a write naming `/tmp`
fails with `EROFS`, and `tempfile` falls back to the current directory, putting scratch into your
persistent workspace. The bytes are charged to the box's own memory cgroup, so filling `/tmp` OOMs the
box and never the host disk. Resize with `tmpfs={"/tmp": "512m"}`, remove with `tmpfs={}`, or bind your
own directory at `/tmp`. Name the REAL mountpoint: `/var/run` is a symlink to `/run` on Alpine, and a
tmpfs at the alias leaves the path the program opens untouched.

**The bytecode route `deps_readonly` closes.** `run_code` mounts `.deps` read-only, so a cell cannot
change what the next cell imports. A `.pyc` is validated on the source's timestamp and size, so a cell
could rewrite a dependency's bytecode, leave the `.py` untouched, and the next `import` would run it -
invisibly to `result.files` and `list_files()`. The setup box compiles before the mount closes, so the
default costs nothing.

**A `tmpfs` that would COVER a `mounts` bind is refused**, since the bind's files would then be on the
host and invisible in the box. "Cover" is the mountpoint relation, not a string compare. The other
direction is legal: a bind at `/tmp` with `tmpfs={"/tmp/scratch": "8m"}` gives a persistent `/tmp` with
a bounded ephemeral subtree, and both halves work.

**The unit is required and a `tmpfs` target may not contain a `:`.** kern's CLI takes both spellings and
means the opposite of what you do: a bare `"64"` is 64 BYTES, `"0"` is UNLIMITED, and `["/scratch:9g"]`
mounts a size rather than a directory. All three are refused here, with the reason. A size larger than
`memory_mb` is refused too, because `df` would report it to a program that preflights against it.

**`/dev/shm` cannot be resized and can be replaced.** `tmpfs={"/dev/shm": ...}` is refused because it
would shadow the hardened `/dev`; its apparent size describes the HOST.
`mounts={host_dir: "/dev/shm"}` is accepted and works, at two costs: a plain directory swaps an
unbounded RAM path for an unbounded DISK one, and a file written there is still on the host after the
box dies.

## Found by running the flagship case: an agent that fixes its own code

**`setup=` runs under the same `memory_mb` as your cells, and a pip install needs more than a cell
does.** MEASURED with `setup="pip install pandas matplotlib"`: at `memory_mb=64` the setup box is
OOM-killed before any of your code runs, and `Sandbox.__enter__` raises `SandboxError: setup failed
(exit 137)` carrying kern's own OOM sentence; at 256 it succeeds. The cap that is right for a cell is
not necessarily right for the install that precedes it, so size the Sandbox for the setup and cap the
cells separately (below). A killed setup also leaves pip's `pip-unpack-*` directories in the workspace,
which is a host directory: remove them or start from a clean one.

**The cap is a property of the SESSION, not of a call.** `Sandbox.run_code` takes `timeout_s` but not
`memory_mb`; the module-level `kern.run_code` takes both, because it builds a one-shot Sandbox for you.
So an agent that reads `fault == "oom"` and wants to retry with more memory opens a NEW Sandbox on the
SAME `workspace=`, which is the cheap move rather than the expensive one: MEASURED on this host, the
first session paid 16.2 s for the pip install, and the second and third sessions on that workspace
started in 364 ms and 756 ms because `.deps` was already there and `setup=` could be omitted. The file
state persisting is what makes the retry cheap.

## Moved here on 2026-09-21, so the README's first screen is a landing page

The four measurements the package README now points at instead of carrying. Every one of them is a
reason a number on that page is written the way it is.

**The prewarm pool speeds up `run_code` and leaves `run()` alone.** A prewarmed box holds a BOOTED
INTERPRETER, so what the pool removes is the interpreter's cost and not the box's. Measured:
`run(["true"])` reads **4.74 ms with the pool against 4.67 ms without it**, which is the same number
twice. Time the wrong call and prewarming looks like a no-op.

**The pool covers a burst, not a rate**, and it refills on a worker thread. Measured on
`python:3.12-slim`, three shapes in one run:

| shape | p50 |
|---|---|
| 8 calls with `prewarm=8`, all served by the pool | **0.81 ms** (min 0.61, max 1.54) |
| 16 calls in a tight loop with `prewarm=8` | first 8: **0.70 ms**, next 8: **13.70 ms** |
| one call every 2 s with `prewarm=4`, an agent's pace | **0.86 ms** (max 1.10) |

Four calls with `prewarm=4` read a p50 of 0.6 ms and twenty read 13.6 ms, which is the default cost;
constructing and calling immediately reads 13.7 ms until the boxes have started. So the fall is a
cliff rather than a slope, and a single p50 over a mixed run reads 12.6 ms and describes neither
regime.

**`egress_allow` is route-level, and here is what that looks like from inside.** Measured in the box:
a raw socket to an IP returns `ENETUNREACH`, DNS does not resolve at all, and an HTTP request to a
domain outside the list comes back `Tunnel connection failed: 403 Forbidden`, while the same socket
under `network=True` connects. Nothing leaves except through the proxy, which is why a client that
does not speak to an HTTP proxy (Postgres, MySQL, Redis) has no path out at all.

**Twice the performance table published a MINIMUM and called it the number**, and both times the
mistake flattered us. The bare-box row read **3.9 ms** until the host was checked: it was the minimum,
and the machine had **300 orphaned box processes** on it from test runs. It then read **4.3 ms** until
it was measured again on 2026-09-19 and the p50 of three separate runs came out **4.60, 4.94 and
5.00**: 4.3 had been sitting between the min and the p25, which is the same mistake in a smaller size.
The row says 4.9 today, and the rule it now carries is **p50 rather than the best run**, with the
machine named beside it.

**The full mount refusal list, and what is deliberately NOT on it.** The README names the three groups
and the reason; this is the enumeration, read from the shipped code.

- Absolute sources: `/`, `/boot`, `/dev`, `/etc`, `/proc`, `/root`, `/sys`, `/run/docker.sock`,
  `/var/run/docker.sock`.
- Credential directories, refused as a COMPONENT anywhere in the source, because they live under a
  per-user home: `.ssh`, `.aws`, `.gnupg`, `.kube`, `.docker`, `.azure`, `.oci`, `.terraform.d`,
  `.password-store`, `.netrc`, `.git-credentials`, `.pypirc`, `.npmrc`, `.databrickscfg`, `.boto`,
  `.s3cfg`, `.rclone.conf`.
- Under `.config`, refused as a consecutive pair because the child name alone is too generic to match
  (`~/projects/gh/src` is ordinary work): `gcloud`, `gh`, `doctl`, `rclone`.
- kern's own state: `$XDG_RUNTIME_DIR/kern`, the image cache, the config dir, and the data dir that
  holds every named volume, each resolved per call from the environment so a moved `XDG_RUNTIME_DIR`
  moves the refusal.

The absolute set alone refused `$HOME` and ACCEPTED `$HOME/.ssh`: measured, a box mounted with
`mounts={"~/.ssh": "/x"}` listed `id_ed25519` and `authorized_keys`. Refusing the parent while allowing
its most sensitive child is the wrong way round, and it is the exact path a prompt-injected agent gets
steered down ("read ~/.aws"). The component rule is that fix.

**Deliberately NOT refused: `.cargo`, `.m2`, `.gem`.** Each holds one credential file next to a package
cache people legitimately mount, such as `~/.cargo/registry` for an offline build, so refusing the
directory would break a real use and push callers off the guard entirely. Naming the residual gap beats
a refusal nobody keeps: mounting `~/.cargo` still exposes `credentials.toml`, and closing that needs a
different mechanism than a path component.

**The first image read is not small.** Measured on a Raspberry Pi 5, an arm64 image pulled and unpacked
for the first time took **38 s** against **0.1 s** once warm. That is the usual cause of a
`startup_failed` whose `stderr` shows kern still building the box: a short `timeout_s` fires while the
pull is running. Run it again; if the second call is fast it was the cold read, and if it is not, look
for a bind source on a dead NFS export.
