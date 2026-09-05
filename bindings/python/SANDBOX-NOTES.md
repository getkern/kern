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


**An enforced `pids` cap produces no fault, deliberately.** A refused `fork` returns `EAGAIN`, which a
program is allowed to catch and exit 0 on, so a contained fork bomb reads as a successful run.
Labelling that a sandbox fault would misreport a process that exited cleanly. The cap is still
enforced: on WSL2, `pids=32` blocked at 29 forks while `pids=256` let 120 through.

