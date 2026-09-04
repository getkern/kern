# Round 14: name us 30+ real jobs that should break this branch, and we will run them

Thirteen rounds have been you naming cells and us running them, and the cells that found things were
never the ones we would have written. So this asks for that explicitly, at scale, and about **real
work** rather than about the options in isolation.

**What we want: at least 30 scenarios, each one a job someone would actually give an agent or an
SDK**, chosen because you expect them to break something on this branch. Not assertions on an option;
a task with a purpose, where the failure would be discovered by a user rather than by a test.

We will run every one of them locally, report each result including the ones that pass, and say which
of your predictions were wrong.

---

## Two targets, and the second is the one that usually gets skipped

1. **The `dev` tree.** What we have been reviewing.
2. **The PUBLICATION artifacts.** `kern_sandbox-0.1.36-py3-none-any.whl`, its sdist, and
   `kern-sandbox-0.1.36.tgz`, installed into a clean venv and a clean `npm init` directory. A
   scenario that passes from the source tree and fails from the wheel is a packaging defect, and it
   is the class nothing in our suites can see: `python -m pytest` runs against the checkout, not
   against what a user installs. Say when a scenario is worth running twice.

## The surface

**SDK options**: `image`, `setup`, `workspace`, `memory_mb`, `cpus`, `pids`, `timeout_s`, `network`,
`egress_allow`, `mounts`, `tmpfs`, `profiles`, `env`, `max_output_bytes`, `enforce_limits`,
`require_limits`, `security_profile`, `apparmor`, `cap_drop`, `deps_readonly`, `track_files`,
`on_stdout`, `on_stderr`.

**SDK methods**: `run_code(language=python|bash|sh|node)`, `run(argv)`, `write_file`, `read_file`,
`list_files`, `snapshot`, `restore`, `kernel()` (a warm interpreter in a long-lived box).

**MCP server** (`kern-mcp`): `run_code`, `write_file`, `read_file`, `list_files`, driven over stdio
JSON-RPC, configured only by `KERN_MCP_*` environment variables.

**pi extension** ([`index.ts`](index.ts)): routes pi's `bash`, `read`, `write`, `edit`, `ls`, `grep`,
`find` at a box; `KERN_PI_IMAGE`, `KERN_PI_EGRESS`, `KERN_PI_MEMORY_MB`, `KERN_PI_PIDS`,
`KERN_PI_TIMEOUT`, `KERN_PI_MAX_OUTPUT`, `KERN_PI_TMPFS_MB`, `KERN_PI_HOME`.

**What this branch changed**, and therefore what a scenario should be aimed at: a default writable
`/tmp`, `language="bash"` meaning bash, the MCP schema naming its image, the `max_bytes` refusal
wording, and the pi extension's `HOME`/`/tmp`/shell defaults. Everything else is 0.1.35 behaviour that
these changes could have disturbed, which is the more interesting half.

## What is already covered, so you do not spend a cell on it

    python  392 tests   (103 in test_sandbox.py, 106 in test_mcp.py, the rest parametrised)
    node     75 tests
    pi       73 + 89 + 25 assertions

Already exercised, with controls: the tmpfs size/target/type gates, the cap resolution and the clamp,
the `untrusted` step-aside, the writable-path pin per profile, the setup-box exclusion, the
bind-covering refusal in both directions, `bash` vs `sh` vs a missing interpreter, the `exec_failed`
message, the fork storm with a `pids` discriminant, the FIFO and symlink and non-UTF-8 hostile set,
the MCP reply bounds and the newline-free flood, the cross-binding argv pair assertion.

## What we can run here, and what we cannot

**Available offline** (images already in the local cache, no pull needed):
`python:3.12-slim`, `python:3.12-alpine`, `python:3.9-slim`, `node:22`, `node:22-slim`,
`node:20-slim`, `node:20-alpine`, `golang:1.23-alpine`, `golang:1.22-alpine`,
`eclipse-temurin:21-jre`, `postgres:16-alpine`, `redis:7-alpine`, `nginx:alpine`, `alpine:3.19`,
`debian:12-slim`, `busybox`. Anything else means a pull, which we can do but it is slower, so say if
a scenario needs one.

**Cannot run here**: a live pi session (`~/.pi/agent/models.json` does not exist on this machine and
there is no local endpoint configured, so `pi auth check` has nothing to check), privileged kern (so
no disk-backed `vdisk:`, no `--uid-range` on a second uid), WSL2, and the ARM boards are usually off.
Network is available, so `egress_allow` and `setup=` scenarios are fine. Every image listed above was
verified runnable with `--pull never` before this document claimed it.

**One host, one architecture**: x86_64, 31914 MiB RAM, cgroup v2 with delegation, ext4 workspace.
Anything that depends on a small-memory host or a different filesystem is a prediction we can state
but not measure, and we will say so rather than pretend.

## The format that makes a suggestion runnable

For each scenario, the four lines that let us run it without guessing what you meant:

    WHAT     the job, in the words of the person who wants it done
    HOW      the code or the command, concretely enough to paste
    BREAK    what you expect to go wrong, and where
    TELL     the discriminant: what distinguishes the failure from a healthy run, and what a
             FALSE GREEN would look like if we asserted the wrong thing

That last line is the one we keep needing. Four of the defects this branch fixed were found because
the instrument was wrong rather than the subject: a 400 MiB allocation that masked the tmpfs limit it
was measuring, a probe reading `lines[0]` of a stacked mount, an OOM message naming the path its
author had in mind, and a fork bomb written in a shell that could not parse it.

## Where we would aim, if it helps you aim elsewhere

Our own list, so you can skip or contradict it:

- **Toolchains that cache**: a `pip install` of something with a build step, a `go build` of a module
  with dependencies, a `mvn` or `gradle` run, `cargo` on a crate with a registry index.
- **Long jobs**: something that runs for minutes and writes as it goes, against `timeout_s` and the
  output cap at the same time.
- **Data work**: a pandas job on a file bigger than the scratch, a matplotlib figure that comes back
  as an image, a SQLite database in the workspace across calls.
- **Multi-call state**: an agent that writes a script in one call and runs it in the next, a
  `snapshot`/`restore` round trip, a `kernel()` session that outlives ten cells.
- **Servers**: `postgres:16-alpine` or `redis:7-alpine` started inside a box, a `nginx:alpine` serving
  the workspace, anything that expects a writable runtime directory or a socket.
- **The publication path**: the same scenario from the wheel, from the sdist, and from the npm
  tarball, on a machine that has never seen the checkout.

## What we are actually asking

Thirty is a floor, not a target. Rank them if you can: we will run the ones you rank highest first
and report as we go rather than at the end. If a scenario needs something this machine does not have,
say so and we will state the gap instead of faking the result.

The single most useful thing you can include is a scenario where you expect the thing to WORK, and
where a plausible test of it would report a false green. Those have been worth more than the failures.
