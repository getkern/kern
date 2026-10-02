# kern-sandbox (Node): the operational notes

The long tail, moved out of the package README so that page stays a landing page. Every item was
measured on a real box; none of it is needed to run your first call. Read it when a box does something
you did not expect. The Python binding has the same list, with more of it:
[SANDBOX-NOTES.md](https://github.com/getkern/kern/blob/main/bindings/python/SANDBOX-NOTES.md).

**Writable paths: `/workspace`, `/tmp` and `/dev/shm`.** The box root is read-only, so `/tmp` is a
64 MiB tmpfs this binding mounts for you. Without it a write naming `/tmp` fails with `EROFS` and
temp-file helpers fall back to the current directory, quietly putting scratch into your persistent
workspace where `listFiles` then reports it. The bytes are charged to the box's own memory cgroup, so
filling `/tmp` OOM-kills the box and never fills the host disk. Resize with `tmpfs: { "/tmp": "512m" }`,
remove with `tmpfs: {}`, or bind your own directory at `/tmp` through `mounts` and the default steps
aside (a `:ro` bind included, which leaves `/tmp` read-only: your call, not an accident). **The unit is
required and the target may not contain a `:`.** kern's CLI takes both spellings and means the
opposite of what you do: a bare `"64"` is 64 BYTES, `"0"` is UNLIMITED, and `["/scratch:9g"]` mounts
`/scratch` at 9 GiB rather than a directory by that name. All three measured, all three refused here. A size larger than `memoryMb` is refused for the same family
of reason: `df` would report it to a program that preflights. The binding's own default is clamped to
half the cap instead.

**`memoryMb` bounds the cgroup, not the workload's usable memory.** The cap is shared with
memory-backed filesystems in the same box, and `/dev/shm` is one of them with **no size at all** (the
kernel's tmpfs default, half of host RAM, so it scales with the machine and not with your config).
Measured: 200 MiB written there under `memoryMb: 128` OOM-kills the box whatever `/tmp` is set to.
`tmpfs: { "/dev/shm": ... }` is refused by kern; `mounts` at the same target IS accepted and stacks over
kern's own mount; measured through it, `multiprocessing.shared_memory` and POSIX semaphores still
work. Two costs: a plain directory is unbounded on DISK instead of in RAM, so bounding it means
binding a host directory that is itself a sized tmpfs, and it has no tmpfs lifetime, so what the box
writes to `/dev/shm` is still on the host after the box dies.

**Scratch does not survive a call.** Each `runCode` is a fresh box, so `/tmp` is fresh too while the
workspace persists. Put anything a later call must find in the workspace. The `setup` box is the exception: an install needs unbounded scratch, so the default is not
applied there (an explicit `tmpfs` still is).

**A fault ends a `kernel()`, and only the workspace comes back.** A cell that is killed (OOM, timeout,
a blocked syscall) takes the interpreter with it. Measured with `memoryMb: 128`: cell A sets a name and
writes a file, cell B allocates until the cap bites (`exitCode` 137, `fault.type === "oom"`), and the next
`runCode` THROWS `kernel is dead: a prior cell ended it (oom). Files written to the workspace are still
there; names and imports from the earlier cells are gone` rather than handing back a fresh interpreter in
silence. `fault` is the signal: if it is not `null`, the names are gone and the files are not, so open a
new kernel and re-run the setup cell.

**Toolchains in the box** need two writable places, and the error names neither. Go reports `failed to
initialize build cache at /root/.cache`, which says nothing about `HOME`; npm renders a failed
`mkdir /root/.npm` as `Invalid response body while trying to fetch https://registry.npmjs.org/...`,
which reads as a network fault and is not one. Measured on `node:22`: neither -> exit 2, `HOME` alone
with a read-only `/tmp` -> still exit 2, both -> exit 0. Pass both:

```js
new Sandbox({
  image: "golang:1.23-alpine",
  env: { HOME: "/workspace" },   // npm's ~/.npm, Go's ~/.cache, Rust's CARGO_HOME, .NET's NuGet
  tmpfs: { "/tmp": "512m" },     // scratch; 64 MiB fits a small install, a real one needs more
});
```

`runCode`/`run` also take `timeoutS`/`onStdout`/`onStderr` as **per-call** options that override the
session defaults for that one call. A `vcpu:` profile can carry `cpus`+`memory`; `memoryMb`/`cpus` are
explicit flags that **override** a profile's values (and the `memoryMb` default `512` shadows a profile's
`memory`, so pass `memoryMb: null` to let the profile apply). The **MCP server** (`kern-mcp`, for Claude
Desktop / Cursor) ships in the Python package `kern-sandbox` (`pip install kern-sandbox`).

**The fault taxonomy is kern's, and it does not care what the workload is written in.** `fault` comes from
a descriptor kern writes at teardown, so a compiled program gets the same verdicts as a cell. Measured: a
Node process allocating past a 128 MiB cap is `exitCode 137, fault.type "oom"`, a sleeper past the deadline
is `timeout`, a Go binary built in the box is `oom` (the Go compiler itself is `oom` when 128 MiB will not
build it), and `./hog || echo handled` is still `oom`, because the kill takes the whole cgroup. What a
language helper adds is the rich side, not the verdict. The trap that makes a non-Python workload look
fault-free is `HOME`: without it `go run` fails on its build cache with an ordinary `exitCode 1, fault
null`, and with `env: { HOME: "/workspace" }` the same command under the same cap reports `oom`.

**Nothing bounds the WORKSPACE, and `df` inside the box agrees with the host.** `memoryMb` bounds RAM
and the tmpfs mounts charged to it; the workspace is a host directory, charged to your disk. Measured
under `memoryMb: 128`: a cell writing a 400 MiB file there returns `exitCode: 0, fault: null` and the box
reads the HOST's free space, so a job that preflights its own output size is told yes. The default
workspace is a temp directory removed on close; a `workspace` you pass is not, and a 300 MiB file
measurably stays. Nothing here caps it: put the workspace on a filesystem you size, and check what the
last run left.

**`network: true` puts the box in the HOST's network namespace, so the host's own `127.0.0.1` is in
reach.** Measured against a server bound to the host loopback: a box with `network: true` read its body.
The services on a developer machine's loopback are the unguarded ones (a model runner, a notebook, a
database with trust auth), so this is a real choice and not a detail. `network: false` refuses the same
request (the box has its own loopback) and `egressAllow` answers `403` through the proxy, localhost
included.

**Pin the image by DIGEST when a run must be reproducible.** `image: "alpine@sha256:4bcff6..."` works and
is cached by digest: two runs gave byte-identical stdout, while `alpine:latest` on the same machine gave a
different release (3.22.1 against 3.24.1). kern does not record the digest a TAG resolved to, so a record
that has to stand up later must carry the digest in the reference.

**An enforced `pids` cap produces no fault, and that is deliberate.** When `pids` binds, the refused
`fork` returns `EAGAIN`. Code that catches it exits 0, so the call reports `fault: null, success: true`
and a contained fork bomb reads as a successful run. `EAGAIN` is an ordinary errno a program is allowed
to handle, unlike a SIGKILL it cannot, and labelling it a sandbox fault would misreport a process that
exited cleanly. Code that does not catch it dies naming "Resource temporarily unavailable". The cap
itself is enforced: on WSL2, `pids: 32` blocked at 29 forks while `pids: 256` let 120 through, same code
and same image.

**The `language` enum is a convenience, not a promise about the image.** MEASURED on the default
`python:3.12-slim`: three of the four run there (`python`, `sh`, and `bash` 5.2) and `node` does not.
`{language:"node"}` on the DEFAULT image is REFUSED before a box is started, with the remedy, because
that is a fact kern holds rather than a guess. On an image YOU named kern cannot know what is inside
it, so that case still reaches the box and comes back `exec_failed`, naming the binary, the image and
the remedy. A shell's own
`command not found` inside your script stays an ordinary non-zero exit.

**Which box-not-started failures THROW, and which come back as a fault.** kern exits **125**, its
box-not-started code, with its own diagnostic for a mount refused at runtime, an unmappable `--user` or a
seccomp/AppArmor/cgroup setup error, and that pair (125 + kern's marker) throws: the code never ran, so
there is no result to hand back. An **image that cannot be pulled is not one of those**: measured on a
typo'd tag, kern exits **1** with `error: registry: ... manifest unknown`, and `runCode`/`run` return
`exitCode: 1, success: false, fault.type: "startup_failed"` with that message in `stderr`. A `kernel()`
throws for either, because there the box IS the session. So branch on `fault`, not on `exitCode`: a box
that never ran exits 1 exactly like a script that did.

**Why `readFile` refuses a non-regular file, and why the flag alone was not enough.** A symlink is not
the only thing a box can leave at a name: `mkfifo out.png` used to make `readFile("out.png")` wait for a
writer that never comes, with no timeout, so the box chose how long the host's call took. Opening
`O_NONBLOCK` on its own would have been worse than the hang, because a non-blocking read of a
writer-less FIFO returns zero bytes and the call would report an EMPTY FILE. Both halves ship: it
returns promptly, and it refuses.
