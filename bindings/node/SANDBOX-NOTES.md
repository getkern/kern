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

