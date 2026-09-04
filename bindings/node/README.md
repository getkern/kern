# kern-sandbox (Node.js / TypeScript)

**Run AI-generated code in a real sandbox, one fresh box per call, in about 4 ms.**

`kern-sandbox` is the Node and TypeScript binding for **[kern](https://getkern.dev)**: a rootless,
kernel-enforced sandbox out of one static binary, with no daemon, no VM and no cloud. An agent's
tool-call, a model's generated snippet, a CI step: code that runs before anyone reads it gets its own
box, and the box is thrown away after.

Network off, memory and PID caps the kernel enforces, capabilities dropped, a deny-by-default seccomp
allowlist, and a wall-clock deadline the binding applies from **outside** the box, so code that hangs
cannot outlive it. Dependency-free: it shells out to the `kern` binary and does not re-implement
isolation in JavaScript.

**The failure comes back as data, not as an exception.** A timeout, an OOM-kill, a blocked syscall or
a missing interpreter is a typed `fault` on the result, beside stdout and the exit code, so an agent
loop reads a field instead of parsing a stack trace to learn that the sandbox ended the run.

On npm: [`npm install kern-sandbox`](https://www.npmjs.com/package/kern-sandbox). Python gets the same
package on PyPI: [`kern-sandbox`](https://pypi.org/project/kern-sandbox/), which also ships an **MCP
server** for Claude Desktop and Cursor.

```js
const kern = require("kern-sandbox");

// one-shot: a throwaway box, network off, hard caps, a timeout the binding enforces
const r = await kern.runCode("print(sum(range(100)))");
console.log(r.stdout, r.success); // "4950\n" true
```

TypeScript types ship in the box. `Buffer` appears in the public surface **because we typed it that
way**, so a TypeScript consumer also needs `@types/node`; without it `tsc` reports `Cannot find name
'Buffer'` against this package's `.d.ts` and tells you what to install. Typing that surface as
`Uint8Array` would remove the requirement (a `Buffer` is one), and that is a change to the published
surface rather than a fix, so it is not in this release.

```ts
import { runCode, withSandbox, Sandbox } from "kern-sandbox";
```

## Install

```sh
npm install kern-sandbox
```

You also need the `kern` binary on `PATH` (or point `$KERN_BIN` at it). The quickest route is the
released static binary, whose checksum the script verifies:

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

From source instead, if you would rather not trust a published artifact:

```sh
cargo install --git https://github.com/getkern/kern getkern --locked
```

kern needs a Linux kernel with unprivileged user namespaces + cgroup v2. On Windows it runs under WSL2.
Node 18+.

**On a Mac this package installs but cannot run**, and it says so rather than sending you after a
download that does not exist: kern is Linux-only, because macOS has no namespaces and no cgroups. Run
inside a Linux VM (colima, Lima, OrbStack, UTM), install `kern` and this package there, and it behaves
as on Linux. Verified on Apple Silicon with an Ubuntu 24.04 guest.
[Install notes for macOS](https://github.com/getkern/kern/blob/main/docs/INSTALL.md).

## A session: files persist, processes are ephemeral

File state lives in a workspace directory on the host, bind-mounted into every box. Each `runCode`/`run`
spawns a **fresh** box on that shared workspace, so file state persists but in-memory state does not
(write to disk for continuity). `withSandbox` opens the session and cleans it up, even on throw:

```js
await kern.withSandbox({ setup: "pip install pandas" }, async (sbx) => {
  await sbx.writeFile("data.csv", csvBytes);
  const r = await sbx.runCode(
    "import pandas as pd; print(pd.read_csv('data.csv').describe())",
  );
  console.log(r.stdout);          // network off, capped, isolated
  const chart = await sbx.readFile("out.png");
});
```

`setup` is the **only** moment the network is on (a separate box that installs deps into the workspace
and dies); every `runCode` after it is network-off. The setup box runs under the **same `memoryMb`
cap** as your runs: a heavy install (pandas, torch, ...) can OOM-kill setup at the default 512 MB, so
raise `memoryMb` (e.g. `memoryMb: 1536`) for the session when installing a large stack.

## Run JavaScript in the box too

```js
const r = await kern.runCode("console.log([1,2,3].map(x => x * x))", {
  image: "node:20-slim",
  language: "node",
});
```

`language` is `"python"` (default), `"bash"`, `"sh"` or `"node"`. Match the image to the language:
**`bash` runs bash and `sh` runs the POSIX shell**, which are different languages (`[[ ]]`, arrays and
`pipefail` are bash), and alpine carries no bash at all. Asking for one the image lacks returns an
`exec_failed` fault naming it, never a different shell.

## The result

`runCode`/`run` resolve to an `ExecutionResult`:

| field | meaning |
|---|---|
| `stdout`, `stderr` | captured output (each capped at `maxOutputBytes`) |
| `exitCode` | the process exit code |
| `durationMs` | wall-clock duration of the call, in ms |
| `success` | `true` iff `exitCode === 0` **and** no sandbox fault |
| `fault` | a sandbox event, or `null`. `{ type, message }` |
| `files` | files created/modified in the workspace this call |
| `results` | rich mime-typed values (`Result[]`): last expression, `display()`, matplotlib figures |
| `truncated` | output hit the cap and overflow was discarded |

A non-zero exit from *your code* is **not** a fault (`fault` stays `null`): it is a normal result.
`fault` is only set when the **sandbox** acted:

| `fault.type` | when |
|---|---|
| `timeout` | the call exceeded `timeoutS`; the binding killed the box |
| `escape_blocked` | a syscall was blocked by the seccomp filter (SIGSYS) |
| `oom` | the box was SIGKILLed and a `memoryMb` cap was **in force**: a breached `memory.max` is the cgroup OOM-killer (`memory.oom.group=1` kills the whole box). kern reports whether the cap actually bound on an unforgeable per-box channel (2nd byte of `KERN_STARTED_FD`), so this is an *enforced-cap* OOM |
| `killed` | a SIGKILL **not** attributed to a cgroup OOM: no `memoryMb` cap was set, or kern reported the cap did not bind here (no cgroup delegation), so it is host pressure / an external kill. Older kern (no enforcement byte) falls back to `oom` when a cap was set |

| `exec_failed` | the box started but the command did not exist inside it. `runCode(code, {language:"node"})` on an image with no `node` is the ordinary way to reach it; the message names the binary AND the image, because the remedy is a different `language` or a different `image`. The `language` enum is a convenience, not a promise about the image: the default `python:3.12-slim` carries `python` and `bash`. A shell's own `command not found` inside your script stays an ordinary non-zero exit |

**An enforced `pids` cap produces no fault, and that is deliberate.** When `pids` binds, the refused
`fork` returns `EAGAIN`. Code that catches it exits 0, so the call reports `fault: null, success:
true` and a contained fork bomb reads as a successful run. `EAGAIN` is an ordinary errno a program is
allowed to handle, unlike a SIGKILL it cannot; labelling it a sandbox fault would misreport a process
that exited cleanly. Code that does **not** catch it dies naming "Resource temporarily unavailable".
The cap itself is enforced: on WSL2, `pids: 32` blocked at 29 forks while `pids: 256` let 120 through,
same code and same image.

A box that fails to **start** (kern exits 125: a mount refused at runtime, an unmappable `--user`, a
seccomp/AppArmor/cgroup setup error, or a pull/image error) is **thrown** as a `SandboxError`, not
returned as a fault, because the code never ran.

```js
const r = await kern.runCode("while True: pass", { timeoutS: 5 });
r.success;      // false
r.fault.type;   // "timeout"
```

## Safe by default

Every relaxing option says so in its name or docs:

- **network off** unless `network: true` (session-level, explicit).
- **hard caps**: `memoryMb` (512), `pids` (256), optional `cpus`. Enforced by cgroup v2.
- **timeout owned by the binding**: `timeoutS` (30) is a real deadline; the binding kills the box (and
  its process group), so a `timeout` fault is a fact, not a guess.
- **output bounded**: `maxOutputBytes` (64 MiB each) so a flooding box cannot exhaust host RAM.
- **env off argv**: workload env is written to a private `0600` file, never `--env K=V` on the command
  line, so a credential in `env` does not leak into `ps`.
- **mounts refused**: sensitive host sources (`/`, `/etc`, `/root`, `/proc`, `/sys`, `/dev`, the docker
  socket, `$HOME`) and escaping targets are refused even when asked.
- **workspace I/O contained**: `writeFile`/`readFile` reject `..` escapes and open the final component
  `O_NOFOLLOW`, so a symlink the box plants cannot redirect host I/O outside the workspace. They also
  open `O_NONBLOCK` and refuse a descriptor that is not a REGULAR file. A symlink is not the only thing
  a box can leave at a name: `mkfifo out.png` used to make `readFile("out.png")` wait for a writer that
  never comes, with no timeout, so the box chose how long the host's call took. The flag alone would be
  worse than the hang, because a non-blocking read of a writer-less FIFO returns zero bytes and the
  call would report an EMPTY FILE. Both halves ship: it returns promptly, and it refuses.

### Options

```ts
new Sandbox({
  image,           // default "python:3.12-slim"
  setup,           // one-time, network-on, e.g. "pip install pandas"
  workspace,       // host dir to persist; omit for a temp dir deleted on close()
  memoryMb,        // default 512
  cpus,            // default null (uncapped)
  pids,            // default 256
  timeoutS,        // default 30, MANDATORY per-call deadline
  network,         // default false (RELAXES ISOLATION)
  capDrop,         // default ["ALL"]: capabilities dropped from every box. kern always drops
                   // 16 dangerous ones; this drops the rest, which were held over the box's own
                   // user namespace. Pass [] to keep them (needed only if the workload binds a
                   // port below 1024 INSIDE the box).
  mounts,          // { hostSrc: boxTarget } or { src: [target, "ro"] }
  tmpfs,           // omitted -> 64 MiB of scratch at /tmp; {} -> none; { "/tmp": "512m" } to resize
  profiles,        // reusable kern.toml profiles: ["vcpu:heavy", "vgpio:leds", "vdisk:scratch"]
  env,             // { KEY: "value" }
  maxOutputBytes,  // default 64 MiB
  enforceLimits,   // default true; false is best-effort and NO faster (see the Python README)
  securityProfile, // "untrusted" = seccomp allowlist + cap-drop ALL + read-only root, one opt-in bundle
  apparmor,        // a PRE-LOADED AppArmor profile the box enters on exec (Docker's --security-opt
                   // apparmor=), an LSM layer over seccomp; kern fails the box CLOSED if it isn't loaded.
  requireLimits,   // default false; true = FAIL-CLOSED (refuse to start unless caps enforced). NOT
                   // enforceLimits (that picks the cap PATH); mutually exclusive with KERN_ALLOW_UNCAPPED env.
  depsReadonly,    // default TRUE: runCode cannot modify what setup= installed
  trackFiles,      // default true: diff the workspace each call for result.files (O(files)); false = [], O(1)
  onStdout,        // (chunk: Buffer) => void, live stdout streaming (result.stdout still captured)
  onStderr,        // (chunk: Buffer) => void, live stderr streaming
});
```

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

## Charts, rich results, live output, and checkpoints

**Rich results (the "code interpreter" pattern).** `runCode` runs Python by default, and like a
Jupyter cell it captures rich, mime-typed values into `result.results` (a list of `Result`) with
**no Jupyter kernel**: the value of the code's **last bare expression**, every **`display(obj)`** call,
and **every open matplotlib figure automatically** (no `savefig`). Accessors: `.png`/`.jpeg` (Buffer),
`.html`, `.svg`, `.markdown`, `.json`, `.text`.

```js
await kern.withSandbox({ setup: "pip install matplotlib pandas" }, async (sbx) => {
  let r = await sbx.runCode("import matplotlib; matplotlib.use('Agg')\n" +
    "import matplotlib.pyplot as plt; plt.plot([1,4,9])");
  const png = r.results.map((x) => x.png).find(Boolean) ?? null;  // figure Buffer, auto-captured

  r = await sbx.runCode("import pandas as pd; pd.DataFrame({'a':[1,2]})");
  r.results[0].html;                            // the DataFrame as an HTML table (also .text)
});
```

Capture never touches `stdout`/`stderr`/`exitCode`; a statement returning `None` yields no result. You
can still WRITE an artifact to the workspace and `readFile` it if you prefer.

**Warm kernel (kill the interpreter boot).** Each `runCode` starts a **fresh** interpreter, paying the
CPython boot (~12 ms) every call. When you run many cells that share state (a REPL, a notebook, an
agent's tool loop), open a `kernel()`: ONE warm interpreter in a long-lived box, fed cells over a pipe.
In-memory state persists across cells and the per-cell cost drops from ~14 ms to **sub-millisecond**
(~300x). Same rich `results` capture as `runCode`.

```js
await kern.withSandbox(async (sbx) => {
  const k = await sbx.kernel();
  try {
    await k.runCode("import numpy as np; a = np.arange(1_000_000)");  // imports paid once
    const r = await k.runCode("a.sum()");                            // 'a' is still here; ~sub-ms
    console.log(r.results[0].text);                                  // 499999500000
  } finally {
    await k.close();                                                 // tears the box down
  }
});
```

The trade vs `runCode`: cells in a kernel share one process and one box, so it is call-fast but not
call-isolated (still network-off and resource-capped; a fresh session or kernel is clean). An uncaught
error is confined (`exitCode` 1, traceback on `stderr`, the kernel keeps serving); a per-cell `timeoutS`
tears the kernel down (a running cell cannot be interrupted), after which it refuses further cells.

**Live output.** Pass `onStdout` / `onStderr` to stream each chunk as it arrives. The callback is
best-effort, not lossless: a SLOW callback drops chunks rather than applying backpressure to the box
(the full capped output is always in `result.stdout`).

**Checkpoints.** `sbx.snapshot(dest)` writes a portable `.tar.gz` of the workspace (a FILESYSTEM
checkpoint, not memory); `sbx.restore(src)` extracts it back, refusing absolute / `..` / symlink
members. Interoperable with `tar` and the Python binding (both write plain USTAR, so a workspace path
must be under 100 bytes). The Node path uses a hand-rolled tar reader,
so while it is new it is **opt-in**: set `KERN_SANDBOX_SNAPSHOT=1` to enable it (it fails closed with a
clear error otherwise). The Python binding uses the stdlib `tarfile` and has no such gate.

## Honest threat model

kern is a **kernel-boundary** sandbox for **your own or semi-trusted** code (CI, dev, edge, your
agents' code). Its default seccomp filter is a **deny-by-default allowlist** (moby's own default
filter minus kern's 35 escape syscalls): right for semi-trusted agent code, **not** a hard boundary
against deliberately hostile multi-tenant code. For that, reach for a microVM (Firecracker / Kata) or
gVisor. The wider denylist is the opt-out (`KERN_SECCOMP=denylist`), and `securityProfile: "untrusted"`
bundles the allowlist with `--cap-drop ALL` + `--read-only`. See the project's
[SECURITY.md](https://github.com/getkern/kern/blob/main/SECURITY.md).

## License

[Apache-2.0](https://github.com/getkern/kern/blob/main/LICENSE).
