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

**Your loop reads a field, not a stack trace.** A timeout, an OOM-kill, a blocked syscall or a missing
interpreter each arrive as a typed `fault` on the result, beside stdout and the exit code, so the
agent branches on a value instead of parsing text to work out who ended the run.

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
| `codeStderr` | `stderr` with kern's own `note:`/`warning:` lines removed: what the code wrote. Feed THIS to a model |
| `runtimeNotes` | the complement: the lines kern wrote about itself. `stderr` still holds both, in order |
| `exitCode` | the process exit code |
| `durationMs` | wall-clock duration of the call, in ms |
| `success` | `true` iff `exitCode === 0` **and** no sandbox fault |
| `fault` | a sandbox event, or `null`. `{ type, message }` |
| `files` | files created/modified in the workspace this call |
| `results` | rich mime-typed values (`Result[]`): last expression, `display()`, matplotlib figures |
| `truncated` | output hit the cap and overflow was discarded |

A non-zero exit from *your code* is **not** a fault (`fault` stays `null`): it is a normal result.

`stderr` is one stream shared by kern and your code, so a note about overlayfs or an undelegated
cgroup arrives interleaved with the program's own output. That is right for a human reading a
terminal and wrong for anything that puts `stderr` into a prompt, where it spends context on the
runtime's housekeeping and reads like an error the code produced. `codeStderr` is the same string
without those lines, and nothing is hidden: `runtimeNotes` holds exactly what was taken out. The
LangChain tool and the MCP server already use it.
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

**The sharp edges are in [SANDBOX-NOTES.md](https://github.com/getkern/kern/blob/main/bindings/node/SANDBOX-NOTES.md):**
the writable paths and why `/tmp` is a tmpfs, `memoryMb` bounding the cgroup rather than usable
memory, scratch that does not survive a call, and the two writable places a toolchain needs before
`npm install` stops reporting a network error that is not one. Each is a measured surprise.

## Egress: the setting between no network and the host's

`network: false` gives the run phase no network and `network: true` gives it the host's. `egressAllow`
is the middle one, and usually the one an agent wants:

```js
await withSandbox({ egressAllow: ["pypi.org", "files.pythonhosted.org"] }, async (sbx) => { /* ... */ });
```

The box stays in its own network namespace and reaches the internet only through kern's filtering
proxy, which permits those domains and nothing else: a workload can fetch from an index you chose and
cannot exfiltrate elsewhere. Mutually exclusive with `network: true`. The `setup` box keeps full
network to install dependencies; the allowlist governs the run phase, which is the one executing code
you did not read.

`kernel()` returns a `Kernel`, and a refused mount throws `MountRefused` rather than the generic
`SandboxError`, so a caller can tell "this sandbox will not do that" from "the sandbox broke".
`DEFAULT_TMPFS_MB` and `version` are exported for callers that assert on them.

## Prewarming: a box ready before the call arrives

`prewarm: N` keeps N boxes started in advance, each holding a booted interpreter that has run nothing,
so a `runCode` claims one instead of paying for a box start plus an interpreter boot. Measured on
`python:3.12-slim`, six calls each: **14.2 ms p50 by default against 0.8 ms with `prewarm: 4`**, and
30.9 ms against 0.9 for the first call.

**The pool also fills on that worker thread, so the first call is fast only once it HAS filled.**
Measured: constructing with `prewarm: 4` and calling immediately gives 13.7 ms five times over,
while half a second later the same burst reads 0.8, 0.6, 0.5, 0.6 for the first four and then
32.7 for the fifth, the pool empty. The table is the steady state, not the first moment.

The refill runs while your agent thinks, so it is off the caller's clock. That also says when it buys
nothing: if calls arrive faster than the pool refills, the pool empties and you are back to the
default cost. N is the burst you want covered, not a throughput knob.

Each prewarmed box serves ONE call and is discarded, so the isolation is unchanged: a fresh box per
call, network off, the same caps. Only the moment of creation moves. That is the difference from
`kernel()`, which deliberately shares one process across cells.

```js
await withSandbox({ image: "python:3.12-slim", prewarm: 4 }, async (sbx) => {
  const r = await sbx.runCode("print(1)");   // served from the pool
});
```

The pool key includes the image, the caps and the profiles, so a session with different settings never
receives a box built for another one.

## Run pi's coding tools in a box

[`integrations/pi`](https://github.com/getkern/kern/tree/main/integrations/pi) is an extension for
[pi](https://github.com/earendil-works/pi) built on THIS binding: it routes pi's built-in `bash`,
`read`, `write`, `edit`, `ls`, `grep` and `find` tools into a kern box. The working directory is
mounted at `/workspace`, so edits write through to the host and everything else a command touches dies
with the box. pi's default posture is no sandbox: it runs as the user who launched it.

The two halves are not confined by the same thing, and the extension's README says which is which:
`bash` runs INSIDE the box (namespaces, seccomp allowlist, cgroup caps), while `read` and the staging
half of `write` are host filesystem calls guarded by this binding's `O_NOFOLLOW` and its
`/proc/self/fd` containment check. Needs Linux, the `kern` binary, and **Node 22 or newer**: pi's own
package manager imports `globSync` from `node:fs`, which landed in 22.

## Charts, rich results, live output, and checkpoints

`runCode` captures mime-typed values into `result.results` the way a notebook cell does: the **last
bare expression**, every **`display(obj)`**, and **every open matplotlib figure automatically**, with
no `savefig`. Accessors: `.png`, `.jpeg`, `.html`, `.svg`, `.markdown`, `.json`, `.text`.

```js
await withSandbox({ setup: "pip install pandas matplotlib" }, async (sbx) => {
  await sbx.writeFile("data.csv", "a,b\n1,2\n3,4\n");
  const r = await sbx.runCode("import pandas as pd; pd.read_csv('data.csv').describe()");
  r.results[0].html;                       // the DataFrame as an HTML table
});
```

Capture never touches `stdout`, `stderr` or `exitCode`. Pass `onStdout` / `onStderr` to stream output
as it arrives (best-effort: a slow callback drops chunks rather than stalling the box).

`snapshot(dest)` and `restore(src)` write a portable `.tar.gz` checkpoint of the **workspace**;
`restore` refuses absolute, `..` and symlink members. Nothing in `/tmp` is on it, because a tmpfs is
on no layer.

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
