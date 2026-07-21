# kern-sandbox (Node.js / TypeScript)

Run LLM/agent-generated code in a fast, **local**, daemonless kernel sandbox, straight from Node.

On npm: [`npm install kern-sandbox`](https://www.npmjs.com/package/kern-sandbox). For Python, the same
package is on PyPI: [`kern-sandbox`](https://pypi.org/project/kern-sandbox/).

It is a thin, dependency-free wrapper around the [`kern`](https://github.com/getkern/kern) binary:
a fresh, isolated box per call, network off by default, hard resource caps, and a timeout the binding
itself enforces. E2B/Firecracker territory, but local and about 1.6 MB, with no cloud, no account, no VM.

```js
const kern = require("kern-sandbox");

// one-shot: a throwaway box, network off, hard caps, a timeout the binding enforces
const r = await kern.runCode("print(sum(range(100)))");
console.log(r.stdout, r.success); // "4950\n" true
```

TypeScript types ship in the box:

```ts
import { runCode, withSandbox, Sandbox } from "kern-sandbox";
```

## Install

```sh
npm install kern-sandbox
```

You also need the `kern` binary on `PATH` (or point `$KERN_BIN` at it). One line on Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

kern needs a Linux kernel with unprivileged user namespaces + cgroup v2. On Windows it runs under WSL2;
on macOS, inside a Linux VM. Node 18+.

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

`language` is `"python"` (default), `"bash"`, or `"node"`. Match the image to the language.

## The result

`runCode`/`run` resolve to an `ExecutionResult`:

| field | meaning |
|---|---|
| `stdout`, `stderr` | captured output (each capped at `maxOutputBytes`) |
| `exitCode` | the process exit code |
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
| `killed` | the box was SIGKILLed, most often the cgroup OOM-killer |
| `startup_failed` | kern could not start the box (bad image, pull error, ...) |

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
  `O_NOFOLLOW`, so a symlink the box plants cannot redirect host I/O outside the workspace.

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
  mounts,          // { hostSrc: boxTarget } or { src: [target, "ro"] }
  profiles,        // reusable kern.toml profiles: ["vcpu:heavy", "vgpio:leds", "vdisk:scratch"]
  env,             // { KEY: "value" }
  maxOutputBytes,  // default 64 MiB
  enforceLimits,   // default true (systemd scope, ~6 ms); false = best-effort, ~3 ms
  depsReadonly,    // default false
  trackFiles,      // default true: diff the workspace each call for result.files (O(files)); false = [], O(1)
  onStdout,        // (chunk: Buffer) => void, live stdout streaming (result.stdout still captured)
  onStderr,        // (chunk: Buffer) => void, live stderr streaming
});
```

`runCode`/`run` also take `timeoutS`/`onStdout`/`onStderr` as **per-call** options that override the
session defaults for that one call. A `vcpu:` profile can carry `cpus`+`memory`; `memoryMb`/`cpus` are
explicit flags that **override** a profile's values (and the `memoryMb` default `512` shadows a profile's
`memory`, so pass `memoryMb: null` to let the profile apply). The **MCP server** (`kern-mcp`, for Claude
Desktop / Cursor) ships in the Python package `kern-sandbox` (`pip install kern-sandbox`).

## Charts, rich results, live output, and checkpoints

**Rich results (the "code interpreter" pattern).** `runCode` runs Python by default, and like a
Jupyter/E2B cell it captures rich, mime-typed values into `result.results` (a list of `Result`) with
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
CPython boot (~10 ms) every call. When you run many cells that share state (a REPL, a notebook, an
agent's tool loop), open a `kernel()`: ONE warm interpreter in a long-lived box, fed cells over a pipe.
In-memory state persists across cells and the per-cell cost drops from ~16 ms to **sub-millisecond**
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
agents' code). Its seccomp filter is a **denylist**: right for semi-trusted agent code, **not** a hard
boundary against deliberately hostile multi-tenant code. For that, reach for a microVM (Firecracker) or
gVisor. See the project's [SECURITY.md](https://github.com/getkern/kern/blob/main/SECURITY.md).

## License

[Apache-2.0](https://github.com/getkern/kern/blob/main/LICENSE).
