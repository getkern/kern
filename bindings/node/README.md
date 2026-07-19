# kern-sandbox (Node.js / TypeScript)

Run LLM/agent-generated code in a fast, **local**, daemonless kernel sandbox, straight from Node.

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
and dies); every `runCode` after it is network-off.

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
  env,             // { KEY: "value" }
  maxOutputBytes,  // default 64 MiB
  enforceLimits,   // default true (systemd scope, ~6 ms); false = best-effort, ~3 ms
  depsReadonly,    // default false
});
```

## Honest threat model

kern is a **kernel-boundary** sandbox for **your own or semi-trusted** code (CI, dev, edge, your
agents' code). Its seccomp filter is a **denylist**: right for semi-trusted agent code, **not** a hard
boundary against deliberately hostile multi-tenant code. For that, reach for a microVM (Firecracker) or
gVisor. See the project's [SECURITY.md](https://github.com/getkern/kern/blob/main/SECURITY.md).

## License

[Apache-2.0](https://github.com/getkern/kern/blob/main/LICENSE).
