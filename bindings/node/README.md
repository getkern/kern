# kern-sandbox (Node.js / TypeScript)

**Run LLM-generated code in a fast, real sandbox, one fresh box per call.**

Fast means milliseconds, and it is two numbers rather than one: the box is the cheap part, and an
interpreter starting inside it costs more than the box does. Both depend on your machine, so they are
measured under [Prewarming](https://github.com/getkern/kern/blob/main/bindings/node/README.md#prewarming-a-box-ready-before-the-call-arrives) with the machine and the method beside them, and the
runtime's own are in [BENCHMARKS.md](https://github.com/getkern/kern/blob/main/BENCHMARKS.md).

`kern-sandbox` is the Node and TypeScript binding for **[kern](https://getkern.dev)**: a rootless,
kernel-enforced sandbox out of one static binary, with no daemon, no VM and no cloud. An agent's
tool-call, a model's generated snippet, a CI step: code that runs before anyone reads it gets its own
box, and the box is thrown away after.

Network off, memory and PID caps the kernel enforces **where your host delegates them**,
capabilities dropped, a deny-by-default seccomp allowlist, and a wall-clock deadline the binding
applies from **outside** the box, so code that hangs cannot outlive it. Whether the caps bind is a property of your
HOST, not of kern: they need a delegated cgroup, which a desktop session has and a bare root shell
in a container often does not. `kern doctor` says which you have, and `requireLimits: true` makes an
unenforceable cap FATAL: the box refuses to start rather than run uncapped. It arrives the way every
other refusal does, as `fault.type === "startup_failed"` on the result, NOT as an exception from the
constructor, so a caller that only catches exceptions will walk past it.

The runtime this drives, its tests and the other bindings are one repository:
**[github.com/getkern/kern](https://github.com/getkern/kern)**. Dependency-free: it shells out to
the `kern` binary and does not re-implement isolation in JavaScript.

**Your loop reads a field, not a stack trace.** A timeout, an OOM-kill, a blocked syscall or a missing
interpreter each arrive as a typed `fault` on the result, beside stdout and the exit code, so the
agent branches on a value instead of parsing text to work out who ended the run.

On npm: [`npm install kern-sandbox`](https://www.npmjs.com/package/kern-sandbox). Python gets the same
package on PyPI: [`kern-sandbox`](https://pypi.org/project/kern-sandbox/), which also ships an **MCP
server** for Claude Desktop, Cursor and LM Studio.

```js
const kern = require("kern-sandbox");

// one-shot: a throwaway box, network off, hard caps, a timeout the binding enforces
const r = await kern.runCode("print(sum(range(100)))");
console.log(r.stdout, r.success); // "4950\n" true
```

TypeScript types ship in the package. `Buffer` is in the public surface, so a TypeScript consumer needs
`@types/node` **and** a `tsconfig.json` that includes it. MEASURED with `tsc` 7.0.2: without the types,
8 errors saying `Cannot find name 'Buffer'`; with the types installed but no `tsconfig.json`, the same 8;
with `{ "compilerOptions": { "types": ["node"] } }`, zero. Installing the package `tsc` names is half the
remedy, which is worth stating because the error message only hints at the other half.

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

The first call on a machine that has never run it is the slow one: it pulls `python:3.12-slim` before
it can start a box. Every call after that reads the cached image, and the `startup_failed` row below
has the measured cost of that first read, which on a slow machine is large enough to trip a short
`timeoutS`.

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
await kern.withSandbox(
  { setup: "pip install pandas matplotlib", memoryMb: 1536 },
  async (sbx) => {
    await sbx.writeFile("data.csv", "a,b\n1,2\n3,4\n");
    const r = await sbx.runCode(
      "import matplotlib; matplotlib.use('Agg')\n" +
        "import pandas as pd, matplotlib.pyplot as plt\n" +
        "df = pd.read_csv('data.csv'); print(df.describe())\n" +
        "df.plot(); plt.savefig('out.png')",
    );
    console.log(r.stdout);        // network off, capped, isolated
    const chart = await sbx.readFile("out.png");   // a Uint8Array of the PNG
  },
);
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
`fault` is only set when the **sandbox** acted:

| `fault.type` | when |
|---|---|
| `timeout` | the call exceeded `timeoutS`; the binding killed the box |
| `escape_blocked` | a syscall was blocked by the seccomp filter (SIGSYS) |
| `oom` | the kernel's OOM killer took the box against its own memory cap. Read from a descriptor the code in the box cannot write, so it is an observation and not a guess from the exit code |
| `killed` | SIGKILL with **no** OOM reported: an external kill (`kern stop`, a signal, the host out of memory), or a cap that did not bind here, which the message names |
| `exec_failed` | the box started, the command did not exist inside it. `{language:"node"}` on an image with no `node` is the ordinary way there; the message names the binary AND the image |
| `startup_failed` | the box never ran, and kern said why in `stderr`. Two shapes: your `timeoutS` fired while kern was still BUILDING the box (run it again: if the second call is fast it was a cold image read, and if it is not, look for a bind source on a dead NFS export), or kern refused to build it at all (an image that cannot be pulled, a mount it will not make). The cold read is the FIRST call on a new machine and it is not small: 38 s for an arm64 image on a Raspberry Pi 5 here, against 0.1 s warm |

```js
const r = await kern.runCode("while True: pass", { timeoutS: 5 });
r.success;      // false
r.fault.type;   // "timeout"
```

A box that fails to **start** is **thrown** as a `SandboxError`, not returned as a fault, because the
code never ran.

`stderr` is one stream shared by kern and your code, so a note about an undelegated cgroup arrives
interleaved with the program's own output. Right for a human at a terminal, wrong for anything that puts
`stderr` into a prompt. `codeStderr` is the same string without kern's own lines, and nothing is hidden:
`runtimeNotes` holds exactly what was taken out.

## Safe by default

Every relaxing option says so in its name or docs:

- **network off** unless `network: true` (session-level, explicit).
- **hard caps**: `memoryMb` (512), `pids` (256), optional `cpus`. Enforced by cgroup v2.
- **timeout owned by the binding**: `timeoutS` (30) is a real deadline; the binding kills the box (and
  its process group), so a `timeout` fault is a fact, not a guess.
- **output bounded**: `maxOutputBytes` (64 MiB each) so a flooding box cannot exhaust host RAM.
- **env off argv**: workload env is written to a private `0600` file, never `--env K=V` on the command
  line, so a credential in `env` does not leak into `ps`.
- **mounts refused**: the host's own sources (`/`, `/etc`, `/root`, `/boot`, `/proc`, `/sys`, `/dev`,
  `$HOME`, the docker socket), any path with a **credential directory** in it (`.ssh`, `.aws`, `.gnupg`,
  `.kube`, `.docker`, `.azure`, `.oci`, `.terraform.d`, `.password-store`, `.netrc`, `.git-credentials`,
  `.pypirc`, `.npmrc`, `.databrickscfg`, `.boto`, `.s3cfg`, `.rclone.conf`, and under `.config`:
  `gcloud`, `gh`, `doctl`, `rclone`),
  **kern's own state** (`$XDG_RUNTIME_DIR/kern`, the image cache, the config dir, the data dir that
  holds every named volume: the sandbox's control plane), and escaping targets.
- **workspace I/O contained**: `writeFile`/`readFile` reject `..` escapes, open the final component
  `O_NOFOLLOW` so a symlink the box plants cannot redirect host I/O, and refuse anything that is not a
  REGULAR file (see the notes for the FIFO that made a read hang).

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

**`network: true` includes the host's LOOPBACK, which is where unauthenticated services live.** It
puts the box in the host's network namespace, so `127.0.0.1` inside the box is the host's
`127.0.0.1`: a test's cell connected to `127.0.0.1:22` and read back `SSH-2.0-OpenSSH_9.6p1`,
and a developer's laptop is where a database, a Redis and a dashboard sit bound to localhost with no
password. The same connect is refused under the default `network: false`, and `egressAllow` refuses
it too, because that one goes through kern's proxy rather than through the host's stack.

```js
await kern.withSandbox({ egressAllow: ["pypi.org", "files.pythonhosted.org"] }, async (sbx) => { /* ... */ });
```

The box stays in its own network namespace and reaches the internet only through kern's filtering
proxy, which permits those domains and nothing else: a workload can fetch from an index you chose and
cannot exfiltrate elsewhere. Mutually exclusive with `network: true`. The `setup` box keeps full
network to install dependencies; the allowlist governs the run phase, which is the one executing code
you did not read.

It is a **route-level** boundary, not proxy variables a program can ignore. Measured inside the box: a
raw socket to an IP returns `ENETUNREACH`, DNS does not resolve, and a request to a domain outside the
list is refused by the tunnel with `403`, while the same socket under `network: true` connects. The other
edge of that: a client which does not speak to an HTTP proxy has no path out at all, so a Postgres, MySQL
or Redis connection under `egressAllow` cannot resolve its host. For a database, the setting today is
`network: true`.


`kernel()` returns a `Kernel`, and a refused mount throws `MountRefused` rather than the generic
`SandboxError`, so a caller can tell "this sandbox will not do that" from "the sandbox broke".
`DEFAULT_TMPFS_MB` and `version` are exported for callers that assert on them.

## Prewarming: a box ready before the call arrives

`prewarm: N` keeps N boxes started in advance, each holding a booted interpreter that has run nothing,
and refills in the background while your agent thinks. Measured on `python:3.12-slim`:

| `runCode` | first call | p50 within the burst |
|---|---:|---:|
| default | 30.9 ms | 14.2 ms |
| `prewarm: 4` | 0.9 ms | **0.8 ms** |

**The number is `runCode`, not `run()`.** A prewarmed box holds a BOOTED INTERPRETER, so what the
pool removes is the interpreter's cost and not the box's. `run(["true"])` starts a fresh box either
way and reads the same either way: measured, 4.74 ms with the pool against 4.67 ms without it. Time
the wrong call and prewarming looks like a no-op.

**The pool covers a burst, not a rate**, and it refills in the background: past N the cost returns to
the default, and a call made immediately after construction pays the default until the boxes exist.

Each prewarmed box still serves ONE call and is thrown away, so the isolation is unchanged: only the
moment of creation moves. The pool key includes the image, the caps and the profiles, so a session never
receives a box built for another one.

```js
await kern.withSandbox({ image: "python:3.12-slim", prewarm: 4 }, async (sbx) => {
  const r = await sbx.runCode("print(1)");   // served from the pool
});
```

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
await kern.withSandbox({ setup: "pip install pandas matplotlib" }, async (sbx) => {
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

**Two jobs, and the handoff is the point.** A microVM product (Docker Sandboxes, Firecracker, Kata,
gVisor) gives the code a kernel of its own, and that is the right answer when the code is actively
hostile or belongs to someone else. It costs what a machine costs: measured here against `sbx`
0.43.0 on the same laptop, half a second per command in a live sandbox and about three seconds to
create one, against 2 ms and 4 ms for kern, with `uname -r` inside reading its own kernel there and
the host's here. kern is for the OTHER job, the one an agent loop does a thousand times: a cell per
call, network off, memory and pids the kernel enforces where the host delegates them, a
deadline applied from outside the box.
Pick by which job you have, not by the ratio.

**What the box does NOT hide from the code inside it.** The caps are real and the kernel enforces
them where it can, but the box still reads the HOST's numbers for things nothing charges it for:
`df` on the workspace reports the host's filesystem, because that is what it is, a bind mount with
no quota, and `nproc` reports the host's core count even under a `cpus` cap, which caps TIME and not
the count (measured here: 28 inside a box capped at 0.5 cores, 28 outside). Anything that sizes
itself from a cgroup-unaware API is in the same family: Go's `GOMAXPROCS`, some JVMs, `ray`-style
CPU detection. `memoryMb` and `pids` ARE enforced and visible as limits, but ONLY where the host
gives kern a delegated cgroup: on one that does not (a root shell with no user manager, some CI
runners) kern warns and the box runs UNCAPPED. `kern doctor` says which path a host takes, and
`requireLimits: true` refuses to start rather than run a box whose caps are decoration.

**`npm install kern-sandbox` does not install the sandbox.** The binding drives a `kern` binary it
finds on `PATH` or in `$KERN_BIN`, and that is a SECOND thing to install and to keep current: a
binary that is not kern is refused by name, but an OLDER kern runs fine and answers fewer questions,
because the fault taxonomy reads bytes only newer builds write. If a verdict looks wrong, print
`kern --version` before anything else.

## License

[Apache-2.0](https://github.com/getkern/kern/blob/main/LICENSE).
