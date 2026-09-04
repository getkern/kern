# Run pi's coding tools in a kern box

An extension for [pi](https://github.com/earendil-works/pi) that routes its built-in `bash`, `read`,
`write`, `edit`, `ls`, `grep` and `find` tools into a kern box. Your working directory is mounted at
`/workspace`, so edits write through to the host and everything else a command touches is discarded
with the box.

pi's default posture is no sandbox: it runs with the permissions of the user who launched it.

```sh
cd integrations/pi && npm install
cd /path/to/your/project
pi -e /path/to/kern/integrations/pi
```

Needs Linux and the `kern` binary on `PATH` (or `KERN_BIN` pointing at it).

## What is confined, and by what

This is the part to read before trusting it, because the two halves are not confined by the same
thing.

| Tool | Runs where | Confined by |
|---|---|---|
| `bash` and `!` | **inside the box** | namespaces, seccomp allowlist, memory/pids/CPU cgroup caps |
| `ls` `grep` `find`, and `mkdir`/`access`/`stat` | **inside the box** | the box's mount namespace: it has no view of the host outside `/workspace` |
| `read`, and the staging half of `write` | host filesystem | the SDK's `O_NOFOLLOW` plus a post-open `readlink("/proc/self/fd")`, measured independently sufficient |

A command the agent runs cannot see your `$HOME`, cannot reach the network unless you name a host,
and cannot outlive its cap. That boundary is the kernel's.

The file tools are a different claim. They are ordinary host I/O, and what keeps them inside your
project is `refuseOutsideWorkspace()`: one function, twenty lines, which resolves `..` before testing
the prefix and **refuses** anything landing outside `/workspace` rather than clamping it. Reads and
writes additionally go through the SDK, which opens the final component `O_NOFOLLOW` and walks
directory components itself so a symlink planted in the workspace cannot redirect them.

That is a path check and a syscall flag. It is not a namespace. If your threat model is a prompt
injection aimed at `~/.ssh/id_rsa`, the command path is stopped by the kernel and the file path is
stopped by that function. Both stop it; only one of them is the kernel.

The alternative would be to route file operations through the box as well, which is what the
[gondolin example](https://github.com/earendil-works/pi/tree/main/packages/coding-agent/examples/extensions/gondolin)
does with a micro-VM. It costs a box per read. This trade is stated here rather than left to be
discovered.

## Compared with the gondolin extension

|  | gondolin | this |
|---|---|---|
| Isolation | micro-VM: a separate kernel | namespaces + seccomp: the same kernel |
| File tools cross the boundary | yes | no, see above |
| Needs | QEMU, Node >= 23.6 | the `kern` binary |
| Per-command cost | a VM boot, amortised | a fresh box per command |
| Runs on macOS | yes | only inside a Linux VM |

**gondolin isolates harder.** A micro-VM is a hardware boundary; kern's is the Linux kernel's, so a
kernel privilege-escalation bug is an escape and kern's own docs say so. If the code your agent will
run is hostile, use the micro-VM. This extension is for the ordinary case: your own project, your own
prompts, and a boundary that costs milliseconds instead of a boot.

## Configuration

All optional, all environment variables, because an extension you drop in with `pi -e` should not
need a config file.

| Variable | Default | What it does |
|---|---|---|
| `KERN_PI_IMAGE` | `python:3.12-slim` | the OCI image commands run in |
| `KERN_PI_EGRESS` | (none) | comma-separated hosts the box may reach, e.g. `registry.npmjs.org,pypi.org` |
| `KERN_PI_MEMORY_MB` | `2048` | hard RAM cap per command |
| `KERN_PI_PIDS` | `512` | task ceiling per command |
| `KERN_PI_TIMEOUT` | `120` | seconds per command, unless pi passes its own |
| `KERN_PI_MAX_OUTPUT` | `1048576` | cap on captured stdout and stderr, each, per command. The SDK's own default is 64 MiB; this is lower because every chunk is forwarded into pi's single-threaded renderer and the agent picks the command |
| `KERN_PI_TMPFS_MB` | `256` | scratch at `/tmp`, charged to the box's own memory cap, thrown away with the box |
| `KERN_PI_HOME` | `/workspace` | where `$HOME` points, so a toolchain's cache has somewhere to go. `/tmp/home` keeps the cache out of your project and loses it with the box |

**Two of these will bite you, so set them first.**

**Node 22 or newer is required on the HOST**, and the failure without it is not obvious. `pi`'s own
package manager imports `globSync` from `node:fs`, which landed in Node 22, so on Node 20 (still LTS
at the time of writing) the extension dies at import with `SyntaxError: The requested module 'node:fs'
does not provide an export named 'globSync'`, naming a file inside `pi-coding-agent` rather than
anything of yours. Measured on a clean aarch64 board: Node 20.18.1 fails that way, Node 22.11.0 runs
all 165 assertions. `package.json` now declares `engines: node >= 22`, so npm says it before the import
does.

**The image must carry your project's toolchain.** The default has Python and no `node`, so on a
TypeScript project the agent's `bash` fails at the first `npm`. Point `KERN_PI_IMAGE` at an image
that matches what you build with.

**Nothing installs without egress.** The box has no network by default, so `npm install` and `pip
install` fail until you name the registry:

```sh
KERN_PI_IMAGE=node:22 KERN_PI_EGRESS=registry.npmjs.org pi -e /path/to/kern/integrations/pi
```

`KERN_PI_EGRESS` is a host allowlist and not a boolean on purpose: an agent that needs one registry
does not need your whole network, and the SDK's `network: true` would hand it over on every command.

## One fact everything below inherits

**Every command is a fresh box, so the workspace is the only path that survives one.** Not a caveat:
it is the architectural fact of this extension, and three things follow from it that would otherwise
look like separate quirks.

- **A package cache re-downloads per command** unless it lives in the workspace. That is why
  `KERN_PI_HOME` points at `/workspace` and not at the scratch: it is load-bearing, not convenient.
- **Anything with a lockfile, a daemon socket or a resume file in `TMPDIR` is broken across
  commands** by construction. The state written on one call is gone on the next, while whatever
  referenced it from the workspace is still there pointing at nothing.
- **`KERN_PI_MEMORY_MB` bounds the cgroup, not the agent's usable memory.** `/dev/shm` is a
  memory-backed filesystem in every box with no size at all (the kernel default, half of host RAM),
  charged to the same cap and not sizeable through this extension or the SDK. An agent that runs
  anything using `multiprocessing` is using it.
- **Every BOUNDED path in the system is memory.** The scratch is a tmpfs charged to the box's memory
  cap; a `vdisk:` profile is also a RAM-backed tmpfs when rootless (kern uses a disk-backed
  ext4-on-loop only when privileged). So the only unbounded-but-persistent path is the host workspace,
  and every bounded one is memory. That is the whole trade in a sentence.

Measured, not reasoned: writing a marker to `/tmp` in one command and reading it in the next returns
GONE, and the same pair against `/workspace` survives. The suite asserts both.

This is also a real difference from a gVisor-backed runner, and the reason is privilege rather than
design: gVisor's root overlay is memory-backed for the same reason, and they added a **disk** backing
precisely because memory-backed file data bloats container memory. Rootless, that escape is closed
here.

**The shell is measured, not assumed.** pi's tool is called `bash` and a model writes bash by reflex,
so the extension asks the box once at open which shell it has and uses that. On `python:3.12-slim` it
is bash; on an image without one it is `sh`, and the status line says which. This mattered: the SDK's
`language: "bash"` used to run `sh`, which on a Debian image is dash, with bash present in the same
image and unused, so `[[ -f x ]]` answered `sh: 1: [[: not found`.

**Why `$HOME` and `/tmp` are set for you.** The box root is read-only, so a toolchain gets exactly two
writable places and it needs both. With neither, `npm install express` on `node:22` exits 2; with
`HOME` alone and a read-only `/tmp` it still exits 2; with both it exits 0 and the cache moves to
`/workspace/.npm`. All three measured. The reason this is a default and not a knob you discover is
the error it produces: npm renders a failed `mkdir /root/.npm` as

```
npm error enoent Invalid response body while trying to fetch https://registry.npmjs.org/express
```

which sends you to check `KERN_PI_EGRESS`, the one thing that was already right. Go is no better:
`failed to initialize build cache at /root/.cache` is true and says nothing about `HOME`.

## Running it non-interactively

```sh
pi --mode json -p "your prompt"        # events on stdout, one JSON object per line
```

**Use `--mode json`, not the default `--mode text`.** `--mode` takes `text` (default), `json` or
`rpc`, and only `json` emits anything before the answer: a `{"type":"session"}` line arrives at once,
so you can see that a run started. A `--mode text -p` run that stalls prints **nothing at all**, on
stdout or stderr, `--verbose` included, which turns a stall into a stare. That is pi's behaviour and
not this extension's, and it is worth knowing before you script a run.

If you are scripting it, read pi's own exit code. Reading the exit code of the last command in a
pipe (`pi ... | tail`) reports `tail` succeeding and makes a timeout look like a clean no-op.

## Tests

```sh
node --experimental-strip-types test.ts        # the seven operations, against a real box
node --experimental-strip-types test-edge.ts   # the adversarial edges of the containment
npx tsc --noEmit                               # against pi's and kern's real types
```

No test runner and no dev dependency beyond the two type packages: `node` runs the files. Both exit
non-zero on a failure, so either is usable as a gate. `harness.ts` holds the assertions they share.

`test.ts` asks whether the operations work; `test-edge.ts` asks whether the path check can be talked
out of its job, with the agent choosing every string and allowed to plant symlinks in its own
workspace. Both need `kern` and a cached image. Between them they have already returned three defects
that reading could not have found:

- pi's `timeout` is in **seconds**; a version that divided by 1000 turned the 120 s default into one,
  and only a stopwatch says so
- `maxBytes` in the SDK is a **refusal**, not a partial read, so the image sniffer silently reported
  every screenshot as "not an image"
- the glob was compiled to a RegExp, and `a*` sixty times against four hundred `a`s took **149
  seconds** of backtracking. Since the agent picks the pattern and node is single-threaded, that was
  a denial of service the agent could ask for. It is a linear two-pointer matcher now, and the same
  input takes 0 ms

## Status

Written against pi's operation-injection API (`createBashTool(cwd, { operations })` and its six
siblings) and the `kern-sandbox` Node SDK. **Not yet exercised against a live pi session**: the
interfaces are taken from pi's own sources, so the shapes are right, but nothing here has been run
end to end. Reports welcome.

## Compatibility, precisely

Not a full replacement for the gondolin extension. What is covered and what is not, so nobody has to
find out by using it:

| | this | gondolin |
|---|---|---|
| `bash` tool | in the box | in the VM |
| `!command` typed by the user | in the box | in the VM |
| `read` `write` `edit` `ls` `grep` `find` | host I/O, workspace-confined | in the VM |
| `powershell` tool | **not routed**: stays on the host | not routed |
| Image reads (`detectImageMimeType`) | **not implemented** | implemented |
| Cancelling a running command | the call returns at once; the box dies on its own deadline | the guest process is aborted |
| `PI_*` session environment | exported into the script | passed as env |
| Session shutdown | box closed | VM closed |
| macOS / Windows host | **no** (Linux only) | yes |

Two of those deserve a sentence rather than a row.

**`powershell` is deliberately not routed.** kern runs Linux images and the default one has no
`pwsh`, so routing it would turn a working host command into a confusing failure. On a Windows host
pi's powershell tool therefore stays outside the box. If that matters for you, say so in an issue.

**Cancellation is weaker.** kern's SDK has no abort, so Ctrl-C tells pi immediately and abandons the
call, and the box is reaped by its own `timeoutS` rather than killed on the spot. gondolin aborts the
guest process. A long command you cancel keeps burning its cap until the deadline.
