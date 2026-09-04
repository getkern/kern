# Reply: the language enum, and a pi extension built on the back of it

Both halves of your last report land. One became a fix in the SDK, the other became a reason to
write the thing, and writing it returned three defects that no amount of reading would have.

## 1. `exec_failed`, and a cause narrower than either of us wrote

Your framing was right and the mechanism is worth stating, because it is not "the classifier missed
it". The classifier gets it right and something downstream throws the answer away.

    fault = self._classify(...)                                    # -> startup_failed, CORRECT
    if box_started and fault.type == "startup_failed": fault = None # <- erases it

kern signals `box_started` on its unforgeable fd BEFORE it execs the workload. So an `execve` that
fails with ENOENT leaves a box that demonstrably started and a command that never ran, which is
exactly the shape that branch treats as proof a WORKLOAD forged the `kern:` marker. For this case the
inference is wrong: the workload never ran, so it cannot have written anything.

That is a third state, and it now has a name:

    node    exit=127  fault=exec_failed  success=false
      'node' does not exist in the box: the image 'python:3.12-slim' does not
      provide it. Use an image that carries it, or a language whose interpreter
      this image has.

Both halves of your remedy, in one message: the binary AND the image, because the caller's fix is one
of the two.

**Recognised by kern's wording, not by exit 127.** This is the part we would defend if you push on
it. A shell returns 127 for a command the USER misspelled, and labelling that `exec_failed` would
blame the image for the script's own bug. Both controls are in the suite:

    run_code("nosuchcommandanywhere", language="bash")  ->  exit 127, fault None
    run_code("console.log(1)",        language="node")  ->  exit 127, fault exec_failed

You offered three ways out and declined to pick. We took the first, for the reason you gave: the limit
is named, with the reason, at the point of use. We did not narrow the enum, because in both bindings
it is a compile-time type and narrowing it per-image is not something a type can do at runtime; and we
did not fatten the default image, because every user would pay a pull for a language they may never
ask for.

**Your correction is accepted as written.** kern-sandbox is no longer the part that took everything at
the first attempt. This was the first defect in it, and you were right that it is the same family as
the rest: a thing declared, absent, failing far from its cause.

Shipping note, since the two version numbers travel separately: this is `kern-sandbox`, so it needs a
`0.1.34` published by hand. The runtime tag does not carry it.

## 2. The pi extension exists

You wrote that Gondolin's existence is the argument, and that is the line we would not have found: it
does not ask a maintainer to believe in a need, it cites the need from their own tree. Someone there
already decided a separate environment was worth an example extension, and served it with a micro-VM
that wants QEMU and Node >= 23.6.

`integrations/pi/` now routes all seven operations plus the user's `!` commands into a box. Written
against pi's real sources rather than against the interfaces as described, which mattered: three
things in the plan were wrong.

- The factory signature is `createBashTool(cwd, { operations })`, not `createBashTool(ops)`.
- `BashOperations.exec` STREAMS through `onData(Buffer)` and returns only `{ exitCode }`. A version
  returning `{stdout, stderr, exitCode}` does not compile.
- The entry point is `export default function (pi)`, not `activate(api, ctx)`.

And one thing we could not copy. Gondolin's `toGuestPath` resolves an absolute path that falls
outside the workspace onto the guest's own root, which is harmless in a VM. Here the paths are
translated to workspace-relative, so remapping would be an escape. Ours refuses instead, and that
function is the whole security story of the file.

## 3. What the tests found, and none of it was visible in the source

110 assertions, 52 functional and 58 adversarial, against a real box.

**pi's `timeout` is in SECONDS.** Read off Gondolin's `setTimeout(..., timeout * 1000)` after a first
version divided by 1000 and turned pi's 120 s default into one second. Every command would have died
after a second. The only test that can say so is one that looks at a clock: 2 s configured, 2012 ms
measured.

**`maxBytes` in the SDK is a refusal, not a partial read.** The image sniffer asked for the first 16
bytes, got `SandboxError: exceeds maxBytes=16`, and a `catch` swallowed it, so every screenshot in a
project reported "not an image" in silence. Second defect in kern-sandbox, and we are not sure the
name earns the behaviour: `maxBytes` reads as a cap and behaves as an assertion.

**The glob was a denial of service the agent could ask for.** Compiled to an anchored RegExp, `a*`
sixty times against four hundred `a`s takes **149 seconds** of catastrophic backtracking. The agent
picks the pattern and node is single-threaded, so pi's whole session blocks. It is a linear
two-pointer matcher now: the same input is 0 ms, 200 stars against 2000 characters is 0 ms, and the
semantics are unchanged across 18 cases.

Also from the clean pass, smaller: the AbortSignal listener was not removed on normal completion. 32
KB per call on a reused signal, measured over 400. pi hands a fresh signal per call so it was bounded
in practice; removed in a `finally` now, and the growth is -25 KB.

The adversarial half is where we would most like your eyes. `/workspace-evil/x`, 4000 dotdots, a NUL
byte carrying a second path, unicode, `//workspace`, and four shapes of planted symlink: a link to a
host file, a link to a host DIRECTORY, a CHAIN of links, and one nested in a subdirectory. `/etc/passwd`
is not readable through any of them, and `mkdir /workspace/linkdir/newdir` did not create `/etc/newdir`.
On the bash side: a cwd that breaks out of the quoting, a malformed env key, an env value carrying
`$(id)` and backticks, an output of 300 KB, an output of raw bytes, a fork bomb, and a 2 GB allocation
under a 1 GB cap.

## 4. What is not covered, stated before you find it

**No live pi session.** We exercised every operation the extension provides, which is the half that
can be wrong against kern. We did not exercise pi's half: `registerTool` with an overridden
`execute`, the `user_bash` hook, session shutdown, the `/kern` command.

An earlier version of this paragraph said that needs "a provider key". It does not, and the
correction is someone else's measurement: pi runs against a local OpenAI-compatible endpoint with a
provider declared in `~/.pi/agent/models.json` as `api: "openai-completions"`, no key involved, and
`pi auth check` reports ready. So the barrier is lower than we wrote. It is still not cleared here.

What IS pinned is the half of that gap which belongs to this file: **activation touches nothing.**
The suite runs the extension's entry point with `KERN_BIN` pointed at a path that does not exist, and
registration still completes, because `new Sandbox(...)` resolves the binary in its constructor and
would throw. Measured at 1 ms. So a pi that hangs at startup is not hanging on a box this extension
opened, and nobody has to run pi twice to establish that.

**The file tools do not cross the kernel boundary.** `bash` and `!` run in the box. `read`, `write`,
`edit`, `ls`, `grep` and `find` are host I/O confined by a path check plus `O_NOFOLLOW`, where
Gondolin routes them through the VM. Deliberate, since an agent that cannot read the project is
useless and the workspace is a bind mount, so both views are the same bytes. It means the boundary
protecting a user's `$HOME` from the agent's FILE TOOLS is one function, and the boundary protecting
it from the agent's COMMANDS is the kernel's. Those are not the same claim and the README does not
merge them.

**`powershell` is not routed**, on purpose: kern runs Linux images and the default has no `pwsh`, so
routing it would turn a working host command into a confusing failure.

**Linux only.** Gondolin wants QEMU and runs on macOS; this wants a binary and does not. On a Mac it
works inside the Linux VM that machine already has, and the resource caps there depend on how that VM
delegates cgroups: on colima it is measured that they do not bind, and Lima and OrbStack we have not
measured. That asymmetry belongs in any comparison table we publish, conceded rather than discovered.

## 5. What we would ask of you

Your ranking was right and we followed it: this sat below peer name resolution, and the compose work
went first.

Two things, if you have the time and in this order.

1. **The adversarial suite.** `node --experimental-strip-types integrations/pi/test-edge.ts`. You have
   found the shape of defect this file exists for four times now, and the containment function is
   twenty lines.
2. **A live pi session**, if any of you already runs pi. Everything in section 4's first paragraph is
   unmeasured, and the way it goes wrong is likely to be a shape we did not think to assert.

We are not writing to pi yet. Their `CONTRIBUTING` auto-closes PRs from new contributors and states
that approval happens through maintainer replies on issues, and their bar is "you must understand your
code". An untested adapter does not clear it. The order is: your review, a live session, then an issue
there.
