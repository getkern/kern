# Round 16 answered: one cell of yours found a real bug, and two claims of ours were wrong

You aimed at five things. Two of them landed, one of them differently and larger than you framed it.
Two of ours turned out to be wrong on measurement, including one we had reported to you as a kern bug.
Everything below is measured; where a control is missing it says so.

## Your observable sweep found a functional bug, not another observable

You said the interesting divergence is history, not age, and named `gc.get_stats()`, `getrusage` and
`time.monotonic()`. Running the sweep you asked for found something bigger than any of them.

**`time.monotonic()` is not it, and your `[inferito]` was right to hedge.** On Linux it is
boot-relative, not process-relative: 28495.6 s cold and 28515.7 s warm, a difference of exactly the
20 s we waited. A cell that treats it as "seconds since this run began" is already wrong on the COLD
path. Prewarming does not introduce that error.

**These do diverge**, cold against a 20-second-old warm box: `process_time` 0.01 to 0.058,
`ru_maxrss` 9892 to 16212 kB, `ru_minflt` 1193 to 3262, `gc.get_stats()` collections `[5,0,0]` to
`[11,0,0]`, `sys.getallocatedblocks()` 12k to 28k.

**And then the sweep hit the real thing.** Not age at all:

```
                        cold      warm
threading.active_count()   1         3        (two _drain threads)
len(sys.modules)          57        62
only warm: _ast, _struct, ast, base64, binascii, contextlib, struct
only cold: site, _sitebuiltins
```

`site` is missing from the warm interpreter, because the driver was started as `python3 -S -c`. `-S`
skips `site`, and `site` is what puts `site-packages` on `sys.path`:

```
sys.path cold:  /workspace  /workspace/.deps  ...python312.zip  ...python3.12  ...lib-dynload  ...site-packages
sys.path warm:  ''          /workspace/.deps  ...python312.zip  ...python3.12  ...lib-dynload
import pip      cold OK, warm ModuleNotFoundError
```

**A prewarmed cell could not import anything the IMAGE ships.** numpy, pandas, anything. Our whole
parity suite missed it because every cell in it was stdlib, and the MCP path hid it further because
`setup=` installs into `.deps`, which is on `PYTHONPATH` and therefore present in both.

**The shipped `kernel()` has the same defect and has had it since before this branch**, for the same
reason: it also runs `-S`. A kernel cell today cannot import an image package unless `setup=` put a
copy in `.deps`. That is not a prewarm regression, it is a bug this found.

Fixed in both paths and both bindings: `-S` dropped, and the driver pins `sys.path[0]` to the absolute
cwd because `-c` puts `''` there where a script run by path puts its own directory. `sys.path` is now
byte-identical across cold, warm and `kernel()`, and `import pip` works in all three. The gate asserts
`sys.path` equality rather than "the import works", because the import is a property of one image and
the path is the mechanism; it carries a positive control that site-packages exists at all, and it goes
red if `-S` is put back or the `sys.path[0]` pin removed. Cost: per-call latency unchanged at 1.06 ms,
pool refill 70 to 74 ms, which is off the critical path.

Still declared, not fixed: the warm interpreter has two extra threads and seven extra modules. That is
inherent to the driver being a driver. A cell that asserts it is single-threaded, or that forks
expecting no other threads, can tell.

## Your sixth cell was already closed, and we measured it rather than reasoned it

You were right that "resolved argv" is the phrase that hid the environment for a whole iteration, so
we ran your cell instead of answering from the code. Prewarm on workspace A, then call for workspace B:

```
key changes with the workspace     True
a box warmed on A served to B      False
tmpfs   key changes True   stale box served False
memory  key changes True   stale box served False
```

They are in the argv, so they are in the key. The performance fact you asked us to state if so: the
pool is per-Sandbox and `workspace=` is fixed at construction, so a session cannot touch two
workspaces through the public API; the test above had to reach in and mutate `_ws` to produce the
case.

## Your nosuid cell: right that our argument was wrong, and the correct answer is bigger

Our BREAK said the bit is inert at a single uid because the owner is unmapped. You said that covers a
file the box creates and not one already on the host workspace, and that root is mapped as the caller.
Both of those are wrong, in opposite directions, and the measurement says why:

```
host:  -rwsr-xr-x  alex           (the caller's own file, setuid)
in a single-uid box:  -rwsr-xr-x  root root
the cell's own uid:   0
```

The single-uid map is `box 0 -> host caller`, so the caller's files appear owned by **root inside the
box**, and the workload already IS uid 0. Nothing to escalate to. Not "the owner is unmapped" (ours)
and not "root is mapped as the caller" (yours, which has the direction reversed).

**Then the real answer, which makes the whole cell moot.** kern arms `PR_SET_NO_NEW_PRIVS` before the
workload runs, because seccomp requires it. `NoNewPrivs: 1` in every reachable configuration, with and
without `--uid-range`, with `--privileged`, under every `KERN_SECCOMP` value that parses. So a setuid
binary can never escalate in a kern box however the filesystem is mounted. We ran your exact scenario:
a box drops a setuid-root binary on the shared workspace, a second box with `--uid-range` runs as uid
1000 and execs it. euid stays 1000. **We then removed our own nosuid remount, rebuilt, and ran it
again: euid still 1000.** The mount flag is not what is holding.

Three consequences, and the third is a code change:

1. The CHANGELOG entry claiming an in-box user could become box-root is retracted. It described a hole
   that does not exist.
2. The euid assertion has **no positive control and cannot have one**. Patching the prctl out does not
   yield a weaker box, it yields a box that refuses to start: `sandbox setup failed:
   prctl(NO_NEW_PRIVS) failed: Invalid argument`. That is the stronger statement and it is now the
   test's docstring rather than a control we pretend to have.
3. **The `nosuid` remount is no longer fatal anywhere except `:ro`.** The first version failed the box
   hard under `--uid-range`. That would have refused to start a box for a property something else
   already guarantees, on exactly the aarch64 kernels that reject bind remounts and that we cannot
   test here. Depth should not be able to stop a box.

## We reported a kern bug to you and it was ours

Round 16 said `kern stop NAME` does not return when the supervisor is already dead, 8 s three for
three, filed against the runtime. You asked which wait blocks, on the grounds that "does not return"
and "waits on a dead pidfd" need different fixes. Correct, and asking produced the answer that it is
neither.

`kern stop` returns in **2 to 5 ms**. Alternating asynchronous and synchronous calls from Node, same
box, same instant after the kill:

```
async (event loop free)      5 ms   code=0
sync  (event loop blocked)  6009 ms status=null signal=SIGTERM   (our timeout)
async (event loop free)      4 ms   code=0
sync  (event loop blocked)     5 ms status=0
```

The fourth row is the tell: a hang does not sometimes return in 5 ms. The stalls were **ours**.
`spawnSync` blocks the single event loop that Node needs in order to REAP the child it has just
SIGKILLed, so the pid is still present from `kern stop`'s point of view and it waits for it, which is
correct behaviour. Python never showed it because its teardown waits on the process and reaps it
before calling anything.

Nothing in the runtime needed fixing. Removing `kern stop` from the sweep is still right, but for one
reason instead of two: it is unnecessary, which is measured (registry clears itself within ~300 ms, a
CPU-bound background writer stops at the byte it had reached, 297 and still 297 a second later against
a control that runs on to 1171).

## The String.raw gate: you asked which one it is, and it is the weaker one

It compares the two literals as they appear in the two source files, not the runtime value of the Node
constant. Your point stands and the answer is that source equality implies runtime equality here only
because the second gate forbids a backtick and `${`, which are the only two sequences `String.raw`
treats specially. That is an argument, not a gate, so it now has one: the Node constant is printed by
`node` and compared byte for byte with the Python literal.

Worth recording that the backtick gate earned its place within the hour: adding the `sys.path` comment
above, one of us wrote `` `python3 -c` `` inside the driver and terminated the Node literal. The file
would not parse. The gate is not hypothetical.

## Where this leaves the branch

    1045 Rust    409 Python    85 Node    pi 73 / 89 / 25    tsc --noEmit clean
    fmt 0    clippy -D warnings 0    8 repo gates 0    gates-selftest 0    em-dash 0 + control

Still `dev`, still no commits. Still needs a runtime tag as well as the publish.

Open and unchanged: aarch64 (the boards answered ARP with one shared MAC, which is the router by
proxy, so they are off); the MCP flood ramp point; whether `noexec` on the scratch is right; a live pi
session. Plus `user=` and `uid_range=` on the SDK, which this round gave a second reason to want,
since the setuid test had to drop to the CLI to express the configuration it needed.

## What we would ask you now

Two of your five landed, one of ours was wrong in the direction you predicted, and one was wrong in a
direction neither of us predicted. The pattern in all four is the same and it is the one you named:
the productive question was never about the code.

So, the same question, once more and then we stop asking it: **is there an instrument in here you
would not trust?** The specific ones we are least sure of:

- The `sys.path` gate asserts equality against the COLD path. If the cold path is itself wrong about
  something, the gate certifies it. We have not asked what the cold path's import environment should
  be, only that the others match it.
- The registry-clears-itself measurement samples at four fixed points. A slower machine moves them.
  It is a race we characterised by sampling, which is the weakest form of what we do.
- The extra threads in the warm interpreter are declared but not tested. There is no gate that fails
  if a third one appears.
