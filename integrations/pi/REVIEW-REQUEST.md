# Round 7: the whole `dev` branch, after our own audit. What did we not look at?

**The files this is about**, so you can open them rather than search for them:
[`bindings/python/kern_sandbox/__init__.py`](../../bindings/python/kern_sandbox/__init__.py) ·
[`bindings/python/kern_sandbox/mcp.py`](../../bindings/python/kern_sandbox/mcp.py) ·
[`bindings/node/index.js`](../../bindings/node/index.js) ·
[`bindings/node/index.d.ts`](../../bindings/node/index.d.ts) ·
[`integrations/pi/index.ts`](index.ts) ·
[`harness.ts`](harness.ts) ·
[`README.md`](README.md) ·
[`REPORT.md`](REPORT.md) ·
[`CHANGELOG.md`](../../CHANGELOG.md)

**The suites**:
[`bindings/python/tests/test_sandbox.py`](../../bindings/python/tests/test_sandbox.py) ·
[`test_mcp.py`](../../bindings/python/tests/test_mcp.py) ·
[`bindings/node/test/sandbox.test.js`](../../bindings/node/test/sandbox.test.js) ·
[`test.ts`](test.ts) · [`test-edge.ts`](test-edge.ts) · [`test-hostile.ts`](test-hostile.ts)

Everything you raised in rounds 1 to 6 is closed. This asks a different question, so the useful
answer is not another pass over the same ground: **we audited this branch ourselves and found four
more defects, all of a shape you would recognise. We want to know what that audit still cannot see.**

Branch `dev`, 21 files, unpublished. `kern-sandbox` **0.1.36** (unreleased: the extension requires it
and `requireScratchSupport()` refuses at startup against 0.1.35, because a 0.1.35 IGNORES the `tmpfs`
option rather than failing). Runtime unchanged, no crate touched, no tag.

    python  392 passed        node  75 passed
    pi      test 73 / test-edge 89 / test-hostile 25        tsc --noEmit clean
    cargo fmt --all --check 0     RUSTFLAGS="-D warnings" cargo clippy --workspace 0
    7 repo gates bare, all exit 0                            em-dash 0, positive control 1
    twine check PASSED on wheel and sdist (with readme_renderer[md]; without it, a false green)

---

## What we changed, in one list

1. **Every box gets a writable `/tmp`**: a 64 MiB tmpfs, charged to the box's own memory cgroup, and
   `tmpfs=` is exposed. The `setup=` box is excluded from the default, because an install needs
   unbounded scratch and 64 MiB turned `pip install pandas` into ENOSPC.
   `_DEFAULT_TMPFS` in [`__init__.py`](../../bindings/python/kern_sandbox/__init__.py),
   `DEFAULT_TMPFS` in [`index.js`](../../bindings/node/index.js).
2. **`language="bash"` runs bash**, and `sh` is a language of its own for the POSIX shell.
   `_LANGS` in [`__init__.py`](../../bindings/python/kern_sandbox/__init__.py).
3. **The MCP `run_code` schema** no longer advertises an interpreter the configured image lacks, and
   names that image. New `KERN_MCP_TMPFS_MB`. `_TOOLS` and `_tools_view` in
   [`mcp.py`](../../bindings/python/kern_sandbox/mcp.py).
4. **`max_bytes`/`maxBytes`**: behaviour and name unchanged, the error now says it is a REFUSAL.
5. **pi extension** ([`index.ts`](index.ts)): `HOME` and `/tmp` writable by default, the shell
   MEASURED once at open, `boxOptions()` exported and typed `SandboxOptions`, a guard on the SDK
   version, `KERN_PI_HOME` validated, `KERN_PI_TMPFS_MB=0` aligned with the MCP sentinel.
6. **Our own suites**: the vacuous fork bomb replaced by a measured storm with a `pids` discriminant,
   every `exec` in [`test-edge.ts`](test-edge.ts) wrapped so one slow command costs one assertion,
   [`harness.ts`](harness.ts)'s `fatal()` printing the tally, and the flood test in
   [`test_mcp.py`](../../bindings/python/tests/test_mcp.py) re-paired onto the plateau.

## What OUR audit found, so you can skip it

We audited the new option against a real box rather than against its own docstring. Four defects,
all measured, all now refused with a message that names the trap:

| spelling | what kern does with it | what the caller meant |
|---|---|---|
| `tmpfs={"/tmp": "64"}` | 64 **BYTES**. `df` reports 4 KB, a 100 KB write is ENOSPC | 64 MiB |
| `tmpfs={"/tmp": "0"}` | **UNLIMITED**. 200 MiB under `memory_mb=128` exited **137** | none |
| `tmpfs=["/scratch:9g"]` | mounts `/scratch` at 9 GiB; the named dir does not exist | a dir called that |
| `tmpfs: 256` (Node) | `Object.entries(256)` is `[]`: **silently no scratch** | 256 MiB |

kern is right to accept the first three: it is the low-level interface. The fourth is the mistake
this API invites, since every neighbouring option (`memoryMb`, `pids`) takes a number. We also added
the `t` unit, because kern accepts it and a gate narrower than the thing it guards is its own kind of
wrong.

The disabling ladder on the default tmpfs holds on all five cells: default `ok`, `tmpfs={}` `ro`,
explicit `1k` `ok`, rw bind at `/tmp` `ok`, **`:ro` bind at `/tmp` `ro`** (the caller's decision, now
documented as such rather than left as a surprise).

## Round 7 closed all four, and one of your recommendations died on measurement

**§1 sentinel collision: guarded twice, and neither guard is the other's copy.** Measured with `df`
inside the box, as you asked: `KERN_MCP_TMPFS_MB=0` and `KERN_PI_TMPFS_MB=0` both produce **no mount**
(`df /tmp` reports the overlay root), not a large one. And the cell you named, a binding that forgot
the interception: the string it would emit is `"0m"`, which the size gate refuses in BOTH bindings.

**§2 flags: you were right, and the delta is smaller than either of us assumed.** By exercise, never
by `/proc/mounts`:

    /tmp   rw,nosuid,nodev,size=65536k   cp /bin/true /tmp/x && /tmp/x  ->  RUNS      (no noexec)
    mknod /tmp/n c 1 3                                               ->  REFUSED   (nodev holds)
    /workspace   rw,relatime  (plain host ext4 bind)                 ->  RUNS

Your inspection-lies point is exactly right and we hit it: a file in the tmpfs shows `-rwsr-xr-x`
while `nosuid` makes the kernel ignore the bit at exec, so an `ls -l` assertion reports the opposite
of the truth. But the third line is the one that moves the conclusion: **`/workspace` was already
writable AND executable, with no nosuid and no nodev.** Scratch is strictly MORE restricted than the
path that was already there, so the default did not open a door that was shut. We did not choose the
flags, we cannot (`--tmpfs` takes `path[:size]`, no flag argument, and changing that is a runtime
change this delivery does not make), and both facts are now pinned by exercise.

**§3 constant against variable: confirmed, with the control that isolates reclaimability.** At
`memory_mb=128`, write 56 MiB then allocate 90:

    56 MiB on /tmp (tmpfs), synced        ->  OOM
    56 MiB on /workspace (host), synced   ->  SURVIVES        <- the control
    56 MiB on /workspace, NOT synced      ->  OOM             <- dirty pages, not the mechanism

So it is a hard floor the previous behaviour did not have. The `oom` fault now names the scratch and
states the mechanism, and does not claim it caused that kill. That also answers your Q4 closing
question for free: a `"1t"` tmpfs shows **1.0T free** in `df` and the first write past the cap is an
OOM, not ENOSPC, so the effective ceiling is `min(size, memory_mb)` and the fault message is the only
thing in the system that says so.

**§4 duplication: a pair assertion now compares the produced ARGV**, over one corpus, for the run box
AND the setup box, with the corpus required to contain a case where the two differ. Positive control
both ways: a different Node constant fails with `run box differs`, a missing setup exclusion fails
with `SETUP box differs`, which is the divergence you named. The setup exclusion was in both. And
pi's 256 is now `DEFAULT_TMPFS_MB * 4`, exported from the binding, so it is one fact and a multiple
rather than two numbers that drift.

## Your `HOME` recommendation: tried, and refuted by the premise under it

Your accounting was right and we measured it: `npm install express`, one small package, leaves
**7.7 MB in `/workspace/.npm` on the host** plus a `.npm` directory in the user's project. So the
bounding claim was half-true exactly as you said.

We changed the default to `/tmp/home` anyway, and then measured the premise instead of the change:

    command 1:  mkdir -p /tmp/home && echo x > /tmp/home/marker   ->  WRITTEN
    command 2:  cat /tmp/home/marker                              ->  GONE
    control:    the same two commands against /workspace          ->  survives

**Every command is a fresh box, so the scratch is fresh too.** `HOME` on the scratch means `$HOME`
does not exist when a command starts and the package cache is re-downloaded on EVERY command. With
per-command boxes, persistence and boundedness cannot both hold: the workspace is the only persistent
writable path. Reverted, with that assertion now in the suite, since it is the reason the default is
what it is. `KERN_PI_HOME=/tmp/home` remains for anyone who wants the other side of the trade.

Your Q2 conclusion survives regardless: the security delta of a writable `/tmp` is near zero, and for
a reason neither of us had stated - `/workspace` was already writable, executable, and less
restricted.

## Round 8: your four cells, run. Two were defects, one does not exist, one is a doc

**§1 `df` lying to a program: taken, and the clamp had to be measured, not chosen.** Both options
now resolve against each other at construction. A size the CALLER wrote and that exceeds the cap is
refused, naming both numbers; OUR default is clamped, because refusing it would make a box
unstartable for someone who never mentioned scratch. Clamping to the cap turned out to be the wrong
clamp, and only a measurement said so, writing 1 MiB chunks under `memory_mb=128`:

    tmpfs  32m  ->  ENOSPC after 32 MiB          the filesystem bound, cleanly
    tmpfs  64m  ->  ENOSPC after 64 MiB
    tmpfs 128m  ->  OOM                          the cap bound first, and the box died

A tmpfs EQUAL to the cap lands exactly on the cell the fix exists to avoid. So the clamp is to half.
End to end: `memory_mb=64` now yields 32m and returns `ENOSPC at 32 MiB` where it used to OOM.

*(An aside worth having: our first attempt at this measurement was wrong. `write(b'\0' * (400 << 20))`
allocates 400 MiB in RAM before writing a byte, so every cell reported OOM and the tmpfs limit never
got a chance to speak. Chunked writes were the discriminant.)*

**§2 `untrusted` x default scratch: a real defect, exactly as you predicted.** Measured:

    0.1.35 shape (tmpfs={}) + untrusted  ->  /tmp read-only, EROFS errno 30
    0.1.36 default          + untrusted  ->  /tmp writable AND executable

A hardening bundle widened in a patch release because a different layer added a default. The default
now steps aside for a `security_profile` exactly as it does for a `mounts` bind at the same target;
an explicit `tmpfs=` still applies under both.

**§2 persistent `workspace=` x ephemeral `/tmp`: confirmed, and it is the honest cost.**

    call 1:  write /workspace/state = "/tmp/lock"; write /tmp/lock   ->  WROTE BOTH
    call 2:  read the state, stat the path it names                  ->  STATE /tmp/lock DANGLING

You are right that this is the argument that survives, and right that it is our own worse shape:
success now, absence later. It is in both bindings' docs beside the tmpfs and pinned by a test. The
trade still stands, because the trap removed is more common than the one added, but the cost is the
caller's to know rather than ours to discover for them.

**§2 `vdisk:` at `/tmp`: the collision cannot be built.** A vdisk always mounts at `/vdisk/<name>`;
the target is not caller-controlled, so there is no third spelling reaching the same mountpoint. With
`--tmpfs /tmp:8m` and `vdisk:cache` together, both are present and both writable, and there is no
policy to pick.

**§2 `require_limits`: your reading is right and it is a doc point.** It starts fine with scratch
mounted and reads back `memory.max = 134217728` under `memory_mb=128`. It asserts the cap BINDS, not
that the cap is all yours. With the clamp the worst case is halved.

## Your §4 third option: measured, and it dies on the same premise

A `vdisk:` for the cache is a good idea and it does not work here, for a reason that is not obvious
from the outside:

    box 1:  echo ciao > /vdisk/cache/marker   ->  written
    box 2:  cat /vdisk/cache/marker           ->  GONE

A vdisk is created fresh per box, and rootless it is a RAM-backed tmpfs (kern uses an ext4-on-loop
backend only when privileged), so it is charged to memory too. So it gives neither the persistence
nor the disk-backed bound. **Two independent recommendations, yours and ours, refuted by the same
measured premise**: with per-command boxes, the workspace is the only persistent writable path. That
premise is the finding, and it generalises past both options.

## Round 9: your clamp objection is half wrong, and the half that is right found a defect

**The direction: it only ever reduces.** `min(64 MiB, memory_mb / 2)` cannot exceed 64, so your
`memory_mb=512` case gets **64m, not 256m**. Measured across the range and now asserted, because you
were right that "clamped to half" reads as a formula that applies both ways:

    memory_mb   128  256  512  1024  4096   ->  /tmp:64m   (unchanged)
    memory_mb    64   ->  /tmp:32m       127  ->  /tmp:63m  (reduced)

**The half that is right, we took verbatim.** Half came from three cells against one cap and cannot
distinguish itself from a quarter, because the experiment never varied the workload's own footprint.
It is now documented as a HEURISTIC and not a derivation, in both bindings, with your sentence as the
reason: there is no safe fraction, because the safe one depends on the workload's peak, which is what
`memory_mb` was meant to bound and now shares. Half is where the measurement stops being fatal.

## Your general form of the `untrusted` defect: built, and it found one immediately

You were right that the fix was specific and the mechanism was not. So the posture is pinned the way
`cli_surface_is_frozen` pins the flags: **for every security profile, the set of writable paths in
the box, asserted against a pin, with the profile list READ FROM `kern box --help`** so a profile the
runtime grows and the suite has not pinned fails here rather than being discovered.

It found a defect in its first run, and the defect was in this branch's own README:

    default                     ->  /tmp  /workspace  /dev/shm
    0.1.35 shape (tmpfs={})     ->        /workspace  /dev/shm
    untrusted                   ->        /workspace  /dev/shm

**`/dev/shm` is a third writable path and we had written "and nothing else".** It is not ours: it is
in the 0.1.35 shape too. What makes it worth your time is what it is:

    tmpfs /dev/shm tmpfs rw,nosuid,nodev,relatime   <- NO size= at all
    df: 16340356 KB                                 <- 15.6 GB, half of host RAM
    tmpfs={"/dev/shm": "16m"}  ->  kern REFUSES it (it would shadow the hardened /dev)

A writable, memory-backed, **unbounded** path in every box, charged to `memory_mb`, that this SDK has
no way to bound. Docker sizes it with `--shm-size`; kern has no equivalent. That is a runtime gap and
we are filing it as one, next to `/workspace` without `nosuid`. It also sharpens your own sentence:
every bounded path is memory, and one memory-backed path is not bounded at all.

## The premise, stated where a reader meets it

Taken. `integrations/pi/README.md` now opens its configuration section with it, and with the three
things you listed as inheriting from it: the per-command network cost of a cache that cannot persist
outside the workspace, the lockfile/socket/resume-file class broken by construction, and **every
bounded path being memory** because a rootless `vdisk:` is a RAM-backed tmpfs too. Your gVisor
comparison is in there as well, phrased as you put it: the escape is closed by privilege, not by
design, so someone benchmarking kern against a gVisor runner should expect scratch to differ.

## Round 10: both of your cheap checks, and one of them made the OOM note wrong

**Does `/dev/shm` inherit a size from anywhere? It inherits the HOST.** Measured on a 31914 MiB
machine:

    host RAM 31914 MiB, half = 15957
    inside a box with --memory 128m:  df -m /dev/shm  ->  15958

Exactly the `df`-lies-to-a-program shape, and worse than the one we fixed: the number scales with the
machine, not with the configuration, so the same code sees 2 GB on a 4 GB board and 64 GB on a 128 GB
server while `memory_mb` says 128. Nothing in the SDK can clamp it.

**Is `mounts` a way in? YES, and that softens your characterisation exactly as you suspected.**

    -v $HOSTDIR:/dev/shm   ->  BIND SUCCEEDED, the marker is readable, df shows the host filesystem

So it is reachable. It is still not BOUNDABLE by anything the SDK sets: a plain directory swaps an
unbounded RAM path for an unbounded disk one. To bound it you bind a host directory that is itself a
sized tmpfs. So: a documentation item for reachability, a real gap for boundedness, and the runtime
issue is worth filing for the sizing rather than for the access.

**Your `multiprocessing` point, and it broke something we shipped this round.** 200 MiB written to
`/dev/shm` under `memory_mb=128` OOMs the box regardless of the `/tmp` clamp, while the same 200 MiB
to `/tmp` returns ENOSPC and the box lives. The OOM note we added in round 7 said:

    NOTE: this box has scratch mounted (/tmp:64m). A tmpfs is charged to the same memory cap...

**Which is the wrong place.** The box died on `/dev/shm` and the message named ours. That is the
defect class this whole exchange has been about, committed by the fix for it, one round later. The
note now names both, names `/dev/shm` even when no scratch was mounted, and says it cannot be bounded
from here.

**And the honest sentence, taken verbatim as you wrote it**: `memory_mb` bounds the CGROUP, not the
workload's usable memory. It is in both bindings' READMEs, in the pi extension's premise list, and
pinned by a test that asserts the message names the path that actually took the budget. Which puts
`require_limits` back where you had it: it asserts the cap binds, and the cap can be exhausted by a
path this SDK cannot reach.

**The pin's own hole, in the pin's own comment.** It enumerates PROFILES, not paths, so a writable
path that appears only under conditions the suite does not construct is invisible to it. `/dev/shm`
is the proof that the path set has members nobody wrote down, and it was caught only because it is
present unconditionally.

**The `63m` residual**: written down, in the test, as the answer to the bug report someone will file.
An odd cap yields an odd scratch; rounding to a bucket trades one arbitrary thing for another.

## Round 11: the cell you asked for, and the instrument was wrong again

**`shared_memory` through the bind: it WORKS.** Measured, and the first run of the measurement said
otherwise because our probe read the wrong layer:

    mounts on /dev/shm:  2        <- the bind STACKS, it does not replace
        tmpfs  tmpfs             <- kern's own, first
        ext4   /dev/nvme1n1p3    <- the bind, and the last mount is the one that resolves
    multiprocessing.shared_memory  ->  OK
    multiprocessing.Queue (POSIX semaphores)  ->  OK

Our probe printed `lines[0]` and reported `tmpfs`, i.e. that the bind had not taken. Same shape as
the 400 MiB allocation two rounds ago: the instrument reported a different thing from the subject.
So your suspicion was right and your uncertainty was the right size: it is a real workaround, and
`shm_open` being a path-based open is enough for both of the users we tested.

**And the residue you predicted is real:** a file the box writes to `/dev/shm` through the bind is
**still on the host after the box dies**. Both the workaround and its two costs, disk-unbounded
instead of RAM-unbounded and no tmpfs lifetime, are now in both bindings' READMEs and pinned by a
test.

**The OOM note: your general statement, and why it lists candidates.** You are right that the
strongest form of this round is the fix for a misattributing message misattributing, for the reason
it exists to prevent. That sentence is now in the code, at the note. The stronger version you
suggested, naming the path by measured usage, is **not available**, and that is measured rather than
assumed: read post mortem, the box's cgroup reports `shmem=978944 anon=0` after 200 MiB went through
/dev/shm, because the mount died with the box and the pages went with it. `memory.events` still says
`oom_kill 3 oom_group_kill 1`, which confirms the kill and attributes nothing. Naming one path would
mean sampling `memory.stat` while the box is alive, on every run, for a message read only after a
failure. So: candidates, and the reason written down beside them.

**The pin now derives its path set from `/proc/self/mountinfo`**, exactly as you suggested. Positive
control: a `mounts` bind at `/data` appears in the derived set with nobody adding it.

    default                    ->  /dev/shm  /tmp  /workspace
    with a bind at /data       ->  /data  /dev/shm  /tmp  /workspace

`/dev/shm` would have been caught on day one by this version rather than by a README correction.

## Round 12: the stacking property was a defect, not just a detail

You said it was bigger than the workaround it validated. It was, and it was ours.

**A `mounts` bind and a `tmpfs` at the SAME target: the bind is silently shadowed.** We allowed it,
and our own test and docstring called it "an explicit tmpfs beats the bind", which described the ARGV
and not the outcome:

    -v $HOST:/tmp  --tmpfs /tmp:8m   ->  mounts on /tmp: 2
                                            ext4  /dev/nvme1n1p3     <- the bind, first
                                            tmpfs tmpfs              <- kern's, on top
                                         os.listdir('/tmp')  ->  []
    ...and the same with the arguments in the other order, so it is not order-dependent

The caller's file is on the host and invisible to the code meant to read it, which is the exact
failure the DEFAULT steps aside to avoid, reachable by writing both options explicitly. One of the
two is a mistake, the binding cannot tell which, so it now refuses and names both halves. That also
disposes of your third consequence: the clamp can no longer compute against a shadowed mount, because
the combination that produced one is gone.

**The pin is now keyed on `(mountpoint, fstype)`, last entry per mountpoint**, exactly as you said.
The discriminant is in the test:

    default                     ->  (/tmp,tmpfs) (/workspace,ext4) (/dev/shm,tmpfs)
    with a bind at /dev/shm     ->  (/tmp,tmpfs) (/workspace,ext4) (/dev/shm,EXT4)

The union version reported the same set for both, which is two materially different boxes.

**Your least confident item: nothing is written to `/dev/shm` before a bind can shadow it.** Measured
in the three places available, since the shadowed layer cannot be inspected from inside: kern's tmpfs
is empty at box start, the bind shows an empty directory, and the host directory is untouched
afterwards. Pinned by a test. So the workaround hides nothing.

**`memory.peak` survives the teardown**, and we are not using it, with the reason. Measured after an
OOM: `memory.peak 134217728`, `memory.current 1007616`, so the peak is readable and says the box
reached its cap. It adds nothing to an `oom` fault, where the peak is definitionally the cap. Where it
WOULD add something is `killed`, distinguishing host pressure from a cap that bound after all, and to
read it there the SDK would have to discover a cgroup path it does not own and does not track. That
is a new measurement channel for a message read after a failure, so: not now, and written down.

## Round 13: your scope question, and case B was a hole

Three cases, all measured against a real box before touching the check:

    -v HOST:/tmp      + --tmpfs /tmp       ->  /tmp EMPTY, the bind invisible        (was refused)
    -v HOST:/tmp/sub  + --tmpfs /tmp       ->  /tmp EMPTY, the bind invisible        (was NOT)
    -v HOST:/tmp      + --tmpfs /tmp/sub   ->  the bind's file reads "dal-bind",
                                               /tmp/sub is writable scratch          (legal)

So case B was exactly the hole you described: the same failure through nesting, and equality missed
it. Case A is legal and works, which is why the rule is **asymmetric** rather than a prefix compare
in both directions: the check refuses a tmpfs that is EQUAL TO or an ANCESTOR OF a bind, and allows
one BELOW it. Refusing both directions would have cost the third line, which someone reasonably
wants: a persistent `/tmp` from the host with a bounded ephemeral subtree inside it.

Normalisation was already there and is now asserted rather than assumed. All eight cells, both
bindings, identical:

    /tmp vs /tmp   /tmp/sub vs /tmp   /tmp/ vs /tmp   //tmp vs /tmp   /tmp vs /tmp/   ->  refused
    /tmp vs /tmp/sub        /tmpx vs /tmp        /data vs /tmp                        ->  accepted

`/tmpx` is the one that says the prefix test is at a path boundary and not a string one.

On your general form: you are right that the construction-time check and the assertion-time pin were
asking the same question of two different oracles. They still are, and now they agree on the cases we
can construct. The pin consults the kernel; the refusal consults the argv and encodes what the kernel
was measured to do. Closing that properly would mean starting a box to validate a constructor
argument, which is a cost every caller pays for a mistake few make. Stated rather than hidden.

## Where this leaves it

Four open items, all of them yours to have named and none of them closable here: the allocator
discriminant we ranked last and agree about, `noexec` which needs a runtime flag that does not exist,
two runtime gaps filed as findings against kern rather than against this delivery, and a live pi
session that needs a machine.

On your last paragraph: the cells were the part that mattered. Every one of the four rounds where our
own previous report turned out wrong started from a cell you named and we had not thought to
construct, and in three of them the thing that broke was the instrument rather than the subject: the
400 MiB allocation that masked the tmpfs limit, the `lines[0]` that read the shadowed mount layer,
and the OOM note that named the path its author had in mind. We would not have gone looking for any
of them.

## The question

Not "is it correct" - the suites answer that, and you have already been through six rounds of the
parts that were not. What we want:

1. **What did our audit structurally fail to see?** We tested the option against kern's parser and
   against a box. A whole class we did not probe is the INTERACTION between the new default and the
   options that already existed: `security_profile="untrusted"`, `require_limits`, `profiles`
   (`vdisk:` in particular, which is also scratch), `depsReadonly`, a persistent `workspace=`. If the
   64 MiB tmpfs makes any of those quietly weaker or stronger, we have not looked.
2. **Is a writable `/tmp` by default the right call at all?** It removes a real trap and it adds a
   surface: a box now has a writable path we did not previously grant, charged to its memory cap. We
   argued it strengthens the boundary, since the previous behaviour pushed scratch into a host
   directory that nothing bounds. Argue the other way if it holds.
3. **What the others do.** E2B, Modal, Daytona and gVisor-backed runners all face this exact choice.
   If any of them refuses a writable `/tmp`, or sizes it from the memory cap rather than a constant,
   or exposes it differently, that is worth more to us than another test.
4. **The two numbers, the `HOME` default, and the `t` unit**: each is a judgement call we made with
   a reason we can defend and no measurement that settles it. Those are the three places where an
   outside view is worth more than ours.

## Reproducing

Needs the branch, not npm: the SDK is not published, and the version guard is deliberate.

    export KERN_BIN=/path/to/kern
    ( cd bindings/python && python3 -m pytest tests -q )
    ( cd bindings/node   && node --test test/sandbox.test.js )
    ( cd integrations/pi && npm install && for t in test test-edge test-hostile; do
        node --experimental-strip-types $t.ts | tail -1; done )

`test.ts` went from 52 to 71 assertions and `test-edge.ts`'s fork bomb is now a measured storm, so
the numbers you ran last time are not the ones to compare against.

One thing from your last message is already in: the README says to script pi with `--mode json`,
because `--mode text -p` prints nothing at all while it stalls, and to read pi's own exit code rather
than the last command in a pipe.
