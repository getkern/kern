# Round 17 answered: all six done, and the mutation harness itself was reading the wrong thing

Six items. All six are implemented and measured. One of them, the one you flagged as the weakest
instrument, turned out to be weaker than either of us said, and the tool that was supposed to catch
that was the thing that failed.

## The primitive works, and it needed the instrument chosen by testing it

`setpriv --no-new-privs` on a reduced system, exactly as you framed it. The hard part was getting a
setuid binary owned by somebody else without being root, and the answer was already in the product: a
box with a mapped uid RANGE chowns the file to an in-box uid, which lands on the host as a subuid.

```
file: -rwsr-xr-x  owner 100999      caller: 1000
without no_new_privs   euid = 100999
with    no_new_privs   euid = 1000
```

That is the mechanism proved where it can be disabled. The in-box half asserts `NoNewPrivs: 1` where
it cannot. Both are in the RUNTIME's suite now, not the SDK's, with the coupling written into the
doc comment: the SDKs let a `nosuid` remount fail non-fatally, and that is only safe while kern arms
the prctl, so the assertion lives next to the thing that could change and says what depends on it.

**The ladder needed a fourth attempt, and the reason is the finding.** `busybox id -u` prints the
REAL uid; coreutils' prints the EFFECTIVE one. Built on busybox, both rungs read 1000 and the test
passes while measuring nothing. So the test now **chooses its instrument by testing it**: it stages
every candidate, and uses the first whose output under setuid actually equals the file's owner. If
none can see, it skips with that as the reason rather than passing. Verified in both directions:
forced to busybox alone it skips and says why; with `setpriv` removed it goes red.

## The `sys.path` gate: you were right twice, and the absolute reference was one call away

**The reference.** `run(["python3", "-c", "..."])`, no driver:

```
unmediated:  ''          /workspace/.deps  ...zip  ...3.12  ...lib-dynload  ...site-packages
cold:        /workspace  /workspace/.deps  ...zip  ...3.12  ...lib-dynload  ...site-packages
```

One difference and it IS a driver artifact, which is what you predicted the gate could not see: a
script run by path puts its own directory at `sys.path[0]`, `-c` puts `''`. Same directory, static
against dynamic. The gate now asserts position 0 explicitly as the known artifact and requires
everything else to equal the unmediated interpreter, so three driver-mediated paths can no longer
agree on something none of them should have.

**The proxy.** You are right that path equality does not imply import equality, and the warm
interpreter's seven preloaded modules are exactly the case where an import never consults the path.
The gate now asserts `importlib.util.find_spec(x).origin` for a probe set alongside the path, with
`pip` as a positive control that resolution happens at all. It goes red if the warm path loses a
resolution route.

## The registry sampling: demoted, and the writer control was weak where you said

Reordered as you framed it. The workload being gone is now the PRIMARY assertion and the registry is
a BOUND, `cleared within 10 s` by polling, not `absent at t+0.3`. A slower machine moves the sample
points; it does not move a bound.

On the writer control: you were right that "297 still 297 a second later" separates stopped from
running but not stopped from stalled. It now asserts on the supervisor being **reaped**, checked
through the process state rather than through `/proc/<pid>` existing, since a zombie keeps the
directory. The counter check stays as the second half, because between them they cover both.

## The threads: pinned as a delta

`active_count() == 3` is gone. What is asserted is that the warm interpreter's extra threads are
exactly `Thread-1 (_drain)` and `Thread-2 (_drain)`, that the cold one is exactly `MainThread`, and
that the extra modules are exactly the seven the driver imports. Plus the direction that matters
historically: **zero modules loaded only on the cold side**, because a name appearing there is what
`-S` looked like.

## `-S`: nobody recorded a reason, which is the finding

`git log -S'"-S"'` gives one commit, `e14053b`, the one that introduced the warm kernel. Its message
does not mention `-S` at all. So by your rule and ours we cannot know what it was for, and what
dropping it turns back on had to be measured rather than argued.

What it turns back on is `site`, which executes `import` lines from `.pth` files at interpreter start,
and in a prewarmed box that now happens at pool-fill time rather than during a call. Measured on the
default image: **no `.pth` files at all, zero import lines.** A custom image that has them will run
them earlier than before, and that is now written in the CHANGELOG rather than left to be found. The
startup cost you asked us to confirm we had measured: 70 to 74 ms of refill, off the critical path.

## The thing that failed was the mutation harness

Verifying the three strengthened gates, the teardown one came back GREEN when the process-group kill
was removed. It should have been red. It was not the gate: the mutation was a `str.replace` whose
anchor did not match (there are three `killpg` call sites), so it silently changed nothing and the
suite ran against unmodified source and passed, correctly.

**A no-op mutation and a surviving mutant are indistinguishable from the outside**, and the harness we
use to certify every gate in this cycle could not tell them apart. It now asserts that the mutation
changed the file before running anything. With that, the teardown gate goes red as it should.

This is the fourth instance of the same class this cycle, and the first one inside the tool that
verifies the others.

## Where this leaves it

    1047 Rust    411 Python    85 Node    pi 73 / 89 / 25    tsc --noEmit clean
    fmt 0    clippy -D warnings 0    8 repo gates 0    gates-selftest 0    em-dash 0 + control

Still `dev`, still no commits, still needs a runtime tag alongside the publish.

Open, unchanged: aarch64 (boards off, one shared MAC on ARP); the MCP flood ramp point; `noexec` on
the scratch; a live pi session. `user=` and `uid_range=` on the SDK now have a third reason: the
setuid ladder had to drop to the CLI to express the configuration it needed, twice.

## Not asking again

You have answered the question three times and each time it produced something, so this is a report
rather than a request.

One correction to our own alarm, made while writing this paragraph and worth more than the alarm was.
The harness defect is **asymmetric**, and we nearly filed it as though it were not. A mutation that
silently fails to apply leaves the source unmodified, so the suite passes, so the verdict is GREEN. It
can never produce a RED. Therefore every RED verdict in this cycle stands on its own: a gate that went
red did so against genuinely mutated source. Only GREENs were ever suspect, there were two, and both
were chased at the time.

So the answer to "which gates need re-running" is: none, and we would have re-run all of them on a
worry that a minute of thinking dissolves. The rule is the reusable part, not the incident: **when a
verification tool can fail silently, work out which of its verdicts the failure can produce.** Ours
could only manufacture false confidence in one direction, and that direction is the one we had already
been forced to investigate twice.

**One qualification, because "REDs are safe" is the sentence that will get carried and it is narrower
than it sounds.** It holds only for SINGLE-mutation runs. If one mutation in a batch applies and
another silently does not, the suite runs against partially mutated source: the RED is still real, but
it may be attributed to the mutation that landed rather than the one being certified. Every batch here
restored the file before AND after each mutation, so it holds. That was checked rather than assumed,
and the check found something worth the trouble: one batch restored a file with `git checkout` while
its backup was of a DIFFERENT file. No residue in the end, but by luck rather than by construction.
