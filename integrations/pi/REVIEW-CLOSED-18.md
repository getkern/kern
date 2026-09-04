# The cycle is closed. What it cost, what it found, and what is left

Eighteen rounds. The reviewer's last message ends it, and their qualification on the asymmetry
argument was taken and checked rather than accepted. This file exists so the next person does not
reconstruct the state from the thread.

    1047 Rust    411 Python    85 Node    pi 73 / 89 / 25    tsc --noEmit clean
    cargo fmt --all --check 0     RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets 0
    8 repo gates bare, all 0      gates-selftest 0      em-dash 0, positive control 1

Branch `dev`, 38 files, **no commits**. It needs a runtime tag as well as the PyPI and npm publish:
this stopped being SDK-only when two of the four filed runtime gaps were closed.

## What ships that did not before

**Prewarming.** `prewarm=N` in both bindings: 37.8 ms per call becomes 1.6 ms over ssh, 38.85 to 1.06
locally, 67.1 to 6.54 on a VPS running the RELEASED binary. Each prewarmed box serves exactly one cell
and is destroyed, so "a fresh box per call" is unchanged. A slot refills in ~74 ms, which makes N a
burst budget and not a speed setting. Default 0 in the SDK, 1 in `kern-mcp`.

**Two mount-posture fixes in the runtime.** Every `-v` volume is mounted `nosuid`, preserving the
flags already in force because a bind remount SETS them and a userns refuses one that clears a locked
one. `/dev/shm` carries the cap already enforced instead of reporting half the HOST's RAM. Plus
`kern box --shm-size`, additive, snapshot regenerated.

**`kernel()` was substantially broken and nobody knew.** It ran its driver under `python3 -S`, which
skips `site`, which is what puts `site-packages` on `sys.path`. Every kernel session since that
feature shipped has been running against a Python that **could not import anything the image
provides**: not numpy, not pandas, nothing outside the standard library, unless `setup=` had put a
copy in `.deps`. That is not a parity gap, it is the feature not working for its main use, and it
stayed invisible because every test that touched it used stdlib only. It is the strongest argument in
this file for the method this file is advocating. Fixed in both paths and both bindings.

## Five defects in the branch

**None was found by reading the code.**

1. `-S` hiding `site-packages` from every warm interpreter, above.
2. `_base_argv` is not a pure function: it also writes the box's private env file, so using it to
   compare postures created a file per comparison and then collided with itself.
3. The Node driver had silently stopped being byte-identical to the Python one while a comment above
   it claimed it was, and nothing checked the claim.
4. `PR_SET_PDEATHSIG` fires on the death of the creating THREAD, not the process, so the first pool
   killed every box it started, about 80 ms in, exactly as each reached its prompt.
5. The pool key covered the resolved argv but not the `KERN_*` environment kern reads when it builds a
   box, so a `KERN_SECCOMP` change mid-session was served a box built under the previous filter.

## Four reports of ours that measurement retracted

These are a different thing from the list above and the better half of the cycle: not bugs in the
branch, but **things we told the reviewer that turned out to be false**, one of them filed against a
codebase we do not own. A reader who merges the two lists will conclude the branch had nine bugs. It
had five.

**They also split by MECHANISM, and the split is the part that transfers.** The first three were
retracted because a later measurement contradicted an earlier one: re-running catches those, and
re-running is something you can decide to do on your own. The fourth was retracted because someone
asked what a cell could OBSERVE that we were not comparing, and no amount of re-measuring the things
we had already chosen to measure would ever have produced it. Re-measuring fixes three kinds of
error. The fourth needs the question changed, deliberately, by someone.

1. "`killpg` alone leaves the box in `kern ps` 4 runs out of 6." That check ran inside the reaping
   window. The registry clears itself.
2. "`kern stop` does not return when the supervisor is dead", filed against the runtime. It returns in
   2 to 5 ms. The stalls were our own `spawnSync` blocking the event loop Node needs to reap the child
   it had just killed. Nothing in the runtime needed fixing.
3. "A setuid-root file on a `-v` volume lets an in-box user become box-root under `--uid-range`." It
   does not: kern arms `PR_SET_NO_NEW_PRIVS`, so the bit is inert however the filesystem is mounted.
   The `nosuid` remount is depth, and is now non-fatal everywhere except `:ro`, because depth must not
   be able to stop a box.
4. "The prewarmed path is observationally identical." Too broad. The interpreter is older, has two
   more threads and seven more modules. The narrow claim is the one in the docs now.

## The techniques, since they outlived the defects

The five from the last close still hold. Three more came out of this stretch:

**When a guard cannot be disabled where it matters, prove it where it can be and assert its presence
where it cannot.** `no_new_privs` cannot be turned off in a box (patching it out yields a box that
refuses to start, which is the stronger statement). It can be turned off with `setpriv` on a bare
shell. Two reachable halves replace one unreachable cell.

**An instrument that cannot be validated in situ should be chosen by validation, not by name.**
`busybox id -u` prints the real uid and coreutils' prints the effective one, so a ladder built on the
wrong one reads the same number on both rungs and passes while measuring nothing. The test now stages
every candidate and uses the first that demonstrably sees a euid change, skipping with a reason when
none can.

**When a verification tool can fail silently, work out which of its verdicts the failure can
produce.** A mutation that does not apply leaves the source clean, so the suite passes, so the verdict
is GREEN; it can never be RED. Every RED in this cycle therefore stands. That holds only for
single-mutation runs, which was checked and not assumed.

## The one thing in the delivery we had no field data on, now measured

`prewarm` defaults to 1 in `kern-mcp` and the key folds in every `KERN_*` variable, so a session whose
environment moves discards its warm box. That is correct and it was unmeasured, which for the option
most users will actually run is the wrong state to ship in.

A session at agent cadence, 12 calls 1.2 s apart, driving the real MCP server:

```
hits 11, misses 1          the miss is the first call, before the pool has filled
distinct keys              1        the posture never moved across the session
per-call latency           0.97 ms median (min 0.81, max 35.19 = that first call)
```

And the case the key exists for, changing `KERN_SECCOMP` half way through a 10-call session:

```
before   29.8  1.0  1.1  1.1  0.9      (the 29.8 is again the first call)
after    32.1  1.3  1.0  1.0  1.1
```

A posture change costs exactly **one** cold call and the pool then refills against the new posture. An
editor restarting the server is a new process and therefore a new pool, so it pays the same single
cold call it would have paid without prewarming at all.

**The stronger claim these numbers support, since it is easy to read them as merely reassuring: the
pool has no pathological case at agent cadence.** The discriminant is that 29.8 and 32.1 appear in the
SAME position on both halves of that table. The cost is attached to filling the pool, not to the
change that emptied it, so there is no input that makes it recur: a miss can only ever be the call
that finds an unfilled slot, and the slot refills in ~74 ms while the agent is thinking. That is a
bound on the failure mode, not an observation that one call was slow.

## What is open, and why none of it is closable here

1. **aarch64.** The boards are off: `.101`, `.103`, `.104` and `.10` all answered ARP with one shared
   MAC, which is the router replying by proxy, and nothing appeared on the direct cable. This is where
   the `nosuid` remount is most likely to be refused, which is why it is non-fatal.
2. **Why the MCP flood test's ramp point moved.** Ranked last then, ranked last now.
3. **Whether `noexec` on the scratch is right.** Needs a kern flag that does not exist.
4. **A live pi session.** Needs a machine with a provider.

Plus `user=` and `uid_range=` on the SDK, which now have three reasons rather than one: the setuid
ladder had to drop to the CLI twice to express a configuration the SDK cannot say.

## On who found what

It is tempting to record this as "the reviewer named cells and we ran them", and the reviewer's own
last message says that overstates the naming. It does. Several of the cells that landed were
reformulations of things our own measurements already implied, and the two that mattered most in the
sequence came out of running a sweep further than the cell asked for: `kernel()` diverging from
`run_code` was not in any cell, and `busybox id -u` reporting the real uid was found while building an
instrument, not while using one.

So the reusable instruction is not "get a reviewer to name cells". It is the thing that happened four
times in this file: **report the measurement that makes your own previous report wrong.** A reviewer
helps because they ask what the instrument is reading. Nothing stops you asking it first.

With the caveat the retraction list makes concrete: asking it first works for three of the four. The
fourth kind of error is invisible to any amount of re-measuring, because the measurement is not wrong,
the CHOICE of what to measure is. For that one the substitute for a reviewer is a standing habit, not
a better run: before calling two paths equivalent, enumerate what the SUBJECT can observe, not what
you have compared.
