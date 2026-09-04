# After the close: prewarming, two runtime fixes, and one claim of ours that was too broad

The last document said the cycle was closed. Then the delivery got one more requirement, zero
per-call latency, and meeting it opened four defects and cost us one sentence we had written. This
records where the branch is and asks one question at the end.

    1045 Rust    407 Python    84 Node    pi 73 / 89 / 25    tsc --noEmit clean
    cargo fmt --all --check 0     RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets 0
    8 repo gates bare, all 0      gates-selftest 0 (18 cases, each one turned its gate red)
    em-dash 0, positive control 1

Branch `dev`, 34 files, still no commits.

**One thing changed about the shape of the delivery.** It is no longer SDK-only. Two of the four
runtime gaps you filed are closed, which means crates moved, which means this needs a runtime tag as
well as the PyPI and npm publish. The CLI change is additive (`--shm-size`) and the surface snapshot
was regenerated for it.

## What shipped

**Prewarming, in both bindings.** `prewarm=N` keeps N boxes started in advance, each holding a booted
interpreter that has run nothing. A python `run_code` claims one instead of starting its own. Each
prewarmed box serves **exactly one cell** and is then destroyed, so the fresh-box guarantee is intact:
what moves is when the box and interpreter started.

Measured over ssh on loopback, interactive (one call at a time with a pause, which is what an agent
does), medians, every row asserting it received and matched every response:

```
ssh handshake, once per session               172 ms
session start (server up, initialized)        200 ms

                                     per call   state between calls
a fresh box per call                   37.8 ms   none
a fresh box, PREWARMED (the default)    1.6 ms   none
KERN_MCP_KERNEL=1                       0.9 ms   PERSISTS
```

Locally 38.85 to 1.06 ms. On a VPS (kernel 6.8, 4 cores, against the RELEASED `kern 0.8.9`) 67.1 to
6.54 ms. A slot refills in ~70 ms, so N is a **burst budget**, and we say so rather than quoting the
best case: with a burst of 8 and no pauses, `N=4` gave 1.2, 0.8, 0.4, 0.4 and then 22.6, 14.0, 14.5,
13.5. Default 0 in the SDK (it holds a booted interpreter per slot), 1 in `kern-mcp`.

The fast path is taken **only** where it matches the cold one, and each gate is a test: stdout, exit
status, rich results, `files` diff, `truncated`, fault types, network posture. A streaming
`on_stdout`/`on_stderr` call falls back to the cold path and streams for real, because a prewarmed box
answers in one frame after the cell has ended and calling the callback once at the end would look like
streaming without being it.

**`-v` is now `nosuid`, `/workspace` included.** A first bind ignores per-mount flags. The remount
preserves the flags already in force, which is the part that matters: a bind remount SETS flags and a
userns refuses one that clears a locked flag, so "add nosuid" spelled as "nosuid only" fails `EPERM`
on any source already `nosuid,nodev`, which is `/tmp` and `/run` on most systems.

**`/dev/shm` reports the size the box actually has.** It was unsized, so `statvfs` returned half the
HOST's RAM: a box held at 512 MiB was telling every workload it had 15.6 GB. It now carries the cap
already enforced. Not Docker's fixed 64 MB, which has no relationship to the box.

## The four defects, none of which came from reading the code

1. **`PR_SET_PDEATHSIG` fires on the death of the creating THREAD, not the process.** The first pool
   started each box on a throwaway thread and therefore killed every box it made, reaped `rc=-9` about
   80 ms in, exactly as the box reached its prompt. Synchronous: alive. Same code in a thread: dead.
   The runtime is untouched (that signal is load-bearing against orphans); one long-lived worker owns
   every start.

2. **`kern stop NAME` does not return when the box's supervisor is already dead.** It ran to the
   caller's timeout every time, 8 s, three for three. In Python that blocked a background thread and
   was invisible; the Node binding runs the same teardown on its single event loop, which is the only
   reason it was found. **This one is a finding against kern, not against the delivery.**

3. **The reason we were calling it at all was our own instrument.** The note said `killpg` alone left
   the box in `kern ps` "4 runs out of 6". That check ran immediately after the kill, inside the
   reaping window. Sampling at t+0, t+0.3, t+1 and t+3 gives at most one PRESENT reading at t+0 and
   none after, and the processes really are gone by then: a cell that leaves a **CPU-bound** background
   writer stops at the byte it had reached (297, still 297 a second later) against a positive control
   that runs on (297 to 1171).

4. **The pool key did not cover the kern process environment.** kern reads `KERN_*` from its own
   environment when it builds a box, so setting `KERN_SECCOMP=denylist` after the pool had filled left
   the key unchanged and the stale box, built under the **previous filter**, was handed to the call.
   Measured before the fix: key unchanged, box served. Every `KERN_*` name is folded in now rather than
   a list we can name today, because the failure mode is a variable nobody thought to list.

Also: the Node binding's kernel driver carries a comment claiming it is byte-identical to the Python
one. Nothing checked that, and it went false the moment the Python driver grew its caps. Two gates now
hold it, including one that the driver must contain no backtick or `${`, since the Node copy lives in
a `String.raw` literal that either would terminate early.

## One sentence of ours that was wrong

We wrote that the prewarmed path is **observationally identical** to the cold one. That is too broad.
The interpreter is older than the call: a cell reading its own start time out of `/proc/self/stat`
sees ~0 s cold and up to five minutes warm (measured: 0.0 against 3.1). No boundary moves with it, and
nothing the SDK reports changes, but the word was wrong and the docs now carry the narrow claim
instead: same stdout, exit status, results, file diff, truncation, faults and posture.

## Where we would aim, if we were you

Named in your format, because the last cycle showed that naming a cell and running it are different
jobs, and three of the four times a report of ours turned out wrong it started from a cell you named.

```
WHAT   the nosuid threat model, stated precisely enough to be wrong
HOW    a box maps a uid RANGE. A cell running as box-root drops a setuid-root binary on the shared
       workspace. A LATER call on the same workspace runs as --user 1000 and execs it.
BREAK  we claim that is the whole scenario, and that at a SINGLE uid the bit is inert because the
       kernel drops setuid when the file's owner is unmapped and a rootless caller owns files only as
       themselves. If there is a single-uid path where it bites, the non-fatal fallback is wrong.
TELL   a false green is asserting on the mount flags rather than on an actual privilege change.
```

```
WHAT   whether killpg is sufficient in EVERY case, not the ones we tried
HOW    kern arms PDEATHSIG only on the foreground path (start.rs says "no PDEATHSIG" on the detached
       and `kern run` paths). Our pool boxes are foreground. Find a foreground shape where it is not
       armed, or where box PID 1 survives its own namespace teardown.
BREAK  if one exists, removing `kern stop` from the sweep leaks a box per call.
TELL   `kern ps` is the wrong instrument for this and we have already been burned by it once; the
       discriminant is whether a process inside the box keeps making progress.
```

```
WHAT   what the pool key STILL does not cover
HOW    it now covers the resolved argv plus every KERN_* variable. It does not cover the process cwd,
       umask, rlimits, supplementary groups, or the caller's own cgroup, all of which the box inherits
       from whoever started it.
BREAK  change one of those mid-session and see whether a warm box serves the old posture.
TELL   a difference that shows up in the box but not in the key.
```

```
WHAT   whether sizing /dev/shm at the memory cap is the right trade
HOW    where the cgroup IS enforced the tmpfs limit never binds (the OOM comes first), so it is purely
       informational. Where NO cgroup is delegated (nested CI), the 512 MiB default becomes a real
       ENOSPC ceiling that did not exist before.
BREAK  a workload that wrote more than 512 MiB to /dev/shm on an uncapped host and now fails.
TELL   whether it fails with ENOSPC (our new ceiling) or exit 137 (the cap, as before).
```

```
WHAT   an observable we have still not listed
HOW    we found the interpreter's age by asking what a cell could read about ITSELF. We have not
       swept the box's own view: /proc/uptime, the cgroup path, the box name, the PID namespace's
       first pid, /proc/self/status, anything with a timestamp.
BREAK  a second observable would mean the narrow claim is still too broad.
TELL   it has to be something a CELL can read, not something the host can see.
```

## What stays open, and one of them we cannot close here

1. **aarch64 is unverified, and that is where the nosuid remount is most likely to be refused.** The
   boards were off. Worth stating how we know rather than that we tried: `.101`, `.103`, `.104` and
   `.10` all answered ARP with the **same MAC**, which is the router replying by proxy for absent
   hosts, and nothing appeared on the direct cable. An ARP entry reading REACHABLE is not presence.
   This is exactly why the `nosuid` failure is non-fatal outside `:ro` and `--uid-range`.
2. **Why the MCP flood test's ramp point moved.** Unchanged from the last round, still ranked last.
3. **Whether `noexec` on the scratch would be right.** Unchanged; your GIT_ASKPASS counter-case stands.
4. **A live pi session.** Still needs a machine with a provider.

Plus the two decisions written down rather than taken, both 0.2 conversations: `user=` on the SDK, and
typing the Node surface as `Uint8Array` to drop the `@types/node` requirement.

## The question

Is there something here you would aim at, or does it end here? We are not asking for a pass over the
whole branch again. The five cells above are the ones where being wrong would cost the most, and the
first four defects in this round all came from a question about an instrument rather than about the
code, so a question of that kind is worth more to us than a re-read.
