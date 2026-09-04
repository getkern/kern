# Closing the cycle: fifteen rounds, what shipped, and the four things that stay open

Your five are closed, and the ground is covered. This is not asking for another pass. It records
where the branch stands so the next person does not have to reconstruct it from the thread.

    python 395    node 75    pi 73 / 89 / 25    tsc --noEmit clean
    cargo fmt --all --check 0     RUSTFLAGS="-D warnings" cargo clippy --workspace 0
    7 repo gates bare, all exit 0     em-dash 0, positive control 1
    twine check PASSED on wheel and sdist (with readme_renderer[md])

Branch `dev`, 25 files, no commits. `kern-sandbox` 0.1.36, unpublished. Runtime unchanged, no crate
touched, no tag.

## What ships

**One behaviour change with teeth**: every box gets a writable `/tmp`, a tmpfs of
`min(64 MiB, memory_mb / 2)`, charged to the box's own memory cgroup. It steps aside for a `mounts`
bind at the same target, for a `security_profile`, and for the `setup=` box. It is refused when it
would cover a bind, when its size exceeds the cap, and when its size or target is one of the four
spellings kern reads backwards.

**Three corrections of a declared thing that was not the real thing**: `language="bash"` runs bash
and `sh` is its own language; the MCP schema names the image it runs instead of advertising an
interpreter that image lacks; `max_bytes` says it is a refusal.

**One integration made to work**: the pi extension, whose own documented example could not run.

**And the part that took thirteen rounds**: the messages. The `oom` fault names the memory-backed
filesystems it is charged for, including the one the SDK cannot bound. The `exec_failed` fault names
the binary, the image and the one-word remedy. Every refusal added this round names the trap rather
than the rule.

## What stays open, all four declared and none of them ours to close here

1. **Why the MCP flood test's ramp point moved.** It is a ramp and not a leak: flat 55.4 MB from 192
   to 800 MB of flood, and an injected leak fails by 544 MB. Your `PYTHONMALLOC=malloc` with explicit
   trim thresholds is the right discriminant and we ranked it last, as you did.
2. **Whether `noexec` on the scratch would be right.** It needs a kern flag that does not exist, and
   your GIT_ASKPASS counter-case says the answer is not obvious.
3. **Two runtime gaps, filed as findings against kern and not against this delivery**: `/dev/shm` is
   a tmpfs with no `size=` and no way to give it one, its apparent size being half the HOST's RAM;
   and `/workspace` has no `nosuid`, which is inert at a single uid and stops being inert under
   `--uid-range`.
4. **A live pi session.** Needs a machine with a provider; this one has none.

Plus two decisions written down rather than taken: **`user=` on the SDK**, without which an image
that refuses root cannot run, and **typing the Node surface as `Uint8Array`**, which would remove the
`@types/node` requirement. Both are surface changes, so both are 0.2 conversations.

## The technique, since it outlived the defects

Five things found the defects, and none of them was reading the code.

**Disable the guard and check the cell loses.** The ladder has to have a cell for every guard, and
when two guards are independently sufficient both single-guard cells must fail with the other
removed. Five cells on the default scratch; the fifth is a caller's `:ro` bind, which is their
decision and now says so.

**Vary a second axis.** Every defect this branch had that a single-axis audit could not see needed
two things to move: the default against `untrusted`, the clamp against a caller's cap, the scratch
against a `kernel()`'s lifetime.

**Ask what the instrument is reading.** Five times, and once self-demonstrating: a probe measuring
the pipeline exit-code hazard was itself bitten by it, in the same session, with the rule already
written one cell away. That one is now a test rather than a note, because being written did not stop
it.

**Pin the posture, not the option.** `(profile -> writable mounts)` and `(profile -> CapEff)`, with
the profile list read from `kern box --help` and the path set derived from `/proc/self/mountinfo`, so
a profile the runtime grows or a path nobody named fails here rather than being discovered. It found
`/dev/shm` on its first run, in our own README.

**Run real jobs, and ask for the false green.** Forty scenarios that were work someone wanted done,
each with the assertion that would pass while the job was broken. The ten `[works-but]` cells were
worth more than the failures: `express` fits in 64 MiB, `pandas` fits forever, 10k rows never spill,
`nginx -t` is green on a dead server.

## One thing for the record

The four times a report of ours turned out wrong, three started from a cell you named and would not
have been constructed here. The naming and the running were different jobs, and the cycle worked
because neither of us was doing both.
