# One clean-code pass, one bottleneck measured to its floor, and a shipped vector the bottleneck's fix uncovered

The cycle was closed. Then a clean-code pass and a bottleneck hunt turned up something that is not
about the pool at all: a cross-call code-execution vector on the DEFAULT `run_code` path, present in
what has shipped, and the reason we are reopening rather than filing it and moving on.

Everything below is measured. Where a control is missing it says so.


> **OUTCOME, added after the owner ruled on the three questions below.** All three are answered and the
> work has shipped, so the present tense in the rest of this document describes the state at the time it
> was written, not now.
>
> 1. **`deps_readonly` flipped to default-True**, in both bindings, published as `kern-sandbox` 0.1.36.
>    The cost the review asked to measure first turned out to be real and avoidable: with a setup that
>    leaves no bytecode (`pip install --no-compile`), a read-only `.deps` costs +40 ms on EVERY call for
>    the life of the session (250 ms against 290, measured on `requests`), because CPython cannot write
>    `__pycache__` and silently recompiles. The setup box now runs `compileall` before the mount closes,
>    which brings that case back to 250 and is a no-op when the bytecode is already there.
> 2. **The read-only precompiled cache was NOT built.** The flip made the ordinary case free, which is
>    what the bottleneck section was about, and the remaining win is the cold start rather than the
>    refill, as the owner's reply said.
> 3. **The 19 ms floor was not pursued**, for the reason given in that reply: the field data shows the
>    pool never empties at agent cadence, so the burst case the number describes is not the one any
>    measured session is bounded by.

## Clean code

The rejection shape in `run_cell` / `runCell` was written five times in Python and three in Node, each
copy differing only in a message string. That is the exact form where one copy drifts from the others,
and it was ours to make. Factored to one `rejected(message)` closure per binding. `run_cell` dropped
from 55 to 51 lines of code, suites green (412 Python, 86 Node), fmt and clippy clean. No behaviour
change, and the parity and fault tests still pass, which is what says so.

## The refill bottleneck, measured to its floor

A pool slot refills in ~74 ms, and that number is the burst budget: it is how fast `N` back-to-back
calls can be replenished. Decomposed:

```
argv + env file      0.04 ms
Popen                0.51 ms
wait for 'hello'    74.0  ms      <- all of it
```

The box alone is 3.8 ms; the other ~70 is the interpreter starting inside it, and the bulk of THAT is
the FIRST import: +44 ms, every import after it only +5. It is not file reads (an `open` costs
nothing). It is recompilation: `python:3.12-slim` ships **567 `.py` files and zero `.pyc`**, the root
is read-only, so every box recompiles the standard library from source.

A shared bytecode cache (`PYTHONPYCACHEPREFIX`) takes the refill from 72 to **19 ms**, which is nearly
the floor (box 3.8 + interpreter 11.5). We have not built it, because the obvious form of it is a
security hole and the safe form is a design decision that is yours. Both are below.

## The vector the fix uncovered, and it is not hypothetical

The obvious cache is a directory the boxes WRITE. A writable, shared, executed-at-import cache across a
trust boundary is a cross-call code-execution channel, and CPython's `.pyc` format makes it trivial
here: the files in that image are **timestamp-based** (`flags=0`), so a box can rewrite
`json/__init__.pyc` with a payload, re-paste the legitimate 16-byte header (magic, mtime, size), and
the next box that runs `import json` executes it. We wrote `/ws/PWNED` from a second box that only ran
`import json`.

**Then the part that reopened the cycle.** That is the same shape as a path that already ships and is
on by default: `.deps`. `setup=` installs packages into `<workspace>/.deps`, it is on `PYTHONPATH`,
and `deps_readonly` defaults to **False**. So:

```
deps_readonly=False   a cell poisons .deps/__pycache__/mylib.pyc, .py left intact
                      -> the next cell reads the poisoned VALUE and runs the payload   APERTO
deps_readonly=True    the write fails, the next cell reads the legitimate value        CHIUSO
```

Measured, on the shipped default. A cell edits only the `.pyc`, leaves the source untouched, and the
next `run_code` in the same session imports the attacker's code. It is invisible to the two surfaces a
caller would audit: the poisoning call reports `files: []`, and `list_files()` never shows a
`__pycache__` entry.

We are NOT claiming this is a sandbox escape. Both cells are the untrusted workload, so a cell that
wanted to run code could just run it. What it defeats is narrower and worth stating precisely: the
in-session assumption that `import mylib` in call N+1 runs the `mylib` that call N could SEE on disk.
An agent that installs a library once and imports it across many turns is trusting a `.pyc` any earlier
turn could have rewritten, and neither the diff nor `list_files` would show it.

`deps_readonly=True` closes it exactly, which is the argument for making it the default rather than an
opt-in. That is a behaviour change (a cell that legitimately writes into `.deps` mid-session would
start failing), so it is a call for you, not one we made.

## What we would ask you

Three, in your format.

```
WHAT   whether deps_readonly should flip to default-True
HOW    the .pyc poisoning above works only because .deps is writable after setup. The flag that
       closes it exists and is off. The cost of flipping it: a workload that writes to .deps at
       RUN time (not setup time) breaks.
BREAK  we claim nothing legitimate writes to .deps after setup, because it is the dependency dir and
       setup is the install phase. If a real workflow does -- a package that writes a cache next to
       itself, a plugin that self-installs -- default-True breaks it silently.
TELL   a false green is testing that `import` still works; that never broke. The discriminant is a
       cell that WRITES to .deps mid-session and now gets EROFS.
```

```
WHAT   the safe precompiled-cache design, if the bottleneck is worth closing at all
HOW    compile the .pyc ONCE in a setup-like box, mount it READ-ONLY in every pool box. Measured:
       same 72 -> 19 ms, and a box cannot poison a mount it cannot write.
BREAK  the open questions are all placement: does the cache live per-image or per-session, is it
       built at first setup= or separately, and what invalidates it when the image changes. Get the
       invalidation wrong and a stale cache runs old bytecode against a new interpreter.
TELL   the magic number in the .pyc header is the interpreter version; a cache from python 3.11 in a
       3.12 box is rejected, so the failure is loud, not silent. That bounds the risk of getting it
       wrong -- worth confirming rather than trusting.
```

```
WHAT   whether the 19 ms floor is even worth the design, given where prewarming already sits
HOW    the refill is off the caller's clock -- it happens on the worker thread while the agent
       thinks. So 74 ms vs 19 ms only matters when calls arrive faster than the pool refills, i.e.
       under burst, which is exactly the case prewarming already tells the operator to raise N for.
BREAK  we may be proposing to optimize a number no realistic MCP session is bounded by. The field
       measurement (11 hits of 12 at agent cadence, one distinct key) suggests the pool never
       empties in normal use.
TELL   the honest test is a burst workload that empties the pool, with and without the cache, at the
       N an operator would actually set. If N=4 already covers every real burst, the cache buys
       nothing a caller feels.
```

## Where the branch is

    1047 Rust    412 Python    86 Node    pi 73 / 89 / 25    tsc --noEmit clean
    fmt 0    clippy -D warnings 0    8 repo gates 0    gates-selftest 0    em-dash 0 + control

Still `dev`, 38 files, no commits. The `.pyc`/`.deps` finding changes nothing in the tree yet: it is a
default to reconsider and a design to approve or decline, both yours. If you say flip the default, that
is a one-line change plus a test and a CHANGELOG line, and it belongs in this delivery because it is a
security default, not a feature. If you say build the read-only cache, that is 0.2.

Open and unchanged: aarch64 (boards off); the MCP flood ramp point; `noexec` on the scratch; a live pi
session. Plus `user=`/`uid_range=` on the SDK.
