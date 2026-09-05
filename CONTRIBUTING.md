# Contributing to kern

Thanks for considering a contribution. kern is security-critical (it runs untrusted images as
a sandbox), so the bar on the sandbox/OCI paths is high, and the tests are the proof.

## Before you start

- **CLA required.** All contributions are under the [CLA](CLA.md) (a bot will ask on your
  first PR). This keeps relicensing/stewardship options open for the project.
- Read [ARCHITECTURE.md](ARCHITECTURE.md). Match the surrounding code's idioms.

## Workflow

```sh
cargo build
cargo test            # unit + integration + characterization (skip-graceful for HW)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

CI runs the above on x86 **and on a native aarch64 runner**, plus `cargo-audit` / `cargo-deny`. The
specific boards (Pi, Jetson, UNO Q) are also validated by hand; hardware-dependent tests **skip
gracefully** when the precondition is absent.

## Tests are not optional

- **Unit** tests go inline (`#[cfg(test)] mod tests`) next to the code (private logic).
- **Integration/CLI** tests go in `crates/<crate>/tests/`.
- **Anything touching the sandbox path** must keep the **characterization** assertion
  (recorded mount/pivot sequence) green AND, where it changes behaviour, add/keep a
  **real-syscall** correctness test (escape-blocked / canary-unreadable).
- **Security fixtures must be synthetic, minimal, and self-contained**: no private paths, no
  real-world exploit payloads. See `kern-oci`'s symlink-escape regression for the template.

## Harness traps that have produced a wrong answer here

Every entry below is a mistake this project actually made, caught only because something else
contradicted it. They are listed as environment facts, not as advice, because each one produced a
confident wrong answer first and a correction second.

- **`trim_start_matches` / `trim_end_matches` / `trim_matches` strip AS MANY TIMES AS THEY FIND,
  which is almost never what a parser means.** Reach for `strip_prefix`/`strip_suffix` whenever the
  thing being removed is a SEMANTIC marker rather than padding. Removing repeated `/`, `.`, spaces or
  quotes is fine and is what most of the uses here do. Removing a word is not: measured, and each of
  these accepted a malformed value as a well-formed one, in silence.

  ```
  x-kern-x-kern-vcpu     read as the x-kern-vcpu key
  on-failure:on-failure:3  read as a clean retry count of 3
  0o0o755                read as mode 755
  ```

  This is the same defect three times, and it is a grep. It belongs with the other parsers that
  accepted an input they did not understand and produced a value that did not correspond to it
  (`parse_binary_size` on `31.2G`, `split_top_commas` on an escaped quote): the fix is never a wider
  accept, it is refusing the input or letting it fall onto the path that already reports it.
- **A green test proves nothing until you have seen it go red.** Sabotage the fix and watch the
  test fail. If it stays green, either the test or the sabotage is blind, and you do not yet know
  which.
- **A sabotage needs its own positive control.** Leaking the outer `readline` in the MCP serve loop
  left the memory test green and looked like a blind test. The flood is consumed by the *drain*
  loop, so that sabotage never produced accumulation. Verify the sabotage broke the thing before
  reading the test's verdict.
- **`ru_maxrss` of a forked child inherits the parent's peak.** A test that holds the payload in a
  Python string measures the *parent* and reports a number that scales beautifully with the input
  while proving nothing. The control that exposes it: a child that reads nothing reports the same
  figure. Hand the payload over as a file descriptor and compare two sizes, so the inherited
  baseline cancels.
- **A differential measurement needs both points on the plateau.** 25 MB against 400 MB spans a
  ramp and reports real growth as if it were slack. Find the knee first, then pick two points past
  it.
- **`io.StringIO` does not exercise the encode path.** A lone-surrogate defect is invisible
  in-process and appears only against a real subprocess, or against a stream whose `write` actually
  encodes.
- **Under `LC_ALL=C` a search for the em-dash U+2014 silently returns zero.** Use `C.UTF-8` and
  prove the search works with a positive control that returns a known hit.
- **Querying git history by a stale path answers for a file nobody has touched.** This repo has
  moved files; verify the path is current before believing "last changed 10 months ago".
- **`pgrep` without a unique marker matches your own shell.** Use a marker, and prove the detector
  is looking with a canary process that must be found.
- **Delete `__pycache__`, or use `python -B`, between sabotage runs.** A same-length, same-second
  restore has already executed stale bytecode while `diff` reported no change.
- **A gate's exit code is read bare.** Never through a pipe. See the `no-em-dash` and
  `stale-numbers` invocations.
- **THE COMMONEST ONE HERE, and it has a name: reading a number before the thing it measures has
  happened.** Five of the seven wrong answers in one measurement session were this single shape,
  wearing a different costume each time, which is why it is worth naming rather than listing. A
  timing loop ran `kern box NAME --rm ...` and timed a usage error, because `--rm` is not a flag
  kern has; the figure was a clean 1.5 ms and a plausible box start. On the GPU branch, a probe
  computed `(size_t)atof("0.05") * 1 GiB` and allocated zero bytes, so eleven cases reported "no
  device" on a card with 14.5 GiB free; a concurrency floor was read from `pgrep`, which counts
  processes that exist but have not allocated yet, and produced twelve false dips; a tok/s median
  was taken over a single sample and read 30% noise as a regression; and a watchdog was armed after
  the first call it was meant to guard, which is itself the call that hangs, so the deliberate
  deadlock hung the program before the watchdog existed. **The defence is one question asked before
  the number is believed: did the thing I am timing actually happen?** Print the exit status of
  every timed command and assert it. Print the value the probe computed, not the value you passed
  it. Assert a positive control that must produce a non-zero reading, and a negative control that
  must produce none.
- **An A/B needs a null control: the same binary in both columns.** Without it an ordering bias in
  the harness reads as an effect of the change. Measured here: `kern doctor` timed against ITSELF
  gives +300 us [-46, +512], so a +553 us "regression" attributed to a new branch was not
  resolvable from the harness, and `strace` then proved that branch had never run. Run the null
  control on the same workload, at the same sample size, and report the effect against it.
  `scripts/ab-measure.py` does all of this and refuses the null control unless you declare it.

## Shipping a claim about a boundary

These three rules were paid for by the GPU work and lived only in its commit messages, which is where
a rule goes to die. They apply to any claim about what kern enforces, not to GPUs.

**Read this before reading `crates/kern-cli/src/gpu.rs`, or that file will look out of proportion.**
It is 915 lines and it prints two strings, on a command whose GPU row most users will never have a
GPU to trigger. That ratio is not an accident and it is not scope creep: the GPU work is the TEST
CASE for the three rules below, and the rules are the deliverable. A capability tier is the smallest
honest thing kern could ship about GPUs, which makes it the cheapest place to find out whether a rule
like "ship a tier only if the code can assign it" survives contact with real hardware. It did not
survive intact, and that is the useful part: the model has three tiers and the code has two, because
the measurement that would have earned the middle one failed.

What the phase actually produced, in order of how long it will matter:

1. These three rules, and `scripts/stale-numbers.py` making them mechanical rather than aspirational.
2. `pentest/pentest-gpu-claims.sh`, which is the shape of a suite that attacks a CLAIM instead of a
   mechanism. Nothing about that shape is specific to GPUs.
3. The GPU tier itself, which is the least of the three and the only one a user sees.

Three reviews across three rounds found ten real defects in this work, and every one of them was the
same class: a sentence or an exit code that said more than had been measured. Not one was a runtime
bug. If you are about to change something here, that is the failure mode to expect from yourself.

**A tier, a mode or a guarantee ships only if the code can assign it on hardware someone can reach.**
The GPU model has three capability tiers and the code has two, because the measurement that would
earn the middle one failed: `dmem` accounts device memory and does not enforce it for the compute
path a tenant allocates through. The variant was removed rather than shipped weak. A level nobody can
be awarded is not completeness, it is a promise in the enum.

The test is not "is it verified", it is **"what happens when it is wrong"**. A branch that can only
fail downward, granting less than the hardware deserves, is acceptable untested and says so. A branch
that can fail upward, granting more, does not ship until it cannot.

**When a defence is not a boundary, the demonstration that it is not goes in the repo before the
announcement.** `pentest/pentest-gpu-claims.sh` publishes the result that defeats a userspace VRAM
quota, on the same day the tier that depends on it was written. Finding your own defeat costs one
paragraph; having a reader find it costs the credibility of every other number you have published.

**A claim and the code that prints it are held together by a gate, not by the discipline of whoever
edits next.** `scripts/stale-numbers.py` refuses a document that names a tier the code cannot print,
requires each tier's caveat verbatim on the pages that carry it, and compares the forbidden
vocabulary between the Rust gate and the shell one, because the shell cannot import a Rust constant
and a duplicated derived condition with no gate on it drifts. Every arm of that gate has a sabotage
test: break the thing on purpose, watch it go red, restore it. A gate nobody has seen fail is a gate
nobody knows works.

## Changing a flag or config key (deprecation policy)

The CLI/config surface isn't frozen pre-1.0, but changes still must not break a user's scripts
without warning. This is **blocking** on review, same as tests:

- **Rename with identical semantics** → keep the old name as a **deprecated alias**. Parse it to
  the same `Command` field and emit a single stderr warning (`warning: --old is deprecated; use
  --new`). Keep it for **≥ 2 minor releases**, then remove. Record it under **Deprecated** in the
  CHANGELOG when introduced and **Removed** when dropped.
- **Rename/repurpose with divergent semantics** → do **not** alias it (a silent reinterpretation
  corrupts behaviour). **Reject the old name with a `Usage` error** that explains the difference
  and names the replacement. The `--memory-swap` → `--memory-swap-max` rejection in
  `cli.rs` is the reference implementation; mirror its message shape (`X is not supported (why);
  use Y`).
- A new flag must land with a parser test asserting it populates the right `Command` field, and a
  rejection must land with a test asserting the `Usage` error (see `cpu_ram_flag_freeze`).

## Before a tag: the acceptance matrix

`sh scripts/acceptance-matrix.sh <path-to-kern>` runs every compose lifecycle transition in both
network modes and checks the three things the unit suites do not: that the OUTPUT agrees with the
state (a line naming a pod on a stack that has none is a failure, not cosmetics), that a payload
crosses with NO settling time (a bare connect cannot see a stale relay; only bytes back can), and that
`down` leaves nothing behind in processes OR on disk, counted by pid rather than by process name.

It was written after four defects in one release cycle were found by an external reviewer rather than
by this repo's own tests, and all four had that shape. `--self-check` exercises its own assertions
against fixed strings, so a matrix that cannot fail is caught before it is trusted.

Run it against the binary a tag will actually publish, not against `cargo build --release`: this
project has twice measured the wrong artifact that way.

## Documentation has a gate too

Prose is checked the same way code is, mechanically, before the commit:

```sh
python3 scripts/no-ai-slop.py          # every tracked .md; exit 1 on a hit
grep -rlP '\x{2014}' --include='*.md' .   # the em-dash: must print nothing
```

`no-ai-slop.py` refuses a fixed list of markers that read as machine-written: `delve`, `leverage`,
`seamless`, `robust`, `comprehensive`, `utilize`, `not only X but also Y`, sentence-opening
`Furthermore`, and the rest. It ignores anything inside a code span, a link target or a fenced block,
because a word in backticks is a symbol and not the document's voice. The reason it exists is
commercial rather than aesthetic: readers who see one of those words decide a model wrote the page
and stop, before checking a single measurement.

## Run `rustup update stable` before trusting a green clippy

CI pins `stable`, which means whatever stable is on the day it runs. A local toolchain one release
behind runs the same command and reaches a different verdict, and the direction is the dangerous one:
the newer clippy has more lints, so LOCAL IS THE WEAKER GATE.

Measured, and it cost a red CI on a release commit: clippy 0.1.98 of 2026-08-18 accepted an empty
line between a doc comment and the item it documents, and 0.1.98 of 2026-09-01 refuses it with
`empty line after doc comment`. Same version number, six weeks apart, opposite answers.

So `cargo clippy` passing here is not evidence until the toolchain matches. The check that settles it
is a positive control: reintroduce the thing CI rejected and confirm your clippy now rejects it too.

## Progress goes through `progress!`, never `eprintln!`

kern and a box's workload share one stderr. A progress line written with a bare `eprintln!` therefore
lands in whatever is reading that stream: a shell pipeline, `kern logs`, or an agent's context through
the SDK, where an external audit found six `-> layer ...` lines sitting in front of the program's own
output inside a LangChain tool result.

```sh
kern_common::progress!("-> resolving {image}");   // kern-cli, kern-oci
crate::progress!("-> publishing {hp} -> box :{bp}");  // kern-isolation, which is libc-only by design
```

Both write only when stderr is a terminal, which is the rule the `kern box` status panel already
followed and the pull path never did.

**A diagnostic is the other half of the rule, and it must carry `kern: `.** That prefix is the only
thing the SDK has to tell kern's voice from the workload's on a shared stderr, so a bare
`warning: bound 0.0.0.0` reaches an agent's context as a line the program printed. Three such lines
were live when this was written; five more used `kern compose:`, which matches neither the benign list
nor the failure marker.

`python3 scripts/progress-is-tty-gated.py` enforces both halves, exhaustively, inside the modules an
SDK caller's stderr is actually made of: in those files every `eprintln!` is one or the other. It
reads the whole macro call rather than one line, because the site that first escaped had its format
string on the following line.

**It is scoped rather than global, and the scope is the judgement.** Its first version instead matched
a set of leading markers (`->`, `OK`, `  layer `). A reviewer pointed out that this freezes today's
punctuation rather than the rule, and they were right: rescoping it immediately found seven more
progress lines written as `[1/3] FROM ...` and `  [cached - ...]`, plus the three unprefixed
diagnostics. A global rule is not reachable statically, because 55 `eprintln!` calls in the workspace
print a variable with no literal to inspect. `--audit` lists what it cannot check instead of passing
it in silence.

**Errors, warnings and `kern: note:` advice are NOT progress.** A pipe is exactly where those must
still arrive. And the two mechanisms are NOT layers over one problem: the TTY gate closes progress at
the source, and for the warning class the `kern: ` convention is the only mechanism there is.

## A changelog entry is not a commit message

The commit explains how a defect was found and why the fix is shaped that way. That is the right
place for it: the reader is whoever maintains this next, and the diagnosis is the content.

The changelog has a different reader, deciding whether a version changes anything for them. So an
entry answers that in its first line and stops. What went wrong, which review caught it, and how it
was verified do not belong there, because a reader scanning for "does this affect me" has to walk
past them to find out.

The measure that made this a rule: the v0.7.1 entries went from 268 lines to 57 without losing a fact
a user needs. Everything cut was already in the commits. If an entry runs past about eight lines, it
is usually telling the story rather than the change.

Behaviour changes are the exception in one direction only: they lead with the symptom, in the words
of someone it happens to, and they say how to keep the old behaviour on purpose.

## Reporting security issues

Do **not** open a public issue, see `SECURITY.md`.

## Scope reminder

GPU limits are not shipped, so a report about their strength has nothing to land on yet. See
`SECURITY.md` for what is and is not a boundary today.
