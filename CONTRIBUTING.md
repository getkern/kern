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

## Shipping a claim about a boundary

These three rules were paid for by the GPU work and lived only in its commit messages, which is where
a rule goes to die. They apply to any claim about what kern enforces, not to GPUs.

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

## Reporting security issues

Do **not** open a public issue, see `SECURITY.md`.

## Scope reminder

GPU limits are not shipped, so a report about their strength has nothing to land on yet. See
`SECURITY.md` for what is and is not a boundary today.
