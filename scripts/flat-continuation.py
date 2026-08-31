#!/usr/bin/env python3
"""No message a user reads may carry a run of source indentation in the middle of a sentence.

WHAT THE DEFECT IS. A literal split across lines is continued with `\\` at end of line, which in Rust
eats the newline AND the next line's indentation. Write it without the `\\`, or generate the code with
a tool that treats `\\` as ITS OWN line continuation, and you get a literal that compiles, survives
review by eye, and prints:

    kern vgpu: the cgroup quota is capped by the cores the machine actually has,
    so this profile would                                   not slow the workload down

The message stays half-readable and the source's indentation ends up inside a user's output. It has
happened twice in this repo: first in the CUDA shim, then writing the budget warnings in
`commands/config.rs`, with a Python script in which a trailing `\\` was Python's continuation and not
Rust's.

WHY THE TEST THAT EXISTED IS NOT ENOUGH. The same check exists as a unit test inside `kern-cuda`, and
it covers THAT crate's files: it was born there because that is where it happened the first time. The
second time happened in `kern-cli`, where nobody was looking. A per-crate check has to be extended by
hand every time a crate is born, and the second occurrence is the proof that it does not get
extended. This one reads the whole tree.

HOW. String literals are pulled out of every `.rs` file and searched for a run of spaces between two
lowercase letters. See RUN below for where the threshold comes from.

STATED LIMIT: the literal extraction is textual and not a Rust parser. A raw literal `r"..."`, or one
containing an escaped quote, can be read wrong. The error leans toward the FALSE NEGATIVE (a literal
is lost, never invented), which for a gate is the right direction: better to miss a case than to
shout at healthy code.
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# How many consecutive spaces make a defect.
#
# TWELVE, AND THE NUMBER COMES FROM A MEASUREMENT, not from an impression. Count every run of spaces
# between two lowercase letters inside a literal, across the whole tree: the longest legitimate one is
# NINE, and every hit up to nine is YAML or a Dockerfile inside a fixture, where the alignment is
# deliberate and is part of the data. The real defect instead carries the SOURCE'S INDENTATION, which
# for a literal nested in this codebase starts at sixteen; the one that made this gate necessary
# carried thirty-five. Twelve sits above every legitimate case measured and far below the defect.
#
# WHAT WOULD BREAK IT, said out loud because a threshold without its limit is a threshold that will
# one day shout at healthy code: a DELIBERATE alignment of twelve or more spaces mid-sentence between
# two lowercase letters. None exists today. If one is born, this number gets raised by the same
# measurement and not by eye. A first draft with a threshold of three produced a hundred and thirty
# false reds, all of them on help tables and fixtures, and that is how a gate gets switched off.
RUN = 12

# A run of spaces inside a literal, between any character and a lowercase letter.
#
# THE LEFT SIDE IS ANY NON-SPACE, and the first draft demanded a lowercase letter. Under that rule the
# gate DID NOT SEE ITS OWN CLASS OF DEFECT: the case that made it necessary has a COMMA before the run
# (`...actually has,<spaces>so this profile...`), and flattened continuations land after a comma or a
# colon almost every time, because that is where a sentence gets split across lines. Its positive
# control passed, and it passed because it measured nothing.
#
# The right side stays a lowercase letter: that is what separates a split sentence from an aligned
# table, where the next column starts with a capital, a digit or a dash.
BAD = re.compile(r"\S {%d,}[a-z]" % RUN)

SKIP_DIRS = {"target", ".git", "node_modules"}


def literals(line: str) -> list[str]:
    """The string literals on one line, roughly.

    Comment lines are skipped: a comment may align as much as it likes, it does not reach output.
    """
    s = line.lstrip()
    if s.startswith("//") or s.startswith("*"):
        return []
    out: list[str] = []
    i = 0
    b = line
    while i < len(b):
        if b[i] == '"':
            j = i + 1
            cur = []
            while j < len(b) and b[j] != '"':
                if b[j] == "\\":
                    # An escape is two characters and is not a character of the message: it is
                    # replaced by a single space, so it neither creates nor breaks a run.
                    j += 2
                    cur.append(" ")
                    continue
                cur.append(b[j])
                j += 1
            out.append("".join(cur))
            i = j + 1
            continue
        i += 1
    return out


def main() -> int:
    problems: list[str] = []
    files = 0
    checked = 0
    for path in sorted(REPO.rglob("*.rs")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        files += 1
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            # TEST MODULES STOP HERE, and that is not an exception: it is the definition of what this
            # gate watches. A message a user reads does not live under `#[cfg(test)]`; what lives
            # there are FIXTURES, and a YAML fixture aligns with spaces because the alignment IS the
            # data. Measured: the only two over-threshold runs left after fixing the real defect were
            # both YAML inside `kern-compose`.
            #
            # It is the same convention this repo already uses to count `unwrap`/`panic!` in
            # production: read the file up to the first `#[cfg(test)]` and stop.
            if line.lstrip().startswith("#[cfg(test)]"):
                break
            for lit in literals(line):
                checked += 1
                m = BAD.search(lit)
                if m:
                    lo = max(0, m.start() - 25)
                    hi = min(len(lit), m.end() + 25)
                    problems.append(
                        f"{path.relative_to(REPO)}:{n}: a message carries a run of spaces "
                        f"inside a sentence\n"
                        f"      ...{lit[lo:hi]}...\n"
                        f"      A line continuation flattened and the source's indentation ended up "
                        f"in text a user reads."
                    )

    if problems:
        print(f"{len(problems)} message(s) carrying a run of spaces:\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}\n", file=sys.stderr)
        return 1

    if checked < 100:
        print(
            f"error: only {checked} literals extracted from {files} files.\n"
            "  This gate compares literals, so an extraction that finds nothing would make it\n"
            "  green by absence instead of by correctness.",
            file=sys.stderr,
        )
        return 2

    print(f"{checked} literals in {files} files, no run of {RUN}+ spaces inside a sentence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
