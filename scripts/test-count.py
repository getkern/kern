#!/usr/bin/env python3
"""Assert the test counts the README states are the counts the suites actually have.

WHY THIS EXISTS
    The README's Status line is a credibility claim: "706 Rust, 72 Python and 57 Node tests".
    A reader who counts and finds a different number stops believing the rest of the page, and the
    numbers go stale the moment anyone adds a test, which is the one thing a healthy project does
    constantly. The Rust one drifted on 2026-08-04, from 703 to 704, inside the same session that
    added three other gates for the same class of defect.

    The first version of THIS script checked only the Rust number, and the Python one drifted from
    71 to 72 in the same session while the gate stayed green: a gate that covers one of the three
    numbers in a sentence protects that sentence one third of the way. All three are checked now.

HOW EACH COUNT IS OBTAINED
    Rust    `cargo test -- --list` enumerates without running: about 0.15s against a minute for the
            suite.
    Python  `pytest --collect-only -q`, likewise: it imports the module but runs no test.
    Node    counted from the SOURCE, because `node --test` has no list mode and running the suite
            needs a kern binary and about 8 seconds. Every test in that file is declared as `test(`
            at column zero, so the count is exact for this codebase and breaks LOUDLY rather than
            silently if the style changes: a declaration this misses makes the number disagree, and
            disagreeing is the whole job.

HOW IT FAILS
    Loudly, with both numbers and the file to edit. It does NOT rewrite the README: a gate that
    silently corrects a claim teaches you to stop reading it. A count it cannot obtain is reported
    as a SKIP and does not fail the run, so a docs-only container without a toolchain stays green
    while still checking whatever it can reach.

Usage:  python3 scripts/test-count.py
Exit:   0 when every count it could obtain matches, 1 when any of them does not.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _run(cmd: list[str], cwd: Path | None = None) -> str | None:
    """Stdout of `cmd`, or None when it cannot run or exits non-zero."""
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600, cwd=cwd or REPO
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def rust_count() -> int | None:
    """Rust tests, enumerated without running them."""
    out = _run(["cargo", "test", "--all", "--quiet", "--", "--list"])
    if out is None:
        return None
    return sum(1 for line in out.splitlines() if line.endswith(": test"))


def python_count() -> int | None:
    """Python binding tests, collected without running them."""
    tests = REPO / "bindings" / "python"
    if not (tests / "tests").is_dir():
        return None
    out = _run([sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"], cwd=tests)
    if out is None:
        return None
    # The tail line is "N tests collected in 0.01s"; the per-test lines are above it.
    m = re.search(r"^(\d+) tests? collected", out, re.M)
    return int(m.group(1)) if m else None


def node_count() -> int | None:
    """Node binding tests, counted from the source (see the module docstring for why)."""
    src = REPO / "bindings" / "node" / "test" / "sandbox.test.js"
    if not src.is_file():
        return None
    try:
        text = src.read_text(encoding="utf-8")
    except OSError:
        return None
    return len(re.findall(r"^test\(", text, re.M))


def stated(text: str, language: str) -> tuple[int, str] | None:
    """The count the README claims for `language`, with the sentence it sits in."""
    m = re.search(rf"\b(\d+)\s+{language}\b", text)
    if not m:
        return None
    line = next((l for l in text.splitlines() if m.group(0) in l), m.group(0))
    return int(m.group(1)), line.strip()


def main() -> int:
    try:
        text = (REPO / "README.md").read_text(encoding="utf-8")
    except OSError as e:
        print(f"SKIP: cannot read README.md: {e}")
        return 0

    checks = (("Rust", rust_count()), ("Python", python_count()), ("Node", node_count()))
    failed = 0
    for language, have in checks:
        if have is None:
            print(f"SKIP: cannot count the {language} tests here")
            continue
        claim = stated(text, language)
        if claim is None:
            print(
                f"README.md no longer states a {language} test count. Either put it back, or "
                f"delete this check on purpose rather than by accident."
            )
            failed += 1
            continue
        said, sentence = claim
        if said == have:
            print(f"{language}: README and the suite agree on {have}")
            continue
        print(
            f"README.md says {said} {language} tests, the suite has {have}.\n"
            f"  the sentence: {sentence!r}\n"
            f"  Update the README. The number is a claim a reader can check in one command, so a "
            f"wrong one costs more than no number at all."
        )
        failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
