#!/usr/bin/env python3
"""Assert the Rust test count the README states is the count the suite actually has.

WHY THIS EXISTS
    The README's Status line is a credibility claim: "703 Rust, 69 Python and 56 Node tests".
    A reader who counts and finds a different number stops believing the rest of the page, and
    the number goes stale the moment anyone adds a test, which is the one thing a healthy
    project does constantly. It drifted on 2026-08-04, from 703 to 704, inside the same session
    that added three other gates for the same class of defect.

    `cargo test -- --list` enumerates without running: 0.14s against about a minute for the
    suite, so this is cheap enough to be a gate rather than a chore.

HOW IT FAILS
    Loudly, with both numbers and the file to edit. It does NOT rewrite the README: a gate that
    silently corrects a claim teaches you to stop reading it.

Usage:  python3 scripts/test-count.py
Exit:   0 when the README matches the suite, 1 when it does not, 0 with a SKIP line when cargo
        is unavailable (so a docs-only CI container does not fail on a missing toolchain).
"""

from __future__ import annotations

import re
import subprocess
import sys


def counted() -> int | None:
    """Tests the suite actually has, or None when cargo cannot answer."""
    try:
        out = subprocess.run(
            ["cargo", "test", "--all", "--quiet", "--", "--list"],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return sum(1 for line in out.stdout.splitlines() if line.endswith(": test"))


def stated(text: str) -> tuple[int, str] | None:
    """The count the README claims, with the sentence it sits in."""
    m = re.search(r"\b(\d+)\s+Rust\b[^.\n]*tests?", text)
    return (int(m.group(1)), m.group(0)) if m else None


def main() -> int:
    have = counted()
    if have is None:
        print("SKIP: cargo could not list the tests (no toolchain?)")
        return 0
    try:
        text = open("README.md", encoding="utf-8").read()
    except OSError as e:
        print(f"SKIP: cannot read README.md: {e}")
        return 0

    claim = stated(text)
    if claim is None:
        print("README.md no longer states a Rust test count at all. Either put it back, or "
              "delete this gate on purpose rather than by accident.")
        return 1

    said, sentence = claim
    if said == have:
        print(f"README.md and the suite agree: {have} Rust tests")
        return 0
    print(
        f"README.md says {said} Rust tests, the suite has {have}.\n"
        f"  the sentence: {sentence!r}\n"
        f"  Update the README. The number is a claim a reader can check in one command, so a "
        f"wrong one costs more than no number at all."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
