#!/usr/bin/env python3
"""Every fix in the Unreleased section declares what it did about its own injection.

WHY THIS EXISTS
    A correction with an injected defect that turns its test red is the strong form of the positive
    control: it proves the test is not green by absence. One round of work produced 24 of them, 24
    red, and that property held only because someone kept doing it by hand.

    It is deliberately NOT a gate on the injection itself. A gate that demanded an executed injection
    would have to verify an artefact it cannot produce - several of this project's suites need
    hardware or permissions CI does not have (AppArmor, a GPU, a delegated cgroup) - and the only
    thing it could then check is that a FILE EXISTS, which is comparing state instead of content:
    exactly the defect class this whole mechanism was built to catch, promoted to a gate.

    So it asks for a DECLARATION, and does not judge its content. The cost to a contributor is one
    line. The number worth watching is how many of them say `none`.

THE LINE
    Anywhere inside the entry, on its own line:

        Injection: verified - <the case it turns red>
        Injection: manual: <host> - <the case, and where it was run>
        Injection: none - <why there is nothing to inject>

    `verified` means it was run here and went red. `manual` means it was run somewhere CI cannot go,
    and says where, which is honest in a way that a green CI badge would not be. `none` is legitimate
    - a documentation change, a rename, a dependency bump - and it is the count this gate reports.

WHAT IT IS NOT
    It never fails the build. A warning that cannot be silenced by writing the wrong thing is worth
    more here than a refusal that gets worked around, and the entries it warns about are visible in
    the same review as the code.

Usage:  python3 scripts/injection-declared.py
Exit:   always 0. The report is the product.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHANGELOG = REPO / "CHANGELOG.md"

# Sections whose entries describe a CODE change. `Added` is included: a new feature has behaviour to
# get wrong, and its test can be green by absence exactly like a fix's.
CODE_SECTIONS = {"Added", "Changed", "Fixed", "Removed", "Security"}

DECL = re.compile(r"^\s*Injection:\s*(verified|manual|none)\b", re.IGNORECASE)

# Entries written before this gate existed, frozen by their opening words.
#
# WITHOUT THIS LIST THE COUNTER DEGRADES. The gate cannot tell "old and undeclared" from "new and
# undeclared", so after a few rounds the number is N historical plus M new, indistinguishable, and
# nobody can say whether the mechanism is working. Freezing them makes `undeclared: 0` a reachable
# state and every appearance new BY CONSTRUCTION - the same property that makes
# `cli_surface_is_frozen` the one part of this bench that has never gone out of sync: an explicit
# snapshot against which the diff is the question.
#
# Nothing is retrofitted into this list. An entry added from now on and left undeclared is meant to
# be visible.
GRANDFATHERED = (
    "**Final validation: eight sentences narrowed",
    "**Closing the GPU phase: a shell payload",
    "**A second review round: a lying exit code",
    "**The hardware tier now claims what it proved",
    "**A fifth adversarial suite, and it publishes a defeat.**",
    "**`kern doctor` now reports what a VRAM cap",
    "**`--landlock-rw <path>` now works on `kern run`**",
    "**A Landlock grant on a file rather than a directory",
)


def unreleased(text: str) -> list[str]:
    """The lines of the `## Unreleased` section, up to the next `## `."""
    lines = text.split("\n")
    start = next((i for i, l in enumerate(lines) if l.strip().lower() == "## unreleased"), None)
    if start is None:
        return []
    out = []
    for l in lines[start + 1 :]:
        if l.startswith("## "):
            break
        out.append(l)
    return out


def entries(lines: list[str]) -> list[tuple[str, str, list[str]]]:
    """`(section, title, body)` for every top-level bullet under a code section."""
    out: list[tuple[str, str, list[str]]] = []
    section = ""
    cur: tuple[str, str, list[str]] | None = None
    for l in lines:
        if l.startswith("### "):
            if cur:
                out.append(cur)
                cur = None
            section = l[4:].strip()
            continue
        if l.startswith("- ") and section in CODE_SECTIONS:
            if cur:
                out.append(cur)
            cur = (section, l[2:].strip(), [])
            continue
        if cur is not None:
            # A new top-level bullet in a NON-code section closes the current entry.
            if l.startswith("- ") and section not in CODE_SECTIONS:
                out.append(cur)
                cur = None
            else:
                cur[2].append(l)
    if cur:
        out.append(cur)
    return out


def main() -> int:
    if not CHANGELOG.is_file():
        print("SKIP: no CHANGELOG.md, so there are no entries to check.", file=sys.stderr)
        return 0
    body = unreleased(CHANGELOG.read_text(encoding="utf-8"))
    if not body:
        print("no `## Unreleased` section: nothing to check")
        return 0

    found = entries(body)
    if not found:
        print("no entries under a code section in `## Unreleased`")
        return 0

    missing: list[tuple[str, str]] = []
    frozen = 0
    counts = {"verified": 0, "manual": 0, "none": 0}
    for section, title, lines in found:
        m = next((DECL.match(l) for l in lines if DECL.match(l)), None)
        if m is None and title.startswith(GRANDFATHERED):
            frozen += 1
        elif m is None:
            missing.append((section, title))
        else:
            counts[m.group(1).lower()] += 1

    total = len(found)
    print(
        f"{total} entr{'y' if total == 1 else 'ies'} under a code section: "
        f"{counts['verified']} verified, {counts['manual']} manual, {counts['none']} none, "
        f"{len(missing)} undeclared, {frozen} frozen (written before this gate)"
    )
    if counts["none"]:
        # The number the gate exists to surface. Not a failure: some changes have nothing to inject.
        print(f"  {counts['none']} entr{'y' if counts['none'] == 1 else 'ies'} declare `none`.")
    for section, title in missing:
        short = title[:96] + ("…" if len(title) > 96 else "")
        print(f"  no `Injection:` line under {section}: {short}", file=sys.stderr)
    if missing:
        print(
            "\n  A correction whose injected defect turns its test red is the proof that the test is\n"
            "  not green by absence. Add one line inside the entry:\n"
            "      Injection: verified - <the case it turns red>\n"
            "      Injection: manual: <host> - <the case, and where it ran>\n"
            "      Injection: none - <why there is nothing to inject>\n"
            "  This never fails the build; it is here so the count is visible in review.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
