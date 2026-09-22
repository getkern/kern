#!/usr/bin/env python3
"""Refuse a social card that says something the README stopped saying.

WHY
    The card (`og-image*.png`) is what every share of this project renders, and it is the one surface
    no other gate can read: `stale-numbers.py` walks tracked `.md` files, and a claim baked into
    pixels is invisible to a text gate. It has now gone stale twice. On 2026-09-07 it still quoted
    "2.0 ms" while the site said 3.5 everywhere, and a screenshot of it carried two different
    latencies in one image. On 2026-09-20 it still said "For any workload, including untrusted and
    AI-generated code" after both phrases had been removed from every other surface for being
    indefensible.

    Neither time did anything go red. This is what goes red.

WHAT IT CHECKS
    `assets/make-og-card.py` holds the card's text as constants, so the picture has a readable
    source. This compares those constants with README.md's first line and with the two phrases that
    are banned from the first line anywhere:

      1. the card's headline must be a substring of the README's opening sentence;
      2. the card's sub-line must open with the README's own "built on ..." clause;
      3. neither may contain an absolute ("any workload") or the word "untrusted", both of which were
         removed from every surface on 2026-09-20 and must not come back through a picture.

    It does NOT read the PNG. A pixel diff would fail on a re-render and tells you nothing about
    truth; what matters is that the generator and the README agree, and that the deploy runs the
    generator. Regenerating the image without re-reading this file is the one hole left, which is why
    the generator is a script and not a paragraph in a commit message.

Usage:  python3 scripts/og-card-matches-readme.py
Exit:   0 clean, 1 if the card and the README disagree.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BANNED = ("any workload", "untrusted")


def card_strings() -> tuple[str, str]:
    src = (ROOT / "assets" / "make-og-card.py").read_text(encoding="utf-8")
    head = re.search(r'HEADLINE\s*=\s*\("([^"]+)",\s*"([^"]+)"\)', src)
    sub = re.search(r'SUBLINE\s*=\s*"([^"]+)"', src)
    if not head or not sub:
        sys.exit("og-card: cannot read HEADLINE/SUBLINE out of assets/make-og-card.py")
    return f"{head.group(1)} {head.group(2)}", sub.group(1)


def card_constant(name: str) -> str:
    """One string constant out of the generator, so a figure baked into pixels has a reader."""
    src = (ROOT / "assets" / "make-og-card.py").read_text(encoding="utf-8")
    m = re.search(rf'{name}\s*=\s*"([^"]+)"', src)
    if not m:
        sys.exit(f"og-card: cannot read {name} out of assets/make-og-card.py")
    return m.group(1)


def readme_lede() -> str:
    for line in (ROOT / "README.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("**kern:**"):
            return line
    sys.exit("og-card: README.md has no line starting with **kern:**, the check cannot run")


def main() -> int:
    headline, subline = card_strings()
    lede = readme_lede()
    flat = re.sub(r"\*+", "", lede).lower()
    problems: list[str] = []

    if headline.lower() not in flat:
        problems.append(
            f"the card's headline is not in the README's first line.\n"
            f"    card:   {headline}\n"
            f"    README: {lede.strip()}"
        )

    # RULE 2 USED TO REQUIRE A "built on ..." CLAUSE, and on 2026-09-22 the tagline stopped having
    # one: the first line became "a fast, rootless container runtime and sandbox with no daemon. It
    # runs workloads, ...". The gate went red on a one-line prose commit, which is the gate working,
    # but it was anchored on a PHRASE rather than on the property it defends. The property is that
    # the card says nothing the README does not, so rule 2 is now the same shape as rule 1 and
    # survives the next rewording.
    if subline.lower().rstrip(".") not in flat.rstrip():
        problems.append(
            f"the card's sub-line is not in the README's first line.\n"
            f"    card:   {subline}\n"
            f"    README: {lede.strip()}"
        )

    # THE PILL CARRIES A FIGURE, and until 2026-09-22 it carried it with no source: it still said
    # "3.5 ms" after BENCHMARKS.md moved to 3.6 and every page followed, because the generator copied
    # that band pixel for pixel. It is a constant now, so this can compare it with the row
    # stale-numbers.py already treats as canonical. A figure inside an image is worth nothing unless
    # something can read it.
    pill = card_constant("PILL")
    said = re.search(r"([\d.]+)\s*ms", pill)
    bench = (ROOT / "BENCHMARKS.md").read_text(encoding="utf-8")
    canonical = re.search(r"\|\s*\*\*kern\*\*\s*`box --image`\s*\|\s*\*\*~?([\d.]+)\s*ms\*\*", bench)
    if not said:
        problems.append("the card's pill no longer states a figure this check can read")
    elif not canonical:
        problems.append("BENCHMARKS.md no longer states the image cold start in its table")
    elif said.group(1) != canonical.group(1):
        problems.append(
            f"the card's pill says {said.group(1)} ms and BENCHMARKS.md says {canonical.group(1)} ms"
        )

    for phrase in BANNED:
        for where, text in (("headline", headline), ("sub-line", subline)):
            if phrase in text.lower():
                problems.append(f"the card's {where} contains {phrase!r}, removed from every surface on 2026-09-20")

    for p in problems:
        print(f"og-card: {p}")
    if problems:
        print(
            "\n       the card is an image, so nothing else can see this. Edit assets/make-og-card.py,\n"
            "       re-run it, and publish under a NEW name: the old one is cached immutable for a year."
        )
        return 1
    print("og-card: the card's text agrees with the README's first line")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
