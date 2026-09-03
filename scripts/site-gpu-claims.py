#!/usr/bin/env python3
"""Does the live getkern.dev page claim a GPU cap that this build does not ship?

THE SITE IS OUTSIDE THE REPO, so `stale-numbers.py` and its `gpu_claims_agree()` never see it.
Measured on 2026-09-02: the live page had been saying "a `vgpu:` profile caps VRAM well enough that
PyTorch and ollama size themselves to it", describing a shipping VRAM cap. kern ships NO GPU limit at
all, which is what SECURITY.md, the README and `kern doctor` all say. A public page advertising a
capability the product does not have is the most expensive kind of drift.

This replaces two `grep` calls in the workflow that BOTH read the page wrong, on the real page, the
day they were written:

  * the forbidden pattern was `GPU (cap|limit|slice)s? (ship|work)`, and the page's own honest
    sentence is "No GPU limit ships, so there is nothing here to attack" - the NEGATION was read as
    the claim, so the gate failed on a page that was telling the truth.
  * the positive control was `grep -q 'NOT a boundary against malicious code'` against raw HTML,
    where that sentence is wrapped across lines. It never matched, so the control could only ever
    fail, whatever the page said.

Both are the same underlying mistake: matching prose in a markup file without normalising it, and
without asking whether the sentence found was affirmative. Usage:

    python3 scripts/site-gpu-claims.py <html-file>   # check that page
    python3 scripts/site-gpu-claims.py                # check THIS SCRIPT, against fixtures

Run bare it checks itself, because `gates-selftest.py` runs every script in `scripts/` with no
arguments and because a gate whose own reading of the page was wrong twice has not earned being
trusted unexercised. Exit 0 when the page makes no GPU-cap claim AND still carries the
cooperative-quota disclaimer.
"""

import re
import sys

# The phrasings that would DESCRIBE A SHIPPING GPU CAP. Deliberately about the capability, not about
# the word "GPU": the page is free to discuss GPUs, and does.
CLAIM = re.compile(
    r"caps VRAM|vgpu:? profile caps|GPU (?:cap|limit|slice)s? (?:ship|work)",
    re.I,
)

# A claim preceded by one of these inside the same clause is a DENIAL of the capability, which is
# exactly what the page is supposed to say. Bounded to the text just before the match so a negation
# two sentences earlier cannot excuse a later claim.
NEGATION = re.compile(r"\b(?:no|not|never|nothing|without|neither|nor)\b[^.;:]{0,40}$", re.I)

# The page must still carry this. Without it, a page that simply deleted the whole GPU section would
# pass the check above by saying nothing at all.
DISCLAIMER = "NOT a boundary against malicious code"


def flatten(html: str) -> str:
    """Collapse every run of whitespace, so a sentence wrapped across lines still reads as one."""
    return re.sub(r"\s+", " ", html)


def gpu_claims(html: str) -> list[str]:
    """Every affirmative GPU-cap claim in `html`, as a quoted excerpt. Empty when the page is clean."""
    flat = flatten(html)
    out = []
    for m in CLAIM.finditer(flat):
        if NEGATION.search(flat[max(0, m.start() - 60) : m.start()]):
            continue
        out.append(flat[max(0, m.start() - 70) : m.end() + 60].strip())
    return out


def carries_disclaimer(html: str) -> bool:
    return DISCLAIMER in flatten(html)


# (what it proves, page fragment, must this page be REFUSED)
#
# The first two are the real sentences: the honest one the page carries today, and the claim the page
# actually shipped on 2026-09-02. Both were mis-read by the `grep` version this replaces, in opposite
# directions, which is why they are the fixtures.
SELFTEST = [
    (
        "the page's own denial is not a claim",
        "<li><b>Not shipping GPU slices.</b> <span>No GPU limit ships, so there is\n"
        "  nothing here to attack. a cooperative quota, NOT a boundary against\n"
        "  malicious code.</span></li>",
        False,
    ),
    (
        "the sentence the site really shipped IS a claim",
        "<p>a <code>vgpu:</code> profile caps VRAM well enough that PyTorch and\n"
        "  ollama size themselves to it. NOT a boundary against malicious code.</p>",
        True,
    ),
    (
        "a page that drops the section is refused too",
        "<li><b>Not shipping GPU slices.</b> <span>No GPU limit ships.</span></li>",
        True,
    ),
    (
        "the disclaimer counts even when the markup wraps it",
        "<span>a cooperative quota, NOT a boundary\n   against\n   malicious code.</span>",
        False,
    ),
]


def selftest() -> int:
    bad = 0
    for what, page, must_refuse in SELFTEST:
        refused = bool(gpu_claims(page)) or not carries_disclaimer(page)
        ok = refused == must_refuse
        bad += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if bad:
        print(f"{bad} of {len(SELFTEST)} self-checks failed", file=sys.stderr)
        return 1
    print(f"{len(SELFTEST)} self-checks: this gate still reads the page the way it claims to")
    return 0


def main() -> int:
    if len(sys.argv) == 1:
        return selftest()
    if len(sys.argv) != 2:
        print("usage: site-gpu-claims.py [html-file]", file=sys.stderr)
        return 2
    html = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    claims = gpu_claims(html)
    if claims:
        print("::error::getkern.dev claims a GPU cap. No GPU limit ships.", file=sys.stderr)
        for c in claims:
            print(f"  {c}", file=sys.stderr)
        return 1
    if not carries_disclaimer(html):
        print(
            "::error::the live page no longer carries the cooperative-quota disclaimer, so the",
            file=sys.stderr,
        )
        print("  check above would pass on a page that simply dropped the GPU section", file=sys.stderr)
        return 1
    print("the live page makes no GPU-cap claim, and still carries the disclaimer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
