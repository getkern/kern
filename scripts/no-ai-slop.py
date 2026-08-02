#!/usr/bin/env python3
"""Refuse the prose tells of an LLM-written document.

WHY THIS EXISTS
    kern's docs are its only sales pitch, and the audience is people who read a lot of generated text
    and have learned to stop at the first tell. One "seamlessly leverage" and the reader concludes a
    model wrote it and stops reading, whatever the measurements underneath say. That judgement is made
    in a second, from vocabulary, before a single claim is checked.

    So this is not a style opinion. It is the same shape as the em-dash rule already in this project:
    a mechanical check, run before a commit, on a fixed list of markers.

WHAT IT FLAGS
    1. Vocabulary almost nobody writes by hand but every model reaches for: delve, leverage (as a
       verb), seamless, robust, harness, unlock, elevate, tapestry, testament, game-changer,
       cutting-edge, comprehensive, streamline, empower, facilitate, utilize, boasts, showcase.
    2. Connective tics: Furthermore, Moreover, Additionally, In conclusion, It is worth noting,
       It is important to note, In today's ... landscape, ever-evolving.
    3. The "not only X but also Y" construction and "isn't just X, it's Y", which is the single most
       reliable marker of generated marketing prose.
    4. The em-dash and the "delve into" family, already banned here by hand.
    5. Emoji used as a heading marker (a heading that opens with an emoji).

WHAT IT DOES NOT FLAG
    Ordinary technical English that happens to contain a listed word inside a code span, a link
    target, or a fenced block: those are not prose. A word inside backticks is a symbol, not a voice.

Usage:  python3 scripts/no-ai-slop.py [files...]      (defaults to every tracked .md)
Exit:   0 clean, 1 if anything was flagged.
"""

from __future__ import annotations

import re
import subprocess
import sys

# (pattern, why it is a tell). Case-insensitive, word-bounded where that matters.
MARKERS: list[tuple[str, str]] = [
    (r"\bdelve[sd]?\b", "nobody delves; they look"),
    (r"\bleverag(e|es|ed|ing)\b", "use, or name the thing you are using"),
    (r"\bseamless(ly)?\b", "claims an absence of friction the reader cannot check"),
    (r"\brobust(ly|ness)?\b", "says nothing measurable; name the property"),
    (r"\bharness(ing|es)? the\b", "marketing verb"),
    (r"\bunlock(s|ing)? (the|your|new)\b", "marketing verb"),
    (r"\belevat(e|es|ing) (your|the)\b", "marketing verb"),
    (r"\btapestry\b", "the single most-mocked generated-prose noun"),
    (r"\ba testament to\b", "generated praise"),
    (r"\bgame[- ]chang(er|ing)\b", "generated praise"),
    (r"\bcutting[- ]edge\b", "generated praise"),
    (r"\bstate[- ]of[- ]the[- ]art\b", "generated praise"),
    (r"\bcomprehensive\b", "usually means 'long'; say what is covered"),
    (r"\bstreamlin(e|es|ed|ing)\b", "marketing verb"),
    (r"\bempower(s|ed|ing)?\b", "marketing verb"),
    (r"\bfacilitat(e|es|ed|ing)\b", "use 'lets' or name the mechanism"),
    (r"\butiliz(e|es|ed|ing)\b", "use 'use'"),
    (r"\bboasts?\b", "products do not boast"),
    (r"\bshowcas(e|es|ed|ing)\b", "show"),
    (r"\bplethora\b", "generated vocabulary"),
    (r"\bmyriad\b", "generated vocabulary"),
    (r"\brealm of\b", "generated vocabulary"),
    (r"\bnavigat(e|ing) the (complexit|landscape)", "generated vocabulary"),
    (r"^\s*(Furthermore|Moreover|Additionally|In conclusion|Notably)\b", "connective tic"),
    (r"\bit('s| is) (worth|important) (noting|to note)\b", "hedge that adds nothing"),
    (r"\bin today's\b", "generated opener"),
    (r"\bever[- ]evolving\b", "generated opener"),
    # `\S` on both sides: after code spans are blanked, a technical "Not only `<= max` but also `> 0`"
    # collapses to "Not only   but also" and must NOT fire. Marketing prose has words in between.
    (r"\bnot only\b[^`]*?\S{3}[^`]*?\bbut also\b", "the strongest single marker of generated marketing prose"),
    (r"\bis(n't| not) just\b.{0,60}\bit('s| is)\b", "same construction, contracted"),
    (r"—", "em-dash: this project writes . : ( ) , instead"),
    (r"^#{1,6}\s+[\U0001F300-\U0001FAFF←-⇿☀-➿]", "emoji opening a heading"),
]

COMPILED = [(re.compile(p, re.IGNORECASE | re.MULTILINE), why) for p, why in MARKERS]


def prose_only(text: str) -> list[tuple[int, str]]:
    """Lines with fenced blocks, inline code, link targets and HTML attributes blanked out.

    A listed word inside backticks is a symbol (`utilize` as a flag name), inside a URL it is a path,
    and inside a fenced block it is someone else's output. None of those are the document's voice, and
    flagging them would train the reader of this tool to ignore it.
    """
    out: list[tuple[int, str]] = []
    fence = False
    for i, line in enumerate(text.split("\n"), 1):
        if re.match(r"^\s*(```|~~~)", line):
            fence = not fence
            continue
        if fence:
            continue
        s = re.sub(r"`[^`]*`", " ", line)          # inline code
        s = re.sub(r"\]\([^)]*\)", "] ", s)        # link targets
        s = re.sub(r'\b\w+="[^"]*"', " ", s)       # HTML attributes (alt text is description, not voice)
        s = re.sub(r"https?://\S+", " ", s)        # bare URLs
        out.append((i, s))
    return out


def scan(path: str) -> list[tuple[int, str, str, str]]:
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as e:
        print(f"{path}: cannot read: {e}", file=sys.stderr)
        return []
    hits = []
    for lineno, line in prose_only(text):
        for rx, why in COMPILED:
            m = rx.search(line)
            if m:
                hits.append((lineno, m.group(0).strip(), why, line.strip()[:78]))
    return hits


def main(argv: list[str]) -> int:
    files = argv[1:]
    if not files:
        files = subprocess.run(
            ["git", "ls-files", "*.md"], capture_output=True, text=True
        ).stdout.split()
    total = 0
    for f in sorted(files):
        hits = scan(f)
        if not hits:
            continue
        total += len(hits)
        print(f"\n{f}")
        for lineno, hit, why, ctx in hits:
            print(f"  {lineno:>5}  {hit!r}: {why}")
            print(f"         {ctx}")
    print(f"\n{total} marker{'' if total == 1 else 's'} in {len(files)} file{'' if len(files) == 1 else 's'}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
