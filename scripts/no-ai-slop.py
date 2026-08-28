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

WHICH FILES, AND WHY THE TWO PASSES DIFFER
    The vocabulary markers are a judgement about PROSE, so they run on tracked .md only: "robust" in
    a Rust identifier is a name, not a voice, and flagging it would train the reader to ignore this
    tool. The em-dash is not a judgement, it is an absolute: zero occurrences, in any tracked text
    file. Those are different rules, so they get different scopes.

    Running the em-dash arm on .md alone was a gate that claimed more than it checked: the rule says
    "no em-dash in this project", the check said "no em-dash in the documentation", and a commit
    could put one in a .rs, a .sh, an .svg or a workflow and stay green. Measured before the fix: an
    em-dash appended to crates/kern-cli/src/main.rs, to assets/demo.svg and to .github/workflows/
    ci.yml passed all four gates. It scans raw bytes with no blanking and no fence handling, because
    "zero" admits no context in which the character is allowed.

    This file states the character as the escape \\u2014 rather than typing it, so the gate does not
    contain what it forbids and needs no exemption for itself.

Usage:  python3 scripts/no-ai-slop.py [files...]
        No arguments: every tracked .md gets the full marker set, every other tracked text file gets
        the em-dash pass. With arguments: .md gets the full set, anything else the em-dash pass.
Exit:   0 clean, 1 if anything was flagged.
"""

from __future__ import annotations

import re
import subprocess
import sys

# The one marker both passes share, named so the prose pass and the em-dash pass cannot drift.
EM_DASH_PATTERN = "\u2014"
EM_DASH_WHY = "em-dash: this project writes . : ( ) , instead"

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
    (EM_DASH_PATTERN, EM_DASH_WHY),
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


EM_DASH = re.compile(EM_DASH_PATTERN)


def read_text(path: str) -> str | None:
    """The file's text, or None if it is binary or unreadable.

    A tracked .png or .gif is not a text file and decoding it would raise; that is the test, so the
    decode failure IS the binary check and no extension list is needed.
    """
    try:
        return open(path, encoding="utf-8").read()
    except UnicodeDecodeError:
        return None
    except OSError as e:
        print(f"{path}: cannot read: {e}", file=sys.stderr)
        return None


def scan(path: str) -> list[tuple[int, str, str, str]]:
    """The full marker set, on prose, with code spans and fenced blocks blanked."""
    text = read_text(path)
    if text is None:
        return []
    hits = []
    for lineno, line in prose_only(text):
        for rx, why in COMPILED:
            m = rx.search(line)
            if m:
                hits.append((lineno, m.group(0).strip(), why, line.strip()[:78]))
    return hits


def scan_em_dash(path: str) -> list[tuple[int, str, str, str]]:
    """The em-dash alone, on raw lines.

    No blanking and no fence handling on purpose: the rule is zero occurrences, so there is no
    context (a string literal, a comment, an SVG text node, a YAML value) in which one is allowed.
    """
    text = read_text(path)
    if text is None:
        return []
    hits = []
    for lineno, line in enumerate(text.split("\n"), 1):
        if EM_DASH.search(line):
            hits.append((lineno, EM_DASH_PATTERN, EM_DASH_WHY, line.strip()[:78]))
    return hits


def tracked(*patterns: str) -> list[str]:
    return subprocess.run(
        ["git", "ls-files", *patterns], capture_output=True, text=True
    ).stdout.split()


def main(argv: list[str]) -> int:
    files = argv[1:]
    if files:
        prose = [f for f in files if f.endswith(".md")]
        rest = [f for f in files if not f.endswith(".md")]
    else:
        prose = tracked("*.md")
        rest = [f for f in tracked() if not f.endswith(".md")]
    total = 0
    work = [(f, scan) for f in prose] + [(f, scan_em_dash) for f in rest]
    for f, scanner in sorted(work, key=lambda t: t[0]):
        hits = scanner(f)
        if not hits:
            continue
        total += len(hits)
        print(f"\n{f}")
        for lineno, hit, why, ctx in hits:
            print(f"  {lineno:>5}  {hit!r}: {why}")
            print(f"         {ctx}")
    n = len(prose) + len(rest)
    print(
        f"\n{total} marker{'' if total == 1 else 's'} in {n} file{'' if n == 1 else 's'} "
        f"({len(prose)} scanned for prose markers, {len(rest)} for the em-dash only)"
    )
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
