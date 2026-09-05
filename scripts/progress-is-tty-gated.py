#!/usr/bin/env python3
"""Every line of kern's own PROGRESS must go through `kern_common::progress!`, never `eprintln!`.

kern and a box's workload share one stderr. A progress line written with a bare `eprintln!` therefore
lands in whatever is reading that stream: a pipeline, `kern logs`, or the SDK, where an external audit
found six `→ layer …` lines sitting in front of the program's own output inside a LangChain tool
result. `progress!` writes only when stderr is a terminal, which is the rule the `kern box` status
panel already followed and the pull path never did.

This gate exists because converting the sites BY HAND missed one. Fourteen were found by grep and the
fifteenth, a multi-line `eprintln!` whose format string sat on the next line, survived into a live run
and was caught by testing rather than by reading. A rule enforced by attention is a rule that decays.

NOT covered, deliberately: errors, warnings and `kern: note:` advice. A pipe is exactly where those
must still arrive.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# A progress line announces a step kern is taking. These are its markers, at the START of the text.
MARKERS = ("→", "✓", "  layer ")


def offending(path: Path):
    """Yield (line_no, text) for every bare eprint!/eprintln! whose message opens with a marker.

    Reads the whole macro call, not one line: the format string is often on the line AFTER the
    `eprintln!(`, which is exactly the shape that escaped the manual pass.
    """
    src = path.read_text(encoding="utf-8")
    for m in re.finditer(r"\beprint(?:ln)?!\s*\(", src):
        i, depth = m.end() - 1, 0
        while i < len(src):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        call = src[m.start():i]
        lit = re.search(r'"((?:[^"\\]|\\.)*)"', call)
        if lit and lit.group(1).startswith(MARKERS):
            yield src[: m.start()].count("\n") + 1, lit.group(1)[:60]


def main() -> int:
    bad = []
    for f in sorted((ROOT / "crates").rglob("*.rs")):
        if f.name == "tests.rs" or "/tests/" in str(f):
            continue
        for line, text in offending(f):
            bad.append(f"{f.relative_to(ROOT)}:{line}: {text}")
    if bad:
        print("progress written with a bare eprintln! (use kern_common::progress! instead):")
        for b in bad:
            print(f"  {b}")
        print(
            "\nkern's stderr is the box's stderr as far as the SDK is concerned, so this line reaches\n"
            "an agent's context on any run that triggers it. `progress!` prints only on a terminal."
        )
        return 1
    print("progress-is-tty-gated: every progress line goes through kern_common::progress!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
