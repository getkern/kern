#!/usr/bin/env python3
"""In the modules that NARRATE, every `eprintln!` is either progress or carries kern's prefix.

kern and a box's workload share one stderr. Two different things go wrong on that stream, and this
gate exists for both:

  PROGRESS ("-> layer 1/3 downloading...") must not go out at all when nobody is watching a terminal.
  It goes through `progress!`, which is the rule the `kern box` status panel already followed.

  A DIAGNOSTIC must carry `kern: `. That prefix is the ONLY thing the SDK has to tell kern's voice
  from the workload's, so a bare `warning: bound 0.0.0.0` or `note: pulled linux/arm64` is, to a
  reader of the result, a line the program printed. Three such lines were live when this gate was
  written, in `ports.rs`, `images.rs` and `build.rs`.

WHY THE RULE IS SCOPED TO A LIST OF FILES

The first version of this gate matched a set of leading MARKERS ("->", "OK", "  layer "). A reviewer
pointed out that it freezes today's punctuation rather than the rule: a new progress line reading
`eprintln!("pulling {image}...")` has no marker and sails through. They were right, and running the
scoped form below immediately found seven more progress lines in `build.rs` and `push.rs` that the
marker version had passed, using `[1/3] FROM ...` and `  [cached - ...]` instead.

So the rule is exhaustive within a scope: in these files, EVERY `eprintln!` must be one or the other.
A wider scope is not reachable statically. 55 `eprintln!` calls in the workspace print a variable with
no literal to inspect, and the honest thing is to say so rather than pass them silently: `--audit`
lists them.

NOT COVERED, and this is the gate's real boundary: a diagnostic added to a file NOT in NARRATING. The
list is the judgement here, and it is the part a future change can outgrow.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The modules that narrate what kern is doing. Everything reachable from a box start or an image
# operation, which is what an SDK caller's stderr is made of.
NARRATING = [
    "kern-oci/src/pull.rs",
    "kern-oci/src/push.rs",
    "kern-cli/src/commands/build.rs",
    "kern-cli/src/commands/compose.rs",
    "kern-cli/src/commands/imagecache.rs",
    "kern-cli/src/commands/images.rs",
    "kern-isolation/src/ports.rs",
]

# A line kern writes about itself starts with one of these. `kern: ` is what the SDK keys on; `error:`
# and `hint:` are the two the CLI's own error path emits, at column 0, by design.
ALLOWED = ("kern: ", "error:", "hint:")


def _test_spans(src: str):
    """Byte ranges of `#[cfg(test)]` items, which are not shipped and may print however they like."""
    spans = []
    for m in re.finditer(r"#\[cfg\(test\)\]", src):
        brace = src.find("{", m.end())
        if brace < 0:
            continue
        i, depth = brace, 0
        while i < len(src):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        spans.append((m.start(), i))
    return spans


def _calls(src: str):
    """Yield (offset, whole_call_text) for each `eprintln!`/`eprint!`, skipping `#[cfg(test)]`.

    Walks to the matching paren rather than to end of line: the call this gate was written for had its
    format string on the FOLLOWING line and a line-based reader missed it.
    """
    skip = _test_spans(src)
    for m in re.finditer(r"\beprint(?:ln)?!\s*\(", src):
        if any(a <= m.start() <= b for a, b in skip):
            continue
        i, depth = m.end() - 1, 0
        while i < len(src):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        yield m.start(), src[m.start():i]


# A diagnostic must never be wrapped in `progress!`. The two halves of the rule are exclusive, and
# satisfying both at once is the one combination that reads as correct and is not: a `kern: warning:`
# inside `progress!` passes the prefix test AND the progress test, and prints only on a terminal, so
# the warning is silent exactly where a machine is reading. One shipped for four minutes, from a bulk
# rewrite whose search found the wrong `eprintln!`.
DIAGNOSTIC_PREFIXES = ("kern: warning:", "kern: note:", "kern: security-profile=")


def _gated_diagnostics(src: str):
    for m in re.finditer(r"\bprogress!\s*\(", src):
        i, depth = m.end() - 1, 0
        while i < len(src):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        lit = re.search(r'"((?:[^"\\]|\\.)*)"', src[m.start():i], re.DOTALL)
        if lit and lit.group(1).startswith(DIAGNOSTIC_PREFIXES):
            yield src[: m.start()].count("\n") + 1, lit.group(1)[:64]


def main() -> int:
    audit = "--audit" in sys.argv
    bad, unverifiable = [], []
    for rel in NARRATING:
        path = ROOT / "crates" / rel
        if not path.exists():
            print(f"NARRATING names a file that does not exist: {rel}")
            return 1
        src = path.read_text(encoding="utf-8")
        for off, call in _calls(src):
            line = src[:off].count("\n") + 1
            # `re.DOTALL`, and it is not decoration. Rust continues a long string with a trailing
            # backslash and a newline, so `\\.` without DOTALL fails to match the escape, the regex
            # gives up on the real format string and matches a LATER literal in the argument list.
            # That reported two `kern: note:` lines in `compose.rs` as unprefixed. It fails the other
            # way just as easily: a benign later literal would have hidden a bad first one.
            lit = re.search(r'"((?:[^"\\]|\\.)*)"', call, re.DOTALL)
            # A format string that is ONLY placeholders (`eprintln!("{note}")`) carries no text of
            # kern's own: the prefix lives in the value, built somewhere else. Reporting it as a
            # violation is wrong, and both real cases in `compose.rs` do produce `kern: note: ...`.
            # It is unverifiable rather than clean, and `--audit` says so.
            placeholder_only = lit is not None and not re.sub(r"\{[^{}]*\}", "", lit.group(1)).strip()
            if lit is None or placeholder_only:
                why = "prints a value" if lit is None else "format string is only placeholders"
                unverifiable.append(f"{rel}:{line}: {why}, nothing to check statically")
            elif not lit.group(1).startswith(ALLOWED):
                bad.append(f"{rel}:{line}: {lit.group(1)[:64]}")
        for line, text in _gated_diagnostics(src):
            bad.append(f"{rel}:{line}: a diagnostic inside progress!, so it prints only on a tty: {text}")
    if bad:
        print("in a narrating module, an eprintln! that is neither progress nor a kern: diagnostic:")
        for b in bad:
            print(f"  {b}")
        print(
            "\nProgress goes through `progress!` (terminal only). A diagnostic starts with `kern: `,\n"
            "which is the only thing the SDK has to tell kern's output from the workload's."
        )
        return 1
    print(
        f"progress-is-tty-gated: {len(NARRATING)} narrating modules clean "
        f"({len(unverifiable)} calls print a value and cannot be checked statically)"
    )
    if audit:
        for u in unverifiable:
            print(f"  unverifiable: {u}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
