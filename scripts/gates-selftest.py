#!/usr/bin/env python3
"""Check that each gate still catches the violation it claims to catch.

WHY THIS EXISTS
    scripts/registry-classified.py spent a long time claiming a capability it did not have. It
    checked that every runtime-root path was classified, and it did catch two of the three ways this
    codebase writes such a path, and nobody noticed the third because a green gate looks the same
    whether it is checking or not. The bug was found by hand, by writing the missing form on purpose
    and watching the gate stay green.

    That is the whole argument for this file. A gate is a claim about what cannot get in, and an
    unexercised claim decays silently: a refactor moves the code the gate greps for, a default
    narrows, a pattern stops matching, and the gate keeps printing 0 for years. The only evidence
    that a check is alive is a violation that it turns red on, run as often as the check itself.

    So: for every gate, a case that MUST fail. Introduce it in a real production file, run the gate,
    require a non-zero exit, restore. Not a fixture, not a synthetic sample: the same file CI reads,
    because a gate that works on a fixture and misses the real tree is exactly the failure above.

HOW IT PROTECTS THE WORKTREE
    Every mutation is undone in a `finally`, and the run refuses to start unless the tree is clean,
    so an interrupted run can never mix a deliberate violation with real work. The last thing it does
    is re-check that the tree is clean, and it fails loudly if it is not, naming the backup.

Usage:  python3 scripts/gates-selftest.py [-v]
Exit:   0 every gate turned red on its case, 1 if any stayed green (or the tree was left dirty).
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DASH = "\u2014"  # stated as an escape so this file does not contain what it helps forbid

# (gate, what the case proves, file, how to mutate its text)
#
# `mutate` takes the file's current text and returns the text with the violation in it. It returns
# None if the file no longer has the shape the case assumed, which is reported as a FAILURE and not
# a skip: a case that cannot be applied is a case that stopped protecting anything.
Case = tuple[str, str, str, object]


def prepend(line: str):
    return lambda text: line + "\n" + text


def replace_once(old: str, new: str):
    def go(text: str) -> str | None:
        return text.replace(old, new, 1) if old in text else None

    return go


def sub_once(pattern: str, new: str):
    def go(text: str) -> str | None:
        out, n = re.subn(pattern, new, text, count=1)
        return out if n else None

    return go


CASES: list[Case] = [
    # --- no-ai-slop: the prose pass, on a .md ---
    ("no-ai-slop", "generated vocabulary in prose", "README.md",
     prepend("This comprehensive tapestry seamlessly leverages a robust runtime.")),
    ("no-ai-slop", "the 'not only X but also Y' construction", "README.md",
     prepend("kern is not only a sandbox but also a resource runtime.")),
    ("no-ai-slop", "an em-dash in a .md", "README.md",
     prepend("A sentence with an em-dash " + DASH + " in it.")),
    # --- no-ai-slop: the em-dash pass, on the file kinds the .md-only default used to miss ---
    ("no-ai-slop", "an em-dash in Rust source", "crates/kern-cli/src/main.rs",
     lambda t: t + "\n// " + DASH + "\n"),
    ("no-ai-slop", "an em-dash in the demo SVG", "assets/demo.svg",
     lambda t: t + "\n<!-- " + DASH + " -->\n"),
    ("no-ai-slop", "an em-dash in a CI workflow", ".github/workflows/ci.yml",
     lambda t: t + "\n# " + DASH + "\n"),
    ("no-ai-slop", "an em-dash in a manifest", "Cargo.toml",
     lambda t: t + "\n# " + DASH + "\n"),
    # --- stale-numbers: one case per arm ---
    ("stale-numbers", "a retired figure (Docker's old footprint)", "SECURITY.md",
     prepend("Docker's resident memory is ~186 MB.")),
    ("stale-numbers", "an unsupported speed multiplier", "SECURITY.md",
     prepend("kern starts ~132x faster than the engines.")),
    ("stale-numbers", "a docker start time that contradicts the table", "SECURITY.md",
     prepend("docker run takes 344 ms for the same task.")),
    ("stale-numbers", "bubblewrap stated as ahead of kern", "SECURITY.md",
     prepend("Measured: bubblewrap is 0.8 ms ahead of kern.")),
    ("stale-numbers", "two documents disagreeing on box start latency", "docs/FAQ.md",
     sub_once(r"from an OCI image in ~?[0-9.]+ ms", "from an OCI image in ~9.9 ms")),
    ("stale-numbers", "a binary size that contradicts the release", "assets/demo.svg",
     sub_once(r"[0-9]\.[0-9]+ MB binary", "9.9 MB binary")),
    # --- test-count ---
    ("test-count", "a README test count that does not match the suite", "README.md",
     sub_once(r"works today:\*\* [0-9]+ Rust", "works today:** 12345 Rust")),
    # --- registry-classified ---
    #
    # Rule 3 fires on a function that BOTH derives the runtime root and joins `kern` onto it, and
    # nothing weaker: a `.join("kern")` on an arbitrary string is not provably a registry child, and
    # a gate that guessed would produce the false positives that get gates switched off. So each case
    # below derives the root the way production does, because that is what makes it a real violation
    # rather than a shape that merely resembles one. The first run of this file got that wrong and
    # the gate was right, which is the sort of thing an unexercised check never tells you.
    #
    # All three forms, because the third (`}/kern/`) is the one the gate silently did not match while
    # its own comment claimed it did.
    ("registry-classified", 'an unclassified dir via .join("kern")', "crates/kern-cli/src/volume.rs",
     prepend('fn _selftest_a() -> String {\n'
             '    let r = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();\n'
             '    Path::new(&r).join("kern").join("selftest_a").display().to_string()\n'
             '}')),
    ("registry-classified", 'an unclassified dir via a "kern/" literal', "crates/kern-cli/src/volume.rs",
     prepend('fn _selftest_b() -> String {\n'
             '    let r = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();\n'
             '    format!("{}", Path::new(&r).join("kern/selftest_b").display())\n'
             '}')),
    ("registry-classified", "an unclassified dir via an interpolated {}/kern/ path", "crates/kern-cli/src/volume.rs",
     prepend('fn _selftest_c(leaf: &str) -> String {\n'
             '    let r = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();\n'
             '    format!("{r}/kern/{leaf}")\n'
             '}')),
]


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True
    ).stdout


def dirty() -> set[str]:
    """Tracked files with changes, as a set.

    Untracked files are excluded: a case can only ever mutate a tracked file, so an untracked build
    artifact lying around is not a hazard and refusing to run because of one would make this
    unusable mid-change, which is exactly when it is worth running.
    """
    return {
        ln for ln in git("status", "--porcelain").splitlines()
        if ln.strip() and not ln.startswith("??")
    }


def run_gate(gate: str) -> int:
    return subprocess.run(
        [sys.executable, f"scripts/{gate}.py"], cwd=REPO, capture_output=True, text=True
    ).returncode


def main(argv: list[str]) -> int:
    verbose = "-v" in argv

    # The tree may legitimately have work in progress, so the check is DIFFERENTIAL: record what is
    # already modified, and at the end require exactly that same set. Anything new is a mutation this
    # run failed to undo, and it is reported with the directory the originals were kept in.
    before = dirty()

    # Sanity: every gate must be green on the untouched tree, or a red below proves nothing.
    for gate in sorted({c[0] for c in CASES}):
        rc = run_gate(gate)
        if rc != 0:
            print(f"gates-selftest: {gate} is already red on the clean tree; fix that first.")
            return 1

    backup = Path(tempfile.mkdtemp(prefix="kern-gates-selftest-"))
    failures: list[str] = []
    for i, (gate, what, rel, mutate) in enumerate(CASES):
        path = REPO / rel
        if not path.is_file():
            failures.append(f"{gate}: {rel} does not exist, so '{what}' checks nothing")
            continue
        original = path.read_text(encoding="utf-8")
        mutated = mutate(original)
        if mutated is None or mutated == original:
            failures.append(
                f"{gate}: could not write '{what}' into {rel} (the file changed shape), "
                f"so this case no longer proves the gate is alive"
            )
            continue
        keep = backup / f"{i:02d}-{path.name}"
        keep.write_text(original, encoding="utf-8")
        try:
            path.write_text(mutated, encoding="utf-8")
            rc = run_gate(gate)
        finally:
            path.write_text(original, encoding="utf-8")
        if rc == 0:
            failures.append(f"{gate}: stayed GREEN on '{what}' in {rel}")
        elif verbose:
            print(f"  red   {gate:<20} {what}  ({rel})")

    leaked = dirty() - before
    if leaked:
        print(f"gates-selftest: a mutation was not undone. Originals are in {backup}")
        for ln in sorted(leaked):
            print(f"    {ln}")
        return 1
    shutil.rmtree(backup, ignore_errors=True)

    if failures:
        print(f"\n{len(failures)} gate case{'' if len(failures) == 1 else 's'} did not hold:\n")
        for f in failures:
            print(f"  {f}")
        print("\nA gate that stays green on its own violation is not checking anything.")
        return 1
    gates = len({c[0] for c in CASES})
    print(f"{len(CASES)} cases across {gates} gates: each one turned the gate red.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
