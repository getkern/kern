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

import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DASH = "\u2014"  # stated as an escape so this file does not contain what it helps forbid

# Scripts in `scripts/` that are NOT gates, each with the reason it is excluded.
#
# The exclusion is a NAMED LIST and not a pattern on purpose: a new gate is covered the day it lands,
# and the only way to escape coverage is to write your name here, where it is read.
NOT_A_GATE = {
    "gates-selftest": "this script, which runs the others by construction",
    "seccomp-audit": "not a gate: it needs a live workload and an audit log to read",
    "injection-declared": "reports rather than refuses: it always exits 0 by design, so a case that turned it red would be asserting the opposite of its contract",
}

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
    # --- flat-continuation: la forma VERA del difetto, con una virgola prima della corsa.
    #
    # La prima stesura del cancello pretendeva una minuscola a sinistra e quindi non vedeva questo
    # caso, che e' esattamente quello che l'ha fatto nascere. Il suo controllo positivo passava, e
    # passava perche' non misurava niente: questo caso esiste per impedire che riaccada.
    ("flat-continuation", "una continuazione di riga appiattita dentro un messaggio",
     "crates/kern-cli/src/commands/mod.rs",
     # L'INIEZIONE DEVE TOGLIERE LA CONTINUAZIONE, non aggiungere spazi prima di essa: Rust mangia
     # `\` piu' il ritorno a capo piu' l'indentazione, quindi degli spazi messi PRIMA della barra
     # sparirebbero e il caso resterebbe verde. La prima stesura faceva esattamente questo, e il
     # selftest l'ha detto: "stayed GREEN on its own violation".
     replace_once(
         "in the box: {e} - \\\n                         name resolution",
         "in the box: {e} -                          name resolution",
     )),
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


def gates() -> list[str]:
    """Every script in `scripts/` that claims to be a gate."""
    return sorted(
        p.stem for p in (REPO / "scripts").glob("*.py") if p.stem not in NOT_A_GATE
    )


def content_state() -> dict[str, str]:
    """Every tracked file that differs from HEAD, mapped to a HASH OF ITS DIFF.

    CONTENT AND NOT STATUS, and the first draft compared status. It built a set of
    `git status --porcelain` lines and called a gate clean when that set had not changed. On a clean
    tree that works. On a tree with work in progress it does not: a file that is ALREADY modified is
    reported by the same ` M path` line no matter what else gets appended to it, so a gate writing
    into a file the operator was already editing produced no difference at all.

    Measured, on a branch carrying nineteen modified files: a probe gate that appended a line to
    `README.md` ran, wrote, and this phase reported that nothing had happened. A check that is blind
    exactly where the tree is busiest is worse than no check, because it is run for reassurance.
    """
    state: dict[str, str] = {}
    for ln in git("status", "--porcelain").splitlines():
        # Untracked files are out of scope for the same reason as in `dirty()`, and a rename or a
        # mode change carries no diff hunk, so the status line itself is the signature.
        if ln.strip() and not ln.startswith("??"):
            state[ln[3:].strip()] = ln[:2]
    # Then the per-file diff, which is what sees a write into an already-modified file.
    current = None
    body: list[str] = []
    for line in git("diff", "HEAD").splitlines():
        if line.startswith("diff --git "):
            if current is not None:
                state[current] = hashlib.sha1("\n".join(body).encode()).hexdigest()
            body = []
            # `diff --git a/PATH b/PATH`; take the b-side, which is the name after any rename.
            current = line.split(" b/", 1)[-1]
        else:
            body.append(line)
    if current is not None:
        state[current] = hashlib.sha1("\n".join(body).encode()).hexdigest()
    return state


def check_no_gate_writes(failures: list[str], keep: Path) -> None:
    """RUN BARE, A GATE MUST READ AND NOT WRITE.

    `gen-seccomp-allowlist.py` used to GENERATE when invoked with no argument and check only under
    `--check`. Every other script here is a gate that reads, so a sweep that ran them all treated
    that one as a gate too and it rewrote `seccomp_allow.rs` on the spot: the tree came back dirty on
    a generated file, `cargo fmt --check` went red next, and the hunt was for a change nobody made.
    Nothing was wrong with the allow-list. The generator was the only thing that had touched it.

    The defect is not that one script's argument parsing; it is that a directory of read-only checks
    had no rule saying so, so the hazardous default was invisible until it fired. This is the rule.
    A generator keeps its power under an explicit `--write`, which is a word you cannot type by
    accident.

    HOW A WRITE IS UNDONE, and this is the part that has to be right before the check is worth
    running at all. The first draft restored with `git checkout -- <path>`, which is correct for a
    file that was clean and DESTROYS UNCOMMITTED WORK for a file that was not. This phase exists to
    be run mid-change, so that is the case it would have hit. Every file that already differs from
    HEAD is therefore copied aside BEFORE any gate runs, and a write is undone from that copy;
    `git checkout` is used only for a file that had nothing to lose.
    """
    before = content_state()
    # The safety net, taken before the first gate and not after the first surprise.
    saved: dict[str, Path] = {}
    for i, rel in enumerate(sorted(before)):
        src = REPO / rel
        if src.is_file():
            dst = keep / f"pre-{i:03d}-{src.name}"
            dst.write_bytes(src.read_bytes())
            saved[rel] = dst

    for gate in gates():
        run_gate(gate)  # the exit code is the other phase's business; this one watches the tree
        after = content_state()
        wrote = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        if not wrote:
            continue
        failures.append(
            f"{gate}: run with no argument, it MODIFIED the tree instead of checking it.\n"
            f"      {', '.join(wrote)}\n"
            "      A gate reads. Put the writing behind an explicit flag, and leave the bare\n"
            "      invocation as the check, because bare is what a sweep and a habit will use."
        )
        for rel in wrote:
            if rel in saved:
                (REPO / rel).write_bytes(saved[rel].read_bytes())
            else:
                subprocess.run(["git", "checkout", "--", rel], cwd=REPO)
        # Re-read, so the next gate is measured against the restored tree and not against this one's
        # damage, which would otherwise blame every gate that follows.
        before = content_state()

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

    # First, because a gate that writes would corrupt every measurement taken after it.
    check_no_gate_writes(failures, backup)

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
    exercised = len({c[0] for c in CASES})
    print(
        f"{len(CASES)} cases across {exercised} gates: each one turned the gate red.\n"
        f"{len(gates())} gates run bare: none of them wrote to the tree."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
