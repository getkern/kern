#!/usr/bin/env python3
"""The words a Docker user TYPES must appear in the documentation, whatever the answer is.

WHY THIS EXISTS. Twice in one day a capability was finished, tested and invisible, because the
documentation described it in the project's own words rather than in the words someone arrives with:

  * `extra_hosts` + `host-gateway` shipped with a test and an example, and `host.docker.internal`
    appeared NOWHERE in any `.md`. A reader whose container cannot reach the host searches for that
    string, finds nothing, and concludes kern cannot do it. Three weeks, nobody noticed.
  * `kern login` is a real verb in the parser, and `docker login` appeared nowhere. Someone evaluating
    kern reads the README before installing the binary, so `kern --help` is the one place they cannot
    look.

This is `stale-numbers.py`'s trade applied to the QUESTION instead of the answer: that gate checks a
figure a reader could disprove, this one checks a word a reader will search for. A "no" is a perfectly
good answer, as long as the word that leads to it is in the text. `--gpus` is here and kern ships no GPU
cap: what the gate wants is the sentence that says so, next to the string that finds it.

NOT A SPELLING RULE. Each entry has a REASON, because the list is only worth what the reasons are: the
capability it leads to, or the non-goal it declares. An entry with no reason is somebody's taste.

    scripts/docker-vocabulary.py

Exit 0 iff every word is findable. The positive and negative controls run FIRST, so a finder that
matches everything or nothing cannot report a green.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Word a Docker user types -> why it must be findable. The reason is the point of the row.
VOCABULARY = {
    "docker-compose.yml": "the file they already have, and the first thing they will search for",
    "host.docker.internal": "the name Docker resolves to the host; kern does it through "
    "`extra_hosts: [\"host.docker.internal:host-gateway\"]`, which nobody guesses",
    "docker login": "a private registry. `kern login` is the verb, and `kern --help` is the one place "
    "someone evaluating kern before installing cannot look",
    "docker.sock": "the first thing an integrator asks for, and a declared non-goal: it is a second "
    "product, not a flag",
    "--gpus": "no GPU cap ships, and the reasoning is in GPU-CLAIMS.md. The word is how a reader "
    "reaches that answer instead of assuming one",
    "swarm": "a declared non-goal (it needs a daemon), and the word a reader arrives with",
    "overlay network": "the multi-host network they may be looking for, refused with a reason: a "
    "rootless L2 bridge is not possible",
    "Dockerfile": "`kern build` reads one, and a reader who does not know that assumes it does not",
    "extra_hosts": "the compose key behind host.docker.internal, so the two are searchable together",
    "healthcheck": "the compose key, because a stack that has one will not start without it",
    "tmpfs": "the mount a reader expects to be able to ask for",
    ".dockerignore": "honoured by the build context, and silently ignoring it would be the defect",
}

# The controls, run FIRST. A finder that matches everything, or nothing, must not be able to report a
# green: this is the same discipline as the em-dash gate's built character.
MUST_BE_PRESENT = "compose"
MUST_BE_ABSENT = "kern-vocabulary-gate-control-string-that-is-nowhere"


def docs() -> "list[Path]":
    """Every tracked `.md` EXCEPT a changelog, because a changelog is not where anyone looks for a
    capability.

    Untracked files are excluded for the reason `stale-numbers.py` learned the hard way: a file nobody
    has added is invisible to a reader of the repository, so counting it makes the gate lie in the
    comfortable direction. The changelog exclusion is the same argument one step further: "it was in the
    0.8.3 notes" is not findable, and without this a word could pass the gate while living only in a list
    of past releases. Measured when this gate was written: every word was also outside the changelog, so
    the exclusion costs nothing today and closes the case it exists for."""
    out = subprocess.run(
        ["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    return [
        ROOT / line
        for line in out.stdout.split("\n")
        if line.strip() and "changelog" not in line.lower()
    ]


def find(word: str, files: "list[Path]") -> "list[str]":
    hits = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if word.lower() in text.lower():
            hits.append(str(f.relative_to(ROOT)))
    return hits


def main() -> int:
    files = docs()
    if not files:
        print("docker-vocabulary: no tracked .md files found, so this gate measured nothing")
        return 2
    print(f"docker-vocabulary: {len(files)} tracked .md files")

    # CONTROLS FIRST.
    if not find(MUST_BE_PRESENT, files):
        print(f"  CONTROL FAILED: {MUST_BE_PRESENT!r} is not findable, so the finder is broken")
        return 2
    if find(MUST_BE_ABSENT, files):
        print(f"  CONTROL FAILED: {MUST_BE_ABSENT!r} was 'found', so the finder matches anything")
        return 2
    print(f"  controls ok: {MUST_BE_PRESENT!r} found, a nonsense string not found")

    missing = []
    for word, why in sorted(VOCABULARY.items()):
        hits = find(word, files)
        if hits:
            where = hits[0] + (f" (+{len(hits) - 1})" if len(hits) > 1 else "")
            print(f"  ok   {word:24} {where}")
        else:
            missing.append((word, why))
            print(f"  MISSING {word:21} {why}")

    if missing:
        print()
        print(f"{len(missing)} word(s) a Docker user types are in no .md file.")
        print("A 'no' is a fine answer; a word that leads nowhere is not. Put the word in the text")
        print("beside whatever the answer is, or delete the row and say why it stopped mattering.")
        return 1
    print(f"\nall {len(VOCABULARY)} findable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
