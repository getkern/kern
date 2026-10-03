#!/usr/bin/env python3
"""Every Dockerfile this repository ships still builds here, checked without building one.

WHY A GATE. A recipe nobody builds rots silently: a base image moves, an instruction stops being
one kern acts on, a path in the context goes away, and the file keeps sitting in the tree looking
fine. Three Dockerfiles are tracked here and NONE of them was covered by anything before this.

WHY `build --check` AND NOT A BUILD. A real build pulls hundreds of megabytes and takes minutes,
which is not something a gate can do on every run. `--check` parses the file, resolves the stages
and reports what kern does with each instruction, exiting non-zero when it would not build. It also
reports instructions kern DROPS, and this gate fails on those too: a dropped line is a line the
author believed was doing something.

WHAT IT CANNOT SEE, stated rather than implied: that the build SUCCEEDS. A `pip install` of a
package that no longer exists passes this gate and fails a build. The check is that the recipe is
still a recipe kern can execute, not that the world it reaches out to is unchanged.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kernbin  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def tracked_dockerfiles() -> list[Path]:
    """Tracked Dockerfiles and Containerfiles. `git ls-files` and not a filesystem walk, so an
    untracked scratch file in a working tree cannot fail somebody else's gate, and so vendored
    `node_modules` trees are excluded by construction."""
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        capture_output=True, text=True, check=True,
    ).stdout
    names = [n for n in out.split("\0") if n]
    pat = re.compile(r"(^|/)(Dockerfile|Containerfile)([.-][\w.-]+)?$")
    return [ROOT / n for n in names if pat.search(n)]


def main() -> int:
    # Release OR debug, whichever represents this tree: see `kernbin.pick` for why release-only made
    # this gate skip on every CI runner.
    kern, stale = kernbin.pick(ROOT)
    files = tracked_dockerfiles()
    if not files:
        print("  no tracked Dockerfile found, nothing to check")
        return 0
    if kern is None and not stale:
        print(f"  SKIP  no kern binary is built ({len(files)} file(s) unchecked): "
              "cargo build -p getkern")
        return 0
    if kern is None:
        print("  no kern binary represents this working tree:")
        for why in stale:
            print(f"    {why}")
        return 2

    # THE COUNT COMES FROM kern's OWN SUMMARY LINE, not from counting the lines above it:
    # "2 stages, 10 instructions kern acts on, 0 it does not". Counting `dropped` lines myself was
    # the first version of this gate and it COULD NOT FAIL: my first sabotage used `HEALTHCHECK`,
    # which kern does act on, so it passed correctly while the dropped branch stayed unexercised and
    # a wrong regex would have gone unnoticed. Reading the number kern states takes my parse out of
    # the verdict. (The instruction kern really drops, and the one that exercises this, is `VOLUME`.)
    SUMMARY = re.compile(r"(\d+) instructions? kern acts on, (\d+) it does not")

    failed = []
    for f in files:
        rel = f.relative_to(ROOT)
        # The CONTEXT is the Dockerfile's own directory, which is how each of these is documented to
        # be built. A context of the repo root would make `COPY . .` mean something entirely different.
        r = subprocess.run(
            [str(kern), "build", "--check", "-f", str(f), str(f.parent)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            failed.append((rel, f"exit {r.returncode}", r.stdout + r.stderr))
            continue
        m = SUMMARY.search(r.stdout)
        if m is None:
            # A GATE THAT CANNOT READ THE OUTPUT MUST NOT REPORT GREEN. If `--check` changes its
            # wording, this fails and gets fixed, instead of passing everything forever.
            failed.append((rel, "could not find the summary line in `build --check` output",
                           r.stdout + r.stderr))
            continue
        acted, dropped = int(m.group(1)), int(m.group(2))
        if dropped:
            failed.append((rel, f"{dropped} instruction(s) kern does not act on", r.stdout))
        else:
            print(f"  ok    {rel}  ({acted} instructions)")

    for rel, why, detail in failed:
        print(f"  FAIL  {rel}  ({why})")
        for line in detail.strip().splitlines()[-12:]:
            print(f"        {line}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
