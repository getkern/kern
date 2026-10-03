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

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def kern_binary() -> Path | None:
    """The release binary, or `None`. A gate that silently used a DEBUG build would be reporting on
    a binary nobody ships."""
    p = ROOT / "target" / "release" / "kern"
    return p if p.exists() else None


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
    kern = kern_binary()
    files = tracked_dockerfiles()
    if not files:
        print("  no tracked Dockerfile found, nothing to check")
        return 0
    if kern is None:
        print(f"  SKIP  target/release/kern is not built ({len(files)} file(s) unchecked): "
              "cargo build --release -p getkern")
        return 0

    failed = []
    for f in files:
        rel = f.relative_to(ROOT)
        # The CONTEXT is the Dockerfile's own directory, which is how each of these is documented to
        # be built. A context of the repo root would make `COPY . .` mean something entirely different.
        r = subprocess.run(
            [str(kern), "build", "--check", "-f", str(f), str(f.parent)],
            capture_output=True, text=True,
        )
        dropped = len(re.findall(r"^\s*dropped\s", r.stdout, re.M))
        if r.returncode != 0:
            failed.append((rel, f"exit {r.returncode}", r.stdout + r.stderr))
        elif dropped:
            failed.append((rel, f"{dropped} instruction(s) dropped", r.stdout))
        else:
            acted = len(re.findall(r"^\s*ok\s", r.stdout, re.M))
            print(f"  ok    {rel}  ({acted} instructions)")

    for rel, why, detail in failed:
        print(f"  FAIL  {rel}  ({why})")
        for line in detail.strip().splitlines()[-12:]:
            print(f"        {line}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
