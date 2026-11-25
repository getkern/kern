#!/usr/bin/env python3
"""Every action a workflow runs is pinned to a commit, with the ref it was pinned from.

WHY THIS EXISTS
    A tag or a branch is a pointer its owner can move: `@v5` today and `@v5` tomorrow can be two
    different programs, and the release workflow runs with the repository's token, builds the
    binaries users install and writes the SBOM that describes them. `dtolnay/rust-toolchain@master`
    was in that workflow, and so were nine other movable refs. A commit id cannot be moved.

    A pin that is never updated is its own risk (it keeps a fixed action's old bug), so this file
    also refreshes them, deliberately and in one diff a person reads:

        python3 scripts/actions-pinned.py            # the gate: every `uses:` is pinned
        python3 scripts/actions-pinned.py --refresh  # re-resolve each `# ref` and rewrite the pins

    The refresh asks the public GitHub API which commit each ref names now (`GITHUB_TOKEN`, if set,
    only raises the rate limit). It changes nothing it cannot resolve.

A `uses:` passes when it is a local action (`./...`), a `docker://` image pinned by digest, or
`owner/repo[/path]@<40 hex> # <ref>`.

Exit: 0 every action pinned (or refreshed), 1 otherwise.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
USES = re.compile(r"^(?P<lead>\s*(?:-\s+)?uses:\s*)(?P<ref>[^\s#]+)(?P<rest>\s*(?:#\s*(?P<comment>\S+).*)?)$")
PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@\s]+)?@[0-9a-f]{40}$")


def problems(path: Path) -> list[str]:
    out = []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        m = USES.match(line)
        if not m:
            continue
        ref, comment = m["ref"], m["comment"]
        where = f"{path.relative_to(REPO)}:{n}"
        if ref.startswith("./"):
            continue
        if ref.startswith("docker://"):
            if "@sha256:" not in ref:
                out.append(f"{where}: {ref} is a docker image without a digest")
            continue
        if not PINNED.match(ref):
            out.append(f"{where}: {ref} is not pinned to a commit (`@<40 hex> # <ref>`)")
        elif not comment:
            out.append(f"{where}: {ref} has no `# <ref>` saying what it was pinned from")
    return out


def resolve(action: str, ref: str) -> str:
    owner_repo = "/".join(action.split("/")[:2])
    req = urllib.request.Request(
        f"https://api.github.com/repos/{owner_repo}/commits/{ref}",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "kern-actions-pinned"},
    )
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=20) as r:
        sha = json.load(r)["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError(f"{owner_repo}@{ref}: the API answered {sha!r}")
    return sha


def refresh(path: Path) -> int:
    lines = path.read_text().splitlines(keepends=True)
    cache: dict[tuple[str, str], str] = {}
    changed = 0
    for i, line in enumerate(lines):
        m = USES.match(line.rstrip("\n"))
        if not m or m["ref"].startswith(("./", "docker://")):
            continue
        action, _, current = m["ref"].partition("@")
        wanted = m["comment"] or current
        key = (action, wanted)
        if key not in cache:
            cache[key] = resolve(action, wanted)
        new = f"{m['lead']}{action}@{cache[key]} # {wanted}\n"
        if new != line:
            lines[i] = new
            changed += 1
    path.write_text("".join(lines))
    return changed


def main(argv: list[str]) -> int:
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    if "--refresh" in argv:
        total = 0
        for f in files:
            try:
                n = refresh(f)
            except (OSError, ValueError, KeyError) as e:
                print(f"actions-pinned: {f.name}: cannot refresh: {e}", file=sys.stderr)
                return 1
            total += n
            if n:
                print(f"  {f.relative_to(REPO)}: {n} pin(s) rewritten")
        print(f"actions-pinned: {total} pin(s) rewritten; read the diff before committing it")
    found = [p for f in files for p in problems(f)]
    for p in found:
        print(f"actions-pinned: {p}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
