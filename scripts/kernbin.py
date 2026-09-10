#!/usr/bin/env python3
"""Refuse to measure with a binary that is not this working tree.

WHY THIS IS SHARED AND NOT A CHECK IN ONE SCRIPT. `compose-compat-rate.py` defaults to
`target/release/kern` while every edit-and-check cycle in this repo builds `target/debug/kern`, so a
whole day's work can be followed by a rate that predates it and says so nowhere. It happened:
a run reported 38% clean from a binary six hours and 28 source files old, and the same corpus with
the binary rebuilt reported 34%. An audit then found SEVENTEEN scripts invoking a binary by a
default path and exactly one checking whether that binary was current.

A number that names no build is not a measurement, so the check belongs next to every script that
produces one.

THE CHECK IS THE BUILD'S OWN IDENTITY, NOT ITS DATE. `kern --version` prints `git describe`, so it
carries the commit it was built from and a `-dirty` flag: `kern v0.9.32-10-g6452ea8-dirty`.
Comparing that commit with `HEAD` catches the case a timestamp cannot, a binary built from a
DIFFERENT commit that happens to be newer than the sources. Measured while writing this: the
release binary said `ge479dff` while `HEAD` was `6452ea8`, one commit behind, with an mtime that
looked perfectly fresh.

The date is still consulted, but only where the hash cannot answer: a build from a dirty tree
identifies a commit and not the edits on top of it, so there the newest source file decides.

Both fall back to "cannot tell" rather than to "fine": no git, no `git describe` in the binary (a
source tarball answers `0.0.0`), or an unreadable version string report that they could not check,
and the caller decides. Silence would put us back where we started.
"""

import pathlib
import re
import subprocess


def _run(args, cwd=None):
    """Return stdout, or None if the command could not run or failed."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=30, cwd=cwd)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout.strip() if p.returncode == 0 else None


def _newer_sources(built_at, root):
    """Source files modified after `built_at`, which is what a stale build looks like by date."""
    out = []
    for sub in ("crates", "bindings"):
        d = root / sub
        if not d.is_dir():
            continue
        for p in d.rglob("*.rs"):
            try:
                if p.is_file() and p.stat().st_mtime > built_at:
                    out.append(p)
            except OSError:
                continue
    return out


def why_not_current(kern, root="."):
    """Why `kern` does not represent this working tree, or None when it does.

    The return value is a ready-to-print explanation ending in the command that fixes it, so every
    caller reports the same thing and none of them has to phrase it.
    """
    root = pathlib.Path(root)
    exe = pathlib.Path(kern)
    if not exe.exists():
        return f"{exe} does not exist.\nBuild it first: cargo build --release --bin kern"

    build = "--release" if "release" in exe.parts else ""
    rebuild = f"cargo build {build} --bin kern".replace("  ", " ")

    # 1. IDENTITY. `git describe` in the binary against HEAD in the tree.
    version = _run([str(exe), "--version"])
    head = _run(["git", "rev-parse", "HEAD"], cwd=str(root))
    built_from = None
    if version:
        m = re.search(r"-g([0-9a-f]{7,40})", version)
        if m:
            built_from = m.group(1)
    if built_from and head:
        if not head.startswith(built_from):
            return (
                f"{exe} was built from commit {built_from}, the tree is at {head[:len(built_from)]}"
                f" ({version}).\nRebuild before measuring: {rebuild}"
            )

    # 2. DATE, for what the hash cannot decide: a dirty build, or a binary with no describe in it.
    dirty_build = bool(version and version.endswith("-dirty"))
    if built_from is None or dirty_build:
        try:
            built_at = exe.stat().st_mtime
        except OSError as e:
            return f"cannot read {exe}: {e}"
        newer = _newer_sources(built_at, root)
        if newer:
            shown = ", ".join(str(p) for p in sorted(newer)[:3])
            more = ", …" if len(newer) > 3 else ""
            return (
                f"{exe} is older than {len(newer)} source file(s) ({shown}{more}).\n"
                f"Rebuild before measuring: {rebuild}"
            )
    return None


def require_current(kern, root="."):
    """Print why the binary is not current and return an exit status, or 0 when it is.

    Callers do `rc = require_current(args.kern); if rc: return rc`, so the refusal is one line and
    cannot be softened into a warning at a call site.
    """
    import sys

    why = why_not_current(kern, root)
    if why is None:
        return 0
    print(why, file=sys.stderr)
    return 2
