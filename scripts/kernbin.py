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

The date is still consulted for what the hash cannot answer, which is the edits on top of that
commit: a build from a dirty tree, AND a clean build in a tree that has been edited since. There
the newest MODIFIED source decides.
Modified is git's answer, not the filesystem's: a file whose content equals HEAD's cannot differ
from what a build of HEAD contains, however recent its timestamp, and timestamps move for reasons
that are not edits (`gates-selftest.py` mutates a real source to prove a gate can go red and then
restores it byte-for-byte; `cargo fmt` rewrites a file that is already formatted).

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


def _dirty_sources(root):
    """The source files git reports as MODIFIED, or None when git cannot answer.

    WHY THE DATE CHECK IS RESTRICTED TO THESE. A file whose content equals HEAD's cannot differ from
    what a build of HEAD contains, whatever its timestamp says, and timestamps move for reasons that
    are not edits: `gates-selftest.py` injects a defect into a REAL source to prove each gate can go
    red and then restores it byte-for-byte, and `cargo fmt` rewrites a file that is already
    formatted. Both leave an mtime newer than the binary and a file identical to what was built.

    Without this, every `gates-selftest` run left the corpus gate and the rate refusing to measure
    until a rebuild that had nothing to rebuild.
    """
    # `-z`, read directly and NOT through `_run`. `_run` strips its output, and porcelain's first
    # line for a file modified in the worktree starts with a SPACE (` M path`): stripped, `line[3:]`
    # cut the path's first letter. MEASURED: one edited `crates/kern-cli/src/commands/mod.rs` came
    # back as `rates/kern-cli/...`, which does not exist, so `_newer_sources` dropped it in silence
    # and the date check never saw the first modified file - which is usually the only one. `-z`
    # also leaves paths unquoted, and gives a rename's ORIGINAL path as a separate entry.
    try:
        p = subprocess.run(["git", "status", "--porcelain", "-z", "--", "*.rs"],
                           capture_output=True, text=True, timeout=30, cwd=str(root))
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    files = []
    entries = p.stdout.split("\0")
    i = 0
    while i < len(entries):
        entry = entries[i]
        i += 1
        if len(entry) < 4:
            continue
        status, path = entry[:2], entry[3:]
        if status[0] in "RC":
            i += 1  # the next entry is where it came FROM, which no longer holds this content
        if path.endswith(".rs"):
            files.append(root / path)
    return files


def _newer_sources(built_at, root):
    """Source files that are BOTH modified and newer than the build, which is what stale means."""
    dirty = _dirty_sources(root)
    if dirty is None:
        # No git: fall back to every source, since nothing else can say which ones changed.
        dirty = []
        for sub in ("crates", "bindings"):
            d = root / sub
            if d.is_dir():
                dirty.extend(d.rglob("*.rs"))
    out = []
    for p in dirty:
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

    # 2. DATE, for what the hash cannot decide, and that is not only a `-dirty` build. It was gated
    # on the BINARY being dirty or carrying no describe, which missed the TREE becoming dirty after a
    # clean build: MEASURED, a debug binary built at a clean HEAD (`-geba5878`, no `-dirty`) was
    # still accepted after a `.rs` file was edited and not rebuilt, so a gate graded the old code.
    # The hash names the commit; only the modified sources say what has changed on top of it. On a
    # clean tree there are none, and this is one `git status`.
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


def pick(root="."):
    """The binary a GATE should run: the first of release and debug that exists AND represents this
    working tree.

    Returns `(binary, reasons_the_others_were_rejected)`. `(None, [])` means nobody has built, which
    is a skip and not a failure: a checkout that has not built a binary should not report a red gate
    for a missing artefact. `(None, [why, ...])` means a binary exists and is NOT this tree, which is
    a failure - a green from a binary that predates the change decides nothing.

    IT USED TO PREFER RELEASE, in two gates, and that is how two defects arrived. `compose-corpus`
    kept grading a release binary from before the change, because every edit-and-check cycle here
    builds debug: caught with the release binary a whole commit behind `HEAD` and an mtime that
    looked fresh. `dockerfiles` took ONLY release, so on a CI runner, which builds debug for its tests,
    it skipped and exited 0, and `gates-selftest` there reported it "stayed GREEN" on both of its
    injected violations. Debug and release run the same parser; what matters is the tree.
    """
    import os

    root = pathlib.Path(root)
    stale = []
    for rel in ("target/release/kern", "target/debug/kern"):
        p = root / rel
        if not (p.is_file() and os.access(p, os.X_OK)):
            continue
        why = why_not_current(str(p), root)
        if why is None:
            return p, stale
        stale.append(why)
    return None, stale
