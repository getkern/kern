#!/usr/bin/env python3
"""Refuse a measured number that was corrected in one document and left standing in another.

WHY THIS EXISTS
    Three times in two days, a figure was re-measured, updated where it was most visible, and left
    stale everywhere else:

      * the OCI-image cold start read 3.4 ms in the README table and 3.6 ms in the sentence in
        BENCHMARKS.md that points AT that table, plus both binding READMEs and the launch post;
      * SECURITY.md said "33 syscalls denied: 24 that hard-kill plus the 9 that return ENOSYS" and,
        two paragraphs later, "ENOSYS moves five syscalls", so the page offered 5 + 24 = 29 against
        its own 33, and an outside audit repeated the smaller number;
      * Docker's resident memory was re-measured at 154 to 160 MB and corrected in the README and
        BENCHMARKS.md, while ~186 MB survived in four places in EDGE.md, in examples/README.md and
        in the blog post. That one is the worst shape: a stale number that flatters us, on the page
        that carries the edge argument.

    None of these was a lie and none was caught by review, because a human reading one document
    cannot see the other. They are all the same defect: a fact with more than one home. This is the
    mechanical check for it, in the same spirit as the em-dash rule and scripts/no-ai-slop.py.

WHAT IT DOES
    Each entry below names a value that has been superseded by a measurement, and the value that
    replaced it. If the old one turns up in a tracked .md outside its allow-list, this fails.

    An allow-list is not a loophole: a document is allowed to state the old value when it is
    explicitly recounting the history (BENCHMARKS.md explains that Docker's footprint used to read
    ~186 MB and why it moved), and CHANGELOG.md is exempt everywhere, since a changelog whose old
    entries were rewritten would be worthless.

WHEN YOU RE-MEASURE SOMETHING
    Add the value you are replacing here, with the date and where the new one came from. That is the
    whole maintenance cost, and it is what makes the next correction complete instead of partial.

Usage:  python3 scripts/stale-numbers.py [files...]      (defaults to every tracked .md)
Exit:   0 clean, 1 if anything was flagged.
"""

from __future__ import annotations

import glob
import os
import re
import subprocess
import sys

# (regex for the superseded value, what it is now, why it changed, files allowed to still say it)
STALE: list[tuple[str, str, str, set[str]]] = [
    (
        r"~?\s*186\s*MB",
        "154 to 160 MB",
        "Docker resident memory, re-measured 2026-08-01: 154 idle, 160 after a working afternoon. "
        "It moves with the Docker version and with what the daemon has done, so it is a range.",
        {"BENCHMARKS.md"},  # explains the history of this very number
    ),
    (
        # Anchored on the CLAIM, not on the digits. An unanchored `3.6 ms` fired on "about 3.6 ms
        # per network round trip", a measurement of pasta that has nothing to do with a cold start,
        # and a gate that cries wolf is a gate that gets switched off. The figure only matters when
        # it is next to the thing it measures, so the pattern requires one of those words on the
        # same line.
        # `\s*` and not a literal space: the launch post writes `3.6ms`, and the first version of
        # this rule required `3.6 ms`, so the gate stayed silent on the one document it mattered
        # most for. Same for every other rule here. A gate that only matches the spelling you
        # happened to use when you wrote it is a gate for that document alone.
        r"\b3\.6\s*ms\b(?=[^\n]{0,80}(?:cold|start|box))"
        r"|(?:cold|start|box)[^\n]{0,80}\b3\.6\s*ms\b",
        "3.4 ms",
        "cold start from an OCI image; the README table and BENCHMARKS.md both measure 3.4.",
        set(),
    ),
    # No rule for the binary size. It was tried and removed: a bare "1.7 MB" also names the RSS of
    # three processes in BENCHMARKS.md, and "1.81 MB" is the recorded measurement of an earlier
    # release in the binary-size entry of OPEN_ITEMS.md. Both are correct where they stand, so the
    # rule fired on true statements. A gate with false positives is switched off, which is worse
    # than no gate: the size is checked instead against the release asset at publish time, where
    # there is exactly one right answer.
    (
        r"\bENOSYS[^.\n]{0,80}\bfive\b|\bfive [a-z]* ?syscalls? [^.\n]{0,40}ENOSYS",
        "nine",
        "nine syscalls return ENOSYS, in five FAMILIES (io_uring, userfaultfd, perf_event_open, "
        "the keyring, syslog). Counting families as calls made 5 + 24 = 29 against a stated 33. "
        "Pinned from the code by the_syscall_counts_in_the_docs_match_the_filter.",
        set(),
    ),
    (
        # The README quoted a single multiplier against the engines and pointed the reader at
        # BENCHMARKS.md for the method, where the same ratio read ~120x: BENCHMARKS measures kern
        # CAPPED (2.45 ms), the README's table measures it uncapped (2.2). Neither was wrong and the
        # two disagreed on the launch page. The README now states the range its own table produces.
        r"\b~?132\s*x\b",
        "128 to 134x",
        "kern vs the engines on the README's own table: 281.5 / 2.2 = 128, 294.4 / 2.2 = 134. "
        "BENCHMARKS.md's ~120x is the CAPPED comparison and says so. Re-measured on the shipping "
        "binary 2026-08-03 the same script gave 123 to 128x, the whole table having drifted ~5% "
        "that day with bubblewrap and docker too; the README records both rather than averaging.",
        set(),
    ),
    (
        # Introduced by the very commit that was leaning the README for the launch: the sentence said
        # bubblewrap was "0.8 ms ahead" while the table two lines above it read kern 2.2 and
        # bubblewrap 3.0, so it handed a competitor a win it does not have on that machine, and an
        # outside review repeated it back within the day. BENCHMARKS.md and EDGE.md are exempt,
        # because on the ARM boards' DEFAULT path bubblewrap IS ahead and they say so with numbers.
        r"bubblewrap is [0-9.]+\s*ms ahead",
        "0.8 ms behind, on the README's own table",
        "kern 2.2 ms against bubblewrap 3.0 on the x86 table, and ahead at the same level of work on "
        "every host where both are installed. bubblewrap leads only on the boards' default path, "
        "where kern enforces a cgroup cap and bubblewrap enforces none.",
        {"BENCHMARKS.md", "EDGE.md"},
    ),
    (
        # One number, two homes: BENCHMARKS.md measured 1000 boxes in 0.61 s and stated 1640 box/s in
        # the same row (1000/0.61 = 1639), while the README said 0.65, which would be 1538.
        r"\b0\.65\s*s\b(?=[^\n]{0,60}(?:thousand|1000))"
        r"|(?:thousand|1000)[^\n]{0,60}\b0\.65\s*s\b",
        "0.61 s",
        "a thousand boxes in parallel; BENCHMARKS.md's table measures 0.61 s and its own rate column "
        "agrees.",
        set(),
    ),
    (
        r"\b344\s*ms\b",
        "285 to 294 ms",
        "docker run for the same task; 344 overstated the gap in kern's favour.",
        set(),
    ),
]

ALWAYS_ALLOWED = {"CHANGELOG.md"}

COMPILED = [(re.compile(p, re.IGNORECASE), now, why, ok) for p, now, why, ok in STALE]

# A version number in prose is only stale when the sentence around it claims to describe the CURRENT
# state. "kern 0.6.30, 2026-08-01" is a dated record and stays true forever; "the current release,
# 0.6.32" and "## Current status (0.6.30, honest)" go wrong the instant the next tag is pushed, and
# both of those were live in the tree on the morning of the launch, three releases out of date. So
# this is anchored on the CLAIM, like the 3.6 ms rule above, and it reads the truth from Cargo.toml
# rather than from a constant here that would itself need updating at every release.
CURRENT_CLAIM = re.compile(
    r"current\s+(?:release|version|status)[^\n]{0,30}?(\d+\.\d+\.\d+)"
    r"|(\d+\.\d+\.\d+)\s+is\s+(?:the\s+)?current",
    re.IGNORECASE,
)


def workspace_version() -> str:
    """The one true version, read from Cargo.toml. Empty string disables the check."""
    try:
        with open("Cargo.toml", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r'\s*version\s*=\s*"([^"]+)"', line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return ""


VERSION = workspace_version()


def excluded_manifests_agree() -> list[str]:
    """Manifests that ship in the release but cannot inherit the workspace version.

    `windows/kern-win` is cross-compiled by release.yml and published as `kern-windows-x86_64.exe`,
    so it ships with every release, and it sat at 0.6.7 while the workspace had moved 28 minors past
    it: that much drift on an artifact users download. Nothing surfaces that number to a user, which
    is precisely why nobody noticed. `fuzz` is exempt on purpose: 0.0.0 says "never published".

    The in-workspace path dependencies restate a version they cannot inherit either. It is only a
    requirement (`0.6.7` means `^0.6.7`, which every later 0.6.x satisfies, which is why nothing ever
    complained), but it is what a `cargo publish` would carry, and it sat 28 releases behind too.
    """
    bad = []
    try:
        with open("windows/kern-win/Cargo.toml", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r'\s*version\s*=\s*"([^"]+)"', line)
                if m:
                    if VERSION and m.group(1) != VERSION:
                        bad.append(
                            f"windows/kern-win/Cargo.toml is {m.group(1)}, "
                            f"the workspace is {VERSION}"
                        )
                    break
    except OSError:
        pass  # a checkout without the Windows tree is not a failure
    try:
        with open("crates/kern-cli/Cargo.toml", encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                m = re.search(r'path = "\.\./(kern-[a-z]+)", version = "([^"]+)"', line)
                if m and VERSION and m.group(2) != VERSION:
                    bad.append(
                        f"crates/kern-cli/Cargo.toml:{i} requires {m.group(1)} "
                        f"{m.group(2)}, the workspace is {VERSION}"
                    )
    except OSError:
        pass
    return bad


def provenance_counts_agree() -> list[str]:
    """The CHANGELOG counts the signed tags and the timestamp proofs. Both are countable.

    "All 27 are signed and timestamped to Bitcoin" was wrong on 2026-08-04: 27 tags were signed but
    only 26 had an OpenTimestamps proof, because v0.6.8 predates the practice. It read as a blanket
    guarantee, which is the one kind of claim a reader cannot check cheaply and therefore takes on
    trust. Both halves are counted from the repository here.

    SKIPS, rather than fails, on a checkout with no tags: `actions/checkout` fetches none by default,
    and a gate that fails on a shallow clone teaches people to ignore it.
    """
    try:
        out = subprocess.run(
            ["git", "tag"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return []
    # The section counts the EARLIER releases, so the tag and proof for the version documented at
    # the top of the file are excluded. Without that the number would be wrong twice per release:
    # once between the commit and the tag, and again between the tag and the OpenTimestamps stamp.
    here = f"v{VERSION}" if VERSION else None
    tags = [t for t in out.stdout.split() if t.startswith("v") and t != here]
    if out.returncode != 0 or len(tags) < 2:
        return []  # no tags here: nothing to compare against

    proofs = [
        p for p in glob.glob("provenance/*.provenance.txt.ots")
        if not (here and os.path.basename(p).startswith(f"{here}."))
    ]
    try:
        text = open("CHANGELOG.md", encoding="utf-8").read()
    except OSError:
        return []

    bad = []
    m = re.search(r"All (\d+) are signed", text)
    if m and int(m.group(1)) != len(tags):
        bad.append(
            f"CHANGELOG.md says {m.group(1)} signed tags, `git tag` lists {len(tags)}"
        )
    m = re.search(r"(\d+) of them carry an\s+OpenTimestamps proof", text)
    if m and int(m.group(1)) != len(proofs):
        bad.append(
            f"CHANGELOG.md says {m.group(1)} OpenTimestamps proofs, provenance/ holds {len(proofs)}"
        )

    # Having a proof and being IN a Bitcoin block are two different states, and the page claimed the
    # stronger one for both: 27 proofs existed, 26 were confirmed, and a freshly stamped proof waits
    # hours for a calendar to reach a block plus six confirmations. Counted from the bytes rather
    # than from `ots`, which is not installed on the CI runner and would make this check vanish
    # exactly where it is unattended. This 8-byte tag is the Bitcoin block-header attestation; it
    # agrees with `ots info` on every file in provenance/, checked when this was written.
    confirmed = sum(
        1 for p in proofs if bytes.fromhex("0588960d73d71901") in open(p, "rb").read()
    )
    m = re.search(r"of which (\d+) are confirmed in a Bitcoin block", text)
    if m and int(m.group(1)) != confirmed:
        bad.append(
            f"CHANGELOG.md says {m.group(1)} proofs are confirmed in a Bitcoin block, "
            f"{confirmed} of the {len(proofs)} carry the attestation"
        )
    return bad


def size_claims_agree() -> list[str]:
    """The binary size claimed OUTSIDE the .md set must equal the one the README states.

    This gate defaults to tracked `.md`, so a number baked into an asset is invisible to it, and on
    2026-08-20 that is exactly what happened: the front-page GIF said 1.84 MB and the demo SVG said
    ~1.8 MB while the README three lines away said 1.58. Nobody lied; the generator's constant simply
    had no gate on it. The GIF is pixels, but the three files that PRODUCE the claim are text.

    Deliberately an AGREEMENT check, not a STALE rule: the note above records that a blacklist on the
    size fired on true statements (a bare "1.7 MB" is also an RSS in BENCHMARKS.md) and a gate with
    false positives gets switched off. Comparing a claim against the canonical one cannot cry wolf,
    because there is exactly one right answer and the README holds it.
    """
    readme = re.search(
        r"out of one\s+([\d.]+)\s*MB binary", open("README.md", encoding="utf-8").read()
    )
    if not readme:
        return ["README.md no longer states the binary size in its headline, so nothing can be "
                "checked against it. Restore the claim or drop this check."]
    canonical = readme.group(1)
    # Only a size sitting NEXT TO the word it measures counts, so the generator's own history note
    # ("the GIF kept claiming ~2 ms and 1.6 MB") is not a claim about today's binary and is skipped.
    claim = re.compile(
        r'BINARY_SIZE\s*=\s*"~?([\d.]+)\s*MB"'
        r'|~?([\d.]+)\s*MB(?=[^\n]{0,24}\bbinary\b)'
        r'|\bbinary\b[^\n]{0,24}~?([\d.]+)\s*MB'
    )
    bad = []
    for path in ("assets/demo.svg", "assets/make-demo-gif.py"):
        try:
            text = open(path, encoding="utf-8").read()
        except OSError:
            continue  # a claimant that no longer exists is not a disagreement
        for lineno, line in enumerate(text.split("\n"), 1):
            for m in claim.finditer(line):
                said = next(g for g in m.groups() if g)
                if said != canonical:
                    bad.append(
                        f"{path}:{lineno} claims a {said} MB binary, README.md says {canonical} MB"
                    )
    return bad


def scan(path: str) -> list[tuple[int, str, str, str, str]]:
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as e:
        print(f"{path}: cannot read: {e}", file=sys.stderr)
        return []
    hits = []
    fence = False
    for lineno, line in enumerate(text.split("\n"), 1):
        if re.match(r"^\s*(```|~~~)", line):
            fence = not fence
            continue
        if fence:
            continue  # a pasted transcript is someone else's output, not our claim
        for rx, now, why, allowed in COMPILED:
            if path in allowed or path in ALWAYS_ALLOWED:
                continue
            m = rx.search(line)
            if m:
                hits.append((lineno, m.group(0).strip(), now, why, line.strip()[:96]))
        if VERSION and path not in ALWAYS_ALLOWED:
            m = CURRENT_CLAIM.search(line)
            if m and (m.group(1) or m.group(2)) != VERSION:
                hits.append(
                    (
                        lineno,
                        m.group(0).strip(),
                        VERSION,
                        "this sentence claims to describe the current release. Either name the "
                        "version Cargo.toml carries, or drop the word 'current' and let it stand "
                        "as the dated record it is.",
                        line.strip()[:96],
                    )
                )
    return hits


def main(argv: list[str]) -> int:
    files = argv[1:]
    if not files:
        files = subprocess.run(
            ["git", "ls-files", "*.md"], capture_output=True, text=True
        ).stdout.split()
    total = 0
    for f in sorted(files):
        hits = scan(f)
        if not hits:
            continue
        total += len(hits)
        print(f"\n{f}")
        for lineno, hit, now, why, ctx in hits:
            print(f"  {lineno:>5}  {hit!r} was superseded by {now}")
            print(f"         {why}")
            print(f"         {ctx}")
    for problem in excluded_manifests_agree():
        total += 1
        print(f"\n{problem}")
        print("       an excluded workspace or a path dependency ships in the release but cannot "
              "inherit the version, so it has to be bumped by hand. This is that hand.")
    for problem in provenance_counts_agree():
        total += 1
        print(f"\n{problem}")
        print("       the signed-tag and timestamp counts are a trust claim, and both are "
              "countable from this repository. Count them.")
    for problem in size_claims_agree():
        total += 1
        print(f"\n{problem}")
        print("       the front page states the size in an asset as well as in prose, and this "
              "gate reads only .md, so the asset drifts silently. Edit the generator, then "
              "re-run it: python3 assets/make-demo-gif.py")
    n = len(files)
    print(f"\n{total} stale figure{'' if total == 1 else 's'} in {n} file{'' if n == 1 else 's'}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
