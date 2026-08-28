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
    # No STALE rule for the OCI-image cold start any more, and the reversal is the point. This file
    # used to pin it at 3.4 ms and flag 3.6 as the stale one. Re-measured 2026-08-22 on the same
    # machine, quiet, five batches of 100 with `$EPOCHREALTIME` around each batch: 3.62 ms, median of
    # medians, min 3.51 max 3.77 - and BENCHMARKS.md's own cold-start table had said 3.61 all along
    # while its working-day table said 3.4. The gate had picked the flattering half of a document
    # that disagreed with itself, and then enforced it across seven files. A blacklist cannot be
    # trusted to hold the right end of a drift, so this claim moves to `latency_claims_agree()`
    # below: an agreement check has no opinion about which value is true, only that one value is
    # written everywhere. Inverting the blacklist was tried first and rejected - "3.4 ms" is a TRUE
    # statement in this repo (WSL2, cap enforced, a different host), so the rule would have fired on
    # a correct line, which is how a gate gets switched off.
    # No STALE rule for the binary size. It was tried and removed: a bare "1.7 MB" also names the RSS
    # of three processes in BENCHMARKS.md, and "1.81 MB" is the recorded measurement of an earlier
    # release in the binary-size entry of OPEN_ITEMS.md. Both are correct where they stand, so the
    # rule fired on true statements. A gate with false positives is switched off, which is worse
    # than no gate.
    # The size is not unchecked, though: `size_claims_agree()` below compares the claim in the two
    # files that PRODUCE the front page (the demo SVG and the GIF's generator, neither of them a `.md`
    # and so invisible to the scan above) against the README's headline. An agreement check cannot
    # fire on a true statement, which is exactly why the size gets one and not a blacklist.
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
    # The gap in the third alternative forbids DIGITS, not just newlines. With `[^\n]{0,24}` it was
    # greedy enough to eat into the number itself: "binary is 1.58 MB" captured `8`, and the gate would
    # then have reported a disagreement against a file that agreed. A rule that invents a mismatch is
    # the same failure as one that misses a real one, so the gap may not cross a digit.
    claim = re.compile(
        r'BINARY_SIZE\s*=\s*"~?([\d.]+)\s*MB"'
        r'|~?([\d.]+)\s*MB(?=[^\n]{0,24}\bbinary\b)'
        r'|\bbinary\b[^\d\n]{0,24}([\d.]+)\s*MB'
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


def _rust_string_literal_after(src: str, marker: str) -> str:
    """The first Rust string literal after `marker`, with `\\`-newline continuations joined.

    Written rather than reached for with a regex because the strings this reads are wrapped across
    source lines with a trailing backslash, and a regex that tried to handle that would either miss
    the continuation or eat the closing quote. Twenty lines of state machine has one behaviour.
    """
    i = src.find(marker)
    if i < 0:
        return ""
    j = src.find('"', i)
    if j < 0:
        return ""
    # Two Rust literal forms this cannot read: a raw string (`r#"..."#`, whose opening quote is
    # preceded by `r#`) and any numeric escape (`\x41`, `\u{41}`), which it would emit as the letter
    # `x` or `u` instead of the character. Both would make the gate compare a value that is not the
    # one the code prints, and a gate that silently reads the wrong string is worse than no gate.
    # Return a sentinel nobody can match so the caller reports a failure and a human looks. Raised in
    # review on 2026-08-28; neither form appears in the claims today.
    if src[max(0, j - 2):j].endswith(("r", "r#")):
        return "<gate cannot read a raw string literal>"
    out: list[str] = []
    k = j + 1
    while k < len(src):
        c = src[k]
        if c == "\\":
            nxt = src[k + 1] if k + 1 < len(src) else ""
            if nxt == "\n":
                k += 2
                while k < len(src) and src[k] in " \t":
                    k += 1
                continue
            if nxt in "xu":
                return "<gate cannot read a numeric escape in this literal>"
            out.append(nxt)
            k += 2
            continue
        if c == '"':
            break
        out.append(c)
        k += 1
    return "".join(out)


def gpu_claims_agree() -> list[str]:
    """What the docs say about a GPU tier must be what `crates/kern-cli/src/gpu.rs` emits.

    The GPU line is a CLAIM about a security boundary, which makes it the most expensive sentence in
    the tree to get wrong: overstate it once and every other honest statement here stops being
    believed. It also has the shape that has failed before, several homes for one fact, and one of
    those homes is source code rather than prose, so `no-ai-slop.py` and the blacklist above cannot
    see the drift between them.

    Three agreements, none of which can fire on a true statement:

      1. Every ``TIER-`` label written in a document must be one the code can actually print. The
         model has a middle tier, ``TIER-MED``, that no code path can reach, because the measurement
         that would earn it failed; a document that starts offering it would be describing a verdict
         kern cannot award. That is the drift this catches.

      2. The cooperative tier's disclaimer, verbatim from ``Tier::claim()``, must appear in the two
         pages that carry the claim to a reader. Reword it in the code and the gate names the pages
         that still say the old thing.

      3. The reserved vocabulary must be identical in the Rust gate and in the shell one.
         ``pentest/pentest-gpu-claims.sh`` cannot import a Rust constant, so it keeps its own copy,
         and a duplicated derived condition with no gate on it is exactly how the two quietly stop
         meaning the same thing. This is that gate.

    WHAT THIS DOES NOT CATCH, stated because a gate mistaken for more than it is does more harm than
    no gate at all. It checks that required text is PRESENT and that forbidden words are ABSENT. It
    cannot see a sentence ADDED elsewhere on the same page that gives back what the caveat took
    away. A reviewer produced this counterexample on 2026-08-28, and it passes every check here:

        "On any host that shows TIER-HW, operators may rely on device memory limits for
         hostile multi-tenant packing without further controls."

    No reserved word, no invented tier, both caveats still present two paragraphs above, and a reader
    walks away with a guarantee kern never made. Detecting that is reading for contradiction, not
    pattern matching, and a regex aimed at it would fire on the sentences that discuss hostile
    multi-tenant use on purpose. This file records elsewhere what happens to a gate with false
    positives. So the defence against added prose is review, and this gate's job is the narrower one
    it can actually do: keeping the code and the documents from drifting apart.
    """
    try:
        src = open("crates/kern-cli/src/gpu.rs", encoding="utf-8").read()
    except OSError:
        return []  # a checkout without the GPU module is not a disagreement

    bad: list[str] = []

    labels = set(re.findall(r'Tier::\w+\s*=>\s*"(TIER-[A-Z]+)"', src))
    if not labels:
        return ["crates/kern-cli/src/gpu.rs no longer emits any TIER- label, so nothing can be "
                "checked against it. Restore Tier::label() or drop this check."]

    docs = subprocess.run(
        ["git", "ls-files", "*.md"], capture_output=True, text=True
    ).stdout.split()
    for path in sorted(docs):
        if os.path.basename(path) in ALWAYS_ALLOWED:
            continue  # a changelog that recorded a tier kern used to print stays true
        try:
            text = open(path, encoding="utf-8").read()
        except OSError:
            continue
        for lineno, line in enumerate(text.split("\n"), 1):
            for said in re.findall(r"\bTIER-[A-Z]+\b", line):
                if said not in labels:
                    bad.append(
                        f"{path}:{lineno} names {said}, which kern cannot print. "
                        f"The tiers the code emits are {', '.join(sorted(labels))}"
                    )

    # Both tiers carry a caveat that a later edit could smooth away, and the two caveats fail in
    # opposite directions: dropping the cooperative one understates the danger, dropping the hardware
    # one overstates the guarantee. The second is the one that actually happened. `Tier::Hw` claimed
    # "per-tenant VRAM enforced by the device" from evidence that is purely topological, which an
    # outside reader caught on 2026-08-28; it is pinned here so the narrower wording cannot drift
    # back without failing the build.
    # WHY THESE TWO SENTENCES ARE PINNED, because a gate that says only "restore this string" leaves a
    # successor with the lock and not the reason. Each marker is an ADMISSION OF A LIMIT, and each
    # tier's admission fails in the opposite direction from the other's:
    #
    #   Tier::Soft's "NOT a boundary against malicious code" is the whole reason a cooperative quota
    #   is safe to describe at all. Lose it and the remaining text reads as a capability.
    #
    #   Tier::Hw's "has not measured the VRAM split" is there because that branch has no positive
    #   control anywhere in the tree: kern has never run on MIG or SR-IOV hardware, so nothing can
    #   demonstrate the promotion is right. Lose it and kern asserts an enforcement nobody checked.
    #
    # Editing either is editing what kern admits it does not know. That is allowed, and it is not
    # allowed to happen by accident while rewording a paragraph, which is what this gate is for.
    for arm, marker, page_required in (
        ("Tier::Soft => {", "NOT a boundary against malicious code", True),
        ("Tier::Hw => {", "has not measured the VRAM split", True),
    ):
        claim = _rust_string_literal_after(src, arm)
        if marker not in claim:
            bad.append(
                f"crates/kern-cli/src/gpu.rs: the claim for {arm.split(' ')[0]} no longer contains "
                f"{marker!r}. If that is deliberate, update this gate and both pages with it."
            )
            continue
        if not page_required:
            continue
        for path in ("README.md", "SECURITY.md"):
            try:
                text = open(path, encoding="utf-8").read()
            except OSError:
                continue
            # The README states only the cooperative half, which is the half a reader meets first;
            # SECURITY.md is the page that owns both, so only it is held to the hardware caveat.
            if marker == "has not measured the VRAM split" and path == "README.md":
                continue
            if marker.lower() not in text.lower():
                bad.append(
                    f"{path} carries the GPU claim to a reader and no longer states "
                    f"{marker!r}, which is what the code prints"
                )

    # A page does not have to be README or SECURITY to make the hardware claim. Any document that
    # writes TIER-HW next to a form of "enforce" is asserting the thing the caveat qualifies, and has
    # to carry the caveat too. Anchored on "enforc" rather than on the tier name alone so a file that
    # merely NAMES the tier (pentest/README.md describes the gate's threshold) is not dragged in: a
    # rule that fires on a true statement is a rule that gets switched off.
    hw_caveat = "has not measured the VRAM split"
    for path in sorted(docs):
        if os.path.basename(path) in ALWAYS_ALLOWED:
            continue
        try:
            text = open(path, encoding="utf-8").read()
        except OSError:
            continue
        # A WINDOW, not a line. Markdown prose wraps, and the first version of this rule anchored on
        # a single line: in ROADMAP.md "TIER-HW" ends one line and "enforced by the device" begins
        # the next, so the rule saw nothing and passed a sabotaged file. A gate that a line break
        # switches off is not a gate. 220 characters is about two wrapped lines.
        # BOTH ORDERS, and a hole for prose that is TALKING ABOUT the rule rather than making a
        # claim. "TIER-HW ... enforce" was one-directional, so "enforcement ... below TIER-HW" was a
        # false negative; and a document describing the gate itself ("A2 refuses isolation/secure/hard
        # on every row below TIER-HW so that cooperative wording cannot claim enforcement") is correct
        # prose that the rule would have failed. Both raised in review on 2026-08-28. A gate with
        # false positives gets switched off, which this file records happening twice already, so the
        # meta case is exempted by the words that only appear when describing the mechanism.
        window = r"(?:TIER-HW.{0,220}?enforc|enforc.{0,220}?TIER-HW)"
        claim = None
        for m in re.finditer(window, text, re.IGNORECASE | re.DOTALL):
            around = text[max(0, m.start() - 160):m.end() + 160].lower()
            if any(w in around for w in ("refuse", "gate", "matcher", "vocabulary", "row below")):
                continue  # describing the rule, not making the claim
            claim = m
            break
        if claim and hw_caveat.lower() not in text.lower():
            n = text.count("\n", 0, claim.start()) + 1
            bad.append(
                f"{path}:{n} says TIER-HW enforces something and the file never states "
                f"{hw_caveat!r}: {' '.join(claim.group(0).split())[:90]}"
            )

    m = re.search(r"BOUNDARY_WORDS:\s*\[&str;\s*\d+\]\s*=\s*\[([^\]]*)\]", src)
    rust_words = re.findall(r'"([^"]+)"', m.group(1)) if m else []
    try:
        suite = open("pentest/pentest-gpu-claims.sh", encoding="utf-8").read()
    except OSError:
        suite = ""
    if suite:
        s = re.search(r"BOUNDARY_WORDS='([^']*)'", suite)
        shell_words = s.group(1).split("|") if s else []
        if sorted(rust_words) != sorted(shell_words):
            bad.append(
                "the reserved GPU vocabulary differs between the two gates that enforce it: "
                f"gpu.rs has {sorted(rust_words)}, pentest-gpu-claims.sh has {sorted(shell_words)}"
            )

    return bad


def latency_claims_agree() -> list[str]:
    """The OCI-image cold start claimed anywhere must equal the one the README states.

    The twin of [`size_claims_agree`], for the same reason and after the same failure: on 2026-08-22
    that figure read 3.4 ms in the README headline, the GIF generator, both binding READMEs, the FAQ
    and the launch post, 3.5 in the README's own comparison table, and 3.61 in BENCHMARKS.md's
    cold-start table - one measurement with seven homes and three values. Re-measured the same day it
    is 3.62 ms, so the 3.4 that six of those files carried was the flattering end of the drift.

    An agreement check rather than a blacklist, because there is exactly one right answer and the
    README holds it: this cannot fire on a true statement, and it does not need to be re-taught when
    the number is measured again - only the README has to be edited, and every other claimant is then
    checked against it.
    """
    readme = re.search(
        r"kernel-enforced container in\s+~?([\d.]+)\s*ms", open("README.md", encoding="utf-8").read()
    )
    if not readme:
        return ["README.md no longer states the image cold start in its headline, so nothing can be "
                "checked against it. Restore the claim or drop this check."]
    canonical = readme.group(1)
    claim = re.compile(
        r'KERN_MS\s*=\s*"~?([\d.]+)\s*ms"'
        r'|from an OCI image in ~?([\d.]+)\s*ms'
        r'|starts in \*\*~?([\d.]+)\s*ms\*\* from an OCI image'
        r'|~?([\d.]+)\s*ms with `--image`'
    )
    bad = []
    for path in (
        "assets/make-demo-gif.py",
        "docs/FAQ.md",
        "bindings/python/README.md",
        "bindings/node/README.md",
        "blog/introducing-kern.md",
    ):
        try:
            text = open(path, encoding="utf-8").read()
        except OSError:
            continue  # a claimant that no longer exists is not a disagreement
        for lineno, line in enumerate(text.split("\n"), 1):
            for m in claim.finditer(line):
                said = next(g for g in m.groups() if g)
                if said != canonical:
                    bad.append(
                        f"{path}:{lineno} claims a {said} ms image cold start, "
                        f"README.md says {canonical} ms"
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
    for problem in latency_claims_agree():
        total += 1
        print(f"\n{problem}")
        print("       one measurement, several homes: the headline is canonical and every other "
              "claimant is checked against it. Edit README.md first, then the others; if the GIF "
              "generator moved, re-run it: python3 assets/make-demo-gif.py")
    for problem in size_claims_agree():
        total += 1
        print(f"\n{problem}")
        print("       the front page states the size in an asset as well as in prose, and this "
              "gate reads only .md, so the asset drifts silently. Edit the generator, then "
              "re-run it: python3 assets/make-demo-gif.py")
    for problem in gpu_claims_agree():
        total += 1
        print(f"\n{problem}")
        print("       the GPU tier is a claim about a security boundary, and the code that prints "
              "it is canonical. Edit crates/kern-cli/src/gpu.rs first, then the pages that quote "
              "it; the shell gate in pentest/pentest-gpu-claims.sh keeps its own copy of the "
              "reserved vocabulary and has to move with it.")
    n = len(files)
    print(f"\n{total} stale figure{'' if total == 1 else 's'} in {n} file{'' if n == 1 else 's'}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
