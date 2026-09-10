#!/usr/bin/env python3
"""Measure how many compose files kern runs with NO behavioural difference from Docker.

WHY THIS IS A SCRIPT AND NOT A SHELL LOOP SOMEBODY RAN ONCE. The rate has been quoted at 14%, 66%,
93% and 94% during this work, each from an ad-hoc loop that is now gone, so none of them can be
recomputed or argued with. The number is only worth as much as the table below, and the table has to
be readable by someone who wants to disagree with a line of it.

THE MEASUREMENT IS KERN'S OWN WARNINGS, WHICH MAKES IT BLIND BY CONSTRUCTION to any difference kern
does not know it has. That is not a flaw to be worked around, it is the property to keep in view:
the rate can only ever be an upper bound, and it goes DOWN when kern learns about a difference it
was silent on. Measured instance: files carrying `ipv4_address` produced no output at all and scored
as perfect while the literal address is unreachable, which cost two points once it was noticed.

Usage:  compose-compat-rate.py <corpus-dir> [--kern PATH] [--verbose]
"""

import argparse
import pathlib
import re
import subprocess
import sys
from collections import Counter

# A warning that is NOT a behavioural difference from Docker. Every entry states WHY, because the
# whole risk of this table is an inconvenient line being quietly moved into it.
BENIGN = [
    # Docker substitutes an unset variable with the empty string too. Saying so is a courtesy.
    (r"is not set \(no default\) - substituted empty", "Docker substitutes empty as well"),
    (r"empty list item", "the file has a hole in it; kern reports, Docker ignores"),
    # `docker compose up -d` also leaves stdin at EOF: `tty:`/`stdin_open:` describe an attached run.
    (r"a compose service runs detached", "identical under `docker compose up -d`"),
    # `expose:` publishes nothing under Docker either. The line explains, it does not report a loss.
    (r"is DECLARED, not published", "`expose:` publishes nothing under Docker either"),
    # The service is skipped under Docker too, for the same reason.
    (r"not active \(set COMPOSE_PROFILES", "Docker skips an inactive profile identically"),
    # kern already does what the key asks for, so the outcome matches.
    (r"is ALREADY ENFORCED", "kern already does what the key asks"),
    (r"is ENFORCED under --no-pod", "the key is honoured, and this says how"),
    # Announcements of a wiring that REPRODUCES Docker's behaviour rather than departing from it.
    (r"share no network, so they get no relay", "reproduces Docker's segregation"),
    (r"this file separates services with `networks:`", "announces the wiring that matches Docker"),
    (r"puts two services on the same internal port", "announces the wiring that matches Docker"),
    (r"gives a service's own name a fixed address with `extra_hosts:`", "announces the wiring that matches Docker"),
    (r"--no-pod gives each service its own network namespace", "announces the chosen wiring"),
    (r"and with a namespace per service kern ENFORCES it", "`internal:` is honoured, and this says how"),
    # `network_mode: service:X` asks for one namespace, and in a pod the stack IS one namespace.
    # The per-service arm of the same sentence is a difference and is listed below: the two arms
    # make opposite claims, so they cannot share a line here.
    (r"'network_mode: service:' is satisfied here", "one namespace is exactly what the key asks for"),
    # `bridge`/`default` ask for the stack's ordinary network, which is what every service that
    # writes no `network_mode` gets, under either wiring.
    (r"is the stack's own network, which is", "the key asks for the wiring kern already gives"),
    # Docker's `json-file` and `local` drivers write the container's output to a file on the host.
    # kern captures stdout and stderr of every box and serves them with `kern logs`. What is
    # genuinely dropped is rotation and the network drivers, and those are counted below.
    (r"is what kern already does - stdout/stderr are captured", "the driver asks for what kern does"),
    # MEASURED, and it replaces a line that said the opposite. Inside a box
    # `/proc/self/attr/current` reads the caller's own context: kern applies no AppArmor profile of
    # its own and sets no SELinux label, so `apparmor=unconfined` and `label=disable` get exactly
    # what they ask for. They were counted as differences on 11 files.
    (r"is ALREADY WHAT KERN DOES", "kern's own posture already is what the key asks for"),
    # `ipv4_address:` is HONOURED in one shared namespace: the address is claimed on the stack's
    # loopback and a peer that hard-codes it reaches the service, which is what the file asked for.
    # The per-service arm of the same sentence is a difference and is listed below.
    (r"`ipv4_address:` is applied here", "the address a peer hard-codes reaches the service"),
]

# Everything else counts as a difference. Named here only so `--verbose` can group the output; an
# unmatched line is counted as a difference regardless, so a NEW warning is never silently benign.
KNOWN_DIFFERENCES = [
    (r"compose_memory_max", "an operator ceiling caps a service below what the file asks"),
    (r"'network_mode: service:' is NOT given a shared namespace", "no shared loopback, and egress does not pass through the named service"),
    (r"this stack runs in ONE shared network namespace", "services share 127.0.0.1"),
    (r"mount the Docker socket", "no daemon behind the socket"),
    # WIDENED FROM ``ipv4_address` are NOT applied``, which is the SINGULAR rendering: a service
    # naming two of these keys produces "`ipv4_address`, `priority` are NOT applied" and fell through
    # to UNCLASSIFIED. It still counted as a difference, which is the safe direction, but it counted
    # under a label that named nothing.
    (r"under `networks:` the key\(s\)", "a `networks:` sub-key kern does not apply, a fixed address above all"),
    (r"has no kern equivalent \(rootless\)", "`privileged:` cannot be given"),
    (r"NOT applied - the box keeps its own IPC", "`ipc:` not shared"),
    (r"ignored \(unsupported\)", "a key kern does not implement"),
    (r"not honoured - seccomp", "`security_opt` seccomp profile"),
    (r"cannot be honoured - kern runs this machine", "`platform:` mismatch"),
    (r"recognised but not applied", "tmpfs options dropped"),
    (r"long-form", "a volume long form kern cannot express"),
    (r"is not a port in 1", "an out-of-range port is skipped"),
    (r"output is captured", "a `logging:` driver kern cannot provide"),
    (r"label=[^:]*: kern sets no SELinux label", "an SELinux label other than `disable`"),
    (r"seccomp=unconfined", "the file asks for NO seccomp filter, which kern does not take from a file"),
    (r"seccomp=[^:]*: a Docker seccomp profile", "a Docker seccomp JSON profile"),
    (r"ask for `privileged: true`", "`privileged:` needs the operator's grant, and nothing granted it"),
    (r"run with `privileged: true` as you granted", "`privileged:` granted, minus the /proc and /sys unmask"),
    (r"'security_opt:' not honoured", "a `security_opt` value with no kern equivalent"),
    (r"has no usable healthcheck", "a `service_healthy` gate degraded to start-order"),
    (r"the box keeps its own PID namespace", "`pid:` not shared"),
    (r"'pid: [a-z]+' is NOT applied", "`pid:` not shared"),
    (r"deploy\.[a-z_]+ ignored", "a `deploy:` key that needs an orchestrator"),
    (r"extra_hosts entry '.*' is incomplete", "an `extra_hosts` entry kern drops"),
    (r"max-size and max-file to its own capture", "a `logging:` option kern cannot provide"),
    (r"under `secrets:` the key\(s\)", "a secret long-syntax key that moves the file or its owner"),
    (r"`ipv4_address:` is claimed only where", "a fixed address a peer still cannot route to"),
]

BENIGN_RE = [(re.compile(p), why) for p, why in BENIGN]
KNOWN_RE = [(re.compile(p), why) for p, why in KNOWN_DIFFERENCES]


def differences(text):
    """The lines of one `config` run that are behavioural differences from Docker."""
    out = []
    for line in text.splitlines():
        if not line.startswith("kern:"):
            continue
        if any(rx.search(line) for rx, _ in BENIGN_RE):
            continue
        out.append(line)
    return out


def label(line):
    for rx, why in KNOWN_RE:
        if rx.search(line):
            return why
    # An unrecognised line is still a difference: the table names what is known, it does not decide
    # what counts. A warning added tomorrow lowers the rate until somebody classifies it on purpose.
    return "UNCLASSIFIED (counted as a difference)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", type=pathlib.Path)
    ap.add_argument("--kern", default="target/release/kern")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    files = sorted(p for p in args.corpus.iterdir() if p.is_file())
    if not files:
        print(f"no compose files under {args.corpus}", file=sys.stderr)
        return 2

    clean, causes, dirty, refused = 0, Counter(), [], []
    # THE COUNT IS PER FILE AND THE HEADING SAYS SO, because it used to say so while counting LINES.
    # MEASURED: the `ipv4_address` cause printed 230 next to the words "by files affected" on a
    # 240-file corpus, which reads as almost every file in the corpus. The true figure is 63 files;
    # the 230 was warning lines, one per service. A measurement that misreports its own unit is worse
    # than no measurement, because the number looks answerable and nobody re-derives it.
    only_cause = {}  # cause -> files where it is the ONLY thing standing between them and clean
    for f in files:
        run = subprocess.run(
            [args.kern, "compose", "-f", str(f), "config"],
            capture_output=True,
            text=True,
        )
        # A REFUSED FILE IS NOT A CLEAN ONE, and counting it as clean is how a rate goes UP by
        # rejecting more. The warning scan below sees only `kern: …` lines, so a hard `error:` would
        # otherwise leave a file with no differences at all - a perfect score for a stack that never
        # rendered. Reported apart from the warnings, because the two mean different things: a
        # refusal is either kern agreeing with Docker (`${VAR:?}` with no value) or a file kern
        # cannot read, and only the corpus gate can tell those apart.
        if run.returncode != 0:
            refused.append(f.name)
            continue
        diffs = differences(run.stderr)
        if diffs:
            dirty.append((f.name, diffs))
            # A file counts ONCE per cause however many services carry it.
            here = {label(d) for d in diffs}
            for why in here:
                causes[why] += 1
            if len(here) == 1:
                only_cause[next(iter(here))] = only_cause.get(next(iter(here)), 0) + 1
        else:
            clean += 1

    total = len(files)
    print(f"corpus              {total} files, one per repository")
    # WHAT THE CORPUS IS MADE OF, printed with the rate and not left for the reader to assume.
    # "One file per repository" is neutral about repositories and NOT about stacks: it favours the
    # small ones. Measured on this corpus: a third of it is single-service files, for which several
    # of the differences below cannot arise at all. A rate quoted without this denominator invites
    # the reading that every point applies to every file.
    shapes = {"multi": 0, "networks": 0, "healthcheck": 0}
    counts = []
    for f in files:
        body = f.read_text(errors="replace")
        n = len(re.findall(r"^  [A-Za-z0-9_.-]+:\s*$", body, re.M))
        counts.append(n)
        if n >= 2:
            shapes["multi"] += 1
        if re.search(r"^networks:", body, re.M):
            shapes["networks"] += 1
        if re.search(r"^\s+healthcheck:", body, re.M):
            shapes["healthcheck"] += 1
    counts.sort()
    median = counts[len(counts) // 2] if counts else 0
    pct = lambda n: f"{n * 100 // total}%" if total else "0%"
    print(f"                    {pct(shapes['multi'])} have 2+ services, "
          f"{pct(shapes['networks'])} declare `networks:`, "
          f"{pct(shapes['healthcheck'])} a healthcheck; median services/file {median}")
    print(f"ZERO differences    {clean} = {clean * 100 // total}%")
    if refused:
        print(f"REFUSED             {len(refused)} (not counted as clean; see compose-corpus-gate.py)")
        for name in refused:
            print(f"                      {name}")
    # THE CEILING, so the rate is read against what closing every remaining difference could buy
    # rather than against 100%. A refused file is not reachable by closing a difference: it never
    # rendered, and only the corpus gate can say whether the refusal is right.
    reachable = total - len(refused)
    print(f"CEILING             {reachable} = {reachable * 100 // total}% (every accepted file, if")
    print("                      every remaining difference below were closed)")
    # THE DISTRIBUTION, NEXT TO THE RATE AND NOT INSTEAD OF IT. The clean/dirty pair is insensitive
    # to progress on the dirty side, and that is measurable rather than suspected: closing the
    # `ipv4_address` silence moved this corpus from 90 clean to 90 clean, because every file carrying
    # that difference carried another one too. Differences are CORRELATED - a file that has one tends
    # to have three - so a cause can be closed for real without a single file crossing into the zero
    # bucket. The histogram shows the 3+ bucket draining into 2, which the rate cannot.
    spread = Counter(len({label(d) for d in diffs}) for _, diffs in dirty)
    print("\ndistribution by NUMBER of named differences (the rate above is only the first row):")
    print(f"  {clean:5d}  files with 0")
    for k in sorted(spread):
        if k < 3:
            print(f"  {spread[k]:5d}  files with {k}")
    three_plus = sum(n for k, n in spread.items() if k >= 3)
    print(f"  {three_plus:5d}  files with 3 or more")
    print("\ncauses, by FILES affected (a file may carry several; the second column is the files")
    print("this cause is the ONLY thing keeping from clean, which is what closing it would buy):")
    for why, n in causes.most_common():
        print(f"  {n:5d}  {only_cause.get(why, 0):5d}  {why}")
    if args.verbose:
        print("\nfiles with a difference:")
        for name, diffs in dirty:
            print(f"  {name}")
            for d in diffs:
                print(f"      {label(d)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
