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
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kernbin
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
    # THE DEFAULT WIRING, ANNOUNCED. It belongs beside the three lines above and not in the table
    # below, and the test is the same one they pass: does the sentence report kern doing something
    # DIFFERENT from Docker, or kern doing what Docker does? It says each service gets its own
    # namespace and its own 127.0.0.1, which is Docker's arrangement exactly.
    #
    # THE CONTROL THAT KEEPS THIS HONEST is two lines down in the other table: `this stack runs in
    # ONE shared network namespace` is still counted as a difference, so a file wired as a pod - by
    # `--pod`, or because it has one service - still costs a point. A classifier that had simply been
    # taught to ignore wiring sentences would have had to move that line too.
    (r"gets its own network namespace on a bridge, which is the arrangement Docker has",
     "announces the wiring that matches Docker"),
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
    # THE PER-SERVICE ARM OF THE SAME KEY, and the outcome Docker gives: on a bridge each service
    # holds its own namespace and takes the literal address the file names, so a peer that hard-codes
    # it reaches exactly the service the file meant. It appeared the day the wiring decision stopped
    # depending on the image cache: a file whose EXPOSE collision was previously invisible is now
    # wired per service, and the sentence changed with the wiring. The gate caught it, which is what
    # the gate is for.
    (r"`ipv4_address:` is honoured exactly here", "the literal address is the service's own, as under Docker"),
    # NOT A DIFFERENCE FROM DOCKER: a statement about what kern could read. kern decides the wiring
    # partly from each image's EXPOSE set, which it will not pull to answer a `config`, so an
    # uncached image leaves the answer provisional and the line says so. Docker has no equivalent
    # because every container has its own namespace there and the question does not arise.
    #
    # IT IS ALSO WHY THIS RATE DECLARES ITS CACHE STATE below: the same file answers `pod` before a
    # pull and `bridge` after one, measured one `kern rmi` apart, and two files moved between the
    # buckets of this very number that way.
    (r"the wiring above was decided WITHOUT reading", "a caveat about kern's own knowledge"),
    # NOT A DIFFERENCE: the gate is HONOURED, and the line says where the check came from. Docker
    # reads the image's `HEALTHCHECK` for a service that declares none, and so does kern now; the
    # note exists because the parser had to defer the decision to a caller that can open an image.
    (r"but its IMAGE carries one, so the `service_healthy` gate is honoured",
     "the image supplies the healthcheck, as under Docker"),
    # NOT A DIFFERENCE: DOCKER REFUSES THE SAME FILE, MEASURED. An `external: true` network is one
    # the file does not create, and a file naming one that does not exist cannot run on either
    # runtime. Measured on the reference daemon (Docker 29.6.2, compose plugin v5.3.1):
    #
    #   docker compose config  ->  renders the file, says nothing
    #   docker compose up      ->  "network X declared as external, but could not be found"
    #
    # kern does the same: `config` renders and WARNS, `up` refuses and names `kern network create`.
    # The warning is the courtesy half - Docker leaves you to find out at `up` - and a courtesy is
    # not a behavioural difference, which is the same reading the "empty list item" line above gets.
    #
    # THE LINE THIS REPLACES COUNTED A REAL DIFFERENCE, and it was real right up until the feature
    # landed: kern had no cross-project network at all, so these files ran with peers that resolved
    # nothing. What changed is the runtime, not the classifier's standard.
    (r"is declared `external: true` and does not exist on this machine",
     "Docker refuses the same file for the same reason, measured"),
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
    (r"NOT applied - the box keeps its own IPC", "`ipc:` not shared"),
    (r"ignored \(unsupported\)", "a key kern does not implement"),
    (r"not honoured - seccomp", "`security_opt` seccomp profile"),
    (r"cannot be honoured - kern runs this machine", "`platform:` mismatch"),
    (r"recognised but not applied", "tmpfs options dropped"),
    (r"long-form", "a volume long form kern cannot express"),
    (r"is not a port in 1", "an out-of-range port is skipped"),
    # THE WHOLE UNCLASSIFIED BUCKET WAS THIS ONE LINE. Measured on the neutral corpus: 38 files
    # carried an unlabelled difference and every one of them was this note, 11 of them with nothing
    # else. It is a real difference and keeps counting as one - a rootful Docker binds :80 and kern,
    # rootless, publishes :8080, so the service is not where the file says - but it was counting
    # under a label that named nothing, which is the state that makes a bucket look mysterious.
    (r"binds from 1024 upward", "a privileged host port is republished above 1024"),
    # THE `external:` NETWORK LINE IS GONE FROM THIS TABLE because the difference is gone: kern
    # implements a network shared between projects (`kern network create`, relays in both
    # directions, hosts entries written into the other project's running boxes). What remains is the
    # BENIGN line above, which reports a network that has not been created on this machine - a state
    # Docker refuses the file in too.
    # `runtime:` USED TO FALL INTO "a key kern does not implement", which named the key and nothing
    # else. Both corpus files that write it write `runtime: nvidia`, and the two values mean opposite
    # things: `nvidia` asks for hardware (a device grant, which has a spelling in the file), any
    # other value asks kern to delegate to a different runtime, which is the position this project
    # refuses. Two labels because they are two answers.
    (r"`runtime: nvidia` is NOT applied", "`runtime: nvidia`: the GPU is a device grant here"),
    (r"`runtime: [^`]+` is NOT applied", "`runtime:` names another runtime, and kern is one"),
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
    ap.add_argument(
        "--with-low-port-floor", action="store_true",
        help="also measure this corpus on a host that permits low ports, in a namespace of our own",
    )
    args = ap.parse_args()

    # The shared check: identity first (`kern --version` carries the commit), date only where a
    # dirty build makes the commit insufficient. See scripts/kernbin.py.
    rc = kernbin.require_current(args.kern)
    if rc:
        return rc

    # THE SECOND NUMBER, MEASURED AND NOT DERIVED.
    #
    # The largest remaining difference on this corpus is a host property and not kern's: rootless,
    # the kernel refuses a bind below `net.ipv4.ip_unprivileged_port_start`, which is 1024 almost
    # everywhere, so a file publishing :80 gets :8080 and is not where it says it is. podman refuses
    # the same port outright and names the same sysctl; Docker rootful binds it because it is root.
    #
    # IT IS A PER-NAMESPACE SETTING, so the difference does not have to be argued about: this re-runs
    # the whole measurement inside a network namespace of our own with the floor at 0, and kern reads
    # the floor from that namespace like any other process. Two measured numbers, one command, and
    # the only thing between them is one `sysctl`.
    #
    # SUBTRACTING THE CAUSE FROM THE FIRST NUMBER WOULD HAVE BEEN A DERIVATION, and a derived figure
    # printed beside a measured one is how this project has produced its wrong numbers before. It
    # also assumes the causes are disjoint, which nothing here guarantees - and which this run is
    # what actually checks.
    #
    # THE NESTED RUN HAS NO NETWORK, which matters for one line of the report: an uncached image
    # config cannot be fetched there, so CACHE-DEPENDENT is printed by both runs and the two numbers
    # are comparable only while it is unchanged. Say so rather than hide it.
    if args.with_low_port_floor and not os.environ.get("KERN_RATE_LOW_FLOOR"):
        inner = (
            "echo 0 > /proc/sys/net/ipv4/ip_unprivileged_port_start || exit 3; "
            f"exec {sys.executable} {os.path.abspath(__file__)} "
            f"{os.path.abspath(str(args.corpus))} --kern {os.path.abspath(args.kern)}"
        )
        try:
            second = subprocess.run(
                ["unshare", "-rn", "sh", "-c", inner],
                capture_output=True, text=True,
                env=dict(os.environ, KERN_RATE_LOW_FLOOR="1"),
                timeout=3600,
            )
        except (OSError, subprocess.SubprocessError) as e:
            print(f"could not measure the low-floor case: {e}", file=sys.stderr)
            second = None
        if second is not None and second.returncode == 0:
            for line in second.stdout.splitlines():
                if line.startswith("ZERO differences"):
                    low_floor_line = line.split("    ", 1)[-1].strip()
                    break
            else:
                low_floor_line = ""
        else:
            why = (second.stderr.strip()[-160:] if second is not None else "not run")
            low_floor_line = ""
            print(f"the low-floor measurement did not complete: {why}", file=sys.stderr)
    else:
        low_floor_line = ""

    files = sorted(p for p in args.corpus.iterdir() if p.is_file())
    if not files:
        print(f"no compose files under {args.corpus}", file=sys.stderr)
        return 2

    clean, causes, dirty, refused = 0, Counter(), [], []
    # Files whose WIRING was decided without reading an image that is not cached. Reported with the
    # rate because it bounds how reproducible the rate is: pulling those images can move a file
    # between `pod` and `bridge`, and with it between the buckets below.
    provisional = 0
    # THE COUNT IS PER FILE AND THE HEADING SAYS SO, because it used to say so while counting LINES.
    # MEASURED: the `ipv4_address` cause printed 230 next to the words "by files affected" on a
    # 240-file corpus, which reads as almost every file in the corpus. The true figure is 63 files;
    # the 230 was warning lines, one per service. A measurement that misreports its own unit is worse
    # than no measurement, because the number looks answerable and nobody re-derives it.
    only_cause = {}  # cause -> files where it is the ONLY thing standing between them and clean
    # THE EXACT WIRING ANSWER, PAID FOR HERE AND NOWHERE ELSE. kern decides the wiring partly from
    # each image's EXPOSE set; an image that is not in the local cache leaves the answer provisional,
    # and a published number must not depend on which images this machine happens to hold. With this
    # set, kern fetches the CONFIG BLOB (kilobytes, no layers) for an uncached image. Measured: the
    # cache-dependent count over this corpus goes from 90 files to 2, the two being images that
    # cannot be fetched at all.
    #
    # It is not kern's default because a dry run must not be slow: measured 2 ms without it and
    # 2084 ms per uncached image with it, and eighty seconds for a file whose registry does not
    # resolve. `up` never needs it, since it resolves its images before deciding anyway.
    env = dict(os.environ, KERN_COMPOSE_FETCH_IMAGE_CONFIG="1")
    for f in files:
        run = subprocess.run(
            [args.kern, "compose", "-f", str(f), "config"],
            capture_output=True,
            text=True,
            env=env,
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
        if "the wiring above was decided WITHOUT reading" in run.stderr:
            provisional += 1
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
    if low_floor_line:
        print(
            f"  same corpus, host that permits low ports: {low_floor_line}\n"
            f"                      (MEASURED in a network namespace of our own with "
            f"net.ipv4.ip_unprivileged_port_start=0,\n"
            f"                      which is one `sysctl` on a real host. The difference is the "
            f"rootless port floor\n                      and nothing else: podman refuses the same "
            f"ports, Docker binds them because it is root.)"
        )
    if refused:
        print(
        f"REFUSED             {len(refused)} (not counted as clean; MEASURED on Docker 29.6.2: it "
        f"refuses the same 12)"
    )
        for name in refused:
            print(f"                      {name}")
    print(
        f"CACHE-DEPENDENT     {provisional} file(s) whose wiring was decided without reading an "
        f"uncached image;\n                      pulling those images can move them between "
        f"buckets"
    )
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

    # NOTHING MAY BE UNCLASSIFIED, and this is a gate rather than a line in the table.
    #
    # WHY IT EXISTS, measured rather than argued: the classifier reads the PROSE of kern's warnings,
    # so rewording one silently rewrites the number. Rewriting "is DECLARED, not published" as "is
    # DECLARED rather than published" - the same sentence, the same meaning, one word - took a
    # 12-file corpus from 58% clean to 0% clean. Nothing else changed and nothing said so.
    #
    # The signal was always in the output: those twelve files landed under UNCLASSIFIED. What was
    # missing was a threshold, so the slide showed up as a smaller rate and not as a failure. With
    # every cause named, the count is ZERO and any drift - a reworded message, a warning added
    # without a label - takes it above zero on the first run.
    #
    # This is the cheap half of the fix. The expensive half is a stable code per warning, which
    # would decouple the classifier from the wording entirely; the gate below makes the coupling
    # SELF-ANNOUNCING, which is the property that was missing.
    unlabelled = [d for _, diffs in dirty for d in diffs if label(d).startswith("UNCLASSIFIED")]
    if unlabelled:
        shapes = Counter(d[:120] for d in unlabelled)
        print(
            f"\nUNCLASSIFIED must be 0, found {len(unlabelled)} line(s) in "
            f"{len(shapes)} shape(s):",
            file=sys.stderr,
        )
        for shape, n in shapes.most_common(10):
            print(f"  {n:4d}  {shape}", file=sys.stderr)
        print(
            "\nEither the warning is new and needs a line in KNOWN_DIFFERENCES/BENIGN, or one it "
            "used to match was reworded and the pattern no longer does. A rate whose classifier is "
            "out of step with the binary is not a measurement.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
