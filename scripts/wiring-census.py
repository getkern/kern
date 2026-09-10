#!/usr/bin/env python3
"""Which wiring does kern actually select, over the whole corpus?

The relay wiring is the one an outside reviewer guessed has no population. `kern compose <f> config`
announces its choice on stderr, so this counts the announcements rather than re-deriving the rule:
It reads the `wiring:` FIELD that `compose config` prints on stdout, which is one token and says
nothing else: `pod`, `bridge` or `relay`. The `wiring-source:` line beside it says whether kern chose
that wiring (`auto`) or someone typed it (`flag`), and is counted separately: after a compose key can
pin the wiring, a file that keeps the pod on purpose must not be counted as the divergence a default
change would remove.
A file kern refuses is counted separately: it has no wiring at all.

MATCH THE DECISION SENTENCE, NOT A SUBSTRING OF THE ADVISORY. The first version of this script keyed
the bridge on `"on a bridge"`, which also appears INSIDE the pod advisory ("`--bridge` gives each
service its own namespace ... meeting on a bridge as Docker does"): every pod stack was counted as a
bridge, and the census reported 60% bridge on a corpus that is 85% pod. It was caught by a number
that refused to reconcile - 136 files carrying the shared-loopback advisory against 85 counted as
pod - which is the only reason a broken instrument becomes visible at all. One pass in that broken
era also reported 121 advisories against 120 pods; the targeted check found no file carrying both an
advisory and a decision, so it was one run's variance and was not chased. Recorded here so nobody
spends the hour again.
"""
import os, subprocess, sys
from pathlib import Path

CORPUS = Path(os.environ.get("KERN_COMPOSE_CORPUS", "/var/tmp/kern-corpus/files"))
KERN = os.environ.get("KERN_BIN", "/home/alex/dev/kern-compat/target/debug/kern")
counts = {"pod": 0, "pod_one_service": 0, "bridge": 0, "relays": 0, "refused": 0, "unknown": 0}
relay_files = []
for f in sorted(CORPUS.iterdir()):
    if not f.is_file():
        continue
    p = subprocess.run([KERN, "compose", str(f), "config"], capture_output=True, text=True, timeout=120)
    err = p.stderr
    if p.returncode != 0:
        counts["refused"] += 1
        continue
    w = next(
        (l.split(":", 1)[1].strip() for l in p.stdout.splitlines() if l.startswith("  wiring:")),
        "",
    )
    src = next(
        (l.split(":", 1)[1].strip() for l in p.stdout.splitlines() if l.startswith("  wiring-source:")),
        "",
    )
    if src:
        counts[f"source_{src}"] = counts.get(f"source_{src}", 0) + 1
    if w == "bridge":
        counts["bridge"] += 1
    elif w == "relay":
        counts["relays"] += 1
        relay_files.append(f.name)
    elif w == "pod":
        counts["pod"] += 1
        # SPLIT THE POD BY SERVICE COUNT, because the two halves are not the same fact. With one
        # service a pod IS Docker's arrangement - one loopback, nobody to share it with - so a
        # default that moved to the bridge should not reach those files at all. Measured on the
        # neutral corpus: 85 single-service pods, none of which carry the shared-loopback advisory,
        # against 136 with two or more, all of which do. The split is exactly the advisory's gate.
        import re as _re
        m = _re.search(r"compose config: (\d+) service", p.stdout)
        if m and int(m.group(1)) <= 1:
            counts["pod_one_service"] += 1
    else:
        # A build of kern that does not print the field. Counting it as a wiring would be the same
        # class of guess this script exists to remove.
        counts["unknown"] += 1
# THE TOTAL IS THE FOUR BUCKETS, NAMED. Everything else in `counts` is a breakdown of one of them
# (`pod_one_service` is a subset of `pod`, `source_*` cuts across all four), and summing the dict
# counted those twice: the corpus reported 344 files and then 506, on a directory of 259. Written as
# an explicit list so a new breakdown cannot silently join the total again.
BUCKETS = ("pod", "bridge", "relays", "refused", "unknown")
total = sum(counts[k] for k in BUCKETS)
print(f"corpus: {total} files")
for k in BUCKETS:
    print(f"  {k:8} {counts[k]:4}  {counts[k]*100.0/total:5.1f}%")
    if k == "pod":
        sub = counts["pod_one_service"]
        print(f"    of which one service only: {sub}  (the pod IS Docker's arrangement there)")
        print(f"    two services or more:      {counts['pod'] - sub}  (these are the divergence)")
srcs = {k[len("source_"):]: v for k, v in counts.items() if k.startswith("source_")}
if srcs:
    print("  chosen by: " + ", ".join(f"{k}={v}" for k, v in sorted(srcs.items())))
if relay_files:
    print("  relay files:", ", ".join(relay_files[:12]), "..." if len(relay_files) > 12 else "")
