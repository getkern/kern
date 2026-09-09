#!/usr/bin/env python3
"""Refuse a change that makes kern reject a real-world compose file it used to accept.

WHY THIS EXISTS, and it is not a hypothetical. In one run against 245 `docker-compose.yml` files
scraped from public repositories, this comparison found THREE files that the tree accepted in the
morning and refused in the evening, and TWO that it had always refused and now parses. The 1097 Rust
tests found none of them, and could not have: not one of those tests is a compose file written by a
stranger who never heard of kern.

WHAT IT ASSERTS, and the direction is the whole point: the accept rate may RISE freely and may not
FALL. A gate that pinned the exact rate would go red on every genuine parser improvement, and would
be deleted within a week. A gate that only catches losses stays useful and never argues with a fix.

WHAT IT DOES NOT ASSERT: that a refusal is wrong. Three of the differences it found were kern's
`compose config` finally agreeing with `compose up` about files that could never have started, which
is a fix and not a regression. When that happens the reference is re-recorded ON PURPOSE, with the
reason in the commit message; the gate exists so that re-recording is a DECISION rather than an
accident nobody noticed.

CORPUS: not vendored. 245 files of other people's code, several megabytes, most of them licensed in
ways that make copying them into this repository a question nobody needs to answer. Point
`KERN_COMPOSE_CORPUS` at a directory of compose files; without one the gate SKIPS and says so,
because a gate that silently passes when its input is missing is worse than no gate.

    KERN_COMPOSE_CORPUS=/var/tmp/kern-corpus/files python3 scripts/compose-corpus-gate.py
    KERN_COMPOSE_CORPUS=... python3 scripts/compose-corpus-gate.py --record   # re-record, on purpose
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REFERENCE = ROOT / "pentest" / "compose-corpus.tsv"
# The corpus is a directory of compose files; the default is where it happens to live on the machine
# this was written on, and any host can point somewhere else.
CORPUS = Path(os.environ.get("KERN_COMPOSE_CORPUS", "/var/tmp/kern-corpus/files"))
# `config` and not `up`: parsing is what this measures, and `up` would need images, a network and a
# host that can start boxes. The three regressions it caught were all parse-time.
TIMEOUT_S = 20


def kern_binary() -> Path | None:
    """The binary to test, preferring a release build and falling back to debug.

    `None` when neither exists, which is a skip and not a failure: this gate is run by hand and by
    `pentest/run-all.sh`, and neither should fail because nobody built first.
    """
    for rel in ("target/release/kern", "target/debug/kern"):
        p = ROOT / rel
        if p.is_file() and os.access(p, os.X_OK):
            return p
    return None


def outcomes(kern: Path, files: list[Path]) -> dict[str, int]:
    """Map each file's NAME to `kern compose config`'s exit status, 0 for accepted.

    A timeout counts as a refusal rather than crashing the gate: a file that hangs the parser is not
    a file that parses, and the run must still produce a comparable vector.
    """
    out: dict[str, int] = {}
    for f in files:
        try:
            r = subprocess.run(
                [str(kern), "compose", "config", "-f", str(f)],
                capture_output=True,
                timeout=TIMEOUT_S,
            )
            out[f.name] = 0 if r.returncode == 0 else 1
        except subprocess.TimeoutExpired:
            out[f.name] = 1
        except OSError as e:
            print(f"gate: cannot run kern on {f.name}: {e}", file=sys.stderr)
            out[f.name] = 1
    return out


def read_reference() -> dict[str, int] | None:
    if not REFERENCE.is_file():
        return None
    ref: dict[str, int] = {}
    for line in REFERENCE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, status = line.rpartition("\t")
        if not name or status not in ("0", "1"):
            print(f"gate: malformed reference line: {line!r}", file=sys.stderr)
            return None
        ref[name] = int(status)
    return ref


def write_reference(res: dict[str, int]) -> None:
    body = [
        "# kern compose corpus: `compose config` exit status per real-world file, 0 = accepted.",
        "# Re-record ONLY on purpose, with the reason in the commit message: every line that moves",
        "# from 0 to 1 is a file the world can write and kern stopped reading.",
    ]
    body += [f"{name}\t{status}" for name, status in sorted(res.items())]
    REFERENCE.write_text("\n".join(body) + "\n", encoding="utf-8")


def main() -> int:
    record = "--record" in sys.argv[1:]

    if not CORPUS.is_dir():
        print(f"SKIP: no corpus at {CORPUS} (set KERN_COMPOSE_CORPUS)")
        return 0
    files = sorted(p for p in CORPUS.iterdir() if p.is_file())
    if not files:
        print(f"SKIP: {CORPUS} holds no files")
        return 0

    kern = kern_binary()
    if kern is None:
        print("SKIP: no kern binary built (cargo build [--release])")
        return 0

    res = outcomes(kern, files)
    accepted = sum(1 for v in res.values() if v == 0)

    if record:
        write_reference(res)
        print(f"recorded {len(res)} files, {accepted} accepted, to {REFERENCE.name}")
        return 0

    ref = read_reference()
    if ref is None:
        print(f"SKIP: no usable reference at {REFERENCE} (run with --record once)")
        return 0

    # Only files present in BOTH are comparable. A corpus that grew says nothing about a regression,
    # and one that shrank must not silently reduce what is checked - so both are reported.
    common = sorted(set(ref) & set(res))
    lost = [n for n in common if ref[n] == 0 and res[n] == 1]
    gained = [n for n in common if ref[n] == 1 and res[n] == 0]
    only_ref = sorted(set(ref) - set(res))
    only_now = sorted(set(res) - set(ref))

    print(f"corpus: {len(files)} files, {accepted} accepted; {len(common)} comparable")
    if only_ref:
        print(f"  {len(only_ref)} in the reference are missing from this corpus")
    if only_now:
        print(f"  {len(only_now)} new files are not in the reference")
    for n in gained:
        print(f"  GAINED: {n}")

    if lost:
        print()
        print(f"{len(lost)} file(s) the reference accepts and this tree refuses:")
        for n in lost:
            path = CORPUS / n
            try:
                r = subprocess.run(
                    [str(kern), "compose", "config", "-f", str(path)],
                    capture_output=True,
                    timeout=TIMEOUT_S,
                )
                why = ""
                for line in r.stderr.decode("utf-8", "replace").splitlines():
                    if line.lower().startswith("error"):
                        why = line.strip()
                        break
            except (subprocess.TimeoutExpired, OSError):
                why = "(timed out)"
            print(f"  {n}\n      {why}")
        print()
        print(
            "Each of these is a compose file the world can write and this tree stopped reading.\n"
            "If a refusal is CORRECT (kern's `config` agreeing with `up` about a file that could\n"
            "never start is the case that has happened), re-record with --record and say why in the\n"
            "commit message. Do not re-record to make this quiet."
        )
        return 1

    print("no file the reference accepts is refused here")
    return 0


if __name__ == "__main__":
    sys.exit(main())
