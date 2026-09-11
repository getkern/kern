#!/usr/bin/env python3
"""Close the half of the shared-loopback question that no cached corpus can reach.

WHY IT EXISTS. 136 corpus files carry kern's "services share 127.0.0.1" note. 94 of them declare
`build:`, and the corpus holds one YAML file per repository and none of the build contexts, so
`loopback-census.py` cannot start them: it measured 22 of the 41 image-only files and nothing else.
`declared-bind-census.py` then read what those 94 SAY about their binds and found 83 that say
nothing at all, because the address is in the image's `CMD` or an application default.

Those 83 are the honest unknown, and there is exactly one way to resolve them: fetch the repository,
build the image, run the stack, and read what it listens on. That is what this does.

IT EXECUTES CODE FROM THE INTERNET. A `docker build` runs the `RUN` lines of a Dockerfile written by
a stranger, and so does this. It is deliberately NOT part of any gate, requires `--yes-build-foreign-
code` to run at all, and belongs on a machine whose owner has decided that is acceptable. The build
itself is kern's, so it is a rootless user namespace with kern's own seccomp filter, which is a
boundary and not a promise about what the code will try.

WHAT IT MEASURES is exactly what `loopback-census.py` measures, through the same probe: a service
that binds `127.0.0.1`/`[::1]` only (private under Docker, reachable by every peer under one shared
namespace), or a service that died because it could not bind a port another service already held.

THE DENOMINATOR IS THE POINT. A repository may be gone, private, too large, may fail to build for a
missing secret or a base image that no longer exists, and may simply not come up. Every one of those
is reported as its own bucket: an unmeasured file is never a clean one.

Usage:
    build-corpus-census.py <corpus-dir> --yes-build-foreign-code [--limit N] [--kern PATH]
                           [--workdir DIR] [--timeout S] [--json OUT]
"""

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kernbin
import importlib.util

# The probe is imported rather than copied: one definition of what `loopback-semantic` means, so this
# census and the image-only one cannot drift into measuring different things.
_spec = importlib.util.spec_from_file_location(
    "loopback_census", os.path.join(os.path.dirname(os.path.abspath(__file__)), "loopback-census.py")
)
loopback_census = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(loopback_census)


def repo_of(name):
    """`owner~repo~path~to~docker-compose.yml` -> (owner, repo, path inside the repository).

    The corpus encodes the path with `~` because a filename cannot hold `/`. The first two fields
    are the repository; everything after them is where the file lived in it.
    """
    parts = name.split("~")
    if len(parts) < 3:
        return None
    owner, repo = parts[0], parts[1]
    inner = "/".join(parts[2:])
    return owner, repo, inner


def clone(owner, repo, dest, timeout):
    """A shallow clone, or None with the reason. No credentials: a private repo is simply absent."""
    url = f"https://github.com/{owner}/{repo}.git"
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="/bin/true")
    try:
        p = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return str(e)[:120]
    if p.returncode != 0:
        return (p.stderr.strip().splitlines() or ["clone failed"])[-1][:120]
    return None


def measure_one(kern, corpus_file, workdir, timeout, settle):
    """Clone, locate the file in the clone, and run the same probe the other census runs."""
    verdict = {"file": corpus_file.name, "bucket": "not-measured", "detail": ""}
    who = repo_of(corpus_file.name)
    if who is None:
        verdict["detail"] = "filename does not encode a repository"
        return verdict
    owner, repo, inner = who
    dest = workdir / f"{owner}~{repo}"
    shutil.rmtree(dest, ignore_errors=True)
    why = clone(owner, repo, dest, timeout)
    if why is not None:
        verdict.update(bucket="not-cloned", detail=why)
        return verdict
    try:
        target = dest / inner
        if not target.is_file():
            # The path may have moved since the corpus was sampled; fall back to any compose file.
            found = None
            for cand in sorted(dest.rglob("*compose*.y*ml")):
                found = cand
                break
            if found is None:
                verdict.update(bucket="not-measured", detail=f"{inner} is not in the clone")
                return verdict
            target = found
        # THE SAME PROBE, imported: `up`, settle, read the listeners and the dead, `down`.
        got = loopback_census.measure(kern, target, timeout, settle)
        verdict.update(bucket=got["bucket"], detail=got["detail"])
        return verdict
    finally:
        shutil.rmtree(dest, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", type=pathlib.Path)
    ap.add_argument("--kern", default="target/release/kern")
    ap.add_argument("--yes-build-foreign-code", action="store_true",
                    help="required: this builds and runs Dockerfiles written by strangers")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--settle", type=float, default=6.0)
    ap.add_argument("--workdir", default="/var/tmp/kern-build-census")
    ap.add_argument("--json", dest="json_out", default="")
    args = ap.parse_args()

    if not args.yes_build_foreign_code:
        print(
            "refusing to run: this clones repositories and BUILDS their Dockerfiles, which executes\n"
            "code written by strangers on this machine. Pass --yes-build-foreign-code if that is\n"
            "acceptable here. It is never run by a gate.",
            file=sys.stderr,
        )
        return 2
    rc = kernbin.require_current(args.kern)
    if rc:
        return rc
    kern = os.path.abspath(args.kern)

    workdir = pathlib.Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    # The subject: files that carry the note AND declare `build:`, which is the half the image-only
    # census cannot reach.
    subject = []
    for f in sorted(p for p in args.corpus.iterdir() if p.is_file()):
        try:
            p = subprocess.run(
                [kern, "compose", "-f", str(f), "config"],
                capture_output=True, text=True, timeout=120,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if p.returncode != 0:
            continue
        if "this stack runs in ONE shared network namespace" not in (p.stdout + p.stderr):
            continue
        if "build:" not in f.read_text(encoding="utf-8", errors="replace"):
            continue
        subject.append(f)
    print(f"subject: {len(subject)} files that carry the note and declare `build:`", flush=True)
    if args.limit:
        subject = subject[: args.limit]

    results = []
    for i, f in enumerate(subject, 1):
        v = measure_one(kern, f, workdir, args.timeout, args.settle)
        results.append(v)
        print(f"  [{i}/{len(subject)}] {v['bucket']:16} {f.name[:56]}", flush=True)

    buckets = {}
    for v in results:
        buckets[v["bucket"]] = buckets.get(v["bucket"], 0) + 1
    measured = sum(
        n for b, n in buckets.items() if b in ("loopback-semantic", "collision", "notice-only")
    )
    print(f"\nattempted {len(results)} of {len(subject)}; measured {measured}")
    for b in ("loopback-semantic", "collision", "notice-only", "not-cloned", "not-measured"):
        n = buckets.get(b, 0)
        share = f" = {n * 100 // measured}% of measured" if measured and b in (
            "loopback-semantic", "collision", "notice-only"
        ) else ""
        print(f"  {n:4d}  {b}{share}")
    print(
        "\nA file that could not be cloned, built or started was NOT measured. Reading those as "
        "clean is the defect this bucket exists to prevent."
    )
    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump({"results": results, "buckets": buckets}, fh, indent=2)
        except OSError as e:
            print(f"could not write {args.json_out}: {e}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
