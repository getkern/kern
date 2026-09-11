#!/usr/bin/env python3
"""What the 94 `build:` files DECLARE about their binds, without building anything.

WHY. `loopback-census.py` answers the shared-loopback question by running a stack and reading what
it listens on, which needs an image. 94 of the 136 files that carry the note declare `build:` and
carry no build context in this corpus, so they cannot be run here at all. Two reviewers, asked how
to close the question without them, gave the same two answers independently, and this is both:

  1. A COLLISION THE FILE ITSELF DECLARES. Two services naming the same container port in `ports:`
     or `expose:` collide in one namespace and do not collide under Docker. No image needed: the
     file says it.

  0. SERVICES BEHIND A `profiles:` ARE SKIPPED, because they are not in the run. Reading them was
     this script's first defect: it reported a collision on a file kern correctly wires as a pod,
     because the colliding pair only exists with a profile nobody enabled.

  2. A BIND ADDRESS THE FILE ITSELF WRITES. `command:`, `entrypoint:` and `environment:` routinely
     carry the address a server binds: `--host 127.0.0.1`, `--bind 0.0.0.0:8000`, `HOST=localhost`,
     `--inspect=127.0.0.1:9229`. A loopback address there is the exposure the census looks for,
     declared where a parser can see it.

WHAT THIS IS AND IS NOT. It is an UPPER BOUND on "could break in a pod, by what the file says", and
a LOWER BOUND on nothing: a service whose bind lives in the image's `CMD` or in an application
default is invisible here and shows up only when the stack runs. Both numbers are printed with the
count that could not be classified, because a file with neither pattern is an unknown and not a
clean.

Usage:
    declared-bind-census.py <corpus-dir> [--kern PATH] [--only-build] [--json OUT]
"""

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kernbin

try:
    import yaml
except ImportError:  # pragma: no cover - reported, never guessed around
    yaml = None

# The forms a compose file writes a bind address in. Each one is a real spelling, not a guess:
# `--host`/`-h` (uvicorn, flask, nginx-ish), `--bind` (gunicorn), `runserver ADDR:PORT` (django),
# `--inspect=` (node), `--listen` (several), and the environment names apps read for the same thing.
BIND_PATTERNS = [
    re.compile(r"--host[=\s]+([0-9a-zA-Z\.:\[\]]+)"),
    re.compile(r"--bind[=\s]+([0-9a-zA-Z\.:\[\]]+)"),
    re.compile(r"--inspect(?:-brk)?=([0-9a-zA-Z\.:\[\]]+)"),
    re.compile(r"--listen[=\s]+([0-9a-zA-Z\.:\[\]]+)"),
    re.compile(r"runserver\s+([0-9a-zA-Z\.:\[\]]+)"),
    re.compile(r"\b(?:HOST|BIND|BIND_ADDR|LISTEN|LISTEN_ADDR|SERVER_HOST)=([0-9a-zA-Z\.:\[\]]+)"),
]
LOOPBACK = re.compile(r"^(127\.|localhost$|\[?::1\]?$)", re.IGNORECASE)
ANY_ADDR = re.compile(r"^(0\.0\.0\.0|\[?::\]?|\*)$")


def texts_of(svc):
    """Every string in a service where a bind address is plausibly written."""
    out = []
    for key in ("command", "entrypoint"):
        v = svc.get(key)
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            out.append(" ".join(str(x) for x in v))
    env = svc.get("environment")
    if isinstance(env, dict):
        out.extend(f"{k}={v}" for k, v in env.items())
    elif isinstance(env, list):
        out.extend(str(x) for x in env)
    return out


def declared_binds(svc):
    """The bind addresses this service's own text names: (loopback, any-address) counts."""
    loop, anyaddr = 0, 0
    for t in texts_of(svc):
        for rx in BIND_PATTERNS:
            for m in rx.finditer(t):
                addr = m.group(1).split(":")[0] if m.group(1).count(":") == 1 else m.group(1)
                if LOOPBACK.match(addr):
                    loop += 1
                elif ANY_ADDR.match(addr):
                    anyaddr += 1
    return loop, anyaddr


def container_ports(svc):
    """The container-side ports this service declares, from `ports:` and `expose:`."""
    out = set()
    for p in svc.get("ports") or []:
        if isinstance(p, dict):
            t = p.get("target")
            if isinstance(t, int):
                out.add(t)
            continue
        parts = str(p).split(":")
        last = parts[-1].split("/")[0]
        if last.isdigit():
            out.add(int(last))
    for e in svc.get("expose") or []:
        e = str(e).split("/")[0]
        if e.isdigit():
            out.add(int(e))
    return out


def classify(path):
    """One file: does it DECLARE a collision, a loopback bind, or neither?"""
    verdict = {"file": path.name, "declared_collision": [], "loopback_bind": [], "any_bind": 0}
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:  # a corpus file that is not valid YAML is not this script's subject
        verdict["error"] = str(e)[:80]
        return verdict
    services = (doc or {}).get("services")
    if not isinstance(services, dict):
        verdict["error"] = "no services mapping"
        return verdict
    seen = {}
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        # A SERVICE BEHIND A PROFILE IS NOT IN THE RUN, and counting it produced this script's first
        # false positive: `CEIJ-GPSDE/GoTracker` declares two trackers on container port 8080, and
        # the second one sits behind `profiles:`. kern wires that file as a pod because it keeps the
        # ACTIVE services only, which is what Docker does, and the collision this script reported
        # could never happen. No profile is active by default, so any non-empty `profiles:` is out.
        if svc.get("profiles"):
            continue
        for port in container_ports(svc):
            if port in seen and seen[port] != name:
                verdict["declared_collision"].append(f"{seen[port]}+{name}:{port}")
            else:
                seen[port] = name
        loop, anyaddr = declared_binds(svc)
        if loop:
            verdict["loopback_bind"].append(name)
        verdict["any_bind"] += anyaddr
    return verdict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", type=pathlib.Path)
    ap.add_argument("--kern", default="target/release/kern")
    ap.add_argument("--only-build", action="store_true",
                    help="only files that declare `build:` (the half no runtime census can reach)")
    ap.add_argument("--json", dest="json_out", default="")
    args = ap.parse_args()

    if yaml is None:
        print("PyYAML is required: pip install pyyaml", file=sys.stderr)
        return 2
    rc = kernbin.require_current(args.kern)
    if rc:
        return rc
    kern = os.path.abspath(args.kern)

    files = sorted(p for p in args.corpus.iterdir() if p.is_file())
    shared = []
    for f in files:
        try:
            p = subprocess.run(
                [kern, "compose", "-f", str(f), "config"],
                capture_output=True, text=True, timeout=90,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if p.returncode != 0:
            continue
        if "this stack runs in ONE shared network namespace" not in (p.stdout + p.stderr):
            continue
        if args.only_build and "build:" not in f.read_text(encoding="utf-8", errors="replace"):
            continue
        shared.append(f)

    results = [classify(f) for f in shared]
    coll = [r for r in results if r.get("declared_collision")]
    loop = [r for r in results if r.get("loopback_bind")]
    either = {r["file"] for r in coll} | {r["file"] for r in loop}
    unreadable = [r for r in results if r.get("error")]
    silent = [
        r for r in results
        if not r.get("error") and not r.get("declared_collision") and not r.get("loopback_bind")
        and not r.get("any_bind")
    ]

    print(f"files examined            {len(results)}")
    print(f"  declare a COLLISION     {len(coll)}  (two services, one container port)")
    print(f"  declare a LOOPBACK bind {len(loop)}  (127.0.0.1/localhost/::1 in command/env)")
    print(f"  either                  {len(either)} = "
          f"{len(either) * 100 // len(results) if results else 0}% of examined")
    print(f"  declare a 0.0.0.0 bind  {sum(1 for r in results if r.get('any_bind'))}")
    print(f"  say NOTHING about binds {len(silent)}  (the bind is in the image or an app default:")
    print("                            invisible here, and only a runtime census can see it)")
    if unreadable:
        print(f"  unreadable YAML         {len(unreadable)}")
    for r in coll[:10]:
        print(f"    collision  {r['file'][:58]}  {r['declared_collision'][:2]}")
    for r in loop[:10]:
        print(f"    loopback   {r['file'][:58]}  {r['loopback_bind'][:3]}")
    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2)
        except OSError as e:
            print(f"could not write {args.json_out}: {e}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
