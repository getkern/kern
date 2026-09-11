#!/usr/bin/env python3
"""The THIRD number: how many of the shared-loopback files the sharing actually CHANGES.

WHY IT EXISTS. `compose-compat-rate.py` counts 136 files carrying kern's "services share 127.0.0.1"
note, 107 of them carrying nothing else, which makes it the largest single cause between the corpus
and a clean rate. But the note is an ANNOUNCEMENT, not an observed failure: it says the stack was
wired into one network namespace, and for most files that changes nothing a running service can
detect. Two independent reviewers, asked whether the wiring default should change, both answered
that it cannot be decided until somebody measures which of the 136 are actually affected. Neither
the config rate (34%) nor the ceiling (95%) contains that number.

WHAT MAKES A FILE AFFECTED, and it is an observable rather than a reading of the file:

  1. A LOOPBACK-ONLY LISTENER. A service binding `127.0.0.1:N` or `[::1]:N` is private under Docker,
     where every container has its own loopback, and reachable by every peer under a kern pod, where
     they share one. Admin ports, metrics endpoints, debuggers, language inspectors and `pprof` are
     bound this way by default. This is an EXPOSURE the file did not ask for.

  2. A COLLISION ON AN UNDECLARED PORT. Two services binding the same port outside `ports:`/`expose:`
     coexist under Docker and cannot under a pod: the second one to try fails. This is a service the
     file expects to be running and that is not.

Everything else is `notice-only`: the note is true and nothing a process in the stack can observe
differs from Docker.

HOW THE LISTENERS ARE READ. `/proc/net/tcp` and `/proc/net/tcp6` inside a box, which every Linux
image has and no image can lack, rather than `ss` or `netstat`, which most images do not ship. In a
pod every member shares one network namespace, so ONE read from any member sees the whole stack's
listeners: that is the very property being measured.

THE DENOMINATOR IS REPORTED. A corpus file may not come up here at all (an image that no longer
exists, a build context the corpus does not carry, a required `.env`), and a file that did not run
was not measured. Counting it as `notice-only` would be the same defect as counting a refused file
as clean.

WHAT IT STILL CANNOT SEE: a bind that happens after the settle. A debugger port opened on first
request, an admin socket bound after a login, a worker that listens only once a queue is reachable.
Measured with a fixture that binds at t=10s under a 6s settle: reported `notice-only`. The settle is
a bound on the claim, not a property of the stacks.

Usage:
    loopback-census.py <corpus-dir> [--kern PATH] [--timeout S] [--settle S] [--limit N] [--json OUT]
"""

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kernbin

# `/proc/net/tcp` column 4 is the connection state; `0A` is TCP_LISTEN. Column 2 is the local
# address as `<hex addr>:<hex port>`.
LISTEN = "0A"
# A bound, unconnected UDP socket sits in TCP_CLOSE (`07`) in `/proc/net/udp`.
UDP_BOUND = "07"
# IPv4 127.0.0.0/8 in the little-endian hex `/proc/net/tcp` prints: the last byte of the string is
# the FIRST octet of the address, so any loopback address ends in `7F`.
V4_LOOPBACK_SUFFIX = "7F"
# IPv6 `::1`, as `/proc/net/tcp6` prints it (four little-endian words).
V6_LOOPBACK = "00000000000000000000000001000000"
# IPv4-mapped `::ffff:127.0.0.1`.
V6_MAPPED_LOOPBACK_PREFIX = "0000000000000000FFFF0000"

EADDRINUSE = re.compile(
    r"address already in use|EADDRINUSE|addrinuse|bind: address in use|"
    r"failed to bind|cannot bind|could not bind|Address in use",
    re.IGNORECASE,
)


def _is_unconnected(remote):
    """Is this `addr:port` remote end all zeroes, i.e. a bound socket with no peer?"""
    addr, _, port = remote.rpartition(":")
    return set(addr) <= {"0"} and set(port) <= {"0"}


def run(args, timeout, cwd=None):
    """Run a command, never raising. Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except (OSError, subprocess.SubprocessError) as e:
        return 125, "", str(e)


def shares_loopback(kern, path, timeout):
    """Does kern wire this file into ONE namespace, i.e. is it one of the 136?"""
    rc, out, err = run([kern, "compose", "-f", str(path), "config"], timeout)
    if rc != 0:
        return False
    return "this stack runs in ONE shared network namespace" in (out + err)


def project_boxes(kern, timeout):
    """Every running box, as (name, pod) pairs, from the registry rather than from parsed prose."""
    rc, out, _ = run([kern, "ps", "--json"], timeout)
    if rc != 0:
        return []
    try:
        rows = json.loads(out)
    except (ValueError, TypeError):
        return []
    if not isinstance(rows, list):
        return []
    got = []
    for r in rows:
        if isinstance(r, dict) and isinstance(r.get("name"), str):
            got.append((r["name"], r.get("pod") or ""))
    return got


def dead_with_bind_error(kern, path, timeout):
    """The services that are NOT running after the settle and whose own log names a bind failure.

    THE OBSERVABLE FOR THE COLLISION AXIS, and the reason it is not `/proc/net`: the process that
    lost the bind exited, so it owns no socket to be seen. Its log is the only place the loss is
    written, and `kern compose <file> logs <service>` is how it is read from outside the box.

    Returns a list of `(service, first matching line)`.
    """
    rc, out, _ = run([kern, "compose", "-f", str(path), "ps", "--services"], timeout)
    if rc != 0:
        return []
    services = [s.strip() for s in out.splitlines() if s.strip()]
    rc, alive_out, _ = run(
        [kern, "compose", "-f", str(path), "ps", "--format", "json"], timeout
    )
    alive = set()
    if rc == 0:
        for line in alive_out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            name = row.get("name") or ""
            # The box name is `<project>-<service>`; match on the suffix so a project hash in the
            # middle cannot make a live service read as dead.
            for s in services:
                if name.endswith(f"-{s}") or name == s:
                    alive.add(s)
    found = []
    for s in services:
        if s in alive:
            continue
        rc, log_out, log_err = run(
            [kern, "compose", "-f", str(path), "logs", "--tail", "200", s], timeout
        )
        text = log_out + log_err
        m = EADDRINUSE.search(text)
        if m:
            line = next(
                (l for l in text.splitlines() if EADDRINUSE.search(l)), m.group(0)
            )
            found.append((s, line.strip()[:120]))
    return found


def loopback_listeners(kern, box, timeout):
    """The loopback-only listening ports visible inside `box`, or None if they could not be read.

    `None` and an empty list are different answers and are kept apart: a box whose image has no
    `cat` reports nothing, and reading that as "no loopback listeners" would silently move a file
    into the benign bucket.
    """
    rc, out, _ = run(
        [
            kern,
            "exec",
            box,
            "cat",
            "/proc/net/tcp",
            "/proc/net/tcp6",
            # UDP TOO. A statsd or a local syslog on `127.0.0.1:8125` is the same exposure as a TCP
            # admin port, and reading only TCP would have called those files clean.
            "/proc/net/udp",
            "/proc/net/udp6",
        ],
        timeout,
    )
    if rc != 0 or not out.strip():
        return None
    ports = []
    for line in out.splitlines():
        f = line.split()
        # `sl local_address rem_address st …`: at least four columns, and the first must be the
        # `N:` index, which skips both header lines without matching on their text.
        if len(f) < 4 or not f[0].rstrip(":").isdigit():
            continue
        # TCP listens are state `0A`; a UDP socket has no LISTEN state and sits at `07`
        # (TCP_CLOSE) while bound, so for the UDP tables the state is not the filter. The two are
        # told apart by the remote address being all-zero, which is what an unconnected bound
        # socket has.
        if f[3].upper() not in (LISTEN, UDP_BOUND):
            continue
        if f[3].upper() == UDP_BOUND and not _is_unconnected(f[2]):
            continue
        local = f[1]
        if ":" not in local:
            continue
        addr, _, port_hex = local.rpartition(":")
        addr = addr.upper()
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        is_v4_loopback = len(addr) == 8 and addr.endswith(V4_LOOPBACK_SUFFIX)
        is_v6_loopback = addr == V6_LOOPBACK
        is_v6_mapped = addr.startswith(V6_MAPPED_LOOPBACK_PREFIX) and addr.endswith(
            V4_LOOPBACK_SUFFIX
        )
        if is_v4_loopback or is_v6_loopback or is_v6_mapped:
            ports.append(port)
    return sorted(set(ports))


def measure(kern, path, timeout, settle):
    """Bring one file up, let it settle, read what it listens on, tear it down.

    THE SETTLE IS PART OF THE MEASUREMENT. `up -d` waits 150 ms for a service to die and returns;
    a service that binds a moment later has neither opened its socket nor lost its bind by then.
    Measured with a fixture whose loser binds at t=2s: without a settle the census called a REAL
    collision `notice-only`, which is the blind bucket this probe exists to avoid.
    """
    verdict = {"file": path.name, "bucket": "not-measured", "detail": "", "ports": []}
    up_rc, up_out, up_err = run(
        [kern, "compose", "-f", str(path), "up", "-d"], timeout, cwd=str(path.parent)
    )
    text = up_out + up_err
    try:
        if up_rc == 0:
            time.sleep(settle)
        if up_rc != 0:
            # A stack that did not come up was not measured. The FIRST line of the reason is kept so
            # the buckets can be audited rather than trusted.
            first = next(
                (l for l in text.splitlines() if l.startswith("error:")), "up failed"
            )
            # A service that died ON A PORT is a measurement, not a failure to measure: that is
            # exactly the collision this census is looking for.
            if EADDRINUSE.search(text):
                verdict.update(bucket="collision", detail=first[:160])
                return verdict
            verdict.update(bucket="not-measured", detail=first[:160])
            return verdict
        boxes = [(n, p) for (n, p) in project_boxes(kern, timeout) if p]
        if not boxes:
            verdict.update(bucket="not-measured", detail="no running box after up")
            return verdict
        ports = None
        for name, _pod in boxes:
            ports = loopback_listeners(kern, name, timeout)
            if ports is not None:
                break
        if ports is None:
            verdict.update(
                bucket="not-measured", detail="no box could read /proc/net/tcp"
            )
            return verdict
        # THE COLLISION AXIS FIRST, because it is the stronger finding: a service the file expects
        # to be running is not, and the reason is the shared namespace. A file can carry both; the
        # bucket names the worse one.
        dead = dead_with_bind_error(kern, path, timeout)
        if dead:
            who = ", ".join(f"{s}: {line}" for s, line in dead[:2])
            verdict.update(bucket="collision", detail=who[:160])
            return verdict
        if ports:
            verdict.update(
                bucket="loopback-semantic",
                detail=f"loopback-only listeners on {ports}",
                ports=ports,
            )
        elif EADDRINUSE.search(text):
            verdict.update(bucket="collision", detail="a service failed to bind (from `up`)")
        else:
            verdict.update(bucket="notice-only", detail="no loopback-only listener, none died")
        return verdict
    finally:
        run([kern, "compose", "-f", str(path), "down"], timeout, cwd=str(path.parent))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", type=pathlib.Path)
    ap.add_argument("--kern", default="target/release/kern")
    ap.add_argument("--timeout", type=int, default=90)
    ap.add_argument(
        "--settle",
        type=float,
        default=6.0,
        help="seconds to wait after `up` before reading (a late bind is invisible before it)",
    )
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--json", dest="json_out", default="")
    args = ap.parse_args()

    rc = kernbin.require_current(args.kern)
    if rc:
        return rc
    # ABSOLUTE, because every `up` below runs with `cwd` set to the compose file's directory so
    # relative binds and build contexts resolve as Docker resolves them. A relative `target/...`
    # would then name nothing, and the whole census would report 41 stacks that "did not come up"
    # in zero seconds. It did exactly that once.
    kern = os.path.abspath(args.kern)

    files = sorted(p for p in args.corpus.iterdir() if p.is_file())
    if not files:
        print(f"no compose files under {args.corpus}", file=sys.stderr)
        return 2

    started = time.time()
    shared = []
    for f in files:
        if shares_loopback(kern, f, args.timeout):
            shared.append(f)
    print(f"files kern wires into ONE namespace: {len(shared)} of {len(files)}", flush=True)
    if args.limit:
        shared = shared[: args.limit]

    results = []
    for i, f in enumerate(shared, 1):
        v = measure(kern, f, args.timeout, args.settle)
        results.append(v)
        print(f"  [{i}/{len(shared)}] {v['bucket']:18} {f.name[:60]}", flush=True)

    buckets = {}
    for v in results:
        buckets[v["bucket"]] = buckets.get(v["bucket"], 0) + 1
    measured = sum(n for b, n in buckets.items() if b != "not-measured")
    print(f"\nmeasured {measured} of {len(shared)} in {time.time() - started:.0f}s")
    for b in ("loopback-semantic", "collision", "notice-only", "not-measured"):
        n = buckets.get(b, 0)
        share = f" = {n * 100 // measured}% of measured" if measured and b != "not-measured" else ""
        print(f"  {n:4d}  {b}{share}")
    print(
        "\nloopback-semantic + collision is the part of the shared-loopback cause that a process in "
        "the stack can observe. notice-only is the part that cannot."
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
