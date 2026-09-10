#!/usr/bin/env python3
"""The SECOND number: what a stack is like from INSIDE, not what `config` says about the file.

WHY IT EXISTS. `compose-compat-rate.py` reads kern's own warnings at `config`, which makes it blind
by construction to every difference kern does not know it has, and blind by ROUTE to everything that
only exists once a box is running. Measured: the seven defects closed in one week - a health probe
running as box root and in `/`, `HOME=/root` for every user, cleared supplementary groups, an
`ipv4_address` nobody could route to, an empty `HOSTNAME`, a privileged port shifted per box, a
`-v` refused with `Invalid argument` and nothing else - moved that rate by ZERO points. Every one of
them was found by running a stack and looking inside it.

So this measures the other half, with the same discipline: each probe is an observable read from
inside a live box or from the timing of a real teardown, never a substring of a log line, and each
probe has a BROKEN fixture that it must report as failing. A probe that cannot go red measures
nothing, and `--self-test` is what proves it can.

Usage:
    e2e-semantic.py [--kern PATH] [--json] [--only NAME]   run the battery
    e2e-semantic.py --self-test [--kern PATH]              prove each probe can fail

Exit status is 0 when every probe passes (or is skipped), 1 otherwise, so it can gate a build.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

IMAGE = os.environ.get("KERN_E2E_IMAGE", "alpine:3.19")


class Probe:
    """One observable, its fixture, and the fixture that must make it fail.

    `compose_ok` and `compose_broken` are functions of the scratch directory, so a fixture can write
    the files it needs beside its compose file. `check` receives the scratch directory and returns
    `(passed, detail)`; raising is a FAILURE, never a crash of the battery.
    """

    def __init__(self, name, why, compose_ok, compose_broken, check, settle=4.0):
        self.name = name
        self.why = why
        self.compose_ok = compose_ok
        self.compose_broken = compose_broken
        self.check = check
        self.settle = settle


def run(kern, args, cwd, timeout=180):
    """Run kern, returning (rc, stdout, stderr). Never raises on a non-zero status."""
    try:
        p = subprocess.run(
            [kern] + args, cwd=cwd, capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def out_dir(scratch):
    d = os.path.join(scratch, "out")
    os.makedirs(d, exist_ok=True)
    # World-writable: the workload runs as a mapped uid that is not this user, so a directory only
    # this user can write is a probe that fails for the wrong reason.
    os.chmod(d, 0o777)
    return d


def read(scratch, name):
    try:
        with open(os.path.join(scratch, "out", name), encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


# --------------------------------------------------------------------------------------------
# 1. The health probe runs as the workload, in the workload's directory.
# --------------------------------------------------------------------------------------------
def fx_identity(scratch, user=True):
    out_dir(scratch)
    who = '    user: "1000:1000"\n' if user else ""
    return f"""services:
  s:
    image: {IMAGE}
{who}    working_dir: /tmp
    volumes: ["{scratch}/out:/out"]
    healthcheck:
      # `$$` THROUGHOUT: a single `$` is a COMPOSE variable and is substituted from the host
      # environment before the box ever sees it. The same trap cost two earlier measurements in this
      # project, and the self-test caught the third: a probe reading `$HOME` was reading the HOST's.
      test: ["CMD-SHELL", "echo $$(id -u):$$(id -g):$$(pwd) > /out/whoami; true"]
      interval: 1s
    command: ["sleep", "20"]
"""


def ck_identity(scratch):
    got = read(scratch, "whoami")
    if not got:
        return None, "the probe never wrote its identity"
    return got == "1000:1000:/tmp", f"probe ran as {got}, expected 1000:1000:/tmp"


# --------------------------------------------------------------------------------------------
# 2. `mem_limit` is the number the kernel enforces.
# --------------------------------------------------------------------------------------------
def fx_memory(scratch, limit="256m"):
    out_dir(scratch)
    return f"""services:
  s:
    image: {IMAGE}
    mem_limit: {limit}
    volumes: ["{scratch}/out:/out"]
    command: ["sh", "-c", "cat /sys/fs/cgroup/memory.max > /out/memmax; sleep 10"]
"""


def ck_memory(scratch):
    got = read(scratch, "memmax")
    if not got:
        return None, "memory.max was not readable in the box"
    return got == "268435456", f"memory.max={got}, expected 268435456 for mem_limit: 256m"


# --------------------------------------------------------------------------------------------
# 3. `ulimits` reach the workload.
# --------------------------------------------------------------------------------------------
def fx_ulimit(scratch, nofile=1234):
    out_dir(scratch)
    return f"""services:
  s:
    image: {IMAGE}
    ulimits:
      nofile: {nofile}
    volumes: ["{scratch}/out:/out"]
    command: ["sh", "-c", "ulimit -n > /out/nofile; sleep 10"]
"""


def ck_ulimit(scratch):
    got = read(scratch, "nofile")
    if not got:
        return None, "ulimit -n was not readable in the box"
    return got == "1234", f"ulimit -n={got}, expected 1234"


# --------------------------------------------------------------------------------------------
# 4. A teardown signals dependents before dependencies, and waits.
# --------------------------------------------------------------------------------------------
def fx_down_order(scratch, depends=True):
    out_dir(scratch)
    dep = "    depends_on: [b]\n" if depends else ""
    trap = (
        "trap 'echo {n}-GOT $(cut -d\" \" -f1 /proc/uptime) >> /out/order; sleep 2; "
        "echo {n}-DONE $(cut -d\" \" -f1 /proc/uptime) >> /out/order' TERM; sleep 999 & wait"
    )
    return f"""services:
  b:
    image: {IMAGE}
    stop_grace_period: 8s
    volumes: ["{scratch}/out:/out"]
    command: ["sh", "-c", "{trap.format(n='B')}"]
  a:
    image: {IMAGE}
    stop_grace_period: 8s
{dep}    volumes: ["{scratch}/out:/out"]
    command: ["sh", "-c", "{trap.format(n='A')}"]
"""


def ck_down_order(scratch):
    # Written by the traps during the teardown, which the runner performs before the check.
    t = {}
    for line in read(scratch, "order").splitlines():
        parts = line.split()
        if len(parts) == 2:
            t[parts[0]] = float(parts[1])
    if not {"A-DONE", "B-GOT"} <= set(t):
        return None, f"the traps did not both run: {sorted(t)}"
    # `<=` AND NOT `<`, because the clock is `/proc/uptime` and its resolution is a centisecond:
    # when the ordering is correct B is signalled the instant A exits, which lands in the same tick.
    # The broken shape is not a tick away, it is the whole trap away (B is signalled ~2 s BEFORE A
    # finishes), so one tick of tolerance discriminates without weakening anything.
    gap = t["B-GOT"] - t["A-DONE"]
    return (
        gap >= -0.01,
        f"A finished at {t['A-DONE']:.2f}, B was signalled at {t['B-GOT']:.2f} (gap {gap:+.2f}s)",
    )


# --------------------------------------------------------------------------------------------
# 5. A peer answers on its service name.
# --------------------------------------------------------------------------------------------
def fx_peer(scratch, same_network=True):
    out_dir(scratch)
    if same_network:
        nets_srv = nets_cli = ""
        tail = ""
    else:
        nets_srv = "    networks: [front]\n"
        nets_cli = "    networks: [back]\n"
        tail = "networks:\n  front:\n  back:\n"
    return f"""services:
  srv:
    image: {IMAGE}
    expose: ["8099"]
{nets_srv}    command: ["sh", "-c", "while :; do echo PONG | nc -l -p 8099; done"]
  cli:
    image: {IMAGE}
    depends_on: [srv]
{nets_cli}    volumes: ["{scratch}/out:/out"]
    command: ["sh", "-c", "sleep 3; (echo | nc -w 3 srv 8099) > /out/peer 2>/dev/null; sleep 6"]
{tail}"""


def ck_peer(scratch):
    got = read(scratch, "peer")
    return got == "PONG", f"peer answered {got!r}, expected 'PONG'"


# --------------------------------------------------------------------------------------------
# 6. HOME follows the user the box runs as.
# --------------------------------------------------------------------------------------------
def fx_home(scratch, user=True):
    out_dir(scratch)
    who = '    user: "1000:1000"\n' if user else ""
    return f"""services:
  s:
    image: {IMAGE}
{who}    volumes: ["{scratch}/out:/out"]
    command: ["sh", "-c", "echo $$HOME > /out/home; sleep 10"]
"""


def ck_home(scratch):
    got = read(scratch, "home")
    if not got:
        return None, "HOME was not readable in the box"
    # The image has no passwd entry for 1000, so the answer is runc's default user home. What must
    # NOT happen is the box-root home leaking to a non-root workload.
    return got != "/root", f"HOME={got} for a non-root user"


# --------------------------------------------------------------------------------------------
# 7. A named volume belongs to ONE project.
# --------------------------------------------------------------------------------------------
def volumes_dir():
    """Where kern keeps named volumes, derived the same way kern derives it."""
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share"
    )
    return os.path.join(base, "kern", "volumes")


def fx_volume_scope(scratch, named=True):
    """Write a marker into a NAMED volume (good) or into a host bind (broken).

    The broken fixture is not a mutilated version of the good one: it is the same stack writing to a
    bind mount, so the marker exists but NOT inside a project-scoped named volume - which is exactly
    what the check is looking for, and exactly what kern did before volumes were scoped.
    """
    out_dir(scratch)
    if named:
        mount, decl = "e2evol:/v", "volumes:\n  e2evol:\n"
    else:
        mount, decl = f"{scratch}/out:/v", ""
    return f"""services:
  s:
    image: {IMAGE}
    volumes: ["{mount}"]
    command: ["sh", "-c", "echo MARKER > /v/marker; sleep 8"]
{decl}"""


def ck_volume_scope(scratch):
    """The marker must land in `<project>_e2evol`, never in a bare `e2evol` every stack shares.

    MEASURED before this was fixed: two projects declaring the same volume name mounted ONE
    directory, so project B read project A's data (Docker 29.6.2 prints EMPTY for the same pair and
    holds `pa_shared` + `pb_shared`).
    """
    root = volumes_dir()
    if not os.path.isdir(root):
        return None, f"no volumes directory at {root}"
    scoped, bare = [], False
    for name in os.listdir(root):
        if not name.endswith("e2evol"):
            continue
        if os.path.isfile(os.path.join(root, name, "data", "marker")):
            if name == "e2evol":
                bare = True
            else:
                scoped.append(name)
    for name in scoped + (["e2evol"] if bare else []):
        shutil.rmtree(os.path.join(root, name), ignore_errors=True)
    if bare:
        return False, "the marker landed in the UNSCOPED volume 'e2evol', shared by every stack"
    if not scoped:
        return False, "no project-scoped volume holds the marker"
    return True, f"marker is in {scoped[0]}"


PROBES = [
    Probe(
        "identity_healthcheck",
        "a health probe must run as the workload, in its working directory",
        lambda s: fx_identity(s, True),
        lambda s: fx_identity(s, False),
        ck_identity,
        settle=5.0,
    ),
    Probe(
        "cgroup_memory_max",
        "mem_limit must be the number the kernel enforces",
        lambda s: fx_memory(s, "256m"),
        lambda s: fx_memory(s, "128m"),
        ck_memory,
    ),
    Probe(
        "ulimit_nofile",
        "ulimits must reach the workload",
        lambda s: fx_ulimit(s, 1234),
        lambda s: fx_ulimit(s, 4321),
        ck_ulimit,
    ),
    Probe(
        "down_order",
        "a teardown signals dependents before dependencies and waits for them",
        lambda s: fx_down_order(s, True),
        lambda s: fx_down_order(s, False),
        ck_down_order,
        settle=3.0,
    ),
    Probe(
        "peer_tcp_by_name",
        "a peer must answer on its service name",
        lambda s: fx_peer(s, True),
        lambda s: fx_peer(s, False),
        ck_peer,
        settle=9.0,
    ),
    Probe(
        "home_follows_user",
        "HOME must follow the user the box runs as",
        lambda s: fx_home(s, True),
        lambda s: fx_home(s, False),
        ck_home,
    ),
    Probe(
        "volume_belongs_to_the_project",
        "a named volume must belong to one project, not to every stack that uses the name",
        lambda s: fx_volume_scope(s, True),
        lambda s: fx_volume_scope(s, False),
        ck_volume_scope,
        settle=5.0,
    ),
]


def run_probe(kern, probe, broken=False):
    """Bring one fixture up, let it settle, tear it down, then check. Returns (status, detail)."""
    scratch = tempfile.mkdtemp(prefix="kern-e2e-")
    try:
        body = probe.compose_broken(scratch) if broken else probe.compose_ok(scratch)
        path = os.path.join(scratch, "docker-compose.yml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        rc, _, err = run(kern, ["compose", "docker-compose.yml", "up", "-d"], scratch)
        if rc != 0:
            # A fixture kern REFUSES is not a failed probe: it is a stack that never ran, and
            # counting it as a difference would blame the runtime for the fixture.
            run(kern, ["compose", "docker-compose.yml", "down"], scratch)
            return "skip", f"the fixture did not come up: {err.strip().splitlines()[-1:]}"
        time.sleep(probe.settle)
        # The teardown is part of the measurement for the ordering probe, and harmless for the rest:
        # every check reads a file the workload has already written.
        run(kern, ["compose", "docker-compose.yml", "down"], scratch)
        try:
            ok, detail = probe.check(scratch)
        except Exception as e:  # a probe that throws is a probe that failed, not a crashed battery
            return "fail", f"the check raised: {e}"
        if ok is None:
            return "skip", detail
        return ("pass" if ok else "fail"), detail
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kern", default="./target/debug/kern")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--only")
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="run each probe against its BROKEN fixture; every one must report fail",
    )
    args = ap.parse_args()
    # ABSOLUTE, because every fixture runs with its own scratch directory as the working directory:
    # a relative path would resolve against the fixture and vanish.
    kern = os.path.abspath(args.kern)
    if not os.path.exists(kern):
        print(f"no kern binary at {kern}", file=sys.stderr)
        return 2
    probes = [p for p in PROBES if not args.only or p.name == args.only]

    if args.self_test:
        bad = []
        for p in probes:
            status, detail = run_probe(kern, p, broken=True)
            print(f"  {p.name:24} broken fixture -> {status}  ({detail})")
            if status != "fail":
                bad.append(p.name)
        if bad:
            print(f"\n{len(bad)} probe(s) could not go red: {', '.join(bad)}")
            print("a probe that cannot fail measures nothing")
            return 1
        print(f"\n{len(probes)} probes, each red on its broken fixture")
        return 0

    results = []
    for p in probes:
        status, detail = run_probe(kern, p)
        results.append({"probe": p.name, "status": status, "detail": detail, "why": p.why})
    npass = sum(1 for r in results if r["status"] == "pass")
    nfail = sum(1 for r in results if r["status"] == "fail")
    nskip = sum(1 for r in results if r["status"] == "skip")
    rate = npass / (npass + nfail) if (npass + nfail) else 0.0
    if args.json:
        print(json.dumps({"probes": results, "pass": npass, "fail": nfail, "skip": nskip,
                          "e2e": round(rate, 4)}, indent=2))
    else:
        for r in results:
            mark = {"pass": "ok  ", "fail": "FAIL", "skip": "skip"}[r["status"]]
            print(f"  {mark} {r['probe']:24} {r['detail']}")
        print(f"\ne2e-semantic: {npass}/{npass + nfail} = {rate * 100:.0f}%"
              f"{f' ({nskip} skipped)' if nskip else ''}")
        print("this number moves when a runtime difference is closed; the config rate does not")
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
