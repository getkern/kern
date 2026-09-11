#!/usr/bin/env python3
"""The end-to-end rehearsal: ten real stacks up and down, interrupted, killed, and counted.

WHY THIS EXISTS AND WHAT IT IS NOT. The compatibility rate reads what `compose config` SAYS about a
file. It is blind to everything that only happens when a stack actually runs: a service that starts
and dies, a peer that resolves but answers nothing, a NAT nobody stopped, a process left behind by an
interrupt. This runs stacks. It is slower by three orders of magnitude and it is the only thing here
that can answer "does it work".

THE CENSUS IS THE POINT, NOT THE BRING-UP. Every phase is bracketed by a count of what kern leaves on
the machine - boxes, pods, NAT processes, relay directories, stack cgroups and host veth interfaces -
and every phase must return that count to exactly where it started. A stack that comes up and works
while leaking one process per run is a stack that fails on the twentieth demo, and nothing short of
counting finds that.

WHAT IT COVERS, in the order a live demo meets it:

  1. identity      the binary under test is the working tree's, not an older build
  2. baseline      what is on this machine before anything runs
  3. stacks        ten real-world shapes, brought up, probed from INSIDE, torn down
  4. interrupt     Ctrl+C on an attached `up`, on a real controlling terminal
  5. kill          SIGKILL of `up` mid-bring-up, and whether `down` still recovers
  6. sdk           the Python wrapper: no binary, then a real run
  7. residue       the machine is exactly where it started

EVERY FAILURE IS LOUD AND THE EXIT CODE IS NON-ZERO. A rehearsal that reports success on a phase it
skipped is worse than no rehearsal, so a phase that cannot run says SKIP with its reason and is
counted apart from the ones that passed.

Usage:
    launch-dryrun.py [--kern PATH] [--only PHASE] [--keep-going] [--stack NAME]
"""

import argparse
import os
import pty
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kernbin

# How long a stack gets to bring every service up before the probe gives up. Generous: some of these
# images (postgres, mariadb, elasticsearch) initialise a data directory on first run.
SETTLE_S = 12.0
# How long `down` gets. A stack whose teardown needs longer than this has a problem of its own.
DOWN_S = 180

# ----------------------------------------------------------------------------------------------
# THE STACKS. Ten shapes taken from what people actually write, each using an image this machine can
# be expected to hold. `probe` runs INSIDE the named service and must print the expected token: a
# stack that comes up and cannot talk to itself is not a stack that works.
#
# WHY THE PROBES REACH A PEER BY NAME. That single act exercises the whole wiring - the address plan,
# the hosts entries, the bridge or the relays - and it is the first thing a user does. A probe that
# only asked "is the process alive" would pass on a stack whose services cannot find each other,
# which is the failure this suite exists to catch.
# ----------------------------------------------------------------------------------------------
STACKS = [
    (
        "python-postgres-redis",
        """
services:
  db:
    image: postgres:13
    environment:
      POSTGRES_PASSWORD: secret
      POSTGRES_USER: app
      POSTGRES_DB: app
    volumes:
      - pgdata:/var/lib/postgresql/data
  cache:
    image: redis:7
    command: ["redis-server", "--save", ""]
  web:
    image: python:3.10-alpine
    command: ["sh", "-c", "sleep 120"]
    depends_on:
      - db
      - cache
    environment:
      DATABASE_URL: postgres://app:secret@db:5432/app
volumes:
  pgdata:
""",
        "web",
        "nc -z -w3 db 5432 && nc -z -w3 cache 6379 && echo BOTH-REACHABLE",
        "BOTH-REACHABLE",
    ),
    (
        "node-mongo",
        """
services:
  mongo:
    image: mongo:4.2.0
    command: ["mongod", "--bind_ip_all"]
  api:
    image: node:12-alpine
    command: ["sh", "-c", "sleep 120"]
    depends_on:
      - mongo
""",
        "api",
        "nc -z -w3 mongo 27017 && echo MONGO-REACHABLE",
        "MONGO-REACHABLE",
    ),
    (
        "wordpress-mariadb",
        """
services:
  db:
    image: mariadb:11
    environment:
      MARIADB_ROOT_PASSWORD: rootpw
      MARIADB_DATABASE: wp
      MARIADB_USER: wp
      MARIADB_PASSWORD: wppw
  wordpress:
    image: wordpress:latest
    depends_on:
      - db
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: wp
      WORDPRESS_DB_PASSWORD: wppw
      WORDPRESS_DB_NAME: wp
    ports:
      - "8080:80"
""",
        "wordpress",
        "getent hosts db && echo DB-RESOLVES",
        "DB-RESOLVES",
    ),
    (
        "nginx-two-backends-same-port",
        """
services:
  proxy:
    image: nginx:alpine
    ports:
      - "8081:80"
  backend_a:
    image: nginx:alpine
  backend_b:
    image: nginx:alpine
""",
        "proxy",
        "nc -z -w3 backend_a 80 && nc -z -w3 backend_b 80 && echo BOTH-ON-80",
        "BOTH-ON-80",
    ),
    (
        "rabbitmq-worker",
        """
services:
  broker:
    image: rabbitmq:3-management
  worker:
    image: python:3.10-alpine
    command: ["sh", "-c", "sleep 120"]
    depends_on:
      - broker
""",
        "worker",
        "getent hosts broker && echo BROKER-RESOLVES",
        "BROKER-RESOLVES",
    ),
    (
        "memcached-app",
        """
services:
  cache:
    image: memcached:1.6.45-alpine
  app:
    image: alpine:latest
    command: ["sh", "-c", "sleep 120"]
    depends_on:
      - cache
""",
        "app",
        "nc -z -w3 cache 11211 && echo CACHE-REACHABLE",
        "CACHE-REACHABLE",
    ),
    (
        "adminer-postgres",
        """
services:
  db:
    image: postgres:13
    environment:
      POSTGRES_PASSWORD: secret
  adminer:
    image: adminer:latest
    ports:
      - "8082:8080"
    depends_on:
      - db
""",
        "adminer",
        "getent hosts db && echo DB-RESOLVES",
        "DB-RESOLVES",
    ),
    (
        "healthcheck-gate",
        """
services:
  db:
    image: postgres:13
    environment:
      POSTGRES_PASSWORD: secret
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 2s
      timeout: 3s
      retries: 10
  app:
    image: alpine:latest
    command: ["sh", "-c", "sleep 120"]
    depends_on:
      db:
        condition: service_healthy
""",
        "app",
        "nc -z -w3 db 5432 && echo DB-HEALTHY-AND-UP",
        "DB-HEALTHY-AND-UP",
    ),
    (
        "named-volume-and-bind",
        """
services:
  writer:
    image: alpine:latest
    command: ["sh", "-c", "echo written > /data/marker; sleep 120"]
    volumes:
      - shared:/data
  reader:
    image: alpine:latest
    command: ["sh", "-c", "sleep 120"]
    volumes:
      - shared:/data
volumes:
  shared:
""",
        "reader",
        "sleep 2; cat /data/marker",
        "written",
    ),
    (
        "segregated-networks",
        """
services:
  front:
    image: alpine:latest
    command: ["sh", "-c", "sleep 120"]
    networks: [pub]
  api:
    image: alpine:latest
    command: ["sh", "-c", "while true; do echo API | nc -l -p 7000; done"]
    expose: ["7000"]
    networks: [pub]
  secret:
    image: alpine:latest
    command: ["sh", "-c", "sleep 120"]
    networks: [priv]
networks:
  pub: {}
  priv: {}
""",
        "front",
        "nc -w3 api 7000",
        "API",
    ),
]


def _services_listed(ps_out):
    """How many services `compose ps` reports as running, in EITHER shape it prints.

    A POD STACK IS A TREE and a relay stack is a FLAT LIST, and counting only the tree read a running
    three-service stack as zero - measured, on the `segregated-networks` case, where the probe
    answered from inside a stack this function had just called empty. A census that can be wrong in
    the quiet direction is worse than none: it reports success.
    """
    n = 0
    for line in ps_out.splitlines():
        if line.startswith("\u251c\u2500 ") or line.startswith("\u2514\u2500 "):
            n += 1
            continue
        # The flat shape: `NAME PID UPTIME …`, where the second field is a pid. The header and every
        # note kern prints fail that test.
        parts = line.split()
        if len(parts) >= 3 and parts[1].isdigit() and not line.startswith(" "):
            n += 1
    return n


def _services_declared(doc):
    """How many services the compose document declares, by its own indentation."""
    n, in_services = 0, False
    for line in doc.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            in_services = line.rstrip() == "services:"
            continue
        if in_services and line.startswith("  ") and not line.startswith("    "):
            if line.rstrip().endswith(":"):
                n += 1
    return n


class Census:
    """What kern has left on this machine, as numbers that must come back to where they started."""

    __slots__ = ("boxes", "pods", "nats", "relays", "cgroups", "veth")

    def __init__(self, boxes, pods, nats, relays, cgroups, veth):
        self.boxes, self.pods, self.nats = boxes, pods, nats
        self.relays, self.cgroups, self.veth = relays, cgroups, veth

    def __eq__(self, other):
        return all(
            getattr(self, f) == getattr(other, f) for f in self.__slots__
        )

    def __str__(self):
        return (
            f"box={self.boxes} pod={self.pods} nat={self.nats} "
            f"relay={self.relays} cgroup={self.cgroups} veth={self.veth}"
        )

    def diff(self, other):
        """The fields that moved, as `name: before -> after`, or an empty list."""
        return [
            f"{f}: {getattr(other, f)} -> {getattr(self, f)}"
            for f in self.__slots__
            if getattr(self, f) != getattr(other, f)
        ]


def _pasta_count():
    """Every `pasta`/`passt` this user is running, read from /proc rather than from `pgrep -f`.

    `pgrep -f` matches the whole command line, so a shell whose own arguments contain the word counts
    itself - measured while writing this suite, where a sweep loop matched its own `pgrep` and its
    own shell. argv[0]'s FILE NAME is the only thing that says what a process IS.
    """
    n = 0
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            argv = open(f"/proc/{d}/cmdline", "rb").read().split(b"\x00")
        except OSError:
            continue
        if argv and os.path.basename(argv[0] or b"") in (b"pasta", b"passt"):
            n += 1
    return n


def _runtime_root():
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    return os.path.join(base, "kern")


def _count_dir(path):
    try:
        return len(os.listdir(path))
    except OSError:
        return 0


def _veth_count():
    """Host-namespace interfaces of the shape kern gives a bridge member (`kv<pid>`/`kp<pid>`).

    kern builds these INSIDE a pod's namespace, so a host-side one is by definition a leak: a pair
    whose far end was never placed, or whose namespace went without it.
    """
    try:
        names = os.listdir("/sys/class/net")
    except OSError:
        return 0
    return sum(1 for n in names if (n.startswith("kv") or n.startswith("kp")) and n[2:].isdigit())


def _cgroup_count():
    """kern's own cgroups under the user slice, which is where a leaked box's caps would remain."""
    n = 0
    for root, dirs, _ in os.walk("/sys/fs/cgroup", topdown=True):
        # Bounded walk: the user slice only, and not into every box's children.
        if root.count(os.sep) > 8:
            dirs[:] = []
            continue
        for d in dirs:
            if d.startswith("kern-box-") or d.startswith("kern.slice"):
                n += 1
    return n


def census(kern, env):
    boxes = 0
    try:
        r = subprocess.run([kern, "ps"], capture_output=True, text=True, timeout=60, env=env)
        boxes = sum(1 for l in r.stdout.splitlines() if l.startswith("\u251c\u2500 ") or l.startswith("\u2514\u2500 "))
    except (OSError, subprocess.SubprocessError):
        boxes = -1
    root = _runtime_root()
    return Census(
        boxes=boxes,
        pods=_count_dir(os.path.join(root, "pods")),
        nats=_pasta_count(),
        relays=_count_dir(os.path.join(root, "relays")),
        cgroups=_cgroup_count(),
        veth=_veth_count(),
    )


class Report:
    def __init__(self, keep_going):
        self.passed, self.failed, self.skipped = [], [], []
        self.keep_going = keep_going

    def ok(self, name, detail=""):
        self.passed.append(name)
        print(f"  \u2713 {name:<34} {detail}", flush=True)

    def skip(self, name, why):
        self.skipped.append((name, why))
        print(f"  - {name:<34} SKIP: {why}", flush=True)

    def fail(self, name, why):
        self.failed.append((name, why))
        print(f"  \u2717 {name:<34} FAIL: {why}", flush=True)
        if not self.keep_going:
            raise SystemExit(self.finish())

    def finish(self):
        print(
            f"\n{len(self.passed)} passed, {len(self.failed)} failed, {len(self.skipped)} skipped"
        )
        for name, why in self.failed:
            print(f"  FAILED {name}: {why}")
        return 1 if self.failed else 0


def compose(kern, workdir, env, args, timeout=DOWN_S):
    """One `kern compose` invocation in `workdir`. Returns (combined output, ok)."""
    try:
        r = subprocess.run(
            [kern, "compose", "-f", "docker-compose.yml", *args],
            cwd=workdir, capture_output=True, text=True, timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        return (f"TIMEOUT after {timeout}s", False)
    except OSError as e:
        return (str(e), False)
    return (r.stdout + r.stderr, r.returncode == 0)


def run_stack(kern, env, report, name, doc, probe_svc, probe_cmd, expect, base):
    work = tempfile.mkdtemp(prefix=f"kern-dryrun-{name}-")
    try:
        with open(os.path.join(work, "docker-compose.yml"), "w", encoding="utf-8") as fh:
            fh.write(doc.lstrip())
        out, ok = compose(kern, work, env, ["up", "-d"])
        if not ok:
            # A missing image is the host's state, not a defect: say so and move on, rather than
            # reporting a failure the reader cannot act on.
            if "could not resolve" in out or "no such image" in out or "manifest" in out:
                # NAME THE IMAGE. A generic "an image is missing" reads the same whether the host
                # lacks a cached layer or this file has a typo in a fixture, and only one of those is
                # the reader's problem.
                missing = [
                    l.split("image:")[1].strip()
                    for l in doc.splitlines()
                    if l.strip().startswith("image:")
                ]
                report.skip(
                    name,
                    "an image is not in this machine's cache (this stack wants: "
                    + ", ".join(sorted(set(missing)))
                    + ")",
                )
                compose(kern, work, env, ["down"])
                return
            report.fail(name, f"`up` failed: {out.strip().splitlines()[-1][:160] if out.strip() else 'no output'}")
            compose(kern, work, env, ["down"])
            return
        time.sleep(SETTLE_S)
        # EVERY SERVICE MUST BE RUNNING, not just the one the probe enters: a stack that lost a
        # service and still answers its probe is a stack that is half down.
        ps_out, _ = compose(kern, work, env, ["ps"])
        alive = _services_listed(ps_out)
        # HOW MANY THE FILE ASKS FOR: a top-level key under `services:`, which at this indentation is
        # a service name and nothing else.
        want = _services_declared(doc)
        probe_out, _ = compose(
            kern, work, env,
            ["exec", "-T", probe_svc, "sh", "-c", probe_cmd],
            timeout=90,
        )
        compose(kern, work, env, ["down"])
        time.sleep(1.5)
        after = census(kern, env)
        moved = after.diff(base)
        if expect not in probe_out:
            report.fail(
                name,
                f"the probe in '{probe_svc}' did not answer {expect!r}: {probe_out.strip()[-160:]!r}",
            )
            return
        if moved:
            report.fail(name, "the stack left residue behind: " + ", ".join(moved))
            return
        if alive < want:
            report.fail(
                name,
                f"only {alive} of {want} service(s) were listed as running, yet the probe answered: "
                "one of the two is lying and both are worth knowing about",
            )
            return
        report.ok(name, f"{alive}/{want} services up, probe answered, residue clean")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def phase_interrupt(kern, env, report, base):
    """Ctrl+C on an ATTACHED `up`, through a real controlling terminal.

    A PTY IS NOT OPTIONAL HERE. kern only attaches when stdout is a terminal, so an `up` run with a
    pipe returns immediately after the bring-up and the interrupt path is never reached. Measured
    while writing this: the same test through a pipe reported a clean pass while exercising nothing.

    `pty.fork` and not `openpty` + `Popen`, because the child must be a session leader with the pty
    as its CONTROLLING terminal, or the INTR character produces no signal at all - measured, with
    `tcsetpgrp` answering ENOTTY and the process living on.
    """
    work = tempfile.mkdtemp(prefix="kern-dryrun-intr-")
    try:
        with open(os.path.join(work, "docker-compose.yml"), "w", encoding="utf-8") as fh:
            fh.write(
                "services:\n"
                "  a:\n    image: alpine:latest\n    command: [\"sh\", \"-c\", \"sleep 120\"]\n"
                "  b:\n    image: alpine:latest\n    command: [\"sh\", \"-c\", \"sleep 120\"]\n"
                "  c:\n    image: alpine:latest\n    command: [\"sh\", \"-c\", \"sleep 120\"]\n"
            )
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.chdir(work)
                for k, v in env.items():
                    os.environ[k] = v
                os.execv(kern, [kern, "compose", "-f", "docker-compose.yml", "up"])
            except OSError:
                pass
            os._exit(127)
        time.sleep(6.0)
        during = census(kern, env)
        if during.boxes < 3:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            compose(kern, work, env, ["down"])
            report.skip("interrupt", f"the stack did not come up ({during})")
            return
        t0 = time.time()
        os.write(fd, b"\x03")
        status = None
        # READ TO EOF, THEN REAP. An EIO on the master is the end of the OUTPUT, not the end of the
        # wait: breaking out there and never calling waitpid leaves an already-exited process in Z
        # and reads as "it never exited" - measured, and it cost an hour chasing a defect that was
        # this harness's.
        while time.time() - t0 < 30:
            try:
                r, _, _ = select.select([fd], [], [], 0.3)
                if r and not os.read(fd, 65536):
                    break
            except OSError:
                break
        while time.time() - t0 < 30:
            w, st = os.waitpid(pid, os.WNOHANG)
            if w == pid:
                status = st
                break
            time.sleep(0.1)
        elapsed = time.time() - t0
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            compose(kern, work, env, ["down"])
            report.fail("interrupt", f"`up` did not exit within {elapsed:.0f}s of Ctrl+C")
            return
        os.close(fd)
        time.sleep(2.0)
        after = census(kern, env)
        moved = after.diff(base)
        if moved:
            compose(kern, work, env, ["down"])
            report.fail("interrupt", "Ctrl+C left residue: " + ", ".join(moved))
            return
        code = os.WEXITSTATUS(status) if not os.WIFSIGNALED(status) else -os.WTERMSIG(status)
        report.ok("interrupt", f"exit={code} in {elapsed:.2f}s, 3 services torn down, residue clean")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def phase_kill(kern, env, report, base):
    """SIGKILL of `up` mid-bring-up: the stack may survive, and `down` must still recover it.

    A DETACHED `up` IS SUPPOSED TO LEAVE THE STACK RUNNING - that is what `-d` means, and the boxes
    belong to their own supervisors, not to the command. What must hold is that the stack is still
    ADDRESSABLE afterwards: `down` finds it and returns the machine to where it started.
    """
    work = tempfile.mkdtemp(prefix="kern-dryrun-kill-")
    try:
        with open(os.path.join(work, "docker-compose.yml"), "w", encoding="utf-8") as fh:
            fh.write(
                "services:\n"
                "  a:\n    image: alpine:latest\n    command: [\"sh\", \"-c\", \"sleep 120\"]\n"
                "  b:\n    image: alpine:latest\n    command: [\"sh\", \"-c\", \"sleep 120\"]\n"
                "  c:\n    image: alpine:latest\n    command: [\"sh\", \"-c\", \"sleep 120\"]\n"
            )
        try:
            p = subprocess.Popen(
                [kern, "compose", "-f", "docker-compose.yml", "up", "-d"],
                cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
            )
        except OSError as e:
            report.fail("kill", f"could not start `up`: {e}")
            return
        time.sleep(0.25)
        p.kill()
        p.wait(timeout=30)
        time.sleep(3.0)
        out, ok = compose(kern, work, env, ["down"])
        time.sleep(1.5)
        after = census(kern, env)
        moved = after.diff(base)
        if moved:
            report.fail("kill", "a killed `up` left residue `down` could not reclaim: " + ", ".join(moved))
            return
        report.ok("kill", f"`down` recovered the stack ({'ok' if ok else 'non-zero exit, residue clean'})")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def phase_sdk(kern, env, report):
    """The Python wrapper: the error when the binary is absent, and a real run when it is not."""
    sdk = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bindings", "python")
    if not os.path.isdir(os.path.join(sdk, "kern_sandbox")):
        report.skip("sdk", "bindings/python is not in this tree")
        return
    missing = subprocess.run(
        [sys.executable, "-c",
         "import os,sys;sys.path.insert(0,'.');os.environ.pop('KERN_BIN',None);"
         "os.environ['PATH']='/nonexistent';import kern_sandbox\n"
         "try:\n kern_sandbox.Sandbox()\n print('NO ERROR')\n"
         "except Exception as e: print(type(e).__name__+'|'+str(e))"],
        cwd=sdk, capture_output=True, text=True, timeout=120,
    )
    text = missing.stdout.strip()
    if "SandboxError|" not in text:
        report.fail("sdk-missing-binary", f"expected a typed SandboxError, got: {text[:160]!r}")
    elif "install.sh" not in text:
        report.fail(
            "sdk-missing-binary",
            "the error does not give the install COMMAND, only prose: a user who just ran "
            f"`pip install kern-sandbox` needs a line to paste: {text[:160]!r}",
        )
    else:
        report.ok("sdk-missing-binary", "typed error, names the install command")

    real = subprocess.run(
        [sys.executable, "-c",
         "import os,sys;sys.path.insert(0,'.');"
         "import kern_sandbox\n"
         "with kern_sandbox.Sandbox() as s:\n"
         "    r = s.run_code('print(6*7)')\n"
         "    print('RESULT:' + (r.stdout or '').strip())"],
        cwd=sdk, capture_output=True, text=True, timeout=300,
        env=dict(env, KERN_BIN=kern),
    )
    if "RESULT:42" in real.stdout:
        report.ok("sdk-run", "a real sandbox ran Python and returned its output")
    else:
        tail = (real.stdout + real.stderr).strip().splitlines()
        report.fail("sdk-run", f"the SDK could not run code: {(tail[-1] if tail else '')[:180]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kern", default="target/release/kern")
    ap.add_argument("--only", default="", help="stacks|interrupt|kill|sdk")
    ap.add_argument("--stack", default="", help="run one stack by name")
    ap.add_argument("--keep-going", action="store_true", help="do not stop at the first failure")
    args = ap.parse_args()

    rc = kernbin.require_current(args.kern)
    if rc:
        return rc
    kern = os.path.abspath(args.kern)
    env = dict(os.environ)

    # WHICH BINARY WAS CERTIFIED, SAID BY THE INSTRUMENT RATHER THAN REMEMBERED BY WHOEVER RAN IT.
    #
    # `kernbin` already refuses a binary older than the working tree. It cannot refuse a binary built
    # with a DIFFERENT PROFILE from the same tree, and that is the gap that matters here: the release
    # workflow builds `x86_64-unknown-linux-musl` with `-Z build-std`, `optimize_for_size` and
    # `panic=immediate-abort`, while `cargo build --release` produces a glibc host binary. They are
    # not the same program - musl resolves names and reads `/etc/passwd` through a different libc -
    # so a rehearsal that passes on the host build has certified something nobody downloads.
    #
    # This does not refuse the host build: running against it is useful while iterating. It prints
    # what it tested, so a green run can never be quoted about the wrong artifact.
    shape = "host build (glibc)"
    try:
        with open(kern, "rb") as fh:
            head = fh.read(20)
        out = subprocess.run(["file", "-b", kern], capture_output=True, text=True, timeout=30).stdout
        if "static-pie" in out or "statically linked" in out:
            shape = "RELEASE SHAPE (static-pie, the artifact the installer fetches)"
        del head
    except (OSError, subprocess.SubprocessError):
        pass
    digest = ""
    try:
        import hashlib
        h = hashlib.sha256()
        with open(kern, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        digest = h.hexdigest()[:16]
    except OSError:
        digest = "unreadable"
    print(f"binary\n  {kern}\n  sha256:{digest}  {shape}\n")

    report = Report(args.keep_going)
    print("baseline")
    # THE MACHINE IS SWEPT FIRST, so debris from an earlier session is not charged to this run.
    # `gc` is kern's own full local cleanup and is the same command a user would reach for.
    subprocess.run([kern, "gc"], capture_output=True, text=True, timeout=600, env=env)
    time.sleep(1.0)
    base = census(kern, env)
    print(f"  {base}\n")

    if args.only in ("", "stacks"):
        print("stacks")
        for name, doc, svc, cmd, expect in STACKS:
            if args.stack and args.stack != name:
                continue
            run_stack(kern, env, report, name, doc, svc, cmd, expect, base)
        print()
    if args.only in ("", "interrupt"):
        print("interrupt")
        phase_interrupt(kern, env, report, base)
        print()
    if args.only in ("", "kill"):
        print("kill")
        phase_kill(kern, env, report, base)
        print()
    if args.only in ("", "sdk"):
        print("sdk")
        phase_sdk(kern, env, report)
        print()

    final = census(kern, env)
    moved = final.diff(base)
    if moved:
        report.fail("residue", "the machine did not return to its baseline: " + ", ".join(moved))
    else:
        report.ok("residue", f"exactly the baseline: {final}")
    return report.finish()


if __name__ == "__main__":
    sys.exit(main())
