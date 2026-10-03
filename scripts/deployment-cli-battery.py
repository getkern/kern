#!/usr/bin/env python3
"""Every command shape a real deployment's scripts run, against kern, on a real stack.

WHY THIS EXISTS. The compose-compat rate measures what kern does with a FILE: parse it, warn about
it, bring it up. A deployment is not only its compose file - it is the fifty-odd command lines its
scripts, its `package.json` and its CI wrap around that file, and none of those are in any corpus.
The three defects that started this battery were all there and none of them was visible to
`compose config`:

  * `exec -i <c> psql < file.sql` hung forever, because `-i` allocated a pseudo-terminal,
  * `build -t a -t b .` kept only `b`, silently, so the `push a` after it had nothing,
  * a `command:` carrying `\\"` was truncated at the escape, so a service ran a fragment of its script.

The shapes below were inventoried by hand from one deployment's scripts, `package.json` and CI: a
database, a REST layer, a workflow engine and their one-shot migrations. What is reproduced here is
the SHAPE of each command, never the deployment - its names are placeholders. Each shape is run for
real against a stack this script brings up, and its EXIT CODE and OUTPUT are checked, not merely
that kern accepted the flags.

WHAT A FAILURE MEANS. A red line here is a command shape that a deployment's scripts contain and
kern no longer serves. That is a regression whether or not any test in the Rust suite changed,
because what broke is the shape of a command rather than the behaviour of a function.

WHERE IT RUNS. Locally, from `scripts/gate.sh`, and deliberately NOT in CI: it starts real boxes,
mounts volumes and pulls an image, and the hosted runner's cgroup delegation differs from a
developer machine's - a red line there would say more about the runner than about the tree. It skips
itself with a reason when no binary has been built.

Usage:
    scripts/deployment-cli-battery.py [--kern PATH] [-v]

`--kern` defaults to ./target/release/kern, then ./target/debug/kern, then `kern` on PATH. Exits
non-zero if any case fails.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time

COMPOSE = """\
services:
  db:
    image: alpine:3.19
    container_name: battery-db
    command: >
      sh -c "
        for i in 1 2 3; do
          if [ -f /shared/token ]; then break; fi
          echo \\"waiting for the token, attempt $$i...\\"
          sleep 1
        done
        echo DB-READY
        sleep 300
      "
    ports:
      - "15999:5432"
    volumes:
      - shared_cfg:/shared
    healthcheck:
      test: ["CMD-SHELL", "true"]
      interval: 1s
      retries: 3
  setup:
    image: alpine:3.19
    container_name: battery-setup
    command: sh -c "echo SETUP-DONE; exit 0"
    volumes:
      - shared_cfg:/shared
  api:
    image: alpine:3.19
    container_name: battery-api
    # RUNS AS A NON-ROOT UID ON PURPOSE. Rootless, uid 999 inside the box is a SUBUID on the host,
    # so what it writes into `owned_data` is a directory this user cannot unlink into - which is
    # what `down -v` has to be able to remove and, for a while, could not. Every database image
    # does this; the battery does it without pulling one.
    user: "999:999"
    command: sh -c "echo owned > /owned/f 2>/dev/null || true; sleep 300"
    volumes:
      - owned_data:/owned
      - shared_cfg:/shared
    depends_on:
      setup:
        condition: service_completed_successfully
      db:
        condition: service_healthy

volumes:
  shared_cfg:
  owned_data:
"""


class Battery:
    def __init__(self, kern, workdir, verbose):
        self.kern = kern
        self.workdir = workdir
        self.verbose = verbose
        self.passed = 0
        self.failed = []

    def run(self, args, stdin=None, timeout=120):
        """One kern invocation. Returns (rc, stdout, stderr); a timeout is rc 124, as `timeout(1)`."""
        try:
            p = subprocess.run(
                [self.kern] + args,
                cwd=self.workdir,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            return 124, "", f"timed out after {timeout}s"

    def check(self, label, script_line, args, *, stdin=None, want_rc=0, want_out=None,
              want_not=None, timeout=120):
        """Run one case and record it. `script_line` is the line the deployment's script contains,
        kept verbatim: the point of a green line is that the script needed no edit."""
        rc, out, err = self.run(args, stdin=stdin, timeout=timeout)
        problems = []
        if want_rc is not None and rc != want_rc:
            problems.append(f"exit {rc}, wanted {want_rc}")
        if want_out is not None and want_out not in out + err:
            problems.append(f"output does not contain {want_out!r}")
        if want_not is not None and want_not in out + err:
            problems.append(f"output contains {want_not!r} and must not")
        if problems:
            self.failed.append((label, script_line, "; ".join(problems), (out + err)[:400]))
            print(f"  FAIL  {label}")
            for p in problems:
                print(f"          {p}")
        else:
            self.passed += 1
            print(f"  ok    {label}")
        if self.verbose and (out or err):
            for line in (out + err).splitlines()[:6]:
                print(f"          | {line}")
        return rc, out, err

    def assert_that(self, label, script_line, ok, detail):
        """Record a judgement about output ALREADY collected, in the same ledger as a run.

        Some questions are about the SHAPE of an answer rather than its presence - which row came
        first, how many there were - and `want_out` can only ask whether a substring occurs. Those
        would otherwise be checked with a bare `assert` that stops the battery at the first
        disagreement and leaves the remaining cases unmeasured.
        """
        if ok:
            self.passed += 1
            print(f"  ok    {label}")
        else:
            self.failed.append((label, script_line, detail, ""))
            print(f"  FAIL  {label}")
            print(f"          {detail}")


def binary_is_the_tree(kern, explicit):
    """Refuse a binary that is not the tree. A stale one passes every case and proves nothing.

    The binary is ASKED what it is: `--version` carries the `git describe` its build baked in. Its
    MTIME is not consulted, because a rebase rewrites files with identical content and moves every
    mtime, so an mtime says when cargo last ran rather than what it compiled - which is how a whole
    green run once described a commit that was not checked out.

    An explicit `--kern` is somebody testing another build on purpose, and is left alone. A tree
    that is not a checkout says so and continues.

    What is compared is the COMMIT, with `-dirty` stripped from both sides. A `-dirty` suffix is a
    statement about uncommitted content, not about identity, and it appears on either side
    independently: editing this very file after building makes the tree dirty while the binary is
    current. Comparing the raw strings therefore refused the right binary, which is what the
    negative control caught. Dirt on either side is reported instead, because it is the one thing a
    matching commit cannot rule out.

    WHAT IT DOES NOT DEFEND AGAINST, written down because a guard that is quiet about its edge gets
    read as one that has none. The subject is an HONEST STALE binary: one built from an older
    commit, which reports that commit and is refused. A binary that LIES in `--version` is accepted,
    and demonstrably so - a two-line shell script echoing this checkout's `git describe` passes it.
    That is not a hole to plug. The default path reads `target/release/kern`, the artefact this
    tree's own `cargo build` writes; if something else is sitting there, no question put to THAT
    binary can find out. Hashing it, sizing it or checking it is an ELF would raise the cost of a
    lie without changing what the check can promise. What it promises is exactly this much: the
    binary SAYS it is this commit, and a forgotten rebuild does not.
    """
    got = subprocess.run([kern, "--version"], capture_output=True, text=True).stdout.strip()
    print(got)
    undirty = lambda s: s[: -len("-dirty")] if s.endswith("-dirty") else s  # noqa: E731
    d = subprocess.run(["git", "describe", "--tags", "--always", "--dirty"],
                       capture_output=True, text=True)
    if explicit:
        # AN ESCAPE HATCH THAT ANNOUNCES ITSELF. `--kern` is how you put an installed binary, or one
        # built elsewhere, to the same battery, so it must not refuse. It used to say nothing at
        # all, which let `--kern $(which kern)` in a script report a green about whatever was on
        # PATH while reading as a verdict on this tree. The check still runs; only its power to
        # refuse is dropped.
        if d.returncode == 0 and undirty(d.stdout.strip()) not in undirty(got):
            print(f"  NOT THIS TREE: --kern was given, so this runs anyway. The result describes "
                  f"{got!r}, not {d.stdout.strip()!r}.")
        return True
    if d.returncode != 0:
        print("  not a checkout: the binary was not matched against a commit")
        return True
    want = d.stdout.strip()
    if undirty(want) not in undirty(got):
        print(f"\nSTALE BINARY: it reports {got!r}, this tree is {want!r}.", file=sys.stderr)
        print("A run against it measures another commit. Build it, then run this again:",
              file=sys.stderr)
        print("    cargo build --release", file=sys.stderr)
        return False
    if want.endswith("-dirty") or got.endswith("-dirty"):
        print("  the commit matches; the content is not pinned, one of the two is dirty")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kern", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    kern = a.kern
    if kern is None:
        for c in ("target/release/kern", "target/debug/kern"):
            if os.path.isfile(c) and os.access(c, os.X_OK):
                kern = os.path.abspath(c)
                break
        else:
            kern = shutil.which("kern")
    if not kern:
        print("no kern binary: build one or pass --kern PATH", file=sys.stderr)
        return 2
    print(f"binary: {kern}")
    if not binary_is_the_tree(kern, explicit=a.kern is not None):
        return 2

    work = tempfile.mkdtemp(prefix="kern-inventory-")
    compose_path = os.path.join(work, "docker-compose.yml")
    with open(compose_path, "w") as f:
        f.write(COMPOSE)
    # A build context, for the `-t a -t b` case the CI runs.
    with open(os.path.join(work, "Dockerfile"), "w") as f:
        f.write("FROM alpine:3.19\nRUN true\n")
    with open(os.path.join(work, "seed.sql"), "w") as f:
        f.write("line one\nline two\nline three\n")

    b = Battery(kern, work, a.verbose)
    try:
        # ---- compose lifecycle: what start.sh / rebuild.sh / npm scripts run ----
        print("\ncompose lifecycle")
        b.check("compose config", "docker compose config",
                ["compose", "docker-compose.yml", "config"], want_out="3 service")
        b.check("compose up -d", "docker compose up -d",
                ["compose", "docker-compose.yml", "up", "-d"], want_out="started", timeout=240)
        time.sleep(3)
        b.check("compose ps", "docker compose ps", ["compose", "docker-compose.yml", "ps"])
        b.check("compose ps --format", 'docker compose ps --format "{{.Name}} {{.Status}}"',
                ["compose", "docker-compose.yml", "ps", "--format", "{{.Names}} {{.Status}}"],
                want_out="battery-db")
        b.check("compose up -d (idempotent)", "docker compose up -d",
                ["compose", "docker-compose.yml", "up", "-d"], want_out="up to date")
        b.check("compose up --force-recreate", "docker compose up -d --build --force-recreate --no-deps api",
                ["compose", "docker-compose.yml", "up", "-d", "--build", "--force-recreate",
                 "--no-deps", "api"], want_out="recreating", timeout=240)
        b.check("compose logs", "docker compose logs", ["compose", "docker-compose.yml", "logs"])
        b.check("compose logs <svc>", "docker compose logs db",
                ["compose", "docker-compose.yml", "logs", "db"])
        b.check("compose exec -T", "docker compose exec -T db pg_isready",
                ["compose", "docker-compose.yml", "exec", "-T", "db", "true"])
        b.check("compose restart <svc>", "docker compose restart db",
                ["compose", "docker-compose.yml", "restart", "db"], timeout=240)
        time.sleep(2)

        # ---- engine verbs against a container_name, the form ~70 scripts use ----
        print("\nengine verbs on container_name")
        b.check("exec -i with redirect", "docker exec -i <db-container> psql ... < file.sql",
                ["exec", "-i", "battery-db", "cat"],
                stdin=open(os.path.join(work, "seed.sql")).read(),
                want_out="line three", timeout=30)
        b.check("exec -i output is byte-exact", "docker exec -i ... < file.sql",
                ["exec", "-i", "battery-db", "cat"],
                stdin="alpha\nbeta\n", want_out="alpha\nbeta\n", want_not="\r", timeout=30)
        b.check("exec <box> <cmd>", 'docker exec <db-container> psql -tAc "..."',
                ["exec", "battery-db", "echo", "hello"], want_out="hello")
        b.check("logs <box>", "docker logs <api-container>", ["logs", "battery-db"])
        b.check("inspect -f State.Status", "docker inspect -f '{{.State.Status}}' <one-shot-container>",
                ["inspect", "-f", "{{.State.Status}}", "battery-setup"], want_out="exited")
        b.check("inspect -f State.ExitCode", "docker inspect -f '{{.State.ExitCode}}' <c>",
                ["inspect", "-f", "{{.State.ExitCode}}", "battery-setup"], want_out="0")
        b.check("inspect --json has status", "docker inspect <c> | jq .State.Status",
                ["inspect", "battery-db", "--json"], want_out='"status":"running"')
        b.check("port <box> <port>", "docker port <api-container> 3000",
                ["port", "battery-db", "5432"], want_out="15999")
        b.check("info", "docker info", ["info"])
        b.check("ps --filter health", "docker ps --filter health=healthy",
                ["ps", "--filter", "health=healthy", "--format", "{{.Names}}"])

        # ---- the CI's image pipeline ----
        print("\nimage pipeline (CI)")
        b.check("build -t A -t B .", "docker build -t $ECR:$VERSION -t $ECR:latest .",
                ["build", "-t", "battery/app:1.0", "-t", "battery/app:latest", "."],
                want_out="battery/app:latest", timeout=300)
        b.check("both tags exist", "docker images", ["images", "--filter", "reference=battery/app*"],
                want_out="battery/app:1.0")
        b.check("tag", "docker tag a b", ["tag", "battery/app:1.0", "battery/app:2.0"])
        b.check("save to a file", "docker save img > images/name.tar",
                ["save", "battery/app:1.0", "-o", os.path.join(work, "app.tar")])
        b.check("load from a file", "docker load < images/name.tar",
                ["load", "-i", os.path.join(work, "app.tar")], timeout=300)
        b.check("rmi", "docker rmi img",
                ["rmi", "battery/app:1.0", "battery/app:2.0", "battery/app:latest"])

        # ---- the contracts a script BRANCHES on, not just the ones it runs ----
        #
        # Each of these four was wrong when it was first written, and three of them were wrong in a
        # way no exit code showed: the command succeeded and answered a different question.
        print("\ncontracts")
        b.check("compose wait returns the status", "docker compose wait tests  # $? is the suite's",
                ["compose", "docker-compose.yml", "wait", "setup"], want_rc=0, timeout=240)
        # NON-ZERO, AND THIS LINE USED TO SAY 0. No service in this file declares `build:`, so the
        # verb publishes nothing; exiting 0 there lets `compose push && deploy` deploy after
        # publishing nothing. The assertion encoded the defect until it was put to an outside
        # reading, which is the same way the `split_argv` trailing-backslash case was found.
        b.check("compose push refuses when it published nothing",
                "docker compose push  # only services with a build section",
                ["compose", "docker-compose.yml", "push"],
                want_out="declares no `build:`", want_rc=1)
        b.check("ps --last is newest CREATED", "docker ps -n 2",
                ["ps", "--last", "2", "--format", "{{.Names}}"])
        # THE ORDER IS THE ANSWER, not just the count. `--last` asks about recency, so the newest
        # box has to be the FIRST row; it used to be the last, because the cut was made on one
        # ordering and the rows were then printed in another.
        #
        # TWO BOXES OF ITS OWN, and not the stack's. Reading the answer off the stack requires
        # knowing which service is newest, and `restart db` a few lines up makes that DB, not the
        # service that started last - an assumption that read as a code defect until the start
        # times were looked at. These two are created here, a second apart, so which is newer is
        # not a matter of interpretation. A second is many kernel ticks; boxes created inside ONE
        # tick are not ordered by this flag and nothing here pretends otherwise.
        b.run(["box", "order-a", "--image", "alpine:3.19", "-d", "--", "sleep", "60"])
        time.sleep(1.2)
        b.run(["box", "order-b", "--image", "alpine:3.19", "-d", "--", "sleep", "60"])
        _, order_out, _ = b.run(["ps", "--last", "2", "--format", "{{.Names}}"])
        names = [n.strip() for n in order_out.splitlines() if n.strip()]
        b.assert_that("ps --last puts the newest FIRST", "docker ps -n 2",
                      names == ["order-b", "order-a"], f"rows were {names}, wanted the newer first")
        b.run(["stop", "order-a", "order-b"])
        b.check("images --filter without a tag", "docker images --filter reference=alpine",
                ["images", "--filter", "reference=alpine"], want_out="alpine:3.19")

        # ---- the four `build:` SHAPES a real file declares, and the chain wrapped around them ----
        #
        # Not the project's code, which this script does not have: its SHAPES. A compose file's
        # `build:` comes in forms that resolve paths differently, and each one is a way for a build
        # to find nothing and say nothing: `context:` with `args:`, the bare short form, and a
        # context at the REPO ROOT with the Dockerfile in a subdirectory (where every COPY resolves
        # from the root, not from beside the Dockerfile).
        #
        # Then the chain those builds sit in, which is one real rebuild script end to end: a one-off
        # box joined to the running stack's network mints a token, an `exec` writes it into the
        # shared volume, and the consumer is force-recreated with `--no-deps` to pick it up. Every
        # step of it was a defect at some point in this release.
        print("\nbuild shapes and the rebuild chain")
        os.makedirs(os.path.join(work, "sub"), exist_ok=True)
        with open(os.path.join(work, "root-file.txt"), "w") as f:
            f.write("from the repo root\n")
        with open(os.path.join(work, "sub", "Dockerfile"), "w") as f:
            f.write(
                "FROM alpine:3.19\nARG MARKER\n"
                "COPY root-file.txt /root-file.txt\n"
                "RUN echo \"marker=$MARKER\" > /marker.txt\n"
            )
        b.check("build --check reports without building", "docker build (no dry run exists)",
                ["build", "--check", "-f", "sub/Dockerfile", "."],
                want_out="builds here")
        # A `--from=` TOKEN THAT NAMES NO STAGE IS AN IMAGE, and the check has to say so.
        #
        # `resolve_from` classifies it as a stage when one matches and as an image otherwise, which is
        # Docker's rule, so `--from=buidler` for `builder` is a silent change of meaning rather than
        # an error. Measured before the note existed: this exact file passed with "builds here, and
        # every line it contains has an effect", and the build then failed with "cannot access
        # 'library/nosuchstage' on registry-1.docker.io - it may be private", which answers a
        # mistyped stage name with a sentence about a registry. The check pulls nothing by design, so
        # the fix is to NAME what it did not resolve, not to start resolving it.
        with open(os.path.join(work, "sub", "D-typo"), "w") as f:
            f.write("FROM alpine:3.19 AS builder\nFROM alpine:3.19\n"
                    "COPY --from=nosuchstage /bin/true /t\n")
        b.check("--check names a --from= that no stage declares", "docker build --check (warnings)",
                ["build", "--check", "-f", "sub/D-typo", "."],
                want_out="did not resolve it: nosuchstage")
        b.check("build.args reaches the build", "docker compose build --build-arg",
                ["build", "-t", "battery/shape:1", "-f", "sub/Dockerfile",
                 "--build-arg", "MARKER=arrivato", "."],
                want_out="battery/shape:1", timeout=300)
        b.check("context=root, dockerfile in a subdir", "build: {context: ., dockerfile: sub/D}",
                ["box", "shapechk", "--image", "battery/shape:1", "--",
                 "sh", "-c", "cat /root-file.txt /marker.txt"],
                want_out="from the repo root", timeout=300)
        b.check("and the arg is in the image", "docker build --build-arg",
                ["box", "shapechk2", "--image", "battery/shape:1", "--", "cat", "/marker.txt"],
                want_out="marker=arrivato", timeout=300)

        # THE CHAIN. `--network <stack>` is how a one-off talks to a running stack; it was
        # `--network <host|none>` and nothing else until this release.
        pod = ""
        rc, out, _ = b.run(["pod", "ls"])
        for line in out.splitlines():
            if line.split()[:1] and line.split()[0].startswith(os.path.basename(work)[:8]):
                pod = line.split()[0]
        if not pod:
            rc, out, _ = b.run(["ps", "--format", "{{.Pod}}"])
            pod = next((l.strip() for l in out.splitlines() if l.strip()), "")
        b.check("one-off joins the stack's network", "docker run --rm --network <stack> …",
                ["box", "tokgen", "--image", "alpine:3.19", "--network", pod, "--",
                 "sh", "-c", "echo tok-battery"], want_out="tok-battery", timeout=300)
        # `db` mounts the shared volume rw and is still running, which is the shape the real chain
        # has: the token is written THROUGH a live service, because the volume belongs to the stack
        # and not to the host.
        b.check("exec writes into the shared volume", "docker exec <c> sh -c 'echo T > /shared/t'",
                ["exec", "battery-db", "sh", "-c", "echo tok-battery > /shared/token"])
        b.check("and the consumer reads it back", "docker exec <c> cat /shared/token",
                ["exec", "battery-api", "cat", "/shared/token"], want_out="tok-battery")
        # `--force-recreate --no-deps <svc>` on a stack whose one-shot dependency already completed:
        # the line that used to burn 120 seconds and then fail about a service that HAD completed.
        b.check("force-recreate --no-deps after the injection",
                "docker compose up -d --build --force-recreate --no-deps api",
                ["compose", "docker-compose.yml", "up", "-d", "--build", "--force-recreate",
                 "--no-deps", "api"], want_out="recreating", timeout=300)

        # ---- teardown ----
        print("\nteardown")
        b.check("compose stop", "docker compose stop", ["compose", "docker-compose.yml", "stop"],
                timeout=240)
        b.check("compose rm", "docker compose rm", ["compose", "docker-compose.yml", "rm"])
        # `down -v` MUST REPORT REMOVING BOTH NAMED VOLUMES, including the one a non-root service
        # wrote to. It used to fail on that one with EACCES and abandon the rest of the loop, so a
        # `reset.sh` reported a reset that had removed nothing and the next `up` reused the old data.
        b.check("compose down -v removes a subuid volume", "docker compose down -v",
                ["compose", "docker-compose.yml", "down", "-v"],
                want_out="2 named volume(s) removed", timeout=240)
        b.check("compose down (twice)", "docker compose down",
                ["compose", "docker-compose.yml", "down"], timeout=240)
    finally:
        subprocess.run([kern, "compose", compose_path, "down", "-v"],
                       capture_output=True, timeout=240)
        for ref in ("battery/app:1.0", "battery/app:2.0", "battery/app:latest"):
            subprocess.run([kern, "rmi", ref], capture_output=True, timeout=60)
        shutil.rmtree(work, ignore_errors=True)

    total = b.passed + len(b.failed)
    print(f"\n{b.passed}/{total} of a deployment's command shapes work on kern")
    if b.failed:
        print("\nFAILED:")
        for label, form, why, out in b.failed:
            print(f"  {label}")
            print(f"    the script contains: {form}")
            print(f"    {why}")
            if out.strip():
                print(f"    output: {out.strip()[:200]}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
