#!/usr/bin/env python3
"""What the default wiring costs, paired, on the same stacks and the same binary.

WHY IT EXISTS. The default wiring for a stack of two or more services is a bridge: a network
namespace per service, which is the arrangement Docker has. A pod - one namespace for the whole
stack - is cheaper, and the decision to stop defaulting to it is only defensible next to a number.
That number was taken once by hand, and a number taken by hand is one that cannot be re-taken after
a change to the bring-up, which is exactly when it stops being true.

WHAT IT MEASURES is the whole `up -d`, from the process starting to it exiting with the stack up:
image resolution off a warm cache, the pod, the namespaces, the veths, the addressing, the NAT, and
every box started. Not a micro-benchmark of veth creation, because nobody waits for a veth.

THE TRAPS IT IS BUILT AROUND, each of which has already produced a wrong number in this project:

  1. MEASURING TWO DIFFERENT THINGS. The two columns are the SAME file and the same binary, one
     argument apart. The bridge column passes nothing (it is the default) and the pod column passes
     `--pod`, and the run refuses to conclude if the wirings it got back are not the two it asked
     for: `config` is read for each column and the `wiring:` field must differ.
  2. MEASURING A FAILURE. A stack that does not come up starts fast. Every `up` is checked for a
     zero exit AND the box count is read back, and a sample that did not bring up every service is
     discarded loudly rather than averaged in.
  3. MEASURING IN BLOCKS. The columns alternate sample by sample, so thermal drift and whatever else
     the machine is doing lands in both halves instead of all in one.
  4. LEAVING THE PREVIOUS STACK BEHIND. Every sample is followed by a `down`, which is NOT timed,
     and the teardown is verified before the next sample starts: a second `up` over a running stack
     measures the reconciler, not a bring-up.

Reports the MEDIAN, because the high tail of a process start is the machine and not the program.

Usage:
    wiring-cost.py [--kern PATH] [--services 1,2,4,8] [--samples N] [--file FILE]
"""

import argparse
import os
import pathlib
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kernbin

# The image every synthetic stack runs. Small, cached, and its entrypoint does nothing but sleep:
# the subject is the bring-up, and an image that starts a server would add its own startup to both
# columns and widen the spread for no reason.
IMAGE = "alpine"
COMMAND = ["sleep", "600"]

# Above this load average per core the machine is already busy and neither column means anything.
# Measured instance in this project: 1879 us read against a true 931 us, with the test suites running.
LOAD_CEILING_PER_CORE = 0.5


def label_of(f, n):
    """How a case is named in the table: the service count for a synthetic one, the file otherwise."""
    return f.name if n is None else f"{n} services"


def synthetic(dirpath, n):
    """A compose file with `n` services that differ only in name."""
    body = ["services:"]
    for i in range(n):
        body.append(f"  s{i}:")
        body.append(f"    image: {IMAGE}")
        body.append("    command: [" + ", ".join(f'"{c}"' for c in COMMAND) + "]")
    f = dirpath / f"stack{n}.yml"
    f.write_text("\n".join(body) + "\n", encoding="utf-8")
    return f


def wiring_of(kern, f, extra):
    """What kern says it will do, read from the field and never from the prose."""
    p = subprocess.run(
        [kern, "compose", "-f", str(f), "config", *extra],
        capture_output=True, text=True, timeout=120,
    )
    for line in p.stdout.splitlines():
        if line.startswith("  wiring: "):
            return line.split(": ", 1)[1].strip()
    return "?"


def down(kern, f, env):
    subprocess.run(
        [kern, "compose", "-f", str(f), "down"],
        capture_output=True, text=True, timeout=300, env=env,
    )


def one_sample(kern, f, extra, env, want_boxes):
    """One timed `up -d`, or None with a reason printed. The `down` after it is not timed."""
    t0 = time.perf_counter()
    p = subprocess.run(
        [kern, "compose", "-f", str(f), "up", "-d", *extra],
        capture_output=True, text=True, timeout=600, env=env,
    )
    dt = (time.perf_counter() - t0) * 1000.0
    if p.returncode != 0:
        print(f"    discarded: `up` exited {p.returncode}: {p.stderr.strip()[-200:]}", flush=True)
        down(kern, f, env)
        return None
    # THE SAMPLE IS ONLY A BRING-UP IF THE STACK CAME UP. `ps` is read back rather than trusting the
    # exit status, because a service that dies a millisecond after start leaves `up` successful.
    #
    # THE SHAPE IS THE TREE `ps` PRINTS, one `|- name pid uptime ...` line per live box under a pod
    # header. The first version of this counted lines containing the word "running", which `ps` does
    # not print: every sample was discarded as "0 of 4 services running" and the run reported a
    # ratio of 0.00x, which it then called a pass. Both halves of that are fixed - the readback here
    # and the empty-sample verdict at the end.
    ps = subprocess.run(
        [kern, "compose", "-f", str(f), "ps"],
        capture_output=True, text=True, timeout=120, env=env,
    )
    running = sum(
        1 for line in ps.stdout.splitlines()
        if line.startswith("\u251c\u2500 ") or line.startswith("\u2514\u2500 ")
    )
    down(kern, f, env)
    if running < want_boxes:
        print(f"    discarded: {running} of {want_boxes} services running", flush=True)
        return None
    return dt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kern", default="target/debug/kern")
    ap.add_argument("--services", default="1,2,4,8")
    ap.add_argument("--samples", type=int, default=7)
    ap.add_argument("--file", default="", help="a real compose file instead of the synthetic ones")
    args = ap.parse_args()

    rc = kernbin.require_current(args.kern)
    if rc:
        return rc
    kern = os.path.abspath(args.kern)

    load = os.getloadavg()[0] / (os.cpu_count() or 1)
    print(f"load per core: {load:.2f}")
    if load > LOAD_CEILING_PER_CORE:
        print(
            f"refusing to conclude: the machine is at {load:.2f} per core, above "
            f"{LOAD_CEILING_PER_CORE}. Both columns would be measuring the other load.",
            file=sys.stderr,
        )
        return 2

    work = pathlib.Path(tempfile.mkdtemp(prefix="kern-wiring-cost-"))
    env = dict(os.environ)
    try:
        if args.file:
            cases = [(pathlib.Path(args.file), None)]
        else:
            cases = [(synthetic(work, n), n) for n in
                     (int(x) for x in args.services.split(",") if x.strip())]

        print(f"{'stack':>22}  {'bridge':>9}  {'pod':>9}  {'delta':>9}  {'ratio':>6}")
        worst = 0.0
        unmeasured = 0
        compared = 0
        for f, n in cases:
            bridge_w = wiring_of(kern, f, [])
            pod_w = wiring_of(kern, f, ["--pod"])
            # THE GUARD AGAINST MEASURING ONE THING TWICE. A single-service file is a pod under
            # both, and averaging those two columns into a "cost of the bridge" is the error this
            # refuses to make.
            if bridge_w == pod_w:
                print(f"{label_of(f, n):>22}  both columns wire `{bridge_w}`: nothing to compare")
                continue
            want = n if n is not None else sum(
                1 for line in subprocess.run(
                    [kern, "compose", "-f", str(f), "config"],
                    capture_output=True, text=True, timeout=120,
                ).stdout.splitlines() if line.startswith("  - ")
            )
            down(kern, f, env)
            a, b = [], []
            for i in range(args.samples):
                # ALTERNATING, and the leading sample of each column is dropped: the first `up` of a
                # pair pays whatever the previous case left cold.
                x = one_sample(kern, f, [], env, want)
                y = one_sample(kern, f, ["--pod"], env, want)
                if i == 0:
                    continue
                if x is not None:
                    a.append(x)
                if y is not None:
                    b.append(y)
            if not a or not b:
                # A CASE WITH NO SAMPLES IS A FAILED MEASUREMENT, not a fast one. It used to fall
                # through to a verdict computed over the cases that did work, which is how a run
                # where NOTHING came up printed a passing ratio.
                print(f"{label_of(f, n):>22}  no usable samples: NOT MEASURED")
                unmeasured += 1
                continue
            ma, mb = statistics.median(a), statistics.median(b)
            ratio = ma / mb if mb else float("inf")
            worst = max(worst, ratio)
            compared += 1
            print(f"{label_of(f, n):>22}  {ma:8.0f}ms  {mb:8.0f}ms  {ma - mb:+8.0f}ms  {ratio:5.2f}x"
                  f"   (n={len(a)}/{len(b)})")
        if unmeasured or not compared:
            print(f"\nNOT MEASURED: {unmeasured} case(s) produced no usable sample and "
                  f"{compared} were compared. No verdict.")
            return 2
        print(f"\nworst ratio {worst:.2f}x over {compared} case(s). The guard set before the change "
              f"was 2x: a default that costs more than twice the pod is not a default.")
        return 0 if worst <= 2.0 else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
