#!/usr/bin/env python3
"""Do concurrent teardowns of different pods ever signal a THIRD pod's pasta?

THE CASE. `claimed_by_another_pasta` scans the other pod dirs to decide whether a pid it
is about to signal belongs to somebody else. That scan is a `read_dir` plus a read per
dir, and it races every `pod rm` running beside it: a dir removed mid-scan is a claim that
was there a moment ago and is not there now. The reviewer's shape for making the harm
VISIBLE rather than invisible is three pods, two torn down at once, and an assertion on
the third - because two pods tearing each other down is a harm nobody can see.

WHY REPEATED RATHER THAN FORCED. The deterministic version blocks the `readdir` from a
FUSE mount over the pod root; this one runs the race many times instead. It cannot prove
the window is closed, and it is not claimed to: a failure is conclusive, a pass is
evidence bounded by the number of rounds, and the number is printed so the bound is
visible rather than implied.

RUN: python3 scripts/teardown-interleave.py [path-to-kern] [rounds]
Exit 0 = the bystander survived every round. 1 = it did not. 77 = skipped, with a reason.
"""
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

SKIP = 77


def skip(reason):
    print(f"SKIP: {reason}")
    sys.exit(SKIP)


def pasta_of(run, name):
    """The pid in a pod's `pasta.pid`, or None."""
    try:
        with open(os.path.join(run, "kern/pods", name, "pasta.pid")) as f:
            return int(f.read().strip().split(":")[0])
    except (OSError, ValueError):
        return None


def alive(pid):
    if pid is None or not os.path.exists(f"/proc/{pid}"):
        return False
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def main():
    kern = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "target/release/kern")
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 25
    if not os.access(kern, os.X_OK):
        skip(f"{kern} is not executable")
    run = os.environ.get("XDG_RUNTIME_DIR")
    if not run:
        skip("XDG_RUNTIME_DIR is unset, so the pod root is not where this script looks")

    def kern_run(*a):
        return subprocess.run([kern, *a], capture_output=True, text=True)

    failures = 0
    for r in range(rounds):
        names = [f"il{r}a", f"il{r}b", f"bystander{r}"]
        for n in names:
            kern_run("pod", "create", n)
        time.sleep(0.3)
        watched = pasta_of(run, names[2])
        if watched is None:
            for n in names:
                kern_run("pod", "rm", n)
            skip("no pasta for the bystander: this host has no outbound pod networking")
        if not alive(watched):
            for n in names:
                kern_run("pod", "rm", n)
            skip(f"the bystander's pasta {watched} was not running before the race")

        # The two teardowns start together. Their scans of the pod root overlap, and each
        # removes a dir the other may be reading.
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda n: kern_run("pod", "rm", n), names[:2]))
        time.sleep(0.2)

        survived = alive(watched)
        if not survived:
            failures += 1
            print(f"FAIL round {r}: the bystander's pasta {watched} was signalled by a "
                  f"teardown of {names[0]} / {names[1]}")
        kern_run("pod", "rm", names[2])
        if not survived:
            break

    if failures:
        return 1
    print(f"PASS: the bystander's pasta survived {rounds} concurrent teardown pairs")
    print("      (a pass bounds the window, it does not close it: see the module docstring)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
