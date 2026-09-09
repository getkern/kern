#!/usr/bin/env python3
"""Does a teardown signal a STRANGER that inherited a recorded pasta's pid?

THE CASE, which an external reviewer named and no test reached. `pasta_to_signal`'s
fallback - taken by a pod dir with no `pasta.id`, i.e. one written by an older kern -
decides on `comm` plus a scan of the other pod dirs. Neither can tell kern's pasta from
somebody else's: `comm` is `pasta` for every pasta on the host, and the cross-pod scan
only covers pods. podman uses pasta too, so the stranger is not hypothetical.

WHY THIS NEEDS A HARNESS RATHER THAN A UNIT TEST. The predicate is private and the
interesting input is a pid the kernel handed out twice. Both are reachable from outside:
`ns_last_pid` sets the next pid to be allocated, and `unshare -Ur -p --fork` gives an
unprivileged user CAP_SYS_ADMIN over a pid namespace, so the recycle is a loop of
milliseconds rather than a wait for the counter to wrap. The pod dir is then crafted by
hand, which is exactly what an older kern leaves behind.

RUN: sudo is NOT needed.  python3 scripts/pid-recycle-pasta.py [path-to-kern]
Exit 0 = the stranger survived. Exit 1 = it was signalled. Exit 77 = could not build the
case (skipped, with the reason), which is never reported as a pass.
"""
import ctypes
import os
import shutil
import signal
import subprocess
import sys
import time

SKIP = 77
NS_LAST_PID = "/proc/sys/kernel/ns_last_pid"


def skip(reason):
    print(f"SKIP: {reason}")
    sys.exit(SKIP)


def inner(kern):
    """Runs as pid 1 of a fresh pid namespace, uid 0 of a fresh user namespace."""
    if not os.path.exists(NS_LAST_PID):
        skip(f"{NS_LAST_PID} is absent on this kernel")

    # A pid to burn, so its number is free and known. Reaped, so nothing holds it.
    victim = os.fork()
    if victim == 0:
        os._exit(0)
    os.waitpid(victim, 0)
    print(f"  recorded pid to recycle: {victim}")

    # Hand the SAME number to a different process. `ns_last_pid` names the LAST allocated,
    # so the next fork gets victim.
    target = victim
    got, tries = None, 0
    while got != target and tries < 200:
        tries += 1
        try:
            with open(NS_LAST_PID, "w") as f:
                f.write(str(target - 1))
        except OSError as e:
            skip(f"cannot write {NS_LAST_PID}: {e}")
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            # THE COINCIDENCE THE GUARD IS FOR: a stranger whose name happens to be pasta.
            # `prctl(PR_SET_NAME)` is how any process sets its own `comm`; podman's pasta
            # arrives at the same string by being pasta.
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.prctl(15, b"pasta", 0, 0, 0)  # PR_SET_NAME
            os.write(w, b"x")
            os.close(w)
            time.sleep(30)
            os._exit(0)
        os.close(w)
        os.read(r, 1)
        os.close(r)
        got = pid
        if got != target:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
    if got != target:
        skip(f"could not force pid {target} in {tries} attempts")
    print(f"  recycled after {tries} attempt(s): pid {got} now has comm="
          f"{open(f'/proc/{got}/comm').read().strip()!r}")

    # A pod dir exactly as an older kern left it: a bare `pasta.pid`, no `pasta.id`, no
    # `boot`. That is the fallback's entire population.
    run = os.environ["XDG_RUNTIME_DIR"]
    dir_ = os.path.join(run, "kern/pods/legacy")
    os.makedirs(dir_, exist_ok=True)
    with open(os.path.join(dir_, "pasta.pid"), "w") as f:
        f.write(f"{got}\n")
    with open(os.path.join(dir_, "holder"), "w") as f:
        f.write("999999\n")  # a holder that is not running
    print(f"  crafted legacy pod dir: {dir_}")

    subprocess.run([kern, "pod", "rm", "legacy"], capture_output=True)
    time.sleep(0.4)

    alive = os.path.exists(f"/proc/{got}")
    state = ""
    if alive:
        try:
            with open(f"/proc/{got}/stat") as f:
                state = f.read().rsplit(")", 1)[1].split()[0]
        except OSError:
            pass
    if alive and state != "Z":
        print(f"PASS: the stranger (pid {got}) survived `pod rm`")
        return 0
    print(f"FAIL: the stranger (pid {got}) was signalled by a teardown that never "
          f"started it (alive={alive} state={state!r})")
    return 1


def main():
    kern = sys.argv[1] if len(sys.argv) > 1 else "target/release/kern"
    kern = os.path.abspath(kern)
    if not os.access(kern, os.X_OK):
        skip(f"{kern} is not executable")

    if os.environ.get("_PIDRECYCLE_INNER") == "1":
        sys.exit(inner(kern))

    if shutil.which("unshare") is None:
        skip("unshare(1) is absent")
    run = "/tmp/kern-pidrecycle-run"
    shutil.rmtree(run, ignore_errors=True)
    os.makedirs(run, exist_ok=True)
    env = dict(os.environ, _PIDRECYCLE_INNER="1", XDG_RUNTIME_DIR=run)
    # `-p --fork --mount-proc`: a fresh pid namespace whose /proc reflects it, so
    # `ns_last_pid` is the namespace's own counter. `-Ur` maps our uid to root inside,
    # which is what grants CAP_SYS_ADMIN over that namespace.
    cmd = ["unshare", "-Ur", "-p", "--fork", "--mount-proc",
           sys.executable, os.path.abspath(__file__), kern]
    print("kern:", kern)
    p = subprocess.run(cmd, env=env)
    shutil.rmtree(run, ignore_errors=True)
    if p.returncode not in (0, 1, SKIP):
        skip(f"the namespace could not be entered (exit {p.returncode})")
    sys.exit(p.returncode)


if __name__ == "__main__":
    main()
