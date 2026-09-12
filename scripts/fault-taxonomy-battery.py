#!/usr/bin/env python3
"""The fault taxonomy, measured against a real binary on every path that can produce one.

WHY THIS EXISTS. An agent branches on `fault.type`, so a wrong label is worse than no label: it sends
the loop to fix the wrong thing. Three of the five classes are produced by deaths that look IDENTICAL
from outside - the kernel's OOM killer, an external kill, and our own deadline are all exit 137 - and
the project has shipped a wrong verdict for each of them in turn:

  * a `kern stop` during a cell was reported `oom`, so an agent retried with more memory a kill that
    had nothing to do with memory;
  * a REAL OOM on a resident kernel was reported as a box that never started, and RAISED, so the
    flagship path could not produce an `oom` at all;
  * a cell calling `sys.exit(137)` was reported `killed`, and `sys.exit(159)` was reported
    `escape_blocked`, which is a security event a cell could fabricate in one line;
  * a binding pointed at a binary that is not kern reported `success=True` for code that never ran.

Each of those was found by a measurement and none of them by reading the code. This is that
measurement, in the repository, so it can be re-run against the tarball before a release instead of
living in a shell history. A reboot took the previous copy out of /tmp, which is how it got written.

WHAT IT IS NOT. It does not test the classifier's internals: those have unit tests, and a unit test
cannot tell you that kern's wording moved or that a host has no cgroup delegation. Everything here
goes through a real box.

SKIP DISCIPLINE. The skip condition is always the HOST's capability, never this script's expectation,
because a test that skips whenever its expectation is unmet is a permanent no-op: one in this tree was
exactly that for months. Every skip prints the output that proves the host could not answer.

    scripts/fault-taxonomy-battery.py [/path/to/kern]

`$KERN_BIN` is used when no path is given. Exit 0 iff every case that COULD be measured was correct.
"""

import json
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SDK = os.path.join(os.path.dirname(HERE), "bindings", "python")
sys.path.insert(0, SDK)

IMAGE = os.environ.get("KERN_TAXONOMY_IMAGE", "python:3.11-alpine")
# An allocator that touches every page, so the kernel has to back it and the cap has to fire.
HOG = "b=bytearray()\nwhile True: b.extend(bytearray(8*1024*1024))\n"
SLEEP = "import time\nfor _ in range(120): time.sleep(1)\n"

ok = 0
bad = 0
skipped = 0


def result(tag: str, expected, got, note: str = "") -> None:
    global ok, bad
    if got == expected:
        ok += 1
        print(f"  OK   {tag}: {got!r}")
    else:
        bad += 1
        print(f"  FAIL {tag}: got {got!r}, expected {expected!r} {note}")


def skip(tag: str, why: str) -> None:
    global skipped
    skipped += 1
    print(f"  SKIP {tag}: {why}")


def fault_of(r) -> "str | None":
    return r.fault.type if r.fault else None


def running(kern: str) -> set:
    """Box names kern will admit to, from the registry rather than from `ps`'s table."""
    p = subprocess.run([kern, "ps", "--json"], capture_output=True, text=True, check=False)
    try:
        return {r.get("name") for r in json.loads(p.stdout or "[]") if r.get("name")}
    except json.JSONDecodeError:
        return set()


def stop_new(kern: str, before: set) -> list:
    """Stop only boxes that appeared AFTER the snapshot, so a concurrent session is never touched."""
    out = []
    for n in running(kern) - before:
        subprocess.run([kern, "stop", n], capture_output=True, text=True, check=False)
        out.append(n)
    return out


def main() -> int:
    kern = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("KERN_BIN") or ""
    if not kern or not os.access(kern, os.X_OK):
        print("usage: fault-taxonomy-battery.py [/path/to/kern]   (or set $KERN_BIN)")
        return 2
    kern = os.path.abspath(kern)
    os.environ["KERN_BIN"] = kern

    # IDENTITY FIRST, and it is not a formality: a previous review measured a DIFFERENT binary for four
    # pages. The sha goes in the output so a result can never be quoted about the wrong program.
    ver = subprocess.run([kern, "--version"], capture_output=True, text=True, check=False)
    sha = subprocess.run(["sha256sum", kern], capture_output=True, text=True, check=False)
    print(f"binary : {kern}")
    print(f"version: {(ver.stdout or ver.stderr).strip()}")
    print(f"sha256 : {sha.stdout.split()[0] if sha.stdout else '?'}")
    print(f"image  : {IMAGE}")

    from kern_sandbox import Sandbox, SandboxError  # noqa: E402  (after KERN_BIN is set)

    # THE GATE, AND ITS EXPECTATION IS THE ONE THAT WAS WRONG. A binding pointed at a binary that is
    # not kern must REFUSE, not return an empty successful result: that shape was measured returning
    # `success=True` for code that never ran, and the control this project shipped said to expect zero
    # faults, which blessed it. A refusal here is what proves the rest of the run is about kern at all.
    print("gate:")
    prev = os.environ["KERN_BIN"]
    os.environ["KERN_BIN"] = "/bin/true"
    try:
        import kern_sandbox

        kern_sandbox.run_code("print(1)")
        result("a binary that is not kern", "refused", "accepted", "(the rest of this run proves nothing)")
    except SandboxError as e:
        result("a binary that is not kern", "refused", "refused" if "is not kern" in str(e) else str(e)[:60])
    finally:
        os.environ["KERN_BIN"] = prev

    # Can this host build a box at all? Everything below needs one, and a host that cannot say so must
    # skip rather than fail: the CI runner allows the namespace and refuses the rootless uid map.
    probe = subprocess.run([kern, "box", f"taxprobe-{os.getpid()}", "--image", "alpine", "--", "/bin/true"],
                           capture_output=True, text=True, check=False)
    if probe.returncode != 0:
        print("host:")
        skip("every case", f"this host cannot build a box: {probe.stderr.strip()[:160]}")
        print(f"\n{ok} ok, {bad} failed, {skipped} skipped")
        return 0 if bad == 0 else 1

    print("one-shot path:")
    with Sandbox(image=IMAGE, memory_mb=64, timeout_s=90) as s:
        r = s.run_code(HOG)
        if fault_of(r) == "killed" and "not enforced" in (r.fault.message or ""):
            skip("real OOM", "no cgroup delegation here, so the cap cannot fire and kern says so")
        else:
            result("real OOM", "oom", fault_of(r))
    with Sandbox(image=IMAGE, memory_mb=256, timeout_s=3) as s:
        result("our deadline", "timeout", fault_of(s.run_code(SLEEP)))
    with Sandbox(image=IMAGE, memory_mb=256, timeout_s=30) as s:
        result("user error is not a fault", None, fault_of(s.run_code("raise ValueError('mine')")))
    with Sandbox(image=IMAGE, memory_mb=256, timeout_s=30) as s:
        r = s.run_code("import ctypes; ctypes.CDLL(None).mount(b'x',b'/mnt',b'tmpfs',0,None)")
        result("blocked syscall", "escape_blocked", fault_of(r))
    with Sandbox(image=IMAGE, memory_mb=256, timeout_s=30) as s:
        r = s.run_code("print(1)", language="node")
        result("missing interpreter", "exec_failed", fault_of(r))
    # THE PAIR THAT NEEDS kern's FOURTH BYTE: the same exit code as a SIGKILL, chosen by the workload.
    # Without the signal byte these came back `killed` and `escape_blocked`, both invented.
    with Sandbox(image="alpine", memory_mb=256, timeout_s=30) as s:
        for code in (137, 159, 143):
            result(f"chosen exit {code} is not a signal", None, fault_of(s.run(["/bin/sh", "-c", f"exit {code}"])))
    before = running(kern)
    with Sandbox(image=IMAGE, memory_mb=256, timeout_s=90) as s:
        threading.Timer(2.5, lambda: stop_new(kern, before)).start()
        result("external kill", "killed", fault_of(s.run_code(SLEEP)))

    print("resident-kernel path:")
    with Sandbox(image=IMAGE, memory_mb=64, timeout_s=90) as s:
        with s.kernel() as k:
            try:
                r = k.run_code(HOG)
                if fault_of(r) == "killed" and "not enforced" in (r.fault.message or ""):
                    skip("real OOM", "no cgroup delegation here")
                else:
                    result("real OOM", "oom", fault_of(r))
            except SandboxError as e:
                # This is the shape the inversion had: a real OOM raised instead of returning `oom`.
                result("real OOM", "oom", f"RAISED {str(e)[:70]}")
    before = running(kern)
    with Sandbox(image=IMAGE, memory_mb=256, timeout_s=90) as s:
        with s.kernel() as k:
            threading.Timer(2.5, lambda: stop_new(kern, before)).start()
            try:
                result("external kill", "killed", fault_of(k.run_code(SLEEP)))
            except SandboxError as e:
                result("external kill", "killed", f"RAISED {str(e)[:70]}")
    with Sandbox(image=IMAGE, memory_mb=256, timeout_s=3) as s:
        with s.kernel() as k:
            result("our deadline", "timeout", fault_of(k.run_code(SLEEP)))
    with Sandbox(image=IMAGE, memory_mb=256, timeout_s=30) as s:
        with s.kernel() as k:
            result("user error is not a fault", None, fault_of(k.run_code("raise ValueError('mine')")))

    print("prewarm path:")
    with Sandbox(image=IMAGE, memory_mb=64, timeout_s=90, prewarm=1) as s:
        time.sleep(0.5)  # let the pool claim one, or this measures the cold path instead
        r = s.run_code(HOG)
        if fault_of(r) == "killed" and "not enforced" in (r.fault.message or ""):
            skip("real OOM", "no cgroup delegation here")
        else:
            result("real OOM", "oom", fault_of(r))

    # THE RESIDUE, because a correct verdict left behind a box is still a defect. Counted from the
    # registry and from the process table by the binary's own PATH, not by the string "kern", which also
    # matches kern-mcp and this script's own harness.
    print("residue:")
    left = running(kern) - before
    ps = subprocess.run(["ps", "-eo", "args", "-u", str(os.getuid())], capture_output=True, text=True, check=False)
    procs = [l for l in ps.stdout.splitlines() if kern in l and "fault-taxonomy" not in l]
    result("no box left behind", [], sorted(left))
    result("no kern process left behind", 0, len(procs), f"({procs[:2]})" if procs else "")

    print(f"\n{ok} ok, {bad} failed, {skipped} skipped")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
