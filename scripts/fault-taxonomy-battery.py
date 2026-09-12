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


def kern_procs(kern: str) -> set:
    """PIDs running THE BINARY UNDER TEST, by its path. Not `grep kern`, which also matches kern-mcp,
    a `kern-pi` extension and this script's own command line."""
    ps = subprocess.run(["ps", "-eo", "pid,args", "-u", str(os.getuid())],
                        capture_output=True, text=True, check=False)
    out = set()
    for line in ps.stdout.splitlines()[1:]:
        pid, _, args = line.strip().partition(" ")
        if kern in args and "fault-taxonomy" not in args and pid.isdigit():
            out.add(int(pid))
    return out


def memory_cap_bites(kern: str) -> "tuple[bool, str]":
    """Does a `--memory` cap actually BIND on this host? Returns (verdict, the evidence for it).

    ASKED ONCE, AND ASKED OF THE BOX. The three OOM cases below are the only ones that need a cap to
    fire, and on a host with no cgroup delegation they cannot fire at all: kern accepts the write and
    the kernel never enforces it. The first version of this script decided that per case, by looking for
    the words "not enforced" in the fault MESSAGE, and that was the very mistake this file lectures
    about: a skip must key on the HOST's capability, not on a string. It cost a reviewer a false red,
    because that sentence only appears when kern's enforcement byte is exactly 2, so the one-shot path
    skipped while the resident-kernel and prewarm paths failed for the same host.

    The evidence is `memory.max` read from INSIDE a capped box, which is the same question the feature
    depends on, so the skip cannot hide the defect.
    """
    probe = subprocess.run(
        [kern, "box", f"taxcap-{os.getpid()}", "--image", "alpine", "--memory", "64m", "--",
         "/bin/sh", "-c",
         "cat /sys/fs/cgroup$(awk -F: '/^0::/{print $3}' /proc/self/cgroup)/memory.max 2>/dev/null"],
        capture_output=True, text=True, check=False,
    )
    seen = (probe.stdout or "").strip() or "(nothing)"
    if probe.returncode != 0:
        return False, f"the probe box did not run (exit {probe.returncode})"
    if seen in ("", "max", "(nothing)"):
        return False, f"memory.max inside a box capped at 64m reads {seen!r}"
    return True, f"memory.max inside a box capped at 64m reads {seen!r}"


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

    # THE BASELINE FIRST, so the residue check below is a delta and never a count of what was already
    # on the machine.
    baseline_procs = kern_procs(kern)
    before = running(kern)

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

    # THE SECOND LAYER OF THE GATE, and a reviewer found it by attacking the design rather than the code:
    # answering `kern <version>` is not behaving like kern. A two-line script that prints a kern-looking
    # version and then exits 0 passed the identity check and produced `success=True` with an empty stdout.
    # The invariant that closes it is the started byte, written by every kern since v0.9.2.
    import tempfile

    d = tempfile.mkdtemp(prefix="kern-idonly-")
    stub = os.path.join(d, "kern")
    with open(stub, "w", encoding="utf-8") as f:
        f.write('#!/bin/sh\ncase "$1" in --version) echo "kern v9.9.9-fake" ; exit 0 ;; esac\nexit 0\n')
    os.chmod(stub, 0o755)
    os.environ["KERN_BIN"] = stub
    try:
        with Sandbox(image="x", timeout_s=5) as sbx:
            r = sbx.run_code("print('never ran')")
        result("a binary that only IDENTIFIES itself", "startup_failed", fault_of(r))
    except SandboxError as e:
        result("a binary that only IDENTIFIES itself", "startup_failed", f"RAISED {str(e)[:60]}")
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

    caps_bite, cap_evidence = memory_cap_bites(kern)
    print(f"host   : memory cap {'BITES' if caps_bite else 'does NOT bite'} ({cap_evidence})")

    print("one-shot path:")
    if caps_bite:
        with Sandbox(image=IMAGE, memory_mb=64, timeout_s=90) as s:
            result("real OOM", "oom", fault_of(s.run_code(HOG)))
    else:
        skip("real OOM", f"a memory cap does not bind here: {cap_evidence}")
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
    # A CELL CANNOT FABRICATE A BLOCKED ESCAPE, and the reason is the kernel rather than anything here:
    # the box's workload is pid 1 of its own pid namespace, and the kernel does not deliver an unhandled
    # fatal signal to a namespace's init from INSIDE it. So `os.kill(os.getpid(), SIGSYS)` is swallowed
    # and the cell simply finishes. A reviewer supposed this route reopened the forgery that the fourth
    # byte closed from the exit-code side; measured, it does not exist. The same property is why
    # `kill -9 $$` cannot end a box from inside.
    with Sandbox(image=IMAGE, memory_mb=256, timeout_s=30) as s:
        r = s.run_code("import os, signal\nos.kill(os.getpid(), signal.SIGSYS)")
        result("a cell cannot fabricate escape_blocked", None, fault_of(r))
        # And a real crash of the workload is the USER's failure, reported with its signal in the code:
        # 139 = 128 + SIGSEGV. Not a fault, because the sandbox did nothing.
        r = s.run_code("import ctypes; ctypes.string_at(0)")
        result("a crash is not a sandbox fault", None, fault_of(r))
        result("a crash carries its signal in the code", 139, r.exit_code)

    # THE PAIR THAT NEEDS kern's FOURTH BYTE: the same exit code as a SIGKILL, chosen by the workload.
    # Without the signal byte these came back `killed` and `escape_blocked`, both invented.
    with Sandbox(image="alpine", memory_mb=256, timeout_s=30) as s:
        for code in (137, 159, 143):
            result(f"chosen exit {code} is not a signal", None, fault_of(s.run(["/bin/sh", "-c", f"exit {code}"])))
    snap = running(kern)
    with Sandbox(image=IMAGE, memory_mb=256, timeout_s=90) as s:
        threading.Timer(2.5, lambda: stop_new(kern, snap)).start()
        result("external kill", "killed", fault_of(s.run_code(SLEEP)))

    print("resident-kernel path:")
    if caps_bite:
        with Sandbox(image=IMAGE, memory_mb=64, timeout_s=90) as s:
            with s.kernel() as k:
                try:
                    result("real OOM", "oom", fault_of(k.run_code(HOG)))
                except SandboxError as e:
                    # The shape the inversion had: a real OOM raised instead of returning `oom`.
                    result("real OOM", "oom", f"RAISED {str(e)[:70]}")
    else:
        skip("real OOM", f"a memory cap does not bind here: {cap_evidence}")
    snap = running(kern)
    with Sandbox(image=IMAGE, memory_mb=256, timeout_s=90) as s:
        with s.kernel() as k:
            threading.Timer(2.5, lambda: stop_new(kern, snap)).start()
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
    if caps_bite:
        with Sandbox(image=IMAGE, memory_mb=64, timeout_s=90, prewarm=1) as s:
            time.sleep(0.5)  # let the pool claim one, or this measures the cold path instead
            result("real OOM", "oom", fault_of(s.run_code(HOG)))
    else:
        skip("real OOM", f"a memory cap does not bind here: {cap_evidence}")

    # THE RESIDUE, because a correct verdict that leaves a box behind is still a defect. A DELTA against
    # the baseline taken before anything ran, never an absolute count: a reviewer got a false red here
    # because he had his own box up while the battery ran, and a suite that fails on someone else's
    # process is measuring the machine rather than itself. Counted by the binary's own PATH and not by
    # the string "kern", which also matches kern-mcp and this script's harness.
    print("residue:")
    left = running(kern) - before
    now = kern_procs(kern)
    leaked = sorted(now - baseline_procs)
    result("no box left behind", [], sorted(left))
    result("no kern process left behind", [], leaked, "(pids this run started and did not reap)")

    print(f"\n{ok} ok, {bad} failed, {skipped} skipped")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
