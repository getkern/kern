#!/usr/bin/env python3
"""Embed kern in Python: run LLM/agent-generated code in a fresh kernel sandbox per call.

This is the `kern_sandbox` package (install from source: `pip install ./bindings/python`) — a thin, safe
wrapper around the `kern` binary. Each `run_code()`/`run()` spawns a FRESH, ephemeral box (user
namespace + seccomp + cgroups); FILE state persists between steps via a workspace directory on disk,
but PROCESSES do not (no resident interpreter — write to disk if you need continuity).

Safe by default: no network, no host mounts, seccomp on, resource caps enforced. Sandbox events
(timeout / blocked-escape / OOM-kill) come back as DATA in `result.fault`, never as an exception —
so running untrusted code doesn't force a try/except for normal outcomes.

    KERN_BIN=./target/release/kern python3 examples/embed-python.py

Honest threat model: this is a KERNEL-boundary sandbox for YOUR OWN or SEMI-TRUSTED code. seccomp is
a denylist — good for agent/CI code, NOT a hard boundary against deliberately hostile multi-tenant
code (for that use a microVM / gVisor). See bindings/python/README.md.
"""
import kern_sandbox as kern

# 1) One-shot: a throwaway box, structured result. Network is OFF; the code cannot reach the host.
print("1) one-shot run_code (fresh box, network off):")
r = kern.run_code("import sys, platform; print(platform.python_version()); print(sum(range(100)))")
print(f"   success={r.success}  exit={r.exit_code}  {r.duration_ms} ms")
print("   stdout:", r.stdout.strip().replace("\n", " | "))

# 2) A session: FILE state persists across steps (a workspace on disk), each step is a fresh box.
#    `setup=` is the ONE moment the network is on (a separate box that installs deps, then dies).
print("\n2) a session — write a file in one step, read it in the next:")
with kern.Sandbox(memory_mb=256, cpus=0.5, timeout_s=15) as sbx:
    sbx.write_file("data.csv", "a,b\n1,2\n3,4\n")
    r = sbx.run_code(
        "print(sum(int(l.split(',')[0]) for l in open('data.csv').read().splitlines()[1:]))"
    )
    print(f"   computed from the CSV the previous step wrote: {r.stdout.strip()}  (success={r.success})")

# 3) Untrusted code that misbehaves is reported as a FAULT (data), not an exception.
print("\n3) untrusted code that runs away — reported as a fault, not a crash:")
with kern.Sandbox(timeout_s=2) as sbx:
    r = sbx.run_code("while True: pass")   # infinite loop
    if r.fault:
        print(f"   fault.type={r.fault.type!r}  -> {r.fault.message}")
    print(f"   success={r.success}   (the binding killed the box at its deadline)")

# 4) The isolation is real: with no `network=True`, the box cannot open a socket to the outside.
print("\n4) network is off by default — an outbound connection fails:")
with kern.Sandbox(timeout_s=10) as sbx:
    r = sbx.run_code(
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 53), timeout=3); print('REACHED (unexpected)')\n"
        "except OSError as e:\n"
        "    print('no route out of the box:', e.__class__.__name__)"
    )
    print("   ", r.stdout.strip())

print("\ndone — a fresh, isolated box per call; file-state on disk; faults as data.")
