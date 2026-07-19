#!/usr/bin/env python3
"""The canonical "code execution tool" an LLM agent can call - safely run MODEL-GENERATED python.

This is the pattern behind every "the model wrote some code, now run it" agent loop (a coding agent,
a data-analysis agent, a `python` tool in a tool-use API). The model emits code; your harness calls a
function like `run_python_tool(code)`; the function runs that code in a fresh, network-off kern box and
hands back a STRUCTURED result (stdout, success, fault) that you feed to the model as the tool result.

Why faults-as-data (not exceptions) is the whole point here:
  A tool an agent calls must ALWAYS return a result the model can read and react to - even when the
  code runs away, gets OOM-killed, or trips the seccomp filter. If the sandbox raised on a timeout,
  every tool call would need a try/except and, worse, the model would get an opaque harness error
  instead of the fact "your code timed out." kern reports those as `result.fault` (a SandboxFault with
  a `.type` and `.message`); a raise is reserved for YOUR bugs (bad config, kern not installed). So the
  agent loop stays a straight line: run -> serialize result -> next turn. The model reads "timeout" and
  can decide to add a break condition, exactly like a human reading an error.

    KERN_BIN=./target/release/kern python3 examples/agent-tool-runner.py

Honest threat model: a KERNEL-boundary sandbox for YOUR OWN or SEMI-TRUSTED (agent-authored) code.
seccomp is a denylist - right for agent code, NOT a hard wall against deliberately hostile multi-tenant
code (use a microVM / gVisor for that). See bindings/python/README.md.
"""
import json

import kern_sandbox as kern


def run_python_tool(code: str, *, timeout_s: int = 5) -> dict:
    """Execute model-generated `code` in a fresh, isolated box and return a JSON-able tool result.

    Network is OFF and resource caps are on: the model's code can compute, but it cannot phone home,
    fork-bomb the host, or eat all its RAM. NOTHING here raises on a misbehaving payload - a runaway
    loop or a blocked syscall comes back in the `fault` field, which is exactly what you want to show
    the model on the next turn.
    """
    r = kern.run_code(code, memory_mb=256, cpus=0.5, timeout_s=timeout_s)
    return {
        "success": r.success,               # True iff exit 0 AND no sandbox fault
        "stdout": r.stdout.strip(),
        "stderr": r.stderr.strip(),
        "exit_code": r.exit_code,
        "duration_ms": r.duration_ms,
        # fault is None on a clean run; on a sandbox event it's a small {type,message} the model reads.
        "fault": None if r.fault is None else {"type": r.fault.type, "message": r.fault.message},
    }


def show(label: str, code: str, **kw) -> None:
    print(f"\n{label}")
    print(f"  code: {code!r}")
    result = run_python_tool(code, **kw)
    # This dict is literally what you'd hand back to the model as the tool result.
    print("  tool result -> " + json.dumps(result))


# 1) A GOOD call: ordinary model-written code. success=True, the answer is in stdout.
show("1) a well-behaved tool call:", "print(sum(i*i for i in range(10)))")

# 2) A HOSTILE call: an infinite loop. The binding kills the box at its deadline and reports a
#    `timeout` fault as DATA - the loop above (a good call) still succeeded; one bad call is contained
#    and simply reported. The model sees fault.type == "timeout" and can fix its code next turn.
show("2) a runaway loop - returned as a `timeout` fault, not a crash:", "while True: pass", timeout_s=2)

# 3) A HOSTILE call: data exfiltration attempt. Network is off, so the outbound socket simply fails.
#    Note this is NOT a sandbox `fault` (the box did its job) - it's the model's code getting an
#    ordinary OSError, surfaced in stderr with a non-zero exit. Honest classification: the sandbox
#    only claims a fault when the SANDBOX acted (timeout/kill/blocked syscall); a failed connect is
#    just the code failing against a wall it can't see past.
show(
    "3) an exfiltration attempt - no route out of the box:",
    "import socket; socket.create_connection(('1.1.1.1', 53), timeout=3); print('LEAKED')",
    timeout_s=8,
)

print("\ndone - one function the agent calls; every outcome comes back as a readable result.")
