#!/usr/bin/env python3
"""A worker POOL: N independent requests, each in its own FRESH throwaway box, faults contained.

The serverless / per-request pattern in Python: you receive a batch of requests (say, code snippets from
different users or different agent turns) and process them concurrently. Each request gets a brand-new,
network-off box with its own namespaces and caps, so ONE request's timeout, crash, or OOM cannot touch
any other - no shared interpreter, no shared filesystem, nothing to leak between them. When its box
exits, everything it did is gone.

Because boxes start in milliseconds, "a fresh box per request" is cheap enough to be the default. We map
over the batch with a stdlib thread pool - no external deps, runs anywhere python does. The pool is only
concurrency; the ISOLATION is the box (a `kern.run_code` throwaway session per request).

    KERN_BIN=./target/release/kern python3 examples/per-request-workers.py

Honest threat model: a KERNEL-boundary sandbox for YOUR OWN or SEMI-TRUSTED code. seccomp is a
denylist, not a hard multi-tenant wall. See bindings/python/README.md.
"""
from concurrent.futures import ThreadPoolExecutor

import kern_sandbox as kern

# A batch of "requests". Each is a snippet of (untrusted) code. Two are hostile - a runaway loop and a
# hard crash - deliberately mixed in with well-behaved ones to show the blast radius is one box.
REQUESTS = {
    "add":       "print(2 + 2)",
    "factorial": "import math; print(math.factorial(20))",
    "runaway":   "while True: pass",              # will hit its per-box timeout
    "crash":     "raise SystemExit('boom')",      # non-zero exit - just this request fails
    "reverse":   "print('kern'[::-1])",
}


def handle(item: tuple[str, str]) -> tuple[str, str]:
    """Process ONE request in its own throwaway box. Returns (name, one-line summary).

    Note there is no try/except around a misbehaving payload: a timeout or kill comes back as
    `r.fault` (data), so the worker just reads the result and reports. A raise here would only mean a
    real config error (kern missing) - a genuine operational problem worth surfacing.
    """
    name, code = item
    r = kern.run_code(code, memory_mb=128, cpus=0.5, timeout_s=2)
    if r.fault is not None:
        return name, f"FAULT[{r.fault.type}] {r.fault.message}"
    if not r.success:
        return name, f"failed exit={r.exit_code}: {r.stderr.strip().splitlines()[-1] if r.stderr else ''}"
    return name, f"ok: {r.stdout.strip()}  ({r.duration_ms} ms)"


# Fan out: each request runs in parallel, each in its own isolated box. `map` preserves input order.
print(f"dispatching {len(REQUESTS)} requests, one fresh box each:\n")
with ThreadPoolExecutor(max_workers=4) as pool:
    for name, summary in pool.map(handle, REQUESTS.items()):
        print(f"  {name:<10} {summary}")

print(
    "\ndone - the 'runaway' and 'crash' requests were contained to their own boxes;\n"
    "     every other request completed normally. No shared state, nothing left behind."
)
