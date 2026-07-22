#!/usr/bin/env python3
"""The warm kernel: a persistent, WARM interpreter that kills the ~10 ms CPython boot per cell.

Each `run_code` starts a FRESH interpreter, so it pays the interpreter boot every call. For a REPL, a
notebook, or an agent's tool loop that runs many cells sharing state, open a `kernel()` instead: ONE warm
interpreter in a long-lived box, fed cells over a private pipe. In-memory state persists across cells and
the per-cell cost drops from ~16 ms to sub-millisecond (about 300x), with the same rich results, still
network-off and resource-capped. Trade: call-fast, not call-isolated (one process, one box; a fresh
session/kernel is clean). This is the E2B/Jupyter "kernel" pattern, but local, ~2 ms cold, and free.

What it shows, each an actual agent/notebook need:
  1. State persists        : `x = 40` in one cell is still there in the next (a real REPL).
  2. Sub-ms cells          : measured, so you see the ~300x vs a cold run_code.
  3. Rich results          : a matplotlib figure auto-captured as result.results[i].png, no savefig.
  4. Errors are confined   : a cell that raises does NOT kill the kernel, and its state survives.
  5. Still sandboxed       : the network is off and a raw fd write cannot corrupt the control channel.
  6. Timeout tears it down : a runaway cell hits the deadline and the kernel is torn down as a fault.

Run:  KERN_BIN=/path/to/kern python3 examples/warm-kernel.py
      (or have `kern` on PATH). Needs outbound network once, for the matplotlib install.
"""

import time

import kern_sandbox as kern


def rule(t):
    print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)


with kern.Sandbox(setup="pip install matplotlib", memory_mb=1024, timeout_s=90) as sbx:
    # open the warm kernel: one long-lived box with a resident interpreter, cells fed over a pipe.
    with sbx.kernel() as k:
        rule("1. in-memory state persists across cells (a real REPL, not a fresh box each call)")
        k.run_code("x = 40")  # first cell sets state
        r = k.run_code("y = x + 2\nprint('y =', y)")  # x survived from the previous cell
        print("  ", r.stdout.strip(), "  <- x carried over, no re-declaration")

        rule("2. sub-millisecond cells (vs a cold run_code's ~16 ms)")
        for _ in range(5):
            k.run_code("1 + 1")  # warm up the pipe
        xs = []
        for _ in range(200):
            t = time.perf_counter_ns()
            k.run_code("sum(range(1000))")
            xs.append((time.perf_counter_ns() - t) / 1e6)
        xs.sort()
        print(f"   warm cell: min {xs[0]:.3f} ms  median {xs[len(xs) // 2]:.3f} ms  (a cold run_code is ~16 ms)")

        rule("3. rich results: a matplotlib figure, auto-captured, no savefig")
        k.run_code("import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt")
        r = k.run_code("plt.plot([1, 4, 9, 16]); plt.title('from a warm cell')")
        png = next((res.png for res in r.results if res.png), None)
        print("   chart captured:", f"{len(png)} PNG bytes" if png else "none")

        rule("4. an error is confined: the cell fails, the kernel keeps serving with state intact")
        k.run_code("saved = 'still here'")
        r = k.run_code("1 / 0")  # raises
        print("   error cell:", "rc", r.exit_code, "| ZeroDivisionError in stderr:", "ZeroDivisionError" in r.stderr)
        r = k.run_code("print(saved)")  # kernel alive, state intact
        print("   kernel survived, state:", r.stdout.strip())

        rule("5. still sandboxed: network off, and a raw fd write cannot corrupt the control channel")
        r = k.run_code(
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 80), 2); print('LEAK')\n"
            "except OSError as e:\n"
            "    print('network off:', type(e).__name__)"
        )
        print("  ", r.stdout.strip())
        r = k.run_code("import os; os.write(1, b'RAW-FD1\\n'); print('and print')")
        print("   raw fd write captured, protocol intact:", repr(r.stdout.strip()), "| ok:", r.success)

    rule("6. a per-cell timeout tears the kernel down and reports a fault (not a hang)")
    with sbx.kernel(timeout_s=2) as k:
        t = time.perf_counter()
        r = k.run_code("while True: pass")  # infinite loop
        print(f"   fault: {r.fault.type if r.fault else None}  ({time.perf_counter() - t:.1f} s, deadline 2 s)")
        try:
            k.run_code("1 + 1")
        except kern.SandboxError as e:
            print("   dead-kernel guard:", str(e)[:48])

print("\nDone. State persists in a kernel; a fresh Sandbox()/kernel() is always a clean slate.")
