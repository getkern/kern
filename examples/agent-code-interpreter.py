#!/usr/bin/env python3
"""A realistic LLM/agent code interpreter on kern, exercising the 0.6.7 / 0.6.8 features at their edges.

What it shows, each an actual agent-harness need:
  1. Egress allowlist    : the agent may `pip install` from PyPI but CANNOT exfiltrate to anywhere else.
  2. Live streaming      : tokens of stdout stream back as the code runs (on_stdout), not just at the end.
  3. Chart return        : no Jupyter kernel, yet the matplotlib figure is auto-captured as a rich,
                           mime-typed result (result.results[i].png) the way an E2B/Jupyter cell returns it.
  4. Faults as data      : a timeout, an OOM kill, and a blocked syscall come back as data, never crash.
  5. Snapshot / restore  : checkpoint the workspace after an expensive step, resume it in a fresh session.
  6. Node language       : the same sandbox runs JavaScript, not just Python.

Run:  KERN_BIN=/path/to/kern python3 examples/agent-code-interpreter.py
      (or have `kern` on PATH). Needs outbound network for the one pip install.
"""

import sys

import kern_sandbox as kern


def rule(t):
    print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)


# --- 1 + 2 + 3: install a dep under an egress allowlist, stream output, return a chart ---------------
rule("1-3. egress-allowed install + live streaming + chart return")
# The agent is UNTRUSTED. It gets the network only to reach PyPI (index + CDN), nothing else: a prompt
# injection telling it to POST your secrets to evil.example cannot leave the box.
with kern.Sandbox(
    setup="pip install matplotlib",
    egress_allow=["pypi.org", "files.pythonhosted.org"],
    memory_mb=512,
    timeout_s=90,
    on_stdout=lambda b: (sys.stdout.write(b.decode(errors="replace")), sys.stdout.flush()),
) as sbx:
    r = sbx.run_code(
        "import matplotlib; matplotlib.use('Agg')\n"
        "import matplotlib.pyplot as plt\n"
        "for i in range(3): print('rendering pass', i, flush=True)\n"
        "plt.plot([1, 4, 9, 16]); plt.title('from the agent')\n"  # no savefig: the figure is auto-captured
        "print('done')\n"
    )
    png = next((res.png for res in r.results if res.png), b"")  # rich mime-typed result, Jupyter/E2B-style
    print(f"[host] chart auto-captured: {len(png)} bytes, PNG header ok: {png[:8] == bytes.fromhex('89504e470d0a1a0a')}")

    # EDGE: the agent tries to phone home to a NON-allowlisted host. It must fail closed.
    leak = sbx.run_code(
        "import urllib.request as u\n"
        "try:\n u.urlopen('http://api.ipify.org', timeout=6); print('LEAKED')\n"
        "except Exception as e: print('exfil blocked:', type(e).__name__)\n"
    )
    print("[host] exfiltration attempt ->", leak.stdout.strip())

# --- 4: faults come back as DATA, so the agent loop can react instead of catching exceptions ---------
rule("4. faults as data (timeout / OOM / blocked escape)")
with kern.Sandbox(memory_mb=64, timeout_s=3) as sbx:
    t = sbx.run_code("while True: pass")  # never terminates
    print("timeout   ->", t.fault and t.fault.type)
    oom = sbx.run_code("x = bytearray()\nwhile True: x += bytes(10_000_000)")
    print("oom kill  ->", oom.fault and oom.fault.type)
    esc = sbx.run_code(
        "import ctypes; ctypes.CDLL(None).syscall(272)"  # a denied syscall -> SIGSYS
    )
    print("escape    ->", esc.fault and esc.fault.type)

# --- 5: snapshot an expensive workspace, resume it in a brand-new session (warm start) ---------------
rule("5. snapshot / restore (checkpoint the workspace, resume cold)")
import tempfile

snap = tempfile.mktemp(suffix=".tar.gz")
with kern.Sandbox() as sbx:
    sbx.run_code("open('model.bin', 'wb').write(b'expensive-artifact' * 1000)")
    sbx.write_file("notes.md", "step 1 complete\n")
    sbx.snapshot(snap)
    print(f"[host] checkpoint written: {snap}")

with kern.Sandbox() as resumed:  # a FRESH, empty session
    resumed.restore(snap)
    r = resumed.run_code("import os; print('resumed with', sorted(os.listdir('.')))")
    print("[host] after restore ->", r.stdout.strip())

# --- 6: the same box runs JavaScript ----------------------------------------------------------------
rule("6. node language in the same sandbox")
r = kern.run_code(
    "console.log('hello from node', process.version)",
    language="node",
    image="node:22-slim",  # the image must provide the interpreter you ask for
)
print("node ->", r.stdout.strip(), "| success:", r.success)

print("\nall edge cases exercised.")
