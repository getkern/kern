#!/usr/bin/env python3
"""The MCP server, driven over stdio the way a client drives it, with the features of this branch.

WHY THIS EXISTS AND WHY THE 180 UNIT TESTS DO NOT COVER IT. Those exercise the functions; a client
exercises the SERVER: the handshake, the shape of each reply, and the environment variables a user
puts in a Claude Desktop config. Three of this branch's changes land exactly there and none of them
is visible to a unit test:

  * `KERN_MCP_SETUP` becomes `setup=` on a Sandbox, and this branch REORDERED when the setup box
    runs relative to a resident box. The server does not use `persist`, so the fix should be a no-op
    here - "should be" is the reason this battery exists rather than an argument that it is.
  * `KERN_MCP_IMAGE` can now name the image this repository builds (`images/sandbox/Dockerfile`),
    whose entire point is that `matplotlib` imports WITHOUT `KERN_MCP_SETUP` and therefore without a
    network-on box. That claim is about an image, a server and a filter at once.
  * a cell that prints NOTHING was reported as a sandbox that never started on the resident path.
    The server is on the one-shot path, so it was green before; this is the control that says so.

⛔ THE CHECK IS IN THE REPLY, NEVER IN THE EXIT CODE. An MCP server exits 0 when it answers with
`isError: true`, so a harness reading `$?` would report green on every failure in here. Every case
below asserts on the decoded JSON-RPC result.

WHAT IT IS NOT. It does not test the MCP protocol against a conformance suite, and it does not test
the tools' internals - those have unit tests. It answers one question a unit test cannot: does a
client that configures this server the documented way get what the documentation promises.

IN THE GATE, because it is cheap: MEASURED at 2.95 s and 2.97 s on two consecutive runs, all 15
cases, with the expensive ones genuinely happening - the setup box resolved DNS and connected, the
OOM produced kern's own OOM-killer line, and a 5 MB print came back capped to 16 kB. The first draft
of this docstring said it was too slow for the gate; it was written before the measurement, which is
the habit this file is supposed to be against.

SKIPS WITHOUT A RELEASE BINARY rather than failing, for the same reason `deployment-cli` does: a
checkout that has not built one should not report a red gate for a missing artefact.
"""

import json
import os
import subprocess
import sys
import tempfile

# RESOLVED FROM THIS FILE, not hard-coded to one machine: a battery that only runs in one checkout
# is a battery nobody else runs.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SDK = os.path.join(ROOT, "bindings", "python")
KERN = os.environ.get("KERN_BIN") or os.path.join(ROOT, "target", "release", "kern")
ok = bad = 0


def session(label, calls, env=None, timeout=300):
    """Una sessione: initialize, poi le chiamate. Torna la lista delle risposte ai tool call."""
    msgs = [{"jsonrpc": "2.0", "id": 0, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "batteria", "version": "1"}}}]
    for i, c in enumerate(calls, start=1):
        msgs.append({"jsonrpc": "2.0", "id": i, **c})
    payload = "".join(json.dumps(m) + "\n" for m in msgs)
    e = dict(os.environ, PYTHONPATH=SDK, KERN_BIN=KERN)
    e.update(env or {})
    p = subprocess.run([sys.executable, "-m", "kern_sandbox.mcp"], input=payload,
                       capture_output=True, text=True, cwd=SDK, env=e, timeout=timeout)
    out = []
    for line in p.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"_raw": line[:200]})
    return out, p.stderr


def check(label, cond, detail):
    global ok, bad
    if cond:
        print(f"  ok    {label:54s} {detail}")
        ok += 1
    else:
        print(f"  FAIL  {label:54s} {detail}")
        bad += 1


def text_of(resp):
    r = resp.get("result") or {}
    return "".join(c.get("text", "") for c in r.get("content", [])), bool(r.get("isError"))


def call(code, **kw):
    args = {"code": code}
    args.update(kw)
    return {"method": "tools/call", "params": {"name": "run_code", "arguments": args}}


if not os.path.exists(KERN):
    print(f"  SKIP  no release binary at {KERN}: cargo build --release -p getkern")
    sys.exit(0)

print("########## MCP da capo a fondo, con le funzionalita' nuove ##########")

# 1. L'handshake e l'elenco degli strumenti.
res, err = session("init", [{"method": "tools/list", "params": {}}])
init = next((m for m in res if (m.get("result") or {}).get("protocolVersion")), None)
check("handshake: il server annuncia il protocollo", init is not None,
      f"protocol={(init or {}).get('result', {}).get('protocolVersion')}")
tools = next(((m["result"]["tools"]) for m in res if "tools" in (m.get("result") or {})), [])
names = sorted(t.get("name") for t in tools)
check("tools/list elenca gli strumenti", len(names) > 0, f"{names}")

# 2. Una cella normale sull'immagine predefinita.
res, err = session("base", [call("print(6*7)")])
txt, is_err = text_of(res[-1])
check("una cella che stampa", not is_err and "42" in txt, f"isError={is_err} {txt.strip()[:60]!r}")

# 3. ⭐ UNA CELLA MUTA: il difetto che ho corretto oggi era proprio questo, su persist.
#    L'MCP non usa persist, quindi qui DEVE essere stato verde anche prima: e' il controllo.
res, err = session("muta", [call("x = 1")])
txt, is_err = text_of(res[-1])
check("una cella MUTA non e' un errore", not is_err, f"isError={is_err} {txt.strip()[:70]!r}")

# 4. KERN_MCP_SETUP: il percorso che il riordino del setup ha toccato. Rete ACCESA solo qui.
with tempfile.TemporaryDirectory() as ws:
    res, err = session(
        "setup", [call("import os; print('dep', os.path.exists('/workspace/.deps/mark'))")],
        env={"KERN_MCP_SETUP": "mkdir -p /workspace/.deps && echo x > /workspace/.deps/mark",
             "KERN_MCP_WORKSPACE": ws}, timeout=600)
    txt, is_err = text_of(res[-1])
    check("KERN_MCP_SETUP installa e la cella lo vede", not is_err and "dep True" in txt,
          f"isError={is_err} {txt.strip()[:70]!r}")

# 5. Il setup con la RETE: deve risolvere e connettere.
with tempfile.TemporaryDirectory() as ws:
    net = ("python3 -c \"import socket; socket.setdefaulttimeout(8); "
           "socket.create_connection(('pypi.org',443))\" && mkdir -p /workspace/.deps "
           "&& echo x > /workspace/.deps/net")
    res, err = session("setup rete", [call("import os; print('net', os.path.exists('/workspace/.deps/net'))")],
                       env={"KERN_MCP_SETUP": net, "KERN_MCP_WORKSPACE": ws}, timeout=600)
    txt, is_err = text_of(res[-1])
    check("il setup dell'MCP ha la RETE", not is_err and "net True" in txt,
          f"isError={is_err} {txt.strip()[:70]!r}")

# 6. E la CELLA no: la rete e' accesa solo nel setup.
res, err = session("rete cella", [call(
    "import socket\n"
    "try:\n socket.setdefaulttimeout(3); socket.create_connection(('pypi.org',443)); print('SU')\n"
    "except OSError: print('spenta')\n")])
txt, is_err = text_of(res[-1])
check("la cella NON ha rete", not is_err and "spenta" in txt, f"{txt.strip()[:60]!r}")

# 7. ⭐ L'IMMAGINE NUOVA (#9): matplotlib SENZA aprire la rete, che e' il motivo per cui esiste.
with tempfile.TemporaryDirectory() as ws:
    res, err = session("immagine nuova", [call(
        "import matplotlib; matplotlib.use('Agg')\n"
        "import matplotlib.pyplot as plt, numpy as np, pandas as pd\n"
        "fig, ax = plt.subplots(); ax.plot(np.arange(5))\n"
        "fig.savefig('/workspace/g.png')\n"
        "import os; print('png', os.path.getsize('/workspace/g.png') > 0, 'numpy', numpy.__version__ if False else np.__version__)\n")],
        env={"KERN_MCP_IMAGE": "kern-sandbox:local", "KERN_MCP_WORKSPACE": ws}, timeout=600)
    txt, is_err = text_of(res[-1])
    check("immagine #9: matplotlib senza KERN_MCP_SETUP", not is_err and "png True" in txt,
          f"isError={is_err} {txt.strip()[:80]!r}")

# 8. node nell'immagine nuova.
res, err = session("node", [call("console.log('node', process.version)", language="node")],
                   env={"KERN_MCP_IMAGE": "kern-sandbox:local"}, timeout=600)
txt, is_err = text_of(res[-1])
check("immagine #9: language=node", not is_err and "node v" in txt, f"{txt.strip()[:60]!r}")

# 9. Il rifiuto di node sull'immagine PREDEFINITA, che l'MCP deve riferire come errore leggibile.
res, err = session("node default", [call("console.log(1)", language="node")])
txt, is_err = text_of(res[-1])
check("node sull'immagine predefinita e' rifiutato", is_err and "node" in txt.lower(),
      f"isError={is_err} {txt.strip()[:80]!r}")

# 10. L'interprete caldo (KERN_MCP_KERNEL=1): lo stato persiste fra le celle.
res, err = session("kernel caldo", [call("v = 7"), call("print(v * 6)")],
                   env={"KERN_MCP_KERNEL": "1"}, timeout=600)
txt, is_err = text_of(res[-1])
check("KERN_MCP_KERNEL: lo stato persiste fra celle", not is_err and "42" in txt,
      f"isError={is_err} {txt.strip()[:60]!r}")

# 11. Un OOM: deve tornare un errore LEGGIBILE, non un silenzio.
res, err = session("oom", [call("x = bytearray(400*1024*1024); print(len(x))")],
                   env={"KERN_MCP_MEMORY_MB": "128"}, timeout=600)
txt, is_err = text_of(res[-1])
check("un OOM torna un errore leggibile", is_err or "oom" in txt.lower() or "kill" in txt.lower(),
      f"isError={is_err} {txt.strip()[:90]!r}")

# 12. Il tetto sull'uscita: una cella che stampa molto non deve far gonfiare la risposta.
res, err = session("tetto uscita", [call("print('x' * 5_000_000)")], timeout=600)
txt, is_err = text_of(res[-1])
check("il tetto sull'uscita tiene", len(txt) < 200_000, f"risposta di {len(txt)} caratteri")

# 13. Una cella che esce non-zero.
res, err = session("exit", [call("import sys; sys.exit(3)")])
txt, is_err = text_of(res[-1])
check("un exit non-zero e' riferito", "3" in txt or is_err, f"isError={is_err} {txt.strip()[:70]!r}")

# 14. Uno strumento che non esiste: errore JSON-RPC, non un crash.
res, err = session("tool ignoto", [{"method": "tools/call",
                                    "params": {"name": "nonesiste", "arguments": {}}}])
last = res[-1]
check("uno strumento ignoto da' un errore, non un crash",
      ("error" in last) or bool((last.get("result") or {}).get("isError")),
      f"{json.dumps(last)[:110]}")

print(f"\n{ok} ok, {bad} falliti")
sys.exit(1 if bad else 0)
