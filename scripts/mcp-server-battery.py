#!/usr/bin/env python3
"""The MCP server, driven over stdio the way a client drives it, with the features of this branch.

WHY THIS EXISTS AND WHY THE 188 UNIT TESTS DO NOT COVER IT. Those exercise the functions; a client
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

IT ALSO DRIVES THE TRANSPORT the way a broken or hostile client does: two frames on one line, a frame
cut short at EOF, `NaN` where JSON has none, and the kern binary deleted between two calls. Each
of those was measured first, and the first three got NO reply at all, so the client waited forever.

WHAT IT IS NOT. It does not test the MCP protocol against a conformance suite, and it does not test
the tools' internals - those have unit tests. It answers one question a unit test cannot: does a
client that configures this server the documented way get what the documentation promises.

IN THE GATE, because it is cheap: MEASURED at 3.94 s and 3.80 s on two consecutive runs, all 28
checks, with the expensive ones genuinely happening - the setup box resolved DNS and connected, the
OOM produced kern's own OOM-killer line, and a 5 MB print came back capped to 16 kB. The first draft
of this docstring said it was too slow for the gate; it was written before the measurement, which is
the habit this file is supposed to be against.

SKIPS WITHOUT A RELEASE BINARY rather than failing, for the same reason `deployment-cli` does: a
checkout that has not built one should not report a red gate for a missing artefact.
"""

import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import time

# RESOLVED FROM THIS FILE, not hard-coded to one machine: a battery that only runs in one checkout
# is a battery nobody else runs.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SDK = os.path.join(ROOT, "bindings", "python")
KERN = os.environ.get("KERN_BIN") or os.path.join(ROOT, "target", "release", "kern")
ok = bad = skipped = 0


INIT = {"jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "batteria", "version": "1"}}}


def session(label, calls, env=None, timeout=300):
    """Una sessione: initialize, poi le chiamate. Torna la lista delle risposte ai tool call."""
    msgs = [INIT]
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


def strict(line):
    """Il JSON che un client RIGOROSO accetta: niente `NaN`/`Infinity`, che `json` di Python
    accetta e `JSON.parse` no. Il decodificatore della batteria non deve essere piu' tollerante
    del client che descrive, o una risposta illeggibile per Node qui risulterebbe leggibile."""
    def no(name):
        raise ValueError(f"{name} non e' JSON")
    return json.loads(line, parse_constant=no)


class Live:
    """Una sessione APERTA: si scrive una riga, si aspetta la risposta, si cambia il mondo, si
    riscrive. `session()` manda tutto e chiude stdin, quindi non puo' cancellare un binario FRA due
    chiamate. Legge dal descrittore senza buffer: un `readline` su uno stdout bufferizzato si porta
    via due righe e il `select` successivo non ne vede piu' nessuna, che e' come la prima sonda di
    questi casi ha scambiato una risposta in ritardo per una mancante."""

    def __init__(self, env=None):
        e = dict(os.environ, PYTHONPATH=SDK, KERN_BIN=KERN)
        e.update(env or {})
        self.p = subprocess.Popen([sys.executable, "-m", "kern_sandbox.mcp"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=SDK, env=e)
        self.buf = b""
        self.lines = []  # ogni riga ricevuta, grezza, per il controllo di validita'
        self.send(json.dumps(INIT))
        self.wait({0}, 30)

    def send(self, line):
        self.p.stdin.write(line.encode() + b"\n")
        self.p.stdin.flush()

    def wait(self, ids, timeout):
        """Le risposte agli `ids`, per id; si ferma quando ci sono tutte o allo scadere."""
        got, end = {}, time.monotonic() + timeout
        while set(ids) - set(got):
            left = end - time.monotonic()
            if left <= 0 or not select.select([self.p.stdout], [], [], left)[0]:
                break
            chunk = os.read(self.p.stdout.fileno(), 1 << 16)
            if not chunk:
                break
            self.buf += chunk
            while b"\n" in self.buf:
                raw, self.buf = self.buf.split(b"\n", 1)
                line = raw.decode("utf-8", "replace")
                self.lines.append(line)
                try:
                    m = strict(line)
                except ValueError:
                    continue
                if isinstance(m, dict) and "id" in m:
                    got[m["id"]] = m
        return got

    def close(self):
        self.p.stdin.close()
        try:
            return self.p.wait(30)
        except subprocess.TimeoutExpired:
            self.p.kill()
            return None


def check(label, cond, detail):
    global ok, bad
    if cond:
        print(f"  ok    {label:54s} {detail}")
        ok += 1
    else:
        print(f"  FAIL  {label:54s} {detail}")
        bad += 1


def skip(label, why):
    """Un caso che NON ha misurato, detto come tale e contato a parte: un salto stampato come `ok`
    sarebbe un verde su una cosa mai provata."""
    global skipped
    print(f"  SKIP  {label:54s} {why}")
    skipped += 1


def have_image(ref):
    """L'immagine e' nello store di kern? Chiesto a kern, non dedotto da un percorso. Se la domanda
    stessa fallisce si risponde SI', cosi' il caso gira e cade in vista invece di saltare in silenzio."""
    try:
        p = subprocess.run([KERN, "images", "--json", "--filter", f"reference={ref}"],
                           capture_output=True, text=True, timeout=30)
        return p.returncode != 0 or json.loads(p.stdout or "[]") != []
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return True


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
#    ⛔ L'immagine NON e' pubblicata, quindi esiste solo dove qualcuno l'ha costruita. Senza, questi
#    due casi cadevano per un artefatto mancante e non per un difetto, su ogni clone pulito e su ogni
#    host di prova: la stessa ragione per cui l'intera batteria salta senza binario.
SANDBOX_IMAGE = "kern-sandbox:local"
BUILD_IT = "kern build -t kern-sandbox:local -f images/sandbox/Dockerfile images/sandbox"
has_sandbox_image = have_image(SANDBOX_IMAGE)
if not has_sandbox_image:
    skip("immagine #9: matplotlib senza KERN_MCP_SETUP", f"{SANDBOX_IMAGE} assente: {BUILD_IT}")
else:
    with tempfile.TemporaryDirectory() as ws:
        res, err = session("immagine nuova", [call(
            "import matplotlib; matplotlib.use('Agg')\n"
            "import matplotlib.pyplot as plt, numpy as np, pandas as pd\n"
            "fig, ax = plt.subplots(); ax.plot(np.arange(5))\n"
            "fig.savefig('/workspace/g.png')\n"
            "import os; print('png', os.path.getsize('/workspace/g.png') > 0, 'numpy', numpy.__version__ if False else np.__version__)\n")],
            env={"KERN_MCP_IMAGE": SANDBOX_IMAGE, "KERN_MCP_WORKSPACE": ws}, timeout=600)
        txt, is_err = text_of(res[-1])
        check("immagine #9: matplotlib senza KERN_MCP_SETUP", not is_err and "png True" in txt,
              f"isError={is_err} {txt.strip()[:80]!r}")

# 8. node nell'immagine nuova.
if not has_sandbox_image:
    skip("immagine #9: language=node", f"{SANDBOX_IMAGE} assente: {BUILD_IT}")
else:
    res, err = session("node", [call("console.log('node', process.version)", language="node")],
                       env={"KERN_MCP_IMAGE": SANDBOX_IMAGE}, timeout=600)
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
# ⛔ IL PREDICATO DEVE FORZARE IL SIGNIFICATO DEL NOME, e la prima versione non lo faceva.
# Era `is_err or "oom" in txt or "kill" in txt`, cioe' soddisfatto da QUALUNQUE `isError: true`.
# PROVATO: sostituendo la cella con un errore di SINTASSI il caso diceva ancora `ok`, perche' un
# SyntaxError e' pure lui un isError. Un caso verde su una classe di fallimento sbagliata e' peggio
# di nessun caso: dice che la storia dell'OOM e' provata quando non lo e'. Ora pretende la riga che
# SOLO un OOM produce - il messaggio del killer del kernel scritto da kern - e in piu' che la cella
# non sia semplicemente andata in errore di programmazione.
res, err = session("oom", [call("x = bytearray(400*1024*1024); print(len(x))")],
                   env={"KERN_MCP_MEMORY_MB": "128"}, timeout=600)
txt, is_err = text_of(res[-1])
check("un OOM e riferito COME un OOM", is_err and "oom killer" in txt.lower(),
      f"isError={is_err} {txt.strip()[:90]!r}")
# E il controllo che rende il caso sopra una misura: un errore di PROGRAMMAZIONE non deve
# somigliargli. Senza questo, "pretende la riga del killer" resterebbe un'asserzione su una stringa.
res, err = session("oom controllo", [call("this is not python at all ((((")])
txt2, is_err2 = text_of(res[-1])
check("un errore di sintassi NON somiglia a un OOM",
      is_err2 and "oom killer" not in txt2.lower(),
      f"isError={is_err2} {txt2.strip()[:60]!r}")

# 12. Il tetto sull'uscita: una cella che stampa molto non deve far gonfiare la risposta.
res, err = session("tetto uscita", [call("print('x' * 5_000_000)")], timeout=600)
txt, is_err = text_of(res[-1])
check("il tetto sull'uscita tiene", len(txt) < 200_000, f"risposta di {len(txt)} caratteri")

# 13. Una cella che esce non-zero.
# Lo stesso difetto, piu' mite: era `"3" in txt or is_err`, e qualunque isError lo soddisfaceva
# senza provare che il codice 3 fosse riportato. Ora pretende la forma documentata, `[exit 3`.
res, err = session("exit", [call("import sys; sys.exit(3)")])
txt, is_err = text_of(res[-1])
check("un exit non-zero riporta IL CODICE", is_err and "[exit 3" in txt,
      f"isError={is_err} {txt.strip()[:70]!r}")

# 14. ⭐ L'INTERPRETE CALDO CHE MUORE: lo stato va perso e il modello DEVE essere avvisato.
#     Senza questo caso la batteria provava solo che `KERN_MCP_KERNEL=1` conserva lo stato (caso 10),
#     cioe' la metta' facile. Un interprete caldo che muore e viene rimpiazzato in silenzio
#     restituirebbe al modello una sessione che SEMBRA continua e non lo e'.
res, err = session("kernel oom", [
    call("marcatore = 'vivo'"),
    call("x = bytearray(400*1024*1024)"),
    call("print('marcatore' in dir())"),
], env={"KERN_MCP_KERNEL": "1", "KERN_MCP_MEMORY_MB": "128"}, timeout=900)
replies = [text_of(m) for m in res if "result" in m and "content" in (m.get("result") or {})]
after_txt, after_err = replies[-1] if replies else ("", False)
died_txt, died_err = replies[-2] if len(replies) > 1 else ("", False)
check("un Kernel caldo che va in OOM lo dichiara", died_err,
      f"la cella che sfora: isError={died_err} {died_txt.strip()[:70]!r}")
check("e lo stato in memoria e' PERSO, non finto continuo",
      "False" in after_txt or after_err,
      f"dopo: isError={after_err} {after_txt.strip()[:70]!r}")

# 15. ⭐ UN PROFILO CON IL PREWARM: la forma in cui il difetto della chiave del pool arriva a un
#     utente dell'MCP. `KERN_MCP_PREWARM` vale 1 per difetto, quindi questa e' la configurazione
#     normale di chi usa `KERN_MCP_PROFILES`.
with tempfile.TemporaryDirectory() as home:
    os.makedirs(os.path.join(home, "kern"))
    toml = os.path.join(home, "kern", "kern.toml")
    with open(toml, "w") as fh:
        fh.write('[[vcpu]]\nname = "agente"\nbackend = "host"\ncpus = 1.0\nmemory = "256M"\n')
    res, err = session("profilo+prewarm", [call(
        "import os\n"
        "print('cap', open('/sys/fs/cgroup/memory.max').read().strip())\n")],
        env={"XDG_CONFIG_HOME": home, "KERN_MCP_PROFILES": "vcpu:agente",
             "KERN_MCP_MEMORY_MB": "0"}, timeout=600)
    txt, is_err = text_of(res[-1])
    # 256 MiB = 268435456. Letto dal cgroup DAL MISURATO, non dalla riga di comando: e' il canale
    # indipendente che il progetto richiede.
    check("un profilo col prewarm applica il SUO tetto",
          not is_err and "268435456" in txt,
          f"isError={is_err} {txt.strip()[:70]!r}")

# 16. Uno strumento che non esiste: errore JSON-RPC, non un crash.
# Pretende il CODICE e il NOME, non "un errore qualunque": `"error" in last or isError` era la stessa
# forma del predicato dell'OOM, soddisfatta da qualunque fallimento.
res, err = session("tool ignoto", [{"method": "tools/call",
                                    "params": {"name": "nonesiste", "arguments": {}}}])
last = (res[-1].get("error") or {}) if res else {}
check("uno strumento ignoto da' -32602 e lo nomina",
      last.get("code") == -32602 and "nonesiste" in last.get("message", ""),
      f"{json.dumps(last)[:110]}")

# 17. ⭐ DUE FRAME SU UNA RIGA. MISURATO prima della correzione: nessuna risposta a nessuno dei due,
#     e il server rispondeva normalmente alla riga dopo, quindi niente segnalava la perdita e il
#     client aspettava due id per sempre. Ora ogni id riceve -32700 e sulla riga non gira niente.
#     ⛔ "Non e' girato niente" senza controllo positivo sarebbe vuoto: se la cella non scrivesse
#     dove credo, il file mancherebbe comunque. Quindi la STESSA scrittura, su una riga sua, deve
#     creare il suo file.
def write_cell(i, name):
    return json.dumps({"jsonrpc": "2.0", "id": i, **call(f"open('/workspace/{name}', 'w').write('x')")})


with tempfile.TemporaryDirectory() as ws:
    s17 = Live(env={"KERN_MCP_WORKSPACE": ws})
    s17.send(write_cell(1, "a") + write_cell(2, "b"))
    both = s17.wait({1, 2}, 30)
    codes = {i: (both.get(i, {}).get("error") or {}).get("code") for i in (1, 2)}
    s17.send(write_cell(3, "c"))
    alone = s17.wait({3}, 120).get(3, {})
    s17.close()
    ran = sorted(n for n in ("a", "b", "c") if os.path.exists(os.path.join(ws, n)))
    check("due frame su una riga: OGNI id riceve -32700", codes == {1: -32700, 2: -32700}, f"{codes}")
    check("e sulla riga non gira niente (controllo: da sola si')",
          ran == ["c"] and not (alone.get("result") or {}).get("isError", True),
          f"file creati {ran}")

# 18. Mezzo frame e poi EOF: il client muore a meta' scrittura. La meta' che c'e' porta l'id, quindi
#     si risponde a quello, e il server esce pulito invece di restare appeso.
p18 = subprocess.run([sys.executable, "-m", "kern_sandbox.mcp"],
                     input=json.dumps(INIT) + "\n" + '{"jsonrpc":"2.0","id":5,"method":"ping"',
                     capture_output=True, text=True, cwd=SDK, timeout=30,
                     env=dict(os.environ, PYTHONPATH=SDK, KERN_BIN=KERN))
half = [m for m in (strict(x) for x in p18.stdout.splitlines() if x.strip()) if m.get("id") == 5]
check("mezzo frame poi EOF: risposta all'id ed uscita pulita",
      p18.returncode == 0 and len(half) == 1 and (half[0].get("error") or {}).get("code") == -32700,
      f"exit={p18.returncode} {json.dumps(half)[:80]}")

# 19. `NaN` e `Infinity`: `json` di Python li accetta, RFC 8259 no. MISURATO prima: `"id": NaN`
#     tornava come `"id": NaN`, una riga che `JSON.parse` di Node rifiuta. Ogni riga che il server
#     scrive deve essere JSON per un client RIGOROSO.
try:
    strict('{"id": NaN}')
    strict_ok = False
except ValueError:
    strict_ok = True
check("controllo: il lettore rigoroso rifiuta NaN", strict_ok, "senza questo il caso sotto e' vuoto")
s19 = Live()
s19.send('{"jsonrpc":"2.0","id":NaN,"method":"ping"}')
s19.send('{"jsonrpc":"2.0","id":8,"method":"ping","params":{"x":Infinity}}')
s19.send(json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"}))
got19 = s19.wait({8, 9}, 30)
s19.close()
bad19 = []
for line in s19.lines:
    try:
        strict(line)
    except ValueError:
        bad19.append(line[:60])
check("NaN/Infinity: ogni riga scritta e' JSON, e la sessione continua",
      not bad19 and (got19.get(8, {}).get("error") or {}).get("code") == -32700 and "result" in got19.get(9, {}),
      f"righe non JSON {bad19}, id 8 -> {(got19.get(8, {}).get('error') or {}).get('code')}")

def gone(txt):
    """La risposta che dice che il binario non c'e' piu': il prefisso degli errori del binding, che
    l'uscita di una cella non porta, piu' l'errore del sistema."""
    return txt.startswith("kern error:") and "No such file or directory" in txt


# 20. ⭐ IL BINARIO CHE SPARISCE A META' SESSIONE. Senza prewarm, cosi' la seconda chiamata ha
#     bisogno del binario per forza: deve dirlo, non restare appesa e non riferire un successo.
with tempfile.TemporaryDirectory() as d:
    kb = os.path.join(d, "kern")
    shutil.copy2(KERN, kb)
    s20 = Live(env={"KERN_BIN": kb, "KERN_MCP_PREWARM": "0"})
    s20.send(json.dumps({"jsonrpc": "2.0", "id": 1, **call("print(6*7)")}))
    first = text_of(s20.wait({1}, 120).get(1, {}))
    os.unlink(kb)
    t20 = time.monotonic()
    s20.send(json.dumps({"jsonrpc": "2.0", "id": 2, **call("print(6*7)")}))
    second = s20.wait({2}, 60).get(2)
    dt20 = time.monotonic() - t20
    s20.close()
    txt2, err2 = text_of(second or {})
    check("binario sparito: la prima cella girava", not first[1] and "42" in first[0], f"{first[0].strip()[:40]!r}")
    # Il predicato e' "un errore DEL BINDING che nomina il file mancante", non una frase: con il
    # controllo d'identita' aggirato, misurato, lo strato sotto risponde `could not execute kern:
    # [Errno 2] No such file or directory`, che e' una risposta altrettanto giusta.
    check("binario sparito: la seconda lo DICE, subito",
          second is not None and err2 and gone(txt2),
          f"{dt20:.2f}s isError={err2} {txt2.strip()[:70]!r}")

# 21. Lo stesso CON il prewarm predefinito, che e' la configurazione normale. Un box caldo avviato
#     PRIMA della cancellazione e' un box vero, quindi usarlo e' un successo vero e non uno finto;
#     quello che non deve succedere e' un'attesa, o un successo senza la cella. Il pool non puo'
#     ricaricarsi senza binario, quindi l'ultima chiamata deve dirlo.
with tempfile.TemporaryDirectory() as d:
    kb = os.path.join(d, "kern")
    shutil.copy2(KERN, kb)
    s21 = Live(env={"KERN_BIN": kb})
    s21.send(json.dumps({"jsonrpc": "2.0", "id": 1, **call("print(6*7)")}))
    s21.wait({1}, 120)
    os.unlink(kb)
    for i in (2, 3, 4):
        s21.send(json.dumps({"jsonrpc": "2.0", "id": i, **call("print(6*7)")}))
    after = s21.wait({2, 3, 4}, 120)
    s21.close()
    shapes = []
    for i in (2, 3, 4):
        t, e = text_of(after.get(i, {}))
        shapes.append("ok" if (not e and "42" in t and "[exit 0" in t) else "detto" if (e and gone(t)) else "ALTRO")
    check("binario sparito col prewarm: nessuna attesa, nessun successo finto",
          len(after) == 3 and "ALTRO" not in shapes and shapes[-1] == "detto", f"{shapes}")

# 22. Due chiamate IN FILA sulla stessa sessione, la seconda servita dal pool caldo: ognuna deve
#     tornare con la SUA uscita sotto il SUO id. Il server e' un solo processo su un solo stdio, quindi
#     non c'e' concorrenza vera da mescolare; questo e' il controllo che lo dice invece di supporlo.
res, err = session("in fila", [call("print('AAA')"), call("print('BBB')")])
by_id = {m.get("id"): text_of(m)[0] for m in res if "result" in m and "content" in (m.get("result") or {})}
check("due chiamate in fila: ognuna la sua uscita",
      "AAA" in by_id.get(1, "") and "BBB" not in by_id.get(1, "")
      and "BBB" in by_id.get(2, "") and "AAA" not in by_id.get(2, ""),
      f"{ {k: v.strip()[:12] for k, v in by_id.items()} }")

print(f"\n{ok} ok, {bad} falliti, {skipped} saltati")
sys.exit(1 if bad else 0)
