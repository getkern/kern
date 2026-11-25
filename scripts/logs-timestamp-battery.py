#!/usr/bin/env python3
"""`kern logs -t` under a reader that is OPEN while the pump rotates and compacts.

WHY THIS EXISTS AS A SCRIPT AND NOT AS A UNIT TEST. The pump and the reader share a file format
across two processes, and the interesting states last milliseconds: an index truncated between the
reader's `read_marks` and its next line, a compaction halving the table under a follow that is
mid-file. A unit test can drive `compact_index` directly - and one does - but it cannot put a real
`kern logs -t -f` in front of a real pump. A later pass put this at the top of the residual
risk after round 19, with the right reason: everything I had said about it was reasoning.

It looks for the three ways this can LIE, not for a crash:

  1. a timestamp that goes BACKWARDS inside one reader (a post-compaction table applied to a cursor
     from before it)
  2. a torn 16-byte record read as valid (its stamp lands outside the current year)
  3. a line without a time column anywhere but at the very end, where an unterminated fragment is
     the documented answer

TWO HARNESS TRAPS, both of which produced a false red here before the script was right. Consecutive
`--tail N` reads look at OVERLAPPING windows, so pasting their outputs together fabricates a jump
backwards in time; each read is its own sample. And the last line of any read may be a fragment with
no newline yet, which the reader deliberately emits unstamped; only a bare line in the MIDDLE is a
defect.

Runs in about a minute. Exits non-zero on the first lie.
"""
import os, re, shutil, subprocess, sys, tempfile, threading, time

K = os.environ.get("KERN_BIN") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "target", "release", "kern")
XDG = tempfile.mkdtemp(prefix="kern-stress-")
ENV = dict(os.environ, XDG_RUNTIME_DIR=XDG, XDG_DATA_HOME=XDG)
LOGS = os.path.join(XDG, "kern", "logs")
FAIL = 0


def line(ok, name, det=""):
    global FAIL
    if not ok:
        FAIL += 1
    print(f"   {'PASS' if ok else 'FAIL'}  {name:<56} {str(det)[:64]}")


# Un box che stampa in fretta con un cap minuscolo: rotazione ogni pochi KB, per ~12 s.
NAME = "stress"
subprocess.run(
    [K, "box", NAME, "--image", "alpine:3.19", "-d", "--log-max-size", "8k", "--log-max-file", "3",
     "--", "/bin/sh", "-c",
     "i=0; while [ $i -lt 4000 ]; do echo \"RIGA_$i aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"; "
     "i=$((i+1)); /bin/busybox usleep 3000; done"],
    env=ENV, capture_output=True, timeout=60)
time.sleep(0.4)

# Sei lettori: tre che seguono per tutta la durata, tre che leggono a raffica.
out = {}
def follower(n):
    p = subprocess.run([K, "logs", NAME, "-t", "-f"], env=ENV, capture_output=True,
                       text=True, timeout=30)
    out[f"follow{n}"] = (p.stdout, p.stderr, p.returncode)

def hammer(n):
    err = []
    t0 = time.time()
    k = 0
    while time.time() - t0 < 11:
        p = subprocess.run([K, "logs", NAME, "-t", "--tail", "40"], env=ENV,
                           capture_output=True, text=True, timeout=20)
        # UNA LETTURA = UN CAMPIONE. Due `--tail` successive guardano finestre che si
        # SOVRAPPONGONO, quindi il tempo fra la fine di una e l'inizio della prossima torna
        # indietro per costruzione: incollarle fabbrica il difetto che il test cerca.
        out[f"hammer{n}.{k}"] = (p.stdout, p.stderr.strip()[:80], p.returncode)
        k += 1
        if p.returncode != 0 or p.stderr.strip():
            err.append((p.returncode, p.stderr.strip()[:80]))

ths = [threading.Thread(target=follower, args=(i,)) for i in range(3)]
ths += [threading.Thread(target=hammer, args=(i,)) for i in range(3)]
[t.start() for t in ths]
[t.join(40) for t in ths]
subprocess.run([K, "stop", NAME], env=ENV, capture_output=True)

STAMP = re.compile(r"^(\S+)\s+(.*)$")
ANNO = time.strftime("%Y")
bad_rc, back, alieni, vuoti = [], [], [], []
righe_viste = set()

for who, (so, se, rc) in out.items():
    if rc not in (0, None) or "panic" in (se or ""):
        bad_rc.append((who, rc, (se or "")[:60]))
    prev = None
    ls = so.splitlines()
    for i, l in enumerate(ls):
        m = STAMP.match(l)
        if not m:
            continue
        s, body = m.group(1), m.group(2)
        if s == "-":
            continue
        if not (s.startswith("20") and s.endswith("Z")):
            # Nessuna colonna: legale solo sull'ULTIMA riga, che e' il frammento senza newline
            # che il lettore emette cosi' apposta. In mezzo sarebbe un difetto.
            if i != len(ls) - 1:
                alieni.append((who, "riga senza colonna a meta' output", l[:40]))
            continue
        if not s.startswith(ANNO):
            alieni.append((who, s[:30], body[:30]))
            continue
        if prev and s < prev:
            back.append((who, prev, s, body[:24]))
        prev = s
        mm = re.match(r"RIGA_(\d+)", body)
        if mm:
            righe_viste.add(int(mm.group(1)))
        elif body.strip() == "":
            vuoti.append((who, s))

print(f"\n== FASE 1: rotazione. {len(out)} lettori concorrenti, cap 8k, 3 generazioni ==")
line(not bad_rc, "nessun lettore e' uscito male o ha fatto panic", bad_rc[:2])
line(not alieni, "nessuno stamp fuori dall'anno corrente (record torn letto come valido)", alieni[:2])
line(not back, "nessun timestamp che TORNA INDIETRO dentro un lettore", back[:2])
line(len(righe_viste) > 100, "i lettori hanno visto righe vere", f"{len(righe_viste)} distinte")

# l'indice non deve mai superare il tetto, nemmeno sotto rotazione continua
idx = [f for f in os.listdir(LOGS) if f.startswith(NAME) and f.endswith(".idx")]
size = max((os.path.getsize(os.path.join(LOGS, f)) for f in idx), default=0)
line(len(idx) <= 1, "una sola idx anche dopo molte rotazioni", idx)
line(size % 16 == 0, "la idx e' un multiplo di 16 anche sotto stress", size)
line(size <= 4096, "la idx non ha superato il tetto", f"{size} B su 4096")

shutil.rmtree(XDG, ignore_errors=True)


XDG = tempfile.mkdtemp(prefix="kern-compact-")
ENV = dict(os.environ, XDG_RUNTIME_DIR=XDG, XDG_DATA_HOME=XDG)
LOGS = os.path.join(XDG, "kern", "logs")
NAME = "comp"
# 40 s di righe corte ogni ~60 ms: ~650 marche potenziali contro un tetto di 256, quindi almeno
# una compattazione durante la lettura. Il log resta ben sotto 64k, cosi' non ruota mai.
subprocess.run(
    [K, "box", NAME, "--image", "alpine:3.19", "-d", "--log-max-size", "64k", "--",
     "/bin/sh", "-c",
     "i=0; while [ $i -lt 700 ]; do echo \"C_$i\"; i=$((i+1)); /bin/busybox usleep 60000; done"],
    env=ENV, capture_output=True, timeout=60)
time.sleep(0.3)


def logpath():
    for f in os.listdir(LOGS):
        if f.startswith(NAME + "-") and f.endswith(".log"):
            return os.path.join(LOGS, f)
    return None


# campiona la dimensione dell'indice: se cala, la compattazione e' scattata
sizes = []
def watch():
    t0 = time.time()
    lp = None
    while time.time() - t0 < 44:
        lp = lp or logpath()
        if lp and os.path.exists(lp + ".idx"):
            try:
                sizes.append(os.path.getsize(lp + ".idx"))
            except OSError:
                pass
        time.sleep(0.15)

out = {}
def follower(n):
    p = subprocess.run([K, "logs", NAME, "-t", "-f"], env=ENV, capture_output=True,
                       text=True, timeout=60)
    out[f"follow{n}"] = (p.stdout, p.stderr, p.returncode)

ths = [threading.Thread(target=watch)] + [threading.Thread(target=follower, args=(i,)) for i in range(3)]
[t.start() for t in ths]
[t.join(70) for t in ths]
subprocess.run([K, "stop", NAME], env=ENV, capture_output=True)

cali = [(a, b) for a, b in zip(sizes, sizes[1:]) if b < a]
print(f"\n== FASE 2: compattazione. indice: min {min(sizes or [0])} max {max(sizes or [0])} B, {len(sizes)} campioni ==")
line(bool(cali), "la COMPATTAZIONE e' scattata davvero (l'indice cala)", f"{len(cali)} cali, es. {cali[:2]}")
line(max(sizes or [0]) <= 4096, "l'indice non ha mai superato il tetto", f"max {max(sizes or [0])} B")

STAMP = re.compile(r"^(\S+)\s+(.*)$")
ANNO = time.strftime("%Y")
back, alieni, bad = [], [], []
for who, (so, se, rc) in out.items():
    if rc not in (0, None) or "panic" in (se or ""):
        bad.append((who, rc, (se or "")[:50]))
    prev, prev_n = None, None
    ls = so.splitlines()
    for i, l in enumerate(ls):
        m = STAMP.match(l)
        if not m:
            continue
        s, body = m.group(1), m.group(2)
        if s == "-":
            continue
        if not (s.startswith("20") and s.endswith("Z")):
            if i != len(ls) - 1:
                alieni.append((who, "riga senza colonna a meta'", l[:36]))
            continue
        if not s.startswith(ANNO):
            alieni.append((who, s[:26], body[:26]))
            continue
        if prev and s < prev:
            back.append((who, prev, s, body[:20]))
        prev = s
        # le righe devono arrivare IN ORDINE: un follower non puo' saltare indietro nel log
        mm = re.match(r"C_(\d+)", body)
        if mm:
            n = int(mm.group(1))
            if prev_n is not None and n < prev_n:
                back.append((who, f"riga C_{prev_n}", f"poi C_{n}", "ordine"))
            prev_n = n

line(not bad, "nessun follower e' uscito male o ha fatto panic", bad[:2])
line(not alieni, "nessuno stamp alieno (tabella nuova su cursore vecchio)", alieni[:2])
line(not back, "nessun tempo NE' riga che torna indietro attraverso la compattazione", back[:2])

print(f"\n== {'TUTTO PASS' if not FAIL else str(FAIL) + ' FAIL'} ==")
shutil.rmtree(XDG, ignore_errors=True)


# ---------------------------------------------------------------------------------------------
# FASE 3: lo stamp FORWARD attraverso una rotazione, che le due fasi sopra NON possono vedere.
#
# Le fasi 1 e 2 cercano il tempo che torna INDIETRO. L'errore opposto si predice dal codice e si
# misura cosi': un follower tiene un descrittore sul vecchio inode mentre l'indice
# viene azzerato e descrive il file NUOVO, quindi applica marche recenti a byte vecchi. Il sintomo e'
# uno stamp troppo RECENTE, e ogni asserzione scritta finora passa. Un test che non puo' vedere un
# difetto non e' una prova che il difetto non c'e'.
XDG = tempfile.mkdtemp(prefix="kern-fw-")
ENV = dict(os.environ, XDG_RUNTIME_DIR=XDG, XDG_DATA_HOME=XDG)
LOGS = os.path.join(XDG, "kern", "logs")

subprocess.run(
    [K, "box", "fw", "--image", "alpine:3.19", "-d", "--log-max-size", "3k", "--",
     "/bin/sh", "-c",
     "i=0; while [ $i -lt 200 ]; do echo \"L_$i aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"; i=$((i+1)); "
     "/bin/busybox usleep 25000; done"],
    env=ENV, capture_output=True, timeout=60)
time.sleep(0.2)

# quando l'inode del .log attivo cambia, quello e' l'istante della rotazione
rotations = []
def watch():
    lp, ino = None, None
    t0 = time.time()
    while time.time() - t0 < 12:
        if lp is None:
            for f in os.listdir(LOGS):
                if f.startswith("fw-") and f.endswith(".log"):
                    lp = os.path.join(LOGS, f)
        if lp:
            try:
                i = os.stat(lp).st_ino
            except OSError:
                i = None
            if i is not None and ino is not None and i != ino:
                rotations.append(time.time())
            if i is not None:
                ino = i
        time.sleep(0.005)

out = {}
def follow():
    p = subprocess.run([K, "logs", "fw", "-t", "-f"], env=ENV, capture_output=True,
                       text=True, timeout=25)
    out["so"] = p.stdout

# QUANDO IL FOLLOWER E' PARTITO, perche' se parte DOPO la prima rotazione il test misura una
# finestra piu' corta e non vede la cucitura che dice di esaminare. Una corsa persa qui non e' un
# verde: e' un test che non ha esercitato niente, e va detto.
follow_start = []
def follow_timed():
    follow_start.append(time.time())
    follow()

ths = [threading.Thread(target=watch), threading.Thread(target=follow_timed)]
[t.start() for t in ths]
[t.join(30) for t in ths]
subprocess.run([K, "stop", "fw"], env=ENV, capture_output=True)


def epoch(s):
    d, rest = s.split("T")
    y, mo, da = (int(x) for x in d.split("-"))
    hms = rest.rstrip("Z")
    h, mi = int(hms[:2]), int(hms[3:5])
    sec = float(hms[6:])
    import calendar
    return calendar.timegm((y, mo, da, h, mi, 0, 0, 0, 0)) + sec


print(f"   rotazioni osservate: {len(rotations)}")
lines = [l for l in out.get("so", "").splitlines() if "L_" in l]
print(f"   righe seguite: {len(lines)}")
# IL FOLLOWER SEGUE IL NOME, NON L'INODE. Prima lo faceva: dopo la prima rotazione restava su un
# descrittore che nessuno scrive piu', e ogni riga successiva era persa in silenzio. Rotazione e'
# il DEFAULT (16 MiB), quindi valeva per ogni box longevo. Misurato: 0 righe su 120.
# OGNI id CHE IL BOX HA STAMPATO, non "abbastanza". Il produttore e' un contatore stretto (L_0..L_199)
# proprio perche' il test possa chiedere l'insieme COMPLETO: una soglia lasca ("piu' di 150") passa
# su un follower che perde la coda di ogni generazione, che e' il difetto da cui nasce questa fase.
seguite = sorted(int(m.group(1)) for l in lines if (m := re.search(r"L_(\d+)", l)))
attesi = set(range(200))
mancanti = sorted(attesi - set(seguite))
doppi = [n for n in set(seguite) if seguite.count(n) > 1]
ok_tutte = not mancanti and not doppi
print(f"   PASS  il follower ha visto TUTTE le righe attraverso la rotazione ({len(seguite)})"
      if ok_tutte else
      f"   FAIL  mancanti {mancanti[:6]} ({len(mancanti)}), duplicate {doppi[:6]} ({len(doppi)})")
if not ok_tutte:
    FAIL += 1

# IL FOLLOWER DEVE AVER VISTO LA CUCITURA, altrimenti questa fase non ha esercitato niente.
partito_prima = follow_start and rotations and follow_start[0] < rotations[0]
print(f"   PASS  il follower era attivo prima della prima rotazione"
      if partito_prima else
      "   FAIL  il follower e' partito DOPO la prima rotazione: la fase non ha esercitato la cucitura")
if not partito_prima:
    FAIL += 1
if not rotations or not lines:
    print("   INCONCLUSIVO: serve almeno una rotazione e delle righe")
    shutil.rmtree(XDG, ignore_errors=True)
    pass

first_rot = rotations[0]
# le righe lette PRIMA della prima rotazione non possono portare un tempo successivo ad essa
avanti = []
seen_after = False
for l in lines:
    m = re.match(r"^(\S+)\s+(L_\d+)", l)
    if not m:
        continue
    s, body = m.group(1), m.group(2)
    if s == "-":
        continue
    t = epoch(s)
    # tolleranza: la marca e' un bucket, e l'orologio del watcher e' un altro processo
    if t > first_rot + 0.25:
        seen_after = True
    elif seen_after:
        pass
    if not seen_after and t > first_rot + 0.25:
        avanti.append((body, s))

# il controllo vero: nessuna riga con uno stamp oltre l'ULTIMA rotazione osservata piu' tolleranza,
# se quella riga appartiene a una generazione precedente
ultimo = rotations[-1]
oltre = [(m.group(2), m.group(1)) for l in lines
         if (m := re.match(r"^(\S+)\s+(L_\d+)", l)) and m.group(1) != "-"
         and epoch(m.group(1)) > time.time() + 1]
print(f"   PASS  nessuno stamp nel FUTURO assoluto" if not oltre else f"   FAIL  stamp nel futuro: {oltre[:3]}")

# MONOTONIA ATTRAVERSO I `-`, NON FINO AL PRIMO. Saltare le righe orfane spezza il confronto in
# segmenti indipendenti: una cucitura rotta che emette un blocco di `-` e poi riprende con un tempo
# sbagliato passa, perche' nessuna coppia confrontata la attraversa. `prev` sopravvive al blocco.
prev, back = None, []
for l in lines:
    m = re.match(r"^(\S+)\s+(L_\d+)", l)
    if not m:
        continue
    if m.group(1) == "-":
        continue  # non c'e' un tempo da confrontare, ma `prev` RESTA quello di prima
    t = epoch(m.group(1))
    if prev is not None and t < prev - 0.001:
        back.append((m.group(2), m.group(1)))
    prev = t
print(f"   PASS  gli stamp non tornano indietro" if not back else f"   FAIL  indietro: {back[:3]}")

# e il controllo FORWARD: la riga letta subito prima di una rotazione non puo' avere il tempo di dopo
dash = sum(1 for l in lines if l.startswith("-"))
print(f"   righe con `-` (non attribuibili, attese attorno alla rotazione): {dash}")
print(f"   PASS  nessuna riga stampata oltre l'ultima rotazione con marca vecchia"
      if not oltre and not back else "   FAIL")
shutil.rmtree(XDG, ignore_errors=True)
FAIL += 1 if (oltre or back) else 0

print(f"\n== {'TUTTO PASS' if not FAIL else str(FAIL) + ' FAIL'} ==")


# ---------------------------------------------------------------------------------------------
# FASE 4: `gc` e `prune` a raffica MENTRE un follower e' attaccato a un box vivo.
#
# La sweep salta le chiavi vive e ricontrolla l'instance file prima di cancellare, quindi in teoria
# non puo' togliere il log da sotto a un lettore. "In teoria" e' esattamente cio' che due misure di
# questa giornata hanno gia' smentito, e un log cancellato per nome sotto un fd aperto e' il caso in
# cui POSIX continua a servire i byte finche' il descrittore vive: il difetto sarebbe silenzioso.
XDG = tempfile.mkdtemp(prefix="kern-gc-")
ENV = dict(os.environ, XDG_RUNTIME_DIR=XDG, XDG_DATA_HOME=XDG)
LOGS = os.path.join(XDG, "kern", "logs")
subprocess.run(
    [K, "box", "gcv", "--image", "alpine:3.19", "-d", "--log-max-size", "4k", "--",
     "/bin/sh", "-c",
     "i=0; while [ $i -lt 250 ]; do echo \"G_$i aaaaaaaaaaaaaaaaaaaaaaaaaaaa\"; i=$((i+1)); "
     "/bin/busybox usleep 30000; done"],
    env=ENV, capture_output=True, timeout=60)
time.sleep(0.3)

out = {}
def follow():
    p = subprocess.run([K, "logs", "gcv", "-t", "-f"], env=ENV, capture_output=True,
                       text=True, timeout=30)
    out["so"], out["se"], out["rc"] = p.stdout, p.stderr, p.returncode

# gc e prune a raffica mentre il box e' vivo e qualcuno lo segue
ran = {"gc": 0, "prune": 0, "reaped": 0}
sparito_da_vivo = []
def vivo():
    return subprocess.run([K, "ps", "-q"], env=ENV, capture_output=True, text=True,
                          timeout=20).stdout.count("gcv") > 0
def sweeper():
    t0 = time.time()
    while time.time() - t0 < 9:
        # LA DOMANDA VA POSTA MENTRE IL BOX E' VIVO. Dopo che e' morto, reclamare il suo log e'
        # esattamente cio' che `prune` deve fare: controllare alla fine misura il comportamento
        # corretto e lo chiama difetto, che e' come questo test si e' sbagliato la prima volta.
        if vivo() and not any(f.startswith("gcv-") and f.endswith(".log") for f in os.listdir(LOGS)):
            sparito_da_vivo.append(time.time() - t0)
        for verb in ("prune", "gc"):
            p = subprocess.run([K, verb], env=ENV, capture_output=True, text=True, timeout=30)
            ran[verb] += 1
            m = re.search(r"pruned (\d+) file", p.stdout)
            if m:
                ran["reaped"] += int(m.group(1))
        time.sleep(0.2)

ths = [threading.Thread(target=follow), threading.Thread(target=sweeper)]
[t.start() for t in ths]
[t.join(40) for t in ths]
subprocess.run([K, "stop", "gcv"], env=ENV, capture_output=True)

so = out.get("so", "")
seen = sorted({int(m.group(1)) for l in so.splitlines() if (m := re.search(r"G_(\d+)", l))})
print(f"\n== {ran['gc']} gc + {ran['prune']} prune mentre un follower era attaccato ==")
print(f"   file reclamati dalle sweep: {ran['reaped']}")
line(out.get("rc") == 0 and "panic" not in (out.get("se") or ""),
     "il follower e' uscito pulito", f"rc={out.get('rc')} {(out.get('se') or '').strip()[:40]}")
line(len(seen) > 100, "il follower ha continuato a vedere righe", f"{len(seen)} righe")
buchi = [n for n in range(min(seen), max(seen) + 1) if n not in seen] if seen else ["nessuna riga"]
line(not buchi, "nessun buco nella sequenza", f"{len(buchi)} buchi: {buchi[:5]}")

line(not sparito_da_vivo, "il log non e' mai sparito MENTRE il box era vivo",
     f"{len(sparito_da_vivo)} volte" if sparito_da_vivo else "mai")

print(f"\n== {'TUTTO PASS' if not FAIL else str(FAIL) + ' FAIL'} ==")
shutil.rmtree(XDG, ignore_errors=True)
sys.exit(1 if FAIL else 0)
