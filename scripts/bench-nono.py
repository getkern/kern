#!/usr/bin/env python3
"""nono contro kern, per MODELLO. Il numero pubblicabile e' il COSTO PER COMANDO con la sua
dispersione, non il rapporto: la riga di sessione di kern e' di pochi millisecondi, quindi una
variazione assoluta minuscola fa oscillare il rapporto fra 75x e 168x fra un giro e l'altro.
Un rapporto di due numeri di cui uno e' piccolo non e' un invariante.

Ogni braccio conta l'output prodotto: un comando che fallisce esce prima di aver lavorato.
Le celle calcolano valori UNICI, perche' con `print('x')` ripetuto la riga leggeva meta'.
"""
import os, statistics, subprocess, time

NONO = "/tmp/nonotest/nono"
KERN = "/tmp/e2e/.local/bin/kern"          # la v0.20.0 PUBBLICATA
IMG  = "python:3.12-slim"
N, REPS = 50, 9

def sh(c): return subprocess.run(c, capture_output=True, text=True)
def stats(v): 
    v=sorted(v); return statistics.median(v), v[0], v[-1]

def main():
    import kern_sandbox as kern
    print("=== COSA E' STATO MISURATO ===")
    print("  nono   :", sh([NONO,"--version"]).stdout.strip(), "(installer ufficiale, oggi)")
    print("  kern   :", sh([KERN,"--version"]).stdout.strip(), "(la release, non un build locale)")
    print("  SDK    : kern-sandbox", kern.__version__, "da PyPI")
    print("  host   :", os.uname().machine, os.uname().release, "| carico", open("/proc/loadavg").read().split()[0])
    print("  metodo : %d repliche, mediana, i bracci ALTERNATI, output contato\n" % REPS)

    # --- MODELLO A: un comando, da freddo. Entrambi partono da zero.
    a=[];b=[]
    for _ in range(REPS):
        for who in ("n","k"):
            t=time.perf_counter()
            if who=="n":
                r=sh([NONO,"run","-s","--allow-cwd","--","/usr/bin/python3","-c","print('x')"])
                ok = r.stdout.strip()=="x"
            else:
                ok = kern.run_code("print('x')", image=IMG).stdout.strip()=="x"
            ms=(time.perf_counter()-t)*1000
            assert ok, who
            (a if who=="n" else b).append(ms)
    na,nlo,nhi = stats(a); ka,klo,khi = stats(b)
    print("  A. UN comando, da freddo")
    print("     nono  %6.1f ms  (%.1f - %.1f)" % (na,nlo,nhi))
    print("     kern  %6.1f ms  (%.1f - %.1f)\n" % (ka,klo,khi))

    # --- MODELLO B: N comandi in un ambiente aperto una volta. Il COSTO PER COMANDO.
    a=[];b=[]
    with kern.Sandbox(image=IMG) as s:
        with s.kernel() as k:
            k.run_code("pass"); sh([NONO,"run","-s","--allow-cwd","--","sh","./loop50.sh"])
            for _ in range(REPS):
                t=time.perf_counter()
                r=sh([NONO,"run","-s","--allow-cwd","--","sh","./loop50.sh"])
                ms=(time.perf_counter()-t)*1000
                assert len([l for l in r.stdout.splitlines() if l.strip()=="x"])==N
                a.append(ms/N)
                t=time.perf_counter()
                ok=sum(1 for i in range(N) if k.run_code(f"print({i}*{i}+7)").stdout.strip()==str(i*i+7))
                ms=(time.perf_counter()-t)*1000
                assert ok==N
                b.append(ms/N)
    na,nlo,nhi = stats(a); ka,klo,khi = stats(b)
    print("  B. %d comandi, ambiente aperto UNA volta, costo PER COMANDO" % N)
    print("     nono  %6.2f ms  (%.2f - %.2f)" % (na,nlo,nhi))
    print("     kern  %6.2f ms  (%.2f - %.2f)" % (ka,klo,khi))
    print("     rapporto sulle mediane: %.0fx, e oscilla fra %.0fx e %.0fx sui singoli giri"
          % (na/ka, nlo/khi, nhi/klo))

main()
