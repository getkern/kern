#!/usr/bin/env python3
"""Misura la differenza fra DUE comandi, appaiata, con l'intervallo e i controlli.

PERCHE' UNO SCRIPT E NON UN `time` A MANO. Ogni numero di questo progetto e' stato preso con la
stessa procedura e la procedura viveva nella testa di chi misurava, quindi si perdeva a ogni sessione
e i suoi controlli si dimenticavano uno alla volta. Le trappole che hanno gia' prodotto un numero
sbagliato qui dentro, in ordine di quanto e' costato accorgersene:

  1. AVER CRONOMETRATO UN ERRORE D'USO. `kern box NOME --rm` non ha quel flag: il comando usciva
     subito e la misura riportava un avvio pulito da 1,5 ms. Da allora ogni uscita si controlla.
  2. AVER MESSO LO STESSO BINARIO IN ENTRAMBE LE COLONNE. La differenza risulta zero e sembra "nessun
     costo aggiunto", che e' il risultato che si sperava. E' il guasto che questo script rifiuta.
  3. AVER MISURATO SOTTO IL PROPRIO CARICO. Con le suite in esecuzione un caso ha letto 1879 us
     contro i 931 veri. Il carico si stampa e sopra una soglia lo script si rifiuta di concludere.
  4. AVER CONFRONTATO DUE COSE DIVERSE. `env VAR=1 cmd` in una colonna sola aggiunge un processo.

FORMA DELLA MISURA. Le due colonne si alternano campione per campione, non a blocchi: un blocco
prende tutta la deriva termica o di frequenza che capita nella sua meta'. Si riporta la MEDIANA,
perche' la coda alta di un avvio di processo e' rumore del sistema e non del programma, e attorno
alla differenza fra mediane un intervallo per ricampionamento, che non assume nessuna distribuzione.
"""

import argparse
import random
import statistics
import subprocess
import sys
import time

# Quanti ricampionamenti per l'intervallo. Diecimila e' dove l'estremo smette di muoversi nella
# terza cifra su campioni di questa dimensione, ed e' meno di un secondo di calcolo.
RESAMPLES = 10000

# Il carico medio oltre il quale una misura su questa macchina non e' interpretabile. Uno per core
# significa che la macchina e' gia' piena e i due comandi si contendono la CPU con altro.
LOAD_CEILING_PER_CORE = 0.5


def _same_file(a: str, b: str) -> bool:
    """Se due percorsi indicano lo stesso file, seguendo i link e i montaggi uniti."""
    import os
    try:
        sa, sb = os.stat(a), os.stat(b)
    except OSError:
        # Un percorso che non si puo' interrogare non e' una prova di uguaglianza. Se poi non
        # esiste davvero, sara' `run_once` a dirlo con l'errore del comando.
        return False
    return (sa.st_dev, sa.st_ino) == (sb.st_dev, sb.st_ino)


def run_once(cmd: list[str]) -> float:
    """Un campione, in microsecondi. Solleva se il comando non esce con zero."""
    start = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True)
    elapsed = (time.perf_counter() - start) * 1e6
    if proc.returncode != 0:
        raise SystemExit(
            f"errore: '{' '.join(cmd)}' e' uscito con {proc.returncode}, non con 0.\n"
            f"  Un comando che fallisce esce PRIMA di aver fatto il lavoro, quindi il tempo\n"
            f"  misurato non e' il tempo di quel lavoro. E' la trappola 1 del docstring.\n"
            f"  stderr: {proc.stderr.decode('utf-8', 'replace')[:400]}"
        )
    return elapsed


def bootstrap_ci(deltas: list[float], confidence: float = 0.95) -> tuple[float, float]:
    """Intervallo per ricampionamento attorno alla mediana delle differenze appaiate."""
    rng = random.Random(20260830)
    n = len(deltas)
    medians = []
    for _ in range(RESAMPLES):
        sample = [deltas[rng.randrange(n)] for _ in range(n)]
        medians.append(statistics.median(sample))
    medians.sort()
    lo = medians[int((1 - confidence) / 2 * RESAMPLES)]
    hi = medians[int((1 + confidence) / 2 * RESAMPLES) - 1]
    return lo, hi


def check_load(cores: int) -> None:
    """Rifiuta di concludere se la macchina e' gia' occupata."""
    try:
        with open("/proc/loadavg", encoding="utf-8") as fh:
            load = float(fh.read().split()[0])
    except (OSError, ValueError, IndexError):
        print("nota: /proc/loadavg non leggibile, il carico non e' stato controllato")
        return
    ceiling = LOAD_CEILING_PER_CORE * cores
    print(f"carico: {load:.2f} su {cores} core (soglia {ceiling:.2f})")
    if load > ceiling:
        raise SystemExit(
            f"errore: carico {load:.2f} sopra la soglia {ceiling:.2f}.\n"
            "  Una misura presa sotto carico proprio e' gia' costata un numero sbagliato in questo\n"
            "  progetto (1879 us contro 931 veri). Aspetta che la macchina sia ferma."
        )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", "--samples", type=int, default=30, help="campioni per colonna")
    ap.add_argument("-w", "--warmup", type=int, default=3, help="campioni scartati all'inizio")
    ap.add_argument("--allow-zero", action="store_true",
                    help="accetta una differenza identicamente nulla (usalo SOLO per il controllo nullo)")
    ap.add_argument("a", help="comando A, fra virgolette")
    ap.add_argument("b", help="comando B, fra virgolette")
    args = ap.parse_args()

    cmd_a, cmd_b = args.a.split(), args.b.split()
    # DUE PERCORSI ALLO STESSO FILE SONO LA STESSA COLONNA, e il confronto fra le stringhe non lo
    # vede: `/bin/true` e `/usr/bin/true` sono lo stesso inode su ogni distribuzione con /usr unito.
    # Provato: quel caso NON viene preso dall'asserzione sullo zero piu' sotto, perche' il rumore dei
    # tempi rende i campioni diversi comunque. Si prende qui, sul file, prima di misurare.
    same = cmd_a == cmd_b or (
        cmd_a and cmd_b and _same_file(cmd_a[0], cmd_b[0]) and cmd_a[1:] == cmd_b[1:]
    )
    if same and not args.allow_zero:
        raise SystemExit(
            "errore: le due colonne sono lo stesso comando (o due percorsi allo stesso file).\n"
            "  Se questo e' il CONTROLLO NULLO, dichiaralo con --allow-zero: e' un uso legittimo e\n"
            "  l'unico in cui una differenza nulla e' il risultato atteso invece di un guasto."
        )

    import os
    cores = os.cpu_count() or 1
    check_load(cores)

    samples_a: list[float] = []
    samples_b: list[float] = []
    # ALTERNATE, non a blocchi: vedi il docstring.
    for i in range(args.samples + args.warmup):
        ta = run_once(cmd_a)
        tb = run_once(cmd_b)
        if i >= args.warmup:
            samples_a.append(ta)
            samples_b.append(tb)

    med_a = statistics.median(samples_a)
    med_b = statistics.median(samples_b)
    deltas = [b - a for a, b in zip(samples_a, samples_b)]
    med_d = statistics.median(deltas)
    lo, hi = bootstrap_ci(deltas)

    print(f"A  {args.a}\n   mediana {med_a:9.1f} us   n={len(samples_a)}")
    print(f"B  {args.b}\n   mediana {med_b:9.1f} us   n={len(samples_b)}")
    print(f"B - A  {med_d:+9.1f} us   intervallo 95% [{lo:+.1f}, {hi:+.1f}]")

    # L'ASSERZIONE CHE UN REVISORE HA CHIESTO DI MECCANIZZARE.
    #
    # Una differenza identicamente nulla su OGNI coppia non e' "nessun costo aggiunto": su un banco
    # vero il rumore da solo la renderebbe diversa da zero, quindi uno zero esatto ripetuto e'
    # l'impronta di uno strumento che non sta misurando. La forma che prende e' un cronometro che
    # non gira, una misura ricavata da un file invece che da un'esecuzione, un campione copiato.
    #
    # COSA NON PRENDE, misurato e non supposto: NON prende due percorsi allo stesso binario. Li' i
    # tempi differiscono comunque per il rumore e le differenze non sono zero. Quel caso lo prende il
    # controllo sul file piu' sopra, e in seconda battuta il verdetto sull'intervallo, che dichiara
    # che le due colonne non si distinguono invece di riportare la mediana come un effetto.
    if all(d == 0.0 for d in deltas) and not args.allow_zero:
        raise SystemExit(
            "errore: la differenza e' esattamente zero su tutte le coppie.\n"
            "  Su un banco reale il rumore da solo la renderebbe diversa da zero, quindi questo non\n"
            "  e' un risultato, e' un guasto dello strumento: le due colonne stanno eseguendo la\n"
            "  stessa cosa. Controlla che i due percorsi risolvano a due file diversi."
        )
    # E LA STESSA IMPRONTA, PIU' DEBOLE: se le due colonne hanno prodotto lo stesso identico insieme
    # di campioni, e' lo stesso guasto anche quando l'ordine differisce.
    if sorted(samples_a) == sorted(samples_b) and not args.allow_zero:
        raise SystemExit(
            "errore: le due colonne hanno prodotto gli stessi identici campioni.\n"
            "  Vedi sopra: e' lo strumento, non il risultato."
        )

    # UN INTERVALLO CHE CONTIENE LO ZERO NON E' UNA DIFFERENZA. Si dice, invece di riportare la
    # mediana come se fosse un effetto: e' il modo in cui un numero ottimista entra in un README.
    if lo <= 0 <= hi:
        print("\nverdetto: l'intervallo contiene lo zero, quindi questa misura NON distingue le due\n"
              "colonne. Non scrivere la mediana come se fosse una differenza.")
    else:
        print(f"\nverdetto: differenza distinguibile, {med_d:+.1f} us")
    return 0


if __name__ == "__main__":
    sys.exit(main())
