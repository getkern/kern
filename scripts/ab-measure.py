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

# Le annotazioni restano stringhe, cosi' `float | None` non alza il pavimento di versione a 3.10 per
# uno strumento che tutti lanciano: il binding dichiara `requires-python = ">=3.9"`.
from __future__ import annotations

import argparse
import random
import statistics
import subprocess
import sys
import time

# Quanti ricampionamenti per l'intervallo. Diecimila e' dove l'estremo smette di muoversi nella
# terza cifra su campioni di questa dimensione, ed e' meno di un secondo di calcolo.
RESAMPLES = 10000

# La percentuale di CPU occupata oltre la quale una misura su questa macchina non e' interpretabile.
# E' la stessa soglia di `scripts/bench-idle.sh`, deliberatamente: due strumenti dello stesso
# progetto che rispondono diversamente a "la macchina e' ferma" rendono il verdetto una questione di
# quale si e' lanciato.
BUSY_CEILING_PERCENT = 12.0


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


def _busy_percent(window_s: float = 2.0) -> float | None:
    """Quanta CPU e' occupata ADESSO, in percentuale, letta su una finestra di `window_s`."""
    def snapshot() -> tuple[int, int] | None:
        try:
            with open("/proc/stat", encoding="utf-8") as fh:
                fields = [int(x) for x in fh.readline().split()[1:]]
        except (OSError, ValueError, IndexError):
            return None
        # `idle` e `iowait` non sono tempo occupato; tutto il resto lo e'. Le voci oltre la ottava
        # (guest, guest_nice) sono gia' contate dentro user e nice dal kernel, quindi fermarsi a
        # otto non perde niente e non conta due volte.
        total = sum(fields[:8])
        idle = fields[3] + fields[4]
        return total, idle

    first = snapshot()
    if first is None:
        return None
    time.sleep(window_s)
    second = snapshot()
    if second is None:
        return None
    elapsed = second[0] - first[0]
    if elapsed <= 0:
        return None
    return 100.0 * (1.0 - (second[1] - first[1]) / elapsed)


def check_load(cores: int) -> None:
    """Rifiuta di concludere se la macchina e' occupata ADESSO.

    IL CARICO MEDIO MENTE, in entrambe le direzioni, e questa funzione lo leggeva. Dopo una
    compilazione il load dice 2,53 su una macchina la cui CPU e' all'8%: la misura veniva rifiutata
    a vuoto. Il verso pericoloso e' l'altro: il load porta un minuto di memoria, quindi all'inizio
    di un carico nuovo e' ancora basso e questo controllo dichiarava ferma una macchina che aveva
    appena iniziato a lavorare. Un controllo che sbaglia verso l'ACCETTARE e' un controllo spento.

    `scripts/bench-idle.sh` legge gia' il segnale giusto e con la stessa soglia, e la ragione e'
    scritta li': "What matters here is whether the CPU is busy NOW". Due strumenti dello stesso
    progetto non possono dare due giudizi diversi su "la macchina e' ferma", quindi la soglia e' la
    stessa costante e non una scelta nuova.
    """
    busy = _busy_percent()
    if busy is None:
        print("nota: /proc/stat non leggibile, il carico non e' stato controllato")
        return
    lagging = "?"
    try:
        with open("/proc/loadavg", encoding="utf-8") as fh:
            lagging = f"{float(fh.read().split()[0]):.2f}"
    except (OSError, ValueError, IndexError):
        pass
    print(f"CPU occupata ora: {busy:.1f}% su {cores} core (soglia {BUSY_CEILING_PERCENT}%)"
          f"   [carico medio, che ritarda di un minuto: {lagging}]")
    if busy > BUSY_CEILING_PERCENT:
        raise SystemExit(
            f"errore: CPU occupata al {busy:.1f}%, sopra la soglia {BUSY_CEILING_PERCENT}%.\n"
            "  Una misura presa sotto carico proprio e' gia' costata un numero sbagliato in questo\n"
            "  progetto (1879 us contro 931 veri). Chiudi cio' che gira, o la misura descrive la\n"
            "  macchina invece dei due comandi."
        )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", "--samples", type=int, default=30, help="campioni per colonna")
    ap.add_argument("-w", "--warmup", type=int, default=3, help="campioni scartati all'inizio")
    ap.add_argument("--allow-zero", action="store_true",
                    help="accetta una differenza identicamente nulla (usalo SOLO per il controllo nullo)")
    # LA TOLLERANZA SI SCRIVE, non ha un valore implicito. Con `nargs="?"` argparse si mangiava il
    # primo comando come se fosse il numero ("invalid float value: '/bin/true'"), e a parte questo
    # una soglia predefinita e' una soglia che nessuno ha scelto.
    ap.add_argument("--assert-not-slower", type=float, default=None, metavar="US",
                    help="esce 1 se l'intervallo sta INTERAMENTE sopra questa tolleranza in us. "
                         "A e' il riferimento, B il candidato. Scrivi 0 per tolleranza nulla")
    # IL CONTROLLO NULLO COME ASSERZIONE. Due copie dello stesso binario nelle due colonne: se la
    # misura le dichiara distinguibili, lo strumento e' rotto e ogni verdetto preso con lui nella
    # stessa sessione e' inaffidabile. Una volta questo script ha dichiarato un binario diverso da
    # se stesso di 645 us, e lo si e' scoperto a mano; un cancello lo deve scoprire da solo.
    ap.add_argument("--assert-indistinguishable", action="store_true",
                    help="esce 1 se l'intervallo NON contiene lo zero: per il controllo nullo A/A")
    ap.add_argument("a", help="comando A, fra virgolette")
    ap.add_argument("b", help="comando B, fra virgolette")
    args = ap.parse_args()
    assert_not_slower = args.assert_not_slower

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
    # ALTERNATE, non a blocchi: vedi il docstring. E DENTRO LA COPPIA SI RUOTA L'ORDINE.
    #
    # 🚨 LA ROTAZIONE E' UN DIFETTO CORRETTO, NON UN ABBELLIMENTO. Questo ciclo eseguiva sempre A e
    # poi B. Su `kern box --vm`, con due COPIE DELLO STESSO BINARIO nelle due colonne, dava:
    #
    #     n=120   B - A  -645,6 us   [-1112,5, -287,9]   "differenza distinguibile"
    #     n=300   B - A  +374,5 us   [  +81,4,  +584,4]  "differenza distinguibile"
    #
    # Un binario dichiarato diverso da se stesso, due volte, con il SEGNO CHE SI RIBALTA fra le due
    # esecuzioni. Chi sta in seconda posizione paga o incassa qualcosa di sistematico (cache di
    # pagina, frequenza, collocazione sulla CPU), l'intervallo per ricampionamento si stringe attorno
    # a quel bias invece che attorno allo zero, e piu' campioni lo rendono PIU' sicuro di una cosa
    # falsa. A n=30 conteneva lo zero per fortuna, non per correttezza.
    #
    # Ruotare mette ogni colonna in prima posizione la meta' delle volte, quindi il bias di posizione
    # entra in entrambe e si cancella nella differenza appaiata. Il campione va nella colonna del
    # comando, mai nella colonna della posizione.
    for i in range(args.samples + args.warmup):
        if i % 2 == 0:
            ta = run_once(cmd_a)
            tb = run_once(cmd_b)
        else:
            tb = run_once(cmd_b)
            ta = run_once(cmd_a)
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

    # L'ASSERZIONE CHE VA MECCANIZZATA E NON LETTA A OCCHIO.
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

    # IL PAVIMENTO DI RILEVAZIONE, sempre, anche quando il verdetto e' "non distinguibile".
    #
    # "Non distinguibile" da solo si legge come "non costa niente", e sono due cose diverse: la
    # seconda e' vera solo se questa misura sarebbe stata capace di vedere un costo. La meta'
    # larghezza dell'intervallo e' cio' che questa misura poteva vedere, quindi si stampa accanto al
    # verdetto invece di lasciarla dedurre.
    floor = (hi - lo) / 2.0
    print(f"pavimento di rilevazione: +-{floor:.1f} us "
          f"(n={len(deltas)}; un costo sotto questa soglia questa misura NON lo vedrebbe)")

    # IL CANCELLO, per chi misura una REGRESSIONE e non una differenza.
    #
    # Chi chiama qui ha gia' deciso quale colonna e' il riferimento: A e' il prima, B e' il dopo.
    # Bocciare quando l'intervallo sta INTERAMENTE sopra la tolleranza, e non quando la mediana e'
    # positiva: una mediana positiva dentro un intervallo che contiene lo zero e' rumore, e un
    # cancello che la boccia diventa un cancello che si spegne.
    #
    # ⛔ E il contrario vale uguale: un intervallo interamente sotto lo zero NON e' un successo da
    # rivendicare qui. Questo cancello dice solo "non e' peggiorato".
    if args.assert_indistinguishable and not (lo <= 0 <= hi):
        print(f"\nSTRUMENTO ROTTO: due colonne che dovrebbero essere identiche escono distinguibili,\n"
              f"intervallo [{lo:+.1f}, {hi:+.1f}]. Nessun verdetto preso in questa sessione vale.")
        return 1
    if assert_not_slower is not None:
        if lo > assert_not_slower:
            print(f"\nREGRESSIONE: l'intervallo [{lo:+.1f}, {hi:+.1f}] sta interamente sopra la\n"
                  f"tolleranza di {assert_not_slower:+.1f} us. B e' piu' lento di A, e non e' rumore.")
            return 1
        print(f"\nnessuna regressione oltre {assert_not_slower:+.1f} us: l'intervallo "
              f"[{lo:+.1f}, {hi:+.1f}] non sta interamente sopra la tolleranza.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
