#!/bin/sh
# Il numero ufficiale: quanto ci mette kern ad avviare un box, misurato in modo che si possa rifare.
#
# QUESTO SCRIPT ESISTE PERCHE' UN NUMERO SENZA LE SUE TRE DICHIARAZIONI NON VALE NIENTE. Lo stesso
# binario, su questa macchina, ha letto da 2372 a 2789 us secondo come lo si misurava. Quindi qui si
# stampano sempre: QUALE binario (sha256 e versione), CON QUALI bandiere, e CON QUALE alternanza. Se
# un numero di kern compare da qualche parte senza quelle tre cose, non viene da qui.
#
# LA TRAPPOLA CHE HA QUASI ROVINATO LA PRIMA ESECUZIONE, e che nessuna revisione del codice avrebbe
# preso: su una macchina dove kern e' installato, `docker` SUL PATH E' KERN. Il pacchetto installa
# `~/.local/bin/docker -> kern`, quindi `docker --version` risponde `kern 0.9.2` e un confronto
# "kern contro docker" misurerebbe kern contro se stesso, con un risultato spettacolare e falso. Ogni
# concorrente qui e' invocato per PERCORSO ASSOLUTO e la sua identita' viene stampata prima di
# misurare. E' la stessa regola dei pod: la misura non passa per un canale che il misurato riscrive.
#
# DUE CLASSI, SEPARATE, perche' mescolarle e' il modo standard di pubblicare un multiplo gonfiato:
#   CLASSE 1  stesso lavoro, nessuna immagine: kern contro bubblewrap. Entrambi ricevono lo STESSO
#             rootfs gia' sul disco e gli stessi namespace. E' il confronto onesto fra runtime.
#   CLASSE 2  il comando che un utente scrive davvero: `--image alpine` contro `podman run alpine`.
#             Qui dentro c'e' anche la risoluzione dell'immagine e l'overlay, che nella classe 1 non
#             ci sono. Il multiplo di questa classe NON va citato come "kern e' N volte piu' veloce
#             di podman a far partire un container": e' N volte piu' veloce a fare QUESTO.
#
# DOCKER NON E' QUI e la ragione va detta invece di lasciar pensare che sia stato omesso: il demone
# non e' attivo su questa macchina e avviarlo richiede privilegi che questo script non ha. Un
# confronto con docker si fa con `systemctl start docker` a monte, e allora va rifatto tutto.
#
# uso: sh scripts/bench-official.sh [campioni]
set -eu

N=${1:-300}
K=${KERN_BIN:-target/$(uname -m)-unknown-linux-musl/release/kern}
[ -x "$K" ] || { echo "costruisci prima il binario estremo, o passa KERN_BIN=..." >&2; exit 2; }
command -v busybox >/dev/null || { echo "serve busybox" >&2; exit 2; }
[ -f scripts/ab-measure.py ] || { echo "esegui dalla radice del repo" >&2; exit 2; }
K=$(readlink -f "$K")

echo "=================== COSA E' STATO MISURATO ==================="
echo "binario:  $K"
echo "versione: $("$K" --version 2>&1 | head -1)"
echo "sha256:   $(sha256sum "$K" | cut -d' ' -f1)"
echo "profilo:  release (opt-level z, lto fat, codegen-units 1, panic abort)"
echo "          build-std=std,panic_abort + optimize_for_size, -Cpanic=immediate-abort"
# VIRGOLETTE SINGOLE, e non e' pignoleria: qui c'erano dei backtick attorno al nome del profilo, e
# bash li ha ESEGUITI. Lo script ha lanciato perf(1) e ne ha stampato l'aiuto in mezzo alle
# dichiarazioni della misura. Un output che si legge come rumore e' il modo piu' facile di pubblicare
# un numero che nessuno ha guardato.
echo '          cioe ESATTAMENTE cio che release.yml spedisce.'
echo '          Il profilo perf e indistinguibile: vedi scripts/bench-codegen.sh'
echo "macchina: $(uname -srm), $(nproc) core"
echo "distro:   $( . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo sconosciuta )"
echo "carico:   $(LC_ALL=C awk '{print $1, $2, $3}' /proc/loadavg)"
echo "alternanza: campione per campione, non a blocchi (vedi scripts/ab-measure.py)"
echo

RF=$(mktemp -d)/rootfs
mkdir -p "$RF/bin" "$RF/proc" "$RF/dev" "$RF/tmp"
BB=$(command -v busybox)
cp "$BB" "$RF/bin/busybox"
for a in sh cat grep test true sleep; do ln -sf busybox "$RF/bin/$a"; done
for l in $(ldd "$BB" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*'); do
    [ -e "$l" ] && { mkdir -p "$RF$(dirname "$l")"; cp "$l" "$RF$l" 2>/dev/null || true; }
done
export KERN_QUIET=1
KBOX="$K box ofb --rootfs $RF -- /bin/busybox true"

echo "=================== CLASSE 1: nessuna immagine ==================="
BW=$(command -v bwrap 2>/dev/null || true)
if [ -n "$BW" ]; then
    echo "concorrente: $BW  ($("$BW" --version 2>&1 | head -1))"
    python3 scripts/ab-measure.py -n "$N" "$KBOX" \
        "$BW --unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-net --bind $RF / --proc /proc --dev /dev /bin/busybox true" \
        2>&1 | grep -E 'mediana|B - A|verdetto' || true
else
    echo "  bubblewrap assente: la classe 1 non ha concorrente qui"
fi

echo
echo "=================== CLASSE 2: con immagine ==================="
PM=$(command -v podman 2>/dev/null || true)
if [ -n "$PM" ] && "$PM" image exists alpine 2>/dev/null; then
    echo "concorrente: $PM  ($("$PM" --version 2>&1 | head -1))"
    # n ridotto: un campione qui costa centinaia di ms, e 60 coppie bastano perche' la differenza
    # e' di due ordini di grandezza, non al bordo della risoluzione.
    python3 scripts/ab-measure.py -n 60 \
        "$K box ofi --image alpine -- /bin/true" "$PM run --rm alpine /bin/true" \
        2>&1 | grep -E 'mediana|B - A|verdetto' || true
else
    echo "  podman assente, o l'immagine alpine non e' in cache: salto (misurare un pull"
    echo "  non dice niente sul runtime, dice quanto e' veloce la rete)"
fi

echo
echo "=================== PORTATA IN PARALLELO ==================="
echo "quanti box al secondo, e a che concorrenza il soffitto"
KERN_BIN="$K" ROOTFS="$RF" python3 - <<'PY'
import os, subprocess, time
from concurrent.futures import ThreadPoolExecutor
K, RF = os.environ["KERN_BIN"], os.environ["ROOTFS"]
DN, env = subprocess.DEVNULL, dict(os.environ, KERN_QUIET="1")
BW = None
for p in ("/usr/bin/bwrap", "/bin/bwrap"):
    if os.path.exists(p):
        BW = p; break
def kern(i):  return [K, "box", f"t{i}", "--rootfs", RF, "--", "/bin/busybox", "true"]
def bwrap(i): return [BW, "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
                      "--unshare-net", "--bind", RF, "/", "--proc", "/proc", "--dev", "/dev",
                      "/bin/busybox", "true"]
def run(mk, n, conc):
    fails, t0 = 0, time.perf_counter()
    with ThreadPoolExecutor(max_workers=conc) as p:
        for rc in p.map(lambda i: subprocess.run(mk(i), stdout=DN, stderr=DN, env=env).returncode, range(n)):
            fails += (rc != 0)
    el = time.perf_counter() - t0
    return n / el, el * 1e3 / n, fails
print(f"{'conc':>5} {'runtime':>7} {'box/s':>8} {'ms/box':>9} {'falliti':>8}")
for idx, conc in enumerate((1, 8, 32, 100, 200)):
    n = max(conc * 4, 100)
    todo = [("kern", kern)] + ([("bwrap", bwrap)] if BW else [])
    # L'ORDINE SI ALTERNA FRA LE RIGHE. Una portata si misura per forza a blocchi (non si possono
    # interlacciare due runtime a concorrenza 200), e un blocco si prende tutta la deriva di
    # frequenza che capita nella sua meta'. Alternare chi parte per primo non elimina la deriva, la
    # distribuisce. La RIGA A CONCORRENZA 1 NON E' UNA MISURA DI LATENZA e non va letta come tale:
    # misurata cosi' kern e bwrap sembrano pari, mentre il confronto appaiato della classe 1, sugli
    # stessi due comandi, separa 0,4 ms. Il numero di latenza e' quello, non questo.
    if idx % 2:
        todo.reverse()
    for name, mk in todo:
        r, ms, f = run(mk, n, conc)
        # I FALLITI SI STAMPANO SEMPRE. Un avvio che fallisce esce prima di aver lavorato, quindi
        # gonfia la portata: una colonna veloce con dei falliti non e' veloce, e' rotta.
        print(f"{conc:>5} {name:>7} {r:>8.0f} {ms:>9.3f} {f:>8}")
PY

rm -rf "$(dirname "$RF")"
echo
echo "ms/box in parallelo e' AMMORTIZZATO (tempo totale diviso il numero di box), non la latenza"
echo "di un singolo avvio: sono due numeri diversi e confonderli fa sembrare kern 4 volte piu'"
echo "veloce di quanto sia su un avvio solo."
