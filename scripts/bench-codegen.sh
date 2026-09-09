#!/bin/sh
# Il codegen "estremo" fa guadagnare millisecondi all'avvio di un box? No, e questo lo rimisura.
#
# LA DOMANDA E' UNA RISPOSTA GIA' SCRITTA NEL `Cargo.toml`, ed e' per questo che vale rifarla. Il
# commento sopra `[profile.release]` diceva che `opt-level = "z"` non costa latenza ed e' anzi "un
# capello piu' veloce". Quella frase e' stata scritta una volta, su una macchina, su un binario che
# da allora e' cambiato in sei modi. Una affermazione della forma "piu' piccolo E piu' veloce" e'
# quella che nessuno rimisura, perche' e' il risultato che si sperava.
#
# I DUE ASSI SI MUOVONO SEPARATI, e un giro che li cambia insieme non puo' dire chi ha pagato:
#   A  `release`, opt-level "z", std con `optimize_for_size`   <- ESATTAMENTE CIO' CHE SI SPEDISCE
#   B  `perf`,    opt-level 3,   std con `optimize_for_size`   <- solo le NOSTRE crate
#   C  `perf`,    opt-level 3,   std SENZA `optimize_for_size` <- entrambi gli assi
#
# UN NULLO NON SI PUO' PUBBLICARE SENZA LA RISOLUZIONE DELLO STRUMENTO. "Nessuna differenza" e'
# indistinguibile da "lo strumento non vede" finche' non si mostra la piu' piccola differenza che lo
# strumento SA vedere. Quindi prima di confrontare i binari questo script inietta ritardi NOTI e
# stampa dove smette di risolverli; se non arriva sotto la soglia, si rifiuta di concludere.
#
# IL PRIMO CONTROLLO POSITIVO CHE HO SCRITTO ERA INUTILE: `busybox true` contro `busybox sh -c true`,
# cioe' un confronto il cui costo vero non conoscevo. Non ha discriminato, e non voleva dire niente
# ne' sullo strumento ne' sul programma. Un controllo positivo deve avere un costo NOTO.
#
# uso: sh scripts/bench-codegen.sh [campioni]
# esce 0 se ha concluso, 2 se non ha potuto (build assente, busybox assente, risoluzione insufficiente).
set -eu

N=${1:-200}
T="$(uname -m)-unknown-linux-musl"
NIGHTLY=nightly-2026-08-09
# La piu' grande differenza che siamo disposti a NON vedere. Sotto questa soglia il nullo vale.
RESOLUTION_FLOOR_US=100

command -v busybox >/dev/null || { echo "serve busybox per costruire il rootfs" >&2; exit 2; }
[ -f scripts/ab-measure.py ] || { echo "esegui dalla radice del repo" >&2; exit 2; }

RF=$(mktemp -d)/rootfs
mkdir -p "$RF/bin" "$RF/proc" "$RF/dev" "$RF/tmp"
BB=$(command -v busybox)
cp "$BB" "$RF/bin/busybox"
# Ogni applet collegato, non solo `sh`: su una busybox senza shell standalone `sleep` non si risolve
# e la scala dei ritardi noti muore in silenzio, che e' il modo in cui un controllo positivo diventa
# un falso verde.
for a in sh cat grep test true sleep; do ln -sf busybox "$RF/bin/$a"; done
for l in $(ldd "$BB" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*'); do
    [ -e "$l" ] && { mkdir -p "$RF$(dirname "$l")"; cp "$l" "$RF$l" 2>/dev/null || true; }
done

D=$(mktemp -d)
export RUSTFLAGS="-Zunstable-options -Cpanic=immediate-abort"
echo "costruisco le tre configurazioni (il primo giro compila anche la std)"
cargo "+$NIGHTLY" build --release --target "$T" --bin kern \
    -Z build-std=std,panic_abort -Z build-std-features=optimize_for_size >/dev/null 2>&1
cp "target/$T/release/kern" "$D/A"
cargo "+$NIGHTLY" build --profile perf --target "$T" --bin kern \
    -Z build-std=std,panic_abort -Z build-std-features=optimize_for_size >/dev/null 2>&1
cp "target/$T/perf/kern" "$D/B"
cargo "+$NIGHTLY" build --profile perf --target "$T" --bin kern \
    -Z build-std=std,panic_abort >/dev/null 2>&1
cp "target/$T/perf/kern" "$D/C"

BOX="box cgbench --rootfs $RF --"
export KERN_QUIET=1

echo
echo "=== risoluzione dello strumento: ritardi NOTI, iniettati nello stesso binario ==="
best=999999
for us in 2000 500 200 100 50; do
    s=$(LC_ALL=C awk -v u="$us" 'BEGIN{printf "%.6f", u/1000000}')
    out=$(python3 scripts/ab-measure.py -n "$N" --allow-zero \
        "$D/A $BOX /bin/busybox true" "$D/A $BOX /bin/busybox sleep $s" 2>&1 || true)
    if printf '%s' "$out" | grep -q 'differenza distinguibile'; then
        printf '  %5d us iniettati -> RISOLTO   %s\n' "$us" "$(printf '%s' "$out" | grep 'B - A')"
        best=$us
    else
        printf '  %5d us iniettati -> non risolto\n' "$us"
        break
    fi
done
if [ "$best" -gt "$RESOLUTION_FLOOR_US" ]; then
    echo
    echo "  RIFIUTO DI CONCLUDERE: lo strumento risolve solo $best us, sopra la soglia di"
    echo "  $RESOLUTION_FLOOR_US us. Un 'nessuna differenza' con questa risoluzione non dice"
    echo "  niente sui binari. Macchina troppo carica, o troppi pochi campioni."
    rm -rf "$D" "$(dirname "$RF")"
    exit 2
fi
echo "  risoluzione dimostrata: $best us"

echo
echo "=== A (spedito) contro le due configurazioni veloci ==="
for v in B C; do
    echo "--- A vs $v ---"
    python3 scripts/ab-measure.py -n "$N" \
        "$D/A $BOX /bin/busybox true" "$D/$v $BOX /bin/busybox true" 2>&1 \
        | grep -E 'mediana|B - A|verdetto' || true
done

echo
echo "=== dove va il tempo, per non cercarlo dove non e' ==="
echo "--- avvio del solo binario contro avvio di un box ---"
python3 scripts/ab-measure.py -n "$N" --allow-zero \
    "$D/A --version" "$D/A $BOX /bin/busybox true" 2>&1 | grep -E 'mediana|B - A' || true
echo "--- costo del namespace di rete: default contro --net host ---"
python3 scripts/ab-measure.py -n "$N" --allow-zero \
    "$D/A $BOX /bin/busybox true" \
    "$D/A box cgbench --rootfs $RF --net host -- /bin/busybox true" 2>&1 \
    | grep -E 'B - A|verdetto' || true

rm -rf "$D" "$(dirname "$RF")"
