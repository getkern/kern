#!/usr/bin/env sh
# Upgrade a pending OpenTimestamps anchor, but only when the Bitcoin block has actually confirmed.
#
# Safe to run any number of times: it does nothing until the calendars have an attestation, and it
# commits only when the .ots file really changed. `ots upgrade` on a still-pending stamp prints
# "not upgraded" and leaves the file alone, so the guard here is about not producing an empty commit
# and not claiming an anchor that is not there yet.
#
#   sh provenance/upgrade-when-ready.sh v0.6.32
set -eu

TAG="${1:?usage: upgrade-when-ready.sh vX.Y.Z}"
OTS="${OTS:-$HOME/.venv-ots/bin/ots}"
DIR="$(CDPATH= cd "$(dirname "$0")" && pwd)"
F="$DIR/$TAG.provenance.txt.ots"

[ -f "$F" ] || { echo "error: no $F" >&2; exit 1; }
[ -x "$OTS" ] || { echo "error: ots not found at $OTS" >&2; exit 1; }

before="$(sha256sum "$F" | cut -d' ' -f1)"
"$OTS" upgrade "$F" 2>&1 | sed 's/^/  /' || true
after="$(sha256sum "$F" | cut -d' ' -f1)"

if [ "$before" = "$after" ]; then
    echo "still pending: the calendars have no Bitcoin attestation for $TAG yet. Nothing committed."
    exit 0
fi

blocks="$("$OTS" info "$F" 2>/dev/null | grep -oE 'BitcoinBlockHeaderAttestation\([0-9]+\)' \
          | grep -oE '[0-9]+' | sort -un | tr '\n' ' ')"
[ -n "$blocks" ] || { echo "error: the file changed but reports no attestation - not committing" >&2; exit 1; }

echo "anchored in block(s): $blocks"
cd "$DIR/.."
git add "provenance/$TAG.provenance.txt.ots"
git commit -m "chore(provenance): upgrade the $TAG anchor, now in the Bitcoin chain

Blocks: $blocks"
git push origin main
