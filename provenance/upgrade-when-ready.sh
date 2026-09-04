#!/usr/bin/env sh
# Upgrade a pending OpenTimestamps anchor, but only when the Bitcoin block has actually confirmed.
#
# Safe to run any number of times. It reports on what the FILE CONTAINS, not on what this run
# happened to change.
#
# THAT DISTINCTION WAS A DEFECT. The first version decided by comparing the file's sha256 before and
# after `ots upgrade`: unchanged meant "still pending". After the first successful upgrade the file
# stops changing, so from then on the script answered "still pending" forever, however many anchors
# it held. Measured on v0.9.0: the committed file carried THREE BitcoinBlockHeaderAttestations
# (blocks 965419, 965400, 965398) while this script kept reporting that the calendars had none,
# which is the opposite of the truth about the one thing it exists to report.
#
# A stamp can hold pending attestations AND confirmed ones at once: several calendars are asked and
# they anchor at different times. ONE Bitcoin attestation is the proof, so its presence is the
# question, and the number of pending ones is not.
#
#   sh provenance/upgrade-when-ready.sh v0.7.0
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

blocks="$("$OTS" info "$F" 2>/dev/null | grep -oE 'BitcoinBlockHeaderAttestation\([0-9]+\)' \
          | grep -oE '[0-9]+' | sort -un | tr '\n' ' ')"

if [ -z "$blocks" ]; then
    echo "still pending: no Bitcoin attestation in $TAG's stamp yet. Nothing committed."
    exit 0
fi

# Anchored. Whether there is anything to COMMIT is a separate question, and asking it separately is
# the point: an anchor already recorded in git is a success to report, not a reason to say pending.
if [ "$before" = "$after" ] && git diff --quiet -- "$F" && git diff --cached --quiet -- "$F"; then
    echo "$TAG is already anchored in Bitcoin (block(s) $blocks) and the stamp is already committed."
    exit 0
fi
[ -n "$blocks" ] || { echo "error: the file changed but reports no attestation - not committing" >&2; exit 1; }

echo "anchored in block(s): $blocks"
cd "$DIR/.."
git add "provenance/$TAG.provenance.txt.ots"
git commit -m "chore(provenance): upgrade the $TAG anchor, now in the Bitcoin chain

Blocks: $blocks"
git push origin main
