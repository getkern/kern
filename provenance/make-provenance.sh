#!/usr/bin/env sh
# Generate and OpenTimestamp the provenance file for a SIGNED release tag.
#
# Run this AFTER `git tag -s vX.Y.Z && git push origin vX.Y.Z`. It writes
# provenance/<tag>.provenance.txt (naming the signed tag object hash + the release commit hash) and
# stamps it with OpenTimestamps, producing the .ots anchor. Then commit both files.
#
#   sh provenance/make-provenance.sh v0.6.9
#
# Requires: a GPG-verifiable signed tag, and `ots` (OpenTimestamps client). Defaults OTS to the venv at
# ~/.venv-ots/bin/ots, override with $OTS.
set -eu

TAG="${1:-v0.6.9}"
OTS="${OTS:-$HOME/.venv-ots/bin/ots}"
DIR="$(CDPATH= cd "$(dirname "$0")" && pwd)"
TXT="$DIR/$TAG.provenance.txt"

# 1. The tag must exist and carry a valid GPG signature (this is the whole point of the record).
if ! git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "error: tag $TAG does not exist. Create it first: git tag -s $TAG -m '...' && git push origin $TAG" >&2
    exit 1
fi
if ! git verify-tag "$TAG" >/dev/null 2>&1; then
    echo "error: $TAG is not a valid signed tag (git verify-tag failed). Use git tag -s (signed)." >&2
    exit 1
fi

TAG_OBJ="$(git rev-parse "$TAG")"       # the annotated/signed tag OBJECT hash
COMMIT="$(git rev-parse "$TAG^{}")"     # the release COMMIT the tag points to

# 2. Write the provenance record in the established format.
printf 'kern %s signed tag object: %s\ncommit: %s\n' "$TAG" "$TAG_OBJ" "$COMMIT" > "$TXT"
echo "wrote $TXT:"
sed 's/^/  /' "$TXT"

# 3. Anchor it to the Bitcoin blockchain via OpenTimestamps (creates $TXT.ots, PendingAttestation).
if [ ! -x "$OTS" ]; then
    echo "error: ots not found at $OTS (set \$OTS or pip install opentimestamps-client)." >&2
    exit 1
fi
"$OTS" stamp "$TXT"
echo
echo "done. Next:"
echo "  git add provenance/$TAG.provenance.txt provenance/$TAG.provenance.txt.ots"
echo "  git commit -m 'chore(provenance): anchor $TAG'"
echo "  git push origin main"
echo "Later (once the BTC block confirms, a few hours): $OTS upgrade $TXT.ots && commit the upgraded .ots"
