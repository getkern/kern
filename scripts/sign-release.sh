#!/bin/sh
# Sign a published release's Linux tarballs and attach the signatures to it. The OWNER runs this,
# on the machine that holds the release key: the key never leaves it, and minisign asks for its
# password once per tarball.
#
#   sh scripts/sign-release.sh v0.52.0
#
# For each published target it downloads the tarball, checks it against the release's own .sha256,
# signs it with a trusted comment `kern self-update` and install.sh read
# (`kern-release v1 version=X.Y.Z target=T file=F`), verifies the signature with the public keys,
# and uploads `<tarball>.minisig` to the release (replacing an older one of the same name).
#
#   KERN_SIGN_KEY   the secret key (default: ~/kern-keys/kern-release.key)
#
# Needs minisign, curl, sha256sum, python3, and a GitHub credential in git's credential helper.
set -eu

tag="${1:-}"
case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *)
    echo "usage: sh scripts/sign-release.sh vX.Y.Z" >&2
    exit 2
    ;;
esac
ver="${tag#v}"
repo="getkern/kern"
key="${KERN_SIGN_KEY:-$HOME/kern-keys/kern-release.key}"
# The same two keys as RELEASE_KEYS in crates/kern-cli/src/selfupdate.rs and install.sh; a unit test
# there fails if the three disagree.
KERN_RELEASE_KEYS="RWSuYG/qtD8AV5p5IzIqfRuCwh5eJlT7ed5+7lVKrgILE1qvIpPGv+Ej RWRLQt2lFPXXsC0g2+1SPfSmOdjpxJ/f+t5DU+xPOaRNjElnisOR0Uo3"

for tool in minisign curl sha256sum python3 git; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "sign-release: $tool is not installed" >&2
    exit 1
  }
done
[ -f "$key" ] || {
  echo "sign-release: no secret key at $key (set KERN_SIGN_KEY)" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
chmod 700 "$work"

# The credential goes in a header FILE, not on a command line where `ps` would show it.
token="$(printf 'protocol=https\nhost=github.com\nusername=realexhub\n\n' | git credential fill 2>/dev/null | sed -n 's/^password=//p')"
[ -n "$token" ] || {
  echo "sign-release: git's credential helper has no GitHub credential for realexhub" >&2
  exit 1
}
printf 'Authorization: token %s\n' "$token" >"$work/auth"
chmod 600 "$work/auth"
unset token
api() { curl -fsS -H @"$work/auth" -H "Accept: application/vnd.github+json" "$@"; }

api "https://api.github.com/repos/$repo/releases/tags/$tag" >"$work/release.json" || {
  echo "sign-release: no release $tag on $repo" >&2
  exit 1
}
release_id="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$work/release.json")"

for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  file="kern-$target.tar.gz"
  url="https://github.com/$repo/releases/download/$tag/$file"
  echo "== $file"
  curl -fsSL "$url" -o "$work/$file"
  curl -fsSL "$url.sha256" -o "$work/$file.sha256"
  want="$(awk '{print $1}' "$work/$file.sha256")"
  got="$(sha256sum "$work/$file" | awk '{print $1}')"
  [ "$want" = "$got" ] || {
    echo "sign-release: $file does not match its .sha256 ($got, release says $want): not signing" >&2
    exit 1
  }
  comment="kern-release v1 version=$ver target=$target file=$file"
  minisign -S -s "$key" -m "$work/$file" -x "$work/$file.minisig" -t "$comment"
  ok=""
  for pub in $KERN_RELEASE_KEYS; do
    if minisign -V -q -P "$pub" -m "$work/$file" -x "$work/$file.minisig" >/dev/null 2>&1; then
      ok=1
    fi
  done
  [ -n "$ok" ] || {
    echo "sign-release: the signature does not verify with either release public key: is $key the release key?" >&2
    exit 1
  }
  grep -qxF "trusted comment: $comment" "$work/$file.minisig" || {
    echo "sign-release: the signed comment is not the release statement" >&2
    exit 1
  }
  # Replace an older signature of the same name: GitHub refuses a second asset with one name.
  old_id="$(python3 -I -c 'import json,sys
for a in json.load(open(sys.argv[1])).get("assets", []):
    if a["name"] == sys.argv[2]:
        print(a["id"])' "$work/release.json" "$file.minisig")"
  if [ -n "$old_id" ]; then
    api -X DELETE "https://api.github.com/repos/$repo/releases/assets/$old_id" >/dev/null
  fi
  api -X POST -H "Content-Type: application/octet-stream" --data-binary @"$work/$file.minisig" \
    "https://uploads.github.com/repos/$repo/releases/$release_id/assets?name=$file.minisig" >/dev/null
  echo "   signed and attached: $file.minisig"
done
echo "done: $tag is installable by \`kern self-update\`"
