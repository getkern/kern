#!/bin/sh
# Sign a release's assets, attach the signatures, and publish it. The OWNER runs this, on the machine
# that holds the release key: the key never leaves it, and minisign asks for its password once per
# file.
#
#   sh scripts/sign-release.sh v0.52.0
#
# The release workflow leaves a new release as a DRAFT, so nothing is public before it is signed.
# This script finds the draft (or a published release, to re-sign one), and for each asset - the two
# Linux tarballs, the Windows shim, the WSL rootfs and the SBOM (`kern.spdx.json`, target `sbom`, so
# its signature can never be taken for a binary's) - downloads it, checks it against the release's
# own .sha256, signs it with the trusted comment `kern self-update`, install.sh and install.ps1 read
# (`kern-release v1 version=X.Y.Z target=T file=F`), verifies the signature with the public keys, and
# uploads `<file>.minisig` (replacing an older one of the same name). When every file is signed, a
# draft is published. With GitHub's immutable releases on, nothing can be changed after that.
#
#   KERN_SIGN_KEY         the secret key (default: ~/kern-keys/kern-release.key)
#   KERN_SIGN_NO_PUBLISH  set to 1 to sign and leave the draft a draft
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

# A DRAFT IS NOT FOUND BY TAG (`releases/tags/<tag>` answers only published ones), so the list is
# read, which includes drafts for a caller with write access.
api "https://api.github.com/repos/$repo/releases?per_page=100" >"$work/releases.json"
python3 -I -c 'import json,sys
hits = [r for r in json.load(open(sys.argv[1])) if r.get("tag_name") == sys.argv[2]]
if len(hits) != 1:
    sys.exit(1)
json.dump(hits[0], open(sys.argv[3], "w"))' "$work/releases.json" "$tag" "$work/release.json" || {
  echo "sign-release: no single release (draft or published) for $tag on $repo" >&2
  exit 1
}
release_id="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$work/release.json")"

draft="$(python3 -I -c 'import json,sys; print(1 if json.load(open(sys.argv[1]))["draft"] else 0)' "$work/release.json")"

# The id of an asset of this release by name, or nothing.
asset_id() {
  python3 -I -c 'import json,sys
for a in json.load(open(sys.argv[1])).get("assets", []):
    if a["name"] == sys.argv[2]:
        print(a["id"])' "$work/release.json" "$1"
}

# Download an asset through the API: a draft's assets have no public URL.
fetch() {
  id="$(asset_id "$1")"
  [ -n "$id" ] || {
    echo "sign-release: $tag has no asset $1: not signing" >&2
    exit 1
  }
  curl -fsSL -H @"$work/auth" -H "Accept: application/octet-stream" \
    "https://api.github.com/repos/$repo/releases/assets/$id" -o "$2"
}

# file and the target its signed comment names
for pair in \
  "kern-x86_64-unknown-linux-musl.tar.gz x86_64-unknown-linux-musl" \
  "kern-aarch64-unknown-linux-musl.tar.gz aarch64-unknown-linux-musl" \
  "kern-windows-x86_64.exe x86_64-pc-windows-gnu" \
  "kern-wsl-rootfs.tar.gz x86_64-wsl-rootfs" \
  "kern.spdx.json sbom"; do
  file="${pair%% *}"
  target="${pair#* }"
  echo "== $file"
  fetch "$file" "$work/$file"
  fetch "$file.sha256" "$work/$file.sha256"
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
  old_id="$(asset_id "$file.minisig")"
  if [ -n "$old_id" ]; then
    api -X DELETE "https://api.github.com/repos/$repo/releases/assets/$old_id" >/dev/null
  fi
  api -X POST -H "Content-Type: application/octet-stream" --data-binary @"$work/$file.minisig" \
    "https://uploads.github.com/repos/$repo/releases/$release_id/assets?name=$file.minisig" >/dev/null
  echo "   signed and attached: $file.minisig"
done

if [ "$draft" = 1 ]; then
  if [ "${KERN_SIGN_NO_PUBLISH:-}" = 1 ]; then
    echo "done: $tag is signed and still a draft (KERN_SIGN_NO_PUBLISH=1)"
    exit 0
  fi
  api -X PATCH -H "Content-Type: application/json" --data '{"draft":false}' \
    "https://api.github.com/repos/$repo/releases/$release_id" >/dev/null
  echo "published: $tag"
fi
echo "done: $tag is installable by \`kern self-update\`"
# kern.exe carries no Authenticode signature, and Defender has removed it before. Microsoft analyses a
# submitted file as a false positive for free; it takes the owner's Microsoft account, so it is said
# here rather than done.
exe_sha="$(sha256sum "$work/kern-windows-x86_64.exe" | awk '{print $1}')"
echo
echo "Windows: submit kern-windows-x86_64.exe as a false positive (free):"
echo "  https://www.microsoft.com/en-us/wdsi/filesubmission"
echo "  file sha256: $exe_sha"

