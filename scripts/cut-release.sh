#!/bin/sh
# Cut a release, in the one order that works, refusing at the first thing that is not true.
#
# WHY THIS FILE EXISTS. On 2026-09-09 v0.9.31 was cut by hand and published BROKEN: the evidence gate
# went red, the Linux `build` matrix was skipped behind it, and the release went out with the Windows
# assets and no Linux binary at all, which is what `install.sh` downloads. Nothing was wrong with the
# code. What was wrong was the ORDER: the changelog was committed after the suites had run, so the
# tagged tree carried a stamp naming an earlier commit, and a gate fired on that.
#
# An order that only works when the person remembers it is not a process, and the repair took an hour
# of workflow surgery at midnight. This script is that order, executable, with the reasons attached.
#
#     sh scripts/cut-release.sh v0.9.32
#
# It stops before anything irreversible and tells you what it is about to do. The two irreversible
# steps - the signed tag and its push - are the last two, and by then everything else has passed.
#
# WHAT IT DELIBERATELY DOES NOT DO: sign for you (`git tag -s` asks for the passphrase, and that is
# the one thing that must stay in a human's hands), delete anything, or re-cut a tag. A tag is never
# re-cut in this repository and a release is never deleted: both destroy the download history that
# is the only measure of adoption there is.
set -eu

cd "$(dirname "$0")/.."

die() { printf 'cut-release: %s\n' "$1" >&2; exit 1; }
step() { printf '\n== %s\n' "$1"; }
ok() { printf '   ok  %s\n' "$1"; }

VERSION="${1:-}"
[ -n "$VERSION" ] || die "usage: sh scripts/cut-release.sh vX.Y.Z"
case "$VERSION" in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) die "'$VERSION' is not a vX.Y.Z tag name" ;;
esac

# ---------------------------------------------------------------- refusals, before any work
step "refusals"

# NEVER RE-CUT A TAG. Checked against the REMOTE as well as locally: a tag deleted here still exists
# there, and re-pushing it silently rewrites what a user already downloaded.
if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
    die "$VERSION already exists locally. A tag is never re-cut; pick the next version."
fi
if git ls-remote --exit-code --tags origin "refs/tags/$VERSION" >/dev/null 2>&1; then
    die "$VERSION already exists on origin. A tag is never re-cut; pick the next version."
fi
ok "$VERSION is new, here and on origin"

[ -z "$(git status --porcelain)" ] || die "the working tree is dirty. Commit or stash first: a release is cut from a tree someone can reproduce."
ok "working tree clean"

branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = "main" ] || die "on branch '$branch'. Releases are cut from main."
git fetch --quiet origin main 2>/dev/null || true
if [ "$(git rev-parse main)" != "$(git rev-parse origin/main 2>/dev/null || echo none)" ]; then
    die "main and origin/main differ. Push or pull first; a tag on an unpushed commit is a release nobody can fetch."
fi
ok "on main, in step with origin"

# THE CHANGELOG IS PART OF THE RELEASE, and it has to exist BEFORE the tag rather than after. Writing
# it afterwards is exactly what broke v0.9.31: the entry became a commit the tag did not contain.
grep -q "^## ${VERSION} " CHANGELOG.md || die "CHANGELOG.md has no '## $VERSION ' entry. Write it, commit it, then cut - not the other way round, which is the mistake this script exists to stop."
ok "CHANGELOG.md has an entry for $VERSION"

# ---------------------------------------------------------------- the gates CI runs
step "gates (the ones CI runs, with the flags CI runs them with)"
RUSTFLAGS="-D warnings"; export RUSTFLAGS
cargo fmt --all --check >/dev/null || die "cargo fmt --check failed"
ok "cargo fmt --check"
cargo clippy --all-targets --all-features >/dev/null 2>&1 || die "cargo clippy -D warnings failed"
ok "cargo clippy -D warnings"
env -u KERN_BIN cargo test --all >/tmp/cut-release-test.$$ 2>&1 || {
    tail -20 /tmp/cut-release-test.$$ >&2
    die "cargo test failed (full output in /tmp/cut-release-test.$$)"
}
ok "cargo test: $(grep -c '^test .* \.\.\. ok' /tmp/cut-release-test.$$) passing"
rm -f /tmp/cut-release-test.$$

for g in flat-continuation gen-seccomp-allowlist injection-declared no-ai-slop \
         registry-classified stale-numbers test-count progress-is-tty-gated gates-selftest; do
    python3 "scripts/$g.py" >/dev/null 2>&1 || die "scripts/$g.py failed"
done
ok "9 doc/consistency gates"

# THE CHARACTER IS BUILT, NEVER TYPED: this file is scanned by the gate it runs.
EM=$(printf '\342\200\224')
printf 'a%sb\n' "$EM" > "/tmp/cut-em.$$"
grep -q "$EM" "/tmp/cut-em.$$" || die "the em-dash positive control failed: this grep cannot see one, so its silence would mean nothing"
rm -f "/tmp/cut-em.$$"
if LC_ALL=C.UTF-8 git grep -l "$EM" -- '*.md' '*.rs' '*.sh' '*.py' >/dev/null 2>&1; then
    LC_ALL=C.UTF-8 git grep -n "$EM" -- '*.md' '*.rs' '*.sh' '*.py' | head -5 >&2
    die "em-dash found in tracked files"
fi
ok "zero em-dashes (positive control passed first)"

# ---------------------------------------------------------------- the evidence, on THIS code
step "pentest suites (the evidence behind SECURITY.md)"
# RUN THEM ON THE CODE THAT WILL SHIP, WHICH IS THE POINT OF DOING IT HERE. `run-all.sh` stamps
# `pentest/.last-run` with the commit it ran at; the stamp commit made below is the last thing that
# happens before the tag, so the tagged tree carries evidence for its own code.
sh pentest/run-all.sh >/tmp/cut-release-pentest.$$ 2>&1 || {
    tail -20 /tmp/cut-release-pentest.$$ >&2
    die "pentest suites failed (full output in /tmp/cut-release-pentest.$$)"
}
ok "$(tail -1 /tmp/cut-release-pentest.$$)"
rm -f /tmp/cut-release-pentest.$$

if [ -n "$(git status --porcelain pentest/.last-run)" ]; then
    git add pentest/.last-run
    printf 'chore(pentest): stamp the tree %s is cut from\n' "$VERSION" > "/tmp/cut-msg.$$"
    # The work-hours hook applies here like anywhere else. It is not bypassed: if it refuses, the
    # release waits, which is the owner's rule and not this script's to override.
    git commit -F "/tmp/cut-msg.$$" --quiet || die "the stamp commit was refused (work-hours hook?). The release waits."
    rm -f "/tmp/cut-msg.$$"
    git push --quiet origin main || die "pushing the stamp failed"
    ok "stamp committed and pushed: $(git rev-parse --short HEAD)"
else
    ok "stamp already current for this tree"
fi

python3 scripts/check-pentest-freshness.py >/dev/null || die "the freshness gate refuses this tree; the release workflow would refuse it too"
ok "freshness gate green"

# ---------------------------------------------------------------- the irreversible part
step "about to cut $VERSION at $(git rev-parse --short HEAD)"
cat <<EOF
   Everything above passed. The next two steps cannot be undone:
     git tag -s $VERSION -m "kern $VERSION"     (asks for the GPG passphrase)
     git push origin $VERSION                   (starts the Release workflow)
EOF
printf '   type the version again to confirm: '
read -r confirm
[ "$confirm" = "$VERSION" ] || die "not confirmed; nothing was tagged"

git tag -s "$VERSION" -m "kern $VERSION" || die "signing the tag failed; nothing was pushed"
ok "signed tag created"
git push origin "$VERSION" || die "pushing the tag failed. The tag exists LOCALLY: delete it with 'git tag -d $VERSION' and start over, or push it by hand once the reason is fixed."
ok "tag pushed; the Release workflow is building"

# ---------------------------------------------------------------- what is left, and it is not nothing
step "what is left for you"
cat <<EOF
   1. Watch the Release workflow. It must attach FOUR Linux/Windows binaries plus their checksums;
      v0.9.31 published with the Windows half only and nobody noticed until an install failed.

   2. VERIFY BY DOWNLOADING, not by reading the page:
        curl -sL https://github.com/getkern/kern/releases/download/$VERSION/kern-x86_64-unknown-linux-musl.tar.gz | tar xz -O kern | wc -c
        ./kern --version     # must print $VERSION, not a -dirty or a -N-g suffix

   3. THE DOCUMENTATION'S OWN COMMANDS, run the way a reader runs them:
        python3 scripts/readme-blocks.py target/release/kern
      It executes the shell blocks of README/INSTALL/MCP in order, carrying state, with HOME inside
      a temporary tree so it cannot touch this machine. It found two blocks that could not work with
      the file printed right above them, the day it was written. Its own control:
        python3 scripts/readme-blocks.py target/release/kern /dev/stdin <<'EOF'
        \`\`\`sh
        kern compose does-not-exist.yml up
        \`\`\`
        EOF
      must exit 1.

   4. WHAT \`install.sh\` ACTUALLY SERVES, which is a different question from step 2. The installer
      follows \`releases/latest\`, and \`latest\` skips a release marked PRE-RELEASE: mark this one by
      mistake and every reader keeps getting the previous binary, with a checksum that verifies,
      because the old \`.sha256\` is the one they fetch too. Nothing about that looks wrong.

        curl -sI https://github.com/getkern/kern/releases/latest | grep -i '^location:'   # must name $VERSION
        # then, on a machine that has never had kern:
        curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
        kern --version    # must print $VERSION

      Do this BEFORE announcing anywhere. A post that describes a version the install line does not
      deliver is the one launch failure no amount of testing prevents.

   5. Provenance, which is NOT automatic:
        sh provenance/make-provenance.sh $VERSION
        git add provenance/$VERSION.provenance.txt provenance/$VERSION.provenance.txt.ots
        git commit -m 'chore(provenance): anchor $VERSION' && git push origin main
      It is born PENDING. Hours later, once a BTC block confirms:
        sh provenance/upgrade-when-ready.sh $VERSION
EOF
