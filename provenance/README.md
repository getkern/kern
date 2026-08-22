# Provenance

Independent, third-party proof of *when* the kern release was created, anchored to the Bitcoin
blockchain via [OpenTimestamps](https://opentimestamps.org). One release, one record:

- `v0.7.0.provenance.txt`, naming the GPG-signed git **tag object** hash and the release **commit**
  hash.
- `v0.7.0.provenance.txt.ots`, an OpenTimestamps proof that the `.txt` above existed at a point in
  time recorded in a Bitcoin block. Several independent calendar servers attest to the same fact.

Together they let anyone prove the release existed at a given time, with no trust in this repo, in
GitHub, or in the author.

> **The record appears with the tag, not before it.** `v0.7.0` is the first public release; the
> pre-launch history was reorganized before it, its tags are not in this repository, and the 29
> proofs that named them were removed rather than kept: a proof that names a tag you cannot resolve
> proves nothing you can check, and a directory of those is worse than an empty one. What is here is
> what you can verify end to end.

## Verify

**Installing the client.** On Debian 12+, Ubuntu 23.04+ and anything else following PEP 668, a bare
`pip install` is refused with `externally-managed-environment`. Use one of:

```sh
pipx install opentimestamps-client                       # if you have pipx
# or a throwaway venv:
python3 -m venv ~/.venv-ots && ~/.venv-ots/bin/pip install opentimestamps-client
~/.venv-ots/bin/ots --version
```

> **Do not `apt install ots`.** When the `ots` command is missing, the shell helpfully suggests that
> package. It is a **different program** (Open Text Summarizer, `section: universe/text`), and it will
> not read these files. The apt package that IS related, `python3-opentimestamps`, is the library, not
> the `ots` command-line client.

**Reading the proof, no node required.** This is the check most people want:

```sh
ots info provenance/v0.7.0.provenance.txt.ots   # BitcoinBlockHeaderAttestation(<height>) + merkle root
sha256sum provenance/v0.7.0.provenance.txt      # the hash the block attests to
```

Cross-check each reported block height and merkle root on any block explorer. A release is normally
anchored in more than one block, because several independent calendars submit it; two calendars
landing in the same block is normal and is not a missing anchor. A freshly stamped release shows only
`PendingAttestation` until a block confirms, a few hours later.

**Full verification** needs a local Bitcoin node:

```sh
ots verify provenance/v0.7.0.provenance.txt.ots
```

Without one it stops with `Could not connect to Bitcoin node`. That is not a failed proof, it is a
missing verifier: `ots` reads the block header from your own node precisely so that it does not have
to trust anybody's block explorer. If you do not run a node, use the `ots info` route above.

## Cross-check the tag

```sh
git verify-tag v0.7.0          # GPG signature on the tag
git rev-parse v0.7.0^{}        # must equal the commit hash in the .txt
```

The signing key ships next to this file, and [SECURITY.md](../SECURITY.md) carries the fingerprint
to compare it against:

```sh
gpg --import provenance/getkerndev-signing-key.asc
```

## Producing the record

For whoever cuts the release, after `git tag -s v0.7.0 && git push origin v0.7.0`:

```sh
sh provenance/make-provenance.sh v0.7.0        # writes the .txt and stamps it (PendingAttestation)
git add provenance/v0.7.0.provenance.txt provenance/v0.7.0.provenance.txt.ots
git commit -m 'chore(provenance): anchor v0.7.0' && git push origin main
# hours later, once a Bitcoin block carries it:
sh provenance/upgrade-when-ready.sh v0.7.0     # safe to re-run; commits only if the anchor arrived
```

`make-provenance.sh` refuses a tag that does not exist or is not GPG-signed, so the record cannot
claim more than the tag does.
