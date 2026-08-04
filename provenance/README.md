# Provenance

Independent, third-party proof of *when* each kern release was created, anchored to the
Bitcoin blockchain via [OpenTimestamps](https://opentimestamps.org).

Each release has two files:

- `vX.Y.Z.provenance.txt`, names the GPG-signed git **tag object** hash and the release **commit** hash.
- `vX.Y.Z.provenance.txt.ots`, an OpenTimestamps proof that the `.txt` above existed at a point in
  time recorded in a Bitcoin block. Multiple independent calendar servers attest to the same fact.

Together they let anyone prove the release existed at a given time, no trust in this repo, GitHub,
or the author required.

> **Scope:** proofs are kept only for tags that exist in *this* repository, **v0.6.5** onward, with
> one exception: **v0.6.8 has no proof**, and stamping it now would attest to now rather than to its
> release, so the gap is left where it is instead of being filled with a later date. The pre-launch
> development history was reorganized before the public release, so earlier internal tags (and their
> old anchors) are not published here: a proof that names a tag you can't resolve would be
> unverifiable, and this directory only carries what you can check end-to-end.

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
ots info provenance/v0.6.29.provenance.txt.ots   # BitcoinBlockHeaderAttestation(<height>) + merkle root
sha256sum provenance/v0.6.29.provenance.txt      # the hash the block attests to
```

Cross-check each reported block height and merkle root on any block explorer. A release is normally
anchored in more than one block, because several independent calendars submit it; two calendars
landing in the same block is normal and is not a missing anchor. Freshly stamped releases show only
`PendingAttestation` until a block confirms, a few hours later.

**Full verification** needs a local Bitcoin node:

```sh
ots verify provenance/v0.6.29.provenance.txt.ots
```

Without one it stops with `Could not connect to Bitcoin node`. That is not a failed proof, it is a
missing verifier: `ots` reads the block header from your own node precisely so that it does not have
to trust anybody's block explorer. If you do not run a node, use the `ots info` route above.

## Cross-check the tag

```sh
git verify-tag v0.6.7          # GPG signature on the tag
git rev-parse v0.6.7^{}        # must equal the commit hash in the .txt
```
