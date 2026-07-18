# Provenance

Independent, third-party proof of *when* each kern release was created — anchored to the
Bitcoin blockchain via [OpenTimestamps](https://opentimestamps.org).

Each release has two files:

- `vX.Y.Z.provenance.txt` — names the GPG-signed git **tag object** hash and the release **commit** hash.
- `vX.Y.Z.provenance.txt.ots` — an OpenTimestamps proof that the `.txt` above existed at a point in
  time recorded in a Bitcoin block. Multiple independent calendar servers attest to the same fact.

Together they let anyone prove the release existed at a given time — no trust in this repo, GitHub,
or the author required.

> **Scope:** proofs are kept only for tags that exist in *this* repository — currently **v0.6.5**
> onward. The pre-launch development history was reorganized before the public release, so earlier
> internal tags (and their old anchors) are not published here: a proof that names a tag you can't
> resolve would be unverifiable, and this directory only carries what you can check end-to-end.

## Verify

```sh
pip install opentimestamps-client        # provides `ots`
ots verify provenance/v0.6.5.provenance.txt.ots
```

`ots verify` confirms the `.txt` against the Bitcoin block it is anchored to (a local or public
Bitcoin node is used to read the block header time). You can also inspect the raw attestation
without a node:

```sh
ots info provenance/v0.6.5.provenance.txt.ots   # shows BitcoinBlockHeaderAttestation(<block height>)
```

Cross-check the reported block height and merkle root on any block explorer.

## Cross-check the tag

```sh
git verify-tag v0.6.5          # GPG signature on the tag
git rev-parse v0.6.5^{}        # must equal the commit hash in the .txt
```
