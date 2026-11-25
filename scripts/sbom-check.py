#!/usr/bin/env python3
"""The release SBOM can be built for this tree, and what it says passes the license rule.

WHY THIS EXISTS
    `scripts/sbom.py` runs in the release pipeline, where a failure is found on the tag. This gate
    runs the same code on every change, without a release build: it reads the graph each published
    binary links (`getkern` for both musl targets, `kern-win` for kern.exe), refuses a crate linked
    into kern under a license outside `sbom.ALLOWED_LICENSES` or a build-only crate with no license
    at all, and assembles a document from stand-in assets to check that it is one a reader can rely
    on (ids unique and resolvable). A dependency that would stop the release stops the change that
    brings it instead.

Usage:  python3 scripts/sbom-check.py
Exit:   0 the SBOM can be built and passes, 1 otherwise (the reason is printed).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sbom  # noqa: E402

BINARIES = [
    ("getkern", "x86_64-unknown-linux-musl", None),
    ("getkern", "aarch64-unknown-linux-musl", None),
    ("kern-win", "x86_64-pc-windows-gnu", "windows/kern-win/Cargo.toml"),
]


def main() -> int:
    try:
        with tempfile.TemporaryDirectory(prefix="kern-sbom-check-") as tmp:
            tmp_p = Path(tmp)
            inputs, assets = tmp_p / "in", tmp_p / "assets"
            inputs.mkdir()
            assets.mkdir()
            for package, target, manifest in BINARIES:
                args = argparse.Namespace(
                    package=package, target=target, manifest_path=manifest, toolchain=None,
                    target_dir=None, binary=None, build_std=False, lenient_runtime=True,
                )
                d = sbom.collect(args)
                for c in d["crates"]:
                    if not c["linked"] and c["license"] == "NOASSERTION":
                        raise sbom.SbomError(f"{c['key']} (built for {target}) declares no license")
                linked = sum(c["linked"] for c in d["crates"])
                # A stand-in asset per binary, so the document is assembled the way the release
                # assembles it; its bytes are not the binary's, and nothing here claims they are.
                name = sbom.ASSET_OF_TARGET[target]
                (assets / name).write_bytes(f"stand-in for {name}\n".encode())
                digest = hashlib.sha256((assets / name).read_bytes()).hexdigest()
                (assets / f"{name}.sha256").write_text(f"{digest}  {name}\n")
                (inputs / f"{target}.json").write_text(json.dumps(d))
                print(f"  {package} for {target}: {linked} crates linked, "
                      f"{len(d['crates']) - linked} build-only")
            doc = sbom.assemble("v0.0.0", assets, inputs, "1970-01-01T00:00:00Z")
            print(f"  document: {len(doc['packages'])} packages, "
                  f"{len(doc['relationships'])} relationships")
    except sbom.SbomError as e:
        print(f"sbom-check: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
