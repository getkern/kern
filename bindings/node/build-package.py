#!/usr/bin/env python3
"""Build kern-sandbox's npm tarball with kern inside, for Linux x64 and arm64.

WHY. `npm install kern-sandbox` installed a wrapper around a binary it did not ship, so on every
machine the install was two steps, which the Python package stopped being at 0.2.41. The tarball now
carries kern's static release binary under `bin/linux-<arch>/kern`, and the binding takes that copy
after `$KERN_BIN` and before PATH (`bundledKern` in index.js).

ONE PACKAGE WITH BOTH BINARIES, NOT A PACKAGE PER PLATFORM. The `optionalDependencies` layout ships
one package per platform and lets npm install the matching one. Two reasons not to here: a lockfile
written on a Mac omits the Linux package, so `npm ci` in a Linux container installs no kern at all;
and every platform package is a new name on a registry where a published version cannot be
withdrawn. The cost is that an install downloads the other architecture's binary too.

WHAT GOES IN IS THE RELEASE, NOT A LOCAL BUILD, through the same checks as the wheels, imported from
`build-wheels.py` so there is one spelling of them: the tarball from the GitHub release checked
against its published `.sha256`, an ELF for the right machine with no program interpreter, and where
the host can run it, `--version` answering the tag asked for. A wheel user, an npm user and an
`install.sh` user run byte-identical kern.

THE SOURCE TREE IS NOT TOUCHED. The package is staged in a temporary directory and packed there, so a
checkout never carries a `bin/` and the tests keep driving the kern they were pointed at. After
packing, the tarball is read back and each binary in it must be the verified bytes, mode 0755.

    python3 build-package.py --kern-version v0.30.0             # writes dist/ next to this file
    python3 build-package.py --kern-version v0.30.0 --assets D  # offline: tarballs + .sha256 from D

Publishing is a separate, authorised step: `npm publish dist/kern-sandbox-<version>.tgz`.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "build_wheels", HERE.parent / "python" / "build-wheels.py"
)
build_wheels = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_wheels)

# The machine names the release uses -> the ones Node reports as `process.arch`.
NODE_ARCH = {"x86_64": "x64", "aarch64": "arm64"}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--kern-version", required=True, help="the kern release tag to ship, e.g. v0.30.0")
    ap.add_argument("--assets", type=Path, help="directory holding the release tarballs and .sha256")
    ap.add_argument("--out", type=Path, default=HERE / "dist")
    args = ap.parse_args()
    tag = args.kern_version if args.kern_version.startswith("v") else f"v{args.kern_version}"

    manifest = json.loads((HERE / "package.json").read_text())
    binaries = {}
    for arch, (triple, machine) in build_wheels.TARGETS.items():
        binary = build_wheels.release_binary(tag, triple, args.assets)
        what = f"kern {tag} {triple}"
        build_wheels.check_elf(binary, machine, what)
        if platform.machine() == arch:
            build_wheels.check_runs(binary, tag, what)
        binaries[f"package/bin/linux-{NODE_ARCH[arch]}/kern"] = binary

    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as d:
        stage = Path(d) / "kern-sandbox"
        stage.mkdir()
        shutil.copy2(HERE / "package.json", stage / "package.json")
        for entry in manifest["files"]:
            if entry.rstrip("/") == "bin":
                continue
            shutil.copy2(HERE / entry, stage / entry)
        for member, binary in binaries.items():
            exe = stage / member.removeprefix("package/")
            exe.parent.mkdir(parents=True, exist_ok=True)
            exe.write_bytes(binary)
            exe.chmod(0o755)
        out = subprocess.run(
            ["npm", "pack", "--json", "--pack-destination", str(args.out.resolve())],
            cwd=stage, check=True, capture_output=True, text=True,
        )
        tarball = args.out.resolve() / json.loads(out.stdout)[0]["filename"]

    # READ BACK WHAT WAS PACKED: what is published is this file, not the directory it came from.
    with tarfile.open(tarball, "r:gz") as tar:
        names = set(tar.getnames())
        for member, binary in binaries.items():
            info = tar.getmember(member)
            if info.mode & 0o777 != 0o755:
                sys.exit(f"{tarball.name}: {member} has mode {info.mode & 0o777:o}, expected 755")
            if tar.extractfile(info).read() != binary:
                sys.exit(f"{tarball.name}: {member} is not the verified kern {tag}")
    want = {f"package/{f}" for f in manifest["files"] if not f.endswith("/")} | set(binaries)
    if missing := sorted(want - names):
        sys.exit(f"{tarball.name}: missing {missing}")
    print(f"{tarball.name}  sha256 {hashlib.sha256(tarball.read_bytes()).hexdigest()}")
    for name in sorted(names):
        print(f"  {name}")


if __name__ == "__main__":
    main()
