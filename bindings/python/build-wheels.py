#!/usr/bin/env python3
"""Build kern-sandbox's wheels: the universal one, and one per Linux architecture with kern inside.

WHY. `pip install kern-sandbox` used to install a wrapper around a binary it did not ship, so the
install was two steps on every machine. The Linux wheels carry kern's static release binary as a
script, the way ruff and uv ship theirs: pip puts `kern` in the environment's `bin` next to `python`,
and the SDK finds it through the package's own RECORD (`_bundled_kern`). The universal wheel stays,
unchanged, for every platform with no Linux wheel: macOS, other architectures, a pip too old to pick
one. pip prefers a matching platform wheel over `any` by itself.

WHAT GOES IN IS THE RELEASE, NOT A LOCAL BUILD. The binary is the one `install.sh` serves for the same
tag, taken from the GitHub release and checked against the `.sha256` published beside it, so a wheel
user and an `install.sh` user run byte-identical kern. Before it is packed it must be an ELF for the
right machine with no program interpreter (static: the wheel claims every glibc and musl Linux, which
only a binary that needs no loader can honour), and where the host can run it, it must answer
`--version` with the tag asked for.

NOTHING IS DOWNLOADED AT INSTALL OR AT RUN TIME. The network is touched here, by whoever builds, and
never by a user's first `run_code`.

    python3 build-wheels.py --kern-version v0.25.0             # writes dist/ next to this file
    python3 build-wheels.py --kern-version v0.25.0 --assets D  # offline: tarballs + .sha256 from D

Publishing is a separate, authorised step: this only builds.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import platform
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
RELEASES = "https://github.com/getkern/kern/releases/download"

# Architecture -> (release target triple, ELF e_machine). The platform tags are the ones a static
# binary can honour: manylinux2014 (pip 19.3+) with its PEP 600 spelling (pip 20.3+), and musllinux
# (pip 21.2+) so Alpine picks it too.
TARGETS = {
    "x86_64": ("x86_64-unknown-linux-musl", 0x3E),
    "aarch64": ("aarch64-unknown-linux-musl", 0xB7),
}
PT_INTERP = 3


def platform_tags(arch: str) -> list[str]:
    return [f"manylinux_2_17_{arch}", f"manylinux2014_{arch}", f"musllinux_1_1_{arch}"]


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 - fixed https host
        return r.read()


def release_binary(tag: str, triple: str, assets: Path | None) -> bytes:
    """kern from the release tarball for `triple`, after checking the tarball against its `.sha256`."""
    name = f"kern-{triple}.tar.gz"
    if assets:
        tarball, digest_file = (assets / name).read_bytes(), (assets / f"{name}.sha256").read_text()
    else:
        tarball = fetch(f"{RELEASES}/{tag}/{name}")
        digest_file = fetch(f"{RELEASES}/{tag}/{name}.sha256").decode()
    want = digest_file.split()[0]
    got = hashlib.sha256(tarball).hexdigest()
    if got != want:
        sys.exit(f"{name}: sha256 {got} does not match the published {want}")
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tar:
        member = tar.getmember("kern")
        if not member.isfile():
            sys.exit(f"{name}: `kern` in the tarball is not a regular file")
        return tar.extractfile(member).read()


def check_elf(data: bytes, machine: int, what: str) -> None:
    """A 64-bit little-endian ELF for `machine` with no PT_INTERP, or exit with the reason."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        sys.exit(f"{what}: not a 64-bit little-endian ELF")
    got = int.from_bytes(data[18:20], "little")
    if got != machine:
        sys.exit(f"{what}: ELF machine {got:#x}, expected {machine:#x}")
    phoff = int.from_bytes(data[32:40], "little")
    phentsize = int.from_bytes(data[54:56], "little")
    phnum = int.from_bytes(data[56:58], "little")
    for i in range(phnum):
        off = phoff + i * phentsize
        if int.from_bytes(data[off:off + 4], "little") == PT_INTERP:
            sys.exit(f"{what}: has a program interpreter, so it is not static and cannot claim musllinux")


def check_runs(binary: bytes, tag: str, what: str) -> None:
    """Where the host can execute it, the binary must say it is kern `tag`."""
    with tempfile.TemporaryDirectory() as d:
        exe = Path(d) / "kern"
        exe.write_bytes(binary)
        exe.chmod(0o755)
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30)
    first = (out.stdout.strip().splitlines() or [""])[0]
    if out.returncode != 0 or not first.startswith(f"kern {tag.lstrip('v')}"):
        sys.exit(f"{what}: `kern --version` printed {first!r}, expected kern {tag.lstrip('v')}")
    print(f"  {what}: runs here, {first}")


def record_line(path: str, data: bytes) -> list[str]:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return [path, f"sha256={digest}", str(len(data))]


def platform_wheel(universal: Path, arch: str, binary: bytes) -> Path:
    """The universal wheel plus `<name>.data/scripts/kern`, re-tagged for `arch` with a fresh RECORD."""
    stem = universal.name[: -len("-py3-none-any.whl")]  # kern_sandbox-0.2.41
    tags = platform_tags(arch)
    out = universal.with_name(f"{stem}-py3-none-{'.'.join(tags)}.whl")
    dist_info = f"{stem}.dist-info"
    records = []
    with zipfile.ZipFile(universal) as src, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        stamp = src.infolist()[0].date_time  # the backend's reproducible timestamp, kept
        for info in src.infolist():
            if info.filename in (f"{dist_info}/RECORD", f"{dist_info}/WHEEL"):
                continue
            data = src.read(info)
            dst.writestr(info, data)
            records.append(record_line(info.filename, data))
        script = zipfile.ZipInfo(f"{stem}.data/scripts/kern", date_time=stamp)
        script.external_attr = 0o100755 << 16
        script.compress_type = zipfile.ZIP_DEFLATED
        dst.writestr(script, binary)
        records.append(record_line(script.filename, binary))
        wheel_lines = [
            line for line in src.read(f"{dist_info}/WHEEL").decode().splitlines()
            if line and not line.startswith("Tag:")
        ]
        wheel = ("\n".join(wheel_lines + [f"Tag: py3-none-{t}" for t in tags]) + "\n").encode()
        dst.writestr(zipfile.ZipInfo(f"{dist_info}/WHEEL", date_time=stamp), wheel)
        records.append(record_line(f"{dist_info}/WHEEL", wheel))
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerows(records + [[f"{dist_info}/RECORD", "", ""]])
        dst.writestr(zipfile.ZipInfo(f"{dist_info}/RECORD", date_time=stamp), buf.getvalue())
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--kern-version", required=True, help="the kern release tag to ship, e.g. v0.25.0")
    ap.add_argument("--assets", type=Path, help="directory holding the release tarballs and .sha256")
    ap.add_argument("--out", type=Path, default=HERE / "dist")
    args = ap.parse_args()
    tag = args.kern_version if args.kern_version.startswith("v") else f"v{args.kern_version}"

    args.out.mkdir(parents=True, exist_ok=True)
    before = set(args.out.glob("*"))
    subprocess.run(["uv", "build", "--out-dir", str(args.out), str(HERE)], check=True)
    built = set(args.out.glob("*")) - before
    universal = [p for p in built if p.name.endswith("-py3-none-any.whl")]
    if len(universal) != 1:
        sys.exit(f"expected one new universal wheel in {args.out}, found {[p.name for p in built]}")
    print(f"universal: {universal[0].name}")

    for arch, (triple, machine) in TARGETS.items():
        binary = release_binary(tag, triple, args.assets)
        what = f"kern {tag} {triple}"
        check_elf(binary, machine, what)
        if platform.machine() == arch:
            check_runs(binary, tag, what)
        wheel = platform_wheel(universal[0], arch, binary)
        print(f"{arch}: {wheel.name}  sha256 {hashlib.sha256(wheel.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
