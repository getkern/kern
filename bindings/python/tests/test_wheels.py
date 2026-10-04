"""The Linux wheels carry kern, and the SDK takes that kern and no other one by accident.

Two halves. `build-wheels.py` must produce a wheel pip installs as-is: the binary as an executable
script, the platform tags a static binary can honour, and a RECORD whose every hash matches. And
`_bundled_kern` must find the binary THROUGH THE PACKAGE'S RECORD, because the place pip puts it can
also hold a kern installed by hand (`~/.local/bin`, where `install.sh` writes), and taking that one
by position is the stale-binary trap `conftest.py` documents.

The install half builds a real venv and installs a wheel made from this source tree with pip, offline.
The binary inside it is a shell script that answers `--version` like kern, so the test needs no
network and no release, and says nothing about kern itself: that is the integration suite's job.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("build_wheels", HERE / "build-wheels.py")
build_wheels = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_wheels)

VERSION = "0.0.0"
STEM = f"kern_sandbox-{VERSION}"
ARCH = "x86_64" if os.uname().machine == "x86_64" else "aarch64"


def _elf(machine: int, interp: bool = False) -> bytes:
    """A 64-bit little-endian ELF header with one program header, PT_INTERP if asked, else PT_LOAD."""
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4], header[5], header[6] = 2, 1, 1
    header[18:20] = machine.to_bytes(2, "little")
    header[32:40] = (64).to_bytes(8, "little")  # e_phoff: right after this header
    header[54:56] = (56).to_bytes(2, "little")  # e_phentsize
    header[56:58] = (1).to_bytes(2, "little")  # e_phnum
    phdr = bytearray(56)
    phdr[:4] = (3 if interp else 1).to_bytes(4, "little")
    return bytes(header + phdr)


def _universal_wheel(dest: Path) -> Path:
    """A universal wheel of THIS source tree's package, as the build backend would lay it out."""
    wheel = dest / f"{STEM}-py3-none-any.whl"
    dist_info = f"{STEM}.dist-info"
    files = {
        f"kern_sandbox/{p.name}": p.read_bytes() for p in sorted((HERE / "kern_sandbox").glob("*.py"))
    }
    files[f"{dist_info}/METADATA"] = f"Metadata-Version: 2.1\nName: kern-sandbox\nVersion: {VERSION}\n".encode()
    files[f"{dist_info}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    rows = [build_wheels.record_line(name, data) for name, data in files.items()]
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows(rows + [[f"{dist_info}/RECORD", "", ""]])
    files[f"{dist_info}/RECORD"] = buf.getvalue().encode()
    with zipfile.ZipFile(wheel, "w") as z:
        for name, data in files.items():
            z.writestr(zipfile.ZipInfo(name, date_time=(2020, 2, 2, 0, 0, 0)), data)
    return wheel


FAKE_KERN = b"#!/bin/sh\n[ \"$1\" = --version ] && echo 'kern 9.9.9-bundled' && exit 0\nexit 1\n"


def test_the_platform_wheel_carries_kern_as_an_executable_script_with_a_true_record(tmp_path):
    binary = _elf(0x3E)
    wheel = build_wheels.platform_wheel(_universal_wheel(tmp_path), "x86_64", binary)
    assert wheel.name == (
        f"{STEM}-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.musllinux_1_1_x86_64.whl"
    )
    with zipfile.ZipFile(wheel) as z:
        script = z.getinfo(f"{STEM}.data/scripts/kern")
        assert z.read(script) == binary
        assert (script.external_attr >> 16) & 0o777 == 0o755
        tags = [l for l in z.read(f"{STEM}.dist-info/WHEEL").decode().splitlines() if l.startswith("Tag:")]
        assert tags == [
            "Tag: py3-none-manylinux_2_17_x86_64",
            "Tag: py3-none-manylinux2014_x86_64",
            "Tag: py3-none-musllinux_1_1_x86_64",
        ]
        rows = list(csv.reader(io.StringIO(z.read(f"{STEM}.dist-info/RECORD").decode())))
        listed = {row[0] for row in rows}
        assert listed == set(z.namelist()), "RECORD must list every file in the wheel, and only those"
        for path, digest, size in rows:
            if path.endswith("RECORD"):
                assert (digest, size) == ("", "")
                continue
            data = z.read(path)
            want = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            assert (digest, size) == (f"sha256={want}", str(len(data))), path


@pytest.mark.parametrize(
    "data, machine, reason",
    [
        (_elf(0xB7), 0x3E, "ELF machine"),  # an aarch64 binary in an x86_64 wheel
        (_elf(0x3E, interp=True), 0x3E, "program interpreter"),  # dynamic: cannot claim musllinux
        (b"#!/bin/sh\n", 0x3E, "not a 64-bit"),
    ],
)
def test_a_binary_the_wheel_cannot_honour_is_refused(data, machine, reason):
    with pytest.raises(SystemExit, match=reason):
        build_wheels.check_elf(data, machine, "kern under test")
    build_wheels.check_elf(_elf(machine), machine, "kern under test")  # and the right one passes


def _make_venv(env_dir: Path) -> Path:
    """A venv with pip, made from the REAL interpreter. Inside a venv, Python 3.9 reports the venv's
    own `python` as `sys._base_executable`, so `venv.EnvBuilder` there links a symlink to a symlink,
    and a relocatable build (uv's) then cannot find its standard library: measured, `No module named
    'encodings'`. The resolved path is the interpreter itself on every version."""
    base = os.path.realpath(getattr(sys, "_base_executable", "") or sys.executable)
    # A HOST THAT CANNOT MAKE A VENV WITH PIP is a host capability, asked of the interpreter on its
    # own and not inferred from the venv failing. MEASURED on Ubuntu 24.04 as root without
    # `python3-venv`: `python3 -m venv` exits 1 because `ensurepip` is absent, and these tests ERRORED
    # there - three at setup and one failed - over a missing package and not over a wheel.
    if subprocess.run([base, "-m", "ensurepip", "--version"], capture_output=True).returncode != 0:
        pytest.skip(f"{base} has no ensurepip, so it cannot make a venv with pip "
                    "(Debian/Ubuntu: the python3-venv package)")
    subprocess.run([base, "-m", "venv", str(env_dir)], check=True)
    return env_dir / "bin" / "python"


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    """A venv with this package's platform wheel installed by pip, offline, and its python and bin."""
    root = tmp_path_factory.mktemp("wheel-install")
    wheel = build_wheels.platform_wheel(_universal_wheel(root), ARCH, FAKE_KERN)
    env_dir = root / "venv"
    python = _make_venv(env_dir)
    subprocess.run([python, "-m", "pip", "install", "-q", "--no-index", str(wheel)], check=True)
    return python, env_dir / "bin"


def _ask(python: Path, code: str, **env: str) -> str:
    base = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/tmp")}
    out = subprocess.run(
        [python, "-c", code], capture_output=True, text=True, env={**base, **env}, cwd="/", check=True
    )
    return out.stdout.strip()


FIND = "import kern_sandbox as k; print(k._find_kern())"


def test_the_sdk_takes_the_kern_its_wheel_installed(installed):
    python, bindir = installed
    assert os.access(bindir / "kern", os.X_OK), "pip must install the script as an executable"
    assert _ask(python, "import kern_sandbox as k; print(k._bundled_kern())") == str(bindir / "kern")
    assert _ask(python, FIND) == str(bindir / "kern")


def test_the_bundled_kern_beats_an_older_one_on_path_and_kern_bin_beats_both(installed, tmp_path):
    python, bindir = installed
    old = tmp_path / "old"
    old.mkdir()
    (old / "kern").write_bytes(b"#!/bin/sh\necho 'kern 0.9.2'\n")
    (old / "kern").chmod(0o755)
    path = f"{old}:/usr/bin:/bin"
    assert _ask(python, FIND, PATH=path) == str(bindir / "kern")
    assert _ask(python, FIND, PATH=path, KERN_BIN=str(old / "kern")) == str(old / "kern")


def test_a_kern_dropped_next_to_python_by_hand_is_not_taken_for_the_bundled_one(tmp_path):
    """The universal wheel installs no binary. A `kern` sitting in the same `bin` anyway (put there by
    hand, or by `install.sh` when that `bin` is `~/.local/bin`) is not in this package's RECORD, so it
    is not "the bundled kern": the SDK falls through to PATH, where the user decides what runs."""
    wheel = _universal_wheel(tmp_path)
    env_dir = tmp_path / "venv"
    python = _make_venv(env_dir)
    subprocess.run([python, "-m", "pip", "install", "-q", "--no-index", str(wheel)], check=True)
    stray = env_dir / "bin" / "kern"
    stray.write_bytes(FAKE_KERN)
    stray.chmod(0o755)
    assert _ask(python, "import kern_sandbox as k; print(k._bundled_kern())") == "None"


def test_pip_target_takes_the_wheels_own_kern_and_not_the_one_its_record_points_at(tmp_path):
    """`pip install --target DIR` writes the RECORD from the temporary prefix it installs into: the
    script's entry reads `../../bin/kern`, two levels ABOVE `DIR`, while the file lands in
    `DIR/bin/kern`. A different kern sitting where the RECORD points must not be taken for the
    wheel's own, and the wheel's own must still be found."""
    wheel = build_wheels.platform_wheel(_universal_wheel(tmp_path), ARCH, FAKE_KERN)
    python = _make_venv(tmp_path / "venv")
    site = tmp_path / "a" / "b" / "site"
    subprocess.run(
        [python, "-m", "pip", "install", "-q", "--no-index", "--target", str(site), str(wheel)], check=True
    )
    record = (site / f"{STEM}.dist-info" / "RECORD").read_text()
    listed = next(row[0] for row in csv.reader(io.StringIO(record)) if row[0].endswith("bin/kern"))
    decoy = Path(os.path.normpath(site / listed))
    if decoy != site / "bin" / "kern":  # this pip writes the misleading entry: plant a kern there,
        decoy.parent.mkdir(parents=True, exist_ok=True)  # the same size, so only the hash tells them apart
        decoy.write_bytes(FAKE_KERN.replace(b"9.9.9", b"0.9.2"))
        decoy.chmod(0o755)
    code = "import kern_sandbox as k; print(k._bundled_kern()); print(k._find_kern())"
    assert _ask(python, code, PYTHONPATH=str(site)).splitlines() == [str(site / "bin" / "kern")] * 2


def test_a_bundled_kern_whose_bytes_are_not_the_records_is_not_taken(tmp_path):
    """Being where the RECORD says is not being what the RECORD says: a kern replaced in place (by
    hand, by `install.sh` writing into a shared `bin`) is passed over, and PATH decides."""
    wheel = build_wheels.platform_wheel(_universal_wheel(tmp_path), ARCH, FAKE_KERN)
    env_dir = tmp_path / "venv"
    python = _make_venv(env_dir)
    subprocess.run([python, "-m", "pip", "install", "-q", "--no-index", str(wheel)], check=True)
    # POSITIVE CONTROL: the untouched copy is taken, so the None below is the replacement's doing.
    assert _ask(python, "import kern_sandbox as k; print(k._bundled_kern())") == str(env_dir / "bin" / "kern")
    (env_dir / "bin" / "kern").write_bytes(FAKE_KERN.replace(b"9.9.9", b"9.9.8"))  # same size
    assert _ask(python, "import kern_sandbox as k; print(k._bundled_kern())") == "None"


def test_a_source_tree_on_sys_path_never_borrows_an_installed_copys_binary(installed):
    """`_bundled_kern` answers for the module that is running. Importing this source tree with an
    installed platform wheel in the same environment must not hand the tree that wheel's binary."""
    python, _ = installed
    code = f"import sys; sys.path.insert(0, {str(HERE)!r}); import kern_sandbox as k; print(k.__file__); print(k._bundled_kern())"
    where, bundled = _ask(python, code).splitlines()
    assert where.startswith(str(HERE))
    assert bundled == "None"
