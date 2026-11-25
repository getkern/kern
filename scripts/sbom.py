#!/usr/bin/env python3
"""The release's SBOM: what each published file contains, in SPDX 2.3, signed with the rest.

WHY THIS EXISTS
    The release used to attach an SBOM that Syft made by scanning the CHECKOUT. MEASURED on
    v0.56.0: 68 entries, among them the workflow's own actions and crates the binary never links,
    while the WSL rootfs's Alpine packages, the Rust standard library the release rebuilds
    (`-Z build-std`) and the musl it links statically were not there at all; 3 entries declared a
    license; and it was the one asset on the release with no signature. An SBOM that lists what
    the source tree mentions answers a question nobody asked.

    This one is built from what each build COMPILED, read two ways that must agree:
      - the resolver: `cargo tree -p <package> --target <t>`, the graph the build resolves, with its
        features (`cargo metadata`'s resolve is NOT that: it lists optional dependencies the build
        never turns on; MEASURED: 44 crates against the 27 the binary links);
      - the build itself: the units cargo fingerprinted under `<target-dir>/<t>/release`, which are
        the ones compiled for the target (build scripts and proc-macros are built for the host,
        under `<target-dir>/release`, and so never appear there).
    A crate in one and not in the other stops the release.

USAGE
    sbom.py collect  --package P --target T [--manifest-path M] [--toolchain TC]
                     [--target-dir D] [--binary FILE] --out F.json
        In a build job, after the build: the graph, the toolchain, the C runtime linked, the binary's
        sha256. Without --target-dir the build check is skipped (the gate has no release build).
    sbom.py rootfs   --tar ROOTFS.tar.gz --out F.json
        The packages of the WSL rootfs, read from its apk database.
    sbom.py assemble --tag vX.Y.Z --assets DIR --inputs DIR --out kern.spdx.json
        Every asset of DIR (each with its .sha256) with what it contains; writes OUT and OUT.sha256.
        Deterministic: the creation time is SOURCE_DATE_EPOCH, or the tag commit's time, so the same
        tag gives the same bytes and anyone can regenerate the file and compare.

Only the Python standard library: this runs in the release pipeline, which takes no new tools.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROJECT_URL = "https://github.com/getkern/kern"

# THE LICENSES A CRATE LINKED INTO kern MAY CARRY. Permissive only: kern ships as one static binary
# under Apache-2.0, so a copyleft crate linked into it changes what the binary is. An expression
# passes when every AND term has an allowed choice (`MIT OR Apache-2.0` needs one, `Apache-2.0 AND
# ISC` needs both). A crate outside this list is a decision, made by editing this list, not a
# warning nobody reads. The Alpine packages of the rootfs are separate programs, not linked into
# kern, and are listed with their own licenses without this check.
ALLOWED_LICENSES = frozenset(
    {
        "0BSD",
        "Apache-2.0",
        "Apache-2.0 WITH LLVM-exception",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSL-1.0",
        "CC0-1.0",
        "ISC",
        "MIT",
        "MIT-0",
        "Unicode-3.0",
        "Unicode-DFS-2016",
        "Unlicense",
        "Zlib",
    }
)


class SbomError(Exception):
    """A fact the SBOM cannot state truthfully: the release must stop, not ship a guess."""


# ------------------------------------------------------------------------------------------------
# License expressions


def normalize_license(expr: str | None) -> str:
    """Cargo's license field as an SPDX expression. The legacy `MIT/Apache-2.0` is `OR`."""
    if not expr or not expr.strip():
        return "NOASSERTION"
    e = expr.strip()
    if "/" in e and " " not in e:
        e = " OR ".join(p.strip() for p in e.split("/"))
    return e


def _tokens(expr: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", expr)


def license_allowed(expr: str) -> bool:
    """Whether the SPDX expression can be satisfied with ALLOWED_LICENSES only."""
    toks = _tokens(expr)
    pos = 0

    def atom() -> bool:
        nonlocal pos
        if pos >= len(toks):
            raise SbomError(f"license expression ends early: {expr!r}")
        t = toks[pos]
        if t == "(":
            pos += 1
            v = disj()
            if pos >= len(toks) or toks[pos] != ")":
                raise SbomError(f"unbalanced license expression: {expr!r}")
            pos += 1
            return v
        if t in (")", "AND", "OR", "WITH"):
            raise SbomError(f"unexpected {t!r} in license expression {expr!r}")
        pos += 1
        if pos < len(toks) and toks[pos] == "WITH":
            if pos + 1 >= len(toks):
                raise SbomError(f"WITH without an exception in {expr!r}")
            t = f"{t} WITH {toks[pos + 1]}"
            pos += 2
        return t in ALLOWED_LICENSES

    def conj() -> bool:
        nonlocal pos
        v = atom()
        while pos < len(toks) and toks[pos] == "AND":
            pos += 1
            v = atom() and v
        return v

    def disj() -> bool:
        nonlocal pos
        v = conj()
        while pos < len(toks) and toks[pos] == "OR":
            pos += 1
            v = conj() or v
        return v

    if expr == "NOASSERTION":
        return False
    v = disj()
    if pos != len(toks):
        raise SbomError(f"trailing tokens in license expression {expr!r}")
    return v


# ------------------------------------------------------------------------------------------------
# collect: the graph a build compiled


def run(cmd: list[str], cwd: Path = REPO) -> str:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        raise SbomError(f"{' '.join(cmd)} failed ({p.returncode}): {p.stderr.strip()[:600]}")
    return p.stdout


TREE_LINE = re.compile(
    r"^(?P<depth>\d+)(?P<name>\S+) v(?P<ver>\S+)(?: \((?P<path>[^)]*)\))?"
    r"\|(?P<lic>[^|]*)\|(?P<repo>.*?)(?P<dup> \(\*\))?$"
)


def cargo_tree(cargo: list[str], package: str, target: str, manifest: Path | None, edges: str):
    """Nodes `{name@ver: {...}}` and edges `{(parent, child)}` of one `cargo tree` run."""
    cmd = cargo + ["tree", "--locked", "-p", package, "--target", target, "-e", edges,
                   "--prefix", "depth", "--format", "{p}|{l}|{r}"]
    if manifest:
        cmd += ["--manifest-path", str(manifest)]
    nodes: dict[str, dict] = {}
    edge_set: set[tuple[str, str]] = set()
    stack: list[str] = []
    for line in run(cmd).splitlines():
        if not line.strip():
            continue
        m = TREE_LINE.match(line)
        if not m:
            raise SbomError(f"cargo tree printed a line this parser does not know: {line!r}")
        depth = int(m["depth"])
        key = f"{m['name']}@{m['ver']}"
        path = m["path"] or ""
        nodes.setdefault(key, {
            "name": m["name"],
            "version": m["ver"],
            "license": normalize_license(m["lic"]),
            "repository": m["repo"].strip(),
            "local": path.startswith("/"),
        })
        del stack[depth:]
        if depth > 0:
            if not stack:
                raise SbomError(f"cargo tree line with no parent: {line!r}")
            edge_set.add((stack[-1], key))
        stack.append(key)
    if not nodes:
        raise SbomError(f"cargo tree printed nothing for {package} on {target}")
    return nodes, edge_set


def proc_macros(cargo: list[str], manifest: Path | None) -> set[str]:
    """`name@version` of every package that is a proc-macro (built for the host, never linked)."""
    cmd = cargo + ["metadata", "--locked", "--format-version", "1"]
    if manifest:
        cmd += ["--manifest-path", str(manifest)]
    meta = json.loads(run(cmd))
    return {
        f"{p['name']}@{p['version']}"
        for p in meta["packages"]
        if any("proc-macro" in t.get("kind", []) for t in p.get("targets", []))
    }


def lock_checksums(lock: Path) -> dict[str, str]:
    """`name@version` -> the sha256 Cargo.lock records for that crate's download."""
    data = tomllib.loads(lock.read_text())
    return {
        f"{p['name']}@{p['version']}": p["checksum"]
        for p in data.get("package", [])
        if p.get("checksum")
    }


def fingerprinted(target_dir: Path, target: str) -> set[str]:
    """Package names cargo compiled FOR THE TARGET in this build (host units live elsewhere).

    Two layouts: cargo's `.fingerprint/` with one entry per unit, and the newer build-dir layout
    (MEASURED on nightly-2026-08-09) with no `.fingerprint/` and one `build/<package>-<hash>/` per
    unit. In the old layout `build/` holds only build-script outputs, so it is read only when
    `.fingerprint/` is absent. A layout this does not know fails the check, it does not pass it."""
    release = target_dir / target / "release"
    fp = release / ".fingerprint"
    units = fp if fp.is_dir() else release / "build"
    if not units.is_dir():
        raise SbomError(f"no release build for {target} under {target_dir} ({release})")
    return {re.sub(r"-[0-9a-f]{16}$", "", e.name) for e in units.iterdir()}


def ar_member(archive: Path, wanted: str) -> bytes | None:
    """One member of a Unix `ar` archive (GNU long names included); None when absent."""
    data = archive.read_bytes()
    if not data.startswith(b"!<arch>\n"):
        raise SbomError(f"{archive} is not an ar archive")
    pos, longnames = 8, b""
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        name = hdr[:16].decode("ascii", "replace").strip()
        size = int(hdr[48:58].decode("ascii").strip() or 0)
        body = data[pos + 60:pos + 60 + size]
        if name == "//":
            longnames = body
        elif name.startswith("/") and name[1:].isdigit() and longnames:
            off = int(name[1:])
            name = longnames[off:longnames.index(b"\n", off)].decode("ascii", "replace")
        name = name.rstrip("/")
        if name == wanted:
            return body
        pos += 60 + size + (size & 1)
    return None


def musl_version(rustc: list[str], target: str) -> str:
    """The musl the toolchain links statically for `target`: its self-contained libc.a carries the
    version string in `version.lo` (what `ldd` prints)."""
    sysroot = Path(run(rustc + ["--print", "sysroot"]).strip())
    libc = sysroot / "lib" / "rustlib" / target / "lib" / "self-contained" / "libc.a"
    if not libc.is_file():
        raise SbomError(f"the toolchain has no self-contained musl for {target}: {libc}")
    member = ar_member(libc, "version.lo")
    # A NUL on BOTH sides: the string table also holds the compiler's own ("GCC: (GNU) 9.4.0",
    # "GNU C99 9.4.0"), which a looser match took for musl's. MEASURED: 1.2.5 and 9.4.0 both found.
    found = set(re.findall(rb"\x00(\d+\.\d+\.\d+)\x00", member or b""))
    if len(found) != 1:
        raise SbomError(f"cannot read musl's version from {libc} (found {sorted(found)})")
    return found.pop().decode()


def dpkg_version(pkg: str) -> str:
    try:
        out = subprocess.run(["dpkg-query", "-W", "-f", "${Version}", pkg],
                             capture_output=True, text=True)
    except OSError:
        return "NOASSERTION"
    return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else "NOASSERTION"


def collect(args) -> dict:
    tc = [f"+{args.toolchain}"] if args.toolchain else []
    cargo, rustc = ["cargo"] + tc, ["rustc"] + tc
    manifest = Path(args.manifest_path).resolve() if args.manifest_path else None
    lock = (manifest.parent if manifest else REPO) / "Cargo.lock"
    normal, n_edges = cargo_tree(cargo, args.package, args.target, manifest, "normal")
    every, a_edges = cargo_tree(cargo, args.package, args.target, manifest, "normal,build")
    macros = proc_macros(cargo, manifest)
    root = next(k for k in normal if normal[k]["name"] == args.package)
    # LINKED: reached from the root through normal edges and never through a proc-macro, whose own
    # dependencies run in the compiler, not in the binary.
    linked: set[str] = set()
    todo = [root]
    while todo:
        k = todo.pop()
        if k in linked or k in macros:
            continue
        linked.add(k)
        todo += [c for (p, c) in n_edges if p == k]
    build_only = set(every) - linked
    std_crates: list[str] = []
    if args.target_dir:
        built = fingerprinted(Path(args.target_dir), args.target)
        resolved = {every[k]["name"] for k in linked}
        extra = built - resolved
        if args.build_std:
            # `-Z build-std` compiles the standard library for the target too, so its crates are in
            # the build and not in kern's graph: allowed exactly when they are packages of the
            # library workspace the toolchain's rust-src carries, and listed under rust-std.
            sysroot = Path(run(rustc + ["--print", "sysroot"]).strip())
            lib_lock = sysroot / "lib" / "rustlib" / "src" / "rust" / "library" / "Cargo.lock"
            if not lib_lock.is_file():
                raise SbomError(f"--build-std, and the toolchain has no rust-src ({lib_lock})")
            std_names = {p["name"] for p in tomllib.loads(lib_lock.read_text()).get("package", [])}
            std_crates = sorted(extra & std_names)
            extra -= std_names
        if extra or resolved - built:
            raise SbomError(
                f"the build of {args.package} for {args.target} compiled {sorted(extra)} that "
                f"the resolver does not link, and the resolver links {sorted(resolved - built)} "
                f"that the build did not compile"
            )
    sums = lock_checksums(lock)
    crates = []
    for k in sorted(every):
        c = dict(every[k])
        c["key"] = k
        c["linked"] = k in linked
        c["proc_macro"] = k in macros
        if not c["local"]:
            if k not in sums:
                raise SbomError(f"{k} has no checksum in {lock}: not a crates.io download?")
            c["sha256"] = sums[k]
        crates.append(c)
    edges = []
    for (p, c) in sorted(a_edges):
        kind = "link" if (p, c) in n_edges and p in linked and c in linked else "build"
        edges.append([p, c, kind])
    vv = run(rustc + ["-Vv"])
    info = dict(line.split(": ", 1) for line in vv.splitlines() if ": " in line)
    runtime = []
    if "musl" in args.target:
        try:
            musl = musl_version(rustc, args.target)
        except SbomError:
            # Only the gate asks for this leniency (a dev machine may lack the target); the release
            # build has the target installed, and there a missing musl is an error.
            if not getattr(args, "lenient_runtime", False):
                raise
            musl = "NOASSERTION"
        runtime.append({"name": "musl", "version": musl,
                        "license": "MIT", "url": "https://musl.libc.org/",
                        "comment": f"the C library, linked statically from the Rust toolchain's "
                                   f"self-contained {args.target} target"})
    if "windows-gnu" in args.target:
        for pkg in ("gcc-mingw-w64-x86-64", "mingw-w64-x86-64-dev"):
            runtime.append({"name": pkg, "version": dpkg_version(pkg), "license": "NOASSERTION",
                            "url": f"https://packages.ubuntu.com/search?keywords={pkg}",
                            "comment": "the MinGW-w64 C runtime and libgcc objects the cross "
                                       "linker puts into kern.exe; their licenses are in the "
                                       "package's copyright file"})
    out = {
        "kind": "binary",
        "package": args.package,
        "target": args.target,
        "root": root,
        "crates": crates,
        "edges": edges,
        "rust": {"release": vv.splitlines()[0], "commit": info.get("commit-hash", ""),
                 "date": info.get("commit-date", ""), "build_std": bool(args.build_std),
                 "std_crates": std_crates},
        "runtime": runtime,
    }
    if args.binary:
        out["binary_sha256"] = hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()
    return out


# ------------------------------------------------------------------------------------------------
# rootfs: the Alpine packages of the WSL rootfs


def rootfs(args) -> dict:
    with tarfile.open(args.tar, "r:gz") as t:
        def read(path: str) -> bytes | None:
            for name in (path, "./" + path):
                try:
                    f = t.extractfile(name)
                except KeyError:
                    continue
                if f:
                    return f.read()
            return None

        db = read("lib/apk/db/installed")
        release = (read("etc/alpine-release") or b"").decode().strip()
        kern = read("usr/local/bin/kern")
    if db is None:
        raise SbomError(f"{args.tar} has no lib/apk/db/installed")
    pkgs = []
    for block in db.decode("utf-8", "replace").split("\n\n"):
        f: dict[str, str] = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":" and line[0] not in f:
                f[line[0]] = line[2:]
        if "P" not in f:
            continue
        pkgs.append({"name": f["P"], "version": f.get("V", ""), "arch": f.get("A", ""),
                     "license": f.get("L", ""), "url": f.get("U", ""), "origin": f.get("o", ""),
                     "commit": f.get("c", ""), "checksum": f.get("C", "")})
    if not pkgs:
        raise SbomError(f"{args.tar}: the apk database lists no package")
    return {"kind": "rootfs", "alpine": release, "packages": sorted(pkgs, key=lambda p: p["name"]),
            "kern_sha256": hashlib.sha256(kern).hexdigest() if kern else ""}


# ------------------------------------------------------------------------------------------------
# assemble: the SPDX document


def spdx_id(*parts: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]+", "-", "-".join(parts)).strip("-")


def apk_license(expr: str) -> str:
    """Alpine's `L:` as an SPDX expression; a value that is not one becomes NOASSERTION."""
    e = expr.strip()
    if not e:
        return "NOASSERTION"
    if all(re.fullmatch(r"[A-Za-z0-9.+-]+|AND|OR|WITH|\(|\)", t) for t in _tokens(e)):
        return e
    return "NOASSERTION"


def created_time() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if not epoch:
        epoch = run(["git", "log", "-1", "--format=%ct"]).strip()
    return dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


ASSET_OF_TARGET = {
    "x86_64-unknown-linux-musl": "kern-x86_64-unknown-linux-musl.tar.gz",
    "aarch64-unknown-linux-musl": "kern-aarch64-unknown-linux-musl.tar.gz",
    "x86_64-pc-windows-gnu": "kern-windows-x86_64.exe",
}
ROOTFS_ASSET = "kern-wsl-rootfs.tar.gz"
ROOTFS_KERN_TARGET = "x86_64-unknown-linux-musl"


def assemble(tag: str, assets: Path, inputs: Path, created: str) -> dict:
    version = tag[1:] if tag.startswith("v") else tag
    files = sorted(p for p in assets.iterdir() if p.is_file() and not p.name.endswith(".sha256")
                   and not p.name.endswith(".spdx.json"))
    if not files:
        raise SbomError(f"no asset in {assets}")
    loaded = [json.loads(p.read_text()) for p in sorted(inputs.glob("*.json"))]
    binaries = {d["target"]: d for d in loaded if d.get("kind") == "binary"}
    rootfs_in = [d for d in loaded if d.get("kind") == "rootfs"]
    pkgs: dict[str, dict] = {}
    rels: list[tuple[str, str, str]] = []

    def add(p: dict) -> str:
        old = pkgs.get(p["SPDXID"])
        if old is not None and old != p:
            raise SbomError(f"two different packages would share the id {p['SPDXID']}")
        pkgs[p["SPDXID"]] = p
        return p["SPDXID"]

    def base(name: str, sid: str, ver: str, where: str, lic: str, purpose: str) -> dict:
        return {"name": name, "SPDXID": sid, "versionInfo": ver, "downloadLocation": where,
                "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
                "licenseDeclared": lic, "copyrightText": "NOASSERTION",
                "primaryPackagePurpose": purpose}

    def binary_node(target: str) -> str:
        d = binaries.get(target)
        if d is None:
            raise SbomError(f"no collected graph for {target}")
        if d.get("target") != target:
            raise SbomError(f"the input for {target} describes {d.get('target')}")
        name = "kern" if d["package"] == "getkern" else "kern.exe"
        sid = spdx_id("binary", name, target)
        # EVERY LICENSE COMES FROM CARGO, kern's own included. MEASURED: with kern's written here as
        # a constant, a workspace relicensed to GPL-3.0-only still produced "Apache-2.0" and passed.
        root_license = next(c["license"] for c in d["crates"] if c["key"] == d["root"])
        node = base(name, sid, version, f"git+{PROJECT_URL}@{tag}", root_license, "APPLICATION")
        node["supplier"] = "Organization: getkern"
        node["comment"] = f"the {d['package']} crate built for {target}"
        if d.get("binary_sha256"):
            node["checksums"] = [{"algorithm": "SHA256", "checksumValue": d["binary_sha256"]}]
        if sid in pkgs:
            return sid
        add(node)
        ids: dict[str, str] = {}
        for c in d["crates"]:
            if c["local"]:
                cid = spdx_id("crate", c["name"])
                cnode = base(c["name"], cid, version, f"git+{PROJECT_URL}@{tag}", c["license"],
                             "LIBRARY")
                cnode["supplier"] = "Organization: getkern"
            else:
                cid = spdx_id("crate", c["name"], c["version"])
                cnode = base(c["name"], cid, c["version"],
                             f"https://crates.io/api/v1/crates/{c['name']}/{c['version']}/download",
                             c["license"], "LIBRARY")
                cnode["supplier"] = "NOASSERTION"
                cnode["checksums"] = [{"algorithm": "SHA256", "checksumValue": c["sha256"]}]
                cnode["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER",
                                          "referenceType": "purl",
                                          "referenceLocator": f"pkg:cargo/{c['name']}@{c['version']}"}]
                if c.get("repository"):
                    cnode["homepage"] = c["repository"]
            ids[c["key"]] = add(cnode)
            if c["linked"]:
                rels.append((sid, "STATIC_LINK", cid))
            else:
                rels.append((cid, "BUILD_DEPENDENCY_OF", sid))
        for (p, c, kind) in d["edges"]:
            if kind == "link":
                rels.append((ids[p], "DEPENDS_ON", ids[c]))
            else:
                rels.append((ids[c], "BUILD_DEPENDENCY_OF", ids[p]))
        rust = d["rust"]
        # One per target when built from source: its crate list is that target's build.
        std = base("rust-std", spdx_id("rust-std", rust["commit"][:12] or "unknown",
                                       target if rust.get("build_std") else ""),
                   rust["release"],
                   f"{'https://github.com/rust-lang/rust/tree/' + rust['commit'] if rust['commit'] else 'NOASSERTION'}",
                   "MIT OR Apache-2.0", "LIBRARY")
        if rust.get("build_std"):
            std["comment"] = ("the standard library compiled from source with the binary "
                              "(-Z build-std); its crates in this build: "
                              + ", ".join(rust.get("std_crates") or []))
        else:
            std["comment"] = "the standard library as the toolchain ships it, precompiled"
        rels.append((sid, "STATIC_LINK", add(std)))
        for r in d["runtime"]:
            rnode = base(r["name"], spdx_id("runtime", r["name"], r["version"], target), r["version"],
                         r["url"], r["license"], "LIBRARY")
            rnode["comment"] = r["comment"]
            rels.append((sid, "STATIC_LINK", add(rnode)))
        rels.append((sid, "DEPENDS_ON", ids[d["root"]]))
        return sid

    described = []
    for f in files:
        sha_file = f.with_name(f.name + ".sha256")
        if not sha_file.is_file():
            raise SbomError(f"{f.name} has no {sha_file.name}")
        want = sha_file.read_text().split()[0]
        got = hashlib.sha256(f.read_bytes()).hexdigest()
        if want != got:
            raise SbomError(f"{f.name} does not match its .sha256 ({got}, file says {want})")
        aid = spdx_id("asset", f.name)
        # A kern file declares its binary's license (filled in below); the rootfs is a collection,
        # each of its parts declared on its own.
        anode = base(f.name, aid, version, f"{PROJECT_URL}/releases/download/{tag}/{f.name}",
                     "NOASSERTION", "ARCHIVE" if f.name.endswith(".tar.gz") else "APPLICATION")
        anode["checksums"] = [{"algorithm": "SHA256", "checksumValue": got}]
        anode["supplier"] = "Organization: getkern"
        add(anode)
        described.append(aid)
        target = next((t for t, a in ASSET_OF_TARGET.items() if a == f.name), None)
        if target:
            bid = binary_node(target)
            anode["licenseDeclared"] = pkgs[bid]["licenseDeclared"]
            rels.append((aid, "CONTAINS", bid))
        elif f.name == ROOTFS_ASSET:
            if len(rootfs_in) != 1:
                raise SbomError(f"{f.name} needs exactly one rootfs input, found {len(rootfs_in)}")
            rf = rootfs_in[0]
            kid = binary_node(ROOTFS_KERN_TARGET)
            if rf["kern_sha256"] != binaries[ROOTFS_KERN_TARGET].get("binary_sha256"):
                raise SbomError("the rootfs carries a kern that is not the released x86_64 binary")
            rels.append((aid, "CONTAINS", kid))
            distro = f"alpine-{rf['alpine']}" if rf["alpine"] else "alpine"
            for p in rf["packages"]:
                pid = spdx_id("apk", p["name"], p["version"])
                pnode = base(p["name"], pid, p["version"], p["url"] or "NOASSERTION",
                             apk_license(p["license"]), "LIBRARY")
                pnode["supplier"] = "Organization: Alpine Linux"
                pnode["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER",
                                          "referenceType": "purl",
                                          "referenceLocator": f"pkg:apk/alpine/{p['name']}@{p['version']}"
                                                              f"?arch={p['arch']}&distro={distro}"}]
                if p["checksum"].startswith("Q1"):
                    pnode["checksums"] = [{"algorithm": "SHA1",
                                           "checksumValue": base64.b64decode(p["checksum"][2:]).hex()}]
                if p["license"] and pnode["licenseDeclared"] == "NOASSERTION":
                    pnode["comment"] = f"Alpine declares the license as {p['license']!r}"
                rels.append((aid, "CONTAINS", add(pnode)))
        else:
            raise SbomError(f"{f.name} is an asset this SBOM does not know how to describe")
    unused = set(binaries) - {t for t, a in ASSET_OF_TARGET.items() if (assets / a).is_file()}
    if unused:
        raise SbomError(f"graphs collected for {sorted(unused)} but no such asset in {assets}")
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"kern {version}",
        "documentNamespace": f"{PROJECT_URL}/releases/download/{tag}/kern.spdx.json",
        "creationInfo": {"created": created,
                         "creators": ["Organization: getkern", "Tool: kern-scripts-sbom.py"]},
        "packages": [pkgs[k] for k in sorted(pkgs)],
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                           "relatedSpdxElement": a} for a in described]
        + [{"spdxElementId": a, "relationshipType": t, "relatedSpdxElement": b}
           for (a, t, b) in sorted(set(rels))],
    }
    check_document(doc)
    return doc


def check_document(doc: dict) -> None:
    """What a reader relies on: ids unique and resolvable, licenses stated, linked crates allowed."""
    ids = [p["SPDXID"] for p in doc["packages"]]
    if len(ids) != len(set(ids)):
        raise SbomError("duplicate SPDXID")
    known = set(ids) | {"SPDXRef-DOCUMENT"}
    for r in doc["relationships"]:
        for k in ("spdxElementId", "relatedSpdxElement"):
            if r[k] not in known:
                raise SbomError(f"relationship names {r[k]}, which is not in the document")
    for p in doc["packages"]:
        if not re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", p["SPDXID"]):
            raise SbomError(f"invalid SPDXID {p['SPDXID']}")
    linked = {r["relatedSpdxElement"] for r in doc["relationships"]
              if r["relationshipType"] == "STATIC_LINK"}
    by_id = {p["SPDXID"]: p for p in doc["packages"]}
    for sid in sorted(linked):
        p = by_id[sid]
        if p["name"].startswith(("gcc-mingw", "mingw-w64")):
            continue  # the C runtime objects: named, versioned, licenses in their copyright file
        if not license_allowed(p["licenseDeclared"]):
            raise SbomError(f"{p['name']} {p['versionInfo']} is linked into kern under "
                            f"{p['licenseDeclared']!r}, which is not in ALLOWED_LICENSES")


def write_json(path: Path, doc: dict) -> None:
    path.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--package", required=True)
    c.add_argument("--target", required=True)
    c.add_argument("--manifest-path")
    c.add_argument("--toolchain")
    c.add_argument("--target-dir")
    c.add_argument("--binary")
    c.add_argument("--build-std", action="store_true")
    c.add_argument("--out", required=True)
    r = sub.add_parser("rootfs")
    r.add_argument("--tar", required=True)
    r.add_argument("--out", required=True)
    a = sub.add_parser("assemble")
    a.add_argument("--tag", required=True)
    a.add_argument("--assets", required=True)
    a.add_argument("--inputs", required=True)
    a.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "collect":
            write_json(Path(args.out), collect(args))
        elif args.cmd == "rootfs":
            write_json(Path(args.out), rootfs(args))
        else:
            out = Path(args.out)
            write_json(out, assemble(args.tag, Path(args.assets), Path(args.inputs),
                                     created_time()))
            digest = hashlib.sha256(out.read_bytes()).hexdigest()
            out.with_name(out.name + ".sha256").write_text(f"{digest}  {out.name}\n")
    except SbomError as e:
        print(f"sbom: {e}", file=sys.stderr)
        return 1
    print(f"sbom: wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
