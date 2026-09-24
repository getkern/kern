"""kern-sandbox: run LLM/agent-generated code in a fast, local, daemonless kernel sandbox.

    import kern_sandbox as kern

    # one-shot (a throwaway session under the hood)
    r = kern.run_code("import sys; print(sys.version)")
    print(r.stdout, r.success)

    # a session: FILE state persists across steps (a workspace on disk), processes are ephemeral
    with kern.Sandbox(setup="pip install pandas") as sbx:
        sbx.write_file("data.csv", csv_bytes)
        r = sbx.run_code("import pandas as pd; print(pd.read_csv('data.csv').shape)")
        png = sbx.read_file("out.png")

Design, the "middle way" (validated with review):
  * FILE state persists between steps via a workspace DIRECTORY on the host, bind-mounted into each
    box. PROCESSES are ephemeral: every run_code()/run() spawns a FRESH box on that shared workspace.
    There is NO resident interpreter - in-memory REPL state (a `x=40` living in globals) does NOT
    survive between calls; write to disk if you need continuity. This keeps the cold-start/density
    win (100s of ephemeral boxes, not 100s of resident pythons) instead of chasing a cloud-session
    model kern isn't built for.
  * ONE class (`Sandbox`). `run_code(...)` at module level is literally a throwaway session
    (`with Sandbox() as s: return s.run_code(...)`), so there is a single, tested security code path -
    not two Sandbox-like surfaces that drift apart. (# DECISION, independent test-ratified.)
  * I/O is HOST-DIRECT: the workspace is a host dir and single-uid maps box-root to the host user, so
    files the box creates are host-owned - write_file/read_file are plain host filesystem I/O, no
    `kern cp`, no in-box shim. (`--uid-range` breaks this ownership and is OUT of v1 scope. # DECISION.)

Threat model (honest): kern is a KERNEL-BOUNDARY sandbox for YOUR OWN or SEMI-TRUSTED code. seccomp
is a DENYLIST - suitable for semi-trusted agent code, NOT a hard boundary against deliberately hostile
multi-tenant code (for that: a microVM / gVisor). A deny-by-default seccomp allowlist ships opt-in:
pass security_profile="untrusted" (or KERN_SECCOMP=allowlist).
"""

from __future__ import annotations

import atexit
import base64
import errno
import hashlib
import json
import os
import queue
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Mapping, Sequence

__all__ = [
    "Sandbox",
    "Kernel",
    "ExecutionResult",
    "Result",
    "SandboxFault",
    "FileInfo",
    "SandboxError",
    "MountRefused",
    "run_code",
]

__version__ = "0.2.36"

# DECISION: default image is a small Python base. Criterion "import pandas with no setup" needs a
# batteries-included image; for v1 we start from a PUBLIC image and let `setup=` bake deps, rather than
# building+hosting our own (independent test-ratified FLAG 4). Ship a datascience default when demand justifies.
_DEFAULT_IMAGE = "python:3.12-slim"

_WORKSPACE = "/workspace"  # where the persistent workspace is mounted inside every box
_DEPS_DIR = ".deps"  # pip --target dir inside the workspace (added to PYTHONPATH for run_code)

# -- the standard library's bytecode, compiled once per image and mounted READ-ONLY ------------------
#
# WHY THIS EXISTS, measured. `python:3.12-slim` ships its standard library as 567 `.py` files and no
# `.pyc`, and a box mounts its root read-only, so EVERY box recompiles from source what it imports and
# throws the result away. `import json,re` costs 45.5 ms on an i7-14700KF and 172.0 ms on a 4-vCPU
# Contabo VPS, against 13.1 ms for a box that runs `/bin/true` there: most of a call is a compiler
# running, not a sandbox starting. `encodings.aliases`, which every interpreter imports before it runs
# anything, is 9.9 ms of that on the VPS by itself.
#
# One box compiles the stdlib once per image into a host directory, and every later box mounts that
# directory READ-ONLY with `PYTHONPYCACHEPREFIX` pointing at it. Measured over 7 alternated pairs:
# `import json,re` goes 45.50 -> 19.68 ms on the desktop.
#
# READ-ONLY IS NOT A PRECAUTION, IT IS THE WHOLE DESIGN. A writable shared bytecode cache is remote
# code execution across calls: `python:3.12-slim`'s `.pyc` are timestamp-validated, so a cell can
# rewrite `json/__init__.pyc` with a payload, re-paste the legitimate header (magic, mtime, size), and
# the NEXT cell that imports json executes it. That attack was demonstrated on this project before this
# cache existed. Here the mount is `:ro`, verified: a cell's `write_bytes` on a cached `.pyc` comes back
# `OSError` 30, EROFS.
#
# A CACHE FROM THE WRONG IMAGE IS SAFE, and this is the property the key rests on rather than a hope.
# CPython validates every `.pyc` against the source's mtime and size before using it, so bytecode that
# does not belong to the interpreter reading it is IGNORED, not executed. Verified by building the cache
# from `python:3.12-slim` and mounting it into `python:3.11-slim`: the box reported 3.11.16 and computed
# correct answers. The failure mode of a stale or mismatched cache is therefore "as slow as before",
# never "runs the wrong code".
_PYC_MOUNT = "/kern-pyc"  # where the cache is mounted inside a box, read-only
# `workers=1` because `compileall` with more than one worker uses multiprocessing, which needs a
# temporary directory, and a box with a read-only root and no tmpfs has none: MEASURED, it dies with
# `FileNotFoundError: No usable temporary directory found`. Serial costs 1.2 s on the desktop, and it
# runs in a background thread where nothing waits for it. `quiet=2` keeps a file that will not compile
# from writing to stderr: bytecode is an optimisation and a failure here is not the caller's problem.
#
# EVERY IMPORT ROOT, NOT JUST THE STDLIB, and the first version compiled only
# `sysconfig.get_paths()['stdlib']`. That is enough on `python:3.12-slim`, where `purelib` happens to
# be a SUBDIRECTORY of stdlib and `compile_dir` recurses into it, and wrong everywhere else: MEASURED
# on `debian:13-slim` with python3 from apt, stdlib is `/usr/lib/python3.13` while purelib is
# `/usr/local/lib/python3.13/dist-packages`, and `sys.path` holds five separate roots. Since
# `PYTHONPYCACHEPREFIX` REPLACES the in-tree `__pycache__` rather than adding to it, a root left out of
# the cache has its shipped bytecode made invisible and is recompiled in every box - the feature would
# slow down exactly the images that carry preinstalled packages. Nested roots are dropped so a
# directory is not walked twice.
#
# CHECKED_HASH, NOT THE DEFAULT TIMESTAMP, and this is a correctness property rather than a taste.
# A timestamp-validated `.pyc` is accepted when the source's mtime and size match what the header
# records, and images built reproducibly (BuildKit `rewrite-timestamp`, apko, Nix, distroless) pin
# mtimes by construction. MEASURED: two images, same CPython 3.12, one stdlib file edited to a
# different value of the SAME LENGTH with the mtime preserved - with timestamp validation the box ran
# the OLD code, with CHECKED_HASH it ran the new one. The failure mode was a security patch that was
# installed and then not executed. Hashing the source on every import costs nothing measurable here
# (15.26 ms against 15.30 for `import json,re`, 7 alternated pairs), and it is what makes the cache key
# a performance hint rather than a correctness dependency. UNCHECKED_HASH would be the opposite error:
# bytecode that never invalidates at all.
#
# `force=True`, and it is NOT belt and braces. MEASURED on the VPS: 39 of 1097 cached files came out
# with TIMESTAMP validation anyway, and they are exactly the modules this very command imports -
# `compileall`, `encodings`, `importlib`, `functools`, `collections`. Importing them writes their
# bytecode to the prefix through the ordinary import machinery, which uses the default mode, BEFORE
# `compile_dir` runs; `compile_dir` then finds them up to date and skips them. So the one guarantee
# this cache rests on was missing from `encodings/aliases`, which is 9.9 ms of interpreter startup on
# that host. Recompiling everything costs a fraction of a second on a tree that is fresh anyway.
_PYC_BUILD_CODE = (
    "import compileall,os,py_compile,sys,sysconfig;"
    "r={p for p in sys.path if p and os.path.isdir(p)};"
    "r|={v for v in (sysconfig.get_paths().get(k) for k in "
    "('stdlib','platstdlib','purelib','platlib')) if v and os.path.isdir(v)};"
    "r={p for p in r if not any(p!=q and p.startswith(q.rstrip('/')+'/') for q in r)};"
    "sys.exit(0 if all([compileall.compile_dir(p,quiet=2,workers=1,force=True,"
    "invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH) for p in sorted(r)]) else 1)"
)
# A ceiling on what one image may publish. The stdlib is ~20 MiB and an image with large packages is
# more, so this is not a tight bound - it exists so a hostile image cannot fill the host's disk from
# the one box that exists to make things faster.
_PYC_MAX_BYTES = 512 * 1024 * 1024
# How many image caches to keep, least-recently-ADOPTED evicted first. Eight is not a measurement: it
# is "more images than a session mixes, fewer than a disk notices" at ~20 MiB each. A cache is
# reproducible from its image, so evicting one costs time and nothing else.
_PYC_KEEP = 8
# A build killed by a SIGKILL leaves its private `.tmp-` tree behind forever: nothing in the happy path
# removes it, because the happy path is the one that did not run. Swept after a day, which is long
# enough that a build still running is never the thing being deleted.
_PYC_DEBRIS_MAX_AGE_S = 24 * 60 * 60
# The two name fragments that mark a directory as NOT a cache: one being written, one being deleted.
_PYC_DEBRIS_MARKS = (".tmp-", ".trash-")
# One build per (process, destination), so ten sessions opened at once on one image start one compile
# and not ten. A MAP OF THREADS rather than a set of names: a second caller gets the thread of the
# build already in flight, which is what lets a test `join()` the real thing instead of polling for a
# directory. A poll would race the build, and in the Node binding it raced the test's own teardown.
_PYC_BUILDS: "dict[str, threading.Thread]" = {}
# True once this process has swept, so adopting a cache in a hundred sessions costs one scan. Under
# `_PYC_LOCK`, because two sessions opened from two threads would otherwise both start one.
_PYC_SWEPT = False
_PYC_LOCK = threading.Lock()


def _pyc_root() -> str:
    """The host directory holding one bytecode cache per image.

    `$XDG_CACHE_HOME` when set, else `~/.cache`, which is where a cache belongs on a Linux host: it is
    reproducible from the image, so a user clearing it loses time and nothing else.
    """
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "kern-sandbox", "pyc")


# kern's own defaults, from `kern-oci/src/pull.rs`. Copied rather than derived because they cross a
# process boundary: if kern ever changes them, two references that kern considers one image would get
# two cache directories here, which costs disk and never correctness.
_OCI_DEFAULT_REGISTRY = "registry-1.docker.io"
_OCI_DEFAULT_TAG = "latest"


def _oci_split_tag(image: str) -> "tuple[str, str] | None":
    """`(name, tag)` iff the reference ends in an explicit tag. Mirrors `split_tag` in kern-oci.

    A trailing `:x` is a tag only when `x` has no `/`, or `localhost:5000/img` would read its PORT as a
    tag. A digest (`img@sha256:<hex>`) splits at that same colon and so counts as explicit, which is
    what a caller wants: a digest pins harder than a tag and must never have `:latest` bolted on.
    """
    name, sep, tag = image.rpartition(":")
    if sep and "/" not in tag and name:
        return name, tag
    return None


def _oci_canonical_ref(image: str) -> str:
    """One canonical string per image, so one cache directory per image.

    WHY THIS EXISTS. `python:3.12-slim`, `docker.io/library/python:3.12-slim` and
    `index.docker.io/python:3.12-slim` are the same image to kern and were three cache directories
    here, because the key was the raw string the caller typed. Three compiles and three copies of the
    same 16 MiB.

    A FAITHFUL PORT OF `parse_ref` in `kern-oci/src/pull.rs`, rule for rule, because the two must agree
    about what "the same image" means:

    * a digest pin splits at `@` FIRST, since `rpartition(':')` would otherwise tear `sha256:<hex>` in
      half; the digest wins over any tag, so a trailing `:tag` on the name is dropped;
    * the first path segment is a REGISTRY only if it looks like a host (contains a dot or a colon, or
      is exactly `localhost`), otherwise `user/img` is a Docker Hub repository, not a host;
    * `docker.io` and `index.docker.io` are aliases for `registry-1.docker.io`, which is where Docker
      Hub's API actually is;
    * on Docker Hub a single-segment repository gets `library/`, and ONLY there: `ghcr.io/alpine`
      means what it says.

    Worst case for a reference this function cannot parse is that it returns the input unchanged and
    two spellings get two directories: disk, never correctness, because the bytecode itself is
    validated against its source by hash.
    """
    if not image:
        return image
    name, sep, digest = image.partition("@")
    if sep and name and digest:
        base = _oci_split_tag(name)
        name, reference = (base[0] if base else name), digest
    else:
        split = _oci_split_tag(image)
        name, reference = split if split else (image, _OCI_DEFAULT_TAG)
    host, sep, rest = name.partition("/")
    if sep and ("." in host or ":" in host or host == "localhost"):
        registry, repo = host, rest
    else:
        registry, repo = _OCI_DEFAULT_REGISTRY, name
    if registry in ("docker.io", "index.docker.io"):
        registry = _OCI_DEFAULT_REGISTRY
    if registry == _OCI_DEFAULT_REGISTRY and "/" not in repo:
        repo = f"library/{repo}"
    return f"{registry}/{repo}:{reference}"


def _pyc_dir_for(image: str) -> str:
    """Where this image's cache lives. Keyed on the image REFERENCE, hashed for a filesystem-safe name.

    The reference, not a content digest, and the honest reason is that kern exposes no digest a caller
    can read cheaply: `kern inspect` prints for a human, and resolving one would cost a box start on
    every session. The key therefore identifies a NAME, and a moved tag yields a cache whose bytecode
    no longer validates - which CPython handles by recompiling, as verified above. The cost of the
    imperfect key is a slow call, not a wrong one.
    """
    # THE FULL DIGEST, not a truncation. 64 bits is almost certainly enough against an accident and the
    # key is no longer load-bearing for correctness (see CHECKED_HASH above), but the saving was 48
    # characters of path and the cost of being wrong is two images sharing a cache directory.
    key = hashlib.sha256(
        _oci_canonical_ref(image).encode("utf-8", "surrogateescape")
    ).hexdigest()
    return os.path.join(_pyc_root(), key)


def _pyc_has_content(dest: str) -> bool:
    """Is there a cache at `dest`, as opposed to a directory named like one?

    AN EMPTY DIRECTORY IS NOT AN ABSENT ONE, and the difference was a hole that silences the whole
    feature. Measured: a sweep in another process discards a tree this session has mounted, kern then
    RECREATES the missing `-v` source as an empty directory, and from then on every session adopts that
    empty directory, mounts it, finds no bytecode and compiles from source - permanently, silently, with
    nothing to rebuild it because a cache "exists". The `.pyc` count in the box went to zero and stayed
    there.

    Treating empty as absent repairs it instead: the adoption is refused, a build starts, and
    `os.rename` onto an EMPTY directory SUCCEEDS (verified; onto a non-empty one it is `ENOTEMPTY`,
    which is the check `_pyc_build` relies on when two processes race). So the next session that opens
    puts a real tree back.

    One `scandir` that stops at the first entry, not a walk: the question is whether anything is there.
    """
    try:
        with os.scandir(dest) as it:
            return any(True for _ in it)
    except OSError:
        return False


def _pyc_path_has_no_symlink(dest: str) -> bool:
    """True iff no component of the cache path is a symlink.

    THE VALIDATOR ABOVE IS LEXICAL AND A BIND MOUNT IS NOT: `_validate_mount_lexical` inspects the
    STRING, while kern's `-v` follows links. So a symlink at `<cache>/kern-sandbox/pyc/<key>` pointing
    at `~/.ssh` passes the name check and mounts the real directory into every box of every later
    session, read-only - and reading is what exfiltration needs.

    WHO CAN PLANT IT is the part that makes this a boundary and not a foot-gun. Not only the user: a
    CELL given a writable volume that contains the cache root (`-v ~:/host`, a workspace under
    `$XDG_CACHE_HOME`) can create it, and then every future session of every future process is
    affected. That is the `.deps` poisoning vector escaping the session that produced it, which is the
    one class of bug this package treats as fatal. The same write also lets a cell replace the `.pyc`
    themselves, so the check has to be on the PATH, before anything is mounted.

    Walked with `lstat` from the leaf to the root: a component that does not exist yet is not a link,
    and a component that is one disqualifies the whole path.
    """
    seen: "set[str]" = set()
    cur = os.path.abspath(dest)
    while cur not in seen:
        seen.add(cur)
        try:
            if stat.S_ISLNK(os.lstat(cur).st_mode):
                return False
        except OSError:
            pass  # does not exist: nothing to follow
        parent = os.path.dirname(cur)
        if parent == cur:
            return True
        cur = parent
    return True


def _pyc_tree_is_publishable(root: str) -> bool:
    """True iff the built tree is only directories and `.pyc` files, and fits under the size ceiling.

    The build box runs the CALLER'S image with this directory writable, so what lands in it is chosen
    by that image, not by the command. Inside a later box a symlink resolves in that box's own
    namespace and is harmless, but this tree also lives on the HOST, where a backup, an indexer or the
    cache's own future eviction will walk it: a symlink out of it is a way to have those follow a link
    the user never made, and a FIFO blocks whoever opens it, forever. Everything that is not a regular
    `.pyc` or a directory is refused, and the tree is discarded rather than repaired.
    """
    total = 0
    try:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            for name in dirnames:
                if stat.S_ISLNK(os.lstat(os.path.join(dirpath, name)).st_mode):
                    return False
            for name in filenames:
                st = os.lstat(os.path.join(dirpath, name))
                if not stat.S_ISREG(st.st_mode) or not name.endswith(".pyc"):
                    return False
                total += st.st_size
                if total > _PYC_MAX_BYTES:
                    return False
    except OSError:
        return False
    return True


def _pyc_discard(path: str) -> None:
    """Remove a cache tree, renaming it out of the way first. Never raises.

    THE RENAME IS THE POINT, not tidiness. `rmtree` walks and unlinks, so a tree being deleted is for a
    while a tree with half its files: a session that mounts it in that window gets a partial stdlib.
    A rename is atomic, so the name either resolves to a whole tree or to nothing, and `kern` CREATES a
    `-v` source that does not exist (measured), which is why nothing breaks when it resolves to nothing:
    the box gets an empty directory, finds no bytecode and compiles from source, exactly as it did
    before this cache existed.
    """
    trash = f"{path}.trash-{uuid.uuid4().hex[:8]}"
    try:
        os.rename(path, trash)
    except OSError:
        return
    shutil.rmtree(trash, ignore_errors=True)


def _pyc_sweep(root: str, keep: int = _PYC_KEEP) -> None:
    """Bound the cache: keep the `keep` most recently adopted, and remove stale debris. Never raises.

    LEAST RECENTLY ADOPTED, and adoption is what `__enter__` records with a `utime` on the directory.
    Not least recently BUILT: an image built once and used daily would be evicted ahead of one built
    yesterday and never used again, which is backwards. The directory's own mtime carries it, so there
    is no marker file - one would be visible inside every box that mounts the cache, and would have to
    be excluded from the tree check that refuses everything which is not a `.pyc`.

    Called at the end of a build, in the background thread: it is the only moment this module runs when
    nobody is waiting, and the only moment a new directory has just appeared.
    """
    now = time.time()
    caches: "list[tuple[float, str]]" = []
    doomed: "list[str]" = []
    try:
        entries = list(os.scandir(root))
    except OSError:
        return
    for e in entries:
        try:
            if not e.is_dir(follow_symlinks=False):
                continue
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue
        if any(mark in e.name for mark in _PYC_DEBRIS_MARKS):
            # A tree half-written by a build that was killed, or half-deleted by a sweep that was.
            if now - st.st_mtime > _PYC_DEBRIS_MAX_AGE_S:
                doomed.append(e.path)
            continue
        caches.append((st.st_mtime, e.path))
    caches.sort(reverse=True)
    doomed.extend(path for _, path in caches[keep:])
    for path in doomed:
        _pyc_discard(path)


def _pyc_build(kern_bin: str, image: str, dest: str, timeout_s: float) -> None:
    """Compile `image`'s standard library into `dest`, atomically. Never raises: the caller is a thread.

    Built into a private sibling and `rename`d into place, so a reader either sees no cache or a
    complete one - there is no window where a box mounts a half-written tree. Two processes racing
    both build, and the loser's tree is removed: `rename` onto an existing directory fails with
    ENOTEMPTY, which is the check, not an error to report.
    """
    tmp = f"{dest}.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    try:
        os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
        os.makedirs(tmp, mode=0o700, exist_ok=True)
    except OSError:
        return
    try:
        # A dedicated argv rather than `_base_argv`: that one mounts the session's workspace, writes an
        # env file and would add THIS cache read-only, which is exactly what must not happen while it is
        # being written. Nothing of the caller's session is in this box.
        argv = [
            kern_bin, "box", f"kern-pyc-{uuid.uuid4().hex[:8]}",
            "--image", image, "--ro",
            "-v", f"{tmp}:{_PYC_MOUNT}",
            "--env", f"PYTHONPYCACHEPREFIX={_PYC_MOUNT}",
            "--cap-drop", "ALL",
            # CAPPED LIKE ANY OTHER BOX, and not because compiling is dangerous: the command is ours,
            # but the INTERPRETER running it is the caller's image, and this package's whole claim is
            # that an image gets no uncapped process. Without these a hostile image's `python3` could
            # fork-bomb or exhaust the host from the one box that exists to make things faster. 512 MiB
            # and 256 tasks are the Sandbox defaults; `compileall` with `workers=1` needs neither.
            "--memory", "512m",
            "--pids-limit", "256",
            "--timeout", str(int(timeout_s)),
            "--", "python3", "-c", _PYC_BUILD_CODE,
        ]
        r = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout_s + 10)
        # An image without python3, or one whose stdlib will not compile, leaves no cache and no trace.
        # The next session finds nothing and runs exactly as it did before this feature existed.
        if r.returncode == 0 and any(os.scandir(tmp)) and _pyc_tree_is_publishable(tmp):
            os.rename(tmp, dest)
            return
    except (OSError, ValueError, subprocess.SubprocessError):
        # `subprocess.TimeoutExpired` is a `SubprocessError`, so a build that overruns lands here and
        # the tree below is removed rather than left for the next process to find.
        pass
    finally:
        # AFTER the publish and after the failure path alike: a build that produced nothing is still the
        # moment to notice that eight other caches are older than this one.
        _pyc_sweep(os.path.dirname(dest))
    shutil.rmtree(tmp, ignore_errors=True)


def _pyc_start_sweep(root: str) -> "threading.Thread | None":
    """Sweep the cache once per process, in the background. Returns the thread, or None if already done.

    WHY THIS EXISTS SEPARATELY FROM THE BUILD. The sweep used to run only at the end of a build, so a
    process that always found its cache already there never evicted anything: the bound existed only
    for callers who happened to compile something. A long-lived server that adopts one cache for weeks
    is exactly the process that should be aging the seven others.

    IN A THREAD, because it is a `scandir` plus one `stat` per entry and a caller's first call must pay
    nothing for it. Once per process, because the answer cannot change often enough to be worth
    scanning twice.
    """
    global _PYC_SWEPT
    with _PYC_LOCK:
        if _PYC_SWEPT:
            return None
        _PYC_SWEPT = True
    th = threading.Thread(target=_pyc_sweep, args=(root,), daemon=True, name="kern-pyc-sweep")
    th.start()
    return th


def _pyc_start_build(kern_bin: str, image: str, dest: str, timeout_s: float) -> "threading.Thread":
    """Start one background build for this destination, or hand back the one already running.

    The thread is returned for the tests and dropped by `__enter__`: a caller's first call must never
    wait on a cache fill. `daemon=True` so a build cannot hold up interpreter exit; a half-built tree is
    a `.tmp-` sibling that no box can mount and that the next build ignores.
    """
    with _PYC_LOCK:
        running = _PYC_BUILDS.get(dest)
        if running is not None:
            return running
        th = threading.Thread(
            target=_pyc_build, args=(kern_bin, image, dest, timeout_s), daemon=True,
            name="kern-pyc-build",
        )
        _PYC_BUILDS[dest] = th
    th.start()
    return th
_ENV_FILE = ".kern-env"  # host-side 0600 env file (kept out of argv so values don't show in `ps`)
# One file per CALL, `.kern-env.<box-name>`: a single fixed name made two concurrent calls on the
# same Sandbox race for one path. The plain `.kern-env` is still recognised so a workspace written
# by an older version is filtered out of file diffs and snapshots rather than surfacing as user state.
_ENV_SEP = "."
# Cap the results file the (untrusted) box writes before the binding reads it back into host RAM: a
# malicious cell could stream a multi-GB `.res` to disk (past its own memory cap) and OOM the host.
_RESULTS_MAX = 64 * 1024 * 1024  # 64 MiB: generous for charts/tables, bounds the attacker-controlled read

# Sentinel for per-call kwargs that DEFAULT to the Sandbox value: `_UNSET` means "inherit the
# constructor's", whereas an explicit `None` means "disable" (used for on_stdout/on_stderr overrides).
_UNSET: object = object()

# Python cell runner (P1: rich mime-typed results, Jupyter/E2B-style, WITHOUT a Jupyter kernel). It
# execs the user cell, then captures (a) the value of a trailing bare expression, (b) every display(obj)
# call, and (c) every open matplotlib figure, writing them as a JSON mime-bundle list to a results file
# the binding reads back. stdout/stderr/exit-code are UNTOUCHED (results go to a file, not stdout); an
# uncaught error is re-formatted so the traceback shows the user's frames, not this runner's. Every step
# is best-effort: any failure leaves results empty and the run otherwise identical to a plain `python3`.
_PY_RUNNER = r'''
import sys, builtins  # C builtins: no .py to recompile in the read-only slim box (the P1 hot path).
_CELL = "__KERN_CELL__"
_RES = "__KERN_RES__"
_out = []
def _js(s):  # minimal JSON string encoder, so the box needs no `import json` (~80ms in a pyc-less slim box)
    r = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            r.append('\\"')
        elif ch == '\\':
            r.append('\\\\')
        elif o == 10:
            r.append('\\n')
        elif o == 13:
            r.append('\\r')
        elif o == 9:
            r.append('\\t')
        elif o < 32:
            r.append('\\u%04x' % o)
        else:
            r.append(ch)
    r.append('"')
    return "".join(r)
def _bundle(o):
    d = {}
    for meth, key in (("_repr_html_", "text/html"), ("_repr_markdown_", "text/markdown"),
                      ("_repr_svg_", "image/svg+xml"), ("_repr_latex_", "text/latex")):
        try:
            fn = getattr(o, meth, None)
            if callable(fn):
                v = fn()
                if isinstance(v, str) and v:
                    d[key] = v
        except Exception:
            pass
    try:
        fn = getattr(o, "_repr_json_", None)
        if callable(fn):
            v = fn()
            if v is not None:
                if isinstance(v, str):
                    d["application/json"] = v
                else:
                    import json  # lazy: only a custom _repr_json_ returning non-str reaches here
                    d["application/json"] = json.dumps(v)
    except Exception:
        pass
    for meth, key in (("_repr_png_", "image/png"), ("_repr_jpeg_", "image/jpeg")):
        try:
            fn = getattr(o, meth, None)
            if callable(fn):
                v = fn()
                if v:
                    import base64  # lazy: only when an object carries an image repr
                    raw = v if isinstance(v, (bytes, bytearray)) else str(v).encode()
                    d[key] = base64.b64encode(raw).decode()
        except Exception:
            pass
    if "text/plain" not in d:  # always carry a plain-text repr alongside any rich reprs (Jupyter/E2B do)
        try:
            d["text/plain"] = repr(o)
        except Exception:
            d["text/plain"] = "<unrepresentable>"
    return d
def display(o=None, **kw):
    if o is not None:
        _out.append(_bundle(o))
builtins.display = display
sys.argv = [_CELL]
_g = {"__name__": "__main__", "__file__": _CELL, "display": display}
_rc = 0
try:
    _src = open(_CELL, "r", encoding="utf-8").read()
    _tree = compile(_src, _CELL, "exec", 0x400)  # PyCF_ONLY_AST: the AST via the builtin, no `import ast`
    _tail = None
    if _tree.body and type(_tree.body[-1]).__name__ == "Expr":
        _n = _tree.body.pop()  # detach the trailing bare expression so exec doesn't run it (no double-eval)
        _lines = _src.split("\n")  # col offsets are UTF-8 BYTE offsets: slice on the encoded line
        if _n.lineno == _n.end_lineno:
            _tail = _lines[_n.lineno - 1].encode()[_n.col_offset:_n.end_col_offset].decode("utf-8", "replace")
        else:
            _seg = [_lines[_n.lineno - 1].encode()[_n.col_offset:].decode("utf-8", "replace")]
            _seg += _lines[_n.lineno:_n.end_lineno - 1]
            _seg.append(_lines[_n.end_lineno - 1].encode()[:_n.end_col_offset].decode("utf-8", "replace"))
            _tail = "\n".join(_seg)
    exec(compile(_tree, _CELL, "exec"), _g)
    if _tail is not None:
        _val = eval(compile(_tail, _CELL, "eval"), _g)
        if _val is not None:
            _out.append(_bundle(_val))
except SystemExit as _e:
    _rc = _e.code if isinstance(_e.code, int) else (0 if _e.code is None else 1)
except BaseException as _e:
    import traceback  # lazy: only on an uncaught error
    _tb = _e.__traceback__
    while _tb is not None and _tb.tb_frame.f_code.co_filename != _CELL:
        _tb = _tb.tb_next
    sys.stderr.write("".join(traceback.format_exception(type(_e), _e, _tb)))
    _rc = 1
try:
    if "matplotlib.pyplot" in sys.modules:  # only if the cell actually used pyplot
        import base64, io  # lazy: matplotlib was already imported, so this is not the hot path
        _plt = sys.modules["matplotlib.pyplot"]
        for _fig in _plt.get_fignums():
            _buf = io.BytesIO()
            _plt.figure(_fig).savefig(_buf, format="png")
            _out.append({"image/png": base64.b64encode(_buf.getvalue()).decode()})
except Exception:
    pass
try:
    _parts = ["{" + ",".join(_js(str(_k)) + ":" + _js(str(_v)) for _k, _v in _d.items()) + "}" for _d in _out]
    open(_RES, "w", encoding="utf-8").write("[" + ",".join(_parts) + "]")
except Exception:
    pass
sys.exit(_rc)
'''

# Persistent-kernel driver (warm-start: kill the ~10 ms CPython boot). Unlike _PY_RUNNER (a fresh
# interpreter per call), this runs ONCE inside a long-lived box and then services many cells from one
# resident process, so in-memory state PERSISTS across cells (a REPL/notebook, not a fresh box) and the
# per-cell cost drops to sub-millisecond. It is warm, so its imports are paid once at startup (not on any
# hot path), which is why it can freely `import json/ast/io/base64` where _PY_RUNNER hand-rolls them.
# Protocol on the box's stdin/stdout (length-prefixed frames): host writes `<n>\n` + n UTF-8 bytes of
# cell source; the driver execs it (capturing stdout/stderr into buffers, the trailing expression, every
# display(), and matplotlib figures) and writes back `<m>\n` + m UTF-8 bytes of a JSON reply
# {stdout, stderr, rc, results:[mime-bundle,...], trunc:bool}. User prints go to a buffer, never the real
# stdout, so the control channel stays clean. Any per-cell error is confined; the driver keeps serving.
#
# `__KERN_OUTCAP__` / `__KERN_RESCAP__` are substituted by the HOST before the driver is written into the
# workspace (see `_kernel_driver`). They exist because this one template serves two callers with different
# contracts. A persistent `Kernel` keeps the historical 64 MiB drain cap and an effectively unbounded
# results budget, so its behaviour is unchanged. A PREWARMED one-shot box (`_WarmBox`) substitutes the
# session's own `max_output_bytes` / results cap, because that path has to be observationally identical to
# the cold `run_code` it replaces: the cold path TRUNCATES oversized output and reports `truncated=True`,
# and a fast path that instead faulted on the same cell would be a silent semantic change.
_PY_KERNEL_DRIVER = r'''
import sys, io, json, base64, builtins, ast, os, threading
_g = {"__name__": "__main__"}
_out = []
def _bundle(o):
    d = {}
    for meth, key in (("_repr_html_", "text/html"), ("_repr_markdown_", "text/markdown"),
                      ("_repr_svg_", "image/svg+xml"), ("_repr_latex_", "text/latex")):
        try:
            fn = getattr(o, meth, None)
            if callable(fn):
                v = fn()
                if isinstance(v, str) and v:
                    d[key] = v
        except Exception:
            pass
    try:
        fn = getattr(o, "_repr_json_", None)
        if callable(fn):
            v = fn()
            if v is not None:
                d["application/json"] = v if isinstance(v, str) else json.dumps(v)
    except Exception:
        pass
    for meth, key in (("_repr_png_", "image/png"), ("_repr_jpeg_", "image/jpeg")):
        try:
            fn = getattr(o, meth, None)
            if callable(fn):
                v = fn()
                if v:
                    raw = v if isinstance(v, (bytes, bytearray)) else str(v).encode()
                    d[key] = base64.b64encode(raw).decode()
        except Exception:
            pass
    if "text/plain" not in d:
        try:
            d["text/plain"] = repr(o)
        except Exception:
            d["text/plain"] = "<unrepresentable>"
    return d
def display(o=None, **kw):
    if o is not None:
        _out.append(_bundle(o))
builtins.display = display
# Make the CONTROL channel private so user code (a raw os.write, a C extension, a subprocess reading
# stdin) can NEVER corrupt a reply on stdout nor steal a cell off stdin. dup the real stdin(0)/stdout(1)
# to close-on-exec control fds; then point fd 0 at /dev/null and fd 1/2 at pipes drained in the
# background, so raw/subprocess output is CAPTURED (and >64 KiB never deadlocks) instead of hitting the
# control channel. Uses only fds 0/1 (which always survive kern's box setup) and re-plumbs inside the box.
# Running the driver with -c puts '' (the current directory, resolved at import time) at sys.path[0],
# while a script run by path puts the script's DIRECTORY there. The one-shot runner is a file in the
# workspace, so its cells see an absolute /workspace; pin the same absolute entry here so an import
# behaves identically whichever way the driver was started. Started BY PATH this is a no-op.
if sys.path and sys.path[0] == "":
    sys.path[0] = os.getcwd()
_ctrl_in = os.dup(0)
_ctrl_out = os.dup(1)
os.set_inheritable(_ctrl_in, False)
os.set_inheritable(_ctrl_out, False)
_nul = os.open(os.devnull, os.O_RDONLY)
os.dup2(_nul, 0)
os.close(_nul)
_u1r, _u1w = os.pipe()
os.dup2(_u1w, 1)
os.close(_u1w)
_u2r, _u2w = os.pipe()
os.dup2(_u2w, 2)
os.close(_u2w)
_CAP = __KERN_OUTCAP__
_RESCAP = __KERN_RESCAP__
_MARK = b"\x00\x01KRNCELLDONE\x01\x00"  # per-cell barrier sentinel written to user fd 1/2 after exec
_ulock = threading.Lock()
_ubuf = {1: bytearray(), 2: bytearray()}
_mevt = {1: threading.Event(), 2: threading.Event()}
# Set by the drain threads when they cut a buffer at _CAP, read+reset by the cell loop under _ulock. A
# list (not a bare name) because the drainers rebind nothing: they mutate this one shared cell.
_tcut = [False]
def _drain(fd, key):
    while True:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        with _ulock:
            _b = _ubuf[key]
            _b += chunk
            _i = _b.find(_MARK)
            if _i >= 0:
                del _b[_i:_i + len(_MARK)]  # strip the barrier sentinel; signal the cell it is drained
                _mevt[key].set()
            if len(_b) > _CAP:
                del _b[_CAP:]
                _tcut[0] = True
threading.Thread(target=_drain, args=(_u1r, 1), daemon=True).start()
threading.Thread(target=_drain, args=(_u2r, 2), daemon=True).start()
_MAIN_PID = os.getpid()  # a cell that raw os.fork()s copies this whole process; the child must NOT re-enter
_rin = os.fdopen(_ctrl_in, "rb")
def _read():
    line = _rin.readline()
    if not line:
        return None
    n = int(line.strip())
    buf = b""
    while len(buf) < n:
        chunk = _rin.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf.decode("utf-8")
def _write(obj):
    b = json.dumps(obj).encode("utf-8")
    _data = memoryview(str(len(b)).encode() + b"\n" + b)
    while _data:
        _data = _data[os.write(_ctrl_out, _data):]
# Readiness. Popen returns when the FORK happens, not when kern has built the box and CPython has
# booted inside it, so a pool that published a box on Popen alone would hand out boxes that are still
# starting - and the caller would pay the remainder of that start on its own clock, which is the exact
# cost prewarming exists to remove. This frame is the only signal that the interpreter is actually at the
# prompt. Emitted only when the host asked for it (see __KERN_HELLO__): a persistent Kernel does not
# read one, and an unexpected frame there would be consumed as the first cell's reply.
if __KERN_HELLO__:
    _write({"hello": 1})
while True:
    _code = _read()
    if _code is None:
        break
    _out.clear()
    with _ulock:
        _m1, _m2 = len(_ubuf[1]), len(_ubuf[2])
        _tcut[0] = False  # a cut belongs to the cell it happens in, so clear it at the cell boundary
    _so, _se = io.StringIO(), io.StringIO()
    _rc = 0
    _oo, _oe, _oi = sys.stdout, sys.stderr, sys.stdin
    sys.stdout, sys.stderr = _so, _se
    # Point user stdin at an empty stream so input()/sys.stdin.read() gets EOF instead of consuming the
    # NEXT control frame off the real pipe (which would deadlock the kernel and desync the protocol).
    sys.stdin = io.StringIO("")
    try:
        _tree = ast.parse(_code, "<cell>", "exec")
        _tail = None
        if _tree.body and isinstance(_tree.body[-1], ast.Expr):
            _tail = ast.Expression(_tree.body.pop().value)
            ast.fix_missing_locations(_tail)
        exec(compile(_tree, "<cell>", "exec"), _g)
        if _tail is not None:
            _v = eval(compile(_tail, "<cell>", "eval"), _g)
            if _v is not None:
                _out.append(_bundle(_v))
    except SystemExit as _e:
        _rc = _e.code if isinstance(_e.code, int) else (0 if _e.code is None else 1)
    except BaseException as _e:
        import traceback
        _tb = _e.__traceback__
        while _tb is not None and _tb.tb_frame.f_code.co_filename != "<cell>":
            _tb = _tb.tb_next
        _se.write("".join(traceback.format_exception(type(_e), _e, _tb)))
        _rc = 1
    finally:
        sys.stdout, sys.stderr, sys.stdin = _oo, _oe, _oi
    if os.getpid() != _MAIN_PID:
        # A cell called raw os.fork(): this is the CHILD. It must not re-enter the loop, write a reply,
        # or touch the control channel (that would spawn a rogue driver clone corrupting the protocol).
        os._exit(0)
    try:
        if "matplotlib.pyplot" in sys.modules:
            _plt = sys.modules["matplotlib.pyplot"]
            for _num in _plt.get_fignums():
                _b = io.BytesIO()
                _plt.figure(_num).savefig(_b, format="png")
                _out.append({"image/png": base64.b64encode(_b.getvalue()).decode()})
    except Exception:
        pass
    # Barrier: write the sentinel to fd 1/2 and wait until the drainers have consumed up to it, so this
    # cell's raw/subprocess output is FULLY captured (not racily missed) before we snapshot. The captured
    # raw bytes are appended AFTER the precise in-order print() capture from the redirected sys.stdout.
    _mevt[1].clear()
    _mevt[2].clear()
    try:
        os.write(1, _MARK)
        os.write(2, _MARK)
    except OSError:
        pass
    _mevt[1].wait(2.0)
    _mevt[2].wait(2.0)
    with _ulock:
        _r1 = bytes(_ubuf[1][_m1:])
        _r2 = bytes(_ubuf[2][_m2:])
        _tr = _tcut[0]
    # sys.stdout is a StringIO, so _CAP (which bounds only the raw-fd drain) never bounded a cell that
    # printed through it: printing a gigabyte built the whole string into the reply. Cut BOTH streams at
    # the same cap and say so, which is what the cold path's capped reader does.
    _o1 = _so.getvalue() + _r1.decode("utf-8", "replace")
    _o2 = _se.getvalue() + _r2.decode("utf-8", "replace")
    if len(_o1) > _CAP:
        _o1 = _o1[:_CAP]
        _tr = True
    if len(_o2) > _CAP:
        _o2 = _o2[:_CAP]
        _tr = True
    # Results are bounded bundle by bundle rather than by serializing the whole list and measuring it: a
    # single json.dumps of an oversized list would build the entire payload in the box before anything
    # could reject it. A bundle that alone exceeds the budget is dropped, not truncated mid-JSON.
    # A _RESCAP of 0 or less means unbounded and skips the measuring entirely: a persistent Kernel keeps
    # its historical contract (the host's frame cap is the only bound) AND does not pay a second
    # json.dumps per bundle, which measuring every bundle would cost it on a large figure.
    if _RESCAP <= 0:
        _res = list(_out)
    else:
        _res = []
        _rsz = 0
        for _bnd in _out:
            try:
                _bl = len(json.dumps(_bnd))
            except Exception:
                continue
            if _rsz + _bl > _RESCAP:
                _tr = True
                break
            _res.append(_bnd)
            _rsz += _bl
    _write({"stdout": _o1, "stderr": _o2, "rc": _rc, "results": _res, "trunc": _tr})
'''


# The raw-fd drain cap a PERSISTENT kernel has always used. Named rather than repeated so the one place
# that must not drift from the shipped behaviour says which number it is and why.
_KERNEL_DRAIN_CAP = 64 * 1024 * 1024


def _kernel_driver(out_cap: int, res_cap: int, *, hello: bool = False) -> str:
    """Materialize :data:`_PY_KERNEL_DRIVER` for one caller's output budget and handshake.

    Two callers, two contracts, one template. Substitution (not a runtime read) because the driver runs
    INSIDE the box, where an environment variable is workload-writable: the caps have to be baked in by
    the host or they are not caps. The values are stringified ints and a literal ``0``/``1`` from our own
    call sites, never from box input, so the generated source cannot be influenced from inside the
    sandbox."""
    return (
        _PY_KERNEL_DRIVER.replace("__KERN_OUTCAP__", str(int(out_cap)))
        .replace("__KERN_RESCAP__", str(int(res_cap)))
        .replace("__KERN_HELLO__", "1" if hello else "0")
    )

# Host paths a `-v` mount must never target - mounting the host's real root/config/secrets into a
# sandbox defeats the point; the docker socket is the classic escape. A footgun guard: refused even
# when asked. Absolute, normalized host-SOURCE paths.
_REFUSED_MOUNT_SOURCES = {
    "/",
    "/etc",
    "/root",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
    "/var/run/docker.sock",
    "/run/docker.sock",
}


# CREDENTIAL DIRECTORIES, REFUSED AS A COMPONENT ANYWHERE IN THE SOURCE. The set above is absolute
# paths, so it refused `$HOME` and accepted `$HOME/.ssh`: MEASURED, a box mounted with
# `mounts={"~/.ssh": "/x"}` listed `id_ed25519` and `authorized_keys`. Refusing the parent and allowing
# its most sensitive child is the wrong way round, and it is the exact scenario a prompt-injected agent
# is steered into ("read ~/.aws"). These are matched by NAME because they live under a per-user home, and
# any path that has one as a component (the directory itself or anything below it) is refused.
#
# NO ESCAPE HATCH, the same as `/etc`: what a job legitimately needs is ONE credential, and the way to
# give it one is to write that file into the workspace (or mount a directory holding only it), which is
# also the only shape an independent test can check.
#
# THE LIST WAS SHORT OF THE PROMISE ABOVE IT, and the asymmetry is what gave it away: AWS refused,
# Azure refused, GCP accepted. MEASURED against the published 0.2.27 with each directory CREATED
# first, because a refusal that is really "source does not exist" is a skip wearing a pass - that is
# how `~/.config/gcloud` read as covered on a host that has no gcloud. Ten candidates were accepted;
# the ones that are nothing but credentials are added here.
#
# `~/.config/<tool>` NEEDS THE PARENT, which is why there is a second set. `gcloud` and `gh` are not
# dotfiles, and refusing a bare `gh` component anywhere would refuse `~/projects/gh/src` - a guard
# that fires on ordinary work gets switched off, and then it guards nothing.
#
# DELIBERATELY NOT ADDED: `.cargo`, `.m2`, `.gem`. Each holds ONE credential file next to a package
# cache people legitimately mount (`~/.cargo/registry` for an offline build), so refusing the
# directory would break a real use and push callers off the guard entirely. Naming the residual gap
# beats a refusal nobody keeps: mounting `~/.cargo` still exposes `credentials.toml`, and closing
# that needs a different mechanism than a path component.
_REFUSED_MOUNT_COMPONENTS = {
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".azure",
    ".password-store",
    ".netrc",
    ".git-credentials",
    ".pypirc",
    ".npmrc",
    ".oci",
    ".terraform.d",
    ".databrickscfg",
    ".boto",
    ".s3cfg",
    ".rclone.conf",
}

# `(parent, child)` pairs, refused when they appear CONSECUTIVELY in the source. For tools whose
# credentials live under `~/.config/<tool>` with a name too generic to match on its own.
_REFUSED_MOUNT_PAIRS = {
    (".config", "gcloud"),
    (".config", "gh"),
    (".config", "doctl"),
    (".config", "rclone"),
}


class SandboxError(RuntimeError):
    """A PROGRAMMER/config error, RAISED: bad argument, illegal mount, `kern` not installed, or the box
    FAILED TO START (kern exits 125 - a mount refused at runtime, an unmappable ``--user``, a seccomp or
    AppArmor setup error). A box that never started means the user's code never ran, so it raises rather
    than return a hollow result (empty stdout, exit 125).

    Runtime sandbox events where the code DID run (timeout, blocked escape, OOM-kill) are NOT raised -
    they are reported as data in ``ExecutionResult.fault`` (a :class:`SandboxFault`). Raising those would
    force every ``run_code`` into a try/except for what is a normal, expected outcome of untrusted code.
    """


class MountRefused(SandboxError):
    """A requested host mount was refused as unsafe (sensitive source, or a relative/escaping path)."""


@dataclass
class SandboxFault:
    """A SANDBOX-level event, reported as DATA on ``ExecutionResult.fault``. ``None`` means the sandbox
    did nothing: any non-zero exit is the user's code. NOTE: ``startup_failed`` is the one type that is
    RAISED (:class:`SandboxError`) rather than returned - a box that never started ran no code, so the
    result would be hollow - so a fault actually seen on a result is only ``timeout``/``oom``/
    ``escape_blocked``/``killed``. The label is kept here because it is how the box-start failure is
    classified internally.

    ``startup_failed`` is decided from an UNFORGEABLE kern signal (a byte on ``KERN_STARTED_FD`` that a
    workload can neither write nor suppress). Against a kern too old to send it, the binding falls back
    to a stderr heuristic that can only OVER-report - a workload can make its own exit look like a start
    failure - never MISS a real one, so it fails in the safe direction. Pair this binding with the
    matching (or newer) kern release for the unforgeable guarantee."""

    type: Literal["timeout", "oom", "escape_blocked", "killed", "startup_failed", "exec_failed"]
    message: str


@dataclass
class FileInfo:
    """A file in the workspace and how this step touched it."""

    path: str  # workspace-relative path
    size: int
    change: Literal["created", "modified"]


@dataclass
class Result:
    """A rich, mime-typed value captured from ``run_code`` (Python), the way a Jupyter/E2B cell captures
    output: the value of the code's last bare expression, every ``display(obj)`` call, and every open
    matplotlib figure. ``data`` maps a MIME type to its payload: text/* and application/json are strings,
    image/* are base64 strings (use the ``.png``/``.jpeg`` byte accessors). A single value can carry
    several representations (e.g. a DataFrame has both text/plain and text/html)."""

    data: dict[str, str]

    @property
    def text(self) -> "str | None":
        return self.data.get("text/plain")

    @property
    def html(self) -> "str | None":
        return self.data.get("text/html")

    @property
    def markdown(self) -> "str | None":
        return self.data.get("text/markdown")

    @property
    def svg(self) -> "str | None":
        return self.data.get("image/svg+xml")

    @property
    def json(self) -> "str | None":
        return self.data.get("application/json")

    @property
    def png(self) -> "bytes | None":
        v = self.data.get("image/png")
        return base64.b64decode(v) if v else None

    @property
    def jpeg(self) -> "bytes | None":
        v = self.data.get("image/jpeg")
        return base64.b64decode(v) if v else None

    def formats(self) -> "list[str]":
        """The MIME types this value was captured as, most-rich first is not guaranteed."""
        return list(self.data.keys())


# The prefixes of stderr lines KERN writes about itself, as opposed to lines the workload wrote.
# ONE definition, used twice and for two different purposes, which is why it is a module constant:
# `ExecutionResult.code_stderr` subtracts these to build what a model should read, and
# `_looks_like_startup_failure` skips them so a benign note cannot be read as a box that failed to
# start. Those two must agree by construction; when they were separate lists they did not have to.
_KERN_DIAGNOSTICS = ("kern: security-profile=", "kern: warning:", "kern: note:")

# The two prefixes kern's CLI writes AT COLUMN 0, and the whole vocabulary of "kern is speaking".
# `kern-cli/src/main.rs` prints every error it ever reports through one `eprintln!("error: {}", ...)`,
# and `ui::scrub_message` INDENTS every continuation line precisely so that a hostile value inside a
# message cannot forge a line at column 0. So this is the complete set, by construction, and matching
# it at column 0 is what keeps the runtime's guarantee worth something.
#
# WHAT THIS REPLACED, and why the shape was the defect: a list of eleven message OPENINGS
# (`error: pull:`, `error: box:`, `error: config:` ...). Every one of them was added after a caller
# measured a call that came back `fault=None`, because a whitelist of openings is an attempt to
# enumerate the error TEXTS of a binary that has hundreds of them behind a single printer, and it can
# never be closed. An independent test closed the argument in one command: `image=""` prints
# `error: bad image reference: empty`, which is not in any of the eleven, so a box that never existed
# came back indistinguishable from a script that exited 1.
_KERN_SPEAKING = ("error: ", "kern:")

# The sentence kern prints when it has READ the kernel's OOM counter for this box's own cgroup, as
# opposed to anything the SDK could infer from an exit code. Kept as one constant because it is a
# contract between two programs: if kern rewords it, this stops recognising a real OOM and starts
# reporting `killed`, which is wrong in the safe direction but still wrong.
_KERN_OOM_MARKER = "killed by the kernel's OOM killer"


# kern writes this byte to `KERN_ALIVE_FD` the moment it accepts the descriptor, before any box setup.
# It is what tells "the setup has not finished" from "this binary does not speak the protocol": an older
# kern never writes to that pipe AND never closes it, so the pipe is open and silent in both cases.
_ALIVE_ACK = b"A"

# The three answers `_alive_state` can give, spelled once so a caller cannot invent a fourth.
_ALIVE_PAST_SETUP = "past-setup"  # the workload ran (EOF at execvp), or kern reported setup failed
_ALIVE_IN_SETUP = "in-setup"      # kern acknowledged the channel and is still BUILDING the box
_ALIVE_UNKNOWN = "unknown"        # nothing on the pipe: a kern that predates this channel


# Terminal escapes and control characters have no meaning to a model and every use to whoever is
# steering it: a cell printing `\x1b[2J` or smuggling a NUL is not producing output, it is producing a
# payload for whatever renders the transcript. Spelled HERE because three renderers need it (the
# LangChain tool, the MCP server, and any caller building its own prompt) and a copy per renderer is
# how one of them ends up without it: MEASURED on 2026-09-12, `SECURITY.md` claimed the MCP server
# stripped these and its own framing, the LangChain renderer did both, and the MCP server did neither.
# THE FRAMING BOTH AGENT SURFACES EMIT, spelled here ONCE because each of them has to neutralise ALL of
# it. Measured on 2026-09-13 with a release checklist: a cell that printed `[sandbox: oom]` (the LangChain
# renderer's verdict marker) came back untouched through the MCP server, which neutralised only its own
# `[exit N]`/`[stderr]` family. Sharing four of them left the same hole two markers wide: the LangChain
# renderer still let through the MCP server's TRUNCATION note and its session-RESET note, and both are
# claims about the sandbox (one about completeness, one about the session) that a cell could then make
# about itself. A model does not know which surface it is reading, and both families are documented as
# OURS in this one package, so the list is one list and each surface neutralises every entry.
_FRAME_LC_FAULT = "[sandbox: "        # langchain: `[sandbox: oom]`
_FRAME_MCP_EXIT = "[exit "            # mcp: `[exit 137, sandbox fault: ...]`
_FRAME_MCP_STDERR = "[stderr]"
_FRAME_MCP_RICH = "[rich result]"
_FRAME_MCP_TRUNC = "[output truncated: reply-size cap]"
_FRAME_MCP_RESET = "[the session's interpreter ended on that cell "
_FRAME_MCP_IMG_TAIL = " image result(s) omitted: reply-size cap]"
# The two truncation notices are INLINE rather than line-anchored, and each surface words its own; both
# are in the shared list for the same reason as the rest.
_FRAME_MCP_CLIP = ("...[truncated ", " chars]")
_FRAME_LC_CUT = ("... ", " characters of output, cut to fit ...")

# Line-anchored markers: at the START of a line is where the surface itself writes them, so an anchored
# match is what tells "the frame" from a sentence that merely mentions it.
_FRAME_LINE_MARKS = (
    _FRAME_LC_FAULT,
    _FRAME_MCP_EXIT,
    _FRAME_MCP_STDERR,
    _FRAME_MCP_RICH,
    _FRAME_MCP_TRUNC,
    _FRAME_MCP_RESET,
)


# The "invisible" leading run a cell can put before a marker to slip it past the line anchor: ASCII
# space and tab, the Unicode spaces (NBSP, the en/em family, ideographic space) and the zero-width
# characters (ZWSP/ZWNJ/ZWJ, BOM). The `^` anchor alone catches `[sandbox: oom]` at column 0 but
# MISSES ` [sandbox: oom]` (one leading space), and a model reads the two identically - the space is
# invisible to it - so a cell forges a verdict by printing one character first. Stripped for the
# anchor AND for the label below, because a line that is ONLY invisibles + marker is the frame
# indented, not a sentence that mentions it ("the error [sandbox: oom]" keeps a WORD before the
# marker and is left alone).
_INVIS = (
    "\t \xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
    "\u2008\u2009\u200a\u200b\u200c\u200d\u202f\u205f\u3000\ufeff"
)
_LEAD = "[" + re.escape(_INVIS) + "]*"

# TWO PATTERNS, not one, because the two surfaces neutralise these differently ON PURPOSE and the
# difference is worth keeping: a line-anchored frame is LABELLED (the reader still sees what the code
# printed), while a truncation notice is REPLACED, since leaving its words in place would leave the claim
# about completeness standing. What is shared is the RECOGNITION: a marker added to either surface is
# recognised by both from this one edit, which is what the reset note needed and did not have.
_FORGED_LINE_FRAME = re.compile(
    "|".join(
        [*(r"^" + _LEAD + re.escape(m.rstrip()) for m in _FRAME_LINE_MARKS),
         r"^" + _LEAD + r"\[\d+" + re.escape(_FRAME_MCP_IMG_TAIL)]
    ),
    re.MULTILINE,
)
_FORGED_CUT_NOTICE = re.compile(
    "|".join(
        [re.escape(_FRAME_MCP_CLIP[0]) + r"\d+" + re.escape(_FRAME_MCP_CLIP[1]),
         re.escape(_FRAME_LC_CUT[0]) + r"\d+" + re.escape(_FRAME_LC_CUT[1])]
    )
)


_ANSI_ESCAPES = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-Z\\-_])")
_CONTROL_BYTES = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _neutralise_terminal(text: str) -> str:
    """One box-produced string with terminal escapes and control bytes removed, newlines normalised.

    What it does NOT do is each renderer's own job: neutralising the FRAMING that renderer adds around
    this text. Only the renderer knows its own markers, and a box that prints them forges a verdict
    about itself in the channel a model uses to decide. kern went to the trouble of an unforgeable
    descriptor byte to tell `oom` from `killed`; handing the forgery back for free at the text layer
    would undo it.

    NOT closed here, and not closable at this layer: ordinary prompt injection. A run whose output is
    `[system] ignore your instructions` is a run that printed a string, and no filter separates that
    from a program legitimately printing the same characters without destroying real output.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _CONTROL_BYTES.sub("", _ANSI_ESCAPES.sub("", text))


def _parse_started_bytes(sig: bytes) -> "tuple[bool, int, int | None, int | None]":
    """kern's KERN_STARTED_FD payload, as ``(box_started, cap_signal, oom_signal, workload_signal)``.

    THE WIRE FORMAT IS SPELLED HERE AND NOWHERE ELSE, because it has grown twice in one day (the OOM
    outcome, then the workload's signal) and each time a reader that had its own copy of the layout was
    left behind: one still asked for three bytes where kern wrote four, silently leaving one in the pipe.

    byte 0 = the box started (kern reached the `Ok` arm with a code that is not 125)
    byte 1 = the memory-cap enforcement signal: 0 undetermined, 1 enforced, 2 requested but not enforced
    byte 2 = the OOM outcome: 1 iff the kernel's OOM killer fired against this box's own cgroup
    byte 3 = the signal that terminated the workload, 0 if it exited on its own

    A SHORT read is an OLDER kern, not a malformed one, and the two OUTCOME bytes read `None` when
    absent rather than 0, because for them "kern did not say" and "kern said no" are different facts and
    a caller acts differently on each. The enforcement byte keeps 0 for absent: it already spells
    "undetermined" as a value of its own.

    THE OOM BYTE LEARNED THIS THE EXPENSIVE WAY. It returned 0 for both cases, so the only way to keep
    an older binary working was to consult the stderr sentence whenever the byte was not 1 - which meant
    consulting it against a binary that had just said 0. A cell printing kern's own OOM sentence then
    turned an outside kill into `fault=oom`. See :func:`_oom_verdict`.
    """
    return (
        len(sig) >= 1 and sig[0] == 1,
        sig[1] if len(sig) >= 2 else 0,
        sig[2] if len(sig) >= 3 else None,
        sig[3] if len(sig) >= 4 else None,
    )


def _oom_verdict(oom_signal: "int | None", stderr: str, *, kern_wrote_payload: bool) -> bool:
    """Did the kernel's OOM killer take this box? The ONE place the byte and the sentence are combined.

    Three states, and each one names what the SUBJECT did rather than what we hope:

    1. the byte arrived: it decides, and the stderr sentence is not read at all;
    2. no byte and kern wrote NOTHING: kern never reached its teardown, so it printed no sentence there
       either, and an OOM line in this stderr is the workload's own text. Not an OOM;
    3. no byte but kern DID write a payload: a binary older than the byte, reporting through the only
       channel it has. The sentence decides.

    MEASURED on 2026-09-12 with the four-byte binary, when these were combined by `or`: a cell that
    wrote kern's own OOM sentence to its stderr and was then stopped from outside came back `fault=oom`
    while kern's third byte said 0. That is the inverted verdict the byte was introduced to close,
    re-opened by the sandboxed code in one line: an agent reading it retries with more memory a kill
    that had nothing to do with memory.

    AND THE FIRST REPAIR OF THAT WAS NOT ENOUGH, which is why case 2 exists. Preferring the byte is not
    the same as knowing whether there is one: an outside kill takes the box before teardown, so the new
    binary ALSO arrives here with no byte, and the forgery still worked. The fact that separates them
    travels on the same wire: kern's payload starts with the byte that says a box ran, so "kern wrote
    nothing" is knowable without asking the binary its version.

    The bound that remains is the old binary's and it is narrow, and it is MEASURED rather than reasoned:
    against kern v0.9.32, a cell that writes the sentence and then chooses `exit 137` reports `oom`,
    where the same cell without the sentence reports `killed`. That is case 3, a run kern DID tear down,
    where the sentence is the only channel that binary has. Both outcomes are sandbox faults, and
    timeout / blocked-escape are decided by exit code before any text is read, so the worst case is a
    caller misleading itself about its own kill.
    """
    if oom_signal is not None:
        return oom_signal == 1
    if not kern_wrote_payload:
        # kern wrote NOTHING at its teardown, so it never reached the place where it would have printed
        # the sentence either: an OOM line in this stderr cannot have come from kern. MEASURED, and this
        # is what the first repair missed: an outside `kern stop` kills the box before teardown, so the
        # NEW binary also arrives here with no byte, and a cell that had printed the sentence in advance
        # still turned its own `killed` into `oom`.
        return False
    return _kern_reported_oom(stderr)


def _read_teardown_bytes(fd: int, wait_s: float = 2.0) -> "tuple[bool, int, int | None, int | None]":
    """kern's teardown bytes off a KERN_STARTED_FD read end, parsed as
    :func:`_parse_started_bytes` does, ``(False, 0, None, None)`` on EOF, timeout or any error.

    THE FIRST ELEMENT IS WHETHER KERN WROTE AT ALL, and it is returned because a caller needs it: kern
    writes this payload at its teardown, so nothing on the pipe means kern never got there (killed from
    outside), and everything kern would have PRINTED at that moment is absent too. A reader that
    discarded this could not tell that from an older binary.

    ONE READER FOR ONE PROTOCOL. There were two, a few lines apart and identical but for what they
    returned, and when kern grew a fourth byte only one of them was updated: the other kept asking for
    three and left a byte in the pipe for whoever read next. Two readers of one wire format is the same
    defect shape as two lists that must agree, and this file already carries that lesson twice.

    Bounded by `select`, because kern writes these only at the box's TEARDOWN: called while the box is
    live it would block, and called after our own kill it answers for a process we already reaped. The
    ``None`` for the signal is not a zero: it means this kern does not report it.
    """
    if fd < 0:
        return False, 0, None, None
    try:
        ready, _, _ = select.select([fd], [], [], wait_s)
        if not ready:
            return False, 0, None, None
        sig = os.read(fd, 4)
    except OSError:
        return False, 0, None, None
    return _parse_started_bytes(sig)


def _alive_state(fd: int) -> str:
    """Where was kern when this was called, read off the `KERN_ALIVE_FD` pipe. Never blocks.

    ``_ALIVE_PAST_SETUP`` when the pipe is at EOF (the box child's ``FD_CLOEXEC`` closed it at
    ``execvp``, so the workload was running) or carries a byte beyond the ack (kern reported that setup
    or exec failed). Either way kern is past the phase that can block.

    ``_ALIVE_IN_SETUP`` when the ack arrived and nothing else did. That is the state nothing could
    observe before, and the only one that changes a verdict.

    ``_ALIVE_UNKNOWN`` when the pipe is silent: an older kern, which neither writes nor closes it. That
    case must keep the caller's previous verdict, and conflating it with ``_ALIVE_IN_SETUP`` would have
    reported every slow workload on an older binary as a box that never started.

    CALLED WHILE KERN IS ALIVE. After the teardown every write end is closed and the answer would be
    EOF for a box that never started, which is the wrong answer arrived at by asking too late. Anything
    that cannot be measured answers ``_ALIVE_UNKNOWN``, so a failed poll can only ever leave the old
    verdict standing.
    """
    if fd < 0:
        return _ALIVE_UNKNOWN
    acked = False
    try:
        while True:
            ready, _, _ = select.select([fd], [], [], 0)
            if not ready:
                return _ALIVE_IN_SETUP if acked else _ALIVE_UNKNOWN
            chunk = os.read(fd, 64)
            if chunk == b"":
                return _ALIVE_PAST_SETUP  # EOF: the workload exec'd
            if chunk.replace(_ALIVE_ACK, b""):
                return _ALIVE_PAST_SETUP  # a byte beyond the ack: kern said setup failed
            acked = True
    except OSError:
        return _ALIVE_UNKNOWN


def _kern_reported_oom(stderr: str) -> bool:
    """True iff KERN said the kernel's OOM killer took this box against its own memory cap.

    The ONE definition of "this was an OOM", used by all three death paths (the one-shot exit-code
    classifier, the resident kernel's death, and a pool box that died) so they cannot drift into
    disagreeing about the same box. It is an OBSERVATION - kern reads `memory.events` and says so -
    where the SDK can only infer, and the inference it replaced was measured wrong in both
    directions: `kern stop` during a cell was reported `oom`, while a real OOM on the resident
    kernel was reported as a box that failed to start.

    Anchored on kern's own `kern:` line prefix, which the real line carries (measured verbatim:
    `kern: the workload was killed by the kernel's OOM killer against this box's own memory cap.`),
    so a cell that merely PRINTS about OOM killers in prose does not match. MINUS the benign
    diagnostics, which a positive control caught: `kern: note: <anything the note mentions>` starts
    with the prefix too, and a note that quotes the sentence is kern TALKING about an OOM, not
    reporting one. Same subtraction, from the same one list, as `_looks_like_startup_failure`.

    THE FALLBACK, NOT THE AUTHORITY. Against a kern that writes the 3rd KERN_STARTED_FD byte the
    verdict comes from there instead, on a pipe the workload never holds. This is what covers an older
    binary, and it is forgeable in exactly one direction: a workload that writes the whole
    `kern:`-prefixed sentence itself turns its own `killed` into `oom`. Both are sandbox faults, and
    timeout / blocked-escape are decided by exit code before any text is read, so the worst case is a
    caller misleading itself about its own kill. Same bound, for the same reason, as
    `_looks_like_startup_failure` and `_exec_failure`.
    """
    for line in stderr.splitlines():
        s = line.lstrip()
        if s.startswith("kern:") and not s.startswith(_KERN_DIAGNOSTICS) and _KERN_OOM_MARKER in s:
            return True
    return False


@dataclass
class ExecutionResult:
    """The outcome of one ``run_code``/``run``. ``fault`` is the source of truth for "did the SANDBOX
    act"; ``exit_code``/``stdout`` are what the user's code did. ``success`` requires both clean."""

    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    fault: SandboxFault | None = None
    files: list[FileInfo] = field(default_factory=list)
    truncated: bool = False  # stdout/stderr hit the capture cap and overflow was discarded
    results: list[Result] = field(default_factory=list)  # rich mime-typed values (Python run_code)

    @property
    def success(self) -> bool:
        """True iff the code exited 0 AND no sandbox fault fired."""
        return self.exit_code == 0 and self.fault is None

    @property
    def runtime_notes(self) -> "list[str]":
        """The lines on ``stderr`` that KERN wrote, not the code: the ``--security-profile`` banner
        and any ``warning:``/``note:`` diagnostic.

        The box's launcher and the workload share one stderr, so a note about overlayfs or an
        undelegated cgroup arrives interleaved with whatever the code printed. That is fine for a
        human reading a terminal and wrong for anything that feeds ``stderr`` to a model: an external
        audit found kern's own notes inside a LangChain tool result, where they cost context and can
        be mistaken for the program's own errors.

        Reported rather than removed. ``stderr`` still holds every byte in its original order, so
        nothing that used to be visible has become invisible; this and :attr:`code_stderr` are the
        two halves, for callers that need to tell the reporter's voice from the subject's.
        """
        return list(self._split_stderr()[1])

    @property
    def code_stderr(self) -> str:
        """``stderr`` with kern's own diagnostics removed: what the user's code actually wrote.

        This is what belongs in a model's context. A workload CAN forge a line that looks like one of
        kern's by printing the prefix itself, and the consequence of that is its line moving to
        :attr:`runtime_notes`: it cannot use the trick to inject text into this field, only to remove
        its own from it.

        THE OTHER DIRECTION, which the sentence above does not cover and an independent test named: the split
        works on lines, so it holds only for LINE-ALIGNED output. A workload that writes a partial line
        with no trailing newline, and is then interleaved with a `kern: warning:` on the shared stderr,
        produces ONE line that begins with the workload's text. That line does not match a prefix, so
        kern's warning lands here, framed by bytes the workload chose. Two writers on one fd make it
        racy rather than a reliable primitive, and it moves kern's voice into the code's half rather
        than the reverse, but the guarantee is line-aligned, not absolute. A file descriptor per writer
        is the only thing that would make it absolute.
        """
        return self._split_stderr()[0]

    def _split_stderr(self) -> "tuple[str, list[str]]":
        """Partition ``stderr`` ONCE into (what the code wrote, the lines kern wrote).

        One pass and one cache, for two reasons. The two public halves are a single partition, so
        computing them separately left two filters that had to agree by inspection rather than by
        construction. And each was O(n) on EVERY read: measured 16 ms on a 200k-line stderr, which one
        caller paid twice in a single statement before it was spotted.

        Keyed on the IDENTITY of the string it partitioned, so reassigning ``stderr`` recomputes rather
        than serving a stale answer. Stored through ``__dict__`` to stay out of the dataclass's fields,
        and therefore out of ``==`` and ``repr``: a cache that changed how two results compare would be
        a worse bug than the one it saves.

        ``split("\n")`` and NOT ``splitlines()``, for two independent reasons. It keeps the trailing
        newline (``splitlines()`` drops the empty final element, so ``"a\n"`` came back as ``"a"``
        while the Node binding returned ``"a\n"`` - a parity gap of exactly the kind the timeout exit
        code already had), and it splits on ``\n`` alone, where ``splitlines()`` also breaks on
        ``\r``, ``\v``, ``\f`` and ``\x1c``, none of which start a line as far as the two runtimes
        agree.
        """
        cached = self.__dict__.get("_stderr_split")
        if cached is not None and cached[0] is self.stderr:
            return cached[1], cached[2]
        kept: list[str] = []
        notes: list[str] = []
        for line in self.stderr.split("\n"):
            (notes if line.lstrip().startswith(_KERN_DIAGNOSTICS) else kept).append(line)
        joined = "\n".join(kept)
        self.__dict__["_stderr_split"] = (self.stderr, joined, notes)
        return joined, notes

    def __bool__(self) -> bool:
        return self.success


def _wait_for_exit(proc: "subprocess.Popen", timeout: "float | None") -> bool:
    """Block until ``proc`` exits, or until ``timeout`` seconds elapse. True iff it exited.

    WHY NOT ``Popen.wait(timeout=...)``
        CPython's timed wait does not block on the child: it polls with an exponential backoff
        (``delay = 0.0005``, then ``delay = min(delay * 2, remaining, .05)``), so its wake-ups fall
        at 0.5, 1.5, 3.5, 7.5, 15.5, 31.5, 63.5 ms. A box that exits in 12.3 ms is therefore not
        noticed until 15.5: 3.2 ms of pure sleep on every call, 26% of the wall time, plus a tail
        that doubles when the exit lands just after a poll. Measured over 200 identical calls before
        this helper existed: 188 at 15-16 ms, 10 at 31-32, 2 at 64, against 12.28 ms of real work
        for the same command run without the binding.

        A pidfd becomes readable the moment the process terminates, so one ``poll(2)`` with the
        deadline returns on the exit itself, with no sleeping at all, and the deadline is enforced
        by the kernel instead of by a backoff loop.

    WHY ``poll`` AND NOT ``select``
        ``select.select`` is bounded by ``FD_SETSIZE`` (1024) on the fd NUMBER, so a caller that
        embeds this binding in a process holding many sockets would get a ValueError out of a
        library that has nothing to do with its fd count. ``poll`` has no such limit.

    FALLBACK
        ``os.pidfd_open`` needs Linux 5.3, and Python 3.9 (this package's floor). If it is missing
        or refused (an old kernel, or a syscall filter in whatever sandbox the CALLER is itself
        running under), we fall back to the polling wait: slower, never wrong. kern's own seccomp
        denylist does not contain it, so a binding running nested inside a box keeps the fast path.
    """
    if proc.returncode is not None:
        return True  # already reaped by an earlier wait; nothing to wait for
    try:
        fd = os.pidfd_open(proc.pid, 0)
    except (AttributeError, OSError):
        # No pidfd here. Poll exactly as CPython would have, and keep the same contract.
        try:
            proc.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            return False
    try:
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        # poll() takes milliseconds. Round UP, never down: rounding a sub-millisecond deadline to 0
        # would turn a short timeout into an instant one and mislabel a healthy run as a timeout.
        # A negative timeout means "block forever", which is what timeout=None asks for.
        ms = -1 if timeout is None else int(timeout * 1000.0 + 0.999)
        # PEP 475: poll() is retried across EINTR with a recomputed deadline, so a signal arriving
        # mid-wait cannot cut the deadline short.
        if not poller.poll(ms):
            return False
    except OSError:
        # poll() itself failed. Degrade to the backoff wait rather than report an exit we did not
        # observe: claiming a timeout here would kill a healthy box.
        try:
            proc.wait(timeout=timeout)
            return True
        except subprocess.TimeoutExpired:
            return False
    finally:
        os.close(fd)
    # The child is a zombie at this point, so this reap returns at once and cannot poll.
    proc.wait()
    return True


class _CappedReader(threading.Thread):
    """Drain a pipe into a bounded buffer: keep at most ``cap`` bytes but KEEP reading past it
    (discarding overflow) so a flooding box never blocks on a full pipe. RAM is bounded to ``cap``.

    If ``on_data`` is given, every chunk is also delivered live (``read1`` returns as soon as any bytes
    are available, so it's prompt, not batched). The full (capped) buffer is STILL captured, so a caller
    can both stream and read ``result.stdout``.

    A CALLBACK EXCEPTION IS SWALLOWED AND REPORTED, which are two decisions and not one. Swallowed,
    because it must never kill the drain: the box would then block on a full pipe and hang. REPORTED,
    because it used to be swallowed in silence, so a caller whose callback raised on its first line
    got a run that succeeded, output that looked complete, and no indication their code never ran.
    An outside review found exactly that. One `warnings.warn` per reader, not per chunk, so a
    callback that raises on every line says it once."""

    def __init__(self, pipe, cap: int, on_data=None) -> None:
        super().__init__(daemon=True)
        self._pipe = pipe
        self._cap = cap
        self._on_data = on_data
        self.buf = bytearray()
        self.truncated = False
        self.callback_failed = False

    def run(self) -> None:
        # read1 (vs read) hands back each chunk as it arrives instead of blocking for a full 64 KiB, so
        # a streaming callback sees output live; it also drains a flooding box just as well.
        read = self._pipe.read1 if hasattr(self._pipe, "read1") else self._pipe.read
        try:
            while True:
                chunk = read(65536)
                if not chunk:
                    break
                if self._on_data is not None:
                    try:
                        self._on_data(bytes(chunk))
                    except Exception as e:  # noqa: BLE001 - a user callback must not break the drain
                        if not self.callback_failed:
                            self.callback_failed = True
                            warnings.warn(
                                f"the on_stdout/on_stderr callback raised "
                                f"{type(e).__name__}: {e}. The box kept running and its output was "
                                f"still captured, but this callback is not seeing it. Exceptions "
                                f"after the first are not reported.",
                                RuntimeWarning,
                                stacklevel=2,
                            )
                room = self._cap - len(self.buf)
                if room > 0:
                    self.buf += chunk[:room]
                if len(chunk) > room:
                    self.truncated = True
        except (ValueError, OSError):
            pass
        finally:
            try:
                self._pipe.close()
            except OSError:
                pass


# Binaries already identified as kern, keyed by (path, device, inode, size, mtime_ns). The identity and
# not the path alone: a `kern` REPLACED between two calls is a different program and must be checked
# again. Bounded by how many distinct binaries one process can point at, which is one in every real
# program and a handful in the test suite.
_VERIFIED_KERN: "dict[tuple, str]" = {}  # identity -> the version line it answered with
_VERIFIED_KERN_LOCK = threading.Lock()


def _verify_is_kern(path: str) -> str:
    """Refuse a binary that does not IDENTIFY ITSELF as kern, and return the version line it answered
    with. Raises :class:`SandboxError` if it does not identify itself.

    MEASURED, AND IT WAS FOUND BY RUNNING MY OWN POSITIVE CONTROL ELSEWHERE: with ``KERN_BIN=/bin/true``
    a call returned ``success=True, exit_code=0, fault=None`` and an empty stdout. The code never ran and
    the caller was told it had. Any `kern` on PATH that is not kern does this: a leftover wrapper, a
    shim, a no-op someone dropped earlier in the search order. An agent loop reads `success` and moves
    on, and every subsequent conclusion it draws is about a program that never executed.

    POSITIVE IDENTIFICATION, not inference from a missing signal. "No started byte" cannot carry this:
    a kern old enough to predate `KERN_STARTED_FD` writes nothing either, and refusing it would break a
    user whose only sin is an old binary. `kern --version` prints `kern <version>` on stdout, and that
    prefix is asserted by a test in kern's own suite (`version_prints_and_succeeds`), so this keys on a
    contract rather than on a hope. `/bin/true` prints nothing and is refused; every kern ever released
    passes.

    Memoised per binary IDENTITY, so the cost is one `--version` (measured at 0.7 ms) per distinct
    binary per process, and zero for every call after the first. Fail-closed: a binary that cannot be
    run, times out, or answers something else is refused, because an unverifiable runtime is exactly the
    case this exists for.
    """
    try:
        st = os.stat(path)
        key = (os.path.realpath(path), st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
    except OSError as e:
        raise SandboxError(f"could not stat the kern binary at '{path}': {e}") from e
    with _VERIFIED_KERN_LOCK:
        if key in _VERIFIED_KERN:
            return _VERIFIED_KERN[key]
    hint = (
        "If this is not the kern you meant, set $KERN_BIN to the right path. To install kern:\n"
        "    curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh"
    )
    try:
        # Generous on purpose: a loaded machine must not be told its kern is fake. `--version` does no
        # I/O beyond writing one line, so a binary that cannot answer in ten seconds is not one to trust
        # with a box.
        out = subprocess.run(  # noqa: S603 - argv list, no shell
            [path, "--version"], capture_output=True, timeout=10, check=False
        )
    except subprocess.TimeoutExpired as e:
        raise SandboxError(
            f"'{path}' did not answer `--version` within 10s, so it cannot be identified as kern. {hint}"
        ) from e
    except OSError as e:
        raise SandboxError(f"could not run '{path} --version': {e}. {hint}") from e
    line = (out.stdout or b"").decode("utf-8", "replace").strip().splitlines()
    first = line[0] if line else ""
    if out.returncode != 0 or not first.startswith("kern "):
        shown = first[:120] if first else "(no output)"
        raise SandboxError(
            f"'{path}' is not kern: `{path} --version` exited {out.returncode} and printed {shown!r}, "
            f"where kern prints a line beginning 'kern '. Refusing to run code, because a binary that "
            f"is not kern would return an EMPTY, SUCCESSFUL result for every call and the code would "
            f"never run. {hint}"
        )
    with _VERIFIED_KERN_LOCK:
        _VERIFIED_KERN[key] = first
    return first


def _find_kern() -> str:
    """Locate ``kern``: ``$KERN_BIN`` if set, else the first ``kern`` on ``$PATH``. The result is also
    IDENTIFIED as kern (see :func:`_verify_is_kern`), because being executable and being named `kern` are
    not the same as being kern."""
    env = os.environ.get("KERN_BIN")
    if env:
        if not (Path(env).is_file() and os.access(env, os.X_OK)):
            raise SandboxError(f"$KERN_BIN='{env}' is not an executable file")
        _verify_is_kern(env)
        return env
    found = shutil.which("kern")
    if not found:
        # On macOS the generic "install it" is a dead end: there is no macOS build to install, and a
        # user who pip-installed this package here would otherwise keep looking for one. kern needs a
        # Linux kernel, so the answer is a VM, and saying so costs one branch.
        if sys.platform == "darwin":
            raise SandboxError(
                "the `kern` binary was not found on PATH, and this is macOS: kern is Linux-only "
                "(no namespaces, no cgroups on a Mac), so there is no macOS build to find. "
                "Run inside a Linux VM (colima, Lima, OrbStack, UTM) and install it there with:\n"
                "    curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh\n"
                "or set $KERN_BIN to a kern reachable from here."
            )
        # THE COMMAND, NOT A LINK. `pip install kern-sandbox` does NOT bring the binary: this
        # package is a wrapper around a process it does not ship, and the moment a user meets that
        # fact is this exception. It used to answer with a repository URL, which asks someone who is
        # one paste away from working to go and read a page first. The installer is the same line
        # the project's README leads with, so the two cannot drift apart in what they recommend.
        raise SandboxError(
            "the `kern` binary was not found on PATH. `pip install kern-sandbox` installs this "
            "wrapper, not the runtime it drives - install kern with:\n"
            "    curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh\n"
            "or point $KERN_BIN at a kern you already have."
        )
    _verify_is_kern(found)
    return found


# The mount points a box needs to be a box, refused as TARGETS. Two sets, because the rule is not the
# same for both, and collapsing them broke a documented feature within the hour.
#
# REFUSED AT THE POINT ITSELF. Mounting over one of these replaces the thing the box is built on: `/`
# is the box, and `/proc`, `/sys` and `/dev` are what the kernel put there for it.
_BOX_ESSENTIAL_MOUNTS = ("/", "/proc", "/sys", "/dev")

# REFUSED ANYWHERE INSIDE, TOO. `/proc` and `/sys` are kernel interfaces whose individual entries are
# read by the box, by its runtime and by kern itself; a bind over one of them shadows a fact rather
# than adding a file. The exact-match check that shipped before let every one of these through:
# `/proc` was refused and `/proc/self`, `/proc/1/environ` and `/sys/fs/cgroup` were accepted. Found in
# review, with the command that shows it.
#
# `/dev` IS NOT IN THIS SET, and that is not an oversight. `/dev/shm` is the one lever this SDK has on
# shared memory - kern refuses `--tmpfs /dev/shm`, so a bind is the only way - and it is documented,
# measured and covered by three tests, all of which went red when the first version of this fix
# refused everything under `/dev`. A device node bound over by a caller is a foot-gun in their own
# box, not a way out of it.
#
# `/etc` is in neither set: a config file at `/etc/myapp.conf` is an ordinary thing to mount. What is
# dangerous there is the SOURCE, and that is where the sensitive-host-path set does its work.
_BOX_ESSENTIAL_SUBTREES = ("/proc", "/sys")


def _is_inside(path: str, root: str) -> bool:
    """Is `path` the directory `root` itself, or anything beneath it? Both are already normalised.

    STRING COMPARISON ON NORMALISED PATHS, deliberately, and not `os.path.commonpath`: this runs on a
    target that does not exist yet, inside a filesystem that does not exist yet, so there is nothing to
    resolve against. The separator is appended before the prefix test so `/sysfoo` is not read as being
    inside `/sys`.

    `/` IS ITSELF AND NOT EVERYTHING. Read as a prefix it contains every path there is, and the first
    version of this function did exactly that: every mount was refused, including `/data`. The root is
    an essential mount because mounting OVER it replaces the box; mounting inside it is what a mount
    is.
    """
    if root == "/":
        return path == "/"
    return path == root or path.startswith(root + "/")


def _kern_state_dirs() -> "dict[str, str]":
    """kern's OWN state on this host: (path, what it is). Refused as a mount source, like the docker
    socket and for the same reason.

    FOUND BY A CHECKLIST ROW, measured: `mounts={"$XDG_RUNTIME_DIR/kern": "/x"}` was ACCEPTED, which hands
    the code in the box kern's control plane - the registry, the instance directories, the netns handles,
    the health and exit files of every other box this user is running. The image cache is the same class
    one step removed: a box that can write it poisons the rootfs a LATER box runs. Neither is a kernel
    escape, and both defeat the point of asking kern for a box.

    Resolved per call rather than at import, because these follow the environment (`XDG_RUNTIME_DIR`,
    `XDG_CACHE_HOME`, `HOME`) and a test or a service manager moves them.

    EACH DIRECTORY IS LISTED TWICE: where the environment says it is, AND where XDG says it is by
    default. The runtime dir was already spelled both ways; the other three were not, and an external
    independent test measured the consequence in one process: with `XDG_DATA_HOME=/tmp/xdh2`, the path
    `~/.local/share/kern` was ACCEPTED and still held `builds` and `volumes`. The variable answers
    "which kern will this SDK spawn", which is the right input for the guard, but the data a previous
    run left on disk does not move when the variable does.
    """
    uid = os.getuid()
    home = os.path.expanduser("~")
    default_runtime = f"/run/user/{uid}"
    # (configured, default, what it is) - one row per directory, so a fourth cannot be added to the
    # environment lookup and forgotten in the refusal list.
    known = (
        (os.environ.get("XDG_RUNTIME_DIR"), default_runtime,
         "kern's runtime state (the registry, instance dirs, netns handles and exit files of every box "
         "you are running)"),
        (os.environ.get("XDG_CACHE_HOME"), os.path.join(home, ".cache"),
         "kern's image cache (a box that writes it poisons the rootfs a later box runs)"),
        (os.environ.get("XDG_CONFIG_HOME"), os.path.join(home, ".config"),
         "kern's configuration (the profiles a later box may be given)"),
        # THE THIRD SIBLING, and the one the list missed. Found by an independent test who took the
        # two that WERE refused as the shape of the rule and looked for the rest: this holds
        # `volumes/` (the contents of every named volume on the host, which is every compose stack's
        # database) and `builds/` (the build records a later image is assembled from). Refusing the
        # runtime dir and the cache while accepting this one was not a smaller policy, it was an
        # inconsistent one.
        (os.environ.get("XDG_DATA_HOME"), os.path.join(home, ".local", "share"),
         "kern's data (every named volume on this host, and the build records a later image is "
         "assembled from)"),
    )
    # A DICT, so the usual case where the variable IS the default collapses to one entry instead of
    # listing the same directory twice with two different accounts of what it is.
    dirs: "dict[str, str]" = {}
    for configured, default, what in known:
        for base in (configured or default, default):
            dirs.setdefault(os.path.join(base, "kern"), what)
    return dirs


def _validate_mount_lexical(source: str, target: str) -> tuple[str, str]:
    """Validate one host->box mount; refuse unsafe sources/targets. Returns (abs_real_source, target).

    TWO HALVES, and callers exist for each. Everything except the last line is LEXICAL: it needs the
    strings and the environment, not the filesystem. The existence check needs a directory that is
    already there. Splitting them is not tidiness:

    * `Sandbox(workspace=...)` CREATES the workspace before mounting it, so the whole check used to run
      after the mkdir, which meant `workspace="~/.aws/ws"` created a directory under a credential
      directory and THEN refused the mount.
    * the LangChain shell policy builds its `-v` for a session directory whose lifetime it does not own,
      and its argv tests pass paths that never exist on disk.

    Both call `_validate_mount_lexical` and let the existence question belong to whoever owns the path.
    """
    # A NUL CANNOT REACH THE OS LAYER AS A ValueError. Every other refusal here is `MountRefused`,
    # which is a `SandboxError`, and a caller's `except SandboxError` is the documented way to handle
    # a bad mount. `os.path.realpath` on a string with an embedded NUL raises `ValueError` instead, so
    # one input in the set escaped the exception type the API promises and took the caller's process
    # down. Found in review. Checked before anything touches the OS layer.
    for label, value in (("source", source), ("target", target)):
        if "\x00" in value:
            raise MountRefused(f"mount {label} must not contain a NUL byte: {value!r}")
        # A NEWLINE IS REFUSED FOR THE SAME REASON A NUL IS, one layer up: it is legal in a Linux path
        # and it poisons every line-oriented reader downstream - kern's own argv is fine, `list_files`
        # and any log a caller greps are not. No legitimate mount needs one.
        if "\n" in value or "\r" in value:
            raise MountRefused(f"mount {label} must not contain a newline: {value!r}")
    if not target.startswith("/"):
        raise MountRefused(f"mount target must be an absolute path in the box, got {target!r}")
    if any(c == ".." for c in target.split("/")):
        raise MountRefused(f"mount target must not contain '..': {target!r}")
    norm_target = "/" + "/".join(c for c in target.split("/") if c and c != ".")
    if norm_target in _BOX_ESSENTIAL_MOUNTS:
        raise MountRefused(
            f"cannot mount over the box essential mount {norm_target!r}: the box needs it to be "
            "what the kernel put there"
        )
    for essential in _BOX_ESSENTIAL_SUBTREES:
        if _is_inside(norm_target, essential):
            raise MountRefused(
                f"cannot mount inside {essential!r} (got {norm_target!r}): its entries are kernel "
                "state the box, its runtime and kern all read, and a bind there shadows a fact "
                "rather than adding a file"
            )
    src = Path(source)
    if not src.is_absolute():
        raise MountRefused(f"mount source must be an absolute host path, got {source!r}")
    real = os.path.realpath(source)  # resolve symlinks BEFORE the sensitive-set check
    if real in _REFUSED_MOUNT_SOURCES or real == os.path.realpath(os.path.expanduser("~")):
        raise MountRefused(
            f"refusing to mount the sensitive host path {real!r} into a sandbox "
            "(this would defeat the isolation)"
        )
    for state, what in _kern_state_dirs().items():
        if _is_inside(real, os.path.realpath(state)):
            raise MountRefused(
                f"refusing to mount {real!r}: it is {what}. Mounting kern's own state into a box it "
                f"started gives the code inside the sandbox's control plane, which is the same reason "
                f"the docker socket is refused"
            )
    parts = real.split(os.sep)
    hit = next((p for p in parts if p in _REFUSED_MOUNT_COMPONENTS), None)
    if hit is None:
        # The `<parent>/<child>` form, consecutive so `~/.config/gh` is refused and `~/gh` is not.
        hit = next(
            (
                f"{a}/{b}"
                for a, b in zip(parts, parts[1:])
                if (a, b) in _REFUSED_MOUNT_PAIRS
            ),
            None,
        )
    if hit is not None:
        raise MountRefused(
            f"refusing to mount {real!r}: {hit!r} holds credentials, and code in the box would "
            f"read them. If the job needs one secret, write THAT FILE into the workspace "
            f"(sbx.write_file) or mount a directory that holds only it"
        )
    return real, target

def _validate_mount(source: str, target: str) -> tuple[str, str]:
    """`_validate_mount_lexical` plus the one question that needs the filesystem: does the source exist?"""
    real, target = _validate_mount_lexical(source, target)
    if not Path(real).exists():
        raise MountRefused(f"mount source does not exist: {source!r}")
    return real, target


# The box root is read-only (`--ro`, always), so every path a workload can write is one we granted.
# `/tmp` was not granted, and both halves of what that cost were measured rather than assumed:
#   * anything NAMING /tmp fails: `open("/tmp/x", "w")` raises OSError(EROFS). That is how a toolchain
#     reaches it. Measured on `golang:1.23-alpine`: `go build` reported "failed to initialize build
#     cache at /root/.cache: read-only file system" and printed nothing else useful.
#   * anything using `tempfile` SILENTLY MOVES INTO THE WORKSPACE. tempfile's last-resort candidate is
#     the current directory, which is /workspace, so `NamedTemporaryFile()` landed on the caller's
#     persistent host directory and showed up in `list_files` as a file the model then has to explain.
# 64 MiB is enough for scratch and small enough that filling it hits the box's own memory cap rather
# than the host. A tmpfs and not a host bind ON PURPOSE: tmpfs pages are charged to the box's memory
# cgroup, so the fill is bounded by a cap the caller already set; a bound host directory is bounded by
# nothing, and that is the one thing this SDK's own README already warns about for the workspace.
_DEFAULT_TMPFS = {"/tmp": "64m"}

# A tmpfs size as kern's `--tmpfs path[:size]` takes it. ANCHORED and unit-restricted: the value is
# concatenated after a colon into one argv element, so anything that could carry a comma, a space or a
# second flag has to be refused here rather than reinterpreted by the parser downstream.
#
# THE UNIT IS MANDATORY, and a leading zero is refused, because kern's CLI accepts two spellings that
# mean the opposite of what an SDK caller writing them means. Both measured:
#   * `"64"` is 64 BYTES, not 64 MiB. `df` reports 4 KB (one page) and a 100 KB write is ENOSPC.
#   * `"0"` is UNLIMITED, not none. `df` reports 0 blocks and 200 MiB written under `memory_mb=128`
#     OOM-killed the box at exit 137, so nothing but the memory cap stopped it.
# kern is right to take both: it is the low-level interface. Here they are foot-guns that fail far
# from their cause, so the gate demands `64m` and points at `tmpfs={}` for "none".
_TMPFS_SIZE_RE = re.compile(r"^[1-9][0-9]*[kmgtKMGT]$")

# Mounting a tmpfs over these hides something the box needs, and silently: a tmpfs at /workspace would
# shadow the workspace bind, so every file the caller wrote would still be on the host and none of it
# would be visible to the code. Refuse rather than let a caller build that.
_REFUSED_TMPFS_TARGETS = ("/", "/proc", "/sys", "/dev", _WORKSPACE)


def _validate_tmpfs(target: str, size: "str | None") -> "tuple[str, str | None]":
    """Validate one in-box tmpfs; return the normalised (target, size). The caller composes the
    argument, because the size still has to be resolved against the memory cap and that resolution
    PARSES it, so it may only run on a value this function has already accepted."""
    if not isinstance(target, str) or not target.startswith("/"):
        raise MountRefused(f"tmpfs target must be an absolute path in the box, got {target!r}")
    if any(c == ".." for c in target.split("/")):
        raise MountRefused(f"tmpfs target must not contain '..': {target!r}")
    # A colon is the SEPARATOR in `--tmpfs path[:size]`, so a path carrying one is reinterpreted
    # rather than rejected. Measured: `tmpfs=["/scratch:9g"]` mounted `/scratch` at 9 GiB and the
    # directory the caller actually named did not exist in the box. Silent, and the caller's own path
    # became a number. kern cannot fix this without breaking its own syntax; the SDK can refuse.
    if ":" in target:
        raise MountRefused(
            f"tmpfs target must not contain ':': {target!r}. It is the size separator in kern's "
            f"`--tmpfs path[:size]`, so this path would be read as a size and a different directory "
            f"would be mounted."
        )
    norm = "/" + "/".join(c for c in target.split("/") if c and c != ".")
    if norm in _REFUSED_TMPFS_TARGETS:
        raise MountRefused(
            f"cannot mount a tmpfs over {norm!r}: it would hide the box's own mount there "
            f"(the workspace bind, or an essential filesystem)"
        )
    if size is None:
        return norm, None
    if not isinstance(size, str) or not _TMPFS_SIZE_RE.fullmatch(size):
        hint = ""
        if isinstance(size, str) and size.isdigit():
            hint = (
                " A bare number is BYTES to kern, not MiB: '64' gives a 4 KB filesystem and the first"
                " real write is ENOSPC."
                if size.strip("0")
                else " A zero size means UNLIMITED to kern, not none: for none, pass tmpfs={}."
            )
        raise MountRefused(
            f"invalid tmpfs size {size!r} for {norm!r}: expected a number with a k/m/g/t unit, e.g."
            f" '64m'.{hint}"
        )
    return norm, size


_TMPFS_UNIT_MIB = {"k": 1 / 1024, "m": 1.0, "g": 1024.0, "t": 1024.0 * 1024.0}


def _tmpfs_mib(size: str) -> float:
    """A validated ``64m``/``1g`` size as MiB. Only ever called after ``_TMPFS_SIZE_RE`` matched."""
    return int(size[:-1]) * _TMPFS_UNIT_MIB[size[-1].lower()]


def _tmpfs_size_vs_cap(target: str, size: "str | None", memory_mb: "int | None", ours: bool) -> "str | None":
    """Resolve a scratch size against the memory cap AT CONSTRUCTION, not at the first write.

    A tmpfs larger than the cap is a number the KERNEL then tells the workload: ``df`` reports the
    tmpfs size, so a ``"1t"`` scratch shows 1.0T free under a 128 MiB cap. Anything that preflights
    with ``statvfs`` (installers, archivers, encoders, SQLite) plans against that and is OOM-killed
    instead of getting a clean ENOSPC. The wrong answer is delivered to a PROGRAM, which will act on
    it, and no message reaches a person at all.

    The two cases are not symmetric, on purpose:
      * a size the CALLER wrote is refused, naming both numbers. Silently shrinking what someone
        asked for is the declared-versus-real defect this whole change exists to remove.
      * OUR default is clamped instead, because adjusting a number we chose ourselves is not
        overriding anyone, and refusing it would make a box unstartable for a caller who never
        mentioned scratch at all (``memory_mb=32`` with a 64 MiB default).
    An uncapped box (``memory_mb=None``) has no ceiling to resolve against, so nothing happens.

    The clamp is ``min(64 MiB, memory_mb / 2)``, and it is a HEURISTIC, not a derivation. It only ever
    REDUCES our own 64 MiB: at ``memory_mb=512`` the default is still 64, not 256. There is no safe
    fraction to derive, because the safe fraction depends on the workload's own peak, which is the
    thing ``memory_mb`` was meant to bound and now shares. Half is where the measurement below stops
    being fatal; it is not a formula that says what is right for a given workload.

    Writing in 1 MiB chunks under ``memory_mb=128``:

        tmpfs  32m  ->  ENOSPC after 32 MiB      the filesystem bound, cleanly
        tmpfs  64m  ->  ENOSPC after 64 MiB
        tmpfs 128m  ->  OOM                      the cap bound first, and the box died

    A tmpfs EQUAL to the cap lands exactly on the cell this function exists to avoid: filling it
    exhausts the whole budget, so the box is killed instead of the write failing. Half leaves the
    workload as much room as the scratch."""
    if size is None or memory_mb is None:
        return size
    if ours:
        # Never grow the default, only shrink it, and never to zero: `"0m"` is refused downstream and
        # a box a caller never asked scratch for must still start.
        capped = max(1, min(int(_tmpfs_mib(size)), memory_mb // 2))
        return size if capped >= _tmpfs_mib(size) else f"{capped}m"
    if _tmpfs_mib(size) <= memory_mb:
        return size
    if not ours:
        raise MountRefused(
            f"tmpfs {size!r} at {target!r} is larger than memory_mb={memory_mb}, and a tmpfs is "
            f"charged to that same cap. `df` inside the box would report {size} free while only "
            f"{memory_mb}m is reachable, so a program that checks free space before writing plans "
            f"against a number that OOM-kills it instead of returning ENOSPC. Lower the tmpfs or "
            f"raise memory_mb."
        )
    return f"{memory_mb}m"


def _tmpfs_items(spec: object) -> "list[tuple[str, str | None]]":
    """Normalise the `tmpfs=` argument to (target, size|None) pairs. A mapping carries sizes, a plain
    sequence does not; a bare string is refused by name, because iterating it would produce one bogus
    mount per character instead of the one the caller meant."""
    if spec is None:
        return list(_DEFAULT_TMPFS.items())
    if isinstance(spec, str):
        raise MountRefused(
            f"tmpfs must be a mapping or a sequence of paths, not a bare string: write "
            f"tmpfs={{{spec!r}: '64m'}} or tmpfs=[{spec!r}]"
        )
    if isinstance(spec, Mapping):
        return list(spec.items())
    # A NUMBER is the mistake this API invites: every neighbour takes one (`memory_mb=512`,
    # `pids=256`), so `tmpfs=256` is the natural thing to type. Iterating it raised a bare TypeError
    # from inside the constructor that never said the word "tmpfs". Name it, and guess the intent.
    if not isinstance(spec, (list, tuple, set, frozenset)):
        if isinstance(spec, bool) or not isinstance(spec, int):
            extra = ""
        elif spec == 0:
            extra = " For no scratch at all, pass tmpfs={}."
        else:
            extra = f" Did you mean tmpfs={{'/tmp': '{spec}m'}}?"
        raise MountRefused(
            f"tmpfs must be a mapping of path -> size or a sequence of paths, got "
            f"{type(spec).__name__}.{extra}"
        )
    return [(t, None) for t in spec]


# A resource-profile token (`vcpu:`/`vgpio:`/`vdisk:` + a named profile from the user's kern.toml).
# ANCHORED and charset-restricted: the token is passed as a POSITIONAL arg to `kern box`, so it must be
# EXACTLY a known prefix plus a safe name. This is what stops a caller (or agent-chosen value) from
# smuggling another flag through the profile list, e.g. "--net", "-v /etc:/etc", "vgpu:x" (unsupported),
# or a name with a space / `=` / `/` / leading dash. The three prefixes mirror `config::classify` in kern.
_PROFILE_RE = re.compile(r"^(?:vcpu|vgpio|vdisk):[A-Za-z0-9][A-Za-z0-9._-]*$")


def _validate_profile(token: str) -> str:
    """Validate one `vcpu:`/`vgpio:`/`vdisk:NAME` resource-profile token before it reaches the argv."""
    if not isinstance(token, str) or not _PROFILE_RE.fullmatch(token):
        raise SandboxError(
            f"invalid resource profile {token!r}: expected 'vcpu:NAME', 'vgpio:NAME' or 'vdisk:NAME' "
            "with an alphanumeric profile name (the profile must be defined in your kern.toml)"
        )
    return token


# A public DNS domain for the egress allowlist. LDH labels, at least one dot (an FQDN), alphabetic TLD.
# Restrictive on purpose: the value is joined with commas and handed to `kern box --egress-allow`, so it
# must not contain a comma, scheme, path, port, wildcard or whitespace that could change the argument's
# meaning. kern re-validates and SSRF-checks the resolved IPs; this is the binding's first gate.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


def _validate_domain(domain: str) -> str:
    """Validate one egress-allowlist domain (an FQDN like ``pypi.org``) before it reaches the argv."""
    if not isinstance(domain, str) or not _DOMAIN_RE.fullmatch(domain):
        raise SandboxError(
            f"invalid egress domain {domain!r}: expected a bare hostname like 'pypi.org' "
            "(no scheme, port, path, wildcard or spaces)"
        )
    return domain


# A Linux capability name for `kern box --cap-drop`, with or without the CAP_ prefix, or the literal
# ALL. Uppercase letters, digits and underscores only: the value is handed to kern as its own argv
# element, so it must not be able to start with a dash or carry a space that could turn into another
# flag. kern itself rejects a name it does not know (a typo cannot silently leave a cap in place);
# this is the binding's first gate, and it is the same discipline as _validate_profile.
# Underscore-JOINED segments, not "any of [A-Z0-9_]": the looser form accepted "CAP_", because the
# optional prefix does not have to consume it and `[A-Z][A-Z0-9_]*` then reads it as C + AP_. Not a
# way to smuggle a flag, but a name kern rejects at box start, and the point of validating here is to
# fail at construction with a message that names the mistake.
_CAP_RE = re.compile(r"^(?=.{1,32}$)(?:CAP_)?[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$")


def _validate_cap(name: str) -> str:
    """Validate one capability name for ``--cap-drop`` before it reaches the argv."""
    if not isinstance(name, str) or not _CAP_RE.fullmatch(name):
        raise SandboxError(
            f"invalid capability {name!r}: expected 'ALL' or an uppercase capability name such as "
            "'NET_BIND_SERVICE' or 'CAP_NET_BIND_SERVICE'"
        )
    return name


# An AppArmor profile name for `kern box --apparmor`. Same discipline as _validate_cap: the value is
# handed to kern as its own argv element, so it must not be able to start with a dash (→ another flag)
# or carry a space. Letters/digits and `._-` cover ordinary profile names (`docker-default`,
# `unconfined`, `kern-box`); kern fails closed if the profile is not actually loaded. Namespaced names
# with `/` or `:` are intentionally not accepted through the binding - use the CLI for those. This
# pattern is compared byte-for-byte with the Node binding's APPARMOR_RE (a parity test), so keep them
# identical and free of chars that would need escaping in a JS regex literal (e.g. `/`).
_APPARMOR_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,127}$")


def _validate_apparmor(name: str) -> str:
    """Validate an AppArmor profile name for ``--apparmor`` before it reaches the argv."""
    if not isinstance(name, str) or not _APPARMOR_RE.fullmatch(name):
        raise SandboxError(
            f"invalid AppArmor profile {name!r}: expected a loaded profile name like 'docker-default' "
            "or 'unconfined' (letters, digits and ._-, not starting with a dash)"
        )
    return name


# Signal-derived exit codes (128 + signum) we classify.
_EXIT_SIGKILL = 137  # 128 + 9  - SIGKILL: timeout backstop or OOM (indistinguishable without cgroup)
_EXIT_SIGSYS = 159  # 128 + 31 - SIGSYS: a seccomp-denied syscall = a blocked escape attempt
# The fatal signals that mean THE CODE went wrong, not that the sandbox acted. NAMED, not "everything
# else": an unknown signal stays an honest `killed` rather than being quietly called a crash. SIGKILL and
# SIGTERM are absent on purpose - those are the kill and the reap, decided by their own branches - and
# SIGSYS is absent because it is kern's seccomp filter, which IS the sandbox acting.
_CRASH_SIGNALS = frozenset({signal.SIGILL, signal.SIGABRT, signal.SIGBUS, signal.SIGFPE, signal.SIGSEGV})
_EXIT_SIGTERM = 143  # 128 + 15 - SIGTERM: kern's --timeout backstop reaping the box (SIGTERM→SIGKILL)


@dataclass
class Sandbox:
    """A configured kernel sandbox. FILE state persists across ``run_code``/``run`` in a workspace on
    disk; each call runs in a FRESH ephemeral box. Safe by default; every relaxing arg says so.

    Args:
        image: OCI image the box runs from. Default: a small Python image.
        setup: a shell command run ONCE at ``__enter__`` in a NETWORK-ENABLED setup box (e.g.
            ``"pip install pandas"``). This is the ONLY moment the network is on; every ``run_code`` is
            network-off. Deps installed to ``<workspace>/.deps`` and put on ``PYTHONPATH``.
        workspace: host directory to use as the persistent workspace. ``None`` (default) → a temp dir
            created on ``__enter__`` and DELETED on ``__exit__`` (session-ephemeral). A given path is
            validated like a mount, is NOT deleted on exit, and its contents persist across sessions.
        memory_mb: RAM cap in MiB (kern ``--memory``). Default 512. NOTE on profiles: this is passed as
            an explicit ``--memory`` flag, and kern's "explicit flag wins over profile" rule means the
            default **overrides** a ``vcpu:`` profile's own ``memory=``. To let a profile's memory apply,
            pass ``memory_mb=None`` (which also means uncapped if the profile carries no memory).
        cpus: CPU cap in cores; ``None`` = uncapped and lets a ``vcpu:`` profile's ``cpus=`` apply (kern
            ``--cpus``). A set value overrides the profile, like ``memory_mb``.
        pids: task/fork-bomb ceiling (kern ``--pids-limit``). Default 256.
        timeout_s: MANDATORY per-call wall-clock limit. The BINDING owns this deadline (it kills the
            box), so a ``timeout`` fault is a known fact, never guessed. Default 30.
        network: **RELAXES ISOLATION.** ``True`` shares the host network for every ``run_code`` (kern
            ``--net``). Default ``False``. There is no per-call network override - network is a
            session-level, explicit choice.
        egress_allow: restrict ``run_code``/``run`` to a DOMAIN ALLOWLIST instead of all-or-nothing,
            e.g. ``["pypi.org", "files.pythonhosted.org"]``. The box runs in an isolated network
            namespace and reaches the internet only through kern's filtering proxy, which permits just
            these domains (an agent can fetch from the index you allow but cannot exfiltrate elsewhere).
            Mutually exclusive with ``network=True``. The ``setup=`` box keeps full network to install
            deps; the allowlist governs the untrusted run phase.
        mounts: extra host paths to bind, ``{host_src: box_target}`` (or ``{src: (target, "ro")}``).
            Sensitive sources are refused. The workspace is mounted automatically; this is for extras.
        tmpfs: fresh in-box scratch filesystems, ``{"/path": "64m"}`` or ``["/path"]`` (kern
            ``--tmpfs``). **A 64 MiB tmpfs is mounted at ``/tmp`` by default.** The box root is
            read-only, so without it ``open("/tmp/x", "w")`` fails and ``tempfile`` falls back to the
            current directory, quietly writing temp files into your persistent workspace. Pass
            ``{"/tmp": "512m"}`` to resize it (**the unit is required**: a bare ``"64"`` is 64 BYTES to
            kern and ``"0"`` is UNLIMITED, so both are refused), ``tmpfs={}`` for none, or bind your own directory at
            ``/tmp`` via ``mounts`` and the default steps aside. The bytes are charged to the box's own
            memory cgroup, so a runaway writer is OOM-killed instead of filling the host disk.

            **Scratch does not survive a command, EXCEPT in a kernel().** Each ``run_code``/``run`` is
            a fresh box, so the tmpfs is fresh too, while the workspace persists. A ``kernel()`` is one
            long-lived box, so the opposite holds there: its ``/tmp`` persists across cells and the
            size is CUMULATIVE. Measured, writing 10 MiB per step under the 64 MiB default: ten
            ``run_code`` calls all succeed and each sees an empty ``/tmp``, while the same ten cells in
            a kernel fail from the seventh with ``OSError: [Errno 28] No space left on device``. That is a trade, not a free win: a
            read-only ``/tmp`` used to fail LOUDLY at the moment of the mistake, and a tool that
            writes state to the workspace and a lock or pidfile to ``/tmp`` now writes both, and the
            second call finds workspace state pointing at a ``/tmp`` path that is gone. Put anything
            another call has to find in the workspace. The
            EFFECTIVE ceiling is therefore ``min(size, memory_mb)``, and ``df`` inside the box does
            not know that: it reports the tmpfs size, so a ``"1t"`` scratch shows 1.0T free and the
            first write past the cap is an OOM, not ``ENOSPC``. The ``oom`` fault names the scratch.
        profiles: reusable kern resource profiles to attach, as ``["vcpu:NAME", "vgpio:NAME",
            "vdisk:NAME"]``. Each names a ``[[vcpu]]``/``[[vgpio]]``/``[[vdisk]]`` block in your
            ``~/.config/kern/kern.toml``: a CPU+memory slice, a specific GPIO/I2C/SPI device set (the
            only way to grant the box hardware), or a size-capped scratch disk. Tokens are strictly
            validated (prefix + alphanumeric name) so a profile entry can never smuggle another flag.
        env: extra environment variables for the workload.
        max_output_bytes: cap on captured stdout/stderr EACH; a flooding box can't OOM the host.
        enforce_limits: ``True`` (default) hard-enforces caps via a systemd scope (~6 ms start);
            ``False`` skips it for a ~3 ms start (best-effort caps).
        cap_drop: Linux capabilities dropped from every box, as kern's ``--cap-drop`` takes them.
            Default ``("ALL",)``. kern already drops 14 dangerous capabilities unconditionally; this
            drops the remainder, which were otherwise held over the box's own user namespace. It is
            defence in depth, not the boundary itself, and it changes one behaviour: a workload that
            binds a port below 1024 INSIDE the box needs ``CAP_NET_BIND_SERVICE``. Pass
            ``cap_drop=()`` for the pre-0.1.14 behaviour, or a narrower set.
    """

    image: str = _DEFAULT_IMAGE
    setup: str | None = None
    workspace: str | None = None
    memory_mb: int | None = 512
    cpus: float | None = None
    pids: int | None = 256
    timeout_s: int = 30
    network: bool = False
    egress_allow: Sequence[str] | None = None
    mounts: Mapping[str, "str | tuple[str, str]"] | None = None
    # `None` means the binding's default (a 64 MiB tmpfs at /tmp, see `_DEFAULT_TMPFS`); an empty
    # mapping or sequence means none at all. The two are distinct on purpose: "I did not say" and "I
    # said no" are different answers, and only the second should leave a box without a writable /tmp.
    tmpfs: "Mapping[str, str | None] | Sequence[str] | None" = None
    profiles: Sequence[str] | None = None
    env: Mapping[str, str] | None = None
    max_output_bytes: int = 64 * 1024 * 1024
    enforce_limits: bool = True
    # `--require-limits`: refuse to start unless the memory/pids caps are ACTUALLY enforced (read back
    # from the cgroup), rather than running best-effort uncapped. The fail-closed OOM / fork-bomb backstop
    # for a host that may not delegate cgroup v2. Distinct from `enforce_limits`, which only picks the
    # systemd-scope vs best-effort cap PATH; this makes an unenforceable cap fatal.
    require_limits: bool = False
    # `--security-profile "untrusted"`: an opt-in hardening BUNDLE (seccomp allowlist + cap-drop ALL +
    # read-only root) for code nobody has read, applied as a base. Only "untrusted" is defined today. The
    # root goes read-only but a bound `mounts` path (and run_code's own workspace) stays writable, so it
    # composes with this SDK. `None` (default) leaves the box on kern's normal posture.
    security_profile: str | None = None
    # `--apparmor "<profile>"`: enter a pre-loaded AppArmor profile on the box's exec (Docker's
    # `--security-opt apparmor=`), a kernel-enforced LSM layer over namespaces + seccomp. The profile
    # must be loaded on the host (root, once, `apparmor_parser -r`); kern fails the box CLOSED if it is
    # not loaded. `None` (default) applies no profile. Validated at construction so it can't smuggle a flag.
    apparmor: str | None = None
    # Capabilities dropped from every box this sandbox starts, as kern's own `--cap-drop` takes them.
    # The default drops the lot: kern already drops 14 dangerous capabilities unconditionally, but the
    # rest were still held over the box's own user namespace, and this is the one code path whose whole
    # purpose is running code nobody has read. It is defence in depth rather than the boundary itself
    # (those capabilities are namespaced, and the always-on seccomp filter refuses the escape syscalls
    # they would unlock either way), and it is measured to cost nothing: `python3 -c` and
    # `pip install --target` behave identically with and without it.
    #
    # It is NOT free of behaviour change, which is why it is a field and not a constant: a workload
    # that binds a port below 1024 INSIDE the box's own network namespace needs CAP_NET_BIND_SERVICE
    # and will get PermissionError. Pass `cap_drop=()` to keep the previous behaviour, or drop a
    # narrower set, e.g. `cap_drop=("SYS_ADMIN", "NET_RAW")`.
    cap_drop: Sequence[str] = ("ALL",)
    deps_readonly: bool = True  # mount setup= deps read-only for run_code (block cross-run poisoning)
    # pyc_cache=True compiles this image's standard library ONCE, in a background box, and mounts the
    # result READ-ONLY into every later box (see `_PYC_MOUNT`). It changes no observable behaviour: the
    # bytecode is the image's own stdlib compiled by the image's own interpreter, and CPython validates
    # each file against its source before using it. Set False to keep boxes compiling from source.
    pyc_cache: bool = True
    # track_files=True populates result.files by walking the workspace before AND after each call, which
    # is O(workspace file count): a long session that accumulates thousands of files makes every run_code
    # slower. Set False (result.files always []) when you don't need the per-call file diff - O(1) then.
    track_files: bool = True
    # live output callbacks: called with each raw chunk (bytes) as it arrives, in a reader thread. The
    # full capped output is still captured in the result, so you can stream AND read result.stdout.
    on_stdout: "Callable[[bytes], None] | None" = None
    on_stderr: "Callable[[bytes], None] | None" = None
    # prewarm=N keeps N boxes started in advance, each holding a booted interpreter that has run nothing.
    # A python `run_code` then claims one instead of starting its own, which takes the ~15 ms of box start
    # + interpreter boot OFF the call and leaves a marginal cost near zero. Each prewarmed box serves
    # exactly one cell and is destroyed, so "a fresh box per call" is unchanged - see :class:`_WarmBox`.
    #
    # Default 0, because it is a RESOURCE decision the caller owns: N warm boxes hold N booted
    # interpreters (tens of MB of RSS) and N kern supervisors for the life of the session, whether or not
    # a call ever arrives. 1 is the right number for an interactive agent (calls are separated by model
    # thinking time, so the pool always refills between them); raise it only for bursts.
    prewarm: int = 0

    _kern: str = field(default="", repr=False)
    _mount_args: list = field(default_factory=list, init=False, repr=False)
    _tmpfs_args: list = field(default_factory=list, init=False, repr=False)
    _tmpfs_default: bool = field(default=True, init=False, repr=False)
    _profile_args: list = field(default_factory=list, init=False, repr=False)
    _egress_allow: list = field(default_factory=list, init=False, repr=False)
    _cap_drop_args: list = field(default_factory=list, init=False, repr=False)
    _single_uid: bool = field(default=False, init=False, repr=False)
    _ws: str = field(default="", init=False, repr=False)
    _own_ws: bool = field(default=False, init=False, repr=False)  # we created it → we delete it
    # The cache directory to mount: "" means this session compiles from source. Set at `__enter__` when
    # a cache is already there, and by `_pyc_adopt_if_ready` on the first call after this session's own
    # build publishes one.
    _pyc_dir: str = field(default="", init=False, repr=False)
    # The destination a build was started for at `__enter__`, until it is adopted or refused. Empty
    # whenever there is nothing to wait for, which is what keeps the check on the call path free.
    _pyc_pending: str = field(default="", init=False, repr=False)
    _entered: bool = field(default=False, init=False, repr=False)
    _pool: object = field(default=None, init=False, repr=False)
    # The workspace files this binding put there itself, by exact name. See `_claim`.
    _ours: set = field(default_factory=set, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.timeout_s is None or self.timeout_s <= 0:
            raise SandboxError("timeout_s must be a positive number of seconds")
        if self.max_output_bytes <= 0:
            raise SandboxError("max_output_bytes must be positive")
        # SHAPE GUARDS FIRST, BEFORE ANYTHING CONSUMES THESE ARGUMENTS, and the position is the whole
        # of it. `setup` and `cap_drop` already refused the wrong shape by name; `mounts` did not, and
        # a list or a string produced a raw `AttributeError: 'list' object has no attribute 'items'`
        # out of the middle of this class, naming neither the argument nor the shape it wanted. An
        # outside review found it by sweeping the constructor one argument at a time.
        #
        # The first attempt at this fix put the check 80 lines lower, next to the other guards, where
        # `self.mounts.items()` had already run and raised: a guard AFTER the use is not a guard, and
        # only the test caught it.
        #
        # ⛔ `tmpfs` IS DELIBERATELY NOT HERE, and that is the second thing the tests caught. It
        # already has a RICHER validator of its own that names the mistake it sees: an int, a bool, a
        # bare string and a list each get their own sentence, down to
        # `Did you mean tmpfs={'/tmp': '256m'}`. A generic "must be a dict" placed here ran FIRST and
        # replaced all of them with something worse. A guard is only an improvement where there is no
        # better one already; nine tests said so.
        for _name, _value in (
            ("mounts", self.mounts),
            ("env", self.env),
        ):
            if _value is not None and not hasattr(_value, "items"):
                _example = {"KEY": "value"} if _name == "env" else {"/host/path": "/in/box"}
                raise SandboxError(
                    f"{_name} must be a dict, not {type(_value).__name__}: write "
                    f"{_name}={_example!r}"
                )
        # A CALLBACK THAT IS NOT CALLABLE is never called and says nothing, so the caller sees a
        # sandbox that simply produces no output and has nothing to debug. Refused by name instead.
        for _name, _cb in (("on_stdout", self.on_stdout), ("on_stderr", self.on_stderr)):
            if _cb is not None and not callable(_cb):
                raise SandboxError(
                    f"{_name} must be callable (it is handed one line at a time), "
                    f"not {type(_cb).__name__}"
                )
        self._mount_args = []
        bound_targets = set()
        if self.mounts:
            for source, spec in self.mounts.items():
                if isinstance(spec, tuple):
                    target, mode = spec
                    if mode not in ("ro", "rw"):
                        raise MountRefused(f"mount mode must be 'ro' or 'rw', got {mode!r}")
                    ro = mode == "ro"
                else:
                    target, ro = spec, False
                real, tgt = _validate_mount(source, target)
                self._mount_args += ["-v", f"{real}:{tgt}:ro" if ro else f"{real}:{tgt}"]
                bound_targets.add("/" + "/".join(c for c in tgt.split("/") if c and c != "."))
        # A caller who binds their own directory at /tmp gets it: the default tmpfs would be mounted
        # over their bind, so the files they passed would be invisible to the code they are running.
        # An explicit `tmpfs=` wins too - both are the caller saying what /tmp is.
        self._tmpfs_args = []
        self._tmpfs_default = self.tmpfs is None
        for target, size in _tmpfs_items(self.tmpfs):
            norm_target = "/" + "/".join(c for c in str(target).split("/") if c and c != ".")
            if self._tmpfs_default:
                # OUR default steps aside wherever the caller has already said something about this
                # area. A bind at the same target, because mounting over it would hide their files.
                # A `security_profile`, because that is a HARDENING BUNDLE: 0.1.35 gave `untrusted` a
                # read-only /tmp, and a default added by a different layer must not quietly widen a
                # posture in a patch release. An explicit `tmpfs=` is the caller's own decision.
                if norm_target in bound_targets or self.security_profile is not None:
                    continue
            else:
                # A tmpfs that COVERS a bind. Equality was the first version of this check and it is
                # only half the shape: mounts stack, the tmpfs goes on top, and "on top" reaches every
                # path underneath it. Measured, both directions:
                #
                #   -v HOST:/tmp      + --tmpfs /tmp       -> /tmp is EMPTY, the bind is invisible
                #   -v HOST:/tmp/sub  + --tmpfs /tmp       -> same, reached through NESTING
                #   -v HOST:/tmp      + --tmpfs /tmp/sub   -> the bind's files are THERE, /tmp/sub is
                #                                             writable scratch inside it
                #
                # So the rule is asymmetric, and refusing both directions would refuse the third line,
                # which is a legal configuration someone would reasonably want: a persistent /tmp with
                # a bounded subtree. Refuse only when the tmpfs is the ancestor, because that is the
                # one where the caller's files exist and cannot be reached.
                swallowed = [b for b in bound_targets
                             if b == norm_target or b.startswith(norm_target.rstrip("/") + "/")]
                if swallowed:
                    raise MountRefused(
                        f"tmpfs {norm_target!r} would cover the mounts bind at "
                        f"{', '.join(sorted(swallowed))}. Mounts STACK: kern puts the tmpfs on top "
                        f"whatever order the arguments arrive in, so those files stay on the host and "
                        f"are invisible in the box. Keep the bind (for host files) or the tmpfs (for "
                        f"ephemeral scratch) at that path, not both. A tmpfs BELOW a bind is fine: "
                        f"mounts={{host: '/tmp'}} with tmpfs={{'/tmp/scratch': '8m'}} works."
                    )
            # Validate FIRST: `_tmpfs_size_vs_cap` parses the size, and parsing an unvalidated one
            # raised a ValueError out of the constructor instead of a named MountRefused. Same class
            # as the wrong-type hole, one layer down.
            norm, valid_size = _validate_tmpfs(target, size)
            resolved = _tmpfs_size_vs_cap(norm, valid_size, self.memory_mb, self._tmpfs_default)
            self._tmpfs_args += ["--tmpfs", norm if resolved is None else f"{norm}:{resolved}"]
        self._profile_args = [_validate_profile(p) for p in (self.profiles or [])]
        self._egress_allow = [_validate_domain(d) for d in (self.egress_allow or [])]
        if self.apparmor is not None:
            _validate_apparmor(self.apparmor)
        # A str is a Sequence[str], so `cap_drop="ALL"` would iterate into ['A','L','L'] and produce
        # three bogus flags instead of one. Refuse it by name rather than silently doing the wrong
        # thing, and say what to write.
        if isinstance(self.cap_drop, str):
            raise SandboxError(
                f"cap_drop must be a sequence of names, not a bare string: write "
                f"cap_drop=({self.cap_drop!r},) for one, or cap_drop=() to drop none"
            )
        self._cap_drop_args = []
        for cap in self.cap_drop or ():
            self._cap_drop_args += ["--cap-drop", _validate_cap(cap)]
        # SKIP THE UID RANGE EXACTLY WHEN THE CAPABILITY IT SERVES IS BEING DROPPED ANYWAY, which is
        # the default and costs a quarter of a cold box.
        #
        # `kern box --image` maps a sub-uid RANGE by default, which exists so an image that degrades
        # privilege in its entrypoint (postgres, nginx, apt's `_apt`) works. Mapping it forks two
        # SETUID HELPERS, `newuidmap` and `newgidmap`. MEASURED on this tree: `parent:idmap` is 22 us
        # with a single-uid map and ~1048 us with the range, and the whole box goes from 3234 to 4298
        # us on this class's own argv - a paired, core-pinned difference of 1083 us (25%), interval
        # [-1184, -952].
        #
        # IT BUYS THIS SANDBOX NOTHING when `ALL` is dropped, and that is measured rather than argued:
        # `os.setuid(1000)` inside a cell is refused EITHER WAY under `--cap-drop ALL` (EPERM with the
        # range, EINVAL without). Without `--cap-drop ALL` the range DOES work, which is why this is
        # conditional and not unconditional - `cap_drop=()` is a documented choice and it keeps both
        # the capability and the range.
        #
        # CHECKED, not assumed, for the two things a range could serve besides privilege drop:
        # `pip install --target` with network on installs the same three files either way, and an
        # image whose files are not root-owned (`postgres:16-alpine`, `node:20-slim`) reads the same.
        # The class also exposes no `user=`, so nothing here can ask to run as a non-root uid.
        #
        # ONE MORE REASON IT IS THE RIGHT DEFAULT HERE: this class's own contract, stated at the top of
        # the module, is that "single-uid maps box-root to the host user, so files the box creates are
        # host-owned". The range never broke that (uid 0 still maps to the caller), but the flag is
        # what the sentence describes.
        self._single_uid = any(
            c.upper().removeprefix("CAP_") == "ALL" for c in (self.cap_drop or ())
        )
        # SAME GUARD AS `cap_drop` ABOVE, for the same reason: the wrong shape is the natural guess.
        # `setup=` is ONE SHELL COMMAND, and a list of package names is what a reader writes first
        # (measured on myself: `setup=["imageio-ffmpeg"]` surfaced as `AttributeError: 'list' object has
        # no attribute 'strip'` from inside `_run_setup`, an internal error where a sentence belongs).
        if self.setup is not None and not isinstance(self.setup, str):
            raise SandboxError(
                f"setup must be a shell command STRING, not {type(self.setup).__name__}: write "
                'setup="pip install pandas matplotlib" for packages, or any one line the setup box '
                "should run (it runs once, with the network on)"
            )
        if self._egress_allow and self.network:
            raise SandboxError(
                "egress_allow and network=True are mutually exclusive: egress_allow gives a restricted "
                "domain allowlist for run_code, network=True gives the full host network"
            )
        self._kern = _find_kern()
        self._kern_version = _verify_is_kern(self._kern)

    # -- lifecycle -----------------------------------------------------------------------------------

    def __enter__(self) -> "Sandbox":
        if self.workspace is None:
            self._ws = os.path.realpath(tempfile.mkdtemp(prefix="kern-ws-"))
            self._own_ws = True
        else:
            # A caller-supplied workspace is host input → validate it like a mount source, and DON'T
            # delete it on exit (its contents persist across sessions - documented).
            #
            # THE LEXICAL HALF RUNS BEFORE THE MKDIR, the existence half after. The mkdir is here so a
            # fresh persistent path works on the first run, and it used to come first, which meant
            # `workspace="~/.aws/ws"` CREATED a directory under a credential directory and only then
            # refused to mount it. Nothing the lexical half asks needs the directory to be there.
            _validate_mount_lexical(self.workspace, _WORKSPACE)
            # A WORKSPACE THAT IS A FILE is the one case `exist_ok=True` does not cover: `mkdir`
            # raises `FileExistsError: [Errno 17] File exists: '/etc/hostname'` straight out of
            # pathlib, which names the path but not the ARGUMENT, and reads like kern tried to
            # overwrite something. Found by the same constructor sweep that found the `mounts` guard,
            # and it is the same defect: an OS error escaping where a sentence belongs.
            if os.path.exists(self.workspace) and not os.path.isdir(self.workspace):
                raise SandboxError(
                    f"workspace must be a directory, and {self.workspace!r} is a file. The "
                    f"workspace is the box's persistent state and is created if it does not exist; "
                    f"pass a directory path, or None for a temporary one"
                )
            Path(self.workspace).mkdir(parents=True, exist_ok=True)
            _validate_mount(self.workspace, _WORKSPACE)
            self._ws = os.path.realpath(self.workspace)
            self._own_ws = False
        self._entered = True
        if self.setup:
            # A setup that fails raises out of `__enter__`, so the `with` body is never entered and
            # `__exit__` never runs: the workspace this method just created would outlive the session
            # that owned it, and a setup is exactly the step that fails (a pip install against a slow
            # index, an image without the interpreter). Undo our own half-built state on the way out,
            # and only ours: a caller-supplied `workspace=` is theirs and predates this call.
            try:
                self._run_setup(self.setup)
            except BaseException:
                self.__exit__()
                raise
        # THE BYTECODE CACHE IS DECIDED HERE, once, before the pool is filled and after the setup ran.
        # Present -> every box this session starts mounts it; absent -> this session compiles from
        # source and a background box builds the cache for the NEXT one. It is never adopted mid-session
        # for the reason the paragraph below gives about `.deps`.
        #
        # SKIPPED WHEN A SETUP INSTALLED DEPS, and this is a regression that was reasoned about rather
        # than discovered in the field: `PYTHONPYCACHEPREFIX` redirects EVERY bytecode lookup, including
        # `<workspace>/.deps`, whose `__pycache__` the setup box fills on purpose (see `_run_setup`,
        # which measures +40 ms per call without it). Pointing the prefix at a read-only mount would
        # make that precompile unreachable and hand back the 40 ms on every call of the session. The
        # stdlib win is not worth a deps loss, and the two cannot share one prefix: deps are per
        # session, the cache is per image, and mixing them would leak one session's bytecode into
        # another's.
        if self.pyc_cache and not os.path.isdir(os.path.join(self._ws, _DEPS_DIR)):
            dest = _pyc_dir_for(self.image)
            # THROUGH THE SAME VALIDATOR AS EVERY OTHER MOUNT. This path is derived from
            # `$XDG_CACHE_HOME`, so a caller whose cache home sits under a credential directory would
            # otherwise have kern mount a subdirectory of it into every box, and into the build box
            # WRITABLE - the one class of mount this package refuses with no opt-out. It only ever
            # exposes a directory we created, so the exposure is narrow; the rule is not. A refusal
            # disables the cache for the session rather than raising: bytecode is an optimisation, and
            # a caller cannot be made to fail over where their cache lives.
            try:
                _validate_mount_lexical(dest, _PYC_MOUNT)
            except MountRefused:
                dest = ""  # refused: no mount, and no build to produce one either
            if dest and not _pyc_path_has_no_symlink(dest):
                dest = ""  # a link anywhere on the path: the lexical check cannot see through it
            # `_pyc_has_content`, not `isdir`: an empty directory here is a cache that was swept
            # out from under a mount and recreated by kern, and adopting it silences the feature
            # for good. Refusing it sends this session down the `elif` and rebuilds the tree.
            if dest and _pyc_has_content(dest):
                self._pyc_dir = dest
                # Records the ADOPTION for the sweep's least-recently-used order. Best effort: a cache
                # on a read-only filesystem is still perfectly usable, it just cannot be aged.
                try:
                    os.utime(dest, None)
                except OSError:
                    pass
                # The bound has to hold for processes that never build, which is most of them once the
                # cache is warm. One scan per process, off the critical path, AFTER the `utime` above so
                # the cache being adopted is the newest thing the sweep can see.
                _pyc_start_sweep(os.path.dirname(dest))
            elif dest:
                _pyc_start_build(self._kern, self.image, dest, float(max(self.timeout_s, 300)))
                # Remembered so the first call AFTER the build publishes can adopt it. Without this the
                # session that paid for the build was the one session that never used it.
                self._pyc_pending = dest
        # AFTER the setup, deliberately. `_base_argv` adds the `.deps` read-only remount only once that
        # directory exists, so a pool filled before the setup ran would hold boxes whose argv no longer
        # matches the one `run_code` builds - every claim would miss, and the prewarming would be pure
        # cost. Filling here means the first box is already warm by the time the caller's first cell
        # arrives, which is the whole point.
        if self.prewarm > 0:
            pool = _WarmPool(self, self.prewarm)
            self._pool = pool
            pool.refill(network=self.network, deadline=self._eff_timeout(None))
        return self

    def __exit__(self, *exc: object) -> None:
        # Boxes first: they are live processes holding the workspace we are about to delete, and a box
        # still writing into a directory being removed is how a teardown turns into a stale mount.
        pool, self._pool = self._pool, None
        if pool is not None:
            pool.close()  # type: ignore[attr-defined]
        if self._own_ws and self._ws:
            shutil.rmtree(self._ws, ignore_errors=True)
        self._entered = False

    def _require_entered(self) -> None:
        if not self._entered:
            raise SandboxError("use the Sandbox as a context manager: `with Sandbox() as s: ...`")

    # -- the box invocation --------------------------------------------------------------------------

    def _base_argv(
        self, name: str, *, network: bool, timeout_s: int, is_setup: bool = False, dry: bool = False
    ) -> list[str]:
        """Build the `kern box` argv for one call. NOT a pure function: it also WRITES the private
        `--env-file` this box will read, so it must be called once per box that is actually started.

        ``dry=True`` suppresses that write and substitutes a fixed placeholder for the env-file path,
        which is what the prewarm pool needs: it compares postures, and a comparison that created a file
        named after a box that will never exist would both litter the workspace and collide with itself.
        A dry argv is for COMPARING, never for running."""
        if not dry:
            # IDENTITY IS RE-ASSERTED PER BOX, not once per Sandbox, and an independent test is the
            # reason. He overwrote the verified binary IN PLACE with `/bin/true` while a Sandbox was
            # open: the next call correctly refused to report an empty run as a success, and the message
            # it refused with quoted the version from the FIRST verification - so it stated that a file
            # which now prints `true (GNU coreutils) 9.4` had "reported 'kern v0.9.32-48-gb578943'", and
            # then offered two explanations, neither of them the truth. The verdict was right and the
            # sentence was false, which is this project's most expensive class of defect.
            #
            # Re-verifying here rather than repairing that sentence, because the sentence was only the
            # symptom: the binary about to run was no longer the binary that was checked. The memo is
            # keyed on `(realpath, dev, ino, size, mtime_ns)`, so an unchanged file costs one `os.stat`
            # and a dict lookup: MEASURED at 10.1 us over 20000 calls, against a box that costs ~4 ms,
            # so 0.25%. A file that HAS changed pays one `--version` (0.44 ms) and is refused by name if
            # it is no longer kern.
            self._kern_version = _verify_is_kern(self._kern)
        argv = [self._kern, "box", name, "--image", self.image, "--ro", "-v", f"{self._ws}:{_WORKSPACE}",
                "--workdir", _WORKSPACE]
        # deps_readonly: mount <workspace>/.deps read-only OVER the writable workspace for run_code boxes
        # (not the setup box, which must populate it). Closes the cross-run dep-poisoning window within a
        # session for tighter (still semi-trusted) workloads. Default off - deps writable, documented.
        if self.deps_readonly and not is_setup:
            deps = os.path.join(self._ws, _DEPS_DIR)
            if os.path.isdir(deps):
                argv += ["-v", f"{deps}:{_WORKSPACE}/{_DEPS_DIR}:ro"]
        # The image's precompiled stdlib, read-only. Not on the setup box: that one installs deps and
        # then compiles them into `.deps/__pycache__`, which the prefix would redirect into a mount it
        # cannot write. `__enter__` already excluded a session that has deps at all.
        if self._pyc_dir and not is_setup:
            argv += ["-v", f"{self._pyc_dir}:{_PYC_MOUNT}:ro"]
        # kern's own --timeout is a tight BACKSTOP just beyond our deadline: it is the RELIABLE killer of
        # the in-PID-namespace box (a CPU-bound box survives a SIGKILL of kern's parent process, but not
        # kern's own timeout teardown). OUR proc.wait deadline is the authority that LABELS a `timeout`
        # fault; kern's backstop guarantees the box is actually gone a few seconds later.
        argv += self._cap_drop_args
        if self._single_uid:
            argv.append("--no-uid-range")
        argv += ["--timeout", str(int(timeout_s) + 5)]
        if self.memory_mb is not None:
            argv += ["--memory", f"{self.memory_mb}m"]
        if self.cpus is not None:
            argv += ["--cpus", str(self.cpus)]
        if self.pids is not None:
            argv += ["--pids-limit", str(self.pids)]
        if self.require_limits:
            argv.append("--require-limits")
        if self.security_profile is not None:
            argv += ["--security-profile", self.security_profile]
        if self.apparmor is not None:
            argv += ["--apparmor", self.apparmor]
        # Network mode for THIS box. egress_allow (a domain allowlist via an isolated netns + kern's
        # filtering proxy) governs the untrusted run_code/run boxes; the setup box keeps the full network
        # it needs to install deps. egress_allow and network are mutually exclusive (checked at construct).
        if self._egress_allow and not is_setup:
            argv += ["--egress-allow", ",".join(self._egress_allow)]
        elif network:
            argv += ["--net"]
        # Resource profiles (vcpu:/vgpio:/vdisk:NAME) are positional tokens `kern box` resolves against the
        # user's kern.toml. Validated at construction, so nothing here can be a smuggled flag.
        argv += self._profile_args
        argv += self._mount_args
        # Scratch for THIS box. The DEFAULT tmpfs is deliberately skipped on the setup box, for the same
        # reason the egress allowlist is: setup is the install phase, and an install needs unbounded
        # scratch. `pip install pandas` puts its build tree in TMPDIR, so a 64 MiB /tmp turns a working
        # install into `OSError [Errno 28] No space left on device` (measured, and it is why this
        # condition exists). With no tmpfs, setup's temp falls back to the workspace on the host disk,
        # which is exactly where a large, short-lived build tree belongs. An EXPLICIT `tmpfs=` is the
        # caller's decision and applies to every box, setup included.
        if not (is_setup and self._tmpfs_default):
            argv += self._tmpfs_args
        merged_env = dict(self.env or {})
        # Deps installed by `setup` live in <workspace>/.deps - put them on PYTHONPATH for run_code.
        merged_env.setdefault("PYTHONPATH", f"{_WORKSPACE}/{_DEPS_DIR}")
        # `setdefault`, so a caller who sets `PYTHONPYCACHEPREFIX` in `env=` keeps their own: this is an
        # optimisation and must never overrule an explicit choice. Set only when the mount above exists,
        # or the interpreter would look for bytecode in a directory that is not there.
        if self._pyc_dir and not is_setup:
            merged_env.setdefault("PYTHONPYCACHEPREFIX", _PYC_MOUNT)
        # Pass the workload env via a private --env-file, NOT `--env K=V` on argv: an argv value is
        # visible in `ps` / /proc/<pid>/cmdline to any local user for the box's lifetime, and this
        # component's whole point is running untrusted code beside sensitive data (a credential in
        # `env=` would leak). The file lives in our own 0700 mkdtemp workspace, written 0600, so it is
        # not readable by other users; kern reads it before the box's env is set up. (Hacker-mode audit.)
        # `_ws` is set by `__enter__`; before that it is "". The public API is gated by
        # `_require_entered`, but the unit tests call `_base_argv` directly to inspect the argv, and
        # with an empty workspace `os.path.join` yielded a RELATIVE path: the env file was written into
        # the current directory. It has been landing in the repository for as long as those tests have
        # existed, hidden by a `.kern-env` line in `.gitignore` that stopped matching when the name
        # became per-call. No workspace means nowhere to put it, so there is nothing to write.
        if merged_env and dry:
            # The path is per-box by construction, so it can never be part of a posture comparison; a
            # constant stands in for it. The env CONTENT is still compared, because a session that changes
            # `env=` must invalidate warm boxes: it is folded in here rather than left out.
            argv += ["--env-file", "\0".join(f"{k}={v}" for k, v in sorted(merged_env.items()))]
        elif merged_env and self._ws:
            env_path = self._claim_path(self._env_path(name))
            # SECURITY: the box has rw access to the workspace and could plant `.kern-env` as a symlink
            # to a host file (e.g. ~/.ssh/authorized_keys); a follow-through open would O_TRUNC-clobber
            # it. Unlink any existing entry (removing a planted symlink), then create fresh with
            # O_EXCL|O_NOFOLLOW so we never write through a symlink. Fails closed on a concurrent re-plant.
            try:
                os.unlink(env_path)
            except FileNotFoundError:
                pass
            fd = os.open(
                env_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            try:
                # K=V lines; values are single-line by construction (a NUL is rejected in _spawn, and a
                # newline in a value would split the record - reject it here so it can't smuggle a var).
                lines = []
                for k, v in merged_env.items():
                    if "\n" in k or "\n" in v or "\0" in k or "\0" in v:
                        raise SandboxError(f"env var {k!r} must not contain a newline or NUL")
                    lines.append(f"{k}={v}\n")
                os.write(fd, "".join(lines).encode())
            finally:
                os.close(fd)
            argv += ["--env-file", env_path]
        return argv

    def _scratch_note(self) -> str:
        """The clause an OOM message owes when this box has scratch mounted.

        A tmpfs is charged to the box's memory cgroup and its pages are NOT reclaimable: measured,
        56 MiB written to /tmp and then 90 MiB allocated under `memory_mb=128` is an OOM, while the
        SAME 56 MiB written to the workspace and synced leaves the allocation room, because file-backed
        pages can be written back and dropped. So a file left in scratch is a hard subtraction from the
        budget, and an OOM message that names only "memory cap" sends the reader to look at their
        allocation. This states the mechanism, and does NOT claim scratch caused this particular kill:
        that is not knowable from here."""
        ours = ", ".join(a for a in self._tmpfs_args if a != "--tmpfs")
        # `/dev/shm` is named even when we mounted nothing, and it is named SECOND, because the first
        # version of this note pointed only at our own scratch: writing 200 MiB to /dev/shm under
        # `memory_mb=128` OOMs the box, and the message said `/tmp:64m`, which is the wrong place.
        # The fix for a misattributing message had misattributed, and for the reason it exists to
        # prevent: it named what the author had in mind rather than what the kernel acted on.
        #
        # It lists CANDIDATES rather than naming the one that took the budget, and that is a measured
        # limit rather than laziness. The evidence is destroyed by the kill: read post mortem, the
        # box's own cgroup reports `shmem=978944 anon=0` after 200 MiB went through /dev/shm, because
        # the mount died with the box and the pages went with it. `memory.events` still says
        # `oom_kill 3 oom_group_kill 1`, which confirms the kill and attributes nothing. Naming one
        # path would mean sampling `memory.stat` while the box is alive, on every run, for a message
        # that is only ever read after a failure.
        return (
            ". NOTE: memory-backed filesystems in this box are charged to that same cap, and their "
            "pages are freed only by DELETING the files: "
            + (f"the scratch this SDK mounted ({ours}), and " if ours else "")
            + "/dev/shm, which every kern box has as a tmpfs with NO size limit (its apparent size is "
            "half the HOST's RAM) and which no option here can bound. Check both before the workload"
        )

    def _pyc_adopt_if_ready(self) -> None:
        """Adopt the bytecode cache THIS session's own build produced, on the first call after it lands.

        WHY THIS EXISTS. Adoption used to happen only in `__enter__`, which made the session that paid
        for the build the one session that never used it. Measured on a held-open Sandbox: `_pyc_dir`
        stayed empty for the whole life of the session, seconds after the tree was published with 1097
        files, and every call kept compiling from source. A one-shot `run_code` was unaffected because
        each call is its own session (measured: the 5th call, 2.3 s in, was the first to drop from 70 ms
        to 21). A held-open Sandbox is the agent loop, which is the shape this package is for.

        WHY THE FREEZE WAS NOT WORTH ITS PRICE. It was defending the prewarm pool: `_base_argv` is what
        `_WarmPool._key` compares postures with, so an argv that changes mid-session invalidates every
        box already warm. That cost is real and it is ALREADY absorbed - `claim` kills the boxes whose
        key no longer matches and `_start_one` rebuilds the key from the live argv, which is the very
        machinery `_key` documents for a `.deps` remount appearing mid-session. So the price is one
        claim that misses, once, not a session that never gets the cache.

        BOTH GUARDS RUN AGAIN. The directory did not exist at `__enter__`, so the state the symlink walk
        reads is new. The lexical check is re-run with it rather than trusted from then, so the refusal
        does not depend on reasoning about which of the two could have changed in between.

        Called on the CALLER's thread, before the pool is asked for a box, so the claim that follows
        already compares against the new posture. `kernel()` is deliberately not covered: its box is
        started once and lives on, and a warm interpreter compiles the stdlib once anyway.
        """
        dest = self._pyc_pending
        # Empty means NOT READY, so the pending destination is kept: either the build has not
        # published yet, or what is there is the husk kern recreates under a swept mount, and the
        # next session's `__enter__` is what rebuilds that.
        if not dest or not _pyc_has_content(dest):
            return
        # Cleared FIRST and unconditionally: a refusal below must not leave this session re-checking a
        # path it has already rejected on every call it makes.
        self._pyc_pending = ""
        # The deps guard again, for the same reason as the two below: `__enter__` asked this question
        # before the build existed, and a prefix pointed at a read-only mount would make the setup box's
        # own precompile unreachable and hand back the 40 ms per call it exists to remove.
        if os.path.isdir(os.path.join(self._ws, _DEPS_DIR)):
            return
        try:
            _validate_mount_lexical(dest, _PYC_MOUNT)
        except MountRefused:
            return
        if not _pyc_path_has_no_symlink(dest):
            return
        self._pyc_dir = dest
        try:
            os.utime(dest, None)  # best effort, as at `__enter__`: it only orders the sweep
        except OSError:
            pass
        _pyc_start_sweep(os.path.dirname(dest))

    def _spawn(
        self,
        command: Sequence[str],
        *,
        network: bool,
        timeout_s: int,
        is_setup: bool = False,
        on_stdout: object = _UNSET,
        on_stderr: object = _UNSET,
    ) -> ExecutionResult:
        self._pyc_adopt_if_ready()  # one attribute read once there is nothing left to wait for
        cb_out = self.on_stdout if on_stdout is _UNSET else on_stdout
        cb_err = self.on_stderr if on_stderr is _UNSET else on_stderr
        for part in command:
            if "\0" in part:
                raise SandboxError("command/code must not contain a NUL byte")
        before = self._snapshot() if self.track_files else None  # skip the O(N) walk when not tracked
        name = _unique_name()
        # The env file is named after THIS box, and removed in the `finally` below. It used to be one
        # fixed `.kern-env` per workspace, which two concurrent calls on the same Sandbox raced for:
        # both `unlink`ed it, both re-created it with `O_EXCL`, and the loser got a bare
        # `FileExistsError` out of `run_code`. Measured at 40 threads: 11 of 40 calls failed that way.
        # The `O_EXCL|O_NOFOLLOW` create is a security property (it refuses to write through a symlink
        # the box may have planted) and is kept exactly as it was; only the NAME becomes per-call, so
        # two calls no longer contend for one path. It is also cleaned up now: with a persistent
        # `workspace=`, the old fixed file was left behind after every session.
        argv = self._base_argv(name, network=network, timeout_s=timeout_s, is_setup=is_setup) + ["--"] + list(command)
        child_env = dict(os.environ)
        if not self.enforce_limits:
            child_env["KERN_NO_SCOPE"] = "1"
        started = time.monotonic()
        # An UNFORGEABLE "box started" channel: kern writes one byte to KERN_STARTED_FD's write end iff
        # its sandbox setup SUCCEEDED and the command ran. The workload never holds this fd, so it can
        # neither forge nor suppress the signal - unlike kern's stderr, which it can. A new kern makes
        # this the authority for `startup_failed`; an OLD kern never writes it, so the read below sees EOF
        # and the stderr heuristic stands (backward compatible).
        started_r, started_w = os.pipe()
        child_env["KERN_STARTED_FD"] = str(started_w)
        # A SECOND, LIVE channel, because the first one is post-mortem. kern writes KERN_STARTED_FD at the
        # box's TEARDOWN, so when OUR deadline fires we kill kern before that write and learn nothing: a
        # workload that was slow and a kern whose SETUP blocked are the same overrun. KERN_ALIVE_FD is the
        # box's readiness pipe: EOF when the workload `execvp`s (the box child marks it FD_CLOEXEC), one
        # byte when setup or exec failed, and NEITHER while kern is still building the box. That third
        # state is the one nothing could observe, and it is what separates a `timeout` from a box that
        # never started. MEASURED as the class behind a FIFO volume source: 404 seconds inside
        # `wait_for_partner`, reported as `timeout`, which is the class an agent retries forever.
        alive_r, alive_w = os.pipe()
        child_env["KERN_ALIVE_FD"] = str(alive_w)
        box_started = False
        cap_signal = 0  # 2nd started byte: 0 undetermined/old-kern, 1 memory cap enforced, 2 not enforced
        oom_signal = None  # 3rd started byte: 1 = OOM-killed, 0 = not, None = this kern does not say
        # None = never asked (we did not time out); otherwise one of the three `_ALIVE_*` states.
        alive_state: "str | None" = None
        # None = this kern does not report it. 0 = the workload exited on its own; otherwise the signal
        # number that terminated it.
        workload_signal: "int | None" = None
        try:
            try:
                # start_new_session so the box + kern share a process group we can signal as a unit.
                proc = subprocess.Popen(  # noqa: S603 - argv list, no shell
                    argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=child_env,
                    start_new_session=True, pass_fds=(started_w, alive_w),
                )
            except FileNotFoundError as e:
                raise SandboxError(f"could not execute kern: {e}") from e
            except OSError as e:
                # E2BIG (argv too long) and other spawn-time OS errors → a clean typed error, not a raw
                # OSError leaking out of the binding. (run_code already routes large code via a file.)
                raise SandboxError(f"could not spawn the box: {e}") from e
            finally:
                os.close(started_w)  # the parent never writes; closing lets the read side see EOF
                os.close(alive_w)  # same reason: with our copy open, EOF could never arrive
            out = _CappedReader(proc.stdout, self.max_output_bytes, cb_out)
            err = _CappedReader(proc.stderr, self.max_output_bytes, cb_err)
            out.start()
            err.start()
            # OUR deadline - the authority for a `timeout` fault. Blocking on a pidfd rather than
            # polling: `Popen.wait(timeout=)` would sleep past the box's exit by 3.2 ms on every
            # call (see _wait_for_exit). The teardown stays HERE, on this thread, where the child is
            # still an unreaped zombie and its pid therefore cannot have been recycled under us.
            we_timed_out = not _wait_for_exit(proc, timeout_s)
            if we_timed_out:
                # BEFORE THE KILL, and that ordering IS the measurement. Our teardown kills kern, every
                # copy of the alive fd closes with it, and the read end then shows EOF whatever the box was
                # doing - so asking afterwards always answers "it started". Asked here, while kern is
                # still alive, the pipe separates the two overruns.
                alive_state = _alive_state(alive_r)
                self._teardown(proc, name, child_env)
            # Join readers, but BOUNDED: a CPU-bound box can survive our signals and hold the pipe open
            # until kern's own --timeout backstop reaps it a few seconds later; never hang the caller on it.
            join_deadline = 8.0 if we_timed_out else None
            out.join(join_deadline)
            err.join(join_deadline)
            # Reap the process so returncode is populated and no zombie lingers (bounded - the backstop
            # has reaped the box by now in the timeout case). On the normal path _wait_for_exit above
            # has already reaped, and this returns immediately on the returncode check.
            _wait_for_exit(proc, 8.0)
            # kern has exited, so its write end is closed. Byte 0 = the box started (setup succeeded,
            # command ran); EOF (empty) = it never started, or an old kern that does not signal. Byte 1
            # (a NEWER kern only) = the memory-cap enforcement signal; absent (EOF) = undetermined.
            # Byte 2 (a NEWER kern still) = the OOM OUTCOME: 1 iff the kernel's OOM killer fired against
            # this box's OWN cgroup. Enforcement is not an outcome, which is the distinction the whole
            # `oom` vs `killed` split rests on, and this byte is the only place the answer arrives where
            # the workload cannot write it.
            # Byte 3 (a NEWER kern still) = the SIGNAL that terminated the workload, or 0 if it exited
            # on its own. `None` here means the byte did not arrive at all, which is a DIFFERENT thing
            # from a zero: an older kern, or a kern our own teardown killed before it could write.
            try:
                sig = os.read(started_r, 4)
            except OSError:
                sig = b""
            box_started, cap_signal, oom_signal, workload_signal = _parse_started_bytes(sig)
        finally:
            # Every exit path, including the two SandboxErrors above: kern has read the file by the time
            # it exits, and leaving it behind would accrete one per call in a persistent workspace.
            try:
                os.unlink(self._env_path(name))
                self._release(os.path.basename(self._env_path(name)))
            except OSError:
                pass
            for fd in (started_r, alive_r):
                try:
                    os.close(fd)
                except OSError:
                    pass
        wall_ms = int((time.monotonic() - started) * 1000)
        stdout = out.buf.decode("utf-8", "replace")
        stderr = err.buf.decode("utf-8", "replace")
        rc = proc.returncode if proc.returncode is not None else -1
        # SIGNAL DEATHS ARE REPORTED AS 128+N, NOT AS -N.
        #
        # `subprocess` gives `-9` for a process killed by SIGKILL; the Node binding gives 137
        # for the same event, because that is what a shell, kern's own CLI and docker report.
        # Two bindings describing one event with two numbers is a contract defect: an external
        # review ran the same timeout through both and got `-9` here and `137` there, so a
        # caller branching on `exit_code == 137` saw the timeout in Node and missed it here.
        #
        # 137 agrees with everything else a reader compares against, so Python is the one that
        # moves. `fault` was already correct on both sides and is what code should branch on;
        # this aligns the number for code that does not.
        if rc < 0:
            rc = 128 + (-rc)
        fault = self._classify(
            rc, stderr, we_timed_out, timeout_s, cap_signal, oom_signal, alive_state, workload_signal,
            box_started,
        )
        # IDENTIFYING ITSELF IS NOT BEHAVING, and this is the layer that says so. `_verify_is_kern`
        # refuses a binary that does not answer `kern <version>`; a stub that DOES answer it and then
        # exits 0 got through, and the call came back `success=True, exit_code=0, fault=None` with an
        # empty stdout - the original defect, one layer down. MEASURED with a two-line shell script.
        #
        # The invariant that closes it: a kern that ran a box WRITES the started byte, and has done so
        # since v0.9.2 (`f5494ab`). So `exit 0` with no byte, no stdout and no stderr is not a box that
        # ran silently: it is nothing having happened at all.
        #
        # A FAULT AND NOT A RAISE, deliberately. On a host where that byte somehow did not arrive, a
        # raise would break a legitimate silent command; a fault leaves the caller a result to read and
        # still refuses to call it a success. All four conditions are required for the same reason: any
        # output, any non-zero code, or the byte itself is evidence that something ran.
        if (
            fault is None
            and rc == 0
            and not box_started
            and not stdout.strip()
            and not stderr.strip()
        ):
            fault = SandboxFault(
                "startup_failed",
                f"'{self._kern}' reported '{self._kern_version}' but never signalled that a box "
                f"started, and produced no output: the code did not run. kern has written that signal "
                f"since v0.9.2, so this is either a binary older than that or one that only looks like "
                f"kern. Refusing to report an empty run as a success",
            )
        exec_fail = _exec_failure_binary(stderr)
        if exec_fail is not None and rc != 0:
            # BEFORE the suppression below, which would erase it: the box started, so that branch
            # would read kern's own marker as a workload forgery.
            #
            # The REASON is carried through rather than assumed. The first version said "does not
            # exist in the box" for every case, and exit 126 (EACCES: the file is there and is not
            # executable) and a script whose interpreter line names a missing binary both got a
            # message blaming the image for a file that exists. That is the same defect this fault
            # was added to remove: a message that sends the reader to the wrong place.
            what, reason = exec_fail
            if "No such file or directory" in reason:
                detail = (
                    f"No such file or directory. The image {self.image!r} does not provide it, or its "
                    f"interpreter line names something the image lacks."
                    # The one case where the remedy is not "a different image": every image has a POSIX
                    # shell, so a caller who asked for bash and does not need bash has a one-word fix.
                    + (" This image has no bash; use language='sh' if the script is POSIX."
                       if what == "bash" else "")
                )
            elif "Permission denied" in reason:
                detail = "Permission denied: it is present in the box but not executable there."
            else:
                detail = reason or "the box could not execute it"
            fault = SandboxFault("exec_failed", f"{what!r} could not be started in the box: {detail}")
        elif fault is not None and fault.type == "startup_failed" and (box_started or stdout.strip()):
            # kern signalled the box STARTED, so a `startup_failed` here can only be the stderr heuristic
            # matching a marker the WORKLOAD wrote (the code-based faults are decided before it). The box
            # demonstrably ran: this is the workload's own non-zero exit - reclassify to a normal result.
            #
            # STDOUT IS THE SECOND WITNESS, and it is here because the first one can be absent. MEASURED
            # with a KERN_BIN wrapper that closes `KERN_STARTED_FD` before exec'ing the real kern: the box
            # ran, printed, exited 1 with `error: forged` on stderr, and came back `startup_failed` - a
            # box that had demonstrably run, reported as one that never started. The same hole is open on
            # any kern too old to write the byte, and on one our own teardown kills before it can.
            # A box that never started cannot print: every genuine startup failure measured here
            # (`image=""`, a registry miss, a bad tag, a missing profile) returns stdout EMPTY, so
            # non-empty stdout is proof the workload ran. It is only ever read in this direction - as
            # evidence FOR a box having run, never against - so a silent workload loses nothing.
            fault = None
        # A box that FAILED TO START ran no user code, so raise rather than return a hollow
        # ExecutionResult (empty stdout). Gated on `rc == 125` (kern's Docker-convention box-not-started
        # code) AND the startup_failed classification (which requires kern's own stderr marker): this
        # confident pair is what tells a genuine box-not-started apart from a workload that itself exited
        # 125 (that has no kern marker -> fault is None -> a normal result). An older kern that exits 127
        # keeps the old behavior (returned as a data fault, not raised). Runtime events where the code DID
        # run (timeout, OOM-kill, blocked escape) stay as DATA on `.fault`, unchanged.
        if rc == 125 and fault is not None and fault.type == "startup_failed":
            raise SandboxError(fault.message or "the box failed to start")
        files = self._diff(before) if before is not None else []
        return ExecutionResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=rc,
            duration_ms=wall_ms,
            fault=fault,
            files=files,
            truncated=out.truncated or err.truncated,
        )

    def _teardown(self, proc: "subprocess.Popen", name: str, child_env: dict) -> None:
        """Best-effort tear down a timed-out box. Defense in depth, because a CPU-bound box in its own
        PID namespace survives a plain SIGKILL of kern's parent process: (1) `kern stop` - the intended
        teardown (cgroup-kill); (2) SIGKILL the whole process group; (3) SIGKILL the parent. kern's own
        --timeout backstop guarantees the box is gone shortly regardless. We never block here."""

        try:
            subprocess.run(
                [self._kern, "stop", name], env=child_env, capture_output=True, timeout=5
            )
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
        try:
            proc.kill()
        except OSError:
            pass

    def _classify(
        self,
        rc: int,
        stderr: str,
        we_timed_out: bool,
        timeout_s: "int | float | None" = None,
        cap_signal: int = 0,
        oom_signal: "int | None" = None,
        alive_state: "str | None" = None,
        workload_signal: "int | None" = None,
        kern_wrote_payload: bool = False,
    ) -> SandboxFault | None:
        # ORDER IS A SECURITY PROPERTY. The classes that are DETERMINISTIC by exit code are decided
        # FIRST, BEFORE we ever look at stderr - because stderr is a channel the workload controls, and
        # `startup_failed` is recognised by a pattern on it. If we checked the stderr marker first, a
        # workload could print "error: sandbox:" and exit with SIGSYS and we'd mislabel a blocked escape
        # as a mere startup failure - hiding a security event behind a benign one. So: our-deadline →
        # SIGSYS → SIGKILL, all by exit code, THEN the stderr-marker heuristic as the LAST resort.
        # (Same discipline as the tar vetter: never make a security decision by parsing an
        # adversary-influenceable channel.)
        if we_timed_out:
            # OUR deadline fired and we killed the box - a known fact, never guessed.
            limit = self.timeout_s if timeout_s is None else timeout_s
            # AND THE DEADLINE ALONE DOES NOT SAY WHOSE FAULT IT WAS. `reached_workload is False` is
            # kern's own answer, read off the readiness pipe while kern was still alive: the box was
            # still being BUILT, so the code never ran and calling this a `timeout` would tell the caller
            # their workload was slow. That class was measured with a FIFO volume source (404 seconds in
            # `wait_for_partner`), and the shapes behind it - an `lstat` on a dead NFS mount, a FUSE whose
            # daemon is gone - are not FIFOs and cannot be refused by type.
            #
            # Every other state keeps the old verdict: `_ALIVE_PAST_SETUP` because the code really did
            # run, and `_ALIVE_UNKNOWN` (an older kern, a failed poll) because absence of evidence is
            # not evidence. This reports `startup_failed` only on kern's own positive answer.
            if alive_state == _ALIVE_IN_SETUP:
                return SandboxFault(
                    "startup_failed",
                    f"the box never started: kern was still setting it up when the {limit}s deadline "
                    "fired, so the code never ran. Two shapes of cause, and they want opposite remedies. "
                    "PERMANENT: a host path that blocks - a bind source on a dead NFS, a FUSE mount whose "
                    "daemon is gone - where the remedy is that path and a longer timeout changes nothing. "
                    "TRANSIENT: the image had to be read cold, which is what the FIRST call on a machine "
                    "that just booted does (a warm box of this shape costs about 15 ms, and a 114 MB image "
                    "read off a busy disk does not), where a longer timeout is exactly the remedy. Run it "
                    "again: if the second call is fast, it was the cold read",
                )
            return SandboxFault("timeout", f"exceeded the {limit}s time limit (killed by the binding)")
        # THE EXIT CODE IS THE RIGHT THING TO PROPAGATE AND THE WRONG THING TO CLASSIFY FROM, which is
        # what `_killed_by` exists for: kern reports `128 + N` as its own status, so a workload the kernel
        # killed and one that called `exit(137)` are the same number. MEASURED: a cell doing
        # `sys.exit(137)` was reported `fault = killed` with a message about an external kill that never
        # happened, and `sys.exit(159)` was reported `escape_blocked`, a security event a cell could
        # fabricate in one line. kern's 4th started-byte carries the signal, so the three signal-derived
        # classes below ask for it. `None` (an older kern, or a kern our teardown killed before it could
        # write) keeps the old exit-code reading: absence of evidence is not evidence.
        def _killed_by(sig: int) -> bool:
            return workload_signal is None or workload_signal == sig

        if rc == _EXIT_SIGSYS and _killed_by(signal.SIGSYS):
            # A seccomp-denied syscall. Decided by exit code plus kern's signal byte, so neither stderr
            # content nor a chosen exit code can mask it or fake it.
            return SandboxFault("escape_blocked", "a syscall was blocked by the seccomp filter (SIGSYS)")
        if (rc == _EXIT_SIGKILL and _killed_by(signal.SIGKILL)) or rc == -signal.SIGKILL:
            # SIGKILL not from our deadline: exit 137 (128+9), or subprocess's -9 if kern itself was
            # signalled. `oom` is claimed only on kern's own OBSERVATION of the kernel's counter for this
            # box's cgroup, from the UNFORGEABLE byte first and its stderr sentence second.
            #
            # THE BYTE IS THE AUTHORITY, THE SENTENCE IS FOR AN OLDER KERN. The 3rd byte of
            # KERN_STARTED_FD is written to a pipe the workload never holds, so it cannot be forged or
            # suppressed; the sentence goes to the stream the workload also writes, so a cell could print
            # it and relabel its own `killed` as `oom`. A kern that predates the byte still reports the
            # OOM in text, so the fallback is what keeps a mixed pair (new SDK, old binary) correct
            # instead of quietly downgrading every real OOM to `killed`.
            #
            # WHAT THIS REPLACED, because the replaced version read as sound: a SIGKILL of a
            # memory-capped box was called the cgroup OOM-killer, which is what a breached
            # `memory.max` does (kern sets `memory.oom.group=1`, so the whole box goes at once).
            # MEASURED: `kern stop` during a cell returns 137, so it came back `oom`, and an agent
            # branching on the fault would retry with MORE MEMORY a kill that had nothing to do with
            # memory. A confident wrong answer is worse than an unclassified one.
            #
            # The first repair kept the inference for `cap_signal == 0` ("an older kern that cannot
            # tell"), which changed nothing: MEASURED, the byte is 0 on this host for every run, so
            # that branch still covered every case. Hence no inference at all. kern has printed the
            # OOM sentence since 2026-09-04; against a kern older than that a real OOM now reads
            # `killed`, wrong in the direction that costs nothing - the agent does not retry memory.
            if _oom_verdict(oom_signal, stderr, kern_wrote_payload=kern_wrote_payload):
                return SandboxFault("oom", "the box exceeded its memory cap and was OOM-killed (SIGKILL)"
                                    + self._scratch_note())
            # `cap_signal` (kern's UNFORGEABLE enforcement byte: 1 = the cap was enforced, 2 =
            # requested but NOT enforced here, 0 = undetermined) no longer decides the TYPE, and a 2
            # still earns its own sentence: that the cap never bound is the one thing the caller
            # cannot discover for itself, and it explains why no OOM was reported against it.
            if cap_signal == 2:
                return SandboxFault(
                    "killed",
                    "the box was SIGKILLed, and its memory cap was not enforced here (no cgroup "
                    "delegation), so no memory limit was in force to attribute it to",
                )
            if self.memory_mb is not None:
                return SandboxFault(
                    "killed",
                    "the box was SIGKILLed and the kernel reported no OOM against its memory cap: "
                    "this is an external kill (`kern stop`, a signal, or the host's own OOM killer), "
                    "not the box exceeding its own memory",
                )
            return SandboxFault("killed", "the box was killed (SIGKILL); no memory cap was set to attribute it to OOM")
        if (rc == _EXIT_SIGTERM and _killed_by(signal.SIGTERM)) or rc == -signal.SIGTERM:
            # SIGTERM without our deadline firing = kern's OWN --timeout backstop reaped the box (it
            # SIGTERMs, then SIGKILLs after a grace). The box exceeded its time limit; label it timeout,
            # noting the backstop caught it rather than our own wait.
            return SandboxFault("timeout", "the box exceeded its time limit (reaped by kern's timeout backstop)")
        # Box-not-started: a non-zero exit whose stderr carries kern's OWN setup-diagnostic markers
        # (printed by the PARENT before the box runs). kern's box-not-started paths BOTH exit 125 (see
        # `box_start_exit_code`) AND print a `kern:` marker, so `rc == 125 && marker` is the reliable
        # signal - and the marker is REQUIRED so a workload that merely exits 125 ITSELF (the code ran and
        # chose 125) is NOT mislabeled as a startup failure. Heuristic because stderr is workload-
        # influenceable, but it can only ever mislabel an ordinary non-zero user exit, never mask an
        # escape/timeout/kill (those were decided above by exit code). `_spawn` RAISES only on the 125
        # case (the caller then knows the code never ran); an older kern that exits 127 with a marker
        # still classifies startup_failed but is returned as DATA, not raised.
        if rc != 0 and _looks_like_startup_failure(stderr):
            return SandboxFault("startup_failed", _startup_failure_message(stderr))
        # exit 139 (SIGSEGV) and any other non-zero exit are the USER's code failing - a normal Result.
        return None

    # -- workspace file I/O (host-direct; single-uid → box files are host-owned) ---------------------

    def _env_path(self, name: str) -> str:
        """Host path of the private --env-file for the box called ``name``, inside the workspace."""
        return os.path.join(self._ws, f"{_ENV_FILE}{_ENV_SEP}{name}")

    def _claim(self, name: str) -> str:
        """Record ``name`` as a file this BINDING put in the workspace, and return it.

        Hiding our scratch by the SHAPE of its name was an invitation with the instructions printed on
        it: the workspace is writable by the box, so anything that writes `/workspace/.cell-deadbeef.py`
        buys invisibility from ``list_files``/``snapshot``/``files``, which is exactly the listing a
        caller would audit. Provenance cannot be imitated: membership is by exact name, the set is only
        ever added to here, and every name in it was generated by this process.

        The failure mode of the strict version is the honest one. A scratch file orphaned by a killed
        process REAPPEARS as user state in a reused `workspace=`, which is visible and true, rather than
        staying hidden forever because its name still fits a pattern.
        """
        self._ours.add(name)
        return name

    def _claim_path(self, path: str) -> str:
        """`_claim` for a caller holding a full host path: the registry keys on the workspace-relative
        name, which is what `_walk` compares against."""
        self._claim(os.path.basename(path))
        return path

    def _release(self, *names: str) -> None:
        """Stop claiming ``names``. Call AFTER unlinking, never before: in the window between, a
        concurrent call's `_walk` would report a file that is still on disk as freshly created."""
        self._ours.difference_update(names)

    def _is_ours(self, rel: str) -> bool:
        """Is ``rel`` this binding's own file rather than user state?

        `_ENV_FILE` bare is kept as an exact legacy match: a workspace written by an older version has
        one, and it is ours even though this process did not create it. The `.kern-env.<box>` PREFIX is
        deliberately no longer matched, because that was the same open invitation as the shapes above.
        """
        return rel in self._ours or rel == _ENV_FILE

    def _ws_path(self, rel: str) -> str:
        """Resolve a workspace-relative path for host-side I/O, refusing any escape out of the workspace.

        Containment is checked on the requested path LEXICALLY (normalize `..`/`.`), NOT by resolving
        symlinks in it - a symlink the box created can point at a box-absolute target like
        `/workspace/x` that doesn't exist on the host, and `realpath`-ing it would both false-positive
        (a legitimate INTERNAL symlink) and, worse, could be steered to follow a link out of the tree.
        So: lexically contain the requested name here, then open the final component with O_NOFOLLOW
        (in read/write) so a symlinked LAST component can't redirect the host I/O outside the workspace.
        """
        base = self._ws  # canonical since enter - no per-walk re-resolution
        # A NUL BYTE IS REFUSED HERE, or it is refused by `os.open` as a bare `ValueError` that the
        # caller sees as `internal error: ValueError` with no path in it. Found through the MCP server,
        # where that string is what a MODEL reads: every other bad path on this route answers with a
        # sentence naming the path and the reason, and this one read as a broken tool. NUL is also the
        # terminator every path API below Python uses, so a name carrying one cannot mean what it says.
        if "\x00" in rel:
            raise SandboxError(
                f"path contains a NUL byte: {rel!r}. A NUL terminates a path for every API below this "
                "one, so the name cannot mean what it appears to say"
            )
        # AN ABSOLUTE PATH IS NOT A WORKSPACE PATH, and that is checked HERE rather than left to
        # `os.path.join`, which happens to drop `base` when the second argument is absolute. Node's
        # `path.join` does the OPPOSITE (it keeps the base), so the same three lines refused here and
        # silently resolved `<workspace>/etc/passwd` there: MEASURED, `readFile("/etc/passwd")` returned a
        # decoy the box had planted at that relative path, and `writeFile` wrote into it. The boundary held
        # either way; the ANSWER was a different file's contents than the one asked for. A caller who
        # passes a host path is asking for a host file, and the honest answer is a refusal.
        if os.path.isabs(rel):
            raise SandboxError(
                f"path escapes the workspace: {rel!r} is absolute, and these calls take a path RELATIVE "
                "to the workspace. Nothing outside it is readable or writable through them, and an "
                "absolute path is NOT reinterpreted as a workspace one"
            )
        # Lexical containment: join + normpath collapses `..`, then require it stays under base.
        full = os.path.normpath(os.path.join(base, rel))
        if full != base and not full.startswith(base + os.sep):
            raise SandboxError(f"path escapes the workspace: {rel!r}")
        return full

    def _ensure_parent_dirs(self, full: str) -> None:
        """Create the parent dirs of ``full`` under the workspace WITHOUT following a symlink in any
        intermediate component. ``mkdir(parents=True)`` follows symlinks, so a box that plants
        ``a -> /etc`` could steer a ``write_file("a/b.txt")`` outside the workspace even though the final
        component is opened ``O_NOFOLLOW``. Descend one level at a time from the (canonical) workspace
        base: reject a symlink component, create a missing dir non-recursively."""
        base = self._ws
        rel_dir = os.path.relpath(os.path.dirname(full), base)
        if rel_dir in ("", "."):
            return  # parent is the workspace root itself
        cur = base
        for part in rel_dir.split(os.sep):
            if not part or part == ".":
                continue
            nxt = os.path.join(cur, part)
            try:
                st = os.lstat(nxt)
            except FileNotFoundError:
                os.mkdir(nxt)  # non-recursive: each level is a fresh real dir we just created
                cur = nxt
                continue
            if stat.S_ISLNK(st.st_mode):
                raise SandboxError(f"path escapes the workspace via a symlinked directory: {part!r}")
            if not stat.S_ISDIR(st.st_mode):
                raise SandboxError(f"workspace path component is not a directory: {part!r}")
            cur = nxt

    def write_file(self, path: str, data: bytes | str) -> None:
        """Write ``data`` to ``path`` (workspace-relative) - host-direct, so the box sees it next run.
        The final component is opened O_NOFOLLOW: a symlink the box planted there can't redirect the
        write outside the workspace (it fails instead)."""
        self._require_entered()
        full = self._ws_path(path)
        self._ensure_parent_dirs(full)  # symlink-safe descent, NOT mkdir(parents) which follows symlinks
        payload = data.encode() if isinstance(data, str) else data
        try:  # openat descent re-checks every component O_NOFOLLOW, closing the create->open TOCTOU too
            fd = self._open_nofollow(full, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        except OSError as e:
            raise _path_refusal("write", path, e) from e
        with os.fdopen(fd, "wb") as f:
            f.write(payload)

    def _open_nofollow(self, full: str, flags: int, mode: int = 0o644) -> int:
        """Open ``full`` (already lexically contained) descending from the workspace base ONE component at
        a time, each with ``O_NOFOLLOW`` via ``openat``, so a symlink the box planted in ANY component -
        not just the last - can't redirect host I/O outside the workspace. This also closes the TOCTOU a
        plain lstat-then-open would leave. Returns an fd (caller owns it).

        TWO MORE PROPERTIES, HERE RATHER THAN AT EACH CALL SITE, because the next caller added would
        not remember them:

        ``O_NONBLOCK`` - opening a FIFO returns a descriptor instead of WAITING FOR A WRITER. Measured
        before this flag: a box that runs ``mkfifo out.png`` makes ``read_file("out.png")`` hang with
        no timeout and no way to interrupt it, so the box decides how long the host's call takes. On
        the write side it is worse: opening a FIFO for writing blocks until a reader appears, and with
        the flag it fails outright (ENXIO). ``O_NOFOLLOW`` does not touch either case, because a FIFO
        is not a symlink.

        ``fstat`` - and the flag ALONE would be worse than the hang. A non-blocking read of a
        writer-less FIFO returns zero bytes, so ``read_file`` would answer ``b""`` and the caller
        would read an empty file where the box had planted a pipe: a stall turned into a silent lie.
        So the OPEN DESCRIPTOR (not a path, which can be swapped after the check) has to be a regular
        file, or a directory when that is what was asked for."""
        base = self._ws
        rel = os.path.relpath(full, base)
        parts = [p for p in rel.split(os.sep) if p and p != "."]
        if not parts:
            raise SandboxError("refusing to open the workspace root as a file")
        cloexec = getattr(os, "O_CLOEXEC", 0)
        nonblock = getattr(os, "O_NONBLOCK", 0)
        dir_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | cloexec)
        try:
            for part in parts[:-1]:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | cloexec, dir_fd=dir_fd)
                os.close(dir_fd)
                dir_fd = nxt
            fd = os.open(parts[-1], flags | os.O_NOFOLLOW | cloexec | nonblock, mode, dir_fd=dir_fd)
        finally:
            os.close(dir_fd)
        wanted_dir = bool(flags & getattr(os, "O_DIRECTORY", 0))
        try:
            mode_bits = os.fstat(fd).st_mode
            ok = stat.S_ISDIR(mode_bits) if wanted_dir else stat.S_ISREG(mode_bits)
        except OSError:
            os.close(fd)
            raise
        if not ok:
            os.close(fd)
            kind = "directory" if wanted_dir else "regular file"
            raise SandboxError(
                f"refusing to open {os.path.basename(full)!r}: not a {kind} (a FIFO, device or "
                f"socket planted in the workspace can stall or fake this operation)"
            )
        return fd

    def read_file(self, path: str, *, max_bytes: "int | None" = None) -> bytes:
        """Read ``path`` (workspace-relative) from the workspace - host-direct. Every path component is
        opened O_NOFOLLOW (via ``openat`` descent), so a symlink the box planted in the final OR an
        intermediate component can't redirect the read outside the workspace.

        ``max_bytes`` is a **REFUSAL threshold, not a partial read**. A file larger than it raises
        ``SandboxError``; it never returns the first ``max_bytes`` bytes. That is the safer default for
        a boundary (a silent truncation is how a caller ends up parsing half a file), and it is not what
        the name suggests, so it is spelled out here and in the error: a caller who asked for 16 bytes to
        sniff a magic number and wrapped the call in ``try`` turned every image in their project into
        "not an image", in silence. For a sniff, read the head yourself with a bounded ``os.read`` on a
        descriptor you opened, or read the file and slice it."""
        self._require_entered()
        full = self._ws_path(path)
        try:
            fd = self._open_nofollow(full, os.O_RDONLY)
        except OSError as e:
            raise _path_refusal("read", path, e) from e
        with os.fdopen(fd, "rb") as f:
            if max_bytes is None:
                return f.read()
            data = f.read(max_bytes + 1)  # one past the cap so we can tell "exactly at" from "over"
            if len(data) > max_bytes:
                raise SandboxError(
                    f"{path!r} is larger than max_bytes={max_bytes}, so the read was REFUSED. "
                    f"max_bytes is a ceiling on what may be read at all, not a request for the "
                    f"first {max_bytes} bytes: nothing was returned. Raise it, or drop it and "
                    f"slice the result."
                )
            return data

    def list_files(self, subdir: str = "") -> list[FileInfo]:
        """List files under the workspace (excluding the ``.deps`` install dir). A ``subdir`` is validated
        with the same O_NOFOLLOW descent as read_file: a box that plants ``peek -> /tmp`` can't make
        ``list_files("peek")`` enumerate a host directory's filenames (an info leak that ``os.walk``'s
        followlinks=False does NOT stop, since it still follows the ROOT of the walk)."""
        self._require_entered()
        if subdir:
            root = self._ws_path(subdir)
            try:  # opens the final as a DIRECTORY, O_NOFOLLOW at every level: a symlinked component fails
                fd = self._open_nofollow(root, os.O_RDONLY | os.O_DIRECTORY)
                os.close(fd)
            except OSError as e:
                raise _path_refusal("list", subdir, e) from e
        else:
            root = self._ws  # _ws is canonical (set at enter)
        return [FileInfo(path=p, size=s, change="created") for p, (_, s) in self._walk(root).items()]

    # -- workspace snapshot (a cheap FILESYSTEM checkpoint; NOT a memory snapshot) --------------------

    def snapshot(self, dest: str) -> None:
        """Write a gzip tar of the whole workspace to ``dest`` on the host, a portable filesystem
        checkpoint. Pair with :meth:`restore` (or seed a new ``Sandbox(workspace=...)``) to resume the
        FILE state later or elsewhere. This is NOT a memory snapshot: processes are ephemeral, only the
        on-disk workspace is captured. The private host-side env file is never included."""
        self._require_entered()
        import tarfile

        # USTAR_FORMAT (not the Python PAX default): PAX writes an 'x' extended header before each member
        # that the deliberately-strict Node reader rejects, so PAX would break cross-binding interop. USTAR
        # is the plain format the Node binding also writes, keeping a snapshot readable by both (and by
        # `tar`). The trade is a 100-byte name limit, matching Node, and second-resolution mtimes.
        # compresslevel=1: a checkpoint is local and often large or already-compressed; level 1 is several
        # times faster than the default 9 with a negligible ratio penalty. Speed over ratio here.
        with tarfile.open(dest, "w:gz", compresslevel=1, format=tarfile.USTAR_FORMAT) as tf:
            for entry in sorted(os.listdir(self._ws)):
                if self._is_ours(entry):
                    continue  # ours (env file, in-flight scratch), not user state
                tf.add(os.path.join(self._ws, entry), arcname=entry)

    def restore(self, src: str) -> None:
        """Extract a snapshot tar (from :meth:`snapshot`) into the workspace, SAFELY. Every member is
        vetted first: absolute paths, ``..`` escapes, and non-regular/non-directory members (symlinks,
        devices, fifos, hardlinks) are refused, and each resolved path must stay under the workspace, so
        a hostile tar can never write outside it. Colliding files are overwritten."""
        self._require_entered()
        import tarfile

        base = os.path.realpath(self._ws)
        with tarfile.open(src, "r:*") as tf:
            members = tf.getmembers()
            for m in members:
                # THE SAME RULE THE HOST-SIDE FILE CALLS USE, not a second copy of it. This loop used to
                # test `m.name.startswith("/")` and `".." in m.name.split("/")` itself, which is the
                # lexical half of `_ws_path` written in a second dialect: the day a rule is added to the
                # chokepoint (the absolute-path refusal was one, on 2026-09-13), a tar would be the one
                # input that arrives from outside this process and does not get it.
                try:
                    self._ws_path(m.name)
                except SandboxError as e:
                    raise SandboxError(f"unsafe path in snapshot: {m.name!r} ({e})") from e
                if not (m.isreg() or m.isdir()):
                    raise SandboxError(f"unsafe member type in snapshot (only files/dirs): {m.name!r}")
                resolved = os.path.realpath(os.path.join(base, m.name))
                if resolved != base and not resolved.startswith(base + os.sep):
                    raise SandboxError(f"snapshot member escapes the workspace: {m.name!r}")
            # members already vetted (regular/dir, no escape); `filter="data"` (3.12+) is defense in depth.
            extra = {"filter": "data"} if sys.version_info >= (3, 12) else {}
            tf.extractall(base, members=members, **extra)

    # -- setup (the only network window) -------------------------------------------------------------

    def _run_setup(self, cmd: str) -> None:
        # DECISION (independent test-ratified C): the network is ON only here, in a SEPARATE setup box that
        # dies at the end. It installs into <workspace>/.deps; every run_code box is network-off.
        install = f"pip install --target {_WORKSPACE}/{_DEPS_DIR} --no-cache-dir --disable-pip-version-check"
        # If the caller gave a bare `pip install X`, route it to the deps dir; else run as-is (net-on).
        shell_cmd = cmd
        if cmd.strip().startswith("pip install "):
            shell_cmd = install + " " + cmd.strip()[len("pip install ") :]
        r = self._spawn(["sh", "-c", shell_cmd], network=True, timeout_s=max(self.timeout_s, 120), is_setup=True)
        if not r.success:
            raise SandboxError(f"setup failed (exit {r.exit_code}): {(r.stderr or r.stdout).strip()[:400]}")
        # PRECOMPILE HERE, because this is the last moment `.deps` is writable.
        #
        # `deps_readonly` defaults to True, so every run_code box mounts `.deps` read-only and CPython
        # cannot write a `__pycache__` into it. It tolerates that silently and recompiles on every
        # import instead, which is correct and is not free. Measured on `requests`, seven calls each:
        #
        #   setup leaves .pyc behind (pip's default)        250 ms/call writable, 252 read-only
        #   setup leaves none (`pip install --no-compile`)  250 ms/call writable, 290 read-only
        #
        # so the read-only default would cost +40 ms on EVERY call of a session whose setup did not
        # compile, for as long as that session lives. One `compileall` in this box removes it: the same
        # case comes back to 250. It is a no-op when the bytecode is already there, which is pip's
        # default, and a full session measured 1976 ms with it against 2018 without, the same number
        # twice.
        #
        # `|| true` because bytecode is an optimisation: a file that will not compile must not fail an
        # install that succeeded. The user's command runs first and separately, so it keeps the exit code.
        if self.deps_readonly and os.path.isdir(os.path.join(self._ws, _DEPS_DIR)):
            self._spawn(["sh", "-c", f"python3 -m compileall -q {_WORKSPACE}/{_DEPS_DIR} || true"],
                        network=False, timeout_s=max(self.timeout_s, 120), is_setup=True)

    # -- files diff (created/modified; excludes .deps) -----------------------------------------------

    def _snapshot(self) -> dict[str, tuple[int, int]]:
        return self._walk(self._ws)  # _ws is canonical (set at enter)

    def _walk(self, root: str) -> dict[str, tuple[int, int]]:
        """Map WORKSPACE-relative path -> (mtime_ns, size), skipping .deps, our own files, and symlinks.
        `root` is where to walk (the workspace, or a subdir for `list_files(subdir)`); paths are ALWAYS
        made relative to the workspace root so `list_files("sub")` returns `sub/a.txt`, composable with
        `read_file` (that was a regression when `root` doubled as the base). One lstat per file: S_ISREG
        excludes non-regular files AND symlinks in a single syscall (a symlink's lstat mode is never
        S_ISREG) - no extra isfile()/islink() stats."""
        base = os.path.realpath(self._ws)
        out: dict[str, tuple[int, int]] = {}
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d != _DEPS_DIR]  # exclude deps from the diff
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                try:
                    st = os.lstat(fp)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                rel = os.path.relpath(fp, base)
                if self._is_ours(rel):
                    continue  # ours (env file, cell/runner/results scratch), not a user artifact
                out[rel] = (st.st_mtime_ns, st.st_size)
        return out

    def _diff(self, before: dict[str, tuple[int, int]]) -> list[FileInfo]:
        """What the USER's code created or changed, with our own scratch kept out of it.

        `_walk` already skips what we hold, but that check races the walk itself: it `lstat`s a file
        and only then asks whether the name is ours, and another call on this Sandbox can release in
        between, so a file that WAS ours reads as user state. The window is microseconds and does not
        open at all until the thread count is high (measured clean at 16, leaking at 64), which is the
        kind of race a small concurrency test certifies as absent.

        Re-checked here, where both directions close, because our two invariants are ordered: a name is
        CLAIMED BEFORE the file is written, and UNLINKED BEFORE it is released.

          * claimed at report time  -> ours, still in flight. Excluded.
          * gone at report time     -> unlinked, so it was ours (a user file the workload created is
            still there; that is what makes it worth reporting). Excluded.
          * present and unclaimed   -> the workload's. Reported.

        `lexists`, not `exists`: the box can leave a dangling symlink, and that is its file, not a
        missing one.
        """
        after = self._snapshot()
        files: list[FileInfo] = []
        for rel, (mtime, size) in after.items():
            if rel not in before:
                files.append(FileInfo(path=rel, size=size, change="created"))
            elif before[rel] != (mtime, size):
                files.append(FileInfo(path=rel, size=size, change="modified"))
        return [
            fi
            for fi in files
            if not self._is_ours(fi.path) and os.path.lexists(os.path.join(self._ws, fi.path))
        ]

    # -- the two ways to run code --------------------------------------------------------------------

    # Above this size, pass code via a file in the workspace instead of `-c <code>` on the argv, so a
    # large agent-generated script can't blow ARG_MAX (~2 MB) with a raw OSError. Well under the limit.
    _INLINE_CODE_MAX = 128 * 1024

    # runner binary, inline-eval flag, and cell-file extension per language (node evals with -e, not -c).
    #
    # `bash` runs BASH. It used to run `sh`, and on a Debian image that is `dash`, with bash sitting
    # right there in the image unused. What a caller got was a shell chosen for them, failing on the
    # syntax the name promised: `[[ 1 == 1 ]]` -> `sh: 1: [[: not found`, arrays and process
    # substitution -> `Syntax error: "(" unexpected`, `set -o pipefail` -> `Illegal option`. That is
    # worse than the missing-interpreter case, because nothing was missing: the right binary was
    # present and the wrong one was picked. An LLM writing a shell command writes bash by reflex.
    #
    # `sh` is the honest name for the old behaviour and is now reachable: it is the POSIX shell, it is
    # in EVERY image (alpine has no bash at all), and it is what to ask for when portability matters.
    # An image without bash now answers `exec_failed` naming it, which is the same mechanism that
    # already covers `node`, and the message points at `language="sh"`.
    _LANGS = {
        "python": ("python3", "-c", "py"),
        "bash": ("bash", "-c", "sh"),
        "sh": ("sh", "-c", "sh"),
        "node": ("node", "-e", "js"),
    }

    def _eff_timeout(self, timeout_s: "int | float | None") -> "int | float":
        """Resolve a per-call ``timeout_s`` override against the constructor default. ``None`` inherits
        the session's ``timeout_s``; any override must be a positive number of seconds."""
        if timeout_s is None:
            return self.timeout_s
        if not isinstance(timeout_s, (int, float)) or isinstance(timeout_s, bool) or timeout_s <= 0:
            raise SandboxError("timeout_s must be a positive number of seconds")
        return timeout_s

    def run_code(
        self,
        code: str,
        *,
        language: Literal["python", "bash", "sh", "node"] = "python",
        timeout_s: "int | float | None" = None,
        on_stdout: object = _UNSET,
        on_stderr: object = _UNSET,
    ) -> ExecutionResult:
        """Run a snippet of ``code`` on the workspace in a fresh, network-off box. File state written to
        the workspace persists to the next call; in-memory state does NOT (fresh process each time).
        ``language`` is ``"python"`` (default), ``"bash"``, ``"sh"`` or ``"node"``, and **the image must
        provide the interpreter**: ``"bash"`` runs bash, not the POSIX shell, so an image without it
        (alpine) answers an ``exec_failed`` fault naming it. Ask for ``"sh"`` where portability matters,
        and for ``"bash"`` where the code uses ``[[ ]]``, arrays or ``pipefail``. Large code is written to a workspace file and executed from there (transparent to
        the caller), so an arbitrarily large script works instead of hitting the argv length limit.

        ``timeout_s``, ``on_stdout`` and ``on_stderr`` override the session defaults for THIS call only:
        ``timeout_s=None`` inherits the constructor's deadline, a number sets a per-call one; the stream
        callbacks default to the session's, an explicit ``None`` disables them for this call."""
        self._require_entered()
        spec = self._LANGS.get(language)
        if spec is None:
            raise SandboxError(
                f"unsupported language {language!r} (v1: 'python' | 'bash' | 'sh' | 'node')"
            )
        runner, inline_flag, ext = spec
        eff = self._eff_timeout(timeout_s)
        if language == "python":
            return self._run_python_cell(code, timeout_s=eff, on_stdout=on_stdout, on_stderr=on_stderr)
        cell = ""
        if len(code.encode()) > self._INLINE_CODE_MAX:
            # Write to a per-call cell file in the workspace and run it by path (no argv-size limit).
            cell = self._claim(f".cell-{uuid.uuid4().hex[:8]}.{ext}")
            self.write_file(cell, code)
            command: list[str] = [runner, f"{_WORKSPACE}/{cell}"]
        else:
            command = [runner, inline_flag, code]
        try:
            return self._spawn(
                command, network=self.network, timeout_s=eff, on_stdout=on_stdout, on_stderr=on_stderr
            )
        finally:
            # The Python path has always deleted its scratch; this one never did, so every oversized
            # bash/node cell left its own source sitting in the workspace for the rest of the session.
            # `_spawn` has returned by here, so the box that was reading it is gone.
            if cell:
                try:
                    os.unlink(os.path.join(self._ws, cell))
                except OSError:
                    pass
                self._release(cell)

    def _run_python_cell(
        self,
        code: str,
        *,
        timeout_s: "int | float | None" = None,
        on_stdout: object = _UNSET,
        on_stderr: object = _UNSET,
    ) -> ExecutionResult:
        """Run Python through the cell runner so a trailing expression, ``display()`` calls and matplotlib
        figures are captured as rich mime-typed ``result.results`` (Jupyter/E2B-style). stdout/stderr/exit
        are identical to a plain run; result capture is best-effort and never alters them. The cell,
        runner and results files are internal and are removed and hidden from ``result.files``."""
        eff = self._eff_timeout(timeout_s)
        # Prewarmed fast path, taken ONLY where it is observationally identical to the cold one below.
        # The streaming callback is the gate that is easy to get wrong: a prewarmed box answers with one
        # length-prefixed frame after the cell has finished, so there is no chunk to hand a callback as it
        # arrives. Calling it once at the end would look like streaming without being it, so a streaming
        # call takes the cold path and streams for real. A NUL in the code is refused by `_spawn` below,
        # and refusing it there keeps ONE place that decides what a rejected cell looks like.
        # BEFORE the claim, not after: the claim compares the posture the next box would have, so a cache
        # adopted here is already in the key and the boxes warmed without it are retired as stale.
        self._pyc_adopt_if_ready()
        pool = self._pool
        streaming = (self.on_stdout if on_stdout is _UNSET else on_stdout) is not None or (
            self.on_stderr if on_stderr is _UNSET else on_stderr
        ) is not None
        if pool is not None and not streaming and "\0" not in code:
            warm = pool.claim(network=self.network, deadline=eff)  # type: ignore[attr-defined]
            if warm is not None:
                before = self._snapshot() if self.track_files else None
                return warm.run_cell(code, deadline=eff, before=before)
        uid = uuid.uuid4().hex[:8]
        # `.res-` is written by the BOX, not by us, so it has to be claimed here too or it surfaces
        # as a user file the moment the cell creates it.
        cell, resf, runf = (self._claim(f".cell-{uid}.py"), self._claim(f".res-{uid}.json"),
                            self._claim(f".run-{uid}.py"))
        self.write_file(cell, code)
        shim = _PY_RUNNER.replace("__KERN_CELL__", f"{_WORKSPACE}/{cell}").replace(
            "__KERN_RES__", f"{_WORKSPACE}/{resf}"
        )
        self.write_file(runf, shim)
        try:
            result = self._spawn(
                ["python3", f"{_WORKSPACE}/{runf}"],
                network=self.network,
                timeout_s=eff,
                on_stdout=on_stdout,
                on_stderr=on_stderr,
            )
            try:
                parsed = json.loads(self.read_file(resf, max_bytes=_RESULTS_MAX))
                if isinstance(parsed, list):
                    result.results = [Result(data=r) for r in parsed if isinstance(r, dict)]
            except Exception:
                pass  # missing / too-large / unreadable / bad JSON: results empty, run otherwise intact
            return result
        finally:
            # Unconditional, and this is the load-bearing part. A timeout comes back as a fault rather
            # than an exception, so the happy path hid the hole: it opens when `_spawn` RAISES (an
            # interrupt, a kern that dies mid-call), and then the three names stay claimed for the life
            # of the session. Claimed means hidden, so from that moment a user file with one of those
            # names is invisible in `list_files`/`snapshot`/`files` FOREVER. Measured before this
            # `finally` existed: 10 injected deaths left 30 names claimed and 20 files on disk, and a
            # user file written under a leaked name did not appear in the listing.
            #
            # Unlink FIRST, release AFTER: in the window between, a concurrent call's `_walk` would
            # report a file that is still on disk as freshly created user state.
            for name in (cell, resf, runf):
                try:
                    os.unlink(os.path.join(self._ws, name))
                except OSError:
                    pass
            self._release(cell, resf, runf)

    def run(
        self,
        command: Sequence[str],
        *,
        timeout_s: "int | float | None" = None,
        on_stdout: object = _UNSET,
        on_stderr: object = _UNSET,
    ) -> ExecutionResult:
        """Run an arbitrary ``command`` (an argv LIST, never a shell string) in a fresh box. ``timeout_s``,
        ``on_stdout`` and ``on_stderr`` override the session defaults for this call only (see ``run_code``)."""
        self._require_entered()
        if isinstance(command, str):
            raise SandboxError('run() takes an argv LIST, not a string. Use run(["sh","-c","..."]).')
        if not command:
            raise SandboxError("run() needs a non-empty command")
        return self._spawn(
            command,
            network=self.network,
            timeout_s=self._eff_timeout(timeout_s),
            on_stdout=on_stdout,
            on_stderr=on_stderr,
        )

    def kernel(self, *, timeout_s: "int | float | None" = None) -> "Kernel":
        """Open a persistent, WARM Python interpreter in a long-lived box (warm-start). Returns a
        :class:`Kernel` context manager whose ``run_code`` executes cells in ONE resident process, so
        in-memory state PERSISTS across cells (a REPL/notebook) and the per-cell cost drops from a full
        interpreter boot (~10 ms) to sub-millisecond::

            with Sandbox() as sbx, sbx.kernel() as k:
                k.run_code("import numpy as np; a = np.arange(1_000_000)")
                k.run_code("a.sum()").results[0].text   # 'a' is still here; ~sub-ms per cell

        Trade-off vs ``run_code``: cells in a kernel share process state and a single box, so it is
        call-fast but not call-isolated (still network-off and resource-capped like any box; a fresh
        session/kernel is clean). A per-cell ``timeout_s`` tears the kernel down, because a running cell
        cannot be interrupted without killing the interpreter."""
        self._require_entered()
        return Kernel(self, self._eff_timeout(timeout_s))


# Sentinel: the box declared (or streamed) a reply frame larger than the cap. The box is UNTRUSTED and
# controls the length prefix + body, so an uncapped reader would let it stream a multi-GB frame and OOM
# the HOST (the box's own memory cap bounds what it BUILDS, not what the host ACCEPTS). run_code maps this
# to a fault and tears the kernel down. Mirrors the one-shot path's _RESULTS_MAX guard.
_KERNEL_OVERSIZE: object = object()


class _FrameReader(threading.Thread):
    """Read length-prefixed reply frames (`<n>\\n` + n bytes) from the kernel box stdout and hand each
    complete frame to a queue. A dedicated thread with blocking reads avoids the select()+buffered-IO
    race (data buffered in the BufferedReader is invisible to select on the fd). A short/closed pipe
    enqueues ``None`` so a waiting ``run_code`` learns the box died; a frame past ``cap`` enqueues
    ``_KERNEL_OVERSIZE`` so an untrusted box cannot OOM the host with a huge reply."""

    def __init__(self, out, q: "queue.Queue", cap: int) -> None:
        super().__init__(daemon=True)
        self._out = out
        self._q = q
        self._cap = cap

    def run(self) -> None:
        try:
            while True:
                # readline(cap+32): bound the header scan too, so a box that streams bytes with NO newline
                # can't grow the line buffer unboundedly. A header longer than that fails the int() below.
                line = self._out.readline(self._cap + 32)
                if not line:
                    self._q.put(None)
                    return
                try:
                    n = int(line.strip())
                except ValueError:
                    self._q.put(None)
                    return
                if n < 0 or n > self._cap:
                    self._q.put(_KERNEL_OVERSIZE)
                    return
                buf = bytearray()  # amortized O(1) append: b"" += chunk would be O(n^2) on a big reply
                while len(buf) < n:
                    chunk = self._out.read(n - len(buf))
                    if not chunk:
                        self._q.put(None)
                        return
                    buf += chunk
                self._q.put(bytes(buf))
        except Exception:
            self._q.put(None)


class Kernel:
    """A warm, persistent Python interpreter living in one long-lived box (see :meth:`Sandbox.kernel`).
    Opened as a context manager; ``run_code`` sends a cell over a length-prefixed pipe to the resident
    driver and returns an :class:`ExecutionResult` with captured stdout/stderr, exit code and rich
    ``results``. In-memory state persists across cells; the box stays network-off and resource-capped.
    Closing the context (or a per-cell timeout) tears the box down."""

    # kern's own --timeout reliably kills the in-PID-namespace box; a kernel is long-lived, so give it a
    # large backstop and let __exit__/timeout own the real lifetime.
    _BACKSTOP_S = 24 * 3600

    def __init__(self, sandbox: "Sandbox", timeout_s: int) -> None:
        self._sbx = sandbox
        self._timeout = timeout_s
        self._proc: "subprocess.Popen | None" = None
        self._name = ""
        self._driver = ""
        self._q: "queue.Queue" = queue.Queue()
        self._err: "_CappedReader | None" = None
        self._dead = False
        # WHY THE CAUSE IS KEPT. Every death funnels through `_teardown_result`, which KNOWS what ended
        # the kernel, and the next cell then raised "a prior cell timed out, or the box exited" - two
        # guesses where the answer was in hand (MEASURED: a cell that blew the memory cap produced
        # `fault.type == "oom"`, and the very next cell blamed a timeout). Same class as the diagnosis
        # that declares one of two causes: if it is known, name it.
        self._death: "str | None" = None
        # Read end of kern's KERN_STARTED_FD channel. For a RESIDENT box kern writes it only at box
        # teardown (the box exits), i.e. when a cell kills the kernel - so it is read ONCE, bounded, on
        # death (see `_read_cap_signal`), never while the box is live (that would block).
        self._started_r = -1
        # THE THREAD THAT WILL START THE BOX, kept so a death can be ATTRIBUTED rather than guessed.
        #
        # kern arms `PR_SET_PDEATHSIG(SIGKILL)` on a foreground box so a hard-killed launcher leaves no
        # orphan, and on Linux that signal fires when the creating THREAD dies, not when the process does.
        # So a kernel started inside a short-lived thread is SIGKILLed the moment that thread returns, and
        # the next cell sees an external kill it cannot explain. MEASURED here: a cell run after the
        # spawning thread exited came back `fault = killed` with a message naming three causes, none of
        # them the real one. Before the OOM work of 2026-09-12 the same death was labelled `oom`.
        #
        # Recording the thread makes the diagnosis an OBSERVATION: if it is no longer alive when the box
        # dies, that IS the cause. The one-shot path needs none of this, because a call cannot outlive the
        # thread that is blocked inside it.
        self._spawn_thread = threading.current_thread()

    def __enter__(self) -> "Kernel":
        sbx = self._sbx
        sbx._require_entered()
        uid = uuid.uuid4().hex[:8]
        self._driver = sbx._claim(f".kernel-{uid}.py")
        # The historical constants, restated at the one call site that must not change: 64 MiB of raw
        # drain and no results budget (the host's frame cap stays the only bound). A persistent Kernel
        # is a REPL, not a replacement for `run_code`, so it keeps the contract it shipped with.
        sbx.write_file(self._driver, _kernel_driver(_KERNEL_DRAIN_CAP, 0))
        self._name = _unique_name()
        argv = sbx._base_argv(self._name, network=sbx.network, timeout_s=self._BACKSTOP_S) + [
            "--",
            "python3",
            f"{_WORKSPACE}/{self._driver}",
        ]
        child_env = dict(os.environ)
        if not sbx.enforce_limits:
            child_env["KERN_NO_SCOPE"] = "1"
        # Same unforgeable channel as the one-shot path; here it carries the memory-cap enforcement byte
        # we consume only on kernel death (`_read_cap_signal`). The workload never holds the write end.
        started_r, started_w = os.pipe()
        child_env["KERN_STARTED_FD"] = str(started_w)
        try:
            self._proc = subprocess.Popen(  # noqa: S603 - argv list, no shell
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=child_env,
                start_new_session=True,
                pass_fds=(started_w,),
            )
        finally:
            os.close(started_w)  # the parent never writes; the box holds the only write end now
        self._started_r = started_r
        _FrameReader(self._proc.stdout, self._q, sbx.max_output_bytes).start()
        # Drain stderr so the box never blocks on a full stderr pipe; the control protocol is on stdout,
        # so stderr only carries kern setup errors / stray driver noise.
        self._err = _CappedReader(self._proc.stderr, sbx.max_output_bytes)
        self._err.start()
        return self

    def run_code(self, code: str, *, timeout_s: "int | float | None" = None) -> ExecutionResult:
        """Execute ``code`` in the warm interpreter; in-memory state persists from the previous cell. A
        trailing bare expression, ``display()`` calls and matplotlib figures are captured into
        ``results`` (like the one-shot ``run_code``). ``timeout_s`` overrides the kernel's deadline for
        this cell; exceeding it tears the kernel down and returns a ``timeout`` fault."""
        if self._proc is None:
            raise SandboxError("kernel not started (use `with sbx.kernel() as k:`)")
        if self._dead:
            why = f"a prior cell ended it ({self._death})" if self._death else "it was closed"
            raise SandboxError(
                f"kernel is dead: {why}. Files written to the workspace are still there; names and "
                "imports from the earlier cells are gone. Open a new one with `sbx.kernel()`"
            )
        if "\0" in code:
            raise SandboxError("code must not contain a NUL byte")
        eff = self._sbx._eff_timeout(timeout_s) if timeout_s is not None else self._timeout
        started = time.monotonic()
        payload = code.encode("utf-8")
        try:
            self._proc.stdin.write(str(len(payload)).encode() + b"\n")
            self._proc.stdin.write(payload)
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError):
            err = bytes(self._err.buf).decode("utf-8", "replace") if self._err else ""
            wrote, cap_sig, oom_sig, wl_sig = self._read_cap_signal()
            fault, default, rc = self._kernel_death_fault(err, cap_sig, oom_sig, wl_sig, wrote)
            return self._teardown_result(fault, err.strip() or default, started, rc)
        try:
            reply = self._q.get(timeout=eff)
        except queue.Empty:
            return self._teardown_result("timeout", f"cell exceeded {eff}s", started)
        if reply is _KERNEL_OVERSIZE:
            return self._teardown_result(
                "killed", f"the kernel reply exceeded the {self._sbx.max_output_bytes}-byte cap", started
            )
        if reply is None:
            err = bytes(self._err.buf).decode("utf-8", "replace") if self._err else ""
            wrote, cap_sig, oom_sig, wl_sig = self._read_cap_signal()
            fault, default, rc = self._kernel_death_fault(err, cap_sig, oom_sig, wl_sig, wrote)
            return self._teardown_result(fault, err.strip() or default, started, rc)
        return self._result_from_reply(reply, started)

    def _read_cap_signal(self) -> "tuple[bool, int, int | None, int | None]":
        """kern's teardown bytes for the resident box, read ONCE on kernel death. See
        :func:`_read_teardown_bytes`, which is the one reader of that wire format: kern writes it only at
        the box's teardown (a resident box exits when a cell kills it), so this is called from the death
        paths above and never while the box is live."""
        return _read_teardown_bytes(self._started_r)

    def _kernel_death_fault(
        self, err: str, cap_signal: int = 0, oom_signal: "int | None" = None,
        workload_signal: "int | None" = None, kern_wrote_payload: bool = False,
    ) -> "tuple[str | None, str, int]":
        """Why the resident kernel box died mid-cell, as ``(fault type or None, message, exit code)``.

        The ``run_code`` counterpart of the one-shot :meth:`_classify`: a kernel death has no per-cell exit
        status of its own, so the whole verdict is made here from what kern wrote.

        THE EXIT CODE COMES FROM THE FOURTH BYTE, so the two paths report one event the same way. It used
        to be a flat ``-1`` here while the one-shot path reported 137 for a kill, 159 for a blocked escape
        and 139 for a segfault. `128 + signal` is the shell's convention and the one `_classify` already
        speaks; ``-1`` remains for the cases where no signal is known (an older kern, or a box that exited
        on its own).

        ORDER, and it was measured wrong before: the OOM is asked about FIRST, because kern's sentence is
        `kern:`-prefixed and so was also matching the box-did-not-start heuristic below. A real OOM on a
        resident kernel therefore came back as ``startup_failed``, which :meth:`_teardown_result` RAISES -
        so the flagship path could not produce an ``oom`` fault at all, while an external ``kern stop``
        DID produce one from the ``memory_mb`` inference. Two defects pointing opposite ways.

        ``oom_signal`` is kern's UNFORGEABLE OOM-outcome byte (3rd of KERN_STARTED_FD, 1 = the kernel's
        OOM killer fired against this box's own cgroup) and is the authority; the stderr sentence is the
        fallback for a kern that predates the byte. ``cap_signal`` is the enforcement byte (0 = old kern /
        undetermined, 1 = cap enforced, 2 = requested but NOT enforced): it does NOT decide the type - a
        SIGKILL on a capped box is not evidence of an OOM, whatever the byte says - but a 2 still earns a
        sentence, because "your cap was not in force here" is the one thing the caller cannot find out for
        itself."""
        rc = 128 + int(workload_signal) if workload_signal not in (None, 0) else -1
        if _oom_verdict(oom_signal, err, kern_wrote_payload=kern_wrote_payload):
            return "oom", "the kernel box exceeded its memory cap and was OOM-killed", rc
        # A BLOCKED ESCAPE, BEFORE ANY STDERR HEURISTIC, and this path could not say it at all. MEASURED
        # through the MCP server, which is the path a Cursor or Claude Desktop user actually runs:
        # `ctypes.CDLL(None).mount(...)` in a cell came back `fault=killed`, with a message naming "an
        # external kill (`kern stop`, a signal, or the host running out of memory)". kern's seccomp filter
        # had killed the box for attempting a blocked syscall, and the caller was told somebody stopped
        # it. The one-shot path has always answered this from the exit code (159); a resident kernel has
        # no per-cell exit code, so it needs the fourth byte, which was arriving here unused.
        #
        # BEFORE `_looks_like_startup_failure` for the same reason the one-shot path decides SIGSYS before
        # reading stderr at all: that heuristic matches a pattern the workload can print, so checking it
        # first would let a cell hide a blocked escape behind "the box failed to start".
        #
        # A cell cannot forge it: the signal must have killed the box's PID 1, and the kernel does not
        # deliver an unhandled fatal signal to a pidns init from inside. Measured, a cell calling
        # `os.kill(os.getpid(), SIGSYS)` here exits 0 with no fault.
        if workload_signal == signal.SIGSYS:
            return (
                "escape_blocked",
                "the kernel box was killed by SIGSYS: kern's seccomp filter refused a syscall the code "
                "attempted, which is a blocked escape and not a kill from outside",
                rc,
            )
        # A CRASH IS NOT A SANDBOX FAULT, and this path called it `killed` with that same false sentence
        # about an external kill. MEASURED: `ctypes.string_at(0)` segfaults the interpreter, which IS the
        # box's PID 1, so the box dies - and the one-shot path reports the identical event as
        # `fault=None, exit_code=139`, because the code crashed and the sandbox did nothing. Two paths
        # disagreeing about one event is the defect, and the disagreement costs a loop: an agent reading
        # `killed` retries the sandbox instead of fixing a null dereference. The lost session state is
        # already reported, by the NEXT call raising "kernel is dead".
        if workload_signal in _CRASH_SIGNALS:
            return (
                None,
                f"the code crashed: the cell died on signal {int(workload_signal)} "
                f"({signal.Signals(workload_signal).name}), which took the kernel box with it because the "
                f"interpreter is its PID 1. The sandbox did not act; the next call reopens a kernel",
                rc,
            )
        # AND THE BYTE DECIDES WHETHER THE TEXT IS BELIEVED. kern writes the teardown payload only for a
        # box that existed, so `kern_wrote_payload` is positive proof that this kernel STARTED and a
        # `startup_failed` here could only be a cell printing kern's prefix at column 0 and dying of
        # something else. The one-shot path gets this from `_run_one`, which drops the verdict when the
        # start byte is set; this path had no such guard, so the widened predicate gets it here.
        if not kern_wrote_payload and _looks_like_startup_failure(err):
            return "startup_failed", "the kernel box failed to start", rc
        # THE ONE CAUSE THIS PATH CAN NAME EXACTLY, before the honest-but-vague ones below. kern arms
        # PDEATHSIG on a foreground box, that signal fires on the death of the creating THREAD on Linux,
        # and a kernel started inside a short-lived thread is therefore SIGKILLed when that thread
        # returns. If the thread is gone, this is not one of three possible external kills: it is that
        # one, and the remedy is a thread that outlives the box rather than a retry.
        if not self._spawn_thread.is_alive():
            return (
                "killed",
                "the kernel box was killed because the thread that started it has exited: kern arms "
                "PR_SET_PDEATHSIG on the box, and on Linux that signal fires when the CREATING THREAD "
                "dies, not when the process does. Start the kernel from the main thread, or from a "
                "thread that lives at least as long as the session",
                rc,
            )
        if cap_signal == 2:
            return (
                "killed",
                "the kernel box was killed, and its memory cap was not enforced here (no cgroup "
                "delegation), so no memory limit was in force to attribute it to",
                rc,
            )
        if self._sbx.memory_mb is not None:
            # A BINARY THAT DOES NOT REPORT THE SIGNAL CANNOT HAVE THIS SENTENCE PUT IN ITS MOUTH.
            # MEASURED on the released 0.9.32, which is what `install.sh` serves today: it writes two of
            # the four teardown bytes, so `workload_signal` is None, and a cell that SEGFAULTED and a cell
            # whose syscall the seccomp filter refused both landed here and were told "an external kill",
            # which is false for both. The verdict cannot improve without the byte; the sentence can say
            # so, which is the difference between a bound and a lie. Same discipline as the `oom` verdict:
            # a right verdict with a false sentence is a defect.
            if kern_wrote_payload and workload_signal is None:
                return (
                    "killed",
                    "the kernel box was killed and the kernel reported no OOM against its memory cap. "
                    "THIS kern does not report which signal ended the box (it writes 2 of the 4 teardown "
                    "bytes), so an external kill, a crash in your own code and a syscall the sandbox "
                    "refused are indistinguishable from here: a newer kern separates them, and until "
                    "then read the box's stderr before concluding it was killed from outside",
                    rc,
                )
            return (
                "killed",
                "the kernel box was killed and the kernel reported no OOM against its memory cap: an "
                "external kill (`kern stop`, a signal, or the host running out of memory), not the box "
                "exceeding its own memory",
                rc,
            )
        # NOBODY KILLED IT, and kern's fourth byte is what allows saying so. A resident kernel whose
        # driver exits on its own (it crashed, or something inside the box killed it) is not an external
        # kill, and a message that says "killed" with no cause is the vague answer this file keeps
        # replacing with named ones. `None` means this kern does not report it, and then the old wording
        # stands rather than a claim the byte did not support.
        if workload_signal == 0:
            return (
                "killed",
                "the kernel box exited on its own (no signal killed it), so its interpreter is gone: a "
                "crash inside the box, or something in the box ending PID 1",
                rc,
            )
        return "killed", "the kernel box exited", rc

    def _result_from_reply(self, reply: bytes, started: float) -> ExecutionResult:
        """Turn one kernel reply into an :class:`ExecutionResult`.

        Extracted so the UNTRUSTED-INPUT boundary is one named place that can be driven directly by a
        test: `reply` is JSON written INSIDE the box, by the same code the sandbox exists to contain.
        Every field is therefore attacker-chosen, and the question for each is what a missing or
        wrong-typed value must mean.
        """
        dur = int((time.monotonic() - started) * 1000)
        try:
            obj = json.loads(reply.decode("utf-8", "replace"))
        except Exception:
            return self._teardown_result("killed", "the kernel sent a malformed reply", started)
        if not isinstance(obj, dict):
            return self._teardown_result("killed", "the kernel sent a non-object reply", started)
        # `rc` is the ONE field whose absence cannot be defaulted. `success` is
        # `exit_code == 0 and fault is None`, so coercing a missing or non-integer `rc` to 0 - which is
        # what this did - reported a SUCCESSFUL run. Since the JSON comes from the box, a cell could
        # declare its own failed run successful by omitting the field or sending a string. An unusable
        # status is not a status: it is a protocol violation by the in-box runner, which always emits
        # `"rc"`, and it is handled like the malformed replies above.
        #
        # `bool` is excluded explicitly: in Python it subclasses `int`, so a JSON `true` would
        # otherwise be accepted and become exit code 1.
        rc = obj.get("rc")
        if isinstance(rc, bool) or not isinstance(rc, int):
            return self._teardown_result(
                "killed", "the kernel reply carried no usable exit code", started
            )
        # The REMAINING fields are informational, so a wrong type degrades to an empty value rather
        # than failing the call: coerced so a caller doing `r.stdout.strip()` cannot be crashed by a
        # box that sent a number.
        results = [Result(data=d) for d in obj.get("results", []) if isinstance(d, dict)]
        return ExecutionResult(
            stdout=str(obj.get("stdout", "")),
            stderr=str(obj.get("stderr", "")),
            exit_code=rc,
            duration_ms=dur,
            fault=None,
            files=[],
            truncated=False,
            results=results,
        )

    def _teardown_result(
        self, kind: "str | None", msg: str, started: float, exit_code: int = -1
    ) -> ExecutionResult:
        self._death = kind if kind is not None else "the code crashed"
        self._kill()
        # Same rule as the one-shot path: a box that never STARTED (the kernel failed to boot) raises,
        # it does not return a hollow result. timeout/killed stay as data.
        if kind == "startup_failed":
            raise SandboxError(msg or "the box failed to start")
        # `kind is None` is a real answer here, not a missing one: the code CRASHED and the sandbox did
        # not act, which is what the one-shot path reports for the same event. The message still travels,
        # on stderr, because "your cell segfaulted and took the kernel with it" is worth saying even
        # though it is not a fault.
        if kind is None:
            return ExecutionResult(
                stdout="",
                stderr=msg,
                exit_code=exit_code,
                duration_ms=int((time.monotonic() - started) * 1000),
                fault=None,
                files=[],
                truncated=False,
                results=[],
            )
        return ExecutionResult(
            stdout="",
            stderr="",
            exit_code=exit_code,
            duration_ms=int((time.monotonic() - started) * 1000),
            fault=SandboxFault(type=kind, message=msg),  # type: ignore[arg-type]
            files=[],
            truncated=False,
            results=[],
        )

    def _kill(self) -> None:
        self._dead = True
        if self._proc is not None:
            # `kern stop` cgroup-kills the box by name: a CPU-bound cell in its own PID namespace can
            # outlive a plain SIGKILL of kern's supervisor until the (24 h) --timeout backstop, so stop it
            # explicitly first, then SIGKILL the process group. Same discipline as the one-shot _teardown.
            if self._name:
                try:
                    subprocess.run(  # noqa: S603 - argv list, no shell
                        [self._sbx._kern, "stop", self._name],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                    )
                except Exception:
                    pass
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                # Blocking on a pidfd, so a box that dies at once is reaped at once instead of on
                # the backoff's next wake-up. A kill path must never raise: swallow everything.
                _wait_for_exit(self._proc, 5)
            except Exception:
                pass

    def __exit__(self, *exc: object) -> None:
        proc = self._proc
        if proc is not None and not self._dead:
            # Graceful: closing stdin makes the driver's _read() return None, so the box exits cleanly.
            try:
                proc.stdin.close()
            except Exception:
                pass
            # Same contract as before: exited in time → done; timed out OR the wait failed → kill.
            try:
                exited = _wait_for_exit(proc, 3)
            except Exception:
                exited = False
            if not exited:
                self._kill()
        elif proc is not None:
            self._kill()
        if self._started_r >= 0:
            try:
                os.close(self._started_r)  # read once on death; closed here on every context exit
            except OSError:
                pass
            self._started_r = -1
        try:
            os.unlink(os.path.join(self._sbx._ws, self._driver))
            self._sbx._release(self._driver)
        except OSError:
            pass


# How long a prewarmed box may sit unclaimed before it is stale. It bounds the ORPHAN window: every warm
# box carries kern's own `--timeout` set to this plus the session deadline it was started for, so a host
# process that dies without running `__exit__` leaves boxes that expire by themselves instead of living
# to a 24 h backstop. The pool refills continuously, so a box is normally claimed within seconds; this is
# the failure bound, not the working lifetime.
_PREWARM_TTL_S = 300

# How long a prewarmed box gets to reach its prompt before the pool gives up on it. Generous on purpose:
# it covers a first-run image pull and an aarch64 board, where a box start is worth several x86 ones. It
# is a background thread's deadline, never a caller's, so a large value costs nothing on any hot path.
_PREWARM_READY_S = 120.0

# Every live prewarmed box in this process, so an interpreter exit that skips `Sandbox.__exit__` (an
# unhandled exception, `sys.exit` inside the `with`) still tears the boxes down. `atexit` is best-effort by
# nature - a SIGKILL runs nothing - which is exactly why the TTL above exists as the mechanical backstop.
_LIVE_WARM: "set[_WarmBox]" = set()
_LIVE_WARM_LOCK = threading.Lock()


def _kill_live_warm_boxes() -> None:
    with _LIVE_WARM_LOCK:
        boxes = list(_LIVE_WARM)
    for b in boxes:
        try:
            b.kill()
        except Exception:
            pass


atexit.register(_kill_live_warm_boxes)


class _WarmBox:
    """One box that is already started and already holds a booted CPython which has run NO user code.

    A cold ``run_code`` pays two costs on the CALLER's clock: starting the box (~4 ms) and booting the
    interpreter inside it (~11 ms). Neither depends on the cell, so neither has to happen while the caller
    waits. This starts them in advance and then serves EXACTLY ONE cell before the box is destroyed.

    The guarantee ``run_code`` documents is therefore unchanged. A cell still gets a private box that has
    executed nothing else, and a virgin interpreter whose only prior action was importing this driver -
    which is precisely what a cold cell gets after its own boot finishes. The one-cell rule is enforced by
    construction: the pool pops a box out of its list before handing it over and never puts one back, and
    :meth:`run_cell` refuses a second call.

    **One observable DOES differ, stated because "identical" was too broad a word for it.** The
    interpreter is older than the call. A cell that reads its own start time out of ``/proc/self/stat``
    sees ~0 s cold and up to ``_PREWARM_TTL_S`` warm (measured: 0.0 s against 3.1 s). Nothing the SDK
    reports changes, and no boundary moves - the box's mounts, capabilities, network posture, memory
    cgroup and one-cell lifetime are the same either way - but code that times itself from process start,
    or asserts it is the first thing its interpreter ever did, can tell. That is why the claim in the
    tests is the specific one: same stdout, exit status, results, file diff, truncation, faults and
    posture, not "indistinguishable".
    """

    __slots__ = (
        "_sbx", "_proc", "_name", "_q", "_err", "_started_r", "key", "_budget", "_born", "_spent",
        "_sweeper", "_rc",
    )

    def __init__(
        self, sbx: "Sandbox", key: str, budget: int, sweeper: "Callable[[_WarmBox], None] | None" = None
    ) -> None:
        self._sbx = sbx
        self.key = key
        self._budget = budget
        self._sweeper = sweeper
        self._proc: "subprocess.Popen | None" = None
        self._name = ""
        self._q: "queue.Queue" = queue.Queue()
        self._err: "_CappedReader | None" = None
        self._started_r = -1
        self._born = time.monotonic()
        self._spent = False
        # The box process's real wait status, captured at the kill. Kept as a field because `sweep()`
        # drops `_proc` on the WORKER thread while the caller is still assembling its result, so reading
        # the status off the Popen object at that point is a race.
        self._rc: "int | None" = None

    # -- lifecycle -----------------------------------------------------------------------------------

    def start(self) -> bool:
        """Bring the box up. Returns False on any failure: a pool that cannot prewarm must degrade to the
        cold path silently, never raise into a caller who did not ask for prewarming."""
        sbx = self._sbx
        self._name = _unique_name()
        # The driver goes in ARGV, not into a workspace file. A pooled box is started BEFORE the cell that
        # will use it, so a driver FILE would sit in the box-writable workspace across the whole inter-call
        # gap, and any cell could rewrite it to hijack the next prewarmed box. In argv the source is fixed
        # at exec time and never exists as a path the sandbox can reach. (`-S`: skip site, like Kernel.)
        driver = _kernel_driver(sbx.max_output_bytes, _RESULTS_MAX, hello=True)
        argv = sbx._base_argv(
            self._name, network=sbx.network, timeout_s=_PREWARM_TTL_S + self._budget
        ) + ["--", "python3", "-c", driver]
        child_env = dict(os.environ)
        if not sbx.enforce_limits:
            child_env["KERN_NO_SCOPE"] = "1"
        started_r, started_w = os.pipe()
        child_env["KERN_STARTED_FD"] = str(started_w)
        try:
            try:
                self._proc = subprocess.Popen(  # noqa: S603 - argv list, no shell
                    argv,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=child_env,
                    start_new_session=True,
                    pass_fds=(started_w,),
                )
            finally:
                os.close(started_w)
        except Exception:
            try:
                os.close(started_r)
            except OSError:
                pass
            return False
        self._started_r = started_r
        # The frame cap has to admit a reply the driver considers legal, or a cell that legitimately
        # truncates at `max_output_bytes` would come back as an oversize FAULT instead. Two capped streams
        # plus the results budget plus JSON overhead is the largest well-formed reply, so that is the cap.
        frame_cap = 2 * self._sbx.max_output_bytes + _RESULTS_MAX + 65536
        _FrameReader(self._proc.stdout, self._q, frame_cap).start()
        self._err = _CappedReader(self._proc.stderr, self._sbx.max_output_bytes)
        self._err.start()
        with _LIVE_WARM_LOCK:
            _LIVE_WARM.add(self)
        return True

    def wait_ready(self, timeout_s: float) -> bool:
        """Block until the driver says it is at the prompt. This is what makes the box PREWARMED rather
        than merely SPAWNED: without it the pool publishes boxes that are still building, and the caller
        pays the rest of the start itself.

        A box that fails to signal in time is not usable and is not kept: the pool must not hold a slot
        for something that never came up, or one bad start would suppress prewarming for the session."""
        try:
            frame = self._q.get(timeout=timeout_s)
        except queue.Empty:
            return False
        if not isinstance(frame, bytes):
            return False  # the box died, or the driver's first frame was already oversize
        try:
            obj = json.loads(frame.decode("utf-8", "replace"))
        except Exception:
            return False
        return isinstance(obj, dict) and obj.get("hello") == 1

    def usable_for(self, key: str, deadline: int) -> bool:
        """Whether this box may serve a call. Every term is a correctness gate, not an optimization:

        - ``key``: the EXACT argv the call would otherwise produce. This is what stops a box prewarmed
          with one posture from serving a call that asked for another - most importantly a network-on box
          answering a network-off call, which would be a real breach rather than a slow path.
        - ``deadline``: kern's timeout on this box was fixed at start. A cell allowed to run longer than
          the box's remaining budget could be killed by that backstop mid-run and reported as ``killed``,
          so a call with a longer deadline takes the cold path instead.
        - age: past the TTL the box is close enough to its own backstop that the same race opens.
        """
        return (
            not self._spent
            and self._proc is not None
            and self.key == key
            and deadline <= self._budget
            and (time.monotonic() - self._born) < _PREWARM_TTL_S
        )

    # -- the one cell --------------------------------------------------------------------------------

    def run_cell(self, code: str, *, deadline: int, before: "dict[str, tuple[int, int]] | None") -> ExecutionResult:
        """Run ``code`` in this box, then destroy it. Callable once; a second call raises rather than
        quietly reusing a box that has already executed user code."""
        if self._spent:
            raise SandboxError("a prewarmed box serves exactly one cell")
        self._spent = True
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise SandboxError("prewarmed box was never started")
        started = time.monotonic()
        payload = code.encode("utf-8")
        try:
            proc.stdin.write(str(len(payload)).encode() + b"\n")
            proc.stdin.write(payload)
            proc.stdin.flush()
            reply: object = self._q.get(timeout=deadline)
        except (BrokenPipeError, OSError):
            return self._fault_result("died", started, before)
        except queue.Empty:
            return self._fault_result("timeout", started, before, f"code exceeded {deadline}s")
        # Every branch below that rejects the reply produces the same shape, so it is written once. The
        # repetition was five copies of an eight-line call differing only in a string, which is the
        # form where one copy quietly drifts from the others.
        def rejected(message: str, *, truncated: bool = False) -> ExecutionResult:
            return self._result(
                "", "", self._exit_code(), started, before, truncated=truncated,
                fault=SandboxFault(type="killed", message=message),
            )

        if reply is _KERNEL_OVERSIZE:
            self.retire()
            return rejected(
                f"the box sent a reply larger than the {self._sbx.max_output_bytes}-byte output cap "
                "allows even after truncation",
                truncated=True,
            )
        if reply is None:
            return self._fault_result("died", started, before)
        self.retire()
        try:
            obj = json.loads(bytes(reply).decode("utf-8", "replace"))  # type: ignore[arg-type]
        except Exception:
            obj = None
        if not isinstance(obj, dict):
            return rejected("the box sent a malformed reply")
        # Same rule as `Kernel._result_from_reply`: `rc` is the one field whose absence cannot be
        # defaulted, because defaulting it to 0 would let a cell declare its own failed run successful.
        rc = obj.get("rc")
        if isinstance(rc, bool) or not isinstance(rc, int):
            return rejected("the box reply carried no usable exit code")
        results = [Result(data=d) for d in obj.get("results", []) if isinstance(d, dict)]
        return self._result(
            str(obj.get("stdout", "")),
            str(obj.get("stderr", "")),
            rc,
            started,
            before,
            truncated=bool(obj.get("trunc", False)),
            results=results,
        )

    def _fault_result(
        self,
        kind: str,
        started: float,
        before: "dict[str, tuple[int, int]] | None",
        msg: str = "",
    ) -> ExecutionResult:
        """A box that died or overran. The stderr text and kern's unforgeable cap byte are read BEFORE the
        kill, then classified exactly as the persistent kernel's death path does, so a prewarmed OOM is
        reported as ``oom`` and not as a bare ``killed``."""
        err = bytes(self._err.buf).decode("utf-8", "replace") if self._err else ""
        if kind == "timeout":
            self.retire()
            return self._result(
                "", "", self._exit_code(), started, before,
                fault=SandboxFault(type="timeout", message=msg or "the code exceeded its deadline"),
            )
        kern_wrote, cap_signal, oom_signal = self._read_cap_signal()
        self.retire()
        # Same order, and for the same measured reason, as `_kernel_death_fault`: kern's OOM sentence
        # carries the `kern:` prefix that `_looks_like_startup_failure` matches on, so asking about the
        # start SECOND is what keeps a pool box's OOM from being raised as a box that never came up. The
        # unforgeable byte is preferred over the sentence here too.
        if _oom_verdict(oom_signal, err, kern_wrote_payload=kern_wrote):
            fault, default = "oom", "the box exceeded its memory cap and was OOM-killed"
        elif not kern_wrote and _looks_like_startup_failure(err):
            # `not kern_wrote` for the reason `_kernel_death_fault` states: the payload exists only for a
            # box that existed, so with it set this RAISE would be a cell's own line deciding that the
            # box never came up.
            raise SandboxError(err.strip() or "the box failed to start")
        elif cap_signal == 2:
            fault, default = (
                "killed",
                "the box was killed, and its memory cap was not enforced here (no cgroup delegation), "
                "so no memory limit was in force to attribute it to",
            )
        elif self._sbx.memory_mb is not None:
            fault, default = (
                "killed",
                "the box was killed and the kernel reported no OOM against its memory cap: an external "
                "kill (`kern stop`, a signal, or the host running out of memory), not the box exceeding "
                "its own memory",
            )
        else:
            fault, default = "killed", "the box exited before the code finished"
        return self._result(
            "", "", self._exit_code(), started, before,
            fault=SandboxFault(type=fault, message=err.strip() or default),  # type: ignore[arg-type]
        )

    def _read_cap_signal(self) -> "tuple[bool, int, int | None]":
        """kern's cap-enforcement and OOM-outcome bytes, read once on death. The pool has no use for the
        workload's signal (it classifies from the box's own exit code through `_classify`), but the read
        itself is shared: see :func:`_read_teardown_bytes` for why there is exactly one."""
        wrote, cap, oom, _ = _read_teardown_bytes(self._started_r)
        return wrote, cap, oom

    def _result(
        self,
        stdout: str,
        stderr: str,
        exit_code: int,
        started: float,
        before: "dict[str, tuple[int, int]] | None",
        *,
        truncated: bool = False,
        fault: "SandboxFault | None" = None,
        results: "list[Result] | None" = None,
    ) -> ExecutionResult:
        """Assemble the result with the SAME shape the cold path returns, including the workspace diff.
        `files` is computed here rather than left empty because a fast path that silently stopped
        reporting created files would be a behaviour change disguised as a speed-up."""
        return ExecutionResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_ms=int((time.monotonic() - started) * 1000),
            fault=fault,
            files=self._sbx._diff(before) if before is not None else [],
            truncated=truncated,
            results=results or [],
        )

    def stop_processes(self) -> None:
        """End the box's workload NOW. Fast, idempotent, never raises.

        SIGKILLing the supervisor's process group is enough to end everything inside the box: kern arms
        ``PR_SET_PDEATHSIG(SIGKILL)`` on a foreground box, so the supervisor's death takes box PID 1, and
        PID 1 leaving its PID namespace takes every other process in it.

        MEASURED rather than reasoned: a cell that leaves a background process appending to the workspace
        stops at the exact byte it had reached (134 bytes, still 134 a second later) while the identical
        cell with no kill runs on (131 to 458 over the same second). That positive control is what lets a
        caller diff the workspace the moment this returns - the guarantee the cold path gets by waiting
        for the whole box to exit."""
        with _LIVE_WARM_LOCK:
            _LIVE_WARM.discard(self)
        self._spent = True
        proc = self._proc
        if proc is None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        try:
            _wait_for_exit(proc, 5)
        except Exception:
            pass  # the process is already signalled; a failed WAIT must not turn a kill into a raise
        if isinstance(proc.returncode, int):
            self._rc = proc.returncode

    def _exit_code(self) -> int:
        """The exit status a FAULT reports. The cold path hands back the box process's real wait status -
        a SIGKILLed box is ``-9`` - so a constant here would make one failure look like two different
        ones depending on which path served it. That is the divergence prewarming must not introduce, and
        the parity suite caught it: cold timeouts reported ``-9`` while warm ones reported ``-1``."""
        rc = self._rc if isinstance(self._rc, int) else -1
        # 128 + N for a signal death, the same shape the cold path now reports. The parity suite
        # caught this twice: cold `-9` against warm `-1`, and then cold `137` against warm `-9`
        # when only the cold path was converted. That is why the conversion is in both places.
        return 128 + (-rc) if rc < 0 else rc

    def sweep(self) -> None:
        """The bookkeeping after the workload is dead: our pipes, the started-fd and the private env
        file. Idempotent, never raises.

        **It deliberately does NOT run `kern stop`, because it is not needed.** `stop_processes` ends
        every process in the box, and kern's registry entry then clears **by itself** within ~300 ms. An
        earlier note here claimed `killpg` alone left the box in `kern ps` "4 runs out of 6", which was
        the instrument and not the system: that check ran immediately after the kill, inside the reaping
        window. Sampling at t+0, t+0.3, t+1 and t+3 shows at most one PRESENT reading at t+0 and none
        after, and a CPU-bound background writer inside the box stops at the byte it had reached.

        A second reason was written here and was WRONG, so it is recorded rather than deleted: that
        `kern stop` does not return once the supervisor is dead. It does, in 2 to 5 ms. The multi-second
        stalls behind that claim were the Node binding's, and they were ours: it called `spawnSync`,
        which blocks the single event loop that Node needs in order to REAP the child just SIGKILLed, so
        the pid was still present from `kern stop`'s point of view and it waited for it, correctly. The
        tell that it was a race and not a hang is that the same call sometimes returned in 5 ms.

        Separating it from :meth:`stop_processes` is still right: the pipes and the env file are not
        needed before the caller's result is correct."""
        proc, self._proc = self._proc, None
        if self._started_r >= 0:
            try:
                os.close(self._started_r)
            except OSError:
                pass
            self._started_r = -1
        if proc is None and not self._name:
            return
        if proc is not None:
            for closer in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    if closer is not None:
                        closer.close()
                except Exception:
                    pass  # a pipe whose peer is gone can raise on close; there is nothing to recover
        # The private `--env-file` `_base_argv` wrote for THIS box. `_spawn` removes its own in a
        # `finally`; a prewarmed box has no `_spawn`, so without this every warm box would leave one
        # behind - a file the caller never created, in a workspace they may have asked to persist.
        # `_release` runs after the unlink so `_walk` never reports a file that is still on disk as
        # user state.
        if self._name:
            try:
                os.unlink(self._sbx._env_path(self._name))
            except OSError:
                pass
            try:
                self._sbx._release(os.path.basename(self._sbx._env_path(self._name)))
            except Exception:
                pass  # the claim registry is ours and best-effort; failing to un-claim leaks a name,
                # not a file, and the file above is already gone
            self._name = ""

    def kill(self) -> None:
        """Destroy the box completely and synchronously. Used from `atexit`, from the pool's close and
        from the start-failure paths, where there is no worker to hand the sweep to."""
        self.stop_processes()
        self.sweep()

    def retire(self) -> None:
        """End the workload on the caller's clock and hand the sweep to the pool's worker. This is the
        hot path: it is what turns a ~16 ms teardown into a ~0.2 ms one without dropping any of it."""
        self.stop_processes()
        sweeper = self._sweeper
        if sweeper is None:
            self.sweep()
            return
        try:
            sweeper(self)
        except Exception:
            self.sweep()  # the pool is gone or refused the order: do it here rather than not at all


class _WarmPool:
    """Keeps up to ``size`` :class:`_WarmBox` instances ready for one :class:`Sandbox`.

    Refilling happens on a daemon thread, so the cost a claim removes from the caller's clock is not
    quietly added back at the end of the call. A claim that finds nothing usable returns ``None`` and the
    caller takes the ordinary cold path: the pool is an accelerator with no authority to change what runs.
    """

    # ONE long-lived worker starts every box, and this is a correctness requirement rather than a
    # tidiness one. A foreground `kern box` arms `PR_SET_PDEATHSIG(SIGKILL)` so a hard-killed launcher
    # takes its box down instead of orphaning it - and on Linux that signal fires when the creating
    # THREAD exits, not when the process does. Starting boxes on throwaway threads therefore killed every
    # box the moment its starter returned (measured: the supervisor reaped with rc=-9 about 80 ms in,
    # exactly as the box reached its prompt). A worker that lives as long as the pool never triggers it,
    # and the guarantee kern is making stays intact: when this process really dies, the worker dies with
    # it and the boxes still go.
    def __init__(self, sbx: "Sandbox", size: int) -> None:
        self._sbx = sbx
        self._size = max(0, int(size))
        self._lock = threading.Lock()
        self._ready: "list[_WarmBox]" = []
        self._starting = 0
        self._closed = False
        # Quante box questo pool ha FATTO PARTIRE. Serve solo a decidere se la reclamazione finale
        # vale un sottoprocesso: un pool che non ha mai avviato nulla non ha scratch da recuperare.
        self._started_total = 0
        self._orders: "queue.Queue" = queue.Queue()
        self._worker: "threading.Thread | None" = None

    def _key(self, network: bool) -> str:
        """The identity a warm box must match. Built from the REAL argv builder with placeholder values
        for the two fields a warm box legitimately differs in (its unique name, and the kern backstop that
        the TTL governs), so any other option this session adds - a profile, a cap, a deps remount that
        appears mid-session - changes the key automatically instead of needing to be listed here.

        The argv is not the whole posture, which is the second half of this and was a real hole: kern
        reads `KERN_*` variables from ITS OWN environment when it builds the box, so a caller who sets
        `KERN_SECCOMP=denylist` after the pool filled would have been served a box built under the
        previous filter. Measured before it was closed: the key did not move and the stale box was
        handed over. Every `KERN_*` variable is folded in, rather than the handful we can name today,
        because the failure mode is a variable nobody thought to list."""
        argv = self._sbx._base_argv("", network=network, timeout_s=0, dry=True)
        env = sorted((k, v) for k, v in os.environ.items() if k.startswith("KERN_"))
        return "\0".join(argv) + "\0\0" + "\0".join(f"{k}={v}" for k, v in env)

    def claim(self, *, network: bool, deadline: int) -> "_WarmBox | None":
        if self._closed or self._size <= 0:
            return None
        key = self._key(network)
        stale: "list[_WarmBox]" = []
        picked: "_WarmBox | None" = None
        with self._lock:
            keep: "list[_WarmBox]" = []
            for b in self._ready:
                if picked is None and b.usable_for(key, deadline):
                    picked = b
                elif (time.monotonic() - b._born) >= _PREWARM_TTL_S or b.key != key:
                    stale.append(b)  # expired, or prewarmed for a posture this session has left behind
                else:
                    keep.append(b)
            self._ready = keep
        for b in stale:  # kill OUTSIDE the lock: `kern stop` is a subprocess, not a memory operation
            b.kill()
        self.refill(network=network, deadline=deadline)
        return picked

    def refill(self, *, network: bool, deadline: int) -> None:
        """Top the pool up in the background. Bounded by ``size`` counting boxes that are ready AND boxes
        currently starting, so a burst of claims cannot spawn an unbounded number of boxes."""
        if self._closed or self._size <= 0:
            return
        with self._lock:
            want = self._size - len(self._ready) - self._starting
            if want <= 0:
                return
            self._starting += want
            # `is_alive()`, not `is None`: the question is whether a worker is RUNNING, and those two
            # answers differ exactly once, in the case that matters. A worker that died leaves a Thread
            # object behind, so `is None` stays false forever, no replacement is ever started, and every
            # later order queues behind nothing. The pool would stop refilling for the rest of the
            # session, silently, with every call falling back to the cold path and no signal that it
            # had. Asking whether it is alive costs nothing and makes that self-healing.
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._serve, daemon=True)
                self._worker.start()
        for _ in range(want):
            self._orders.put(("start", network, deadline))

    def sweep(self, box: "_WarmBox") -> None:
        """Queue a spent box's bookkeeping. Called from `_WarmBox.retire` on the caller's thread, which
        must not wait for a `kern stop`."""
        if self._closed:
            box.sweep()  # no worker will drain the queue any more: do it inline rather than never
            return
        self._orders.put(("sweep", box))

    def _serve(self) -> None:
        """The single starter thread. It outlives every box it creates, which is what keeps kern's
        parent-death signal from firing on a box that is perfectly healthy. It also disposes of spent
        boxes, so a `kern stop` never lands on a caller's clock."""
        while True:
            order = self._orders.get()
            if order is None:  # the close sentinel
                return
            kind = order[0]
            if kind == "sweep":
                try:
                    order[1].sweep()
                except Exception:
                    # A sweep is bookkeeping for a box whose workload is ALREADY dead, so nothing is
                    # leaked by giving up on it; letting it out would kill this thread and stop the
                    # pool refilling for the rest of the session.
                    pass
                continue
            _, network, deadline = order
            try:
                self._start_one(network, deadline)
            except Exception:
                # A start that raises must still release its slot, or the pool would count a box that
                # does not exist forever and stop refilling for the rest of the session.
                with self._lock:
                    self._starting = max(0, self._starting - 1)

    def _start_one(self, network: bool, deadline: int) -> None:
        box = _WarmBox(self._sbx, self._key(network), deadline, sweeper=self.sweep)
        ok = False
        try:
            ok = box.start() and box.wait_ready(_PREWARM_READY_S)
        except Exception:
            ok = False
        with self._lock:
            self._starting -= 1
            if ok:
                self._started_total += 1
            keep = ok and not self._closed
            if keep:
                self._ready.append(box)
        if not keep:
            # Three ways to land here and all of them must destroy the box, not just the first: the
            # start failed, the box came up but never signalled readiness (a started box - killing it
            # is the whole point), or the session closed while it was still building. `kill` is
            # idempotent and safe on a box that never got a process.
            box.kill()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            boxes, self._ready = self._ready, []
            worker = self._worker
            started = self._started_total
        for b in boxes:
            b.kill()
        if worker is not None:
            # Stop the worker only AFTER the boxes are down. It is the thread they are parented to, so
            # letting it exit first would hand their teardown to the parent-death signal - which does
            # work, but leaves `kern stop` unrun and the cgroup kill to a race. Bounded join: a daemon
            # thread must never be able to hold up a caller's `with` block.
            self._orders.put(None)
            worker.join(timeout=5)
        # RECLAIM THE SCRATCH THE KILLS LEFT BEHIND, or a prewarmed session leaks directories into a
        # tmpfs for as long as it runs.
        #
        # MEASURED, and it is the pool that is special rather than kern. A box ends here by SIGKILL of
        # the supervisor's process group, which is what makes `stop_processes` fast and idempotent - and
        # a process killed that way never runs its own teardown, so its scratch directory stays. The
        # cold path does not have this: its box exits normally and removes its own. So prewarming turns
        # what kern treats as the CRASH case into the routine one, and `recover` is the command kern
        # ships for exactly that ("reclaim orphaned scratch of dead boxes"). Measured before the fix:
        # `prewarm=4` plus two calls left SIX directories under `$XDG_RUNTIME_DIR/kern/scratch`, and
        # `kern prune` did not take them - only `gc`/`recover` did - while the same two calls without
        # prewarming left none.
        #
        # ONCE, AT CLOSE, not per box. Reclaiming after every cell would put a subprocess back on the
        # path whose entire purpose is to have none: a prewarmed call is ~0.4 ms here and spawning kern
        # costs several. This bounds the residue to one session instead of forever.
        #
        # It asks KERN rather than deleting paths itself: the scratch layout is kern's, and an SDK that
        # rebuilt `<runtime>/kern/scratch/<name>-<pid>` from its own guesses would be a second copy of
        # a rule only one side owns. Never raises, and bounded: teardown may not fail a caller's `with`
        # block, nor hold it open.
        if started:
            try:
                subprocess.run(  # noqa: S603 - argv list, no shell
                    [self._sbx._kern, "recover"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
            except Exception:
                pass


def _unique_name() -> str:
    return "pysbx-" + uuid.uuid4().hex[:12]


_EXEC_FAILED_RE = re.compile(r"^kern: cannot start '([^']+)' in box: ([^\n]*)", re.M)


def _exec_failure_binary(stderr: str) -> "tuple[str, str] | None":
    """The binary kern could not exec, or None.

    A THIRD state, and the reason this exists: kern signals "box started" on its unforgeable fd BEFORE
    it execs the workload, so an `execve` that fails with ENOENT leaves a box that demonstrably started
    and a command that never ran. `_classify` gets that right (kern's own marker is on stderr, so it
    says `startup_failed`) and `_spawn` then ERASES it, because "box started + a kern: marker" is its
    signal that a WORKLOAD forged the marker. For this case that inference is wrong: the workload never
    ran, so it cannot have written anything.

    Matched on kern's own wording rather than on exit 127 alone, because 127 is also what a shell
    returns for `command not found` inside a script the user wrote, which IS the user's failure.

    A workload CAN print this line and exit 127 to be labelled `exec_failed` instead of a plain
    failure. That is accepted: it downgrades nothing security-relevant, because timeout, OOM and
    blocked-escape are decided by EXIT CODE before any stderr is read (see `_classify`).
    """
    m = _EXEC_FAILED_RE.search(stderr)
    return (m.group(1), m.group(2).strip()) if m else None


# One row per errno the boundary produces, so the shared prefix is written once and the next one is a
# row rather than a branch.
_PATH_REFUSALS = {
    errno.ELOOP: (
        "a component of that path is a SYMLINK. Host-side reads and writes descend the workspace with "
        "O_NOFOLLOW and never follow one, because a link planted inside the workspace is how a box "
        "reaches a host file it was not given (the kernel reports this as ELOOP). Remove it, or name "
        "the file you meant"
    ),
    errno.ENXIO: (
        "it is a FIFO with no reader. Opening one for writing would block until the box chose to read, "
        "so the open is non-blocking and fails instead"
    ),
}


def _path_refusal(verb: str, path: str, e: OSError) -> "SandboxError":
    """The message for a host-side open that the workspace boundary refused.

    ELOOP here is not a filesystem oddity, it is the boundary doing its job: every component is opened
    O_NOFOLLOW, so a symlink the BOX planted at a path the host is about to read or write fails instead of
    redirecting. Passed through raw it reads `[Errno 40] Too many levels of symbolic link`, which sends a
    reader looking for a broken link chain when what happened is an attempt to reach a host file. Whoever
    reads this (a person, a log, a red team) should be able to tell the two apart.
    """
    why = _PATH_REFUSALS.get(e.errno)
    if why is None:
        return SandboxError(f"cannot {verb} {path!r}: {e}")
    return SandboxError(f"refusing to {verb} {path!r}: {why}")


def _looks_like_startup_failure(stderr: str) -> bool:
    """True iff KERN ITSELF reported an error on this box, rather than the workload failing.

    `_KERN_SPEAKING` at column 0 is the whole test: kern has exactly one error printer and indents every
    continuation line, so a line that starts there is kern's. What it deliberately does NOT try to do is
    decide forgery from the text. A workload can print `error: anything` at column 0, and no list of
    openings ever stopped that; what stops it is the byte kern writes to `KERN_STARTED_FD`, which the
    workload does not hold. Callers pair this predicate with that byte:
    :meth:`Sandbox._run_one` drops a `startup_failed` whenever kern signalled that the box started, and
    the two kernel paths ask the byte first. That is the same discipline as the taxonomy above: the
    unforgeable channel decides, the text only describes.
    """
    # kern's BENIGN lines are subtracted first, and they are the reason this cannot be a bare prefix
    # test: the `--security-profile` banner and `warning:`/`note:` lines carry `kern:` too, so without
    # the skip a workload that merely exits non-zero while one is on stderr (code under
    # `security_profile="untrusted"` that hits a network error) would read as a box that never started.
    #
    # The OOM sentence is skipped for a sharper reason: it is a report about a box that RAN. MEASURED,
    # that is how a real OOM on a resident kernel came back as `startup_failed` and was RAISED instead
    # of returning an `oom` fault.
    for line in stderr.splitlines():
        if line.startswith(_KERN_DIAGNOSTICS) or _kern_reported_oom(line):
            continue
        if line.startswith(_KERN_SPEAKING) or "sandbox setup failed" in line:
            return True
    return False


def _startup_failure_message(stderr: str) -> str:
    """Why the box did not start: kern's stderr with its warning and note lines dropped, capped at 500.

    MEASURED 2026-09-23 with kern inside a container, the shape a Google Colab runtime has: kern wrote a
    `kern: note:` and a ~430-character `kern: warning:` BEFORE `error: sandbox: unprivileged user
    namespaces are unavailable`, which began at character 557. The message used to be the first 500
    characters of stderr, so it showed the warning, which says the box "still runs", and cut the cause
    off. The lines dropped are the ones `code_stderr` drops, by the same prefixes, so the two cannot
    disagree about what counts as a diagnostic. If nothing else is left, the raw stderr still beats an
    empty message.
    """
    kept = "\n".join(l for l in stderr.split("\n") if not l.lstrip().startswith(_KERN_DIAGNOSTICS))
    return (kept.strip() or stderr.strip())[:500]


def run_code(
    code: str, *, language: Literal["python", "bash", "sh", "node"] = "python", **kwargs: object
) -> ExecutionResult:
    """One-shot convenience: run ``code`` in a throwaway session (workspace created and deleted). This is
    literally ``with Sandbox(**kwargs) as s: return s.run_code(code)`` - one tested code path, no state
    persists. For multi-step work (write a file, then read it), use ``Sandbox`` as a context manager."""
    with Sandbox(**kwargs) as s:  # type: ignore[arg-type]
        return s.run_code(code, language=language)
