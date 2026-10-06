"""`user=`: the account of the image every box runs as, and the workspace that has to stay shared with it.

UNIT tests run everywhere (the ACL tests need a filesystem with POSIX ACLs and skip without one).
INTEGRATION tests need a runnable kern AND a uid range for this user, because a non-root account is a uid
of that range; they skip, naming which one is missing.
"""

import errno
import os
import pathlib
import stat
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
import warnings
from unittest import mock

import pytest

import kern_sandbox as kern
from kern_sandbox import Sandbox, SandboxError

from _fake_kern import FAKE_KERN as _FAKE_KERN


def _cfg(**kw):
    """A Sandbox over the fake kern, with the real $KERN_BIN restored afterwards."""
    prev = os.environ.get("KERN_BIN")
    os.environ["KERN_BIN"] = _FAKE_KERN
    try:
        return Sandbox(**kw)
    finally:
        if prev is None:
            os.environ.pop("KERN_BIN", None)
        else:
            os.environ["KERN_BIN"] = prev


def _acls_supported(path) -> bool:
    try:
        os.setxattr(path, kern._ACL_ACCESS, kern._acl_encode(kern._acl_of_mode(os.stat(path).st_mode)))
        return True
    except OSError:
        return False


def _acl(path, name):
    try:
        return kern._acl_decode(os.getxattr(path, name, follow_symlinks=False))
    except OSError as e:
        if e.errno == errno.ENODATA:
            return None
        raise


def _named(entries, uid):
    """The perm of the named-user entry for `uid`, or None."""
    for tag, perm, ident in entries or []:
        if tag == kern._ACL_USER and ident == uid:
            return perm
    return None


# ---------------------------------------------------------------------------
# UNIT
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spec", ["node", "1000", "1000:1000", "node:staff", "a.b-c_d", "_x", "x" * 32])
def test_a_user_spec_is_an_account_name_or_number(spec):
    assert kern._validate_user(spec) == spec
    assert _cfg(user=spec).user == spec


@pytest.mark.parametrize(
    "spec", ["", "-u", "--user=root", "a b", "a:b:c", ":x", "x:", "a;b", "x" * 33, "n\node", 1000]
)
def test_anything_else_is_refused_by_name_before_it_reaches_an_argv(spec):
    with pytest.raises(SandboxError, match="user must be"):
        _cfg(user=spec)


def test_root_is_root_by_number_or_name_and_with_any_group():
    for spec in (None, "", "0", "root", "0:0", "root:wheel", "0:5"):
        assert kern._is_root_user(spec), spec
    for spec in ("1000", "node", "nobody:0", "10", "rooty"):
        assert not kern._is_root_user(spec), spec


def test_the_image_user_is_read_from_the_sidecar_kern_starts_the_box_from(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    images = tmp_path / "kern" / "images"
    images.mkdir(parents=True)
    side = images / (kern._sanitize_ref("example/app:1") + ".image")
    side.write_text("fmt\t3\nentrypoint\t/bin/app\nuser\tapp:staff\nworkdir\t/srv\n")
    assert kern._image_user("example/app:1") == "app:staff"
    side.write_text("fmt\t3\nuser\t\n")
    assert kern._image_user("example/app:1") is None, "an empty USER declares nothing"
    side.write_text("fmt\t3\nworkdir\t/srv\n")
    assert kern._image_user("example/app:1") is None
    # "cannot tell" leaves a session as it was before this existed: box root, no probe.
    assert kern._image_user("never/pulled:1") is None


def test_the_acl_codec_round_trips_and_the_mask_is_the_union_of_the_group_class():
    base = kern._acl_of_mode(0o640)
    assert base == [
        (kern._ACL_USER_OBJ, 6, kern._ACL_NO_ID),
        (kern._ACL_GROUP_OBJ, 4, kern._ACL_NO_ID),
        (kern._ACL_OTHER, 0, kern._ACL_NO_ID),
    ]
    granted = kern._acl_with_user(base, 4242, 7)
    assert kern._acl_decode(kern._acl_encode(granted)) == sorted(
        granted, key=lambda e: (e[0], e[2] if e[0] in (kern._ACL_USER, kern._ACL_GROUP) else 0)
    )
    assert (kern._ACL_MASK, 7, kern._ACL_NO_ID) in granted
    # Replacing an entry recomputes the mask from what is left, and keeps other named entries.
    again = kern._acl_with_user(kern._acl_with_user(granted, 7000, 4), 4242, 6)
    assert _named(again, 4242) == 6 and _named(again, 7000) == 4
    assert [e for e in again if e[0] == kern._ACL_MASK] == [(kern._ACL_MASK, 6, kern._ACL_NO_ID)]
    assert kern._acl_decode(b"\x01\x00\x00\x00") is None, "a version other than 2 is not an ACL"
    assert kern._acl_decode(b"\x02\x00\x00\x00\x01") is None, "a torn entry is not an ACL"


def test_the_tree_grant_gives_the_owners_bits_and_a_default_and_never_follows_a_symlink(tmp_path):
    if not _acls_supported(str(tmp_path)):
        pytest.skip("no POSIX ACLs on the temp filesystem")
    own, box = os.getuid(), 4242424
    root = tmp_path / "ws"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("host")
    (root / "a").mkdir(parents=True)
    (root / "a" / "f").write_text("f")
    os.chmod(root / "a" / "f", 0o644)
    (root / "a" / "x").write_text("#!/bin/sh\n")
    os.chmod(root / "a" / "x", 0o755)
    (root / "a" / "ro").write_text("r")
    os.chmod(root / "a" / "ro", 0o444)
    os.symlink(outside, root / "a" / "dirlink")
    os.symlink(outside / "secret", root / "filelink")
    foreign, example = kern._acl_grant_tree(str(root), box, own)
    assert (foreign, example) == (0, "")
    assert _named(_acl(root, kern._ACL_ACCESS), box) == 7
    assert _named(_acl(root / "a", kern._ACL_ACCESS), box) == 7
    assert _named(_acl(root / "a" / "f", kern._ACL_ACCESS), box) == 6, "the owner's bits: rw-"
    assert _named(_acl(root / "a" / "ro", kern._ACL_ACCESS), box) == 4, "read-only to its owner, read-only to the box user"
    assert _named(_acl(root / "a" / "x", kern._ACL_ACCESS), box) == 7
    default = _acl(root / "a", kern._ACL_DEFAULT)
    assert _named(default, own) == 7 and _named(default, box) == 7
    assert (kern._ACL_GROUP_OBJ, 0, kern._ACL_NO_ID) in default
    assert (kern._ACL_OTHER, 0, kern._ACL_NO_ID) in default
    assert _acl(root / "a" / "f", kern._ACL_DEFAULT) is None, "a file has no default ACL"
    # THE LINKS' TARGETS ARE HOST PATHS OUTSIDE THE TREE, and neither gets an entry.
    assert _acl(outside, kern._ACL_ACCESS) is None and _acl(outside / "secret", kern._ACL_ACCESS) is None


def test_the_grant_applies_to_the_inodes_the_walk_saw_even_if_a_directory_becomes_a_symlink(tmp_path, monkeypatch):
    """DETERMINISTIC, the swap injected at the point that matters: at the first file of `d`, `d` becomes a
    symlink to a host directory. By descriptor the rest of `d` is granted where the walk found it (now
    `d.real`); by path every remaining entry would land on the host directory."""
    if not _acls_supported(str(tmp_path)):
        pytest.skip("no POSIX ACLs on the temp filesystem")
    own, box = os.getuid(), 4242429
    root, outside = tmp_path / "ws", tmp_path / "outside"
    (root / "d").mkdir(parents=True)
    outside.mkdir()
    for i in range(5):
        (root / "d" / f"f{i}").write_text("x")
        (outside / f"f{i}").write_text("host")
    real = kern._acl_grant_fd
    swapped = []

    def swap_then_grant(fd, box_uid, own_uid):
        if not swapped and os.readlink(f"/proc/self/fd/{fd}").startswith(str(root / "d") + "/"):
            os.rename(root / "d", root / "d.real")
            os.symlink(outside, root / "d")
            swapped.append(True)
        real(fd, box_uid, own_uid)

    monkeypatch.setattr(kern, "_acl_grant_fd", swap_then_grant)
    kern._acl_grant_tree(str(root), box, own)
    assert swapped, "the swap never ran: the walk did not reach d's files"
    for p in [outside, *outside.iterdir()]:
        assert _named(_acl(p, kern._ACL_ACCESS), box) is None and _named(_acl(p, kern._ACL_DEFAULT), box) is None, p
    for i in range(5):
        assert _named(_acl(root / "d.real" / f"f{i}", kern._ACL_ACCESS), box) == 6, f"f{i} lost its entry"


def test_the_tree_grant_never_lands_outside_the_tree_while_a_box_swaps_a_directory_for_a_symlink(tmp_path):
    """THE RACE THE DESCRIPTOR WALK EXISTS FOR. A box writing the workspace during the grant can swap a
    directory for a symlink to a host directory between the listing and the `setxattr`. Walking by path,
    the entry would land on the host directory's files. Run against a concurrent swapper for a fixed
    time: the outside tree must never carry an entry. The positive control is the same swapper against
    a PATH-based grant, which has to be caught at least once, or this test could not see the class."""
    if not _acls_supported(str(tmp_path)):
        pytest.skip("no POSIX ACLs on the temp filesystem")
    own, box = os.getuid(), 4242425

    def arena(name):
        root = tmp_path / name / "ws"
        outside = tmp_path / name / "outside"
        (root / "d").mkdir(parents=True)
        outside.mkdir()
        for i in range(20):
            (root / "d" / f"f{i}").write_text("x")
            (outside / f"f{i}").write_text("host")
        return root, outside

    def swapper(root, outside, stop):
        d, real = root / "d", root / "d.real"
        while not stop.is_set():
            try:
                os.rename(d, real)
                os.symlink(outside, d)
                os.unlink(d)
                os.rename(real, d)
            except OSError:
                pass

    def leaked(outside):
        # THE OUTSIDE DIRECTORY ITSELF COUNTS, and its default ACL: a swapped `d` resolved by path takes
        # the directory's own entry to the outside tree first.
        return [
            p for p in [outside, *outside.iterdir()]
            if _named(_acl(p, kern._ACL_ACCESS), box) is not None or _named(_acl(p, kern._ACL_DEFAULT), box) is not None
        ]

    def by_path(root, box_uid, own_uid):  # the walk this replaced: paths resolved at every call
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            for name in dirnames + filenames:
                p = os.path.join(dirpath, name)
                try:
                    entries = kern._acl_of_mode(os.stat(p).st_mode)
                    os.setxattr(p, kern._ACL_ACCESS, kern._acl_encode(kern._acl_with_user(entries, box_uid, 6)))
                except OSError:
                    pass

    results = {}
    for name, grant in (("fd", kern._acl_grant_tree), ("path", by_path)):
        root, outside = arena(name)
        stop = threading.Event()
        t = threading.Thread(target=swapper, args=(root, outside, stop), daemon=True)
        t.start()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and not leaked(outside):
            try:
                grant(str(root), box, own)
            except OSError:
                pass
        stop.set()
        t.join()
        results[name] = leaked(outside)
    assert results["fd"] == [], f"the descriptor walk put an entry outside the tree: {results['fd']}"
    if not results["path"]:
        pytest.skip("the path-based control never lost the race here, so this host cannot see the class")


# -- the host-side walk, snapshot, restore and mkdir BY DESCRIPTOR ----------------------------------
#
# Each test swaps a workspace directory for a symlink to a HOST directory at the one moment that tells a
# descriptor implementation from a path one, by wrapping the call that moment sits next to. By descriptor
# the host directory is never reached; by path it is, every time: the same tests run against the
# path-based code these replaced fail (measured). The Node binding has the same four.


def _swap_once(monkeypatch, ws, outside, *, after=(), before=()):
    """Swap `<ws>/dswap` for a symlink to `outside`, once, at the first matching call: AFTER it returns
    for the callables in `after`, BEFORE it runs for those in `before`. Each is `(owner, attribute)`."""
    done = []

    def swap():
        if not done:
            done.append(True)
            os.rename(ws / "dswap", ws / "dswap.real")
            os.symlink(outside, ws / "dswap")

    def names(a):
        a = os.fsdecode(a) if isinstance(a, (str, bytes, os.PathLike)) else ""
        return "dswap" in a and "dswap.real" not in a

    for owner, attr, when in [*((o, a, "after") for o, a in after), *((o, a, "before") for o, a in before)]:
        real = getattr(owner, attr)

        def wrapped(*args, _real=real, _when=when, **kw):
            hit = bool(args) and names(args[0])
            if hit and _when == "before":
                swap()
            r = _real(*args, **kw)
            if hit and _when == "after":
                swap()
            return r

        monkeypatch.setattr(owner, attr, wrapped)


def _arena(tmp_path):
    ws, outside = tmp_path / "ws", tmp_path / "outside"
    (ws / "dswap").mkdir(parents=True)
    outside.mkdir()
    (ws / "dswap" / "mine.txt").write_text("mine")
    (outside / "hostsecret").write_text("host")
    s = _cfg()
    s._ws = str(ws.resolve())
    s._entered = True
    return ws.resolve(), outside, s


def test_the_walk_never_lists_a_host_directory_a_box_swapped_in(tmp_path, monkeypatch):
    ws, outside, s = _arena(tmp_path)
    _swap_once(monkeypatch, ws, outside, before=[(os, "scandir"), (os, "open")])
    names = [f.path for f in s.list_files()]
    assert not any("hostsecret" in n for n in names), names


def test_a_snapshot_never_archives_a_host_directory_a_box_swapped_in(tmp_path, monkeypatch):
    ws, outside, s = _arena(tmp_path)
    dest = tmp_path / "snap.tgz"
    _swap_once(monkeypatch, ws, outside, after=[(os, "lstat"), (os, "stat")])
    s.snapshot(str(dest))
    monkeypatch.undo()
    with tarfile.open(dest) as tf:
        assert not any("hostsecret" in n for n in tf.getnames()), tf.getnames()


def test_a_restore_never_writes_through_a_directory_a_box_swapped_for_a_symlink(tmp_path, monkeypatch):
    ws, outside, s = _arena(tmp_path)
    scratch = tmp_path / "scratch"
    (scratch / "dswap").mkdir(parents=True)
    (scratch / "dswap" / "planted").write_text("x")
    src = tmp_path / "in.tgz"
    with tarfile.open(src, "w:gz", format=tarfile.USTAR_FORMAT) as tf:
        tf.add(scratch / "dswap", arcname="dswap")
    _swap_once(monkeypatch, ws, outside, before=[(os, "open"), (os, "mkdir"), (tarfile, "bltn_open")])
    with pytest.raises(SandboxError):
        s.restore(str(src))
    monkeypatch.undo()
    assert not (outside / "planted").exists(), "the restore wrote into the host directory"


def test_write_file_never_makes_a_directory_inside_a_host_directory_a_box_swapped_in(tmp_path, monkeypatch):
    ws, outside, s = _arena(tmp_path)
    _swap_once(monkeypatch, ws, outside, after=[(os, "lstat")], before=[(os, "open"), (os, "mkdir")])
    with pytest.raises(SandboxError):
        s.write_file("dswap/sub/x.txt", "x")
    monkeypatch.undo()
    assert not (outside / "sub").exists(), "a directory was made inside the host directory"


def test_the_helper_list_parses_a_name_with_a_newline_and_skips_junk():
    raw = b"81a4 5 100\n./a\nb\x00" + b"41ed 4096 7\n./d\x00garbage\x00" + b"81a4 x 1\n./bad\x00"
    assert kern._parse_helper_list(raw) == [("a\nb", 0o100644, 5, 100), ("d", 0o40755, 4096, 7)]


def test_a_directory_closed_to_this_process_is_reported_whole_and_not_counted(tmp_path):
    if os.getuid() == 0:
        pytest.skip("root reads a 000 directory, so nothing here is closed to it")
    (tmp_path / "open").mkdir()
    (tmp_path / "open" / "f").write_bytes(b"x" * 8192)
    closed = tmp_path / "closed"
    closed.mkdir()
    (closed / "big").write_bytes(b"y" * (1 << 20))
    os.chmod(closed, 0)
    # LISTABLE BUT NOT SEARCHABLE, the other shape: `r--` lists the names and refuses every `stat`. The
    # entries listed before the refusal must not be counted here AND again by the helper.
    half = tmp_path / "half"
    half.mkdir()
    for i in range(50):
        (half / f"f{i:02d}").write_bytes(b"h" * 65536)
    os.chmod(half, 0o444)
    try:
        blind: list = []
        used = kern._workspace_usage(str(tmp_path), blind)
        assert sorted(blind) == sorted([str(closed), str(half)])
        assert used < (1 << 20), "a closed directory's contents were counted from here"
        # WITHOUT A LIST THERE IS NO ONE TO ASK, so the walk refuses instead of returning a number
        # that is short by whatever is hidden. That is the cap bypass this closes: with the workspace
        # owned by this process's own uid, one call writes a cap's worth of bytes into a directory and
        # chmods it to 0, and every later call measured those bytes as nothing and was admitted.
        with pytest.raises(SandboxError) as e:
            kern._workspace_usage(str(tmp_path))
        assert "cannot be measured" in str(e.value) and str(closed) in str(e.value)
    finally:
        os.chmod(closed, 0o700)
        os.chmod(half, 0o700)


def _argv_recorder(tmp_path):
    """A fake kern that answers the identity check and writes its argv, one per line, to a file."""
    out = tmp_path / "argv"
    script = tmp_path / "kern"
    script.write_text(
        "#!/bin/sh\n"
        'case "$1" in --version) echo "kern v0.0.0-test-double"; exit 0;; esac\n'
        f'printf "%s\\n" "$@" > {out}\n'
        "exit 0\n"
    )
    script.chmod(0o755)
    return str(script), out


def test_a_non_root_session_names_the_user_on_every_box_and_on_kern_exec(tmp_path, monkeypatch):
    fake, out = _argv_recorder(tmp_path)
    monkeypatch.setenv("KERN_BIN", fake)
    s = Sandbox(user="node")
    s._ws = str(tmp_path)
    argv = s._base_argv("b", network=False, timeout_s=5, dry=True)
    assert argv[argv.index("--user") + 1] == "node"
    assert "--no-uid-range" in argv, "before the identity is resolved nothing is known to be non-root"
    s._as_user = "node"
    argv = s._base_argv("b", network=False, timeout_s=5, dry=True)
    assert "--no-uid-range" not in argv, "kern maps the range for a non-root user whatever this says"
    s._entered = True
    s._resident = "kern-sbx-t"
    s._spawn(["true"], network=False, timeout_s=5)
    called = out.read_text().splitlines()
    assert called[:6] == ["exec", "kern-sbx-t", "-w", "/workspace", "-u", "node"], called
    # Box root keeps today's argv exactly.
    r = Sandbox()
    r._ws = str(tmp_path)
    argv = r._base_argv("b", network=False, timeout_s=5, dry=True)
    assert "--user" not in argv and "--no-uid-range" in argv
    r._entered = True
    r._resident = "kern-sbx-t"
    r._spawn(["true"], network=False, timeout_s=5)
    assert "-u" not in out.read_text().splitlines()


def test_persist_as_a_non_root_user_is_refused_by_a_kern_without_exec_u(tmp_path, monkeypatch):
    """The fake answers `kern exec --help` like kern 0.30.2: no `-u <user>` in it."""
    fake, _ = _argv_recorder(tmp_path)
    monkeypatch.setenv("KERN_BIN", fake)
    s = Sandbox(user="node", persist=True, name="n")
    s._ws = str(tmp_path)
    with pytest.raises(SandboxError, match=r"needs a kern whose `kern exec` takes `-u <user>`"):
        s._resolve_identity()


# ---------------------------------------------------------------------------
# INTEGRATION
# ---------------------------------------------------------------------------


def _kern_bin():
    k = os.environ.get("KERN_BIN") or shutil.which("kern")
    return k if k and k != _FAKE_KERN and os.access(k, os.X_OK) else None


def _why_no_user_box():
    """None when a box can run as a non-root account here, else the reason it cannot."""
    k = _kern_bin()
    if k is None:
        return "no runnable kern (set KERN_BIN)"
    # THESE TESTS ARE FOR THE KERN BUILT WITH THIS SDK: `exec -u`, and the kern fixes they assert. An
    # older one on PATH (the installed release) is named and skipped, not failed: against it the SDK
    # refuses `persist` by name, which is its contract with an older kern.
    said = subprocess.run([k, "exec", "--help"], capture_output=True, text=True).stdout
    if "-u <user>" not in said:
        return f"{k} predates `kern exec -u`: build this tree's kern and set KERN_BIN"
    probe = tempfile.mkdtemp()
    try:
        if not _acls_supported(probe):
            return f"no POSIX ACLs on {tempfile.gettempdir()}"
    finally:
        os.rmdir(probe)
    r = subprocess.run(
        [k, "box", f"probe-{uuid.uuid4().hex[:8]}", "--image", "python:3.12-alpine", "--user", "1000",
         "--", "true"],
        capture_output=True, text=True, timeout=300,
    )
    return None if r.returncode == 0 else f"no box as uid 1000 here: {r.stderr.strip()[-200:]}"


@pytest.fixture(scope="module")
def user_box():
    """Skip, naming why, unless a box can run as a non-root account here. A FIXTURE and not a mark, so
    the probe box starts on the first integration test rather than at import: a unit-only run starts
    no box and pulls nothing."""
    why = _why_no_user_box()
    if why is not None:
        pytest.skip(why)


def test_a_snapshot_of_what_the_host_cannot_read_is_taken_through_the_helper(tmp_path, user_box):
    """THE WHOLE POINT OF THE HELPER BOX, and it failed every time until an audit measured it.

    `snapshot()` reads a directory the box account closed to the host by streaming a `tar` from a box
    of the same image running as that account. The host side stopped at the archive's end-of-archive
    marker and then KILLED the helper, which was still tearing its box down, and read the `-9` as the
    box user's failure: measured 9 times out of 9 (a 0700 directory, a 0600 file, and both), each
    one reported as "the box user could not read ... exit -9" about a stream it had read in full.
    Node did it correctly, so this was also a Python/Node split on a documented API."""
    ws = tmp_path / "ws"
    ws.mkdir()
    arc = tmp_path / "ckpt.tar"
    with Sandbox(image="python:3.12-slim", user="daemon", workspace=str(ws), timeout_s=120) as s:
        r = s.run_code(
            "import os\n"
            "os.makedirs('/workspace/sd', exist_ok=True)\n"
            "open('/workspace/sd/in', 'w').write('d')\n"
            "os.chmod('/workspace/sd', 0o700)\n"
            "open('/workspace/f', 'w').write('x')\n"
            "os.chmod('/workspace/f', 0o600)\n"
        )
        assert r.fault is None and r.exit_code == 0, r
        # THE PREMISE: this process really cannot read them, so the helper is the only way in.
        with pytest.raises(PermissionError):
            os.listdir(ws / "sd")
        s.snapshot(str(arc))
    with tarfile.open(arc) as tf:
        names = sorted(n for n in tf.getnames() if not n.startswith(".kern"))
    assert names == ["f", "sd", "sd/in"], names


def test_an_image_that_declares_a_user_works_without_user_and_runs_as_it(tmp_path, user_box):
    """MEASURED on 0.2.45: every call on an image declaring `USER app` failed with `can't open file
    '/workspace/.run-....py': [Errno 13] Permission denied`, exit 2, no fault."""
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-alpine\nRUN adduser -D -u 1000 app\nUSER app\n")
    tag = f"kern-sdk-user-test:{uuid.uuid4().hex[:8]}"
    built = subprocess.run([_kern_bin(), "build", "-q", "-t", tag, str(tmp_path)], capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    try:
        with Sandbox(image=tag, pyc_cache=False) as s:
            r = s.run_code("import os; print(os.getuid()); open('x.txt', 'w').write('1')")
            assert r.exit_code == 0 and r.stdout.strip() == "1000", r
            assert s.read_file("x.txt") == b"1"
            ws = s._ws
        assert not os.path.exists(ws)
        with Sandbox(image=tag, user="root", pyc_cache=False) as s:
            r = s.run_code("import os; print(os.getuid())")
            assert r.stdout.strip() == "0", r
            assert "could not give the workload the group" not in r.stderr, r.stderr
    finally:
        subprocess.run([_kern_bin(), "image", "rm", tag], capture_output=True)


def test_what_the_box_user_closes_to_the_host_is_still_read_listed_counted_snapshotted_and_removed(tmp_path, user_box):
    with Sandbox(image="python:3.12-alpine", user="nobody", pyc_cache=False, workspace_max_bytes=64 << 20) as s:
        r = s.run_code(
            "import os, tempfile\n"
            "print(os.getuid(), os.getgid())\n"
            "os.mkdir('priv', 0o700)\n"
            "fd = os.open('priv/k', os.O_CREAT | os.O_WRONLY, 0o600); os.write(fd, b'secret' * 1000); os.close(fd)\n"
            "os.mkdir('pub', 0o755); open('pub/a.txt', 'w').write('A')\n"
            "fd, p = tempfile.mkstemp(dir='.'); os.write(fd, b'tmp'); os.close(fd); print(os.path.basename(p))\n"
        )
        assert r.exit_code == 0, r
        ids, made = r.stdout.split("\n")[0], r.stdout.split("\n")[1]
        assert ids == "65534 65534"
        with pytest.raises(PermissionError):
            os.listdir(os.path.join(s._ws, "priv"))  # the premise: the host really is refused
        assert {"priv/k", "pub/a.txt", made} <= {f.path for f in r.files}
        assert s.read_file("priv/k") == b"secret" * 1000
        assert s.read_file(made) == b"tmp"
        with pytest.raises(SandboxError, match="larger than max_bytes"):
            s.read_file("priv/k", max_bytes=10)
        s.write_file("pub/new.txt", "hello")
        r = s.run_code("print(open('pub/new.txt').read()); open('pub/new.txt', 'a').write('!')")
        assert r.exit_code == 0 and r.stdout.strip() == "hello", r
        s.write_file("host.txt", "H")
        r = s.run_code("open('host.txt', 'a').write('+'); print(open('host.txt').read())")
        assert r.stdout.strip() == "H+", r
        assert {f.path for f in s.list_files("priv")} == {"priv/k"}
        blind: list = []
        kern._workspace_usage(s._ws, blind)
        assert [os.path.basename(b) for b in blind] == ["priv"]
        r = s.run_code("open('priv/big', 'wb').write(b'z' * (80 << 20))")
        assert r.exit_code == 0, r
        with pytest.raises(SandboxError, match="workspace_max_bytes"):
            s.run_code("print(1)")  # 80 MiB behind a 0700 directory still counts
        s._ws_helper("rm -f /w/priv/big", write=True)
        snap = tmp_path / "snap.tgz"
        s.snapshot(str(snap))
        ws = s._ws
    assert not os.path.exists(ws), "a workspace with closed directories was left behind"
    with tarfile.open(snap) as tf:
        assert "priv/k" in tf.getnames()
    with Sandbox(image="python:3.12-alpine", user="nobody", pyc_cache=False) as s:
        s.restore(str(snap))
        r = s.run_code("print(open('priv/k').read()[:6]); open('priv/k', 'a').write('x')")
        assert r.exit_code == 0 and r.stdout.strip() == "secret", r


def test_every_path_runs_as_the_user_prewarm_kernel_setup_and_persist(tmp_path, user_box):
    with Sandbox(image="python:3.12-alpine", user="1000:1000", prewarm=1, pyc_cache=False) as s:
        r = s.run_code("import os; print(os.getuid(), os.getgid())")
        assert r.stdout.strip() == "1000 1000", r
        with s.kernel() as k:
            r = k.run_code("import os; print(os.getuid())")
            assert r.stdout.strip() == "1000", r
    with Sandbox(image="python:3.12-alpine", user="1000", setup="pip install six", pyc_cache=False) as s:
        r = s.run_code("import os, six; print(os.stat(six.__file__).st_uid)")
        assert r.exit_code == 0 and r.stdout.strip() == "1000", r
    ws = tmp_path / "ws"
    name = f"user-{uuid.uuid4().hex[:8]}"
    try:
        with Sandbox(image="python:3.12-alpine", user="nobody", name=name, persist=True,
                     workspace=str(ws), pyc_cache=False) as s:
            r = s.run_code("import os; print(os.getuid()); open('p.txt', 'w').write('p')")
            assert r.stdout.strip() == "65534", r
            assert s.read_file("p.txt") == b"p"
            s.destroy()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with Sandbox(image="python:3.12-alpine", user="1000", workspace=str(ws), pyc_cache=False) as s:
                assert s.read_file("p.txt") == b"p", "this process still reaches the first account's file"
        assert any("different box account" in str(c.message) and "p.txt" in str(c.message) for c in caught)
    finally:
        subprocess.run([_kern_bin(), "stop", f"kern-sbx-{name}"], capture_output=True)
        subprocess.run([_kern_bin(), "box", f"clean-{name}", "--image", "python:3.12-alpine", "--user", "0",
                        "-v", f"{ws}:/w", "--", "sh", "-c", "rm -rf /w/* /w/.[!.]*"], capture_output=True)


def test_the_helper_refuses_what_the_host_refuses(user_box):
    """The fallback reaches what the box user closed to this process and NOTHING the host path would
    refuse: a symlink on the way (exit 40), a FIFO (41), a file where a directory was asked for (43),
    in the same words as the host's refusals."""
    with Sandbox(image="python:3.12-alpine", user="nobody", pyc_cache=False) as s:
        r = s.run_code(
            "import os\n"
            "os.mkdir('priv', 0o700)\n"
            "os.symlink('/etc/passwd', 'priv/link')\n"
            "os.mkfifo('priv/fifo')\n"
            "open('priv/file', 'w').write('f')\n"
        )
        assert r.exit_code == 0, r
        with pytest.raises(SandboxError, match="(?i)symlink"):
            s.read_file("priv/link")
        with pytest.raises(SandboxError, match="not a regular file"):
            s.read_file("priv/fifo")
        with pytest.raises(SandboxError, match="not a directory"):
            s.list_files("priv/file")
        with pytest.raises(SandboxError, match="(?i)symlink"):
            s.write_file("priv/link", "x")
        with pytest.raises(SandboxError, match="not a regular file"):
            s.write_file("priv/fifo", "x")
        assert s.read_file("priv/file") == b"f", "the control: a regular file there is read"


def test_the_bytecode_cache_is_readable_by_a_non_root_user(user_box):
    """The cache tree is 0755 under a 0700 parent, and a tree left 0700 by an older build is opened up
    when a non-root session adopts it: at 0700 CPython could not enter the prefix and compiled every
    import from source, in silence."""
    image = "python:3.12-alpine"
    with Sandbox(image=image, user="1000"):
        pass
    for th in list(kern._PYC_BUILDS.values()):
        th.join(timeout=300)
    dest = kern._pyc_dir_for(image)
    if not kern._pyc_has_content(dest):
        pytest.skip("no bytecode cache could be built here")
    os.chmod(dest, 0o700)  # the shape an older build left
    with Sandbox(image=image, user="1000") as s:
        assert s._pyc_dir == dest
        assert os.stat(dest).st_mode & 0o777 == 0o755
        r = s.run_code(
            "import os, json, importlib.util\n"
            "p = os.environ['PYTHONPYCACHEPREFIX']\n"
            "print(os.getuid(), os.access(p, os.R_OK | os.X_OK), "
            "os.path.exists(importlib.util.cache_from_source(json.__file__)))"
        )
        assert r.stdout.split() == ["1000", "True", "True"], r


# ---------------------------------------------------------------------------
# WALK: WIDTH, DEPTH AND WHAT COUNTS AS CHURN
# ---------------------------------------------------------------------------


def test_a_wide_workspace_is_listed_whole_under_a_low_descriptor_limit(tmp_path):
    """The walk may hold one descriptor per DEPTH level, never one per entry.

    Its first descriptor-based version opened every subdirectory while listing the parent and held
    them all until each was visited, so the count grew with the tree's WIDTH: 1500 package
    directories under `node_modules` need 1500 at once and the usual soft limit is 1024. The opens
    then failed, and because a resource error was treated as churn those subtrees were simply absent
    from `list_files` and `result.files` - the silence the descriptor walk exists to remove.

    The limit is lowered for this test so a pass does not depend on the host's being generous, and
    the control is the count: every file must come back.
    """
    import resource

    s = _cfg()
    s._ws = str(tmp_path)
    ws = tmp_path
    width, depth = 400, 12
    for i in range(width):
        d = ws / f"d{i}"
        d.mkdir()
        (d / "f.txt").write_text(str(i))
    deep = ws / "deep"
    cur = deep
    for i in range(depth):
        cur = cur / f"l{i}"
    cur.mkdir(parents=True)
    (cur / "bottom.txt").write_text("bottom")

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(128, hard), hard))
    try:
        got = s._walk(s._ws)
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

    missing = [f"d{i}/f.txt" for i in range(width) if f"d{i}/f.txt" not in got]
    assert not missing, f"{len(missing)} of {width} subtrees were dropped, first: {missing[:3]}"
    assert "deep/" + "/".join(f"l{i}" for i in range(depth)) + "/bottom.txt" in got


def test_the_walk_raises_on_a_resource_error_instead_of_reporting_a_smaller_workspace(tmp_path):
    """A descriptor it could not get is not a subtree that is not there.

    `result.files` and `list_files` are what a caller reads to find out what the code wrote. An
    answer that is short because the host ran out of descriptors, with nothing said, is the one
    failure shape this must not have: `ENOENT`/`ENOTDIR`/`ELOOP` are churn in a workspace a box is
    writing to, everything else is raised.
    """
    s = _cfg()
    s._ws = str(tmp_path)
    ws = tmp_path
    (ws / "sub").mkdir()
    (ws / "sub" / "f.txt").write_text("x")
    real_open = os.open

    def no_fds(path, flags, *a, **kw):
        if isinstance(path, str) and path == "sub":
            raise OSError(errno.EMFILE, "too many open files")
        return real_open(path, flags, *a, **kw)

    with mock.patch("os.open", side_effect=no_fds):
        with pytest.raises(OSError) as e:
            s._walk(s._ws)
    assert e.value.errno == errno.EMFILE

    # The control, same shape: a directory that really did go away is churn, and the walk goes on.
    def gone(path, flags, *a, **kw):
        if isinstance(path, str) and path == "sub":
            raise OSError(errno.ENOENT, "no such file or directory")
        return real_open(path, flags, *a, **kw)

    (ws / "top.txt").write_text("kept")
    with mock.patch("os.open", side_effect=gone):
        got = s._walk(s._ws)
    assert "top.txt" in got and "sub/f.txt" not in got


def test_an_unreadable_directory_cannot_hide_bytes_from_workspace_max_bytes(tmp_path):
    """The cap is cooperative, but it must not be defeatable for good by one `chmod`.

    In a default session the box runs as this process's own uid, so the code in the box owns the
    workspace and can close a directory to the host. The usage walk counted such a directory as zero,
    so: call one writes a cap's worth of bytes into `h/` and runs `os.chmod("h", 0)`, and every call
    after that measures those bytes as nothing and is admitted. The cap is gone for the life of the
    session, with nothing said.

    There is no helper to ask here - the helper runs AS the box user, which in this session is this
    process - so the only honest outcomes are to refuse or to admit on a number known to be short.
    This asserts the refusal, and that it names the cap rather than leaving the reader with an
    unexplained error from a listing.
    """
    if os.getuid() == 0:
        pytest.skip("root reads a 000 directory, so nothing here is closed to it")
    s = _cfg(workspace_max_bytes=1 << 20)
    s._ws = str(tmp_path)
    hidden = tmp_path / "h"
    hidden.mkdir()
    (hidden / "big").write_bytes(b"y" * (2 << 20))
    os.chmod(hidden, 0)
    try:
        with pytest.raises(SandboxError) as e:
            s._spawn(["true"], timeout_s=5, network=False)
        said = str(e.value)
        assert "workspace_max_bytes cannot be measured" in said, said
        assert "refused before running" in said, said
    finally:
        os.chmod(hidden, 0o700)


def test_a_symlinked_path_component_is_refused_by_the_sentence_that_names_the_symlink(tmp_path):
    """The refusal has to name what is wrong, and the kernel's errno does not.

    `O_DIRECTORY|O_NOFOLLOW` on a symlink answers ENOTDIR on current kernels, not ELOOP, so a
    symlinked component came back as "workspace path component is not a directory" - true of a
    regular file in the way too, and it drops the fact that matters: something in this path points
    out of the workspace. Both shapes are asserted, because one sentence for both is how the
    distinction was lost in the first place.
    """
    s = _cfg()
    s._ws = str(tmp_path)
    s._entered = True
    outside = tmp_path.parent / f"outside-{uuid.uuid4().hex[:8]}"
    outside.mkdir()
    os.symlink(outside, tmp_path / "evil")
    (tmp_path / "plain").write_text("not a directory")
    try:
        with pytest.raises(SandboxError) as e:
            s.write_file("evil/x", "nope")
        assert "symlinked directory" in str(e.value), str(e.value)
        assert not (outside / "x").exists(), "the write landed outside the workspace"

        with pytest.raises(SandboxError) as e:
            s.write_file("plain/x", "nope")
        assert "not a directory" in str(e.value), str(e.value)
    finally:
        shutil.rmtree(outside, ignore_errors=True)


def test_a_snapshot_written_into_the_workspace_does_not_contain_itself(tmp_path):
    """`snapshot(f"{ws}/ckpt.tar.gz")` is an ordinary thing to ask for.

    Without the check the archive holds a member for itself: the half-written gzip of the snapshot so
    far, whose contents depend on when the walk reached it. `tarfile.add` skipped its own file for
    this reason and the descriptor walk that replaced it had no equivalent. Compared by inode, so a
    hard link to the archive under another name is caught too.
    """
    s = _cfg()
    s._ws = str(tmp_path)
    s._entered = True
    (tmp_path / "kept.txt").write_text("user state")
    dest = tmp_path / "ckpt.tar.gz"
    s.snapshot(str(dest))
    with tarfile.open(dest, "r:gz") as tf:
        names = tf.getnames()
    assert "kept.txt" in names, names
    assert "ckpt.tar.gz" not in names, f"the archive archived itself: {names}"


# ---------------------------------------------------------------------------
# SNAPSHOT: WHAT IT CARRIES, WHAT IT LEAVES OUT, AND WHERE ITS .deps CAME FROM
# ---------------------------------------------------------------------------


def _entered(tmp_path, name, **kw):
    s = _cfg(**kw)
    ws = tmp_path / name
    ws.mkdir()
    s._ws, s._entered = str(ws), True
    return s, ws


def test_a_snapshot_records_what_its_deps_were_built_for_as_its_first_member(tmp_path):
    a, ws = _entered(tmp_path, "a", image="example.org/py:3.12")
    (ws / ".deps" / "m").mkdir(parents=True)
    (ws / ".deps" / "m" / "__init__.py").write_text("V = 1")
    (ws / "a.txt").write_text("A")
    arc = tmp_path / "s.tgz"
    a.snapshot(str(arc))
    with tarfile.open(arc) as tf:
        first = tf.getmembers()[0]
        assert first.name == kern._SNAPSHOT_RECORD and first.isreg()
        import json

        rec = json.loads(tf.extractfile(first).read())
    assert rec == {"kern_snapshot": 1, "image": "example.org/py:3.12", "machine": os.uname().machine, "deps": True}


def test_restore_says_where_deps_came_from_only_when_the_image_or_cpu_differs(tmp_path):
    """MEASURED without it: orjson installed by `setup=` in a python 3.12 glibc image, restored into
    `python:3.10-alpine`, then `import orjson` -> `ModuleNotFoundError: No module named
    'orjson.orjson'`, with nothing pointing at the snapshot. The control is the same archive restored
    into the SAME image, where a warning would be noise on every ordinary resume."""
    a, ws = _entered(tmp_path, "a", image="example.org/py:3.12")
    (ws / ".deps").mkdir()
    (ws / ".deps" / "x.py").write_text("")
    arc = tmp_path / "s.tgz"
    a.snapshot(str(arc))

    def restore_into(name, image):
        b, bws = _entered(tmp_path, name, image=image)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            b.restore(str(arc))
        notes = [str(x.message) for x in w if "were installed in image" in str(x.message)]
        assert not (bws / kern._SNAPSHOT_RECORD).exists(), "the record is read, never restored"
        assert (bws / ".deps" / "x.py").exists()
        return notes

    assert restore_into("same", "example.org/py:3.12") == []
    other = restore_into("other", "python:3.10-alpine")
    assert len(other) == 1 and "'example.org/py:3.12'" in other[0] and "'python:3.10-alpine'" in other[0]
    # `alpine` IS `alpine:latest`: the comparison is kern's own normalisation, not string equality.
    assert kern._snapshot_origin_note({"image": "alpine", "machine": "m"}, "alpine:latest", "m", True) is None
    # Another CPU with the same image is a difference too, and no .deps is nothing to warn about.
    assert kern._snapshot_origin_note({"image": "a", "machine": "x86_64"}, "a", "aarch64", True)
    assert kern._snapshot_origin_note({"image": "a", "machine": "x86_64"}, "b", "aarch64", False) is None


def test_a_user_file_named_like_the_record_is_restored_as_a_file(tmp_path):
    """The record is recognised as the FIRST member holding its key, not by name: a user's own file
    of the same name is a later member and comes back like any other. And an archive whose first
    member has the name but not the key (a tar made by hand) restores it as a file, with no warning."""
    a, ws = _entered(tmp_path, "a")
    (ws / kern._SNAPSHOT_RECORD).write_text('{"mine": true}')
    arc = tmp_path / "s.tgz"
    a.snapshot(str(arc))
    b, bws = _entered(tmp_path, "b")
    b.restore(str(arc))
    assert (bws / kern._SNAPSHOT_RECORD).read_text() == '{"mine": true}'

    import io as _io

    hand = tmp_path / "hand.tar"
    with tarfile.open(hand, "w", format=tarfile.USTAR_FORMAT) as tf:
        body = b'{"kern_snapshot": 2, "image": "elsewhere"}'
        info = tarfile.TarInfo(kern._SNAPSHOT_RECORD)
        info.size = len(body)
        tf.addfile(info, _io.BytesIO(body))
    c, cws = _entered(tmp_path, "c")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        c.restore(str(hand))
    assert (cws / kern._SNAPSHOT_RECORD).read_bytes() == body
    assert not [x for x in w if "were installed in image" in str(x.message)]


def test_a_snapshot_never_holds_a_member_its_restore_refuses(tmp_path):
    """MEASURED on 0.2.45: a workspace with one symlink gave a snapshot that `restore` refused whole
    ("unsafe member type in snapshot"), and a hard link did the same through its link member. The
    refusal stays, because it is right for an archive from outside; the snapshot stops producing it.
    Symlinks, FIFOs, devices and sockets are named in a warning; a hard link is a file of its own."""
    a, ws = _entered(tmp_path, "a")
    (ws / "data.txt").write_text("x")
    os.symlink("data.txt", ws / "latest")
    os.link(ws / "data.txt", ws / "hard.txt")
    os.mkfifo(ws / "pipe")
    arc = tmp_path / "s.tgz"
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        a.snapshot(str(arc))
    said = [str(x.message) for x in w if "not archived" in str(x.message)]
    assert len(said) == 1 and "'latest'" in said[0] and "'pipe'" in said[0], said
    with tarfile.open(arc) as tf:
        assert all(m.isreg() or m.isdir() for m in tf.getmembers()), [(m.name, m.type) for m in tf.getmembers()]
    b, bws = _entered(tmp_path, "b")
    b.restore(str(arc))  # the control: raised SandboxError on 0.2.45
    assert (bws / "hard.txt").read_text() == "x" and (bws / "data.txt").read_text() == "x"


def test_the_helper_box_and_the_uid_probe_clear_the_images_entrypoint(tmp_path, monkeypatch):
    """kern PREPENDS the image's ENTRYPOINT to what follows ``--``, so without ``--entrypoint ""``
    the helper ran ``ENTRYPOINT sh -c SCRIPT`` and the IMAGE chose what came out - and a helper's
    output is parsed, not displayed: ``_helper_read`` returns it as the file's bytes,
    ``_parse_helper_list`` reads stat records out of it, ``_snapshot_blind`` reads a tar. An audit of
    this branch found it; the docstring of ``_helper_argv`` had already promised the opposite ("only
    the scripts of this module: never code from the session")."""
    s = _cfg()
    s._as_user = "app"
    argv = s._helper_argv(kern._HELPER_READ, ("f.txt",), False, 60)
    assert "--entrypoint" in argv, argv
    assert argv[argv.index("--entrypoint") + 1] == "", "an empty value is what clears it"
    # BEFORE THE `--`, or it would be an argument of the workload instead of a flag of kern.
    assert argv.index("--entrypoint") < argv.index("--"), argv
    # AND THE FLAG IS REAL, WITH THIS MEANING, in the kern on this host: the argv above is this
    # package's half, and a flag kern stopped accepting would make every helper call fail. Asked of
    # the real binary when there is one (`_cfg` runs against a fake), skipped when there is not.
    real = _kern_bin()
    if real is None:
        return
    said = subprocess.run(
        [real, "box", "--help"], capture_output=True, text=True, timeout=60,
    ).stdout
    assert '`--entrypoint ""` clears it' in said, "kern's own help must still say so"


def test_an_image_whose_user_is_not_a_user_is_refused_by_name(tmp_path, monkeypatch):
    """``user=`` is validated in ``__post_init__``; the image's own ``USER`` reached the argv
    unexamined, so an image declaring ``USER --privileged`` put that after ``--user``. kern's parser
    takes the next token whatever it looks like, so this was not an argv injection - but
    ``_USER_SPEC_RE``'s comment promises the value can never read as a flag, and a promise that holds
    for one of two halves is not one."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    images = tmp_path / "kern" / "images"
    images.mkdir(parents=True)
    side = images / (kern._sanitize_ref("evil/img:1") + ".image")
    for bad in ("--privileged", " root", "x" * 300, "a:b:c"):
        side.write_text(f"fmt\t3\nuser\t{bad}\n")
        assert kern._image_user("evil/img:1") == bad, "the premise: the sidecar says so"
        s = _cfg(image="evil/img:1")
        with pytest.raises(kern.SandboxError) as e:
            s._resolve_identity()
        said = str(e.value)
        assert "declares USER" in said and "user=" in said, said
    # THE CONTROL: a spec that IS a shape kern can be given gets past this check (and then fails
    # elsewhere, because the fake kern has no such image - which is not what this test is about).
    side.write_text("fmt\t3\nuser\tnode\n")
    assert kern._image_user("evil/img:1") == "node"
    s = _cfg(image="evil/img:1")
    try:
        s._resolve_identity()
    except kern.SandboxError as e:
        assert "declares USER" not in str(e), f"a valid image USER must not be refused here: {e}"


def test_a_leftover_env_file_is_never_archived_and_nothing_but_the_bare_name_is_hidden(tmp_path):
    """Out of the ARCHIVE by shape, out of the LISTING only by provenance.

    This version writes no env file into the workspace; an OLDER one did, and a process killed
    mid-call left it there holding `env=` values, so a `snapshot` - which TRAVELS - must not carry
    one. A LISTING is a different question: it is the operator's answer to "what did this cell leave
    behind", and every shape in that pattern is one a cell can create (12 free hex digits, or 191
    free characters after `kern-sbx-`). Using one predicate for both made the pattern a hiding
    primitive: a box that named a file to match was absent from `list_files`, `result.files` AND
    `snapshot`. An audit of this branch found it; this asserts the split that closed it."""
    a, ws = _entered(tmp_path, "a")
    (ws / ".kern-env.pysbx-0123456789ab").write_text("TOKEN=secret\n")
    (ws / ".kern-env.jssbx-abcdefabcdef").write_text("TOKEN=secret\n")
    (ws / ".kern-env.kern-sbx-payload").write_text("what a box would name\n")
    (ws / ".kern-env.notmine").write_text("visible\n")
    (ws / ".kern-env").write_text("TOKEN=secret\n")  # the bare legacy name: ours, exactly
    arc = tmp_path / "s.tgz"
    a.snapshot(str(arc))
    with tarfile.open(arc) as tf:
        names = tf.getnames()
    for hidden in (
        ".kern-env",
        ".kern-env.pysbx-0123456789ab",
        ".kern-env.jssbx-abcdefabcdef",
        ".kern-env.kern-sbx-payload",
    ):
        assert hidden not in names, f"{hidden} must not travel in an archive"
    assert ".kern-env.notmine" in names, "a name no version ever wrote is the caller's own file"
    # AND THE LISTING SHOWS EVERYTHING BUT THE ONE EXACT LEGACY NAME.
    listed = {f.path for f in a.list_files()}
    for shown in (
        ".kern-env.notmine",
        ".kern-env.pysbx-0123456789ab",
        ".kern-env.jssbx-abcdefabcdef",
        ".kern-env.kern-sbx-payload",
    ):
        assert shown in listed, f"{shown} is a file a box can create: hiding it is the defect"
    assert ".kern-env" not in listed, "the bare legacy name is ours by exact match"


def test_one_archive_restores_to_the_same_tree_in_both_bindings(tmp_path, user_box):
    """THE ARCHIVE IS A WIRE FORMAT BETWEEN THE TWO BINDINGS, so a tree that goes in has to come out
    the same whichever one wrote it and whichever one reads it. It did not, in four ways, each
    measured on the same tree:

    * mtimes: Python wrote the real ones, Node wrote 0 and applied none, so a restored tree carried
      the moment of the restore there and the moment of the snapshot here - which is what an
      incremental tool reads (`make`, `tsc --incremental`, and CPython's own `(mtime, size)` check on
      a `.pyc` under `.deps`).
    * empty directories: Node wrote no directory members at all, so `emptydir/` was absent from the
      archive and from the restored tree. `docs/SANDBOX.md` promises `restore` writes "regular files
      and directories".
    * modes: Node wrote a constant 0644, so an executable file came back without its execute bit.
    * paths of 101 to 255 bytes: Node's writer refused them while its own reader has always read the
      ustar `prefix` field, so Node could not write what Node could read, and a Python-written
      archive with such a path threw from Node's re-emission path after part of the tree was written.

    Four combinations, one expected tree. The group and other bits are deliberately NOT preserved:
    on a workspace shared with a box account the group bits are the ACL's mask, and the ACL does not
    travel in a tar (see `_restore_host`)."""
    import json
    import shutil

    node = shutil.which("node")
    js_path = pathlib.Path(kern.__file__).resolve().parents[2] / "node" / "index.js"
    if not node or not js_path.exists():
        pytest.skip("needs node and the Node binding's source beside this one")
    mt = 1_600_000_000

    def make_tree(ws: pathlib.Path) -> None:
        (ws / "emptydir").mkdir()
        (ws / "d").mkdir()
        (ws / "d" / "a.txt").write_text("y")
        (ws / "script.sh").write_text("#!/bin/sh\n")
        os.chmod(ws / "script.sh", 0o755)
        (ws / "plain.txt").write_text("p")
        os.chmod(ws / "plain.txt", 0o644)
        # A 182-byte path, which ustar can only carry split across `prefix` and `name`.
        deep = ws / ("a" * 60) / ("b" * 60) / ("c" * 60)
        deep.mkdir(parents=True)
        (deep / "deep.txt").write_text("D")
        for root, dirs, files in os.walk(ws, topdown=False):
            for n in files + dirs:
                os.utime(os.path.join(root, n), (mt, mt))

    def py_write(dest: pathlib.Path) -> None:
        ws = tmp_path / f"pw-{dest.name}"
        ws.mkdir()
        make_tree(ws)
        with Sandbox(image="alpine:3.19", workspace=str(ws), timeout_s=60) as s:
            s.snapshot(str(dest))

    def py_read(arc: pathlib.Path) -> "list[str]":
        ws = tmp_path / f"pr-{arc.name}"
        ws.mkdir()
        with Sandbox(image="alpine:3.19", workspace=str(ws), timeout_s=60) as s:
            s.restore(str(arc))
        rows = []
        for root, dirs, files in os.walk(ws):
            for n in dirs + files:
                p = os.path.join(root, n)
                st = os.lstat(p)
                kind = "d" if stat.S_ISDIR(st.st_mode) else "f"
                rows.append(
                    f"{os.path.relpath(p, ws)} {kind} {stat.S_IMODE(st.st_mode):o} {int(st.st_mtime)}"
                )
        return sorted(r for r in rows if kern._SNAPSHOT_RECORD not in r)

    # The Node half, driven as one script per direction: it uses the binding's real `snapshot` and
    # `restore`, not a re-implementation, which is the only version of this test worth having.
    js = """
    const {Sandbox} = require(process.argv[1]);
    const fs = require('fs'), os = require('os'), path = require('path');
    const MT = 1600000000;
    function tree(ws) {
      fs.mkdirSync(path.join(ws,'emptydir')); fs.mkdirSync(path.join(ws,'d'));
      fs.writeFileSync(path.join(ws,'d','a.txt'),'y');
      fs.writeFileSync(path.join(ws,'script.sh'),'#!/bin/sh\\n'); fs.chmodSync(path.join(ws,'script.sh'),0o755);
      fs.writeFileSync(path.join(ws,'plain.txt'),'p'); fs.chmodSync(path.join(ws,'plain.txt'),0o644);
      const deep = path.join(ws,'a'.repeat(60),'b'.repeat(60),'c'.repeat(60));
      fs.mkdirSync(deep,{recursive:true}); fs.writeFileSync(path.join(deep,'deep.txt'),'D');
      const walk = (d) => { for (const e of fs.readdirSync(d,{withFileTypes:true})) {
        const p = path.join(d,e.name); if (e.isDirectory()) walk(p); fs.utimesSync(p,MT,MT); } };
      walk(ws);
    }
    (async () => {
      const mode = process.argv[2], arc = process.argv[3];
      if (mode === 'write') {
        const ws = fs.mkdtempSync(path.join(os.tmpdir(),'nw-')); tree(ws);
        const s = new Sandbox({image:'alpine:3.19', workspace:ws, timeoutS:60});
        await s.open(); await s.snapshot(arc); await s.close();
        process.stdout.write('[]');
        return;
      }
      const ws = fs.mkdtempSync(path.join(os.tmpdir(),'nr-'));
      const s = new Sandbox({image:'alpine:3.19', workspace:ws, timeoutS:60});
      await s.open(); await s.restore(arc); await s.close();
      const rows = [];
      const walk = (d) => { for (const e of fs.readdirSync(d,{withFileTypes:true})) {
        const p = path.join(d,e.name); const st = fs.lstatSync(p);
        rows.push(`${path.relative(ws,p)} ${e.isDirectory()?'d':'f'} ${(st.mode & 0o7777).toString(8)} ${Math.floor(st.mtimeMs/1000)}`);
        if (e.isDirectory()) walk(p); } };
      walk(ws);
      process.stdout.write(JSON.stringify(rows.filter((r) => !r.includes('.kern-snapshot')).sort()));
    })().catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
    """
    env = dict(os.environ, KERN_SANDBOX_SNAPSHOT="1")
    if _kern_bin():
        env["KERN_BIN"] = _kern_bin()

    def node_run(mode: str, arc: pathlib.Path) -> "list[str]":
        r = subprocess.run(
            [node, "-e", js, str(js_path), mode, str(arc)],
            capture_output=True, text=True, timeout=300, env=env,
        )
        assert r.returncode == 0, f"node {mode} failed: {r.stderr[-800:]}"
        return json.loads(r.stdout or "[]")

    py_arc = tmp_path / "py.tar"
    node_arc = tmp_path / "node.tar"
    py_write(py_arc)
    node_run("write", node_arc)
    trees = {
        "py->py": py_read(py_arc),
        "py->node": node_run("read", py_arc),
        "node->py": py_read(node_arc),
        "node->node": node_run("read", node_arc),
    }
    # The expected tree, spelled out: the facts this test is about, not just "the four agree".
    want = sorted(
        [
            f"emptydir d 775 {mt}",
            f"d d 775 {mt}",
            f"d/a.txt f 600 {mt}",
            f"plain.txt f 600 {mt}",
            f"script.sh f 700 {mt}",
            f"{'a' * 60} d 775 {mt}",
            f"{'a' * 60}/{'b' * 60} d 775 {mt}",
            f"{'a' * 60}/{'b' * 60}/{'c' * 60} d 775 {mt}",
            f"{'a' * 60}/{'b' * 60}/{'c' * 60}/deep.txt f 600 {mt}",
        ]
    )
    for how, got in trees.items():
        assert got == want, f"{how} differs:\n got  {got}\n want {want}"


def test_both_bindings_read_the_same_bytes_as_the_record_or_as_not_the_record():
    """An archive one binding wrote is restored by the other, and a crafted one by either, so the
    question "is this the record?" must have one answer. It had four that differed: a lone surrogate
    in `image` made this binding's restore RAISE, `true` counted as the key here and not in Node, a
    BOM or UTF-16 body counted here only, and an escape sequence reached the host's stderr through the
    warning in both. The cases run through BOTH implementations and must agree, and each must give the
    answer written beside it."""
    import base64
    import json
    import shutil

    node = shutil.which("node")
    js_path = pathlib.Path(kern.__file__).resolve().parents[2] / "node" / "index.js"
    if not node or not js_path.exists():
        pytest.skip("needs node and the Node binding's source beside this one")
    rec = lambda **kw: json.dumps({"kern_snapshot": 1, "image": "python:3.12", "machine": "x86_64", **kw}).encode()
    cases = {
        "valid": (rec(), True),
        "key 1.0": (b'{"kern_snapshot":1.0,"image":"a","machine":"m"}', True),
        "key true": (rec(kern_snapshot=True), False),
        "key string": (rec(kern_snapshot="1"), False),
        "UTF-8 BOM": (b"\xef\xbb\xbf" + rec(), False),
        "UTF-16": (json.dumps({"kern_snapshot": 1, "image": "a", "machine": "m"}).encode("utf-16"), False),
        "lone surrogate": (b'{"kern_snapshot":1,"image":"\\ud800","machine":"m"}', False),
        "escape in machine": (b'{"kern_snapshot":1,"image":"a","machine":"\\u001b[31m"}', False),
        "space in image": (rec(image="a b"), False),
        "image too long": (rec(image="a" * 257), False),
        "not an object": (b"[1]", False),
    }
    js = (
        "const src=require('fs').readFileSync(process.argv[1],'utf8');"
        "const body=src.match(/const SNAPSHOT_FIELD = [^\\n]+\\n/)[0]"
        "+src.match(/function snapshotRecord\\(raw\\) \\{[\\s\\S]*?\\n\\}\\n/)[0]+'return snapshotRecord;';"
        "const f=new Function('TextDecoder','SNAPSHOT_RECORD_KEY',body)(TextDecoder,'kern_snapshot');"
        "const c=JSON.parse(require('fs').readFileSync(0,'utf8'));"
        "process.stdout.write(JSON.stringify(Object.fromEntries(Object.entries(c).map(([k,v])=>[k,f(Buffer.from(v,'base64'))!==null]))));"
    )
    out = subprocess.run(
        [node, "-e", js, str(js_path)],
        input=json.dumps({k: base64.b64encode(v).decode() for k, (v, _) in cases.items()}),
        capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, out.stderr
    in_node = json.loads(out.stdout)
    for name, (raw, want) in cases.items():
        in_python = kern._snapshot_record(raw) is not None
        assert (in_python, in_node[name]) == (want, want), f"{name}: python={in_python} node={in_node[name]}"


def test_a_snapshot_path_inside_the_workspace_never_follows_what_the_box_planted(tmp_path):
    """`snapshot(f"{ws}/ckpt.tar.gz")` is documented and tested, so the name is one a box can predict.
    By path, a symlink planted there sent the archive onto the host file it named, and one planted at
    a `restore` source made the host restore a HOST archive where the box can read it. Inside the
    workspace both are now opened by descriptor; the controls are the same calls with nothing planted,
    which must still work."""
    a, ws = _entered(tmp_path, "a")
    (ws / "kept.txt").write_text("k")
    victim = tmp_path / "host-file"
    victim.write_text("HOST")
    os.symlink(victim, ws / "ckpt.tar.gz")
    with pytest.raises(SandboxError):
        a.snapshot(str(ws / "ckpt.tar.gz"))
    assert victim.read_text() == "HOST", "the archive was written through the box's symlink"
    # A symlinked DIRECTORY on the way, the same.
    (tmp_path / "hostdir").mkdir()
    os.symlink(tmp_path / "hostdir", ws / "out")
    with pytest.raises(SandboxError):
        a.snapshot(str(ws / "out" / "ckpt.tar.gz"))
    assert not (tmp_path / "hostdir" / "ckpt.tar.gz").exists()

    # restore: a host archive behind a planted name is not read.
    host_arc = tmp_path / "host.tgz"
    with tarfile.open(host_arc, "w:gz") as tf:
        import io as _io

        info = tarfile.TarInfo("secret.txt")
        info.size = 6
        tf.addfile(info, _io.BytesIO(b"SECRET"))
    os.symlink(host_arc, ws / "incoming.tgz")
    with pytest.raises(SandboxError):
        a.restore(str(ws / "incoming.tgz"))
    assert not (ws / "secret.txt").exists()

    # The controls: in the workspace with nothing planted, both still work.
    os.unlink(ws / "ckpt.tar.gz")
    a.snapshot(str(ws / "ckpt.tar.gz"))
    b, bws = _entered(tmp_path, "b")
    shutil.copy(ws / "ckpt.tar.gz", bws / "in.tgz")
    b.restore(str(bws / "in.tgz"))
    assert (bws / "kept.txt").read_text() == "k"
