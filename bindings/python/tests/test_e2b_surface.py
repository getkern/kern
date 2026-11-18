"""Labels and `Sandbox.list`, `get_metrics`, `set_timeout` and `watch_dir`.

The unit tests need no kern. The integration ones start real boxes and need a kern with
`kern update --timeout` and `ends_at` in `kern inspect --json` (0.51.4 or newer, or this tree's).
"""
import contextlib
import os
import shutil
import threading
import time
import uuid

import pytest

import kern_sandbox as kern
from kern_sandbox import Sandbox, SandboxError, SandboxMetrics, WatchEvent
from _fake_kern import FAKE_KERN as _FAKE_KERN


def _kern_runnable() -> bool:
    k = os.environ.get("KERN_BIN") or shutil.which("kern")
    return bool(k) and k != _FAKE_KERN and os.access(k, os.X_OK)


integration = pytest.mark.skipif(not _kern_runnable(), reason="no runnable kern (set KERN_BIN)")


# ---------------------------------------------------------------------------------------------- unit


def _cfg(**kw):
    """A Sandbox built against the fake kern, the real `$KERN_BIN` put back afterwards."""
    prev = os.environ.get("KERN_BIN")
    os.environ["KERN_BIN"] = _FAKE_KERN
    try:
        return Sandbox(**kw)
    finally:
        if prev is None:
            os.environ.pop("KERN_BIN", None)
        else:
            os.environ["KERN_BIN"] = prev


def test_labels_become_label_flags_and_bad_ones_are_refused_by_name():
    s = _cfg(labels={"run": "r-42", "team/x": "a b,c=d"})
    assert s._label_args == ["--label", "run=r-42", "--label", "team/x=a b,c=d"]
    for bad, says in [
        ({"kern.sbx.cfg": "x"}, "kern's own"),
        ({"-x": "y"}, "letters, digits"),
        ({"a b": "y"}, "letters, digits"),
        ({"k": "two\nlines"}, "one line"),
        ({"k": 3}, "must be a str"),
        (["k=v"], "mapping"),
        ({f"k{i}": "v" for i in range(65)}, "at most 64"),
    ]:
        with pytest.raises(SandboxError, match=says):
            _cfg(labels=bad)


def test_labels_are_not_posture():
    """Two processes meeting on one persist sandbox may label it differently and must still meet:
    labels stay out of every dry argv (the resident fingerprint and the prewarm key)."""
    a = _cfg(labels={"run": "1"})
    b = _cfg(labels={"run": "2"})
    c = _cfg()
    mats = {s._posture_material(network=False, timeout_s=60) for s in (a, b, c)}
    assert len(mats) == 1
    assert "--label" not in a._base_argv("", network=False, timeout_s=60, dry=True)


def test_set_timeout_is_refused_without_persist_before_any_box():
    with pytest.raises(SandboxError, match="persist=True"):
        _cfg().set_timeout(5)


# ------------------------------------------------------------------------------------- integration


@pytest.fixture
def persist_box(tmp_path):
    name = f"e2b{uuid.uuid4().hex[:8]}"
    ws = tmp_path / "ws"
    ws.mkdir(mode=0o700)
    sb = Sandbox(persist=True, name=name, workspace=str(ws), labels={"suite": name})
    sb.__enter__()
    try:
        yield sb
    finally:
        sb.destroy()
        sb.__exit__(None, None, None)


@integration
def test_a_resident_box_carries_the_fingerprint_this_process_computes(persist_box):
    """MEASURED on 0.2.53: the box was made with one fingerprint and the same process, after its
    `__enter__` decided the bytecode cache, computed another; `set_timeout` then refused the box
    it had just created."""
    persist_box.run_code("print(1)")
    on_box = (persist_box._resident_lookup() or {}).get("labels", {}).get(Sandbox._CFG_LABEL)
    assert on_box == persist_box._resident_fingerprint()


@integration
def test_list_finds_a_sandbox_by_its_labels_and_only_while_it_runs(persist_box):
    persist_box.run_code("print(1)")
    label = dict(persist_box.labels)
    found = Sandbox.list(labels=label)
    assert [(i.name, i.kind) for i in found] == [(persist_box.name, "persist")]
    assert found[0].labels == label
    assert not any(k.startswith("kern.") for k in found[0].labels)
    assert Sandbox.list(labels={"suite": "no-such-label"}) == []
    persist_box.destroy()
    assert Sandbox.list(labels=label) == []


@integration
def test_set_timeout_moves_the_resident_box_deadline_both_ways(persist_box):
    persist_box.run_code("print(1)")
    persist_box.set_timeout(600)
    left = persist_box.get_metrics(interval_s=0).ends_at - int(time.time())
    assert 590 <= left <= 601, left
    persist_box.set_timeout(2)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and persist_box._resident_lookup() is not None:
        time.sleep(0.2)
    assert persist_box._resident_lookup() is None, "set_timeout(2) did not end the box"
    # The next call recreates it, as after any expiry.
    r = persist_box.run_code("print('again')")
    assert r.stdout.strip() == "again", r.stderr


@integration
def test_set_timeout_zero_removes_the_deadline(persist_box):
    persist_box.run_code("print(1)")
    persist_box.set_timeout(0)
    assert persist_box.get_metrics(interval_s=0).ends_at is None


@integration
def test_get_metrics_reads_the_box_and_the_workspace(persist_box):
    persist_box.run_code("open('blob', 'wb').write(b'x' * 300_000)")
    m = persist_box.get_metrics(interval_s=0.1)
    assert isinstance(m, SandboxMetrics)
    assert m.memory_bytes is not None and m.memory_bytes > 0
    assert m.memory_limit_bytes in (512 * 2**20, None)
    assert m.pids is not None and m.pids >= 1
    assert m.cpu_seconds is not None and m.cpu_percent is not None
    assert m.disk_bytes >= 300_000


@integration
def test_get_metrics_of_a_one_shot_sandbox_has_no_box_fields():
    with Sandbox() as sb:
        m = sb.get_metrics(interval_s=0)
        assert (m.memory_bytes, m.cpu_seconds, m.pids, m.ends_at) == (None, None, None, None)


@integration
def test_a_kernel_reports_its_own_box():
    with Sandbox() as sb, sb.kernel() as k:
        k.run_code("x = bytearray(20_000_000)")
        m = k.get_metrics(interval_s=0)
        assert m.memory_bytes is not None and m.memory_bytes >= 20_000_000


@integration
def test_watch_dir_reports_what_the_box_and_the_host_do():
    with Sandbox() as sb:
        sb.write_file("data/keep.txt", "x")
        got: "list[WatchEvent]" = []
        lock = threading.Lock()

        def on(ev: WatchEvent) -> None:
            with lock:
                got.append(ev)

        with sb.watch_dir("data", on):
            sb.run_code(
                "import os\n"
                "open('data/a.txt','w').write('1')\n"
                "os.rename('data/a.txt','data/b.txt')\n"
                "os.chmod('data/b.txt', 0o600)\n"
                "os.makedirs('data/sub/deep')\n"
                "open('data/sub/deep/c.txt','w').write('2')\n"
                "os.remove('data/keep.txt')\n"
            )
            sb.write_file("data/host.txt", "h")
            time.sleep(0.5)
        seen = {(e.type, e.path, e.old_path) for e in got}
        for want in [
            ("create", "data/a.txt", None),
            ("write", "data/a.txt", None),
            ("rename", "data/b.txt", "data/a.txt"),
            ("chmod", "data/b.txt", None),
            ("create", "data/sub", None),
            ("create", "data/sub/deep/c.txt", None),
            ("remove", "data/keep.txt", None),
            ("create", "data/host.txt", None),
        ]:
            assert want in seen, (want, sorted(seen, key=str))


@integration
def test_watch_dir_never_follows_a_symlink_out_of_the_workspace(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    with Sandbox() as sb:
        os.symlink(str(outside), os.path.join(sb._ws, "link"))
        with pytest.raises(SandboxError, match="not a directory in the workspace"):
            sb.watch_dir("link", lambda e: None)
        with pytest.raises(SandboxError, match="escapes the workspace"):
            sb.watch_dir("../x", lambda e: None)
        # A directory under the watch swapped for a link to the outside is not followed either.
        sb.write_file("d/x", "1")
        got: "list[WatchEvent]" = []
        with sb.watch_dir("", got.append):
            shutil.rmtree(os.path.join(sb._ws, "d"))
            os.symlink(str(outside), os.path.join(sb._ws, "d"))
            time.sleep(0.2)
            (outside / "secret.txt").write_text("host")
            time.sleep(0.4)
        assert not any("secret" in e.path for e in got), got


# ------------------------------------------------------------------------------- egress deny / ranges


def test_egress_entries_take_domains_ranges_and_star_and_deny_alone_means_star():
    s = _cfg(egress_allow=["pypi.org", "10.1.2.9/24", "2001:db8::1", "*"], egress_deny=["bad.io", "10.9.0.0/16"])
    argv = s._base_argv("x", network=False, timeout_s=10, dry=True)
    i = argv.index("--egress-allow")
    assert argv[i + 1] == "pypi.org,10.1.2.0/24,2001:db8::1/128,*"
    j = argv.index("--egress-deny")
    assert argv[j + 1] == "bad.io,10.9.0.0/16"
    only_deny = _cfg(egress_deny=["github.com"])
    argv = only_deny._base_argv("x", network=False, timeout_s=10, dry=True)
    assert argv[argv.index("--egress-allow") + 1] == "*"
    for bad, says in [
        ({"egress_deny": ["*"]}, "denies everything"),
        ({"egress_allow": ["http://x.com"]}, "invalid egress_allow"),
        ({"egress_deny": ["a b"]}, "invalid egress_deny"),
        ({"egress_allow": "pypi.org"}, "list of entries"),
        ({"egress_deny": ["x.com"], "network": True}, "mutually exclusive"),
    ]:
        with pytest.raises(SandboxError, match=says):
            _cfg(**bad)


_EGRESS_PROBE = """
import urllib.request, ssl
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
for u in ["https://example.com", "https://github.com"]:
    try:
        urllib.request.urlopen(u, timeout=10, context=ctx).read(16); print(u, "OPEN")
    except Exception as e:
        print(u, "SHUT")
"""


@integration
@pytest.mark.skipif(os.environ.get("KERN_TEST_NO_INTERNET") == "1", reason="no internet here")
def test_egress_deny_refuses_what_the_allowlist_would_open():
    with Sandbox(egress_deny=["github.com"]) as sb:
        out = sb.run_code(_EGRESS_PROBE).stdout
    assert "https://example.com OPEN" in out, out
    assert "https://github.com SHUT" in out, out


# ------------------------------------------------------------------- ports, get_host, start and ready


def test_ports_start_and_ready_are_validated_and_ports_are_loopback_only():
    s = _cfg(persist=True, name="p", workspace="/tmp", ports=[8000, 9000], start_cmd="srv", ready_cmd="ok")
    argv = s._base_argv("x", network=False, timeout_s=10, dry=True, resident=True)
    assert argv.count("-p") == 2 and "127.0.0.1::8000" in argv and "127.0.0.1::9000" in argv
    assert "-p" not in s._base_argv("x", network=False, timeout_s=10, dry=True), "a call box publishes nothing"
    a = s._posture_material(network=False, timeout_s=10, resident=True)
    b = _cfg(persist=True, name="p", workspace="/tmp", ports=[8000, 9000], start_cmd="other", ready_cmd="ok")
    assert a != b._posture_material(network=False, timeout_s=10, resident=True), "start_cmd is posture"
    for bad, says in [
        ({"ports": [0]}, "not a port"),
        ({"ports": [80, 80]}, "twice"),
        ({"ports": "8000"}, "list of box ports"),
        ({"start_cmd": "x"}, "needs persist=True"),
        ({"ready_cmd": "x"}, "needs persist=True"),
        ({"persist": True, "name": "p", "workspace": "/tmp", "ready_timeout_s": 0}, "positive"),
    ]:
        with pytest.raises(SandboxError, match=says):
            _cfg(**bad)


@integration
def test_a_started_server_is_waited_for_and_reached_through_get_host(tmp_path):
    import urllib.request

    ws = tmp_path / "ws"
    ws.mkdir(mode=0o700)
    sb = Sandbox(
        persist=True,
        name=f"srv{uuid.uuid4().hex[:8]}",
        workspace=str(ws),
        ports=[8000],
        start_cmd="cd /workspace && echo served > index.html && python3 -m http.server 8000",
        ready_cmd="python3 -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000')\"",
    )
    with sb:
        try:
            host = sb.get_host(8000)
            assert host.startswith("127.0.0.1:")
            assert urllib.request.urlopen(f"http://{host}/index.html", timeout=10).read() == b"served\n"
            with pytest.raises(SandboxError, match="not published"):
                sb.get_host(9000)
        finally:
            sb.destroy()


@integration
def test_a_box_that_never_gets_ready_is_refused_by_name(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir(mode=0o700)
    sb = Sandbox(persist=True, name=f"nr{uuid.uuid4().hex[:8]}", workspace=str(ws), ready_cmd="false", ready_timeout_s=2)
    try:
        with pytest.raises(SandboxError, match="was not ready within 2"):
            sb.__enter__()
    finally:
        sb.destroy()
        with contextlib.suppress(Exception):
            sb.__exit__(None, None, None)


@integration
def test_a_kernel_publishes_its_ports():
    import urllib.request

    with Sandbox(ports=[7000]) as sb, sb.kernel() as k:
        k.run_code(
            "import subprocess; subprocess.Popen(['python3','-m','http.server','7000'], "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)"
        )
        host = k.get_host(7000)
        deadline = time.monotonic() + 10
        while True:
            try:
                assert urllib.request.urlopen(f"http://{host}/", timeout=5).status == 200
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)


# ------------------------------------------------------------------------------------------------ pty


def _drive_pty(sb: Sandbox) -> "tuple[int, str]":
    buf = bytearray()
    lock = threading.Lock()

    def on(b: bytes) -> None:
        with lock:
            buf.extend(b)

    def wait_for(text: str, within: float = 10.0) -> None:
        end = time.monotonic() + within
        while time.monotonic() < end:
            with lock:
                if text in bytes(buf).decode(errors="replace"):
                    return
            time.sleep(0.05)
        raise AssertionError(f"{text!r} never appeared: {bytes(buf)!r}")

    with sb.pty(on_data=on, cols=100, rows=30) as t:
        t.send_input("stty size; echo mark-$((6*7))\n")
        wait_for("mark-42")
        t.resize(120, 40)
        time.sleep(0.2)
        t.send_input("stty size; echo after-resize\n")
        wait_for("after-resize")
        t.send_input("sleep 30\n")
        time.sleep(0.5)
        t.send_input(b"\x03")
        t.send_input("exit 5\n")
        rc = t.wait(timeout_s=15)
    with lock:
        return rc, bytes(buf).decode(errors="replace").replace("\r", "")


@integration
def test_a_pty_in_a_one_shot_sandbox_sizes_resizes_interrupts_and_exits():
    with Sandbox() as sb:
        rc, screen = _drive_pty(sb)
    assert rc == 5, screen
    assert "30 100" in screen and "40 120" in screen, screen


@integration
def test_a_pty_in_a_persist_sandbox_runs_in_the_resident_box(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir(mode=0o700)
    sb = Sandbox(persist=True, name=f"pty{uuid.uuid4().hex[:8]}", workspace=str(ws))
    with sb:
        try:
            sb.run_code("open('/tmp/resident-mark','w').write('x')")
            rc, screen = _drive_pty(sb)
            assert rc == 5, screen
            got = bytearray()
            with sb.pty(["sh", "-c", "cat /tmp/resident-mark; echo; echo done"], on_data=got.extend) as t:
                assert t.wait(timeout_s=15) == 0
            assert b"x" in got and b"done" in got, got
        finally:
            sb.destroy()


def test_pty_arguments_are_checked():
    s = _cfg()
    s._entered = True
    with pytest.raises(SandboxError, match="on_data"):
        s.pty(on_data=None)
    with pytest.raises(SandboxError, match="argv list"):
        s.pty("bash", on_data=print)
