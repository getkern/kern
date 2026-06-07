"""Tests for kern_sandbox (v1 — the middle-way session model).

  * UNIT tests (always run): fail-closed defaults, mount/workspace guards, taxonomy plumbing. No kern.
  * INTEGRATION tests (skipped unless a runnable `kern` is present): the brief's acceptance criteria
    against real ephemeral boxes on a persistent workspace.

Run: `pytest`  (integration auto-skips without a real kern; set `KERN_BIN=/path/to/kern`).
"""

import os
import shutil
import time

import pytest

import kern_sandbox as kern
from kern_sandbox import ExecutionResult, MountRefused, Sandbox, SandboxError

_FAKE_KERN = shutil.which("true") or "/bin/true"


def _cfg(**kw):
    """Construct a Sandbox with a fake kern, restoring the real $KERN_BIN so integration tests still
    see the real binary (the leak that once made every box shell out to /bin/true)."""
    prev = os.environ.get("KERN_BIN")
    os.environ["KERN_BIN"] = _FAKE_KERN
    try:
        return Sandbox(**kw)
    finally:
        if prev is None:
            os.environ.pop("KERN_BIN", None)
        else:
            os.environ["KERN_BIN"] = prev


# ---------------------------------------------------------------------------
# UNIT
# ---------------------------------------------------------------------------


def test_defaults_are_fail_closed():
    s = _cfg()
    assert s.network is False and s.timeout_s > 0
    assert s.memory_mb is not None and s.pids is not None
    argv = s._base_argv("n", network=False, timeout_s=s.timeout_s)
    assert "--net" not in argv and "--timeout" in argv and "--ro" in argv


def test_timeout_is_mandatory():
    for bad in (None, 0, -5):
        with pytest.raises(SandboxError):
            _cfg(timeout_s=bad)


def test_network_is_opt_in_and_session_level():
    assert "--net" not in _cfg()._base_argv("n", network=False, timeout_s=30)
    assert "--net" in _cfg(network=True)._base_argv("n", network=True, timeout_s=30)


@pytest.mark.parametrize(
    "mounts",
    [
        {"/": "/host"},
        {"/etc": "/etc-host"},
        {"/var/run/docker.sock": "/sock"},
        {"/tmp": "/"},
        {"/tmp": "/proc"},
        {"/tmp": "/foo/../bar"},
        {"relative/x": "/x"},
        {"/definitely-not-here-xyz": "/x"},
    ],
)
def test_dangerous_mounts_refused(mounts):
    with pytest.raises(MountRefused):
        _cfg(mounts=mounts)


def test_home_mount_refused():
    with pytest.raises(MountRefused):
        _cfg(mounts={os.path.expanduser("~"): "/home-x"})


def test_run_requires_context_manager():
    with pytest.raises(SandboxError):
        _cfg().run_code("print(1)")  # not entered


def test_run_rejects_shell_string():
    s = _cfg()
    s._entered = True  # bypass ctx for the pure-guard check
    with pytest.raises(SandboxError):
        s.run("echo hi")


def test_result_success_semantics():
    from kern_sandbox import SandboxFault

    assert ExecutionResult("", "", 0, 1).success is True
    assert ExecutionResult("", "", 1, 1).success is False
    assert ExecutionResult("", "", 0, 1, fault=SandboxFault("timeout", "x")).success is False


def test_classify_order_escape_not_masked_by_stderr_marker():
    # SECURITY REGRESSION: a workload can print kern's setup marker ("error: sandbox:") to its own
    # stderr and exit with SIGSYS. The classifier MUST still call it escape_blocked (decided by exit
    # code), NOT startup_failed (the stderr-marker heuristic) — else a blocked escape hides behind a
    # benign "startup failed" label. Deterministic classes are checked before the stderr marker.
    s = _cfg()
    forged = "error: sandbox: totally not a real kern setup error\n"
    assert s._classify(159, forged, False).type == "escape_blocked"  # SIGSYS wins over the marker
    assert s._classify(137, forged, False).type == "killed"  # SIGKILL wins over the marker
    assert s._classify(1, forged, False).type == "startup_failed"  # plain non-zero: marker heuristic
    assert s._classify(1, "boom\n", False) is None  # non-zero, no marker: user code, no fault


def test_classify_signal_exit_codes():
    # Every signal-derived exit maps to the right fault (or None for user crashes).
    s = _cfg()
    assert s._classify(143, "", False).type == "timeout"  # SIGTERM = kern backstop reap
    assert s._classify(-15, "", False).type == "timeout"
    assert s._classify(137, "", False).type == "killed"  # SIGKILL = likely OOM
    assert s._classify(-9, "", False).type == "killed"
    assert s._classify(159, "", False).type == "escape_blocked"  # SIGSYS
    assert s._classify(139, "", False) is None  # SIGSEGV = user code crash, not a fault
    assert s._classify(1, "", False) is None  # ordinary non-zero user exit


# ---------------------------------------------------------------------------
# INTEGRATION — the brief's acceptance criteria
# ---------------------------------------------------------------------------


def _kern_runnable() -> bool:
    k = os.environ.get("KERN_BIN") or shutil.which("kern")
    return bool(k) and k != _FAKE_KERN and os.access(k, os.X_OK)


integration = pytest.mark.skipif(not _kern_runnable(), reason="no runnable kern (set KERN_BIN)")


@pytest.fixture(autouse=True)
def _eula():
    os.environ.setdefault("KERN_ACCEPT_EULA", "1")


@integration
def test_c2_file_state_persists_between_steps():
    with Sandbox(timeout_s=30) as s:
        s.run_code("open('/workspace/x.txt','w').write('40')")
        r = s.run_code("print(int(open('/workspace/x.txt').read()) + 2)")
    assert r.stdout.strip() == "42" and r.success


@integration
def test_c3_write_file_then_read_csv():
    with Sandbox(setup="pip install pandas", timeout_s=60) as s:
        s.write_file("data.csv", "a,b\n1,2\n3,4\n")
        r = s.run_code("import pandas as pd; print(pd.read_csv('/workspace/data.csv').shape)")
    assert "(2, 2)" in r.stdout and r.success and r.fault is None


@integration
def test_c4_infinite_loop_times_out():
    with Sandbox(timeout_s=4) as s:
        t = time.monotonic()
        r = s.run_code("while True: pass")
        dt = time.monotonic() - t
    assert r.fault is not None and r.fault.type == "timeout"
    assert not r.success and dt < 16  # our deadline labels it; not the 21s backstop-only path


@integration
def test_c5a_write_outside_workspace_blocked_not_crash():
    with Sandbox(timeout_s=20) as s:
        r = s.run_code("open('/evil','w').write('x')")
    # blocked in fact (read-only root), surfaced as the user's non-zero exit — NOT a sandbox crash,
    # NOT a silent success. (Filesystem denial is indistinguishable from a normal PermissionError, so
    # it is not labelled escape_blocked — that label is reserved for SIGSYS; see c5b.)
    assert not r.success and "Read-only" in r.stderr


@integration
def test_c5b_blocked_syscall_is_escape_blocked():
    with Sandbox(timeout_s=20) as s:
        r = s.run_code("import ctypes; ctypes.CDLL(None).mount(0, 0, 0, 0, 0)")
    assert r.fault is not None and r.fault.type == "escape_blocked"


@integration
def test_result_files_created_then_modified():
    with Sandbox(timeout_s=20) as s:
        r1 = s.run_code("open('/workspace/f.txt','w').write('aaa')")
        r2 = s.run_code("open('/workspace/f.txt','w').write('bbbb')")
    assert any(f.change == "created" for f in r1.files)
    assert any(f.change == "modified" for f in r2.files)


@integration
def test_deps_excluded_from_files_diff():
    # A pip-installed tree lives in .deps and must NOT flood result.files.
    with Sandbox(setup="pip install beautifulsoup4", timeout_s=90) as s:
        r = s.run_code("import bs4; print(bs4.__name__)")
    assert r.success and all(".deps" not in f.path for f in r.files)


@integration
def test_deps_readonly_blocks_cross_run_poisoning():
    # With deps_readonly, run_code cannot write into the setup= deps dir (RO submount).
    with Sandbox(setup="pip install beautifulsoup4", deps_readonly=True, timeout_s=90) as s:
        r = s.run_code("open('/workspace/.deps/poison.py', 'w').write('x')")
    assert not r.success  # write into .deps refused (read-only)


@integration
def test_read_write_are_symlink_and_traversal_safe():
    # SECURITY: host-direct I/O must not follow a symlink the box planted (O_NOFOLLOW) nor a `..`
    # traversal (lexical containment), while normal files and nested subdirs still work.
    with Sandbox(timeout_s=20) as s:
        s.write_file("real.txt", "dati")
        assert s.read_file("real.txt") == b"dati"
        s.write_file("a/b/c.txt", "nested")
        assert s.read_file("a/b/c.txt") == b"nested"
        s.run_code('import os; os.symlink("/etc/passwd", "/workspace/bad")')
        with pytest.raises(SandboxError):
            s.read_file("bad")  # O_NOFOLLOW blocks a symlinked final component
        with pytest.raises(SandboxError):
            s.read_file("../../../etc/passwd")  # lexical `..` containment


@integration
def test_box_cannot_read_host_file_by_absolute_path(tmp_path):
    secret = tmp_path / "host-secret.txt"
    secret.write_text("TOP-SECRET-HOST")
    with Sandbox(timeout_s=20) as s:
        r = s.run_code(f"print(open({str(secret)!r}).read())")
    assert not r.success and "TOP-SECRET" not in r.stdout


@integration
def test_fork_bomb_contained_by_pids_limit():
    with Sandbox(pids=32, timeout_s=20) as s:
        r = s.run_code(
            "import os\nn=0\nwhile n<10000:\n"
            "  try:\n    pid=os.fork()\n    (os._exit(0) if pid==0 else None); n+=1\n"
            "  except OSError:\n    print('blocked', n); break"
        )
    assert "blocked" in r.stdout  # pids.max stopped the fork bomb before the timeout


@integration
def test_large_code_runs_via_file_not_argv():
    # A big generated script must not hit ARG_MAX — run_code routes >128 KiB via a workspace file.
    code = "# " + "padding " * 20000 + "\nprint('big-ok')"  # ~156 KiB, fast to execute
    with Sandbox(timeout_s=20) as s:
        r = s.run_code(code)
    assert r.success and r.stdout.strip() == "big-ok"


@integration
def test_user_exception_is_not_a_fault():
    with Sandbox(timeout_s=20) as s:
        r = s.run_code("raise ValueError('boom')")
    assert r.fault is None and r.exit_code != 0 and "ValueError" in r.stderr


@integration
def test_default_box_is_network_isolated():
    with Sandbox(timeout_s=20) as s:
        r = s.run_code(
            "import socket; socket.setdefaulttimeout(4); "
            "socket.socket().connect(('1.1.1.1', 53)); print('CONNECTED')"
        )
    assert not r.success and "CONNECTED" not in r.stdout


@integration
def test_host_secret_env_does_not_leak(monkeypatch):
    monkeypatch.setenv("HOST_SECRET", "super-secret-token-xyz")
    with Sandbox(timeout_s=20) as s:
        r = s.run_code("import os; print(os.environ.get('HOST_SECRET', 'ABSENT'))")
    assert "super-secret" not in r.stdout and "ABSENT" in r.stdout


@integration
def test_one_shot_run_code_helper():
    r = kern.run_code("print(6 * 7)", timeout_s=20)
    assert r.stdout.strip() == "42" and r.success


@integration
def test_workspace_is_deleted_on_exit_when_owned():
    holder = {}
    with Sandbox(timeout_s=20) as s:
        holder["ws"] = s._ws
        s.write_file("a.txt", "x")
        assert os.path.exists(os.path.join(s._ws, "a.txt"))
    assert not os.path.exists(holder["ws"])  # temp workspace cleaned up
