"""Tests for kern_sandbox (v1 - the middle-way session model).

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
from kern_sandbox import ExecutionResult, Kernel, MountRefused, Result, Sandbox, SandboxError

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


def test_profiles_validated_and_placed_in_argv():
    # valid vcpu:/vgpio:/vdisk: profiles appear as positional tokens before the `--`
    s = _cfg(profiles=["vcpu:heavy", "vgpio:leds", "vdisk:scratch"])
    argv = s._base_argv("n", network=False, timeout_s=s.timeout_s)
    for tok in ("vcpu:heavy", "vgpio:leds", "vdisk:scratch"):
        assert tok in argv, f"{tok} missing from argv"
    # a profile entry can NEVER smuggle another flag, an unknown prefix, or an unsafe name
    for bad in ("--net", "-v /etc:/etc", "vgpu:x", "vcpu:", "vcpu:bad name", "vcpu:a;b",
                "vdisk:../x", "vgpio:a/b", "vcpu:x=y", "vcpu:-lead", "", "profile", "vcpu:heavy\n"):
        with pytest.raises(SandboxError):
            _cfg(profiles=[bad])


def test_egress_allow_validated_and_scoped_to_run_boxes():
    s = _cfg(egress_allow=["pypi.org", "files.pythonhosted.org"])
    run = s._base_argv("n", network=False, timeout_s=s.timeout_s, is_setup=False)
    setup = s._base_argv("n", network=True, timeout_s=s.timeout_s, is_setup=True)
    assert "--egress-allow" in run and "pypi.org,files.pythonhosted.org" in run and "--net" not in run
    # the setup box keeps full network to install deps; the allowlist governs only the untrusted run box
    assert "--egress-allow" not in setup and "--net" in setup
    for bad in ("http://x.com", "x.com/p", "x.com:80", "*.x.com", "a,b.com", "localhost", "", "-x.com",
                "no dom", "pypi.org\n", "pypi.org\r\n"):  # a trailing newline must not slip past
        with pytest.raises(SandboxError):
            _cfg(egress_allow=[bad])
    with pytest.raises(SandboxError):  # egress_allow and network are mutually exclusive
        _cfg(egress_allow=["x.com"], network=True)


def test_snapshot_restore_roundtrip_and_rejects_hostile_archives(tmp_path):
    import io
    import tarfile

    snap = str(tmp_path / "s.tgz")
    with _cfg() as s:  # file ops are host-side; the fake kern is never invoked
        s.write_file("a.txt", "hi")
        s.write_file("sub/b.txt", "deep")
        s.snapshot(snap)
    with _cfg() as s2:
        s2.restore(snap)
        assert s2.read_file("a.txt") == b"hi"
        assert s2.read_file("sub/b.txt") == b"deep"
    # a hostile archive can never write outside the workspace
    def _tar(build) -> str:
        p = str(tmp_path / f"bad{id(build)}.tar")
        with tarfile.open(p, "w") as tf:
            build(tf)
        return p

    abs_tar = _tar(lambda tf: tf.addfile(tarfile.TarInfo("/etc/evil"), io.BytesIO(b"x")))
    esc_tar = _tar(lambda tf: tf.addfile(tarfile.TarInfo("../escape"), io.BytesIO(b"x")))
    link = tarfile.TarInfo("link")
    link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
    link_tar = _tar(lambda tf: tf.addfile(link))
    for bad in (abs_tar, esc_tar, link_tar):
        with _cfg() as s3, pytest.raises(SandboxError):
            s3.restore(bad)


def test_snapshot_is_ustar_not_pax_for_cross_binding_interop(tmp_path):
    # Python's default PAX format writes an 'x' extended header before each member that the strict Node
    # reader rejects; the snapshot must be plain USTAR so a .tar.gz round-trips between both bindings.
    import gzip
    import tarfile

    p = str(tmp_path / "s.tgz")
    with _cfg() as s:
        s.write_file("f.txt", "hi")
        s.snapshot(p)
    with tarfile.open(p) as tf:
        assert all(not m.pax_headers for m in tf.getmembers()), "PAX headers must not leak (breaks Node)"
    raw = gzip.open(p).read()
    assert chr(raw[156]) in ("0", "5"), "first tar record must be a plain ustar file/dir, not a pax 'x' header"


def test_run_code_language_table():
    # node evaluates inline with -e (NOT -c); python/bash use -c. File cells keep the right extension.
    assert Sandbox._LANGS["node"] == ("node", "-e", "js")
    assert Sandbox._LANGS["python"] == ("python3", "-c", "py")
    assert Sandbox._LANGS["bash"] == ("sh", "-c", "sh")


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
    # code), NOT startup_failed (the stderr-marker heuristic) - else a blocked escape hides behind a
    # benign "startup failed" label. Deterministic classes are checked before the stderr marker.
    s = _cfg()
    forged = "error: sandbox: totally not a real kern setup error\n"
    assert s._classify(159, forged, False).type == "escape_blocked"  # SIGSYS wins over the marker
    assert s._classify(137, forged, False).type == "killed"  # SIGKILL wins over the marker
    assert s._classify(1, forged, False).type == "startup_failed"  # plain non-zero: marker heuristic
    assert s._classify(1, "boom\n", False) is None  # non-zero, no marker: user code, no fault


def test_pull_network_failure_is_startup_failed():
    # A box that never started because the PULL failed (network/DNS down) prints kern's
    # "error: curl failed:" prefix. That is a startup failure, not the user's code failing.
    s = _cfg()
    curl = ("-> resolving bad.invalid/x (linux/amd64)\n"
            "error: curl failed: exit Some(28): curl: (28) Resolving timed out after 10000 ms\n")
    assert s._classify(1, curl, False).type == "startup_failed"


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
# INTEGRATION - the brief's acceptance criteria
# ---------------------------------------------------------------------------


def _kern_runnable() -> bool:
    k = os.environ.get("KERN_BIN") or shutil.which("kern")
    return bool(k) and k != _FAKE_KERN and os.access(k, os.X_OK)


integration = pytest.mark.skipif(not _kern_runnable(), reason="no runnable kern (set KERN_BIN)")


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
def test_per_call_timeout_overrides_session():
    # A generous session deadline, but a tight PER-CALL one wins for that call.
    with Sandbox(timeout_s=30) as s:
        t = time.monotonic()
        r = s.run_code("while True: pass", timeout_s=1)
        dt = time.monotonic() - t
    assert r.fault is not None and r.fault.type == "timeout"
    assert "1s" in r.fault.message and dt < 10
    # run() honours the per-call override too.
    with Sandbox(timeout_s=30) as s:
        r = s.run(["sleep", "5"], timeout_s=1)
    assert r.fault is not None and r.fault.type == "timeout"


def test_per_call_timeout_is_validated():
    s = _cfg(timeout_s=30)
    for bad in (0, -1, "x"):
        with pytest.raises(SandboxError):
            s._eff_timeout(bad)
    assert s._eff_timeout(None) == 30 and s._eff_timeout(2) == 2


@integration
def test_per_call_on_stdout_streams():
    chunks = []
    with Sandbox(timeout_s=20) as s:
        r = s.run_code("for i in range(3): print(i)", on_stdout=lambda b: chunks.append(bytes(b)))
    assert b"".join(chunks).split() == [b"0", b"1", b"2"]
    assert r.stdout.split() == ["0", "1", "2"]  # streaming does not disturb the captured stdout


@integration
def test_track_files_off_skips_diff_but_keeps_results():
    # track_files=False skips the O(N) per-call workspace walk: result.files is empty, but rich results
    # (which come from the runner's results file, not the diff) still work.
    with Sandbox(track_files=False, timeout_s=20) as s:
        r = s.run_code("open('/workspace/x.txt','w').write('hi'); 6*7")
    assert r.files == []
    assert r.results and r.results[0].text == "42"
    # the default still tracks the created file
    with Sandbox(timeout_s=20) as s:
        r = s.run_code("open('/workspace/y.txt','w').write('hi')")
    assert any(f.path == "y.txt" for f in r.files)


@integration
def test_read_write_refuse_symlinked_dir_component():
    # SECURITY REGRESSION: a box plants a symlinked DIRECTORY component (`d/esc -> /etc`); host-side
    # read_file/write_file must NOT follow it out of the workspace (else read leaks arbitrary host files).
    # O_NOFOLLOW only guards the FINAL component; the fix descends every component O_NOFOLLOW (openat).
    with Sandbox(track_files=False) as s:
        s.run_code("import os; os.makedirs('/workspace/d', exist_ok=True); os.symlink('/etc', '/workspace/d/esc')")
        with pytest.raises(SandboxError):
            s.read_file("d/esc/hostname")   # would otherwise return the HOST's /etc/hostname
        with pytest.raises(SandboxError):
            s.write_file("d/esc/pwned", b"x")
        with pytest.raises(SandboxError):
            s.list_files("d/esc")          # symlinked subdir must not enumerate a host dir's filenames
        s.write_file("sub/ok.txt", b"hi")   # normal nested I/O still works
        assert s.read_file("sub/ok.txt") == b"hi"
        assert [f.path for f in s.list_files("sub")] == ["sub/ok.txt"]


@integration
def test_c5a_write_outside_workspace_blocked_not_crash():
    with Sandbox(timeout_s=20) as s:
        r = s.run_code("open('/evil','w').write('x')")
    # blocked in fact (read-only root), surfaced as the user's non-zero exit - NOT a sandbox crash,
    # NOT a silent success. (Filesystem denial is indistinguishable from a normal PermissionError, so
    # it is not labelled escape_blocked - that label is reserved for SIGSYS; see c5b.)
    assert not r.success and "Read-only" in r.stderr


@integration
def test_c5b_blocked_syscall_is_escape_blocked():
    with Sandbox(timeout_s=20) as s:
        r = s.run_code("import ctypes; ctypes.CDLL(None).mount(0, 0, 0, 0, 0)")
    assert r.fault is not None and r.fault.type == "escape_blocked"


# -- P1: rich mime-typed results (Jupyter/E2B-style), non-network ------------------------------------


@integration
def test_p1_trailing_expression_is_a_result():
    with Sandbox(timeout_s=30) as s:
        r = s.run_code("a = 20\nb = 22\na + b")
    assert r.success and r.results and isinstance(r.results[0], Result)
    assert r.results[0].text == "42"


@integration
def test_p1_statement_produces_no_result_and_stdout_intact():
    with Sandbox(timeout_s=30) as s:
        r = s.run_code("print('hello')")
    assert r.stdout.strip() == "hello" and r.results == []  # print returns None -> no spurious result


@integration
def test_p1_display_and_rich_repr():
    with Sandbox(timeout_s=30) as s:
        r = s.run_code("display(1); display(2); print('done')")
        rh = s.run_code("class H:\n    def _repr_html_(self): return '<b>hi</b>'\nH()")
    assert len(r.results) == 2 and r.results[0].text == "1" and r.stdout.strip() == "done"
    assert rh.results and rh.results[0].html == "<b>hi</b>" and rh.results[0].text  # html + plain both


@integration
def test_p1_capture_never_alters_exit_or_traceback():
    with Sandbox(timeout_s=30) as s:
        rc = s.run_code("import sys; sys.exit(3)")
        rx = s.run_code("def boom():\n    raise ValueError('kaboom')\nboom()")
    assert rc.exit_code == 3  # exit code preserved through the runner
    assert not rx.success and rx.fault is None and "ValueError: kaboom" in rx.stderr
    assert "_PY_RUNNER" not in rx.stderr and "traceback.format_exception" not in rx.stderr  # user frames only


@integration
def test_p1_internal_files_hidden_and_cleaned():
    with Sandbox(timeout_s=30) as s:
        r = s.run_code("open('user.txt', 'w').write('hi')\n'done'")
        left = [n for n in os.listdir(s._ws) if n.startswith((".cell-", ".run-", ".res-"))]
    names = [fi.path for fi in r.files]
    assert "user.txt" in names and not any(n.startswith((".cell-", ".run-", ".res-")) for n in names)
    assert left == [] and r.results[0].text == "'done'"


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
    # A big generated script must not hit ARG_MAX - run_code routes >128 KiB via a workspace file.
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


@integration
def test_planted_env_symlink_cannot_clobber_host_file(tmp_path):
    # A box has rw access to the workspace and could replace our private `.kern-env` with a symlink to
    # a host file; without O_NOFOLLOW the next call would follow it and O_TRUNC-clobber that file.
    victim = tmp_path / "precious.txt"
    victim.write_text("PRECIOUS")
    with Sandbox(timeout_s=20, env={"X": "1"}) as s:
        s.run_code(
            "import os\n"
            "p = '/workspace/.kern-env'\n"
            "os.path.lexists(p) and os.remove(p)\n"
            f"os.symlink({str(victim)!r}, p)"
        )
        s.run_code("print('ok')")  # writes .kern-env again; must not follow the symlink
    assert victim.read_text() == "PRECIOUS"  # untouched


@integration
def test_write_file_refuses_intermediate_symlink(tmp_path):
    # A box plants an intermediate directory symlink; write_file must not traverse it (mkdir -p would).
    outside = tmp_path / "outside"
    outside.mkdir()
    with Sandbox(timeout_s=20) as s:
        s.run_code(f"import os; os.symlink({str(outside)!r}, '/workspace/evil')")
        with pytest.raises(SandboxError):
            s.write_file("evil/pwned.txt", "x")
    assert not (outside / "pwned.txt").exists()


@integration
def test_p1_read_file_max_bytes_caps_the_read():
    # P1 reads the box-written results file back; max_bytes bounds an untrusted box from OOMing the host.
    with Sandbox(timeout_s=30) as s:
        s.run_code("open('big.bin', 'wb').write(b'x' * 200_000)")
        with pytest.raises(SandboxError):
            s.read_file("big.bin", max_bytes=1000)
        assert len(s.read_file("big.bin", max_bytes=500_000)) == 200_000


# -- warm kernel (persistent interpreter, warm-start) --------------------------------------------


@integration
def test_kernel_state_persists_and_captures_results():
    # A kernel is ONE warm interpreter: in-memory state persists across cells (unlike run_code), and a
    # trailing expression is still captured into rich results.
    with Sandbox(timeout_s=30) as s:
        with s.kernel() as k:
            assert isinstance(k, Kernel)
            r = k.run_code("x = 40")
            assert r.success and r.results == []
            r = k.run_code("y = x + 2\nprint('y =', y)")
            assert r.stdout.strip() == "y = 42" and r.success  # x survived from the previous cell
            r = k.run_code("x * 100")  # trailing bare expression -> a rich result
            assert r.results and r.results[0].text == "4000"


@integration
def test_kernel_survives_a_cell_error():
    # An uncaught error in a cell is confined: rc=1, the user traceback is on stderr, and the kernel
    # keeps serving with its state intact.
    with Sandbox(timeout_s=30) as s:
        with s.kernel() as k:
            k.run_code("z = 7")
            r = k.run_code("1 / 0")
            assert r.exit_code == 1 and not r.success and "ZeroDivisionError" in r.stderr
            assert r.fault is None  # a user error is NOT a sandbox fault
            r = k.run_code("z")  # kernel is alive, z is still here
            assert r.results and r.results[0].text == "7"


@integration
def test_kernel_timeout_tears_down_and_guards():
    # A per-cell timeout kills the kernel (a running cell cannot be interrupted); afterwards the kernel
    # is dead and refuses further cells with a clear error.
    with Sandbox(timeout_s=30) as s:
        with s.kernel(timeout_s=2) as k:
            assert k.run_code("print('alive')").stdout.strip() == "alive"
            t = time.monotonic()
            r = k.run_code("while True: pass")
            assert r.fault is not None and r.fault.type == "timeout" and not r.success
            assert time.monotonic() - t < 8
            with pytest.raises(SandboxError):
                k.run_code("1 + 1")


@integration
def test_kernel_stdin_is_eof_not_the_control_channel():
    # A cell that reads stdin must get EOF, NOT the next control frame (which would deadlock the kernel
    # and desync the protocol). The kernel must stay aligned for the following cell.
    with Sandbox(timeout_s=6) as s:
        with s.kernel() as k:
            r = k.run_code("import sys; print('in=' + repr(sys.stdin.readline()))")
            assert r.stdout.strip() == "in=''" and r.success
            assert k.run_code("print(2 + 2)").stdout.strip() == "4"  # protocol still aligned


@integration
def test_kernel_raw_fd_writes_are_captured_not_corrupting():
    # A cell writing RAW to fd 1 (bypassing sys.stdout) or via a subprocess must NOT corrupt the control
    # channel (control lives on private fds); the raw output is captured, and the kernel stays aligned.
    with Sandbox(timeout_s=10) as s:
        with s.kernel() as k:
            r = k.run_code("import os; os.write(1, b'RAW\\n'); print('P')")
            assert r.success and "RAW" in r.stdout and "P" in r.stdout  # both captured, no fault
            assert k.run_code("print(6 * 7)").stdout.strip() == "42"  # protocol still aligned
            r = k.run_code("import subprocess; subprocess.run(['printf', 'sub'])")
            assert "sub" in r.stdout and r.success  # subprocess stdout captured
            r = k.run_code("import sys; print('in=' + repr(sys.stdin.read()))")
            assert r.stdout.strip() == "in=''"  # a subprocess/read of stdin gets EOF, never a cell frame


@integration
def test_kernel_survives_raw_fork_and_multiprocessing():
    # A cell that raw os.fork()s (or uses multiprocessing) must not spawn rogue driver clones that corrupt
    # the control channel: the forked child exits instead of re-entering the loop. The kernel stays aligned.
    with Sandbox(memory_mb=512, pids=128, timeout_s=15) as s:
        with s.kernel() as k:
            r = k.run_code(
                "import os\n"
                "for _ in range(15):\n"
                "    pid = os.fork()\n"
                "    if pid == 0: os._exit(0)\n"
                "    os.waitpid(pid, 0)\n"
                "print('forked-clean')"
            )
            assert r.stdout.strip() == "forked-clean" and r.success
            assert k.run_code("print(7 * 7)").stdout.strip() == "49"  # protocol aligned after forks
            r = k.run_code(
                "from concurrent.futures import ProcessPoolExecutor as P\n"
                "with P(2) as e: print('mp', sum(e.map(abs, [-1, -2, -3])))"
            )
            assert "mp 6" in r.stdout and r.success  # multiprocessing works in the kernel
            assert k.run_code("print('alive')").stdout.strip() == "alive"


@integration
def test_kernel_oversize_reply_is_capped_not_host_oom():
    # The box controls the reply length; a reply past max_output_bytes must be refused (host-OOM guard),
    # tearing the kernel down with a clear fault rather than buffering gigabytes into host RAM.
    with Sandbox(timeout_s=20, max_output_bytes=4 * 1024 * 1024) as s:
        with s.kernel() as k:
            r = k.run_code("print('A' * 20_000_000)")  # 20 MB reply vs a 4 MB cap
            assert r.fault is not None and r.fault.type == "killed" and "cap" in r.fault.message
            with pytest.raises(SandboxError):
                k.run_code("1 + 1")  # torn down


@integration
def test_kernel_is_warm_far_faster_than_a_cold_cell():
    # The whole point: a warm cell skips the ~10 ms CPython boot. Assert it is at least 10x faster than
    # a cold one-shot run_code on the same session (generous bound; real gap is ~400x).
    with Sandbox(timeout_s=30) as s:
        t = time.monotonic()
        s.run_code("1 + 1")  # cold: a fresh interpreter boot
        cold = time.monotonic() - t
        with s.kernel() as k:
            k.run_code("1 + 1")  # warm up the pipe
            t = time.monotonic()
            for _ in range(20):
                k.run_code("sum(range(1000))")
            warm = (time.monotonic() - t) / 20
    assert warm < cold / 10
