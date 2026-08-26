"""Tests for kern_sandbox (v1 - the middle-way session model).

  * UNIT tests (always run): fail-closed defaults, mount/workspace guards, taxonomy plumbing. No kern.
  * INTEGRATION tests (skipped unless a runnable `kern` is present): the brief's acceptance criteria
    against real ephemeral boxes on a persistent workspace.

Run: `pytest`  (integration auto-skips without a real kern; set `KERN_BIN=/path/to/kern`).
"""

import errno
import re
import signal
from pathlib import Path
import os
import shutil
import subprocess
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


def test_capabilities_are_dropped_by_default_and_the_opt_out_is_explicit():
    """The default box drops every capability, and only an explicit `cap_drop=()` keeps them.

    kern always drops 14 dangerous capabilities; the rest were held over the box's own user
    namespace, on the one code path whose whole purpose is running code nobody has read, while the
    README told a CLI user to write `--cap-drop ALL` for exactly that case. Measured before the
    change: a box held CapEff 00000110bdacffff, and with the flag it holds 0000000000000000.
    """
    argv = _cfg()._base_argv("n", network=False, timeout_s=30)
    assert "--cap-drop" in argv, "the default must drop capabilities"
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    # The flag must land BEFORE the `--` that ends kern's own arguments, or kern would read it as
    # part of the workload command. There is no `--` in _base_argv itself, so assert the shape that
    # matters: it sits among the flags, after the image, and nothing follows it into the command.
    assert argv.index("--cap-drop") > argv.index("--image")

    # The opt-out exists because the change is not behaviour-free: a workload binding a port below
    # 1024 inside the box needs CAP_NET_BIND_SERVICE. It has to be asked for by name.
    assert "--cap-drop" not in _cfg(cap_drop=())._base_argv("n", network=False, timeout_s=30)

    # A narrower set is passed through one flag per name, in order.
    narrow = _cfg(cap_drop=("SYS_ADMIN", "CAP_NET_RAW"))._base_argv("n", network=False, timeout_s=30)
    assert narrow.count("--cap-drop") == 2
    assert narrow[narrow.index("--cap-drop") + 1] == "SYS_ADMIN"

    # The setup box is hardened the same way: it installs dependencies, from the network, which is
    # precisely when a hostile package would run its own code.
    setup = _cfg()._base_argv("n", network=True, timeout_s=30, is_setup=True)
    assert "--cap-drop" in setup


def test_both_bindings_validate_a_capability_name_identically():
    """The Python and Node bindings guard the same argv boundary with the same rule.

    Two copies of one rule is this project's `derived-condition-duplicated` shape: if one binding
    tightened or loosened its pattern, the same string would be accepted by one SDK and refused by
    the other, and nothing would say so. The regexes are compared literally rather than by behaviour
    because a behavioural comparison would need a JS engine, and a literal difference is the thing
    that goes wrong first.

    Skips when the Node source is absent, which is the case in a published wheel.
    """
    node = Path(__file__).resolve().parents[3] / "bindings" / "node" / "index.js"
    if not node.is_file():
        pytest.skip(f"no Node source at {node} (published wheel)")
    src = node.read_text(encoding="utf-8")
    m = re.search(r"const CAP_RE = /(.+)/;", src)
    assert m, "bindings/node/index.js no longer defines CAP_RE"
    from kern_sandbox import _CAP_RE

    assert m.group(1) == _CAP_RE.pattern, (
        f"the two bindings disagree on what a capability name is:\n"
        f"  node:   {m.group(1)}\n"
        f"  python: {_CAP_RE.pattern}"
    )


def test_a_capability_name_can_never_smuggle_another_flag():
    """`cap_drop` reaches kern's argv, so it is validated like a profile token rather than trusted."""
    for bad in ("--net", "-v /etc:/etc", "net_admin", "NET ADMIN", "NET;rm", "NET\n", "",
                "CAP_", "1NET", "A" * 40, "--cap-add", "NET_", "_NET", "NET__RAW", "ALL "):
        with pytest.raises(SandboxError):
            _cfg(cap_drop=(bad,))
    # And the names that MUST work, or the opt-out is useless: the bare form, the CAP_ form, and a
    # multi-segment name. A validator that only ever says no is not one anybody can use.
    for good in ("ALL", "SYS_ADMIN", "CAP_NET_BIND_SERVICE", "DAC_OVERRIDE", "MKNOD"):
        assert _cfg(cap_drop=(good,))._cap_drop_args == ["--cap-drop", good]
    # A bare string is a Sequence[str] and would iterate into single characters, producing three
    # bogus flags from "ALL". Refused by name, with the spelling that works.
    with pytest.raises(SandboxError):
        _cfg(cap_drop="ALL")


def test_apparmor_profile_reaches_the_argv_and_bad_names_are_refused():
    """`apparmor=` emits `--apparmor <profile>` (right after `--security-profile`), `None` emits nothing,
    and a name that could turn into another flag is refused AT CONSTRUCTION. Whether the profile is
    actually loaded is kern's fail-closed problem at box start, not the binding's."""
    argv = _cfg(apparmor="docker-default")._base_argv("n", network=False, timeout_s=30)
    assert "--apparmor" in argv
    assert argv[argv.index("--apparmor") + 1] == "docker-default"
    assert argv.index("--apparmor") > argv.index("--image")
    # The default (None) adds no flag - the box keeps kern's normal posture.
    assert "--apparmor" not in _cfg()._base_argv("n", network=False, timeout_s=30)
    # Names that MUST work, or the flag is useless: plain profiles and the special `unconfined`.
    from kern_sandbox import _validate_apparmor

    for good in ("unconfined", "kern-box", "docker-default", "lxc-container-default"):
        assert _validate_apparmor(good) == good
    # Names that could smuggle a flag, carry a space/newline, be namespaced (`/`), empty, or too long.
    for bad in ("-net", "--privileged", "a b", "prof;rm", "prof\n", "", "a/b", "ns:prof", "x" * 200):
        with pytest.raises(SandboxError):
            _cfg(apparmor=bad)


def test_both_bindings_validate_an_apparmor_name_identically():
    """Python and Node guard the `--apparmor` argv boundary with the SAME rule, compared literally (see
    the capability-name parity test for why). Skips when the Node source is absent (a published wheel)."""
    node = Path(__file__).resolve().parents[3] / "bindings" / "node" / "index.js"
    if not node.is_file():
        pytest.skip(f"no Node source at {node} (published wheel)")
    src = node.read_text(encoding="utf-8")
    m = re.search(r"const APPARMOR_RE = /(.+)/;", src)
    assert m, "bindings/node/index.js no longer defines APPARMOR_RE"
    from kern_sandbox import _APPARMOR_RE

    assert m.group(1) == _APPARMOR_RE.pattern, (
        f"the two bindings disagree on what an AppArmor profile name is:\n"
        f"  node:   {m.group(1)}\n"
        f"  python: {_APPARMOR_RE.pattern}"
    )


def test_both_bindings_agree_on_every_apparmor_input_behaviourally():
    """Beyond the literal regex comparison: run a SHARED vector of inputs through BOTH bindings'
    construction-time validation and assert they AGREE on accept/reject for each. This catches a
    divergence the literal test cannot - e.g. one binding adding a `.strip()`/`.lower()` before it
    validates, while the two regexes stay byte-identical. Skips when `node` or the Node source is
    unavailable (a published wheel / no runtime)."""
    import json
    import shutil
    import subprocess

    node_bin = shutil.which("node")
    node_src = Path(__file__).resolve().parents[3] / "bindings" / "node" / "index.js"
    if node_bin is None or not node_src.is_file():
        pytest.skip("node runtime or Node source unavailable")

    vectors = [
        "kern-box", "unconfined", "docker-default", "lxc-container-default", "a.b_c-1", "A", "x" * 128,
        "", " x", "x ", "x\n", "\tx", "-x", "--privileged", "a b", "a/b", "ns:profile", "a;b", "a|b",
        "x" * 129, "café", ".", "..",
    ]

    def py_ok(v: str) -> bool:
        # Via the Python Sandbox CONSTRUCTOR (validates in __post_init__), symmetric with Node below.
        try:
            _cfg(apparmor=v)
            return True
        except SandboxError:
            return False

    # Node: validate each input via the SAME path the SDK uses - the Sandbox constructor calls
    # validateApparmor. KERN_BIN=/bin/true lets construction complete for an ACCEPTED value.
    script = (
        f"const {{Sandbox}} = require({json.dumps(str(node_src))});\n"
        "process.env.KERN_BIN = '/bin/true';\n"
        f"const V = {json.dumps(vectors)};\n"
        "console.log(JSON.stringify(V.map(function (v) {"
        " try { new Sandbox({ apparmor: v }); return true; } catch (e) { return false; } })));\n"
    )
    res = subprocess.run([node_bin, "-e", script], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, f"node validation harness failed: {res.stderr}"
    node_ok = json.loads(res.stdout.strip())
    assert len(node_ok) == len(vectors)
    for v, n in zip(vectors, node_ok):
        assert py_ok(v) == n, (
            f"the bindings DISAGREE on {v!r}: python accepts={py_ok(v)}, node accepts={n} "
            "(a normalization difference the literal regex comparison cannot catch)"
        )


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
    assert s._classify(137, forged, False).type == "oom"  # SIGKILL wins over the marker (capped box: OOM)
    assert s._classify(1, forged, False).type == "startup_failed"  # plain non-zero: marker heuristic
    assert s._classify(1, "boom\n", False) is None  # non-zero, no marker: user code, no fault


def test_classify_sigkill_is_oom_only_when_a_memory_cap_was_set():
    # A SIGKILL (137 or -9) of a MEMORY-CAPPED box is the cgroup OOM-killer: kern sets
    # memory.oom.group=1, so a breached memory.max takes the WHOLE box. The signal is the `--memory`
    # flag WE set (self.memory_mb), never the workload's stderr, so it keeps the same
    # order-is-a-security-property discipline as the classes above. Uncapped, the cause is ambiguous
    # (host memory pressure, an external kill) and stays `killed`.
    capped = _cfg(memory_mb=256)
    assert capped._classify(137, "", False).type == "oom"
    assert capped._classify(-signal.SIGKILL, "", False).type == "oom"
    # A forged stderr marker cannot flip the exit-code verdict either way.
    assert capped._classify(137, "error: sandbox: forged\n", False).type == "oom"
    uncapped = _cfg(memory_mb=None)
    assert uncapped._classify(137, "", False).type == "killed"
    assert uncapped._classify(-signal.SIGKILL, "", False).type == "killed"
    # PRECEDENCE (locks the check ORDER): even with a cap set, the more specific deterministic classes
    # win over oom. OUR deadline (we_timed_out) is a known kill -> timeout, never oom. A SIGSYS is a
    # blocked escape -> escape_blocked, never oom. A backstop SIGTERM is still a timeout.
    assert capped._classify(137, "", True).type == "timeout"  # our deadline beats oom
    assert capped._classify(159, "", False).type == "escape_blocked"  # SIGSYS beats oom
    assert capped._classify(143, "", False).type == "timeout"  # kern's --timeout backstop, not oom
    # cap_signal (kern's UNFORGEABLE enforcement byte) refines the SIGKILL verdict: 1 = enforced -> a
    # certain cgroup OOM; 2 = requested-but-not-enforced -> not attributable to the box's cgroup, so we
    # do NOT overclaim oom (honest `killed`); 0 = undetermined (older kern) -> the memory_mb heuristic.
    assert capped._classify(137, "", False, cap_signal=1).type == "oom"  # enforced: certain OOM
    assert capped._classify(137, "", False, cap_signal=2).type == "killed"  # not enforced: no overclaim
    assert capped._classify(137, "", False, cap_signal=0).type == "oom"  # undetermined: heuristic stands
    assert capped._classify(-signal.SIGKILL, "", False, cap_signal=2).type == "killed"


def test_exit_125_startup_failure_requires_the_kern_marker_not_a_bare_125():
    # kern's box-not-started paths exit 125 (Docker's convention) AND print a `kern:` marker. The marker
    # is REQUIRED: a workload that ITSELF exits 125 (the code ran and chose 125) has no kern marker and
    # must stay a NORMAL result - else the SDK would raise "box failed to start" on the user's own exit
    # code. This is the false-positive the raise-on-125 must not have.
    s = _cfg()
    marker = "kern: sandbox setup failed: --apparmor demo: could not enter the profile\n"
    assert s._classify(125, marker, False).type == "startup_failed"  # 125 + kern marker = box not started
    assert s._classify(125, "", False) is None  # bare 125 = the WORKLOAD's own exit, a normal result
    assert s._classify(125, "my app exited 125\n", False) is None  # no marker = the workload's own exit
    assert s._classify(159, marker, False).type == "escape_blocked"  # SIGSYS decided first, marker ignored
    # A non-125 exit with a marker still classifies startup_failed, but `_spawn` raises ONLY on rc==125,
    # so a 127-class (older kern) or a forged-marker exit is returned as DATA, never raised.
    assert s._classify(3, marker, False).type == "startup_failed"


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
    assert s._classify(137, "", False).type == "oom"  # SIGKILL + default memory cap = cgroup OOM
    assert s._classify(-9, "", False).type == "oom"
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


def test_a_reply_without_a_usable_exit_code_is_a_fault_not_a_success():
    """The kernel reply is JSON written INSIDE the box, by the code the sandbox exists to contain.

    `rc` was read as `int(obj.get("rc", 0))`, so a missing field or a wrong type became exit code 0 -
    and `success` is `exit_code == 0 and fault is None`. A cell could therefore report its own failed
    run as successful by omitting one key. Every shape below is what an untrusted payload can send.
    """
    k = Kernel(_cfg(), timeout_s=5)
    started = time.monotonic()

    for reply in (
        b'{"stdout":"","stderr":"","results":[]}',        # no rc at all
        b'{"rc":"0","stdout":"","stderr":""}',            # rc as a string
        b'{"rc":null,"stdout":"","stderr":""}',           # rc explicitly null
        b'{"rc":0.0,"stdout":"","stderr":""}',            # rc as a float
        b'{"rc":true,"stdout":"","stderr":""}',           # rc as a bool (an int subclass in Python)
        b'{"rc":[0],"stdout":"","stderr":""}',            # rc as a list
    ):
        r = k._result_from_reply(reply, started)
        assert not r.success, f"{reply!r} must not be reported as a successful run"
        assert r.fault is not None, f"{reply!r} must carry a fault explaining why"
        assert r.exit_code != 0, f"{reply!r} must not present exit code 0"

    # Positive control: a well-formed reply still produces an ordinary successful result, or the
    # assertions above would pass on a binding that rejects everything.
    ok = k._result_from_reply(b'{"rc":0,"stdout":"hi","stderr":"","results":[]}', started)
    assert ok.success and ok.exit_code == 0 and ok.stdout == "hi"
    # And a genuine non-zero exit is preserved rather than coerced.
    bad = k._result_from_reply(b'{"rc":3,"stdout":"","stderr":"boom"}', started)
    assert not bad.success and bad.exit_code == 3 and bad.fault is None


def test_kernel_death_is_oom_only_when_a_memory_cap_was_set():
    # A resident kernel that dies mid-cell (an OOM-killed cell, a crash) does NOT flow through
    # `_classify` - it has no per-cell exit code - so its OOM attribution lives in `_kernel_death_fault`,
    # the run_code counterpart of the one-shot SIGKILL branch. Capped -> oom (the cgroup OOM-killer took
    # the kernel), uncapped -> killed (ambiguous), a kern setup marker on stderr -> startup_failed. The
    # signal is the --memory flag WE set, not the box's (workload-influenceable) stderr.
    capped = Kernel(_cfg(memory_mb=256), timeout_s=5)
    assert capped._kernel_death_fault("")[0] == "oom"
    assert capped._kernel_death_fault("some traceback\n")[0] == "oom"  # workload stderr does not flip it
    marker = "kern: sandbox setup failed: --apparmor demo: could not enter the profile\n"
    assert capped._kernel_death_fault(marker)[0] == "startup_failed"  # a box that never really started
    uncapped = Kernel(_cfg(memory_mb=None), timeout_s=5)
    assert uncapped._kernel_death_fault("")[0] == "killed"
    # cap_signal (kern's unforgeable enforcement byte) refines it, same as the one-shot path: enforced
    # (1) -> oom, requested-but-not-enforced (2) -> killed (no overclaim), undetermined (0) -> heuristic.
    assert capped._kernel_death_fault("", cap_signal=1)[0] == "oom"
    assert capped._kernel_death_fault("", cap_signal=2)[0] == "killed"
    assert capped._kernel_death_fault("", cap_signal=0)[0] == "oom"
    # A startup marker still wins over the enforcement byte (the box never came up).
    assert capped._kernel_death_fault(marker, cap_signal=2)[0] == "startup_failed"


@integration
def test_concurrent_calls_on_one_sandbox_do_not_fight_over_the_env_file():
    """Two calls on the SAME Sandbox must not race for one host-side `--env-file` path.

    The env file used to be a single fixed `.kern-env` in the workspace. Every call unlinked it and
    re-created it with `O_EXCL|O_NOFOLLOW` (a deliberate refusal to write through a symlink the box
    may have planted), so two concurrent calls fought over one path: the loser got a bare
    `FileExistsError` straight out of `run_code`. Measured at 40 threads before the fix: 11 of 40
    failed that way, and the README advertises 100 concurrent calls.

    The security property is unchanged; only the NAME is per-call. Asserted on the failure mode that
    was observed (an exception escaping the call), with the leftover-file check beside it, because the
    old code also never removed the file: a persistent `workspace=` accumulated one per session.
    """
    import concurrent.futures as cf

    n = 24
    errors: list[str] = []

    with Sandbox(env={"KERN_TEST_VAR": "x"}) as sbx:
        def call(_):
            try:
                return sbx.run(["true"]).success
            except Exception as e:  # noqa: BLE001 - the defect surfaced as a raw OSError
                errors.append(f"{type(e).__name__}: {e}")
                return False

        with cf.ThreadPoolExecutor(max_workers=n) as ex:
            ok = sum(1 for r in ex.map(call, range(n)) if r)

        leftover = [f for f in os.listdir(sbx._ws) if f.startswith(".kern-env")]

    assert not errors, f"concurrent calls raised: {errors[:3]}"
    assert ok == n, f"only {ok}/{n} concurrent calls succeeded"
    assert not leftover, f"env files left in the workspace: {leftover}"


def test_a_file_is_hidden_from_listings_only_if_this_binding_created_it():
    """Ours by PROVENANCE, not by the shape of the name.

    The filter used to be prefix-based (`.kern-env.<box>`, and later `.cell-<uid>.<ext>` and friends),
    which published the recipe for invisibility: the workspace is writable by the box, so anything that
    wrote a matching name disappeared from `list_files`/`snapshot`/`files`, which is the listing a
    caller would audit. Membership in a set this process filled cannot be imitated from inside a box.

    `.kern-env` bare stays an exact legacy match: a workspace written by an older version has one and
    it is ours, even though this process did not create it.
    """
    s = _cfg()
    assert not s._is_ours(".cell-deadbeef.py"), "a name we never wrote is not ours"
    assert not s._is_ours(".kern-env.box-abc123"), "the prefix hole is what got closed"
    assert s._claim(".cell-deadbeef.py") == ".cell-deadbeef.py", "claim returns the name it took"
    assert s._is_ours(".cell-deadbeef.py"), "claimed, so ours"
    s._release(".cell-deadbeef.py")
    assert not s._is_ours(".cell-deadbeef.py"), "released, so theirs again"
    assert s._is_ours(".kern-env"), "legacy exact name from an older version"
    assert not s._is_ours(".kern-environment") and not s._is_ours("notes.txt")


def test_the_version_in_the_code_matches_the_one_in_pyproject():
    """`__version__` and the packaging metadata are the same number written twice.

    They drifted once already: the release that publishes to PyPI reads `pyproject.toml`, while
    anything importing the module reads `__version__`, so a bumped manifest and a stale constant ship
    a package whose own `kern_sandbox.__version__` reports the PREVIOUS release. Four places carry
    this version (two manifests, two sources); this test pins the Python pair, and its Node twin pins
    the other.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    try:
        import tomllib

        declared = tomllib.loads(text)["project"]["version"]
    except ModuleNotFoundError:
        # `tomllib` is stdlib from 3.11, and this package's floor is 3.9: on the interpreter that
        # PROVES the floor, importing it is a ModuleNotFoundError and this test would fail for a
        # reason that has nothing to do with the versions agreeing. One regex over one known line
        # keeps the check running everywhere rather than skipping it exactly where it is cheapest
        # to run. (Found by running the suite under a real 3.9, not by reading the imports.)
        m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        assert m, "pyproject.toml no longer has a top-level `version = \"...\"`"
        declared = m.group(1)
    assert kern.__version__ == declared, (
        f"kern_sandbox.__version__ is {kern.__version__} but pyproject.toml says {declared}"
    )


# ---------------------------------------------------------------------------
# UNIT: the process wait
#
# These need no kern: `_wait_for_exit` is a primitive over a plain Popen, so they run everywhere,
# including the CI hosts where the box tests skip. They assert the MECHANISM rather than a duration,
# so a loaded machine cannot make them flap.
# ---------------------------------------------------------------------------


def _sleeper(seconds: str) -> subprocess.Popen:
    """A child of our own, with no kern in the picture: the wait primitive is what is under test."""
    return subprocess.Popen(
        ["sleep", seconds], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


@pytest.mark.skipif(not hasattr(os, "pidfd_open"), reason="no os.pidfd_open on this interpreter")
def test_the_wait_blocks_on_a_pidfd_instead_of_polling_for_the_exit():
    """The whole point of the helper.

    `Popen.wait(timeout=...)` does not block on the child: it polls on an exponential backoff whose
    wake-ups land at 0.5, 1.5, 3.5, 7.5, 15.5, 31.5 ms, so a box that exits at 12.3 ms is not noticed
    until 15.5. Measured over 200 identical calls, that cost 3.9 ms on the floor of every call and
    pushed 32 of them into a 31 ms or 64 ms bucket they had no reason to be in.

    A timed wait is therefore simply not allowed to happen while a pidfd is available, and that is
    what this asserts: no clock, no threshold, nothing to go flaky.
    """
    proc = _sleeper("0.05")
    real_wait = proc.wait
    calls: list = []

    def spy(timeout=None):
        calls.append(timeout)
        return real_wait(timeout=timeout)

    proc.wait = spy
    try:
        assert kern._wait_for_exit(proc, 5) is True
    finally:
        proc.wait = real_wait
        if proc.returncode is None:
            proc.kill()
            proc.wait()
    assert proc.returncode == 0, "the child must be reaped, not left a zombie"
    assert calls == [None], f"a TIMED wait means we went back to polling the child: {calls}"


def test_the_wait_falls_back_to_polling_when_pidfd_is_refused(monkeypatch):
    """An old kernel, or a syscall filter in whatever sandbox the CALLER is itself running under, and
    the helper degrades instead of failing. ENOSYS is what a filter returns. Slower, never wrong."""

    def refused(pid, flags=0):
        raise OSError(errno.ENOSYS, "Function not implemented")

    monkeypatch.setattr(os, "pidfd_open", refused, raising=False)
    proc = _sleeper("0.05")
    try:
        assert kern._wait_for_exit(proc, 5) is True
        assert proc.returncode == 0
    finally:
        if proc.returncode is None:
            proc.kill()
            proc.wait()


def test_the_wait_reports_a_deadline_it_could_not_meet_and_leaves_the_child_alone():
    """False means 'still running'. The caller owns the teardown, and it must find the child exactly
    where it left it: this helper never kills and never reaps a live process. That ordering is also
    what keeps the pid from being recycled under the teardown that follows."""
    proc = _sleeper("30")
    try:
        assert kern._wait_for_exit(proc, 0.05) is False
        assert proc.poll() is None, "the helper must not have reaped or killed a running child"
    finally:
        proc.kill()
        proc.wait()


def test_the_wait_short_circuits_on_a_child_that_was_already_reaped():
    """Guards a real hazard rather than a style point: calling pidfd_open on an already-reaped pid is
    at best ESRCH and at worst a handle on whatever process inherited that number."""
    proc = _sleeper("0")
    proc.wait()
    assert proc.returncode is not None
    assert kern._wait_for_exit(proc, 0) is True


# ---------------------------------------------------------------------------
# Our own scratch in a shared workspace
# ---------------------------------------------------------------------------


@integration
def test_a_box_cannot_hide_a_file_by_naming_it_like_our_scratch():
    """The listing a caller audits must not be something the audited party can edit.

    Our scratch was once hidden by the SHAPE of its name (`.cell-<8 hex>.<ext>`, `.kern-env.<box>`),
    and the workspace is writable by the box, so the rule published its own bypass: a cell that wrote
    `/workspace/.cell-deadbeef.py` vanished from `list_files`, `snapshot` and `files`. Provenance is
    not imitable from inside a box, and this is the discriminating test: names in exactly the retired
    shapes, written BY THE BOX, must all still be visible to the caller.
    """
    planted = [".cell-deadbeef.py", ".run-00000000.py", ".res-a1b2c3d4.json",
               ".kernel-01234567.py", ".kern-env.pysbx-forged"]
    with Sandbox(timeout_s=60) as s:
        code = "\n".join(f"open({name!r}, 'w').write('planted')" for name in planted)
        assert s.run_code(code).success
        listed = {f.path for f in s.list_files()}
    assert set(planted) <= listed, f"a box hid files from the caller: {sorted(set(planted) - listed)}"


@integration
def test_a_concurrent_call_does_not_see_the_other_call_s_scratch():
    """Two calls on the SAME Sandbox share one workspace by design (that is what makes file state
    persist). Each used to filter only the three names IT had written, so a call's file diff reported
    the other call's in-flight cell and runner to the caller as freshly created user files."""
    import concurrent.futures as cf

    with Sandbox(timeout_s=60) as s:
        with cf.ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda i: s.run_code(f"print({i} * {i})"), range(8)))
    assert [r.stdout.strip() for r in results] == [str(i * i) for i in range(8)]
    leaked = sorted({f.path for r in results for f in r.files})
    assert leaked == [], f"internal scratch reported as user files: {leaked}"


@integration
def test_the_provenance_registry_balances_under_parallel_calls():
    """`_claim`/`_release` share one set across every call on a Sandbox, and the LangChain tool is
    exactly the thing an agent runs several of at once. The observable invariant is that the registry
    BALANCES: every name claimed is released, so after the last call it is empty again. A leak leaves
    names behind, and a name that stays claimed forever hides a real user file from that point on, which
    is the quiet failure a per-call assertion would never see.

    Sixteen against eight in the other test, because a race that survives eight threads is not a race
    that has been ruled out.
    """
    import concurrent.futures as cf

    with Sandbox(timeout_s=60) as s:
        with cf.ThreadPoolExecutor(16) as pool:
            out = list(pool.map(lambda i: s.run_code(f"print({i})"), range(48)))
        leftover = set(s._ours)
    assert [r.stdout.strip() for r in out] == [str(i) for i in range(48)]
    assert leftover == set(), f"names still claimed after every call returned: {sorted(leftover)}"




@integration
def test_a_call_that_dies_mid_flight_still_gives_its_names_back():
    """The registry hides what it holds, so a name it never gives back hides a user file FOREVER.

    A timeout returns a fault rather than raising, so the ordinary failure paths all released
    correctly and hid this one: it opens only when `_spawn` RAISES, which is an interrupt or a kern
    that dies mid-call. Measured before the `finally` existed: ten injected deaths left thirty names
    claimed and twenty files on disk, and a user file written under one of the leaked names did not
    appear in `list_files()` at all. That is the failure this pins, and the last assertion is the one
    that matters, because a leaked name is only a leak when it starts hiding something real.
    """
    with Sandbox(timeout_s=30) as s:
        real_spawn = s._spawn

        def dies(*a, **kw):
            raise RuntimeError("injected death between claim and release")

        s._spawn = dies
        for _ in range(10):
            with pytest.raises(RuntimeError):
                s.run_code("print(1)")
        s._spawn = real_spawn

        assert s._ours == set(), f"names never given back: {sorted(s._ours)}"
        assert os.listdir(s._ws) == [], "scratch outlived the call that made it"

        # And the consequence, asserted directly rather than inferred: a user file named like the
        # scratch that just died must be visible.
        s.write_file(".cell-deadbeef.py", "this one is the user's")
        assert ".cell-deadbeef.py" in {f.path for f in s.list_files()}


@integration
def test_an_oversized_bash_cell_does_not_leave_its_source_behind():
    """Over `_INLINE_CODE_MAX` the code goes to a workspace file and runs by path. The Python path has
    always deleted that file; this one never did, so every big bash/node cell left its own source in
    the workspace for the rest of the session. The box listing itself is the positive control: without
    it, an empty workspace afterwards would equally well mean the file path was never taken."""
    with Sandbox(timeout_s=60) as s:
        padding = "\n".join(f"# {i} {'x' * 100}" for i in range(1400))
        code = "ls -a /workspace | tr '\\n' ' '\n" + padding + "\necho"
        assert len(code.encode()) > s._INLINE_CODE_MAX, "the inline path would be exercised instead"
        r = s.run_code(code, language="bash")
        assert re.search(r"\.cell-[0-9a-f]{8}\.sh", r.stdout), "the file path was not taken"
        assert [f.path for f in r.files] == []
        assert os.listdir(s._ws) == [], "the cell source outlived the call"


@integration
def test_a_failed_setup_does_not_leave_its_workspace_behind():
    """`__enter__` creates the workspace and only then runs `setup`, so a setup that fails raises out of
    `__enter__`: the `with` body is never entered, `__exit__` never runs, and the directory outlives the
    session that made it. Setup is also the step most likely to fail, being a pip install against
    whatever the index is doing that minute."""
    import glob
    import tempfile

    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "kern-ws-*")))
    with pytest.raises(SandboxError, match="setup failed"):
        with Sandbox(setup="exit 3", timeout_s=30):
            pass
    assert set(glob.glob(os.path.join(tempfile.gettempdir(), "kern-ws-*"))) == before


@integration
def test_a_failed_setup_keeps_a_workspace_the_caller_supplied(tmp_path):
    """The cleanup must undo only what `__enter__` built. A `workspace=` predates the session, its
    contents are documented as persisting, and deleting it would destroy caller data on a bad setup."""
    theirs = tmp_path / "ws"
    theirs.mkdir()
    (theirs / "keep.txt").write_text("mine")
    with pytest.raises(SandboxError, match="setup failed"):
        with Sandbox(setup="exit 3", workspace=str(theirs), timeout_s=30):
            pass
    assert (theirs / "keep.txt").read_text() == "mine"
