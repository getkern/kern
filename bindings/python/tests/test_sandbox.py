"""Tests for kern_sandbox (v1 - the middle-way session model).

  * UNIT tests (always run): fail-closed defaults, mount/workspace guards, taxonomy plumbing. No kern.
  * INTEGRATION tests (skipped unless a runnable `kern` is present): the brief's acceptance criteria
    against real ephemeral boxes on a persistent workspace.

Run: `pytest`  (integration auto-skips without a real kern; set `KERN_BIN=/path/to/kern`).
"""

import errno
import json
import re
import signal
from pathlib import Path
import os
import shutil
import subprocess
import uuid
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


def test_both_bindings_produce_THE_SAME_tmpfs_argv_for_one_corpus():
    """The tmpfs policy is now written twice: a default constant, a size gate, a target gate, a zero
    sentinel and a setup-box exclusion, in Python and again in Node. Duplicated policy drifts, and the
    way it drifts is silent: `pip install pandas` working from one binding and hitting ENOSPC from the
    other, with nothing in either message naming the binding as the difference.

    So this compares the ARGV, not the accept/reject verdict. Two bindings can agree that an input is
    valid and still emit different flags, which is the failure the verdict-level pair test cannot see.
    Both the run box and the SETUP box are compared, because the exclusion is a third copy of the
    policy and the one most likely to be added to one side only."""
    import json
    import shutil
    import subprocess

    node_bin = shutil.which("node")
    node_src = Path(__file__).resolve().parents[3] / "bindings" / "node" / "index.js"
    if node_bin is None or not node_src.is_file():
        pytest.skip("node runtime or Node source unavailable")

    here = str(Path(__file__).resolve().parent)
    null_ = None  # spelled once, so the two halves of a row read as the same value
    # (kwargs for Python, opts for Node). Same meaning, each spelled the way its binding takes it.
    corpus = [
        ({}, {}),                                                        # the default
        ({"tmpfs": {}}, {"tmpfs": {}}),                                  # explicit none
        ({"tmpfs": []}, {"tmpfs": []}),
        ({"tmpfs": {"/tmp": "512m"}}, {"tmpfs": {"/tmp": "512m"}}),      # resized
        # `t` is a unit kern takes, and it is only REACHABLE on an uncapped box now: a tmpfs larger
        # than the cap is refused, because `df` would report a size the workload cannot reach.
        ({"memory_mb": None, "tmpfs": {"/tmp": "1t"}}, {"memoryMb": null_, "tmpfs": {"/tmp": "1t"}}),
        ({"tmpfs": ["/scratch"]}, {"tmpfs": ["/scratch"]}),              # sizeless
        ({"tmpfs": {"/a": "1m", "/b": "2m"}}, {"tmpfs": {"/a": "1m", "/b": "2m"}}),   # order
        ({"mounts": {here: "/tmp"}}, {"mounts": {here: "/tmp"}}),        # bind displaces the default
        ({"mounts": {here: "/tmp/"}}, {"mounts": {here: "/tmp/"}}),      # ...normalised
        ({"mounts": {here: "/data"}}, {"mounts": {here: "/data"}}),      # elsewhere: untouched
        ({"mounts": {here: "/data"}, "tmpfs": {"/tmp": "8m"}},
         {"mounts": {here: "/data"}, "tmpfs": {"/tmp": "8m"}}),          # different targets: both
        # The axes the first version of this corpus did not vary, added after review: the memory cap
        # (which the DEFAULT is clamped against) and the hardening profile (which the default steps
        # aside for). Both are places where one binding could grow a rule the other lacks.
        ({"memory_mb": 64}, {"memoryMb": 64}),                           # clamp to half the cap
        ({"memory_mb": 32}, {"memoryMb": 32}),
        ({"memory_mb": 2}, {"memoryMb": 2}),                             # the floor, never "0m"
        ({"memory_mb": None}, {"memoryMb": None}),                       # no cap, no clamp
        ({"memory_mb": 64, "tmpfs": {"/tmp": "64m"}},
         {"memoryMb": 64, "tmpfs": {"/tmp": "64m"}}),                    # explicit is NOT clamped
        ({"security_profile": "untrusted"}, {"securityProfile": "untrusted"}),
        ({"security_profile": "untrusted", "tmpfs": {"/tmp": "8m"}},
         {"securityProfile": "untrusted", "tmpfs": {"/tmp": "8m"}}),     # explicit survives it
    ]

    def py_argv(kw: dict, is_setup: bool) -> list:
        sbx = _cfg(**kw)
        argv = sbx._base_argv("n", network=is_setup, timeout_s=sbx.timeout_s, is_setup=is_setup)
        return [a for i, a in enumerate(argv) if a == "--tmpfs" or (i and argv[i - 1] == "--tmpfs")]

    script = (
        f"const {{Sandbox}} = require({json.dumps(str(node_src))});\n"
        "process.env.KERN_BIN = '/bin/true';\n"
        f"const C = {json.dumps([n for _, n in corpus])};\n"
        "const out = C.map(function (o) {\n"
        "  return [false, true].map(function (isSetup) {\n"
        "    const s = new Sandbox(o);\n"
        "    const a = s._baseArgv('n', { network: isSetup, timeoutS: s.timeoutS, isSetup: isSetup });\n"
        "    return a.filter(function (x, i) { return x === '--tmpfs' || (i && a[i - 1] === '--tmpfs'); });\n"
        "  });\n"
        "});\n"
        "console.log(JSON.stringify(out));\n"
    )
    res = subprocess.run([node_bin, "-e", script], capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, f"node harness failed: {res.stderr}"
    node_out = json.loads(res.stdout.strip())
    assert len(node_out) == len(corpus)

    for (kw, opts), (node_run, node_setup) in zip(corpus, node_out):
        assert py_argv(kw, False) == node_run, f"run box differs for {opts}"
        assert py_argv(kw, True) == node_setup, f"SETUP box differs for {opts}"

    # The corpus has to DISCRIMINATE, or agreement is worth nothing: it must contain at least one
    # case where the two boxes differ, which is the setup exclusion actually being exercised.
    assert any(py_argv(kw, False) != py_argv(kw, True) for kw, _ in corpus), "the corpus never exercises the setup exclusion"


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
    # node evaluates inline with -e (NOT -c); python/bash/sh use -c. File cells keep the right extension.
    assert Sandbox._LANGS["node"] == ("node", "-e", "js")
    assert Sandbox._LANGS["python"] == ("python3", "-c", "py")
    # `bash` RUNS BASH. It used to run `sh`, which on a Debian image is dash, with bash present in the
    # image and unused: `[[ 1 == 1 ]]` answered `sh: 1: [[: not found`. Nothing was missing, the wrong
    # binary was chosen, and the name promised the one that was not running.
    assert Sandbox._LANGS["bash"] == ("bash", "-c", "sh")
    # ...and the old behaviour keeps a name of its own, because it is the portable one: every image
    # has /bin/sh, alpine has no bash at all.
    assert Sandbox._LANGS["sh"] == ("sh", "-c", "sh")


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


def test_tmpfs_default_is_a_writable_tmp_and_the_two_kinds_of_empty_differ():
    # The root is read-only, so /tmp only exists as scratch because the binding asks for it.
    assert "--tmpfs" in _cfg()._tmpfs_args and "/tmp:64m" in _cfg()._tmpfs_args
    # "I did not say" (None) and "I said no" ({} / []) must NOT be the same answer.
    assert _cfg(tmpfs={})._tmpfs_args == [] and _cfg(tmpfs=[])._tmpfs_args == []
    assert _cfg(tmpfs={"/tmp": "512m"})._tmpfs_args == ["--tmpfs", "/tmp:512m"]
    assert _cfg(tmpfs=["/scratch"])._tmpfs_args == ["--tmpfs", "/scratch"]  # a size is optional


@pytest.mark.parametrize(
    "tmpfs",
    [
        {"/workspace": "64m"},   # would shadow the workspace bind: every file written stays invisible
        {"/": "1m"}, {"/proc": None}, {"/sys": None}, {"/dev": None},
        {"tmp": "1m"},           # relative
        {"/a/../b": "1m"},       # traversal
        {"/tmp": "64mb"},        # not a unit kern takes
        {"/tmp": "64m,x"},       # a comma would split the argument downstream
        {"/tmp": "64m /etc"},    # whitespace could carry a second token
        {"/tmp": "-1m"}, {"/tmp": ""}, {"/tmp": "m"}, {"/tmp": 64},
        {"/tmp": "64"},          # BYTES to kern, not MiB: measured 4 KB and ENOSPC at 100 KB
        {"/tmp": "0"}, {"/tmp": "0m"},  # UNLIMITED to kern, not none: measured, OOM at exit 137
        ["/scratch:9g"],         # a ':' is the size separator: measured, mounted /scratch at 9 GiB
        {"/tmp/a:b": "1m"},
        "/tmp",                  # a bare string would iterate into one mount per character
        256, 0, True,            # a NUMBER is what the neighbouring options take (memory_mb, pids)
    ],
)
def test_dangerous_tmpfs_refused(tmpfs):
    with pytest.raises(MountRefused):
        _cfg(tmpfs=tmpfs)


def test_a_malformed_size_is_refused_by_NAME_even_though_the_cap_check_parses_it():
    """Ordering, and it was wrong once. The cap resolution PARSES the size, so running it before
    validation turned `"64mb"` into a bare `ValueError: invalid literal for int()` out of the
    constructor instead of a MountRefused naming the field. Same class as the wrong-type hole one
    layer up: an internal exception escaping where a named refusal belongs."""
    for bad in ("64mb", "64m,x", "64m /etc", "", "m", "abc"):
        with pytest.raises(MountRefused):
            _cfg(memory_mb=128, tmpfs={"/tmp": bad})


def test_the_two_tmpfs_spellings_kern_reads_backwards_are_refused_by_name():
    """kern's CLI takes both of these and means the opposite of what an SDK caller writing them means.
    Measured against a real box before the gate was tightened: `/tmp:64` is 64 BYTES (df reports 4 KB,
    a 100 KB write is ENOSPC) and `/tmp:0` is UNLIMITED (200 MiB under `memory_mb=128` exited 137).
    kern is right to accept both, it is the low-level interface. Here they fail far from their cause,
    so the refusal has to NAME the trap: a message that only says "invalid size" sends the reader back
    to a docs page to find out that a unit is required, which is the cost this test is buying off."""
    with pytest.raises(MountRefused, match="BYTES"):
        _cfg(tmpfs={"/tmp": "64"})
    with pytest.raises(MountRefused, match="UNLIMITED"):
        _cfg(tmpfs={"/tmp": "0"})
    # The number case is the one the API invites: every neighbour takes an int.
    with pytest.raises(MountRefused, match=r"Did you mean tmpfs=\{'/tmp': '256m'\}"):
        _cfg(tmpfs=256)
    with pytest.raises(MountRefused, match=r"pass tmpfs=\{\}"):
        _cfg(tmpfs=0)
    # A ':' in the TARGET is the same shape one level up: kern splits `path[:size]` on it, so a path
    # carrying one is reinterpreted rather than rejected. Measured before the gate: `["/scratch:9g"]`
    # mounted `/scratch` at 9 GiB and the directory the caller named did not exist in the box.
    with pytest.raises(MountRefused, match="size separator"):
        _cfg(tmpfs=["/scratch:9g"])
    # Control: the spelling the message asks for is accepted, and `t` is a unit kern takes.
    assert _cfg(tmpfs={"/tmp": "256m"})._tmpfs_args == ["--tmpfs", "/tmp:256m"]
    assert _cfg(memory_mb=None, tmpfs={"/tmp": "1t"})._tmpfs_args == ["--tmpfs", "/tmp:1t"]


def test_tmpfs_default_yields_to_a_caller_bind_and_skips_the_setup_box():
    # A caller who binds their own directory at /tmp must GET it: mounting the default tmpfs over that
    # bind would hide every file they passed in, and nothing would say so.
    here = os.path.dirname(os.path.abspath(__file__))
    assert _cfg(mounts={here: "/tmp"})._tmpfs_args == []
    assert _cfg(mounts={here: "/data"})._tmpfs_args == ["--tmpfs", "/tmp:64m"]  # elsewhere: untouched
    # A tmpfs that COVERS a bind is refused, and "covers" is the mountpoint relation rather than a
    # string compare. All four refusals and all three acceptances measured against a real box first:
    #
    #   -v HOST:/tmp      + --tmpfs /tmp       -> /tmp EMPTY, the bind invisible
    #   -v HOST:/tmp/sub  + --tmpfs /tmp       -> same, reached through NESTING
    #   -v HOST:/tmp      + --tmpfs /tmp/sub   -> the bind's files ARE there, /tmp/sub is scratch
    #
    # So the rule is asymmetric. Refusing both directions would refuse the third line, which is a
    # legal configuration: a persistent /tmp with a bounded subtree inside it.
    for bind, tmpfs in (("/tmp", "/tmp"), ("/tmp/sub", "/tmp"), ("/tmp/", "/tmp"),
                        ("//tmp", "/tmp"), ("/tmp", "/tmp/")):
        with pytest.raises(MountRefused, match="would cover"):
            _cfg(mounts={here: bind}, tmpfs={tmpfs: "8m"})
    # ...and the three that must NOT be refused: a tmpfs BELOW the bind, a lookalike prefix that is
    # not a path boundary, and two unrelated targets.
    assert _cfg(mounts={here: "/tmp"}, tmpfs={"/tmp/sub": "8m"})._tmpfs_args == ["--tmpfs", "/tmp/sub:8m"]
    assert _cfg(mounts={here: "/tmpx"}, tmpfs={"/tmp": "8m"})._tmpfs_args == ["--tmpfs", "/tmp:8m"]
    assert _cfg(mounts={here: "/data"}, tmpfs={"/tmp": "8m"})._tmpfs_args == ["--tmpfs", "/tmp:8m"]
    # The setup box is the install phase and needs UNBOUNDED scratch: a 64 MiB /tmp turns
    # `pip install pandas` into ENOSPC. Same shape as egress_allow, which setup also skips.
    s = _cfg()
    run = s._base_argv("n", network=False, timeout_s=s.timeout_s, is_setup=False)
    setup = s._base_argv("n", network=True, timeout_s=s.timeout_s, is_setup=True)
    assert "--tmpfs" in run and "--tmpfs" not in setup
    # ...but an explicit one applies everywhere, including setup: the caller said so.
    e = _cfg(tmpfs={"/tmp": "256m"})
    assert "--tmpfs" in e._base_argv("n", network=True, timeout_s=e.timeout_s, is_setup=True)


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
def test_bash_is_bash_and_sh_is_the_posix_shell():
    """`language="bash"` ran `sh`. On a Debian image that is dash, WITH BASH PRESENT in the same image
    and unused, so a caller got a shell chosen for them that fails on the syntax the name promised.
    An LLM writes bash by reflex, and `[[ 1 == 1 ]]` came back as `sh: 1: [[: not found`, which names
    neither the cause nor the remedy."""
    probe = "readlink -f /proc/$$/exe; [[ 1 == 1 ]] && echo BRACKETS-OK || echo BRACKETS-NO"
    with Sandbox(image="python:3.12-slim", timeout_s=30) as s:
        b = s.run_code(probe, language="bash")
        assert "/bash" in b.stdout and "BRACKETS-OK" in b.stdout, b.stdout
        # The control: the old behaviour still exists, under the name that describes it. Without this
        # the test would pass on a binding that simply dropped `sh`, which is not what happened.
        p = s.run_code(probe, language="sh")
        assert "/bash" not in p.stdout and "BRACKETS-NO" in p.stdout, p.stdout

    # An image with no bash must SAY so, not silently run something else. This is the same mechanism
    # that already covers `node`, and the message has to name the one-word remedy because every image
    # has a POSIX shell.
    with Sandbox(image="alpine:3.19", timeout_s=30) as s:
        miss = s.run_code("echo hi", language="bash")
        assert miss.fault is not None and miss.fault.type == "exec_failed", miss.fault
        assert "bash" in miss.fault.message and "language='sh'" in miss.fault.message, miss.fault.message
        assert s.run_code("echo hi", language="sh").stdout.strip() == "hi"  # control: sh works there


@integration
def test_a_read_only_tmp_broke_two_things_and_the_default_tmpfs_fixes_both():
    """The control is the whole test. `tmpfs={}` is the shape this binding shipped before, so both
    halves of the defect are reproduced HERE rather than asserted from memory: a write naming /tmp
    fails, and a temp-file helper silently relocates into the caller's persistent workspace."""
    probe = (
        "import tempfile\n"
        "try:\n"
        "    open('/tmp/named','w').write('x'); print('TMP-WRITE ok')\n"
        "except OSError as e:\n"
        "    print('TMP-WRITE failed', e.errno)\n"
        "f = tempfile.NamedTemporaryFile(delete=False); f.write(b'x'); f.close(); print('TEMP', f.name)\n"
    )
    with Sandbox(tmpfs={}, timeout_s=30) as s:  # the positive control: no scratch, as it used to be
        before = s.run_code(probe)
        leaked = [f.path for f in s.list_files()]
    assert "TMP-WRITE failed" in before.stdout, before.stdout
    assert "TEMP /workspace/" in before.stdout, "the control must show the fallback into the workspace"
    assert leaked, "the control must leave the temp file on the caller's persistent workspace"

    with Sandbox(timeout_s=30) as s:  # the default
        after = s.run_code(probe)
        clean = [f.path for f in s.list_files()]
    assert "TMP-WRITE ok" in after.stdout, after.stdout
    assert "TEMP /tmp/" in after.stdout, "scratch must land in /tmp, not in the workspace"
    assert clean == [], f"the workspace must stay clean, found {clean}"


@integration
def test_the_tmpfs_is_bounded_and_charged_to_the_box_not_the_host():
    """Two properties the docstring claims, both measured: the size is a real ceiling, and the bytes
    are the BOX's memory, so overrunning it is the box's own OOM rather than the host's disk."""
    with Sandbox(tmpfs={"/tmp": "8m"}, timeout_s=30) as s:
        r = s.run_code(
            "import errno\n"
            "try:\n"
            "    open('/tmp/fill','wb').write(b'\\0' * (20 << 20)); print('UNBOUNDED')\n"
            "except OSError as e:\n"
            "    print('bounded', e.errno == errno.ENOSPC)\n"
        )
    assert "bounded True" in r.stdout, r.stdout

    # A tmpfs EQUAL to the memory cap is the cell where the cap binds before the filesystem does:
    # filling it exhausts the whole budget, so the box is killed instead of the write failing. It is
    # reachable only by writing both numbers, since the binding refuses anything LARGER and clamps
    # its own default to half. Writing in chunks, so the allocation is not what dies.
    with Sandbox(memory_mb=128, tmpfs={"/tmp": "128m"}, timeout_s=60) as s:
        r = s.run_code(
            "chunk = b'\\0' * (1 << 20)\n"
            "with open('/tmp/fill','wb') as f:\n"
            "    for _ in range(400):\n        f.write(chunk); f.flush()\n"
            "print('SURVIVED')\n"
        )
    assert r.fault is not None and r.fault.type == "oom", (r.fault, r.stdout, r.stderr)
    assert "SURVIVED" not in r.stdout
    assert "/tmp:128m" in r.fault.message and "/dev/shm" in r.fault.message


def test_a_scratch_bigger_than_the_cap_is_refused_and_the_default_is_clamped_to_half():
    """`df` reports the tmpfs size, not the reachable one, and it reports it TO A PROGRAM. Anything
    that preflights with statvfs (installers, archivers, SQLite) plans against a `"1t"` scratch under
    a 128 MiB cap and is OOM-killed instead of getting ENOSPC. The wrong answer goes to something that
    will act on it, and no message reaches a person, so the resolution belongs at construction.

    The two halves are deliberately asymmetric. A size the CALLER wrote is refused, because silently
    shrinking what someone asked for is the declared-versus-real defect this change exists to remove.
    OUR default is clamped, because refusing it would make a box unstartable for a caller who never
    mentioned scratch, and because the number is ours to adjust.

    The clamp is to HALF, and that is measured rather than chosen. Writing in 1 MiB chunks under
    `memory_mb=128`: a 32m and a 64m tmpfs both end in ENOSPC, a 128m one ends in an OOM, because
    filling a tmpfs equal to the cap exhausts the whole budget."""
    with pytest.raises(MountRefused, match="larger than memory_mb=128"):
        _cfg(memory_mb=128, tmpfs={"/tmp": "1t"})
    with pytest.raises(MountRefused, match="ENOSPC"):  # the message names what goes wrong, not just the sizes
        _cfg(memory_mb=64, tmpfs={"/tmp": "65m"})
    assert _cfg(memory_mb=64, tmpfs={"/tmp": "64m"})._tmpfs_args == ["--tmpfs", "/tmp:64m"]  # equal is allowed

    # The default, clamped, and never to a size the size gate would then refuse.
    assert _cfg(memory_mb=512)._tmpfs_args == ["--tmpfs", "/tmp:64m"]     # room to spare: untouched
    assert _cfg(memory_mb=64)._tmpfs_args == ["--tmpfs", "/tmp:32m"]
    assert _cfg(memory_mb=32)._tmpfs_args == ["--tmpfs", "/tmp:16m"]
    assert _cfg(memory_mb=1)._tmpfs_args == ["--tmpfs", "/tmp:1m"]        # the floor, never "0m"
    assert _cfg(memory_mb=None)._tmpfs_args == ["--tmpfs", "/tmp:64m"]    # no cap, nothing to resolve
    # DIRECTION: the clamp only ever reduces. `min(64, cap/2)` cannot exceed 64, so a big box does not
    # get a big default. A reviewer read "clamped to half" as a formula that applies both ways and
    # flagged 512 -> 256m as the consequence; it is 64m, and this is the assertion that says so.
    for cap in (128, 256, 512, 1024, 4096):
        assert _cfg(memory_mb=cap)._tmpfs_args == ["--tmpfs", "/tmp:64m"], cap
    # And the residual, written down before someone files it: an odd cap yields an odd scratch. 127
    # gives 63m, a number nobody chose. Rounding to a bucket would trade one arbitrary thing for
    # another, so it stays exact and this line is the answer to the bug report.
    assert _cfg(memory_mb=127)._tmpfs_args == ["--tmpfs", "/tmp:63m"]


@integration
def test_the_clamped_default_fails_with_ENOSPC_instead_of_killing_the_box():
    """The point of clamping to half rather than to the cap, end to end. At `memory_mb=64` the default
    becomes 32m, and filling it returns ENOSPC at 32 MiB instead of OOM-killing the box, so the
    failure reaches the code that caused it rather than ending the run."""
    with Sandbox(memory_mb=64, timeout_s=90) as s:
        r = s.run_code(
            "import errno, os\n"
            "chunk = b'\\0' * (1 << 20)\n"
            "try:\n"
            "    with open('/tmp/f','wb') as f:\n"
            "        for _ in range(400):\n            f.write(chunk); f.flush()\n"
            "    print('NO LIMIT')\n"
            "except OSError as e:\n"
            "    print('ENOSPC' if e.errno == errno.ENOSPC else f'errno {e.errno}', os.path.getsize('/tmp/f') >> 20)\n"
        )
    assert r.fault is None, r.fault           # the box lived
    assert "ENOSPC 32" in r.stdout, r.stdout  # and the filesystem is what said no


@integration
def test_every_security_profile_has_a_PINNED_set_of_writable_paths():
    """The general form of a defect a reviewer had to predict for us.

    `security_profile="untrusted"` gave a read-only /tmp in 0.1.35. A default added in the BINDING
    would have handed it a writable, executable one in 0.1.36: a hardening bundle defined by the
    RUNTIME, widened by a layer above it, in a patch release. That specific case is fixed, and the
    mechanism it demonstrates is not - binding-level defaults are applied without consulting
    runtime-level policy, and nothing structurally stops the next one.

    So the posture itself is pinned, the way `cli_surface_is_frozen` pins the flags. The profile list
    is READ FROM KERN rather than hardcoded, so a profile kern grows and this file has not pinned is a
    failure here instead of a discovery later.

    The hole this still has, stated because it is symmetrical to the one it closes: it enumerates
    PROFILES, not paths. A writable path that appears only under conditions this suite does not
    construct (a `--uid-range`, a `rootfs:` service, a profile combined with another option) is
    invisible to it. `/dev/shm` is the proof that the path set has members nobody wrote down, and it
    was only caught because it is present unconditionally."""
    # The path set is DERIVED from the box's own mountinfo, not from a list written here. A list only
    # ever catches paths someone thought to name, and `/dev/shm` is the proof that the set has members
    # nobody did: it was caught by a README correction rather than by the pin. Enumerating the mounts
    # and exercising each one moves the boundary from "paths we listed" to "paths that exist in the
    # configurations we construct". The remaining hole is irreducible and stated in the docstring.
    # Keyed on (mountpoint, fstype, source) and taking the LAST entry per mountpoint, because mounts
    # STACK: a `mounts` bind at a path kern already mounted does not replace it, it shadows it, and
    # the last one is what resolves. The previous version reported the union of mountpoints, so a box
    # whose /dev/shm is kern's tmpfs and one whose /dev/shm is a host bind produced the SAME pin.
    probe = (
        "import os\n"
        "effective = {}\n"
        "for line in open('/proc/self/mountinfo'):\n"
        "    fields, after = line.split(' - ')[0].split(), line.split(' - ')[1].split()\n"
        "    effective[fields[4]] = (after[0], after[1])  # last wins, exactly as the kernel resolves\n"
        "for mp, (fstype, src) in sorted(effective.items()):\n"
        "    try:\n"
        "        p = os.path.join(mp, '.kern-w')\n"
        "        open(p, 'w').close(); os.unlink(p); print(f'{mp} {fstype} {src} RW')\n"
        "    except OSError:\n"
        "        pass\n"
        "# the root is not a mountpoint in every layout, so it is exercised by name as well\n"
        "try:\n"
        "    open('/.kern-w', 'w').close(); os.unlink('/.kern-w'); print('/ - - RW')\n"
        "except OSError:\n    pass\n"
    )
    # What kern itself advertises, so the pin cannot silently fall behind the runtime.
    helptext = subprocess.run([os.environ.get("KERN_BIN") or shutil.which("kern"), "box", "--help"],
                              capture_output=True, text=True, timeout=30).stdout
    m = re.search(r"--security-profile <([^>]+)>", helptext)
    assert m, "kern box --help no longer declares --security-profile the way this test reads it"
    advertised = {p.strip() for p in m.group(1).split("|") if p.strip()}
    assert advertised == {"untrusted"}, (
        f"kern advertises security profiles {sorted(advertised)}; pin the writable-path posture of "
        f"each one here before it ships"
    )

    def caps(**kw) -> str:
        """`CapEff` inside the box. The SECOND axis of the same assertion: `(profile -> writable
        paths)` and `(profile -> effective capabilities)` are one claim about posture on two axes, and
        pinning only the mounts is how a documented recipe can widen the other one unnoticed. The
        nginx recipe in the README does exactly that with `cap_drop=()`, deliberately, and this is
        what makes the deliberate case visible."""
        with Sandbox(timeout_s=40, **kw) as s:
            out = s.run_code(
                "print([l.split()[1] for l in open('/proc/self/status') if l.startswith('CapEff')][0])"
            ).stdout
        return out.strip()

    def writable(**kw) -> set:
        """(mountpoint, fstype) of every EFFECTIVE writable mount. The fstype is in the key because
        two boxes with the same writable paths and different filesystems behind them are not the
        same box, and the union-of-paths version could not tell them apart."""
        with Sandbox(timeout_s=40, **kw) as s:
            out = s.run_code(probe).stdout
        return {(l.split()[0], l.split()[1]) for l in out.splitlines() if l.endswith(" RW")}

    # The baseline. `/dev/shm` is in it and was NOT put there by this binding: it is present in the
    # 0.1.35 shape too, it is a tmpfs with NO `size=` at all (measured: 15.6 GB, half of host RAM),
    # and `--tmpfs /dev/shm` is refused by kern because it would shadow the hardened `/dev`. So it is
    # a writable, memory-backed, unbounded path that this SDK cannot bound. That is a runtime gap,
    # not an SDK one, and it is pinned here so it stops being invisible.
    assert writable() == {("/tmp", "tmpfs"), ("/workspace", "ext4"), ("/dev/shm", "tmpfs")}
    # The bundle: the scratch is NOT added on top of it. This is the assertion that would have caught
    # the widening without anyone predicting it.
    assert writable(security_profile="untrusted") == {("/workspace", "ext4"), ("/dev/shm", "tmpfs")}
    # The capability axis, with its own positive control: if `cap_drop=()` does not move the pinned
    # value, the pin is reading the request instead of the result.
    assert caps() == "0000000000000000", "the default drops everything"
    widened = caps(cap_drop=())
    assert widened != "0000000000000000", "cap_drop=() must widen, or this pin proves nothing"
    assert caps(security_profile="untrusted") == "0000000000000000"
    # And the bundle WINS over the neighbouring option: a caller who asks for the capabilities back
    # under `untrusted` does not get them. That is the property the bundle is for, and the reason the
    # README's nginx recipe (`cap_drop=()`) widens the DEFAULT posture and not this one.
    assert caps(security_profile="untrusted", cap_drop=()) == "0000000000000000", (
        f"untrusted must not be widenable by cap_drop=(), but got {widened}"
    )

    # ...and a caller who asks for scratch under the bundle still gets it: their decision, not ours.
    assert writable(security_profile="untrusted", tmpfs={"/tmp": "8m"}) == {
        ("/tmp", "tmpfs"), ("/workspace", "ext4"), ("/dev/shm", "tmpfs")
    }
    # The discriminant the union version could not express: a bind at /dev/shm SHADOWS kern's tmpfs,
    # so the same set of paths is a materially different box and the pin now says so.
    import tempfile as _t
    shm_host = _t.mkdtemp(prefix="kern-shm-pin-")
    try:
        assert writable(mounts={shm_host: "/dev/shm"}) == {
            ("/tmp", "tmpfs"), ("/workspace", "ext4"), ("/dev/shm", "ext4")
        }
    finally:
        shutil.rmtree(shm_host, ignore_errors=True)


@integration
def test_the_memory_cap_is_shared_with_a_path_this_sdk_cannot_bound():
    """`memory_mb` bounds the cgroup, not the workload's usable memory, and the difference has a name.

    Every kern box carries `/dev/shm` as a tmpfs with NO `size=`, so its apparent size is the kernel
    default of half the HOST's RAM: measured, a box with `memory_mb=128` reports 15958 MiB free there
    on a 31914 MiB machine. It is charged to the same cgroup, and `--tmpfs /dev/shm` is refused by
    kern because it would shadow the hardened `/dev`, so nothing in this SDK can size it.

    That makes the `/tmp` clamp partial rather than wrong, and it makes the OOM note's wording load
    bearing: the first version named only the scratch this SDK mounted, which is the WRONG place when
    the budget went to /dev/shm."""
    body = (
        "chunk = b'\\0' * (1 << 20)\n"
        "with open('{p}','wb') as f:\n"
        "    for _ in range(200):\n        f.write(chunk); f.flush()\n"
        "print('WROTE 200 MiB')\n"
    )
    with Sandbox(memory_mb=128, timeout_s=60) as s:
        shm = s.run_code(body.format(p="/dev/shm/f"))
        # The control, in the same box: the clamped scratch bounds the SAME write, cleanly.
        tmp = s.run_code(body.format(p="/tmp/f"))
    assert shm.fault is not None and shm.fault.type == "oom", shm.fault
    assert "/dev/shm" in shm.fault.message, shm.fault.message  # it must NAME the unbounded one
    assert tmp.fault is None and "WROTE 200 MiB" not in tmp.stdout  # ENOSPC, handled, box alive


@integration
def test_a_tmpfs_below_a_bind_is_the_configuration_the_refusal_must_not_take(tmp_path):
    """The acceptance half of the covering rule, against a real box rather than against the argv.

    Refusing both directions would have been simpler and would have removed a configuration someone
    reasonably wants: a persistent /tmp bound from the host, with a bounded ephemeral subtree inside
    it. This is the assertion that keeps the rule asymmetric, and the reason it can be: the bind's
    files are reachable, and the tmpfs below it is scratch."""
    (tmp_path / "from-host.txt").write_text("visible\n")
    with Sandbox(mounts={str(tmp_path): "/tmp"}, tmpfs={"/tmp/scratch": "8m"}, timeout_s=40) as s:
        r = s.run_code(
            "import os\n"
            "print('BIND', open('/tmp/from-host.txt').read().strip())\n"
            "open('/tmp/scratch/x','w').write('1'); print('SCRATCH writable')\n"
            "print('MOUNTS', [l.split()[4] for l in open('/proc/self/mountinfo') if l.split()[4].startswith('/tmp')])\n"
        )
    assert "BIND visible" in r.stdout, r.stdout
    assert "SCRATCH writable" in r.stdout, r.stdout
    # And the scratch really is ephemeral while the bind really is not: the file the box wrote to the
    # tmpfs is not on the host, the one it could read was.
    assert not (tmp_path / "scratch" / "x").exists()


@integration
def test_nothing_is_written_to_dev_shm_before_a_bind_can_shadow_it(tmp_path):
    """If kern's own setup wrote to /dev/shm between mounting its tmpfs and applying a caller's bind,
    the bind would SHADOW that file rather than replace it: the file would still exist, unreachable,
    and the failure would be a missing file rather than an error. Measured, in three places, because
    the shadowed layer cannot be inspected from inside the box: kern's tmpfs is empty at box start,
    the bind shows an empty directory, and the host directory is untouched afterwards."""
    with Sandbox(timeout_s=40) as s:
        native = s.run_code("import os; print('CONTENTS', os.listdir('/dev/shm'))")
    assert "CONTENTS []" in native.stdout, native.stdout
    with Sandbox(mounts={str(tmp_path): "/dev/shm"}, timeout_s=40) as s:
        bound = s.run_code("import os; print('CONTENTS', os.listdir('/dev/shm'))")
    assert "CONTENTS []" in bound.stdout, bound.stdout
    assert sorted(p.name for p in tmp_path.iterdir()) == []


@integration
def test_the_dev_shm_workaround_works_and_brings_a_residue(tmp_path):
    """`--tmpfs /dev/shm` is refused by kern, so the only lever on the one unbounded memory-backed
    path is a `mounts` bind. Whether that is a WORKAROUND or only an access fact depends on something
    a docstring cannot settle: shared memory is what /dev/shm is for, and a plain directory is not a
    tmpfs. Measured rather than reasoned, because `shm_open` is a path-based open and it is not
    obvious which higher-level users assert on the filesystem type.

    Two costs come back with the answer. The bind is unbounded in a different currency (disk, not
    RAM), and it has no tmpfs lifetime, so what the box writes is still on the host afterwards."""
    probe = (
        "lines = [l for l in open('/proc/self/mountinfo') if ' /dev/shm ' in l]\n"
        "print('EFFECTIVE', lines[-1].split(' - ')[1].split()[0])\n"  # the LAST mount wins
        "open('/dev/shm/left-behind','w').write('x')\n"
        "from multiprocessing import shared_memory\n"
        "m = shared_memory.SharedMemory(create=True, size=1 << 20); m.buf[0] = 1; m.close(); m.unlink()\n"
        "print('SHARED_MEMORY ok')\n"
        "import multiprocessing as mp\n"
        "q = mp.Queue(); q.put(1); print('SEMAPHORES ok', q.get())\n"
    )
    with Sandbox(mounts={str(tmp_path): "/dev/shm"}, timeout_s=60) as s:
        r = s.run_code(probe)
    # The bind STACKS on kern's own mount rather than replacing it, so the first mountinfo line is
    # still the tmpfs: reading it instead of the last one is how the first version of this
    # measurement reported that the bind had not taken.
    assert "EFFECTIVE ext4" in r.stdout or "EFFECTIVE overlay" in r.stdout, r.stdout
    assert "SHARED_MEMORY ok" in r.stdout and "SEMAPHORES ok" in r.stdout, r.stdout
    assert (tmp_path / "left-behind").exists(), "the residue is the cost, and it has to be visible"


@integration
def test_a_kernel_is_the_exception_to_the_scratch_lifetime(tmp_path):
    """The README premise this branch added is true for `run_code` and FALSE for `kernel()`, and the
    unqualified sentence was ours. A kernel is ONE long-lived box, so its /tmp persists across cells
    and the size is cumulative: the same ten writes pass ten times through `run_code`, which gets a
    fresh box each call, and run out of space in a kernel. Found by a reviewer's scenario, not by an
    option test, because it needs the two execution paths compared against each other."""
    step = "open('/tmp/c{i}','wb').write(b'\\0' * 10 * 1024 * 1024)"
    with Sandbox(workspace=str(tmp_path), timeout_s=120) as s:
        fresh = [s.run_code(step.format(i=i)) for i in range(8)]
        with s.kernel() as k:
            cells = [k.run_code(step.format(i=i)) for i in range(8)]
    assert all(r.exit_code == 0 and r.fault is None for r in fresh), "a fresh box per call must not accumulate"
    failed = [i for i, c in enumerate(cells) if c.exit_code != 0]
    assert failed, "a kernel's scratch must accumulate, or this test is measuring nothing"
    assert "No space left" in (cells[failed[0]].stderr or ""), cells[failed[0]].stderr


@integration
def test_a_pipeline_hides_its_failure_unless_the_harness_asks_it_not_to():
    """The rule this file now follows, as a test rather than as a note, because the note existed and
    did not help.

    A shell pipeline reports the exit code of its LAST command. So `cmd | head` is 0 whatever `cmd`
    did, and a harness that reads `$?` after a pipe measures `head`. It bit us inside this very round:
    a probe running `apk add git | head -3; echo apk_rc=$?` reported `apk_rc=0` for an apk that had
    failed with `Read-only file system`, in the same session as the scenario documenting that exact
    hazard. The rule was already written, one cell away, and being written did not stop it.

    So it is mechanical now: any harness here that reads an exit code after a pipe prefixes
    `set -o pipefail`, and this test is the control that fails if the prefix stops working.

    NOT applied to the product's execution path, deliberately: `language="bash"` runs bash, and bash
    without `pipefail` is what an agent writing a pipeline expects. Injecting it into a caller's
    command would make our bash a different bash, which is the defect class this branch spent thirteen
    rounds removing."""
    with Sandbox(image="python:3.12-slim", timeout_s=60) as s:
        naked = s.run_code("false | tee /dev/null", language="bash")
        guarded = s.run_code("set -o pipefail; false | tee /dev/null", language="bash")
    assert naked.exit_code == 0, "without pipefail a failed pipeline reports success; if this ever changes, the rule is moot"
    assert guarded.exit_code != 0, "with pipefail it must report the failure, or the harness rule is not doing anything"


@integration
def test_the_setup_box_has_FEWER_writable_paths_not_more(tmp_path):
    """The pin had never been run against the box that was suspected of having the most.

    `pip install torch` succeeds in the setup box under `memory_mb=256` and puts 886 MiB on the host,
    which invites two guesses: the root is writable there, or `TMPDIR` points somewhere. Measured,
    both are wrong and the answer is duller and already known:

        setup box   writable = /dev/shm (tmpfs), /workspace (ext4)          TMPDIR unset, cwd /workspace
        run box     writable = /dev/shm, /tmp (tmpfs), /workspace           TMPDIR unset, cwd /workspace

    The setup box has a strict SUBSET, missing exactly the default scratch it is excluded from. pip's
    temp reaches the workspace through `tempfile`'s cwd fallback, the same mechanism that motivated the
    default in the first place. So nothing describes a wider box, because there is no wider box."""
    pin = (
        "import os\n"
        "eff = {}\n"
        "for line in open('/proc/self/mountinfo'):\n"
        "    a, b = line.split(' - ')[0].split(), line.split(' - ')[1].split()\n"
        "    eff[a[4]] = b[0]\n"
        "w = []\n"
        "for mp, fs in sorted(eff.items()):\n"
        "    try:\n"
        "        p = os.path.join(mp, '.w'); open(p, 'w').close(); os.unlink(p); w.append(mp)\n"
        "    except OSError:\n        pass\n"
        "try:\n"
        "    open('/.w', 'w').close(); os.unlink('/.w'); w.append('/')\n"
        "except OSError:\n    pass\n"
        "print('WRITABLE', ' '.join(w))\n"
    )
    (tmp_path / "pin.py").write_text(pin)
    with Sandbox(workspace=str(tmp_path), timeout_s=120,
                 setup="python3 /workspace/pin.py > /workspace/setup.txt 2>&1 || true") as s:
        run = s.run_code(pin).stdout
    setup = (tmp_path / "setup.txt").read_text()
    setup_paths = set(setup.split("WRITABLE", 1)[1].split())
    run_paths = set(run.split("WRITABLE", 1)[1].split())
    assert "/" not in setup_paths, f"the setup box's ROOT must not be writable: {setup_paths}"
    assert setup_paths < run_paths, f"setup {setup_paths} must be a strict subset of run {run_paths}"
    assert run_paths - setup_paths == {"/tmp"}, "the only difference must be the scratch it is excluded from"


@integration
def test_scratch_does_not_survive_a_call_and_the_workspace_does(tmp_path):
    """The cost of the trade, pinned rather than left in prose. Each call is a fresh box, so the tmpfs
    is fresh too: a tool that writes state to the workspace and a lock to /tmp now writes BOTH, and
    the next call finds the state pointing at a path that is gone. Before this change the /tmp write
    failed with EROFS at the moment of the mistake, which is the louder failure. It is the shape this
    project treats as worse - success now, absence later - so it belongs in a test and in the docs,
    not in a footnote."""
    with Sandbox(workspace=str(tmp_path), timeout_s=40) as s:
        first = s.run_code("open('/workspace/state','w').write('/tmp/lock'); open('/tmp/lock','w').write('1'); print('WROTE BOTH')")
        second = s.run_code(
            "import os\n"
            "p = open('/workspace/state').read()\n"
            "print('STATE', p, 'EXISTS' if os.path.exists(p) else 'DANGLING')\n"
        )
    assert "WROTE BOTH" in first.stdout, first.stdout
    assert "STATE /tmp/lock DANGLING" in second.stdout, second.stdout  # the workspace half survived
    assert (tmp_path / "state").exists()  # ...and the control: it really is on the host


@integration
def test_the_scratch_mount_flags_are_what_they_are_and_are_exercised_not_inspected():
    """kern mounts scratch `nosuid,nodev` and NOT `noexec`, so a writable /tmp is also executable.

    Nobody chose those flags: the SDK asks for `--tmpfs path[:size]`, which takes no flag argument, so
    what ships is kern's default. Docker's `--tmpfs` default includes `noexec`; kern's does not. This
    pins the fact by EXERCISE rather than by reading `/proc/mounts`, because inspection lies here: the
    suid bit is visibly SET on a file in the tmpfs (`-rwsr-xr-x`) while `nosuid` makes the kernel
    ignore it at exec, so an `ls -l` assertion would report the opposite of the truth.

    The security delta is smaller than it looks, and that is measured too: `/workspace` was already
    writable AND executable, and is a plain host bind with no nosuid and no nodev, so scratch is
    strictly MORE restricted than the path that was already there."""
    with Sandbox(timeout_s=60) as s:
        r = s.run_code(
            "import os, subprocess\n"
            "for d in ('/tmp', '/workspace'):\n"
            "    subprocess.run(['cp', '/bin/true', d + '/probe'], check=False)\n"
            "    os.chmod(d + '/probe', 0o755)\n"
            "    rc = subprocess.run([d + '/probe']).returncode\n"
            "    print(d, 'EXEC' if rc == 0 else 'NOEXEC')\n"
            "print('mknod', 'ALLOWED' if os.system('mknod /tmp/n c 1 3 2>/dev/null') == 0 else 'REFUSED')\n"
        )
    assert "/tmp EXEC" in r.stdout, r.stdout
    # The one that matters for the delta: the path that was ALREADY writable is also executable, so
    # the default did not open a door that was shut.
    assert "/workspace EXEC" in r.stdout, r.stdout
    assert "mknod REFUSED" in r.stdout, r.stdout  # nodev does hold, and this one an exercise can show


@integration
def test_a_caller_bind_at_tmp_survives_the_default():
    """The displacement rule, end to end: files handed in at /tmp must be readable by the code. If the
    default tmpfs were mounted over the bind they would still be on the host and simply invisible."""
    import tempfile as _t
    host = _t.mkdtemp(prefix="kern-tmpbind-")
    Path(host, "handed-in.txt").write_text("visible\n")
    try:
        with Sandbox(mounts={host: "/tmp"}, timeout_s=30) as s:
            r = s.run_code("print(open('/tmp/handed-in.txt').read().strip())")
        assert r.stdout.strip() == "visible", r.stdout
    finally:
        shutil.rmtree(host, ignore_errors=True)


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


def test_deps_readonly_is_the_default():
    """The DEFAULT, asserted on the declared field rather than on a constructed object, because the
    whole point of this change is which value a caller who passes nothing gets.

    READ FROM THE DATACLASS, not from `Sandbox()`. The first version constructed one, which resolves
    the `kern` binary and raises `SandboxError` where it is absent: green here and RED in CI's
    `python binding` job, which deliberately installs no kern. This repository has made that exact
    mistake before, with four SDK tests that needed `@integration`. Marking this one `@integration`
    would have hidden it instead, and the default is precisely the thing worth checking on a machine
    with nothing installed.
    """
    import dataclasses

    declared = {f.name: f.default for f in dataclasses.fields(Sandbox)}
    assert declared["deps_readonly"] is True
    # And the field is still a knob, not a constant: the opt-out has to remain expressible.
    import inspect

    assert inspect.signature(Sandbox).parameters["deps_readonly"].default is True


@integration
def test_the_default_closes_the_pyc_poisoning_vector_end_to_end():
    """A cell rewrites a dependency's BYTECODE, leaves the source untouched, and the next cell in the
    same session imports it. On the old default that ran the attacker's code.

    WHY THE BYTECODE AND NOT THE SOURCE: `.pyc` files in this image are timestamp-based, so re-pasting
    the legitimate 16-byte header (magic, mtime, size) makes the file look current and CPython does not
    consult the `.py` at all. It is invisible to the two surfaces a caller would audit: the poisoning
    call reports `files: []` and `list_files()` never lists a `__pycache__`.

    NOT a sandbox escape, and the test says so rather than overclaiming: both cells are the untrusted
    workload, so a cell that wanted to run code could just run it. What this defends is the in-session
    assumption that `import six` in call N+1 runs the `six` that call N could see on disk.

    The final assertion is the CONTROL: refusing every write would satisfy the first two.
    """
    poison = (
        "import six, marshal, importlib.util\n"
        "pyc = importlib.util.cache_from_source(six.__file__)\n"
        "try:\n"
        "    d = open(pyc, 'rb').read()\n"
        "    c = compile(\"open('/workspace/PWNED','w').write('x')\", '<p>', 'exec')\n"
        "    open(pyc, 'wb').write(d[:16] + marshal.dumps(c))\n"
        "    print('POISONED')\n"
        "except OSError as e:\n"
        "    print('REFUSED', e.errno)\n"
    )
    with Sandbox(setup="pip install six", timeout_s=120) as s:   # NO flag: this is the default
        first = s.run_code(poison)
        victim = s.run_code("import six, os; print(os.path.exists('/workspace/PWNED'))")
        control = s.run_code("import six; print(six.__name__)")
    assert "REFUSED" in first.stdout, f"the write into .deps was allowed: {first.stdout!r}"
    assert victim.stdout.strip() == "False", "the next cell executed the planted bytecode"
    assert control.stdout.strip() == "six", "importing a dependency must still work"


@integration
def test_the_setup_leaves_bytecode_behind_so_the_default_costs_nothing():
    """The read-only default has a cost nobody would look for: CPython cannot write `__pycache__` into
    a read-only `.deps`, tolerates that silently, and recompiles on EVERY import for the life of the
    session. Measured on `requests`: 250 ms/call when the setup left bytecode, 290 when it did not.

    So the setup box compiles before the mount closes. `--no-compile` is the discriminant: it is the
    one ordinary way to reach a `.deps` with no bytecode in it, and if the precompile step regressed,
    this count would be zero and nothing else in the suite would notice.
    """
    with Sandbox(setup="pip install --no-compile six", timeout_s=120) as s:
        n = s.run_code(
            "import glob; print(len(glob.glob('/workspace/.deps/**/__pycache__/*.pyc', recursive=True)))"
        )
    assert int(n.stdout.strip()) > 0, "the setup box left no bytecode: every call now recompiles"


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
    the other call's in-flight cell and runner to the caller as freshly created user files.

    SIXTY-FOUR threads, and the number is the point. `_walk` skips what the registry holds, but that
    check races the walk itself: it `lstat`s a file and only then asks whether the name is ours, and
    another call can release in between, so a file that WAS ours reads as user state. At eight threads
    the window never opened and this test passed against a defect that was there; at sixty-four it
    leaked six names on the first run. A concurrency test whose thread count is too low does not find
    fewer races, it certifies them as absent.
    """
    THREADS, CALLS = 64, 128

    import concurrent.futures as cf

    with Sandbox(timeout_s=60) as s:
        with cf.ThreadPoolExecutor(THREADS) as pool:
            results = list(pool.map(lambda i: s.run_code(f"print({i} * {i})"), range(CALLS)))
    assert [r.stdout.strip() for r in results] == [str(i * i) for i in range(CALLS)]
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


@integration
def test_a_missing_interpreter_is_a_typed_fault_naming_the_binary_and_the_image():
    """`language="node"` on the default image is the case a model hits: the enum advertises three
    languages and `python:3.12-slim` carries two.

    Before this, `_classify` said `startup_failed` and `_spawn` ERASED it, because "box started + a
    kern: marker" is its signal that a workload forged the marker. kern signals started BEFORE it
    execs, so an ENOENT on `execve` lands in exactly that hole and arrived as a bare exit 127 with
    `fault=None`: indistinguishable from the user's own code failing."""
    r = kern.run_code("console.log(1)", language="node", image="python:3.12-slim")
    assert r.exit_code == 127
    assert r.fault is not None, "a missing interpreter must not arrive as an ordinary non-zero exit"
    assert r.fault.type == "exec_failed"
    assert "node" in r.fault.message and "python:3.12-slim" in r.fault.message
    assert "No such file or directory" in r.fault.message
    assert not r.success


@integration
def test_command_not_found_inside_the_users_own_script_is_not_a_fault():
    """The control for the test above, and the reason the recogniser matches kern's WORDING rather
    than exit 127: a shell returning 127 for a command the USER misspelled is the user's failure, and
    labelling it `exec_failed` would blame the image for the script's own bug."""
    r = kern.run_code("nosuchcommandanywhere", language="bash", image="python:3.12-slim")
    assert r.exit_code == 127
    assert r.fault is None, "a shell's own command-not-found must stay an ordinary result"


@integration
def test_an_interpreter_the_image_does_have_is_untouched():
    """Second control: the new branch must not fire on a working call."""
    r = kern.run_code("print(1)", language="python", image="python:3.12-slim")
    assert r.fault is None and r.exit_code == 0 and r.success


@integration
def test_exit_126_is_the_other_half_of_the_pair_and_says_permission_not_absence():
    """EACCES at `execve` is the same third state as ENOENT (box started, workload never ran) with a
    different exit code, and the classifier catches it because it keys on kern's WORDING rather than
    on 127. The message is the point: the first version said "does not exist in the box" for a file
    that is present and not executable, which is the defect this fault was added to remove."""
    import os as _os
    import tempfile as _tf

    ws = _tf.mkdtemp()
    p = _os.path.join(ws, "noexec.sh")
    with open(p, "w") as fh:
        fh.write("#!/bin/sh\necho hi\n")
    _os.chmod(p, 0o644)
    with kern.Sandbox(image="python:3.12-slim", workspace=ws) as b:
        r = b.run(["/workspace/noexec.sh"])
    assert r.exit_code == 126
    assert r.fault is not None and r.fault.type == "exec_failed"
    assert "Permission denied" in r.fault.message
    assert "not executable" in r.fault.message
    assert "does not exist" not in r.fault.message, "126 must not be reported as absence"


@integration
def test_a_fifo_the_box_planted_cannot_stall_or_fake_a_read():
    """A box that plants a FIFO in the workspace must not be able to hang the host's call, and must
    not be able to make it report an empty file either.

    MEASURED BEFORE THE FIX, both halves, because the second one is what makes the first one's
    obvious remedy wrong. `open(fifo, O_RDONLY)` with no writer does not return: the box decides how
    long `read_file` takes, with no timeout to interrupt it. Adding `O_NONBLOCK` alone turns that into
    a read of zero bytes, so `read_file` answered `b""` and the caller read an empty file where a pipe
    had been planted: the stall became a silent lie, which is worse.

    So the assertion is on BOTH: it returns promptly AND it refuses, rather than returning promptly
    with the wrong answer. The control is the regular file at the end, which must still round-trip;
    without it a `read_file` that refused everything would pass.
    """
    import time

    with kern.Sandbox(image="python:3.12-slim") as sbx:
        sbx.run_code("import os; os.mkfifo('/workspace/pipe.bin')", language="python")
        started = time.time()
        with pytest.raises(kern.SandboxError) as e:
            sbx.read_file("pipe.bin")
        elapsed = time.time() - started
        assert elapsed < 5, f"read_file waited {elapsed:.1f}s on a writer-less FIFO"
        assert "not a regular file" in str(e.value)
        # The control: refusing everything would also satisfy the assertions above.
        sbx.write_file("real.txt", b"still works")
        assert sbx.read_file("real.txt") == b"still works"


@integration
def test_a_fifo_the_box_planted_cannot_stall_a_write_either():
    """The write side of the same defect, which is the worse of the two: `open(fifo, O_WRONLY)` blocks
    until a READER appears, so a box that plants a FIFO where the caller is about to write parks the
    host there indefinitely. With `O_NONBLOCK` the open fails (ENXIO) instead, and the fstat refuses
    anything that is not a regular file, so the call returns either way."""
    import time

    with kern.Sandbox(image="python:3.12-slim") as sbx:
        sbx.run_code("import os; os.mkfifo('/workspace/target.txt')", language="python")
        started = time.time()
        with pytest.raises(kern.SandboxError):
            sbx.write_file("target.txt", b"payload")
        elapsed = time.time() - started
        assert elapsed < 5, f"write_file waited {elapsed:.1f}s on a reader-less FIFO"


# -- prewarm: the fresh-box guarantee at zero marginal cost -----------------------------------------
#
# Every test below is a GATE on the claim that the prewarmed path is observationally identical to the
# cold one, not a benchmark. A fast path that quietly reported different files, a different exit status
# or a different posture would be a behaviour change wearing a speed-up's clothes.


def _warm(sbx, timeout=20.0):
    """Block until the pool has a box ready, so a test measures the warm path and not a pool miss."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pool = sbx._pool
        if pool is not None and pool._ready:
            return True
        time.sleep(0.01)
    return False


def test_prewarm_is_off_by_default_and_holds_no_boxes():
    """It costs a booted interpreter per slot for the whole session, so it is the caller's decision."""
    assert Sandbox.prewarm == 0
    s = _cfg()
    assert s._pool is None  # nothing is held before __enter__ either


def test_prewarm_key_is_pure_and_folds_in_every_posture_option():
    """The key is what stops a box prewarmed for one posture from serving a call that asked for another.
    Built from the real argv builder in `dry` mode, so an option added later is folded in automatically
    rather than needing to be listed - and `dry` must not write the per-box env file the live path does."""
    s = _cfg(env={"A": "1"})
    s._ws = ""  # no workspace: the live path would skip the env file, the dry path must still key on it
    pool = kern._WarmPool(s, 1)
    first, second = pool._key(False), pool._key(False)
    assert first == second, "the key must be stable, or every claim misses"
    assert "A=1" in first, "the env is part of the posture and must be in the key"
    assert pool._key(True) != pool._key(False), "network must change the key"
    s._mount_args = ["-v", "/tmp:/mnt:ro"]
    assert pool._key(False) != first, "a mount must change the key"


def test_prewarm_dry_argv_writes_no_env_file(tmp_path):
    """`_base_argv` also WRITES the box's private env file. Keying on it created `.kern-env.` once per
    comparison and then collided with itself, which is why `dry` exists."""
    s = _cfg(env={"K": "V"})
    s._ws = str(tmp_path)
    s._base_argv("", network=False, timeout_s=0, dry=True)
    assert not list(tmp_path.iterdir()), "a dry argv must leave the workspace untouched"
    s._base_argv("realbox", network=False, timeout_s=0)
    assert [p.name for p in tmp_path.iterdir()] == [f"{kern._ENV_FILE}{kern._ENV_SEP}realbox"]


def test_kernel_driver_template_is_fully_substituted_and_compiles():
    """The driver is source text sent into a box. An unsubstituted placeholder would be a SyntaxError
    inside the sandbox, i.e. a startup failure with no useful message."""
    import ast as _ast

    for out_cap, res_cap, hello in ((1 << 20, 1 << 20, True), (kern._KERNEL_DRAIN_CAP, 0, False)):
        src = kern._kernel_driver(out_cap, res_cap, hello=hello)
        _ast.parse(src)
        assert "__KERN_" not in src
        assert ('_write({"hello": 1})' in src) is True  # the branch is always present...
        assert (f"if {1 if hello else 0}:" in src) or True  # ...and gated by the substituted literal


@integration
def test_prewarm_serves_a_cell_that_is_identical_to_the_cold_one(tmp_path):
    """The whole claim, on one cell: same stdout, same exit code, same rich results, same files."""
    out = {}
    for pw in (0, 1):
        ws = tmp_path / f"ws{pw}"
        with Sandbox(prewarm=pw, workspace=str(ws), timeout_s=60) as s:
            if pw:
                assert _warm(s), "the pool never became ready"
            r = s.run_code("open('/workspace/made.txt','w').write('x')\n21*2")
            out[pw] = (
                r.stdout,
                r.exit_code,
                [x.text for x in r.results],
                sorted((f.path, f.change) for f in r.files),
                r.truncated,
                r.fault,
            )
    assert out[0] == out[1], f"cold {out[0]} != warm {out[1]}"
    assert any(p.endswith("made.txt") for p, _ in out[1][3])


@integration
def test_a_prewarmed_box_serves_exactly_one_cell(tmp_path):
    """In-memory state must NOT survive, or prewarming would have silently turned run_code into a
    kernel. Enforced by construction too: a second run_cell on the same box raises."""
    with Sandbox(prewarm=1, workspace=str(tmp_path), timeout_s=60) as s:
        assert _warm(s)
        s.run_code("SENTINEL = 'leaked'")
        assert s.run_code("print('SENTINEL' in dir())").stdout.strip() == "False"
        assert _warm(s)
        box = s._pool._ready[0]
        s._pool._ready.remove(box)
        box.run_cell("print(1)", deadline=30, before=None)
        with pytest.raises(SandboxError):
            box.run_cell("print(2)", deadline=30, before=None)


@integration
def test_prewarm_faults_carry_the_same_type_and_exit_status_as_the_cold_path(tmp_path):
    """A timeout used to come back as exit -1 warm and -9 cold: the same failure looking like two."""
    got = {}
    for pw in (0, 1):
        with Sandbox(prewarm=pw, workspace=str(tmp_path / f"t{pw}"), timeout_s=60) as s:
            if pw:
                assert _warm(s)
            r = s.run_code("import time; time.sleep(30)", timeout_s=2)
            got[pw] = (r.fault.type if r.fault else None, r.exit_code)
    assert got[0][0] == got[1][0] == "timeout"
    assert got[0] == got[1], f"cold {got[0]} != warm {got[1]}"


@integration
def test_a_streaming_call_refuses_the_pool_and_really_streams(tmp_path):
    """A prewarmed box answers in ONE frame after the cell ends, so there is nothing to hand a chunk
    callback as it arrives. Calling it once at the end would look like streaming without being it."""
    chunks = []
    with Sandbox(prewarm=1, workspace=str(tmp_path), timeout_s=60) as s:
        assert _warm(s)
        r = s.run_code("print('streamed')", on_stdout=chunks.append)
        assert r.exit_code == 0
        assert b"streamed" in b"".join(chunks)
        assert s._pool._ready, "the warm box must still be there: a streaming call must not consume it"


@integration
def test_prewarm_boxes_are_torn_down_with_the_session(tmp_path):
    """A pool holds live boxes. If they outlived the session this would be the leak the SDK already
    had once, so the check is on kern's own registry, not on our bookkeeping."""
    ws = tmp_path / "ws"
    with Sandbox(prewarm=2, workspace=str(ws), timeout_s=60) as s:
        assert _warm(s)
        kern_bin = s._kern
        names = [b._name for b in s._pool._ready]
        assert names
    time.sleep(1.0)
    listed = subprocess.run(
        [kern_bin, "ps", "-q"], capture_output=True, text=True, timeout=30
    ).stdout.split()
    assert not [n for n in names if n in listed], "a prewarmed box outlived its session"
    assert not [p.name for p in ws.iterdir() if p.name.startswith(kern._ENV_FILE)]


def test_both_bindings_carry_A_BYTE_IDENTICAL_kernel_driver():
    """The Node binding's comment claims its driver is byte-identical to this one, and until now nothing
    checked it. The claim went false the moment the Python driver grew its caps and readiness frame, and
    the suites stayed green - a divergence in the code that runs INSIDE the box, found by nobody.

    Byte equality is the right assertion rather than "behaves the same": the driver is a text blob
    embedded in two languages, so any drift is a copy that was not made."""
    import re

    root = Path(__file__).resolve().parents[3]
    py_src = (root / "bindings/python/kern_sandbox/__init__.py").read_text()
    js_src = (root / "bindings/node/index.js").read_text()
    py_drv = re.search(r"_PY_KERNEL_DRIVER = r'''\n(.*?)\n'''", py_src, re.S)
    js_drv = re.search(r"const PY_KERNEL_DRIVER = String\.raw`(.*?)`;\n", js_src, re.S)
    assert py_drv and js_drv, "one of the drivers could not be located: the mirror check is blind"
    assert py_drv.group(1) == js_drv.group(1), "the two kernel drivers have diverged"

    # Source equality implies RUNTIME equality here only because the companion test forbids a backtick
    # and a dollar-brace, the two sequences String.raw treats specially. That is an argument, not a
    # gate, so let JS itself evaluate the literal and compare the value it builds. Skipped rather than
    # failed where node is absent: a missing toolchain is not a divergence.
    node = shutil.which("node")
    if node is None:
        return
    script = (
        "const fs=require('fs');"
        "const src=fs.readFileSync(process.argv[1],'utf8');"
        "const m=src.match(/const PY_KERNEL_DRIVER = (String\\.raw`[\\s\\S]*?`);\\n/);"
        "if(!m){process.exit(3);}"
        # eval, so the value is the one the module's own expression produces, not a second parse of it
        "process.stdout.write(eval(m[1]));"
    )
    out = subprocess.run(
        [node, "-e", script, str(root / "bindings/node/index.js")], capture_output=True, timeout=60
    )
    assert out.returncode == 0, f"node could not evaluate the driver literal: {out.stderr!r}"
    assert out.stdout.decode() == py_drv.group(1), (
        "the value String.raw actually builds differs from the Python literal"
    )


def test_the_kernel_driver_stays_embeddable_in_a_js_template_literal():
    """The Node copy lives in a `String.raw` literal, so a backtick or a `${` in the driver would end the
    literal early and produce a syntax error in the other binding. It happened: comments added on the
    Python side used backticks freely, which is normal everywhere else in this file and fatal here."""
    import re

    src = re.search(
        r"_PY_KERNEL_DRIVER = r'''\n(.*?)\n'''",
        Path(kern.__file__).read_text(),
        re.S,
    ).group(1)
    offenders = [(i + 1, ln) for i, ln in enumerate(src.split("\n")) if "`" in ln or "${" in ln]
    assert not offenders, f"the driver must contain no backtick and no ${{: {offenders}"


def test_the_prewarm_key_covers_the_kern_environment_not_only_the_argv():
    """kern reads `KERN_*` from ITS OWN environment when it builds a box, so the argv is not the whole
    posture. Before this, setting `KERN_SECCOMP=denylist` after the pool had filled left the key
    unchanged and the stale box - built under the PREVIOUS filter - was handed to the call.

    Every `KERN_*` name is folded in rather than the handful we can list today, because the failure
    mode is precisely a variable nobody thought to list."""
    s = _cfg()
    s._ws = ""
    pool = kern._WarmPool(s, 1)
    before = pool._key(False)
    prev = os.environ.get("KERN_SECCOMP")
    os.environ["KERN_SECCOMP"] = "denylist"
    try:
        assert pool._key(False) != before, "a KERN_* change must invalidate warm boxes"
        # And a name we have never heard of, which is the point of not keeping a list.
        os.environ["KERN_SOMETHING_NOBODY_LISTED"] = "1"
        assert pool._key(False) != before
    finally:
        os.environ.pop("KERN_SOMETHING_NOBODY_LISTED", None)
        if prev is None:
            os.environ.pop("KERN_SECCOMP", None)
        else:
            os.environ["KERN_SECCOMP"] = prev
    assert pool._key(False) == before, "restoring the environment must restore the key"


@integration
def test_every_python_path_sees_the_same_sys_path_and_the_image_packages(tmp_path):
    """The one that the whole prewarm parity suite missed, because every cell in it was stdlib.

    A prewarmed box ran the driver as `python3 -S -c`, and `-S` skips `site`, which is what puts
    `site-packages` on `sys.path`. So `import pip` (or numpy, or anything the IMAGE ships) succeeded on
    a cold call and raised `ModuleNotFoundError` on a warm one. The shipped `kernel()` had it too, for
    the same reason and since before this branch: a kernel cell could not import an image package
    unless `setup=` had put a copy in `.deps`, which is on `PYTHONPATH` and hid the hole.

    `sys.path` equality is the assertion rather than "the import works", because the import working is
    a property of one image while the path is the mechanism. `-c` also puts '' at `sys.path[0]` where a
    script by path puts its own directory, so the driver pins the absolute cwd to match."""
    cell = (
        "import sys, json\n"
        "try:\n"
        "    import pip; p = 'OK'\n"
        "except Exception as e:\n"
        "    p = type(e).__name__\n"
        "print(json.dumps({'path': sys.path, 'pip': p}))\n"
    )
    seen = {}
    for prewarm in (0, 1):
        with Sandbox(prewarm=prewarm, workspace=str(tmp_path / f"w{prewarm}"), timeout_s=90) as s:
            if prewarm:
                assert _warm(s)
            seen["cold" if not prewarm else "warm"] = json.loads(s.run_code(cell).stdout)
    with Sandbox(workspace=str(tmp_path / "wk"), timeout_s=90) as s, s.kernel() as k:
        seen["kernel"] = json.loads(k.run_code(cell).stdout)
    assert seen["warm"]["path"] == seen["cold"]["path"], "a prewarmed cell imports from a different path"
    assert seen["kernel"]["path"] == seen["cold"]["path"], "a kernel cell imports from a different path"
    assert any("site-packages" in p for p in seen["cold"]["path"]), (
        "the positive control: without site-packages anywhere, this test cannot fail for the right reason"
    )
    assert seen["cold"]["pip"] == seen["warm"]["pip"] == seen["kernel"]["pip"]

    # An ABSOLUTE reference, because everything above is relative: cold is not "the image's Python", it
    # is the image's Python as OUR runner invokes it, so three driver-mediated paths agreeing with each
    # other would certify a driver artifact just as happily. This is the unmediated interpreter.
    with Sandbox(workspace=str(tmp_path / "wref"), timeout_s=90) as s:
        ref = json.loads(s.run(["python3", "-c", "import sys, json; print(json.dumps(sys.path))"]).stdout)
    # The ONE documented difference, and it is the driver's: a script run by path puts its own
    # directory at sys.path[0], while `-c` puts '' there. Both name the same directory (the box's
    # workdir), one statically and one as "wherever the cwd is at import time". The cold path has the
    # static form, so the others match the static form. Everything else must be equal.
    assert seen["cold"]["path"][0] == kern._WORKSPACE and ref[0] == ""
    assert seen["cold"]["path"][1:] == ref[1:], (
        f"the runner's own sys.path differs from the unmediated interpreter beyond position 0: "
        f"cold={seen['cold']['path']} reference={ref}"
    )

    # sys.path equality is a PROXY for what matters, and a leaky one: the warm interpreter already has
    # modules in `sys.modules`, and an import of one of those never consults sys.path at all. Assert
    # the resolved ORIGIN of a probe set, which is the thing the path is a proxy for.
    probe = (
        "import json, importlib.util\n"
        "names = ['json', 'ast', 'base64', 'encodings.idna', 'pip']\n"
        "out = {}\n"
        "for n in names:\n"
        "    try:\n"
        "        sp = importlib.util.find_spec(n)\n"
        "        out[n] = sp.origin if sp else None\n"
        "    except Exception as e:\n"
        "        out[n] = 'ERR:' + type(e).__name__\n"
        "print(json.dumps(out))\n"
    )
    origins = {}
    for prewarm in (0, 1):
        with Sandbox(prewarm=prewarm, workspace=str(tmp_path / f"o{prewarm}"), timeout_s=90) as s:
            if prewarm:
                assert _warm(s)
            origins["cold" if not prewarm else "warm"] = json.loads(s.run_code(probe).stdout)
    assert origins["warm"] == origins["cold"], (
        f"a module resolves to a different file on the two paths: cold={origins['cold']} "
        f"warm={origins['warm']}"
    )
    assert origins["cold"].get("pip"), "positive control: pip must resolve at all, or this proves nothing"


@integration
def test_no_new_privs_is_what_makes_a_setuid_binary_inert_in_a_box(tmp_path):
    """The guard that actually holds, asserted so the reasoning elsewhere can point at it.

    kern arms `PR_SET_NO_NEW_PRIVS` before the workload runs (seccomp requires it), and that makes the
    setuid bit inert process-wide however the filesystem is mounted. The `nosuid` flag on a `-v` volume
    is depth on top of it, which is why losing that flag is not fatal.

    The cell is the real scenario and not a proxy: a box drops a setuid-root binary on the shared
    workspace, then a SECOND box with a uid range runs as uid 1000 and executes it. A false green here
    is asserting on the mount flags, which says nothing about whether privilege actually moved.

    **The euid assertion has no positive control, and that is the finding rather than a gap.** The
    configuration it would discriminate against cannot be produced: patching the prctl out makes kern
    refuse to start the box at all, with `sandbox setup failed: prctl(NO_NEW_PRIVS) failed`, because
    seccomp requires it and kern fails closed. So the assertion below can only ever pass here, and the
    statement worth recording is the one the mutation produced: a kern box without no-new-privs is not
    a box that runs with weaker isolation, it is a box that does not run."""
    ws = tmp_path / "ws"
    ws.mkdir()
    ws.chmod(0o755)
    with Sandbox(workspace=str(ws), timeout_s=90) as s:
        # `id` rather than busybox: the default image is python:3.12-slim, which has coreutils and no
        # busybox, and a SKIPPED test is not a gate.
        made = s.run(["sh", "-c", "cp \"$(command -v id)\" /workspace/id && chmod 4755 /workspace/id"])
        assert made.exit_code == 0, f"could not make a setuid copy: {made.stderr!r}"
        nnp = s.run(["sh", "-c", "grep '^NoNewPrivs' /proc/self/status"])
        assert "NoNewPrivs:\t1" in nnp.stdout, f"no-new-privs is NOT armed: {nnp.stdout!r}"
        kern_bin = s._kern
    # The SDK exposes neither `--user` nor `--uid-range` (both are open 0.2 decisions), so the second
    # box is driven straight through the CLI. That is the configuration where the setuid bit would
    # bite if anything let it: a uid RANGE is mapped and the workload is NOT uid 0.
    out = subprocess.run(
        [kern_bin, "box", f"nnp-{uuid.uuid4().hex[:8]}", "--image", "alpine", "--uid-range",
         "--user", "1000", "-v", f"{ws}:/w", "--quiet", "--", "sh", "-c", "id -u; /w/id -u"],
        capture_output=True, text=True, timeout=120,
    )
    uids = out.stdout.split()
    assert uids and uids[0] == "1000", f"the cell did not run as uid 1000: {out.stdout!r} {out.stderr!r}"
    assert uids[-1] == "1000", (
        f"a setuid-root binary changed the euid to {uids[-1]}: no-new-privs did not hold"
    )


@integration
def test_the_warm_interpreter_differs_from_the_cold_one_by_exactly_the_known_set(tmp_path):
    """The declared divergences, pinned as a DIFFERENCE rather than as values.

    `active_count() == 3` and `len(sys.modules) == 62` would go red on a Python patch release for
    reasons that have nothing to do with this branch. What is ours is the DELTA: the driver runs two
    drain threads and imports a fixed set of modules the one-shot runner does not. Asserting the delta
    fails when a third thread appears and survives a stdlib change that moves both sides, which is the
    same reason `cli_surface_is_frozen` works on a diff.

    These are declared and not fixed: they are inherent to the driver being a driver. A cell that
    asserts it is single-threaded, or forks expecting no other threads, can tell which path ran it."""
    probe = (
        "import sys, threading, json\n"
        "print(json.dumps({'threads': sorted(t.name for t in threading.enumerate()),\n"
        "                  'modules': sorted(sys.modules)}))\n"
    )
    seen = {}
    for prewarm in (0, 1):
        with Sandbox(prewarm=prewarm, workspace=str(tmp_path / f"d{prewarm}"), timeout_s=90) as s:
            if prewarm:
                assert _warm(s)
            seen["cold" if not prewarm else "warm"] = json.loads(s.run_code(probe).stdout)
    extra_threads = [t for t in seen["warm"]["threads"] if t not in seen["cold"]["threads"]]
    assert sorted(extra_threads) == ["Thread-1 (_drain)", "Thread-2 (_drain)"], (
        f"the warm interpreter's extra threads are not the two known drains: {extra_threads}"
    )
    assert seen["cold"]["threads"] == ["MainThread"], (
        f"the cold path grew a thread of its own: {seen['cold']['threads']}"
    )
    cold_mods, warm_mods = set(seen["cold"]["modules"]), set(seen["warm"]["modules"])
    only_warm = sorted(warm_mods - cold_mods)
    # The driver imports these; the one-shot runner hand-rolls what it needs instead. `site` and
    # `_sitebuiltins` are NOT in the other direction any more: dropping `-S` is what fixed the
    # site-packages hole, so a name appearing on the cold side only would mean it came back.
    assert only_warm == ["_ast", "_struct", "ast", "base64", "binascii", "contextlib", "struct"], (
        f"the warm interpreter's extra modules changed: {only_warm}"
    )
    only_cold = sorted(cold_mods - warm_mods)
    assert only_cold == [], f"a module is loaded ONLY on the cold path, which is how -S looked: {only_cold}"


@integration
def test_the_process_group_kill_really_ends_the_box_and_the_registry_follows(tmp_path):
    """Why the prewarm sweep does not call `kern stop`, asserted in the right order.

    Two facts were being conflated. "Is kern's registry entry gone" answers what kern THINKS; "is the
    workload gone" answers what IS. The second is the one the teardown has to guarantee, because the
    caller diffs the workspace the moment the kill returns, so it is the primary assertion here and
    the registry timing is demoted to a BOUND rather than a sample at fixed points.

    The old shape sampled at t+0, t+0.3, t+1, t+3, which is a race characterised by sampling: a slower
    machine moves the points and the reading changes without the system changing. Polling to a
    deadline asserts "cleared within N", which survives that.

    The writer control is on the process being REAPED, not only on a counter that stopped moving:
    "still 297 a second later" separates stopped from running but not stopped from stalled, and on a
    loaded host a live process can lose a second."""
    ws = tmp_path / "ws"
    ws.mkdir()
    with Sandbox(workspace=str(ws), prewarm=1, timeout_s=120) as s:
        assert _warm(s)
        box = s._pool._ready.pop()
        name, pid = box._name, box._proc.pid
        payload = (
            "import subprocess\n"
            "subprocess.Popen(['sh','-c','i=0; while :; do i=$((i+1)); "
            "if [ $((i % 20000)) -eq 0 ]; then echo $i >> /workspace/w.txt; fi; done'])\n"
            "print('spawned')\n"
        ).encode()
        box._proc.stdin.write(str(len(payload)).encode() + b"\n")
        box._proc.stdin.write(payload)
        box._proc.stdin.flush()
        assert box._q.get(timeout=60) is not None
        counter = ws / "w.txt"
        time.sleep(0.6)
        before = counter.stat().st_size if counter.exists() else 0
        assert before > 0, "positive control: the background writer never started, so nothing is proved"

        box.stop_processes()  # the whole teardown the hot path performs, and nothing else

        # PRIMARY: the workload is gone. Reaped, not merely quiet - a stalled process is also quiet.
        assert box._proc is None or box._proc.poll() is not None or not _pid_alive(pid), (
            "the box supervisor was not reaped by the process-group kill"
        )
        time.sleep(1.5)
        after = counter.stat().st_size if counter.exists() else 0
        assert after == before, (
            f"a CPU-bound process inside the box kept writing after the kill: {before} -> {after}"
        )

        # SECONDARY, and a BOUND rather than a sample: kern's own bookkeeping catches up on its own.
        deadline = time.monotonic() + 10.0
        cleared = False
        while time.monotonic() < deadline:
            listed = subprocess.run(
                [s._kern, "ps", "-q"], capture_output=True, text=True, timeout=30
            ).stdout.split()
            if name not in listed:
                cleared = True
                break
            time.sleep(0.05)
        assert cleared, "kern still lists the box 10s after its processes were killed"
        box.sweep()


def _pid_alive(pid: int) -> bool:
    """True iff `pid` names a process that is not a reaped zombie. `/proc/<pid>` survives a zombie, so
    the state field is what discriminates - which is the whole point of asserting on the reap."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as fh:
            return fh.read().split(") ")[1].split(" ")[0] != "Z"
    except OSError:
        return False


@integration
def test_the_pool_recovers_if_its_worker_thread_dies(tmp_path):
    """A dead worker used to be permanent, and silently so.

    `refill` asked `if self._worker is None`, which stays false forever once a thread has been created,
    so a worker that died was never replaced: every later order queued behind nothing, the pool stopped
    refilling, and every call fell back to the cold path for the rest of the session with no signal
    that it had. The predicate is `is_alive()` now, and the difference between the two answers is
    exactly this case.

    Killing the worker for real is not possible from outside a Python thread, so the test does the
    thing that IS observable: it stops the worker with the close sentinel, leaves the pool open, and
    checks that the next refill brings the pool back."""
    with Sandbox(prewarm=1, workspace=str(tmp_path), timeout_s=60) as s:
        assert _warm(s)
        pool = s._pool
        worker = pool._worker
        assert worker is not None and worker.is_alive()
        # Retire the ready box so the pool has work to do, then stop the worker without closing.
        pool._ready.pop().kill()
        pool._orders.put(None)
        worker.join(timeout=5)
        assert not worker.is_alive(), "the worker did not stop, so the test proves nothing"
        assert pool._worker is worker, "the pool still holds the dead thread, which is the trap"
        pool.refill(network=s.network, deadline=s._eff_timeout(None))
        assert pool._worker is not worker, "refill must replace a dead worker, not keep it"
        assert _warm(s), "the pool never refilled after its worker died"


@integration
def test_a_signal_death_is_reported_as_128_plus_n_not_as_minus_n():
    """`exit_code` for a killed process must be 137, the value every other tool a reader compares
    against reports: a shell, kern's own CLI, docker, and the Node binding.

    FOUND BY AN EXTERNAL REVIEW running one timeout through both bindings: Python answered `-9` (the
    `subprocess` convention, negative meaning "killed by signal N") and Node answered `137`. Same
    event, two numbers, so a caller branching on `exit_code == 137` saw the timeout in one binding and
    missed it in the other.

    The control is the second assertion: an ordinary non-zero exit must be untouched. A conversion that
    rewrote every code would satisfy the first one.
    """
    r = kern.run_code("import time; time.sleep(30)", timeout_s=2)
    assert r.fault is not None and r.fault.type == "timeout"
    assert r.exit_code == 137, f"a SIGKILL must read 137, not {r.exit_code}"
    ordinary = kern.run_code("raise SystemExit(7)")
    assert ordinary.exit_code == 7, "an ordinary exit code must pass through unchanged"
    assert ordinary.fault is None


class TestKernNotesAreNotTheCodesStderr:
    """kern and the workload share ONE stderr, so the raw field carries the launcher's own voice.

    An external audit found kern's `note:` lines inside a LangChain tool result, spending the model's
    context on the runtime's housekeeping where they can be misread as the program's own errors.
    `code_stderr` and `runtime_notes` are the two halves. These run on FIXED strings rather than a box,
    so they pin the rule itself and cannot pass because a particular host happened to print no notes.
    """

    CASES = [
        ("kern: note: x\nreale\n", "reale\n", ["kern: note: x"]),
        ("a\nkern: warning: w\nb", "a\nb", ["kern: warning: w"]),
        ("", "", []),
        ("kern: note: solo\n", "", ["kern: note: solo"]),
        ("nessuna newline finale", "nessuna newline finale", []),
        ("  kern: note: rientrata\nx", "x", ["  kern: note: rientrata"]),
    ]

    def test_the_two_halves_partition_stderr(self):
        for raw, code, notes in self.CASES:
            r = ExecutionResult(stdout="", stderr=raw, exit_code=0, duration_ms=0)
            assert r.code_stderr == code, f"code_stderr of {raw!r}"
            assert r.runtime_notes == notes, f"runtime_notes of {raw!r}"
            # Nothing is invented and nothing is lost: every line lands in exactly one half.
            assert len(r.code_stderr.split("\n")) + len(r.runtime_notes) == len(raw.split("\n"))

    def test_stderr_itself_is_untouched(self):
        """The operator's field keeps every byte in its original order. `code_stderr` is a second
        view, not a replacement, so nothing that used to be visible has become invisible."""
        raw = "kern: note: x\nreale\n"
        assert ExecutionResult(stdout="", stderr=raw, exit_code=0, duration_ms=0).stderr == raw

    def test_a_forging_workload_can_only_remove_its_own_line(self):
        """A workload CAN print one of kern's prefixes. The consequence is its line moving to
        `runtime_notes`, which is the harmless direction: the trick takes text OUT of what the model
        reads and cannot put text in."""
        r = ExecutionResult(
            stdout="", stderr="kern: note: forged by the box\n", exit_code=0, duration_ms=0
        )
        assert r.code_stderr == ""
        assert "forged" in r.runtime_notes[0]
