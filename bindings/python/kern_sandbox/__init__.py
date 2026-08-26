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
    not two Sandbox-like surfaces that drift apart. (# DECISION, reviewer-ratified.)
  * I/O is HOST-DIRECT: the workspace is a host dir and single-uid maps box-root to the host user, so
    files the box creates are host-owned - write_file/read_file are plain host filesystem I/O, no
    `kern cp`, no in-box shim. (`--uid-range` breaks this ownership and is OUT of v1 scope. # DECISION.)

Threat model (honest): kern is a KERNEL-BOUNDARY sandbox for YOUR OWN or SEMI-TRUSTED code. seccomp
is a DENYLIST - suitable for semi-trusted agent code, NOT a hard boundary against deliberately hostile
multi-tenant code (for that: a microVM / gVisor). A deny-by-default seccomp allowlist ships opt-in:
pass security_profile="untrusted" (or KERN_SECCOMP=allowlist).
"""

from __future__ import annotations

import base64
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

__version__ = "0.1.27"

# DECISION: default image is a small Python base. Criterion "import pandas with no setup" needs a
# batteries-included image; for v1 we start from a PUBLIC image and let `setup=` bake deps, rather than
# building+hosting our own (reviewer-ratified FLAG 4). Ship a datascience default when demand justifies.
_DEFAULT_IMAGE = "python:3.12-slim"

_WORKSPACE = "/workspace"  # where the persistent workspace is mounted inside every box
_DEPS_DIR = ".deps"  # pip --target dir inside the workspace (added to PYTHONPATH for run_code)
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
# {stdout, stderr, rc, results:[mime-bundle,...]}. User prints go to a buffer, never the real stdout, so
# the control channel stays clean. Any per-cell error is confined; the driver keeps serving.
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
_CAP = 64 * 1024 * 1024
_MARK = b"\x00\x01KRNCELLDONE\x01\x00"  # per-cell barrier sentinel written to user fd 1/2 after exec
_ulock = threading.Lock()
_ubuf = {1: bytearray(), 2: bytearray()}
_mevt = {1: threading.Event(), 2: threading.Event()}
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
while True:
    _code = _read()
    if _code is None:
        break
    _out.clear()
    with _ulock:
        _m1, _m2 = len(_ubuf[1]), len(_ubuf[2])
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
    _write({
        "stdout": _so.getvalue() + _r1.decode("utf-8", "replace"),
        "stderr": _se.getvalue() + _r2.decode("utf-8", "replace"),
        "rc": _rc,
        "results": list(_out),
    })
'''

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

    type: Literal["timeout", "oom", "escape_blocked", "killed", "startup_failed"]
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
    can both stream and read ``result.stdout``. A callback exception is swallowed: it must never kill the
    drain, or the box would deadlock on a full pipe."""

    def __init__(self, pipe, cap: int, on_data=None) -> None:
        super().__init__(daemon=True)
        self._pipe = pipe
        self._cap = cap
        self._on_data = on_data
        self.buf = bytearray()
        self.truncated = False

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
                    except Exception:  # noqa: BLE001 - a user callback must not break the drain
                        pass
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


def _find_kern() -> str:
    """Locate ``kern``: ``$KERN_BIN`` if set, else the first ``kern`` on ``$PATH``."""
    env = os.environ.get("KERN_BIN")
    if env:
        if not (Path(env).is_file() and os.access(env, os.X_OK)):
            raise SandboxError(f"$KERN_BIN='{env}' is not an executable file")
        return env
    found = shutil.which("kern")
    if not found:
        raise SandboxError(
            "the `kern` binary was not found on PATH - install it "
            "(https://github.com/getkern/kern) or set $KERN_BIN"
        )
    return found


def _validate_mount(source: str, target: str) -> tuple[str, str]:
    """Validate one host->box mount; refuse unsafe sources/targets. Returns (abs_real_source, target)."""
    if not target.startswith("/"):
        raise MountRefused(f"mount target must be an absolute path in the box, got {target!r}")
    if any(c == ".." for c in target.split("/")):
        raise MountRefused(f"mount target must not contain '..': {target!r}")
    norm_target = "/" + "/".join(c for c in target.split("/") if c and c != ".")
    if norm_target in ("/", "/proc", "/sys", "/dev"):
        raise MountRefused(f"cannot mount over the box essential mount {norm_target!r}")
    src = Path(source)
    if not src.is_absolute():
        raise MountRefused(f"mount source must be an absolute host path, got {source!r}")
    real = os.path.realpath(source)  # resolve symlinks BEFORE the sensitive-set check
    if real in _REFUSED_MOUNT_SOURCES or real == os.path.realpath(os.path.expanduser("~")):
        raise MountRefused(
            f"refusing to mount the sensitive host path {real!r} into a sandbox "
            "(this would defeat the isolation)"
        )
    if not Path(real).exists():
        raise MountRefused(f"mount source does not exist: {source!r}")
    return real, target


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
    deps_readonly: bool = False  # mount setup= deps read-only for run_code (block cross-run poisoning)
    # track_files=True populates result.files by walking the workspace before AND after each call, which
    # is O(workspace file count): a long session that accumulates thousands of files makes every run_code
    # slower. Set False (result.files always []) when you don't need the per-call file diff - O(1) then.
    track_files: bool = True
    # live output callbacks: called with each raw chunk (bytes) as it arrives, in a reader thread. The
    # full capped output is still captured in the result, so you can stream AND read result.stdout.
    on_stdout: "Callable[[bytes], None] | None" = None
    on_stderr: "Callable[[bytes], None] | None" = None

    _kern: str = field(default="", repr=False)
    _mount_args: list = field(default_factory=list, init=False, repr=False)
    _profile_args: list = field(default_factory=list, init=False, repr=False)
    _egress_allow: list = field(default_factory=list, init=False, repr=False)
    _cap_drop_args: list = field(default_factory=list, init=False, repr=False)
    _ws: str = field(default="", init=False, repr=False)
    _own_ws: bool = field(default=False, init=False, repr=False)  # we created it → we delete it
    _entered: bool = field(default=False, init=False, repr=False)
    # The workspace files this binding put there itself, by exact name. See `_claim`.
    _ours: set = field(default_factory=set, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.timeout_s is None or self.timeout_s <= 0:
            raise SandboxError("timeout_s must be a positive number of seconds")
        if self.max_output_bytes <= 0:
            raise SandboxError("max_output_bytes must be positive")
        self._mount_args = []
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
        if self._egress_allow and self.network:
            raise SandboxError(
                "egress_allow and network=True are mutually exclusive: egress_allow gives a restricted "
                "domain allowlist for run_code, network=True gives the full host network"
            )
        self._kern = _find_kern()

    # -- lifecycle -----------------------------------------------------------------------------------

    def __enter__(self) -> "Sandbox":
        if self.workspace is None:
            self._ws = os.path.realpath(tempfile.mkdtemp(prefix="kern-ws-"))
            self._own_ws = True
        else:
            # A caller-supplied workspace is host input → validate it like a mount source, and DON'T
            # delete it on exit (its contents persist across sessions - documented). Create it FIRST so
            # a fresh persistent path is usable on the first run: mkdir is a no-op on an existing
            # sensitive source (e.g. /etc), which _validate_mount then still refuses.
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
        return self

    def __exit__(self, *exc: object) -> None:
        if self._own_ws and self._ws:
            shutil.rmtree(self._ws, ignore_errors=True)
        self._entered = False

    def _require_entered(self) -> None:
        if not self._entered:
            raise SandboxError("use the Sandbox as a context manager: `with Sandbox() as s: ...`")

    # -- the box invocation --------------------------------------------------------------------------

    def _base_argv(self, name: str, *, network: bool, timeout_s: int, is_setup: bool = False) -> list[str]:
        argv = [self._kern, "box", name, "--image", self.image, "--ro", "-v", f"{self._ws}:{_WORKSPACE}",
                "--workdir", _WORKSPACE]
        # deps_readonly: mount <workspace>/.deps read-only OVER the writable workspace for run_code boxes
        # (not the setup box, which must populate it). Closes the cross-run dep-poisoning window within a
        # session for tighter (still semi-trusted) workloads. Default off - deps writable, documented.
        if self.deps_readonly and not is_setup:
            deps = os.path.join(self._ws, _DEPS_DIR)
            if os.path.isdir(deps):
                argv += ["-v", f"{deps}:{_WORKSPACE}/{_DEPS_DIR}:ro"]
        # kern's own --timeout is a tight BACKSTOP just beyond our deadline: it is the RELIABLE killer of
        # the in-PID-namespace box (a CPU-bound box survives a SIGKILL of kern's parent process, but not
        # kern's own timeout teardown). OUR proc.wait deadline is the authority that LABELS a `timeout`
        # fault; kern's backstop guarantees the box is actually gone a few seconds later.
        argv += self._cap_drop_args
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
        merged_env = dict(self.env or {})
        # Deps installed by `setup` live in <workspace>/.deps - put them on PYTHONPATH for run_code.
        merged_env.setdefault("PYTHONPATH", f"{_WORKSPACE}/{_DEPS_DIR}")
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
        if merged_env and self._ws:
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
        box_started = False
        cap_signal = 0  # 2nd started byte: 0 undetermined/old-kern, 1 memory cap enforced, 2 not enforced
        try:
            try:
                # start_new_session so the box + kern share a process group we can signal as a unit.
                proc = subprocess.Popen(  # noqa: S603 - argv list, no shell
                    argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=child_env,
                    start_new_session=True, pass_fds=(started_w,),
                )
            except FileNotFoundError as e:
                raise SandboxError(f"could not execute kern: {e}") from e
            except OSError as e:
                # E2BIG (argv too long) and other spawn-time OS errors → a clean typed error, not a raw
                # OSError leaking out of the binding. (run_code already routes large code via a file.)
                raise SandboxError(f"could not spawn the box: {e}") from e
            finally:
                os.close(started_w)  # the parent never writes; closing lets the read side see EOF
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
            try:
                sig = os.read(started_r, 2)
            except OSError:
                sig = b""
            box_started = len(sig) >= 1 and sig[0] == 1
            cap_signal = sig[1] if len(sig) >= 2 else 0
        finally:
            # Every exit path, including the two SandboxErrors above: kern has read the file by the time
            # it exits, and leaving it behind would accrete one per call in a persistent workspace.
            try:
                os.unlink(self._env_path(name))
                self._release(os.path.basename(self._env_path(name)))
            except OSError:
                pass
            try:
                os.close(started_r)
            except OSError:
                pass
        wall_ms = int((time.monotonic() - started) * 1000)
        stdout = out.buf.decode("utf-8", "replace")
        stderr = err.buf.decode("utf-8", "replace")
        rc = proc.returncode if proc.returncode is not None else -1
        fault = self._classify(rc, stderr, we_timed_out, timeout_s, cap_signal)
        if box_started and fault is not None and fault.type == "startup_failed":
            # kern signalled the box STARTED, so a `startup_failed` here can only be the stderr heuristic
            # matching a marker the WORKLOAD wrote (the code-based faults are decided before it). The box
            # demonstrably ran: this is the workload's own non-zero exit - reclassify to a normal result.
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
            return SandboxFault("timeout", f"exceeded the {limit}s time limit (killed by the binding)")
        if rc == _EXIT_SIGSYS:
            # A seccomp-denied syscall. Decided by exit code, so no stderr content can mask it.
            return SandboxFault("escape_blocked", "a syscall was blocked by the seccomp filter (SIGSYS)")
        if rc == _EXIT_SIGKILL or rc == -signal.SIGKILL:
            # SIGKILL not from our deadline: exit 137 (128+9), or subprocess's -9 if kern itself was
            # signalled. A memory-capped box SIGKILLed is the cgroup OOM-killer - precisely what a
            # breached `memory.max` does (kern sets `memory.oom.group=1`, so the whole box dies at once).
            # `cap_signal` is kern's UNFORGEABLE per-box enforcement byte (2nd byte of KERN_STARTED_FD, so
            # not the workload's stderr - the order-is-a-security-property discipline holds): 1 = the cap
            # was enforced, 2 = requested but NOT enforced here (no cgroup delegation), 0 = undetermined
            # (an older kern, or no `--memory`). We claim `oom` when a `--memory` cap was set AND kern did
            # not report it unenforced (`cap_signal != 2`): enforced (1) is a certain cgroup OOM, and
            # undetermined (0) keeps the pre-signal heuristic for older kerns. When kern reports the cap
            # did NOT bind (2), a SIGKILL cannot be attributed to the box's cgroup - it is host memory
            # pressure or an external kill - so we do not overclaim `oom` and keep the honest `killed`.
            if self.memory_mb is not None and cap_signal != 2:
                return SandboxFault("oom", "the box exceeded its memory cap and was OOM-killed (SIGKILL)")
            if cap_signal == 2:
                return SandboxFault(
                    "killed",
                    "the box was SIGKILLed, but its memory cap was not enforced here (no cgroup "
                    "delegation), so it is not attributed to a cgroup OOM",
                )
            return SandboxFault("killed", "the box was killed (SIGKILL); no memory cap was set to attribute it to OOM")
        if rc in (_EXIT_SIGTERM, -signal.SIGTERM):
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
            return SandboxFault("startup_failed", stderr.strip()[:500])
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
            raise SandboxError(f"cannot write {path!r}: {e}") from e
        with os.fdopen(fd, "wb") as f:
            f.write(payload)

    def _open_nofollow(self, full: str, flags: int, mode: int = 0o644) -> int:
        """Open ``full`` (already lexically contained) descending from the workspace base ONE component at
        a time, each with ``O_NOFOLLOW`` via ``openat``, so a symlink the box planted in ANY component -
        not just the last - can't redirect host I/O outside the workspace. This also closes the TOCTOU a
        plain lstat-then-open would leave. Returns an fd (caller owns it)."""
        base = self._ws
        rel = os.path.relpath(full, base)
        parts = [p for p in rel.split(os.sep) if p and p != "."]
        if not parts:
            raise SandboxError("refusing to open the workspace root as a file")
        cloexec = getattr(os, "O_CLOEXEC", 0)
        dir_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | cloexec)
        try:
            for part in parts[:-1]:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | cloexec, dir_fd=dir_fd)
                os.close(dir_fd)
                dir_fd = nxt
            return os.open(parts[-1], flags | os.O_NOFOLLOW | cloexec, mode, dir_fd=dir_fd)
        finally:
            os.close(dir_fd)

    def read_file(self, path: str, *, max_bytes: "int | None" = None) -> bytes:
        """Read ``path`` (workspace-relative) from the workspace - host-direct. Every path component is
        opened O_NOFOLLOW (via ``openat`` descent), so a symlink the box planted in the final OR an
        intermediate component can't redirect the read outside the workspace. ``max_bytes`` caps the read:
        if the file is larger, ``SandboxError`` is raised rather than loading it all into host RAM (use it
        when reading a file a box you don't fully trust may have written)."""
        self._require_entered()
        full = self._ws_path(path)
        try:
            fd = self._open_nofollow(full, os.O_RDONLY)
        except OSError as e:
            raise SandboxError(f"cannot read {path!r}: {e}") from e
        with os.fdopen(fd, "rb") as f:
            if max_bytes is None:
                return f.read()
            data = f.read(max_bytes + 1)  # one past the cap so we can tell "exactly at" from "over"
            if len(data) > max_bytes:
                raise SandboxError(f"{path!r} exceeds max_bytes={max_bytes}")
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
                raise SandboxError(f"cannot list {subdir!r}: {e}") from e
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
                if m.name.startswith("/") or ".." in m.name.split("/"):
                    raise SandboxError(f"unsafe path in snapshot: {m.name!r}")
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
        # DECISION (reviewer-ratified C): the network is ON only here, in a SEPARATE setup box that
        # dies at the end. It installs into <workspace>/.deps; every run_code box is network-off.
        install = f"pip install --target {_WORKSPACE}/{_DEPS_DIR} --no-cache-dir --disable-pip-version-check"
        # If the caller gave a bare `pip install X`, route it to the deps dir; else run as-is (net-on).
        shell_cmd = cmd
        if cmd.strip().startswith("pip install "):
            shell_cmd = install + " " + cmd.strip()[len("pip install ") :]
        r = self._spawn(["sh", "-c", shell_cmd], network=True, timeout_s=max(self.timeout_s, 120), is_setup=True)
        if not r.success:
            raise SandboxError(f"setup failed (exit {r.exit_code}): {(r.stderr or r.stdout).strip()[:400]}")

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
    _LANGS = {
        "python": ("python3", "-c", "py"),
        "bash": ("sh", "-c", "sh"),
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
        language: Literal["python", "bash", "node"] = "python",
        timeout_s: "int | float | None" = None,
        on_stdout: object = _UNSET,
        on_stderr: object = _UNSET,
    ) -> ExecutionResult:
        """Run a snippet of ``code`` on the workspace in a fresh, network-off box. File state written to
        the workspace persists to the next call; in-memory state does NOT (fresh process each time).
        ``language`` is ``"python"`` (default), ``"bash"``, or ``"node"`` (the image must provide the
        interpreter). Large code is written to a workspace file and executed from there (transparent to
        the caller), so an arbitrarily large script works instead of hitting the argv length limit.

        ``timeout_s``, ``on_stdout`` and ``on_stderr`` override the session defaults for THIS call only:
        ``timeout_s=None`` inherits the constructor's deadline, a number sets a per-call one; the stream
        callbacks default to the session's, an explicit ``None`` disables them for this call."""
        self._require_entered()
        spec = self._LANGS.get(language)
        if spec is None:
            raise SandboxError(f"unsupported language {language!r} (v1: 'python' | 'bash' | 'node')")
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
                timeout_s=self._eff_timeout(timeout_s),
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
        # Read end of kern's KERN_STARTED_FD channel. For a RESIDENT box kern writes it only at box
        # teardown (the box exits), i.e. when a cell kills the kernel - so it is read ONCE, bounded, on
        # death (see `_read_cap_signal`), never while the box is live (that would block).
        self._started_r = -1

    def __enter__(self) -> "Kernel":
        sbx = self._sbx
        sbx._require_entered()
        uid = uuid.uuid4().hex[:8]
        self._driver = sbx._claim(f".kernel-{uid}.py")
        sbx.write_file(self._driver, _PY_KERNEL_DRIVER)
        self._name = _unique_name()
        argv = sbx._base_argv(self._name, network=sbx.network, timeout_s=self._BACKSTOP_S) + [
            "--",
            "python3",
            "-S",
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
            raise SandboxError("kernel is dead (a prior cell timed out, or the box exited)")
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
            fault, default = self._kernel_death_fault(err, self._read_cap_signal())
            return self._teardown_result(fault, err.strip() or default, started)
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
            fault, default = self._kernel_death_fault(err, self._read_cap_signal())
            return self._teardown_result(fault, err.strip() or default, started)
        return self._result_from_reply(reply, started)

    def _read_cap_signal(self) -> int:
        """kern's memory-cap enforcement byte for the resident box, read ONCE on kernel death. kern
        writes the two-byte KERN_STARTED_FD signal only at the box's teardown (a resident box exits when
        a cell kills it), so this is called from the death paths above and NEVER while the box is live
        (that read would block). Bounded: `select` waits up to 2 s for kern to reap the box and close the
        fd, then reads. Returns 0 (undetermined -> the memory_mb heuristic stands) on EOF (an older kern),
        timeout, or any error, so a missing signal only ever falls back, never blocks or raises."""
        if self._started_r < 0:
            return 0
        try:
            ready, _, _ = select.select([self._started_r], [], [], 2.0)
            if not ready:
                return 0
            sig = os.read(self._started_r, 2)
        except OSError:
            return 0
        return sig[1] if len(sig) >= 2 else 0

    def _kernel_death_fault(self, err: str, cap_signal: int = 0) -> "tuple[str, str]":
        """Why the resident kernel box died mid-cell, and a default message. A kern setup marker on
        stderr means it never came up (``startup_failed``). Otherwise this is the ``run_code`` counterpart
        of the one-shot :meth:`_classify` SIGKILL branch - a kernel death has no per-cell exit code, so
        the OOM attribution lives here. ``cap_signal`` is kern's UNFORGEABLE enforcement byte (0 = old
        kern / undetermined, 1 = memory cap enforced, 2 = requested but NOT enforced): with a ``--memory``
        cap in force AND not-reported-unenforced (``!= 2``), the cgroup OOM-killer is the cause -> ``oom``;
        when kern reports the cap did not bind (``2``) the kill cannot be attributed to the box's cgroup
        -> ``killed``; uncapped is also ``killed``."""
        if _looks_like_startup_failure(err):
            return "startup_failed", "the kernel box failed to start"
        if self._sbx.memory_mb is not None and cap_signal != 2:
            return "oom", "the kernel box was OOM-killed (it exceeded its memory cap)"
        if cap_signal == 2:
            return (
                "killed",
                "the kernel box was SIGKILLed, but its memory cap was not enforced here (no cgroup "
                "delegation), so it is not attributed to a cgroup OOM",
            )
        return "killed", "the kernel box exited"

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

    def _teardown_result(self, kind: str, msg: str, started: float) -> ExecutionResult:
        self._kill()
        # Same rule as the one-shot path: a box that never STARTED (the kernel failed to boot) raises,
        # it does not return a hollow result. timeout/killed stay as data.
        if kind == "startup_failed":
            raise SandboxError(msg or "the box failed to start")
        return ExecutionResult(
            stdout="",
            stderr="",
            exit_code=-1,
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


def _unique_name() -> str:
    return "pysbx-" + uuid.uuid4().hex[:12]


def _looks_like_startup_failure(stderr: str) -> bool:
    """True iff kern (the PARENT, before the box exists) failed to start the box. Anchored on kern's own
    diagnostic prefixes - printed by kern, not by the workload - so the workload can't forge them by
    writing the marker to its own stderr. (Same discipline as the tar vetter: don't trust text the
    adversary controls; kern's setup errors precede any workload output and carry kern's prefixes.)"""
    markers = (
        "kern:",
        "error: pull:",
        "error: curl failed:",
        "error: registry:",
        "error: manifest:",
        "error: sandbox:",
        "error: box:",
        "error: oci:",
        "error: image:",
    )
    # kern also writes BENIGN `kern:` diagnostics to stderr that are NOT a box-start failure: the
    # `--security-profile` posture banner, and `warning:`/`note:` lines. They start with `kern:` too, so
    # without this skip a workload that merely exits non-zero WHILE one is on stderr (e.g. code run under
    # `security_profile="untrusted"` that hits a network error) would be mislabeled `startup_failed`.
    benign = ("kern: security-profile=", "kern: warning:", "kern: note:")
    for line in stderr.splitlines():
        s = line.lstrip()
        if s.startswith(benign):
            continue
        if "sandbox setup failed" in s or any(s.startswith(m) for m in markers):
            return True
    return False


def run_code(
    code: str, *, language: Literal["python", "bash", "node"] = "python", **kwargs: object
) -> ExecutionResult:
    """One-shot convenience: run ``code`` in a throwaway session (workspace created and deleted). This is
    literally ``with Sandbox(**kwargs) as s: return s.run_code(code)`` - one tested code path, no state
    persists. For multi-step work (write a file, then read it), use ``Sandbox`` as a context manager."""
    with Sandbox(**kwargs) as s:  # type: ignore[arg-type]
        return s.run_code(code, language=language)
