/**
 * kern-sandbox - run LLM/agent-generated code in a fast, local, daemonless kernel sandbox.
 *
 *   const kern = require('kern-sandbox');
 *
 *   // one-shot (a throwaway session under the hood)
 *   const r = await kern.runCode("console.log(1 + 1)", { language: "node" });
 *   console.log(r.stdout, r.success);
 *
 *   // a session: FILE state persists across steps; processes are ephemeral
 *   await kern.withSandbox({ setup: "pip install pandas" }, async (sbx) => {
 *     await sbx.writeFile("data.csv", csvBytes);
 *     const r = await sbx.runCode("import pandas as pd; print(pd.read_csv('data.csv').shape)");
 *     const png = await sbx.readFile("out.png");
 *   });
 *
 * Design mirrors the Python binding exactly:
 *   - FILE state persists via a workspace DIRECTORY on the host, bind-mounted into each box.
 *     PROCESSES are ephemeral: every runCode()/run() spawns a FRESH box on that shared workspace.
 *     In-memory state does NOT survive between calls; write to disk for continuity.
 *   - I/O is HOST-DIRECT: single-uid maps box-root to the host user, so files the box creates are
 *     host-owned; writeFile/readFile are plain host filesystem I/O.
 *   - The BINDING owns the timeout (it kills the box), so a `timeout` fault is a known fact.
 *
 * Threat model (honest): kern is a KERNEL-BOUNDARY sandbox for YOUR OWN or SEMI-TRUSTED code. seccomp
 * is a DENYLIST - suitable for semi-trusted agent code, NOT a hard boundary against deliberately
 * hostile multi-tenant code (for that: a microVM / gVisor).
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");
const { spawn, spawnSync } = require("child_process");

const VERSION = "0.1.36";

const DEFAULT_IMAGE = "python:3.12-slim";
const WORKSPACE = "/workspace"; // where the persistent workspace is mounted inside every box
const DEPS_DIR = ".deps"; // pip --target dir inside the workspace (added to PYTHONPATH for python)
const ENV_FILE = ".kern-env"; // host-side 0600 env file (kept out of argv so values don't show in `ps`)
// One file per CALL, `.kern-env.<box-name>`. A single fixed name made concurrent calls on the same
// Sandbox fight over one path: one call `unlink`ed the file while kern was still starting for
// another and had not read it yet, and that box died with
//   error: sandbox: cannot read --env-file '...': No such file or directory
// Measured at 30 concurrent runCode calls: 2 failed that way, and one file was left behind.
// The `O_EXCL|O_NOFOLLOW` create is a security property and is unchanged; only the NAME is per-call.
const ENV_SEP = ".";
const INLINE_CODE_MAX = 128 * 1024; // above this, pass code via a file instead of argv (ARG_MAX guard)
// Cap the results file the (untrusted) box writes before the binding reads it into host RAM: a malicious
// cell could stream a multi-GB `.res` to disk (past its own memory cap) and OOM the host.
const RESULTS_MAX = 64 * 1024 * 1024; // 64 MiB: generous for charts/tables, bounds the attacker read

// Python cell runner (P1: rich mime-typed results, Jupyter/E2B-style, no Jupyter kernel). Runs INSIDE
// the box (it is Python, regardless of which binding drove it): execs the user cell, then captures the
// trailing bare expression's value, every display(obj) call, and every open matplotlib figure, writing
// them as a JSON mime-bundle list the binding reads back. stdout/stderr/exit are UNTOUCHED. On the hot
// path it imports only C builtins (no .py to recompile in the read-only slim box); base64/io/traceback/
// json are lazy. Mirrors the Python binding's runner. __KERN_CELL__/__KERN_RES__ are substituted per call.
const PY_RUNNER = `
import sys, builtins  # C builtins: no .py to recompile in the read-only slim box (the P1 hot path).
_CELL = "__KERN_CELL__"
_RES = "__KERN_RES__"
_out = []
def _js(s):  # minimal JSON string encoder, so the box needs no \`import json\` (~80ms in a pyc-less slim box)
    r = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            r.append('\\\\"')
        elif ch == '\\\\':
            r.append('\\\\\\\\')
        elif o == 10:
            r.append('\\\\n')
        elif o == 13:
            r.append('\\\\r')
        elif o == 9:
            r.append('\\\\t')
        elif o < 32:
            r.append('\\\\u%04x' % o)
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
                    import json
                    d["application/json"] = json.dumps(v)
    except Exception:
        pass
    for meth, key in (("_repr_png_", "image/png"), ("_repr_jpeg_", "image/jpeg")):
        try:
            fn = getattr(o, meth, None)
            if callable(fn):
                v = fn()
                if v:
                    import base64
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
sys.argv = [_CELL]
_g = {"__name__": "__main__", "__file__": _CELL, "display": display}
_rc = 0
try:
    _src = open(_CELL, "r", encoding="utf-8").read()
    _tree = compile(_src, _CELL, "exec", 0x400)
    _tail = None
    if _tree.body and type(_tree.body[-1]).__name__ == "Expr":
        _n = _tree.body.pop()
        _lines = _src.split("\\n")
        if _n.lineno == _n.end_lineno:
            _tail = _lines[_n.lineno - 1].encode()[_n.col_offset:_n.end_col_offset].decode("utf-8", "replace")
        else:
            _seg = [_lines[_n.lineno - 1].encode()[_n.col_offset:].decode("utf-8", "replace")]
            _seg += _lines[_n.lineno:_n.end_lineno - 1]
            _seg.append(_lines[_n.end_lineno - 1].encode()[:_n.end_col_offset].decode("utf-8", "replace"))
            _tail = "\\n".join(_seg)
    exec(compile(_tree, _CELL, "exec"), _g)
    if _tail is not None:
        _val = eval(compile(_tail, _CELL, "eval"), _g)
        if _val is not None:
            _out.append(_bundle(_val))
except SystemExit as _e:
    _rc = _e.code if isinstance(_e.code, int) else (0 if _e.code is None else 1)
except BaseException as _e:
    import traceback
    _tb = _e.__traceback__
    while _tb is not None and _tb.tb_frame.f_code.co_filename != _CELL:
        _tb = _tb.tb_next
    sys.stderr.write("".join(traceback.format_exception(type(_e), _e, _tb)))
    _rc = 1
try:
    if "matplotlib.pyplot" in sys.modules:
        import base64, io
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
`;

// Persistent-kernel driver (warm-start: kill the ~10 ms CPython boot). Runs ONCE in a long-lived box and
// then services many cells from one resident process, so in-memory state PERSISTS across cells and the
// per-cell cost drops to sub-millisecond. It is warm, so imports (json/ast/io/base64) are paid once at
// startup, not on any hot path. Protocol on the box's stdin/stdout (length-prefixed frames): host writes
// `<n>\n` + n UTF-8 bytes of cell source; the driver execs it (capturing stdout/stderr into buffers, the
// trailing expression, every display() and matplotlib figure) and writes back `<m>\n` + m UTF-8 bytes of
// {stdout, stderr, rc, results}. User prints go to a buffer, so the control channel stays clean. String.raw
// keeps the single `\n` byte-literal intact (the driver has no backtick or ${...}). Byte-identical to the
// Python binding's _PY_KERNEL_DRIVER so both bindings behave the same.
const PY_KERNEL_DRIVER = String.raw`import sys, io, json, base64, builtins, ast, os, threading
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
    _write({"stdout": _o1, "stderr": _o2, "rc": _rc, "results": _res, "trunc": _tr})`;

// Signal-derived exit codes (128 + signum) we classify.
const EXIT_SIGKILL = 137; // SIGKILL: timeout backstop or OOM (indistinguishable without cgroup)
const EXIT_SIGSYS = 159; // SIGSYS: a seccomp-denied syscall = a blocked escape attempt
const EXIT_SIGTERM = 143; // SIGTERM: kern's --timeout backstop reaping the box

// Per-call kwargs that DEFAULT to the Sandbox value: UNSET means "inherit the constructor's", whereas
// an explicit `null` means "disable" (used for onStdout/onStderr overrides).
const UNSET = Symbol("unset");

// Host paths a `-v` mount must never target - mounting the host's real root/config/secrets into a
// sandbox defeats the point; the docker socket is the classic escape. Refused even when asked.
const REFUSED_MOUNT_SOURCES = new Set([
  "/",
  "/etc",
  "/root",
  "/boot",
  "/proc",
  "/sys",
  "/dev",
  "/var/run/docker.sock",
  "/run/docker.sock",
]);

/** A PROGRAMMER/config error, THROWN: bad argument, illegal mount, `kern` not installed, or the box
 * FAILED TO START (kern exits 125 - a mount refused at runtime, an unmappable `--user`, a seccomp or
 * AppArmor setup error). A box that never started ran no user code, so it rejects rather than resolve a
 * hollow result. Runtime sandbox events where the code DID run (timeout, blocked escape, OOM-kill) are
 * NOT thrown - they are data on `result.fault`. */
class SandboxError extends Error {
  constructor(message) {
    super(message);
    this.name = "SandboxError";
  }
}

/** A requested host mount was refused as unsafe (sensitive source, or a relative/escaping path). */
class MountRefused extends SandboxError {
  constructor(message) {
    super(message);
    this.name = "MountRefused";
  }
}

/** A rich, mime-typed value captured from a Python `runCode` (the way a Jupyter/E2B cell captures
 * output): the value of the code's last bare expression, every `display(obj)` call, and every open
 * matplotlib figure. `data` maps a MIME type to its payload; text/* and application/json are strings,
 * image/* are base64 strings (use `.png`/`.jpeg` for Buffers). One value can carry several forms. */
class Result {
  constructor(data) {
    this.data = data || {};
  }
  get text() {
    return this.data["text/plain"];
  }
  get html() {
    return this.data["text/html"];
  }
  get markdown() {
    return this.data["text/markdown"];
  }
  get svg() {
    return this.data["image/svg+xml"];
  }
  get json() {
    return this.data["application/json"];
  }
  get png() {
    const v = this.data["image/png"];
    return v ? Buffer.from(v, "base64") : null;
  }
  get jpeg() {
    const v = this.data["image/jpeg"];
    return v ? Buffer.from(v, "base64") : null;
  }
  /** The MIME types this value was captured as. */
  formats() {
    return Object.keys(this.data);
  }
}

/** The outcome of one runCode()/run(). `fault` is the source of truth for "did the SANDBOX act";
 * `exitCode`/`stdout` are what the user's code did. `success` requires both clean. */
class ExecutionResult {
  constructor({ stdout, stderr, exitCode, durationMs, fault, files, truncated, results }) {
    this.stdout = stdout;
    this.stderr = stderr;
    this.exitCode = exitCode;
    this.durationMs = durationMs;
    /** @type {{type: string, message: string} | null} */
    this.fault = fault || null;
    this.files = files || [];
    this.truncated = !!truncated;
    /** @type {Result[]} rich mime-typed values (Python runCode) */
    this.results = results || [];
  }
  /** True iff the code exited 0 AND no sandbox fault fired. */
  get success() {
    return this.exitCode === 0 && this.fault === null;
  }
}

/** A sandbox event `{type, message}` for `result.fault`. NB: `startup_failed` is decided from an
 * UNFORGEABLE kern signal (a byte on fd 3 / `KERN_STARTED_FD` a workload can neither write nor
 * suppress). Against a kern too old to send it, the binding falls back to a stderr heuristic that can
 * only OVER-report - a workload can make its own exit look like a start failure - never MISS a real
 * one, so it fails in the safe direction. Pair this binding with the matching (or newer) kern release. */
function sandboxFault(type, message) {
  return { type, message };
}

/** Locate `kern`: $KERN_BIN if set, else the first `kern` on $PATH. */
function findKern() {
  const env = process.env.KERN_BIN;
  if (env) {
    try {
      fs.accessSync(env, fs.constants.X_OK);
      if (!fs.statSync(env).isFile()) throw new Error("not a file");
    } catch {
      throw new SandboxError(`$KERN_BIN='${env}' is not an executable file`);
    }
    return env;
  }
  const exts = [""];
  const dirs = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  for (const d of dirs) {
    for (const ext of exts) {
      const cand = path.join(d, "kern" + ext);
      try {
        fs.accessSync(cand, fs.constants.X_OK);
        if (fs.statSync(cand).isFile()) return cand;
      } catch {
        /* keep looking */
      }
    }
  }
  // On macOS the generic "install it" is a dead end: there is no macOS build to install. kern needs
  // a Linux kernel, so the answer is a VM, and the error says which one rather than leaving the
  // reader hunting for a download that does not exist.
  if (process.platform === "darwin")
    throw new SandboxError(
      "the `kern` binary was not found on PATH, and this is macOS: kern is Linux-only " +
        "(no namespaces, no cgroups on a Mac), so there is no macOS build to find. " +
        "Run inside a Linux VM (colima, Lima, OrbStack, UTM), where kern installs normally, " +
        "or set $KERN_BIN to a kern reachable from here. https://github.com/getkern/kern",
    );
  throw new SandboxError(
    "the `kern` binary was not found on PATH - install it " +
      "(https://github.com/getkern/kern) or set $KERN_BIN",
  );
}

// The box root is read-only (`--ro`, always), so every path a workload can write is one we granted.
// `/tmp` was not granted, and both halves of what that cost were measured rather than assumed:
//   * anything NAMING /tmp fails with EROFS, which is how a toolchain reaches it. Measured on
//     `golang:1.23-alpine`: `go build` reported "failed to initialize build cache at /root/.cache:
//     read-only file system" and printed nothing else useful;
//   * anything using a temp-dir helper silently moves into the WORKSPACE, because the last-resort
//     candidate is the current directory, so temp files land on the caller's persistent host
//     directory and then show up in `listFiles`.
// A tmpfs and not a host bind ON PURPOSE: tmpfs pages are charged to the box's memory cgroup, so a
// runaway writer hits a cap the caller already set; a bound host directory is bounded by nothing.
const DEFAULT_TMPFS_MB = 64;
const DEFAULT_TMPFS = { "/tmp": `${DEFAULT_TMPFS_MB}m` };

// A tmpfs size as kern's `--tmpfs path[:size]` takes it. ANCHORED and unit-restricted: the value is
// concatenated after a colon into one argv element, so anything carrying a comma, a space or a second
// flag is refused here rather than reinterpreted downstream.
//
// THE UNIT IS MANDATORY, and a leading zero is refused, because kern's CLI accepts two spellings that
// mean the opposite of what an SDK caller writing them means. Both measured:
//   * `"64"` is 64 BYTES, not 64 MiB: `df` reports 4 KB and a 100 KB write is ENOSPC.
//   * `"0"` is UNLIMITED, not none: 200 MiB written under `memoryMb: 128` OOM-killed the box (137).
// kern is right to take both, it is the low-level interface; here they fail far from their cause.
const TMPFS_SIZE_RE = /^[1-9][0-9]*[kmgtKMGT]$/;

// A tmpfs over these hides something the box needs, and silently: one at /workspace would shadow the
// workspace bind, so every file the caller wrote would stay on the host and none would be visible.
const REFUSED_TMPFS_TARGETS = new Set(["/", "/proc", "/sys", "/dev", WORKSPACE]);

/** Validate one in-box tmpfs; returns the normalised `[target, size]`. The caller composes the
 * argument, because the size still has to be resolved against the memory cap and that resolution
 * PARSES it, so it may only run on a value this function has already accepted. */
function validateTmpfs(target, size) {
  if (typeof target !== "string" || !target.startsWith("/"))
    throw new MountRefused(`tmpfs target must be an absolute path in the box, got ${JSON.stringify(target)}`);
  if (target.split("/").some((c) => c === ".."))
    throw new MountRefused(`tmpfs target must not contain '..': ${JSON.stringify(target)}`);
  // A colon is the SEPARATOR in `--tmpfs path[:size]`, so a path carrying one is reinterpreted
  // rather than rejected. Measured: `tmpfs: ["/scratch:9g"]` mounted `/scratch` at 9 GiB and the
  // directory the caller actually named did not exist in the box. kern cannot fix this without
  // breaking its own syntax; the SDK can refuse.
  if (target.includes(":"))
    throw new MountRefused(
      `tmpfs target must not contain ':': ${JSON.stringify(target)}. It is the size separator in ` +
        "kern's `--tmpfs path[:size]`, so this path would be read as a size and a different " +
        "directory would be mounted.",
    );
  const norm = "/" + target.split("/").filter((c) => c && c !== ".").join("/");
  if (REFUSED_TMPFS_TARGETS.has(norm))
    throw new MountRefused(
      `cannot mount a tmpfs over ${JSON.stringify(norm)}: it would hide the box's own mount there ` +
        "(the workspace bind, or an essential filesystem)",
    );
  if (size === null || size === undefined) return [norm, null];
  if (typeof size !== "string" || !TMPFS_SIZE_RE.test(size)) {
    let hint = "";
    if (typeof size === "string" && /^[0-9]+$/.test(size))
      hint = Number(size) === 0
        ? " A zero size means UNLIMITED to kern, not none: for none, pass tmpfs: {}."
        : " A bare number is BYTES to kern, not MiB: '64' gives a 4 KB filesystem and the first real write is ENOSPC.";
    throw new MountRefused(
      `invalid tmpfs size ${JSON.stringify(size)} for ${JSON.stringify(norm)}: expected a number ` +
        `with a k/m/g/t unit, e.g. '64m'.${hint}`,
    );
  }
  return [norm, size];
}

const TMPFS_UNIT_MIB = { k: 1 / 1024, m: 1, g: 1024, t: 1024 * 1024 };

/** A validated `64m`/`1g` size as MiB. Only ever called after `TMPFS_SIZE_RE` matched. */
function tmpfsMib(size) {
  return parseInt(size.slice(0, -1), 10) * TMPFS_UNIT_MIB[size.slice(-1).toLowerCase()];
}

/** Resolve a scratch size against the memory cap AT CONSTRUCTION, not at the first write.
 *
 * A tmpfs larger than the cap is a number the KERNEL then tells the workload: `df` reports the tmpfs
 * size, so a `"1t"` scratch shows 1.0T free under a 128 MiB cap. Anything that preflights with
 * `statvfs` plans against that and is OOM-killed instead of getting a clean ENOSPC. The wrong answer
 * goes to a PROGRAM, which acts on it, and no message reaches a person.
 *
 * A size the CALLER wrote is refused, naming both numbers; OUR default is clamped, because adjusting
 * a number we chose is not overriding anyone and refusing it would make a box unstartable for someone
 * who never mentioned scratch. The clamp is `min(64 MiB, memoryMb / 2)` and it is a HEURISTIC, not a
 * derivation: it only ever REDUCES our own 64 MiB, so `memoryMb: 512` still gets 64 and not 256.
 * There is no safe fraction to derive, because the safe one depends on the workload's own peak, which
 * is what `memoryMb` was meant to bound and now shares. Half is where the measurement stops being
 * fatal: writing in 1 MiB chunks under `memoryMb: 128`, a 32m and a 64m tmpfs both end in ENOSPC, a
 * 128m one ends in an OOM, because filling a tmpfs equal to the cap exhausts the whole budget. */
function tmpfsSizeVsCap(target, size, memoryMb, ours) {
  if (size === null || size === undefined || memoryMb === null || memoryMb === undefined) return size;
  if (ours) {
    const capped = Math.max(1, Math.min(Math.trunc(tmpfsMib(size)), Math.floor(memoryMb / 2)));
    return capped >= tmpfsMib(size) ? size : `${capped}m`;
  }
  if (tmpfsMib(size) <= memoryMb) return size;
  throw new MountRefused(
    `tmpfs ${JSON.stringify(size)} at ${JSON.stringify(target)} is larger than memoryMb=${memoryMb}, ` +
      `and a tmpfs is charged to that same cap. \`df\` inside the box would report ${size} free while ` +
      `only ${memoryMb}m is reachable, so a program that checks free space before writing plans ` +
      "against a number that OOM-kills it instead of returning ENOSPC. Lower the tmpfs or raise memoryMb.",
  );
}

/** Normalise `tmpfs` to [target, size|null] pairs. `undefined`/`null` = the binding default. */
function tmpfsItems(spec) {
  if (spec === undefined || spec === null) return Object.entries(DEFAULT_TMPFS);
  if (typeof spec === "string")
    throw new MountRefused(
      `tmpfs must be an object or an array of paths, not a bare string: write ` +
        `tmpfs: { ${JSON.stringify(spec)}: "64m" } or tmpfs: [${JSON.stringify(spec)}]`,
    );
  if (Array.isArray(spec)) return spec.map((t) => [t, null]);
  // A NUMBER is the mistake this API invites: every neighbour takes one (`memoryMb: 512`,
  // `pids: 256`), so `tmpfs: 256` is the natural thing to type. `Object.entries(256)` is `[]`, so it
  // used to mean SILENTLY NO SCRATCH: a read-only /tmp, no error, and the defect back in full.
  if (typeof spec !== "object")
    throw new MountRefused(
      `tmpfs must be an object of path -> size or an array of paths, got ${typeof spec}.` +
        (typeof spec !== "number"
          ? ""
          : spec === 0
            ? " For no scratch at all, pass tmpfs: {}."
            : ` Did you mean tmpfs: { "/tmp": "${spec}m" }?`),
    );
  return Object.entries(spec);
}

/** Validate one host->box mount; refuse unsafe sources/targets. Returns [absRealSource, target]. */
function validateMount(source, target) {
  if (typeof target !== "string" || !target.startsWith("/"))
    throw new MountRefused(`mount target must be an absolute path in the box, got ${JSON.stringify(target)}`);
  if (target.split("/").some((c) => c === ".."))
    throw new MountRefused(`mount target must not contain '..': ${JSON.stringify(target)}`);
  const normTarget = "/" + target.split("/").filter((c) => c && c !== ".").join("/");
  if (["/", "/proc", "/sys", "/dev"].includes(normTarget))
    throw new MountRefused(`cannot mount over the box essential mount ${JSON.stringify(normTarget)}`);
  if (typeof source !== "string" || !path.isAbsolute(source))
    throw new MountRefused(`mount source must be an absolute host path, got ${JSON.stringify(source)}`);
  let real;
  try {
    real = fs.realpathSync(source); // resolve symlinks BEFORE the sensitive-set check
  } catch {
    throw new MountRefused(`mount source does not exist: ${JSON.stringify(source)}`);
  }
  const home = (() => {
    try {
      return fs.realpathSync(os.homedir());
    } catch {
      return os.homedir();
    }
  })();
  if (REFUSED_MOUNT_SOURCES.has(real) || real === home)
    throw new MountRefused(
      `refusing to mount the sensitive host path ${JSON.stringify(real)} into a sandbox ` +
        "(this would defeat the isolation)",
    );
  return [real, target];
}

// A resource-profile token (`vcpu:`/`vgpio:`/`vdisk:` + a named profile from the user's kern.toml).
// ANCHORED and charset-restricted: the token is passed as a POSITIONAL arg to `kern box`, so it must be
// EXACTLY a known prefix plus a safe name. This is what stops a caller (or agent-chosen value) from
// smuggling another flag through the profile list ("--net", "-v /etc:/etc", "vgpu:x", a name with a
// space / `=` / `/` / leading dash). The three prefixes mirror `config::classify` in kern.
const PROFILE_RE = /^(?:vcpu|vgpio|vdisk):[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Validate one `vcpu:`/`vgpio:`/`vdisk:NAME` resource-profile token before it reaches the argv. */
function validateProfile(token) {
  if (typeof token !== "string" || !PROFILE_RE.test(token))
    throw new SandboxError(
      `invalid resource profile ${JSON.stringify(token)}: expected 'vcpu:NAME', 'vgpio:NAME' or ` +
        "'vdisk:NAME' with an alphanumeric profile name (the profile must be defined in your kern.toml)",
    );
  return token;
}

// A public DNS domain for the egress allowlist. LDH labels, at least one dot (an FQDN), alphabetic TLD.
// Restrictive on purpose: the value is comma-joined and handed to `kern box --egress-allow`, so it must
// not carry a comma, scheme, path, port, wildcard or whitespace that could change the argument. kern
// re-validates and SSRF-checks the resolved IPs; this is the binding's first gate.
const DOMAIN_RE = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

// A Linux capability name for `kern box --cap-drop`, with or without the CAP_ prefix, or the literal
// ALL. Underscore-JOINED uppercase segments rather than "any of [A-Z0-9_]": the looser form accepts
// "CAP_", because the optional prefix does not have to consume it. Not a way to smuggle a flag, but
// a name kern rejects at box start, and validating here exists to fail at construction instead.
const CAP_RE = /^(?=.{1,32}$)(?:CAP_)?[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/;

/** Validate one egress-allowlist domain (an FQDN like "pypi.org") before it reaches the argv. */
function validateDomain(domain) {
  if (typeof domain !== "string" || !DOMAIN_RE.test(domain))
    throw new SandboxError(
      `invalid egress domain ${JSON.stringify(domain)}: expected a bare hostname like 'pypi.org' ` +
        "(no scheme, port, path, wildcard or spaces)",
    );
  return domain;
}

/** Validate one capability name for `--cap-drop` before it reaches the argv. */
function validateCap(name) {
  if (typeof name !== "string" || !CAP_RE.test(name))
    throw new SandboxError(
      `invalid capability ${JSON.stringify(name)}: expected 'ALL' or an uppercase capability name ` +
        "such as 'NET_BIND_SERVICE' or 'CAP_NET_BIND_SERVICE'",
    );
  return name;
}

// An AppArmor profile name for `kern box --apparmor`. Same discipline as validateCap: handed to kern as
// its own argv element, so it must not start with a dash (-> another flag) or carry a space. Letters,
// digits and ._- cover ordinary profile names (docker-default, unconfined, kern-box); kern fails closed
// if the profile is not loaded. Namespaced names with / or : are intentionally not accepted here (use
// the CLI). Compared byte-for-byte with the Python binding's _APPARMOR_RE by a parity test - keep them
// identical and free of chars that need escaping in a regex literal (e.g. /).
const APPARMOR_RE = /^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,127}$/;

/** Validate an AppArmor profile name for `--apparmor` before it reaches the argv. */
function validateApparmor(name) {
  if (typeof name !== "string" || !APPARMOR_RE.test(name))
    throw new SandboxError(
      `invalid AppArmor profile ${JSON.stringify(name)}: expected a loaded profile name like ` +
        "'docker-default' or 'unconfined' (letters, digits and ._-, not starting with a dash)",
    );
  return name;
}

/** Map a Node close event {code, signal} to a unix-style rc (128 + signum for a signal). */
function toRc(code, signal) {
  if (typeof code === "number") return code;
  const table = { SIGHUP: 1, SIGINT: 2, SIGKILL: 9, SIGSEGV: 11, SIGTERM: 15, SIGSYS: 31 };
  if (signal && table[signal] !== undefined) return 128 + table[signal];
  return -1;
}

/** True iff kern (the PARENT, before the box exists) failed to start the box. Anchored on kern's OWN
 * diagnostic prefixes so the workload can't forge them by writing the marker to its own stderr. */
const EXEC_FAILED_RE = /^kern: cannot start '([^']+)' in box: ([^\n]*)/m;

/** The binary kern could not exec, or null.
 *
 * A THIRD state, and the reason this exists: kern signals "box started" on its unforgeable fd BEFORE
 * it execs the workload, so an `execve` that fails with ENOENT leaves a box that demonstrably started
 * and a command that never ran. The classifier gets that right (kern's own marker is on stderr, so it
 * says `startup_failed`) and the caller then ERASES it, because "box started + a kern: marker" is its
 * signal that a WORKLOAD forged the marker. For this case that inference is wrong: the workload never
 * ran, so it cannot have written anything.
 *
 * Matched on kern's own wording rather than on exit 127 alone, because 127 is also what a shell
 * returns for `command not found` inside a script the user wrote, which IS the user's failure.
 *
 * A workload CAN print this line and exit 127 to be labelled `exec_failed` instead of a plain
 * failure. That is accepted: it downgrades nothing security-relevant, because timeout, OOM and
 * blocked-escape are decided by EXIT CODE before any stderr is read. */
function execFailureBinary(stderr) {
  const m = EXEC_FAILED_RE.exec(stderr || "");
  return m ? { what: m[1], reason: (m[2] || "").trim() } : null;
}

function looksLikeStartupFailure(stderr) {
  const markers = [
    "kern:",
    "error: pull:",
    "error: curl failed:",
    "error: registry:",
    "error: manifest:",
    "error: sandbox:",
    "error: box:",
    "error: oci:",
    "error: image:",
  ];
  // kern also writes BENIGN `kern:` diagnostics that are NOT a box-start failure: the
  // `--security-profile` posture banner, and `warning:`/`note:` lines. They start with `kern:` too, so
  // without this skip a workload that merely exits non-zero WHILE one is on stderr (e.g. code run under
  // securityProfile: "untrusted" that hits a network error) would be mislabeled `startup_failed`.
  const benign = ["kern: security-profile=", "kern: warning:", "kern: note:"];
  for (const line of stderr.split("\n")) {
    const s = line.replace(/^\s+/, "");
    if (benign.some((b) => s.startsWith(b))) continue;
    if (s.includes("sandbox setup failed") || markers.some((m) => s.startsWith(m))) return true;
  }
  return false;
}

function uniqueName() {
  return "jssbx-" + crypto.randomBytes(6).toString("hex");
}

/** Drain a readable stream into a bounded buffer: keep at most `cap` bytes but KEEP reading past it
 * (discarding overflow) so a flooding box never blocks on a full pipe. RAM is bounded to `cap`. */
function cappedCollector(stream, cap, onData) {
  const chunks = [];
  let len = 0;
  const state = { truncated: false };
  stream.on("data", (chunk) => {
    if (onData) {
      // stream every chunk live; a callback throw must never break the drain (the box would then
      // block on a full pipe), so swallow it, the buffered result still returns.
      try {
        onData(chunk);
      } catch {
        /* user callback error ignored on purpose */
      }
    }
    if (len < cap) {
      const room = cap - len;
      if (chunk.length <= room) {
        chunks.push(chunk);
        len += chunk.length;
      } else {
        chunks.push(chunk.subarray(0, room));
        len = cap;
        state.truncated = true;
      }
    } else {
      state.truncated = true;
    }
    // never pause: keep draining so the box can't block on a full pipe
  });
  stream.on("error", () => {});
  state.buffer = () => Buffer.concat(chunks);
  return state;
}

// --- Minimal ustar (POSIX tar) over gzip, for workspace snapshots -------------------------------
// Dependency-free (Node's zlib does the gzip) and interoperable with `tar tzf` and the Python binding:
// a snapshot is a real .tar.gz. Only regular files are written; on restore only files/dirs are accepted
// (symlinks, devices, hardlinks and any absolute or `..`-escaping name are refused), and the final
// component is opened O_NOFOLLOW, so a hostile archive can never write outside the workspace.

function tarWriteFile(out, name, content) {
  if (Buffer.byteLength(name) > 100)
    throw new SandboxError(`snapshot: path too long for the tar format (>100 bytes): ${name}`);
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, "utf8");
  h.write("0000644\0", 100, 8); // mode
  h.write("0000000\0", 108, 8); // uid
  h.write("0000000\0", 116, 8); // gid
  h.write(content.length.toString(8).padStart(11, "0") + "\0", 124, 12); // size (octal)
  h.write("00000000000\0", 136, 12); // mtime 0 (deterministic)
  h.write("        ", 148, 8); // checksum field = 8 spaces while summing
  h.write("0", 156, 1); // typeflag '0' = regular file
  h.write("ustar\0", 257, 6); // magic
  h.write("00", 263, 2); // version
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8); // checksum: 6 octal digits, NUL, space
  out.push(h, content);
  const pad = (512 - (content.length % 512)) % 512;
  if (pad) out.push(Buffer.alloc(pad));
}

function tarCollect(dir, base, skip, out) {
  for (const entry of fs.readdirSync(dir).sort()) {
    const abs = path.join(dir, entry);
    const st = fs.lstatSync(abs);
    if (st.isSymbolicLink()) continue; // never archive a symlink
    if (st.isDirectory()) tarCollect(abs, base, skip, out);
    else if (st.isFile()) {
      const rel = path.relative(base, abs);
      // `skip` names OUR env file. Since it is now one per call, match the `<skip>.` prefix too, so a
      // file left behind by a process that died mid-call cannot end up inside a user's snapshot.
      if (rel === skip || rel.startsWith(skip + ENV_SEP)) continue;
      tarWriteFile(out, rel.split(path.sep).join("/"), fs.readFileSync(abs));
    }
  }
}

function tarPack(base, skip) {
  const out = [];
  tarCollect(base, base, skip, out);
  out.push(Buffer.alloc(1024)); // two zero blocks = end of archive
  // level 1: a local checkpoint is often large or already-compressed; level 1 is several times faster
  // than the default with a negligible size penalty. Speed over ratio here.
  return zlib.gzipSync(Buffer.concat(out), { level: 1 });
}

function tarParse(gz) {
  // Cap the inflated size so a tiny gzip bomb can't force a huge allocation before we even vet members.
  const buf = zlib.gunzipSync(gz, { maxOutputLength: 1024 * 1024 * 1024 });
  const members = [];
  let off = 0;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break; // end-of-archive zero block
    // Verify the ustar header checksum (sum of all header bytes with the 8-byte checksum field taken as
    // spaces): a single corrupt header field is rejected wholesale, before the per-field vetting runs.
    const stored = parseInt(h.toString("utf8", 148, 156).replace(/\0.*$/s, "").trim(), 8);
    let ck = 0;
    for (let i = 0; i < 512; i++) ck += i >= 148 && i < 156 ? 0x20 : h[i];
    if (stored !== ck) throw new SandboxError("malformed snapshot: bad header checksum");
    // Strip a trailing slash (the ustar dir convention "d/"): otherwise path.join keeps it, and a
    // trailing slash makes lstat FOLLOW a planted symlink ("d/" resolves the link to its target dir)
    // instead of seeing the link, which would defeat the symlink-vet on a dir member.
    const name = h.toString("utf8", 0, 100).replace(/\0.*$/s, "").replace(/\/+$/, "");
    // Size is octal ASCII by spec; reject anything else rather than let parseInt guess ("12x" -> 10).
    // This also makes a negative size impossible (no `-` in the field), closing the spin-forever case.
    const sizeField = h.toString("utf8", 124, 136).replace(/\0.*$/s, "").trim();
    if (!/^[0-7]*$/.test(sizeField)) throw new SandboxError("malformed snapshot: non-octal member size");
    const size = parseInt(sizeField, 8) || 0;
    const flag = String.fromCharCode(h[156]);
    off += 512;
    const type = flag === "0" || flag === "\0" ? "file" : flag === "5" ? "dir" : "other";
    // A dir/other member carries no content in ustar; a non-zero size there is malformed, so reject it
    // rather than silently ignore it (reject-not-guess).
    if (type !== "file" && size !== 0)
      throw new SandboxError("malformed snapshot: non-file member with a non-zero size");
    // Refuse a member claiming more bytes than remain: reject the malformed archive instead of silently
    // truncating the restored file (subarray would clamp to the buffer end).
    if (type === "file" && off + size > buf.length)
      throw new SandboxError("malformed snapshot: member size exceeds archive");
    const content = type === "file" ? buf.subarray(off, off + size) : Buffer.alloc(0);
    members.push({ name, type, content });
    off += Math.ceil(size / 512) * 512;
  }
  return members;
}

class Sandbox {
  /**
   * @param {object} [opts]
   * @param {string} [opts.image]            OCI image the box runs from. Default a small Python image.
   * @param {string} [opts.setup]            shell command run ONCE at open() in a NETWORK-ENABLED box.
   * @param {string} [opts.workspace]        host dir to persist as the workspace. null -> a temp dir,
   *                                          created on open() and DELETED on close().
   * @param {number|null} [opts.memoryMb]    RAM cap (kern --memory). Default 512.
   * @param {number|null} [opts.cpus]        CPU cap in cores; null = uncapped.
   * @param {number|null} [opts.pids]        task/fork-bomb ceiling. Default 256.
   * @param {number} [opts.timeoutS]         MANDATORY per-call wall-clock limit (binding-owned). Default 30.
   * @param {boolean} [opts.network]         RELAXES ISOLATION. true shares the host network. Default false.
   * @param {string[]} [opts.egressAllow]    restrict runCode/run to a DOMAIN ALLOWLIST, e.g. ["pypi.org"]; isolated netns + kern's filtering proxy. Mutually exclusive with network:true.
   * @param {Object<string, string|[string,string]>} [opts.mounts] extra host->box binds. Sensitive refused.
   * @param {Object<string,string>|string[]} [opts.tmpfs] fresh in-box scratch filesystems (kern --tmpfs). Default: a 64 MiB tmpfs at /tmp, because the root is read-only. `{}` for none; a `mounts` bind at the same target wins.
   * @param {string[]} [opts.profiles] kern resource profiles to attach, e.g. ["vcpu:heavy","vgpio:leds","vdisk:scratch"]; each names a block in your kern.toml. Strictly validated.
   * @param {Object<string,string>} [opts.env] extra environment for the workload.
   * @param {number} [opts.maxOutputBytes]   cap on captured stdout/stderr EACH. Default 64 MiB.
   * @param {boolean} [opts.enforceLimits]   true (default) hard-enforces caps via a systemd scope.
   * @param {boolean} [opts.depsReadonly]    mount setup= deps read-only for runCode (default true).
   */
  constructor(opts = {}) {
    this.image = opts.image ?? DEFAULT_IMAGE;
    this.setup = opts.setup ?? null;
    this.workspace = opts.workspace ?? null;
    this.memoryMb = opts.memoryMb === undefined ? 512 : opts.memoryMb;
    this.cpus = opts.cpus ?? null;
    this.pids = opts.pids === undefined ? 256 : opts.pids;
    this.timeoutS = opts.timeoutS ?? 30;
    this.network = opts.network ?? false;
    this.egressAllow = opts.egressAllow ?? null;
    this.mounts = opts.mounts ?? null;
    // `undefined` means the binding's default (a 64 MiB tmpfs at /tmp); `{}` or `[]` means none at
    // all. The two are distinct on purpose: "I did not say" and "I said no" are different answers,
    // and only the second should leave a box without a writable /tmp.
    this.tmpfs = opts.tmpfs === undefined ? null : opts.tmpfs;
    this.profiles = opts.profiles ?? null;
    this.env = opts.env ?? null;
    this.maxOutputBytes = opts.maxOutputBytes ?? 64 * 1024 * 1024;
    // live output callbacks: called with each Buffer chunk as it arrives. The full capped output is
    // still captured in the result, so you can stream AND read result.stdout.
    this.onStdout = opts.onStdout ?? null;
    this.onStderr = opts.onStderr ?? null;
    // prewarm=N keeps N boxes started in advance, each holding a booted interpreter that has run
    // nothing. A python runCode then claims one instead of starting its own, which takes the box start
    // and the interpreter boot OFF the call and leaves a marginal cost near zero. Each prewarmed box
    // serves exactly one cell and is destroyed, so "a fresh box per call" is unchanged - see WarmBox.
    //
    // Default 0, because it is a RESOURCE decision the caller owns: N warm boxes hold N booted
    // interpreters and N kern supervisors for the life of the session, whether or not a call arrives.
    // 1 is the right number for an interactive agent; raise it only for bursts.
    this.prewarm = opts.prewarm ?? 0;
    /** @type {WarmPool|null} */
    this._pool = null;
    this.enforceLimits = opts.enforceLimits ?? true;
    // `--require-limits`: refuse to start unless the memory/pids caps are ACTUALLY enforced (read back
    // from the cgroup), rather than running best-effort uncapped - the fail-closed OOM / fork-bomb
    // backstop. Distinct from `enforceLimits` (systemd-scope vs best-effort PATH); this makes an
    // unenforceable cap fatal.
    this.requireLimits = opts.requireLimits ?? false;
    // `--security-profile "untrusted"`: an opt-in hardening BUNDLE (seccomp allowlist + cap-drop ALL +
    // read-only root) for code nobody has read. The root goes read-only but a bound `mounts` path stays
    // writable, so it composes with this SDK. null (default) leaves kern's normal posture.
    this.securityProfile = opts.securityProfile ?? null;
    // `--apparmor "<profile>"`: enter a pre-loaded AppArmor profile on the box's exec (Docker's
    // `--security-opt apparmor=`), a kernel-enforced LSM layer over namespaces + seccomp. The profile
    // must be loaded on the host; kern fails the box CLOSED if it is not. null (default) applies none.
    this.apparmor = opts.apparmor ?? null;
    this.depsReadonly = opts.depsReadonly ?? true;
    // Capabilities dropped from every box this sandbox starts, as kern's own `--cap-drop` takes them.
    // The default drops the lot: kern already drops 14 dangerous capabilities unconditionally, but the
    // rest were still held over the box's own user namespace, on the one code path whose purpose is
    // running code nobody has read. Defence in depth rather than the boundary itself, and measured to
    // cost nothing. It is NOT behaviour-free: a workload binding a port below 1024 INSIDE the box
    // needs CAP_NET_BIND_SERVICE. Pass `capDrop: []` for the previous behaviour.
    this.capDrop = opts.capDrop ?? ["ALL"];
    // trackFiles=true populates result.files by walking the workspace before AND after each call (O(N)
    // in file count); a long session that accretes files slows every runCode. false = result.files [], O(1).
    this.trackFiles = opts.trackFiles ?? true;

    if (!(this.timeoutS > 0)) throw new SandboxError("timeoutS must be a positive number of seconds");
    if (!(this.maxOutputBytes > 0)) throw new SandboxError("maxOutputBytes must be positive");

    this._mountArgs = [];
    const boundTargets = new Set();
    if (this.mounts) {
      for (const [source, spec] of Object.entries(this.mounts)) {
        let target, ro;
        if (Array.isArray(spec)) {
          const [t, mode] = spec;
          if (mode !== "ro" && mode !== "rw")
            throw new MountRefused(`mount mode must be 'ro' or 'rw', got ${JSON.stringify(mode)}`);
          target = t;
          ro = mode === "ro";
        } else {
          target = spec;
          ro = false;
        }
        const [real, tgt] = validateMount(source, target);
        this._mountArgs.push("-v", ro ? `${real}:${tgt}:ro` : `${real}:${tgt}`);
        boundTargets.add("/" + tgt.split("/").filter((c) => c && c !== ".").join("/"));
      }
    }
    // A caller who binds their own directory at /tmp gets it: the default tmpfs would be mounted OVER
    // their bind, so the files they passed would be invisible to the code they are running. An
    // explicit `tmpfs` wins too; both are the caller saying what that path is.
    this._tmpfsArgs = [];
    this._tmpfsDefault = this.tmpfs === null;
    for (const [target, size] of tmpfsItems(this.tmpfs)) {
      // OUR default steps aside wherever the caller has already said something about this area: a
      // bind at the same target, because mounting over it would hide their files, and a
      // `securityProfile`, because that is a HARDENING BUNDLE and 0.1.35 gave `untrusted` a
      // read-only /tmp. A default added by a different layer must not widen a posture in a patch
      // release.
      const normTarget = "/" + String(target).split("/").filter((c) => c && c !== ".").join("/");
      if (this._tmpfsDefault && (boundTargets.has(normTarget) || this.securityProfile !== null)) continue;
      // A tmpfs that COVERS a bind. Equality was the first version and it is only half the shape:
      // mounts stack, the tmpfs goes on top, and "on top" reaches every path underneath. Measured:
      //   -v HOST:/tmp     + --tmpfs /tmp      -> /tmp EMPTY, the bind invisible
      //   -v HOST:/tmp/sub + --tmpfs /tmp      -> same, through NESTING
      //   -v HOST:/tmp     + --tmpfs /tmp/sub  -> the bind's files are there, /tmp/sub is scratch
      // So the rule is asymmetric: refusing both directions would refuse the third, which is a legal
      // configuration (a persistent /tmp with a bounded subtree).
      if (!this._tmpfsDefault) {
        const swallowed = [...boundTargets].filter(
          (b) => b === normTarget || b.startsWith(normTarget.replace(/\/+$/, "") + "/"),
        );
        if (swallowed.length)
          throw new MountRefused(
            `tmpfs ${JSON.stringify(normTarget)} would cover the mounts bind at ` +
              `${swallowed.sort().join(", ")}. Mounts STACK: kern puts the tmpfs on top whatever ` +
              "order the arguments arrive in, so those files stay on the host and are invisible in " +
              "the box. Keep the bind (for host files) or the tmpfs (for ephemeral scratch) at that " +
              'path, not both. A tmpfs BELOW a bind is fine: mounts {host: "/tmp"} with ' +
              'tmpfs {"/tmp/scratch": "8m"} works.',
          );
      }
      // Validate FIRST: `tmpfsSizeVsCap` parses the size, and parsing an unvalidated one threw out
      // of the constructor instead of a named MountRefused. Same class as the wrong-type hole.
      const [norm, validSize] = validateTmpfs(target, size);
      const resolved = tmpfsSizeVsCap(norm, validSize, this.memoryMb, this._tmpfsDefault);
      this._tmpfsArgs.push("--tmpfs", resolved === null || resolved === undefined ? norm : `${norm}:${resolved}`);
    }
    // A bare string has a .map-less shape here, but Array.from("ALL") would yield ["A","L","L"] and
    // three bogus flags, so refuse the string by name and say what to write instead.
    if (typeof this.capDrop === "string")
      throw new SandboxError(
        `capDrop must be an array of names, not a bare string: write capDrop: [${JSON.stringify(
          this.capDrop,
        )}] for one, or capDrop: [] to drop none`,
      );
    if (!Array.isArray(this.capDrop))
      throw new SandboxError("capDrop must be an array of capability names");
    this._capDropArgs = this.capDrop.flatMap((c) => ["--cap-drop", validateCap(c)]);
    this._profileArgs = (this.profiles || []).map(validateProfile);
    this._egressAllow = (this.egressAllow || []).map(validateDomain);
    if (this.apparmor !== null) validateApparmor(this.apparmor);
    if (this._egressAllow.length && this.network)
      throw new SandboxError(
        "egressAllow and network:true are mutually exclusive: egressAllow gives a restricted domain " +
          "allowlist for runCode, network:true gives the full host network",
      );
    this._kern = findKern();
    this._ws = "";
    this._ownWs = false;
    this._entered = false;
  }

  // -- lifecycle -----------------------------------------------------------------------------------

  /** Open the session: create/validate the workspace and run `setup` (if any). Must be called before
   * runCode/run/writeFile. Prefer withSandbox() which opens and closes for you. */
  async open() {
    if (this._entered) return this;
    if (this.workspace === null) {
      this._ws = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "kern-ws-")));
      this._ownWs = true;
    } else {
      // Create the persistent workspace FIRST so a fresh path is usable on the first run; mkdir is a
      // no-op on an existing sensitive source (e.g. /etc), which validateMount then still refuses.
      fs.mkdirSync(this.workspace, { recursive: true });
      validateMount(this.workspace, WORKSPACE);
      this._ws = fs.realpathSync(this.workspace);
      this._ownWs = false;
    }
    this._entered = true;
    if (this.setup) await this._runSetup(this.setup);
    // AFTER the setup, deliberately. _baseArgv adds the .deps read-only remount only once that
    // directory exists, so a pool filled before the setup ran would hold boxes whose argv no longer
    // matches the one runCode builds: every claim would miss and the prewarming would be pure cost.
    if (this.prewarm > 0) {
      this._pool = new WarmPool(this, this.prewarm);
      this._pool.refill({ network: this.network, deadlineS: this._effTimeout(undefined) });
    }
    return this;
  }

  /** Close the session: tear down any prewarmed boxes, then delete the workspace iff we created it.
   * Idempotent. */
  async close() {
    // Boxes first: they are live processes holding the workspace we are about to delete, and a box
    // still writing into a directory being removed is how a teardown turns into a stale mount.
    const pool = this._pool;
    this._pool = null;
    if (pool) await pool.close();
    if (this._ownWs && this._ws) {
      try {
        fs.rmSync(this._ws, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    }
    this._entered = false;
  }

  _requireEntered() {
    if (!this._entered)
      throw new SandboxError("open the Sandbox first: `await sandbox.open()` (or use withSandbox()).");
  }

  // -- the box invocation --------------------------------------------------------------------------

  /** Host path of the private --env-file for the box called `name`, inside the workspace. */
  _envPath(name) {
    return path.join(this._ws, `${ENV_FILE}${ENV_SEP}${name}`);
  }

  /**
   * Is `rel` one of OUR env files rather than user state? Exact-match on the legacy name plus the
   * `.kern-env.` prefix, never a bare startsWith: a user file called `.kern-environment` is theirs
   * and must still show up in `files` and in a snapshot.
   */
  static _isEnvFile(rel) {
    return rel === ENV_FILE || rel.startsWith(ENV_FILE + ENV_SEP);
  }

  /** Remove this call's env file. Every exit path calls it; a missing file is the desired end state. */
  _removeEnvFile(name) {
    try {
      fs.unlinkSync(this._envPath(name));
    } catch {
      /* ENOENT is fine: no env was passed, or it is already gone */
    }
  }

  /** The clause an OOM message owes when this box has scratch mounted.
   *
   * A tmpfs is charged to the box's memory cgroup and its pages are NOT reclaimable: measured, 56 MiB
   * written to /tmp then 90 MiB allocated under `memoryMb: 128` is an OOM, while the SAME 56 MiB
   * written to the workspace and synced leaves room, because file-backed pages can be written back and
   * dropped. An OOM message naming only "memory cap" sends the reader to look at their allocation.
   * It states the mechanism and does NOT claim scratch caused this kill: that is not knowable here. */
  _scratchNote() {
    const ours = this._tmpfsArgs.filter((a) => a !== "--tmpfs").join(", ");
    // `/dev/shm` is named even when we mounted nothing: writing 200 MiB there under `memoryMb: 128`
    // OOMs the box, and the first version of this note said `/tmp:64m`, which is the wrong place.
    // Every kern box has a /dev/shm tmpfs with NO size, and this SDK cannot bound it.
    return (
      ". NOTE: memory-backed filesystems in this box are charged to that same cap, and their pages " +
      "are freed only by DELETING the files: " +
      (ours ? `the scratch this SDK mounted (${ours}), and ` : "") +
      "/dev/shm, which every kern box has as a tmpfs with NO size limit (its apparent size is half " +
      "the HOST's RAM) and which no option here can bound. Check both before the workload"
    );
  }

  /** Build the `kern box` argv for one call. NOT a pure function: it also WRITES the private
   * `--env-file` this box will read, so it must be called once per box that is actually started.
   *
   * `dry: true` suppresses that write and folds the env CONTENT into the argv instead, which is what the
   * prewarm pool needs: it compares postures, and a comparison that created a file named after a box
   * that will never exist would both litter the workspace and collide with itself. A dry argv is for
   * COMPARING, never for running. */
  _baseArgv(name, { network, timeoutS, isSetup = false, dry = false }) {
    const argv = [
      this._kern, "box", name, "--image", this.image, "--ro",
      "-v", `${this._ws}:${WORKSPACE}`, "--workdir", WORKSPACE,
    ];
    if (this.depsReadonly && !isSetup) {
      const deps = path.join(this._ws, DEPS_DIR);
      try {
        if (fs.statSync(deps).isDirectory()) argv.push("-v", `${deps}:${WORKSPACE}/${DEPS_DIR}:ro`);
      } catch {
        /* no deps yet */
      }
    }
    // kern's own --timeout is a tight BACKSTOP just beyond our deadline; OUR wait is the authority.
    argv.push(...this._capDropArgs);
    argv.push("--timeout", String(Math.floor(timeoutS) + 5));
    if (this.memoryMb !== null) argv.push("--memory", `${this.memoryMb}m`);
    if (this.cpus !== null) argv.push("--cpus", String(this.cpus));
    if (this.pids !== null) argv.push("--pids-limit", String(this.pids));
    if (this.requireLimits) argv.push("--require-limits");
    if (this.securityProfile !== null) argv.push("--security-profile", this.securityProfile);
    if (this.apparmor !== null) argv.push("--apparmor", this.apparmor);
    // Network mode: egressAllow (a domain allowlist via an isolated netns + kern's filtering proxy)
    // governs the untrusted runCode/run boxes; the setup box keeps the full network it needs to install
    // deps. egressAllow and network are mutually exclusive (checked at construction).
    if (this._egressAllow.length && !isSetup) argv.push("--egress-allow", this._egressAllow.join(","));
    else if (network) argv.push("--net");
    // Resource profiles (vcpu:/vgpio:/vdisk:NAME): positional tokens `kern box` resolves against the
    // user's kern.toml. Validated at construction, so nothing here can be a smuggled flag.
    argv.push(...this._profileArgs);
    argv.push(...this._mountArgs);
    // Scratch for THIS box. The DEFAULT tmpfs is deliberately skipped on the setup box, for the same
    // reason the egress allowlist is: setup is the install phase, and an install needs unbounded
    // scratch. A package manager puts its build tree in TMPDIR, so a 64 MiB /tmp turns a working
    // install into ENOSPC (measured on the Python side, same shape here). With no tmpfs, setup's temp
    // falls back to the workspace on the host disk, where a large short-lived build tree belongs. An
    // EXPLICIT `tmpfs` is the caller's decision and applies to every box, setup included.
    if (!(isSetup && this._tmpfsDefault)) argv.push(...this._tmpfsArgs);

    const mergedEnv = { ...(this.env || {}) };
    if (mergedEnv.PYTHONPATH === undefined) mergedEnv.PYTHONPATH = `${WORKSPACE}/${DEPS_DIR}`;
    // Pass env via a private 0600 --env-file, NOT `--env K=V` on argv (an argv value is visible in
    // `ps` to any local user for the box's lifetime; a credential in env= would leak).
    // `_ws` is set by open(); before that it is "". The public API is gated, but the unit tests call
    // `_baseArgv` directly to inspect the argv, and with an empty workspace `path.join` yielded a
    // RELATIVE path, so the env file was written into the current directory. Same as the Python side:
    // it had been landing in the repository, hidden by a `.gitignore` line that stopped matching when
    // the name became per-call. No workspace means nowhere to put it.
    if (Object.keys(mergedEnv).length > 0 && dry) {
      // The path is per-box by construction, so it can never be part of a posture comparison; a constant
      // stands in for it. The env CONTENT is still compared, because a session that changes `env` must
      // invalidate warm boxes: it is folded in here rather than left out.
      // Sorted BY KEY, not by the joined string, so this matches the Python binding exactly: sorting
      // "A=1" against "A1=2" as strings puts them in the other order, because '1' sorts before '='.
      argv.push(
        "--env-file",
        Object.entries(mergedEnv)
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([k, v]) => `${k}=${String(v)}`)
          .join("\0"),
      );
    } else if (Object.keys(mergedEnv).length > 0 && this._ws) {
      const envPath = this._envPath(name);
      const lines = [];
      for (const [k, v] of Object.entries(mergedEnv)) {
        const val = String(v);
        if (/[\n\0]/.test(k) || /[\n\0]/.test(val))
          throw new SandboxError(`env var ${JSON.stringify(k)} must not contain a newline or NUL`);
        lines.push(`${k}=${val}\n`);
      }
      // SECURITY: the box has rw access to /workspace and could plant `.kern-env` as a symlink to a host
      // file (e.g. ~/.ssh/authorized_keys); a follow-through open would O_TRUNC-clobber it. Unlink any
      // existing entry (removing a planted symlink) and create fresh with O_EXCL|O_NOFOLLOW so we never
      // write through a symlink. Fails closed if a concurrent box re-plants it between the two calls.
      try {
        fs.unlinkSync(envPath);
      } catch {
        /* ENOENT is fine */
      }
      const fd = fs.openSync(
        envPath,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
        0o600,
      );
      try {
        fs.writeSync(fd, lines.join(""));
      } finally {
        fs.closeSync(fd);
      }
      argv.push("--env-file", envPath);
    }
    return argv;
  }

  _spawn(command, { network, timeoutS, isSetup = false, onStdout = UNSET, onStderr = UNSET }) {
    const cbOut = onStdout === UNSET ? this.onStdout : onStdout;
    const cbErr = onStderr === UNSET ? this.onStderr : onStderr;
    for (const part of command)
      if (typeof part !== "string" || part.includes("\0"))
        throw new SandboxError("command/code must be strings with no NUL byte");
    const before = this.trackFiles ? this._snapshot() : null; // skip the O(N) walk when not tracked
    const name = uniqueName();
    const argv = [...this._baseArgv(name, { network, timeoutS, isSetup }), "--", ...command];
    const childEnv = { ...process.env };
    if (!this.enforceLimits) childEnv.KERN_NO_SCOPE = "1";
    // Unforgeable "box started" channel: kern writes one byte to fd 3 iff its sandbox setup SUCCEEDED
    // and the command ran. The workload never holds fd 3, so it can neither forge nor suppress it -
    // unlike kern's stderr, which it can. A new kern makes this the authority for `startup_failed`; an
    // OLD kern never writes it, `boxStarted` stays false, and the stderr heuristic stands (backward
    // compatible).
    childEnv.KERN_STARTED_FD = "3";

    const started = process.hrtime.bigint();
    return new Promise((resolve, reject) => {
      let child;
      let boxStarted = false;
      let capSignal = 0; // 2nd started byte: 0 undetermined/old-kern, 1 memory cap enforced, 2 not enforced
      try {
        // detached: own process group, so we can signal the box + kern as a unit (killpg).
        // The 4th stdio slot is fd 3: the child (kern) writes the started byte, the parent reads it.
        child = spawn(argv[0], argv.slice(1), {
          env: childEnv,
          detached: true,
          stdio: ["ignore", "pipe", "pipe", "pipe"],
        });
      } catch (e) {
        this._removeEnvFile(name);
        return reject(new SandboxError(`could not spawn the box: ${e.message}`));
      }

      const startedCh = child.stdio[3];
      if (startedCh) {
        // Byte 0 (0x01) = the box started; stream end with no byte = never started / old kern. Byte 1
        // (a NEWER kern only, same atomic write) = the memory-cap enforcement signal; absent = 0.
        startedCh.on("data", (b) => {
          if (b.length && b[0] === 1) boxStarted = true;
          if (b.length >= 2) capSignal = b[1];
        });
        startedCh.on("error", () => {});
      }

      const out = cappedCollector(child.stdout, this.maxOutputBytes, cbOut);
      const err = cappedCollector(child.stderr, this.maxOutputBytes, cbErr);
      let timedOut = false;
      let settled = false;
      // Both timers are armed further down, once `finish` exists. They are declared here, as `let`,
      // so the closures that clear them can never reference a binding in its temporal dead zone
      // whatever the callback ordering turns out to be.
      let timer = null;
      let hardTimer = null;

      const finish = (code, signal) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        if (hardTimer) clearTimeout(hardTimer);
        // kern has read the file by the time it exits; leaving it behind would accrete one per call
        // in a persistent `workspace`.
        this._removeEnvFile(name);
        const wallMs = Number((process.hrtime.bigint() - started) / 1000000n);
        const stdout = out.buffer().toString("utf8");
        const stderr = err.buffer().toString("utf8");
        const rc = toRc(code, signal);
        let fault = this._classify(rc, signal, stderr, timedOut, timeoutS, capSignal);
        const execFail = execFailureBinary(stderr);
        if (execFail !== null && rc !== 0) {
          // BEFORE the suppression below, which would erase it: the box started, so that branch
          // would read kern's own marker as a workload forgery.
          //
          // The REASON is carried through rather than assumed. The first version said "does not
          // exist in the box" for every case, and exit 126 (EACCES: the file is there and is not
          // executable) and a script whose interpreter line names a missing binary both got a
          // message blaming the image for a file that exists.
          const { what, reason } = execFail;
          let detail;
          if (reason.includes("No such file or directory")) {
            detail =
              `No such file or directory. The image '${this.image}' does not provide it, or its ` +
              `interpreter line names something the image lacks.` +
              // The one case where the remedy is not "a different image": every image has a POSIX
              // shell, so a caller who asked for bash and does not need bash has a one-word fix.
              (what === "bash" ? " This image has no bash; use language:'sh' if the script is POSIX." : "");
          } else if (reason.includes("Permission denied")) {
            detail = "Permission denied: it is present in the box but not executable there.";
          } else {
            detail = reason || "the box could not execute it";
          }
          fault = sandboxFault("exec_failed", `'${what}' could not be started in the box: ${detail}`);
        } else if (boxStarted && fault && fault.type === "startup_failed") {
          // kern signalled the box STARTED, so a `startup_failed` here is only the stderr heuristic
          // matching a marker the WORKLOAD wrote (code-based faults are decided first). The box
          // demonstrably ran: this is the workload's own non-zero exit - reclassify to a normal result.
          fault = null;
        }
        // A box that FAILED TO START ran no user code, so REJECT rather than resolve a hollow
        // ExecutionResult (empty stdout). Gated on `rc === 125` (kern's box-not-started code) AND the
        // startup_failed classification (which requires kern's own stderr marker): the confident pair
        // that tells a genuine box-not-started apart from a workload that itself exited 125 (no marker ->
        // fault null -> a normal result). An older kern (127) is returned as a data fault, not thrown.
        // Runtime events where the code DID run (timeout, OOM, escape) stay as data on `.fault`.
        if (rc === 125 && fault && fault.type === "startup_failed") {
          return reject(new SandboxError(fault.message || "the box failed to start"));
        }
        const files = before ? this._diff(before) : [];
        resolve(
          new ExecutionResult({
            stdout, stderr, exitCode: rc, durationMs: wallMs, fault, files,
            truncated: out.truncated || err.truncated,
          }),
        );
      };

      child.on("error", (e) => {
        this._removeEnvFile(name);
        if (e && e.code === "ENOENT")
          return reject(new SandboxError(`could not execute kern (${argv[0]}): not found`));
        return reject(new SandboxError(`could not execute kern: ${e.message}`));
      });
      child.on("close", (code, signal) => {
        finish(code, signal);
      });
      // Hard safety net: a CPU-bound box can survive our signals until kern's backstop reaps it;
      // never hang the caller. If close hasn't fired a few seconds after our teardown, resolve anyway.
      const armHardNet = () => {
        if (hardTimer) return;
        hardTimer = setTimeout(() => finish(EXIT_SIGKILL, "SIGKILL"), 10000);
      };

      timer = setTimeout(() => {
        timedOut = true;
        this._teardown(child, name, childEnv);
        // Armed HERE, at the one place that decides to kill. It used to be noticed instead by a
        // 250 ms setInterval that `finish` never cleared, so after every call that interval kept the
        // event loop alive until its own next tick: measured 224 to 232 ms of dead time between a
        // call resolving and the process being able to exit, against 19 to 27 ms of real work.
        armHardNet();
      }, timeoutS * 1000);
    });
  }

  _teardown(child, name, childEnv) {
    // Best-effort tear down a timed-out box. A CPU-bound box in its own PID namespace survives a plain
    // SIGKILL of kern's parent: (1) `kern stop` (cgroup-kill); (2) SIGKILL the whole process group;
    // (3) SIGKILL the child. kern's own --timeout backstop guarantees the box is gone shortly.
    try {
      spawnSync(this._kern, ["stop", name], { env: childEnv, timeout: 5000, stdio: "ignore" });
    } catch {
      /* ignore */
    }
    try {
      if (child.pid) process.kill(-child.pid, "SIGKILL"); // process group (detached)
    } catch {
      /* ignore */
    }
    try {
      child.kill("SIGKILL");
    } catch {
      /* ignore */
    }
  }

  _classify(rc, signal, stderr, timedOut, timeoutS, capSignal = 0) {
    // ORDER IS A SECURITY PROPERTY: deterministic-by-exit-code classes are decided BEFORE the stderr
    // heuristic, because stderr is a channel the workload controls.
    if (timedOut)
      return sandboxFault(
        "timeout",
        `exceeded the ${timeoutS ?? this.timeoutS}s time limit (killed by the binding)`,
      );
    if (rc === EXIT_SIGSYS || signal === "SIGSYS")
      return sandboxFault("escape_blocked", "a syscall was blocked by the seccomp filter (SIGSYS)");
    if (rc === EXIT_SIGKILL || signal === "SIGKILL") {
      // A memory-capped box SIGKILLed is the cgroup OOM-killer - what a breached memory.max does (kern
      // sets memory.oom.group=1, so the whole box dies at once). `capSignal` is kern's UNFORGEABLE
      // enforcement byte (2nd byte of KERN_STARTED_FD, not the workload's stderr): 1 = enforced, 2 =
      // requested but NOT enforced here, 0 = undetermined (old kern / no --memory). Claim `oom` when a
      // --memory cap was set AND kern did not report it unenforced (capSignal !== 2): enforced (1) is a
      // certain cgroup OOM, undetermined (0) keeps the pre-signal heuristic. When kern reports the cap did
      // not bind (2), a SIGKILL cannot be attributed to the box's cgroup - keep the honest `killed`.
      if (this.memoryMb !== null && capSignal !== 2)
        return sandboxFault(
          "oom",
          "the box exceeded its memory cap and was OOM-killed (SIGKILL, exit 137)" + this._scratchNote(),
        );
      if (capSignal === 2)
        return sandboxFault(
          "killed",
          "the box was SIGKILLed, but its memory cap was not enforced here (no cgroup delegation), so it is not attributed to a cgroup OOM",
        );
      return sandboxFault("killed", "the box was killed (SIGKILL); no memory cap was set to attribute it to OOM");
    }
    if (rc === EXIT_SIGTERM || signal === "SIGTERM")
      return sandboxFault("timeout", "the box exceeded its time limit (reaped by kern's timeout backstop)");
    // Box-not-started: a non-zero exit whose stderr carries kern's OWN setup markers (printed by the
    // PARENT before the box runs). kern's box-not-started paths BOTH exit 125 AND print a `kern:` marker,
    // so `rc === 125 && marker` is the reliable signal - the marker is REQUIRED so a workload that merely
    // exits 125 ITSELF (the code ran and chose 125) is NOT mislabeled. `finish` REJECTS only on rc===125;
    // a non-125 startup_failed (an older kern's 127, or a forged marker) is returned as DATA, not thrown.
    if (rc !== 0 && looksLikeStartupFailure(stderr))
      return sandboxFault("startup_failed", stderr.trim().slice(0, 500));
    // Any other non-zero exit (incl. 139 SIGSEGV) is the USER's code failing - a normal Result.
    return null;
  }

  // -- workspace file I/O (host-direct; single-uid -> box files are host-owned) ---------------------

  _wsPath(rel) {
    // Lexical containment: normalize `..`/`.`, require it stays under the workspace base. Symlinks in
    // the final component are neutralized by O_NOFOLLOW on the actual open below.
    const base = this._ws;
    const full = path.normalize(path.join(base, rel));
    if (full !== base && !full.startsWith(base + path.sep))
      throw new SandboxError(`path escapes the workspace: ${JSON.stringify(rel)}`);
    return full;
  }

  /** Create the parent directories of `full` under the workspace WITHOUT following a symlink in any
   * intermediate component. `mkdir -p` follows symlinks, so a box that plants `a -> /etc` could steer a
   * `writeFile("a/b.txt")` outside the workspace even though the final component is O_NOFOLLOW. Descend
   * one level at a time from the (canonical) base: reject a symlink, create a missing dir non-recursively. */
  _ensureParentDirs(full) {
    const base = this._ws;
    const relDir = path.relative(base, path.dirname(full));
    if (relDir === "" || relDir === ".") return; // parent is the workspace root itself
    let cur = base;
    for (const part of relDir.split(path.sep)) {
      if (!part || part === ".") continue;
      const next = path.join(cur, part);
      let st = null;
      try {
        st = fs.lstatSync(next);
      } catch {
        st = null;
      }
      if (st === null) {
        fs.mkdirSync(next); // non-recursive: each level is a fresh real dir we just created
      } else if (st.isSymbolicLink()) {
        throw new SandboxError(`path escapes the workspace via a symlinked directory: ${JSON.stringify(part)}`);
      } else if (!st.isDirectory()) {
        throw new SandboxError(`workspace path component is not a directory: ${JSON.stringify(part)}`);
      }
      cur = next;
    }
  }

  /** Write `data` (Buffer|string) to `path` (workspace-relative) - host-direct, so the box sees it next
   * run. The final component is opened O_NOFOLLOW: a symlink the box planted can't redirect the write. */
  async writeFile(rel, data) {
    this._requireEntered();
    const full = this._wsPath(rel);
    this._ensureParentDirs(full); // symlink-safe descent, NOT mkdir -p (which follows a planted symlink)
    const payload = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
    let fd;
    try {
      // O_NONBLOCK for the same reason as readFile, and the write side is the WORSE of the two: opening
      // a FIFO for writing blocks until a reader appears, and with the flag it fails outright (ENXIO)
      // instead. Either way the call returns to the caller rather than parking there.
      fd = fs.openSync(
        full,
        fs.constants.O_WRONLY |
          fs.constants.O_CREAT |
          fs.constants.O_TRUNC |
          fs.constants.O_NOFOLLOW |
          fs.constants.O_NONBLOCK,
        0o644,
      );
    } catch (e) {
      throw new SandboxError(`cannot write ${JSON.stringify(rel)}: ${e.message}`);
    }
    try {
      // The file the box left at this name has to be a REGULAR file before we write into it: writing
      // into a device node or a socket the box planted is host I/O it chose the target of.
      if (!fs.fstatSync(fd).isFile())
        throw new SandboxError(
          `refusing to write ${JSON.stringify(rel)}: not a regular file (a FIFO, device or socket ` +
            `planted in the workspace can stall or redirect this write)`,
        );
      fs.writeSync(fd, payload);
    } finally {
      fs.closeSync(fd);
    }
  }

  /** Verify no INTERMEDIATE path component under the workspace is a symlink (read-only counterpart of
   * _ensureParentDirs). readFile follows directory components on open, so a box that plants `d -> /etc`
   * would otherwise leak host files via `readFile("d/x")` even with O_NOFOLLOW on the last component.
   * Descend one level at a time, reject a symlinked component. */
  _verifyParentDirs(full) {
    const base = this._ws;
    const relDir = path.relative(base, path.dirname(full));
    if (relDir === "" || relDir === ".") return;
    let cur = base;
    for (const part of relDir.split(path.sep)) {
      if (!part || part === ".") continue;
      const next = path.join(cur, part);
      let st;
      try {
        st = fs.lstatSync(next);
      } catch {
        throw new SandboxError(`cannot resolve workspace path component: ${JSON.stringify(part)}`);
      }
      if (st.isSymbolicLink())
        throw new SandboxError(`path escapes the workspace via a symlinked directory: ${JSON.stringify(part)}`);
      if (!st.isDirectory())
        throw new SandboxError(`workspace path component is not a directory: ${JSON.stringify(part)}`);
      cur = next;
    }
  }

  /** RACE-FREE containment on an ALREADY-OPEN fd: the fd is pinned to the real file, so read WHERE it
   * actually landed via `/proc/self/fd` and refuse if a symlinked PARENT component (which O_NOFOLLOW on
   * the final component does not stop) redirected the open outside the workspace. Node has no `openat`,
   * so this closes the lstat-then-open TOCTOU that _verifyParentDirs alone would leave. */
  _assertFdInWorkspace(fd, rel) {
    let real;
    try {
      real = fs.readlinkSync(`/proc/self/fd/${fd}`);
    } catch {
      return; // /proc unavailable (non-Linux): the lstat pre-check already ran
    }
    const base = fs.realpathSync(this._ws);
    if (real !== base && !real.startsWith(base + path.sep))
      throw new SandboxError(`path escapes the workspace: ${JSON.stringify(rel)}`);
  }

  /** Read `path` (workspace-relative) from the workspace - host-direct. A symlink in the final component
   * is refused by O_NOFOLLOW; a symlinked intermediate component is caught by _verifyParentDirs (fast) AND
   * _assertFdInWorkspace (race-free, on the open fd) - no lstat-then-open TOCTOU. */
  async readFile(rel, { maxBytes = null } = {}) {
    this._requireEntered();
    const full = this._wsPath(rel);
    this._verifyParentDirs(full); // fast reject + nice error before we open (host-leak guard)
    let fd;
    try {
      // O_NONBLOCK: opening a FIFO returns a descriptor instead of WAITING FOR A WRITER. Measured
      // before this flag: a box that runs `mkfifo out.png` makes `readFile("out.png")` hang with no
      // timeout and no way to interrupt it, so the box decides how long the host's call takes. That is
      // a denial of service the workspace hands out for free, and O_NOFOLLOW does not touch it.
      fd = fs.openSync(full, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    } catch (e) {
      throw new SandboxError(`cannot read ${JSON.stringify(rel)}: ${e.message}`);
    }
    try {
      this._assertFdInWorkspace(fd, rel); // race-free backstop: a swapped-in parent symlink is caught here
      // AND THE FLAG ALONE WOULD BE WORSE THAN THE HANG. A non-blocking read of a writer-less FIFO
      // returns zero bytes, so `readFile` would answer `<Buffer >` and the caller would read an empty
      // file where the box had planted a pipe. Refuse anything that is not a REGULAR file: FIFO,
      // device, socket, directory. Judged on the OPEN DESCRIPTOR, not on a path that can be swapped.
      const st = fs.fstatSync(fd);
      if (!st.isFile())
        throw new SandboxError(
          `refusing to read ${JSON.stringify(rel)}: not a regular file (a FIFO, device or socket ` +
            `planted in the workspace can stall or fake this read)`,
        );
      // maxBytes caps the read so a file a not-fully-trusted box wrote can't OOM the host.
      if (maxBytes !== null && st.size > maxBytes)
        throw new SandboxError(
          `${JSON.stringify(rel)} is ${st.size} bytes, larger than maxBytes=${maxBytes}, so the ` +
            "read was REFUSED. maxBytes is a ceiling on what may be read at all, not a request " +
            "for the first bytes: nothing was returned. Raise it, or drop it and slice the result.",
        );
      return fs.readFileSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }

  /** List regular files under the workspace (excluding the .deps install dir and our env file). */
  async listFiles(subdir = "") {
    this._requireEntered();
    let root;
    if (subdir) {
      root = this._wsPath(subdir);
      // a box that plants `peek -> /tmp` must not make listFiles("peek") enumerate a host dir's names
      // (the walk's followlinks=false does NOT stop it, since it follows the ROOT). Reject a symlinked
      // subdir (parents via _verifyParentDirs, the final component via lstat).
      this._verifyParentDirs(root);
      let st;
      try {
        st = fs.lstatSync(root);
      } catch {
        throw new SandboxError(`cannot list ${JSON.stringify(subdir)}`);
      }
      if (st.isSymbolicLink())
        throw new SandboxError(`path escapes the workspace via a symlinked directory: ${JSON.stringify(subdir)}`);
      if (!st.isDirectory()) throw new SandboxError(`not a directory: ${JSON.stringify(subdir)}`);
    } else {
      root = this._ws;
    }
    const walked = this._walk(root);
    return Object.entries(walked).map(([p, [, size]]) => ({ path: p, size, change: "created" }));
  }

  // -- workspace snapshot (a cheap FILESYSTEM checkpoint; NOT a memory snapshot) --------------------

  /** Write a gzip tar of the whole workspace to `dest` on the host, a portable filesystem checkpoint.
   * Pair with restore() (or seed a new Sandbox({ workspace })) to resume the FILE state later or
   * elsewhere. NOT a memory snapshot: processes are ephemeral, only on-disk state is captured. */
  // The Node snapshot/restore path uses a HAND-ROLLED ustar parser. While it is new, it is opt-in: set
  // KERN_SANDBOX_SNAPSHOT=1 to enable it. Fails CLOSED (refuses, never silently degrades). The Python
  // binding uses the stdlib `tarfile` and has no such gate. Remove this once the parser is battle-tested.
  _requireSnapshotOptIn() {
    if (process.env.KERN_SANDBOX_SNAPSHOT !== "1")
      throw new SandboxError(
        "snapshot/restore is opt-in in the Node binding while its archive parser is new: " +
          "set KERN_SANDBOX_SNAPSHOT=1 to enable it (the Python binding uses stdlib tarfile and is always on)",
      );
  }

  snapshot(dest) {
    this._requireEntered();
    this._requireSnapshotOptIn();
    fs.writeFileSync(dest, tarPack(fs.realpathSync(this._ws), ENV_FILE));  // prefix-excluded inside tarPack
  }

  /** Extract a snapshot (from snapshot()) into the workspace, SAFELY. Every member is vetted first:
   * absolute paths, `..` escapes and non-file/dir members (symlinks, devices, hardlinks) are refused,
   * and each path must resolve under the workspace; the final component is opened O_NOFOLLOW. Colliding
   * files are overwritten. */
  restore(src) {
    this._requireEntered();
    this._requireSnapshotOptIn();
    const base = fs.realpathSync(this._ws);
    const members = tarParse(fs.readFileSync(src));
    for (const m of members) {
      if (m.name === "") continue;
      if (m.name.startsWith("/") || m.name.split("/").includes(".."))
        throw new SandboxError(`unsafe path in snapshot: ${JSON.stringify(m.name)}`);
      if (m.type === "other")
        throw new SandboxError(`unsafe member type in snapshot (only files/dirs): ${JSON.stringify(m.name)}`);
      const resolved = path.resolve(base, m.name);
      if (resolved !== base && !resolved.startsWith(base + path.sep))
        throw new SandboxError(`snapshot member escapes the workspace: ${JSON.stringify(m.name)}`);
    }
    for (const m of members) {
      if (m.name === "") continue;
      const dest = path.join(base, m.name);
      // _ensureParentDirs descends one level at a time and REFUSES a symlinked component, so a symlink
      // the box planted in the workspace (e.g. `evil -> ~/.ssh`) can't steer a member outside it. A
      // plain mkdir -p would follow that symlink (the lexical pre-vet above does not resolve it).
      this._ensureParentDirs(dest);
      if (m.type === "dir") {
        let st = null;
        try {
          st = fs.lstatSync(dest);
        } catch {
          st = null;
        }
        if (st === null) {
          // mkdirSync is not O_NOFOLLOW: a box could swap `dest` for a symlink between _ensureParentDirs
          // and here (mkdir-through-symlink -> an empty dir created OUTSIDE the workspace). Node has no
          // mkdirat, so close the race by re-lstat'ing after: a symlink swapped in is caught. No member
          // content is ever written through it (file writes use O_NOFOLLOW leaves).
          try {
            fs.mkdirSync(dest);
          } catch (e) {
            if (e.code !== "EEXIST") throw e;
          }
          const post = fs.lstatSync(dest);
          if (post.isSymbolicLink() || !post.isDirectory())
            throw new SandboxError(`snapshot dir member is not a real directory: ${JSON.stringify(m.name)}`);
        } else if (st.isSymbolicLink() || !st.isDirectory()) {
          throw new SandboxError(`snapshot dir member collides with a non-directory: ${JSON.stringify(m.name)}`);
        }
        continue;
      }
      // O_NOFOLLOW: a symlink already planted at this leaf can't redirect the write outside the workspace.
      const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW;
      const fd = fs.openSync(dest, flags, 0o644);
      try {
        fs.writeSync(fd, m.content);
      } finally {
        fs.closeSync(fd);
      }
    }
  }

  // -- setup (the only network window) -------------------------------------------------------------

  async _runSetup(cmd) {
    // The network is ON only here, in a SEPARATE setup box that dies at the end. `pip install X` is
    // routed to <workspace>/.deps; every runCode box is network-off.
    const install = `pip install --target ${WORKSPACE}/${DEPS_DIR} --no-cache-dir --disable-pip-version-check`;
    let shellCmd = cmd;
    if (cmd.trim().startsWith("pip install "))
      shellCmd = install + " " + cmd.trim().slice("pip install ".length);
    const r = await this._spawn(["sh", "-c", shellCmd], {
      network: true,
      timeoutS: Math.max(this.timeoutS, 120),
      isSetup: true,
    });
    if (!r.success)
      throw new SandboxError(`setup failed (exit ${r.exitCode}): ${(r.stderr || r.stdout).trim().slice(0, 400)}`);
    // PRECOMPILE HERE, because this is the last moment `.deps` is writable.
    //
    // `depsReadonly` defaults to true, so every runCode box mounts `.deps` read-only and CPython cannot
    // write a `__pycache__` into it. It tolerates that silently and recompiles on every import instead,
    // which is correct and is not free. Measured on `requests`, seven calls each: a setup that leaves
    // bytecode behind (pip's default) reads 250 ms/call writable and 252 read-only, while one that does
    // not (`pip install --no-compile`) reads 250 writable and 290 read-only. So the read-only default
    // would cost +40 ms on EVERY call of such a session, for as long as it lives. One `compileall` here
    // removes it: that case comes back to 250, and it is a no-op when the bytecode already exists.
    //
    // `|| true` because bytecode is an optimisation: a file that will not compile must not fail an
    // install that succeeded. The user's command ran first and separately, so it keeps the exit code.
    if (this.depsReadonly && fs.existsSync(path.join(this._ws, DEPS_DIR))) {
      await this._spawn(["sh", "-c", `python3 -m compileall -q ${WORKSPACE}/${DEPS_DIR} || true`], {
        network: false,
        timeoutS: Math.max(this.timeoutS, 120),
        isSetup: true,
      });
    }
  }

  // -- files diff (created/modified; excludes .deps and our env file) ------------------------------

  _snapshot() {
    return this._walk(this._ws);
  }

  _walk(root) {
    const base = this._ws;
    const out = {};
    const stack = [root];
    while (stack.length) {
      const dir = stack.pop();
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const ent of entries) {
        if (ent.isDirectory()) {
          if (ent.name === DEPS_DIR) continue; // exclude deps from the diff
          stack.push(path.join(dir, ent.name));
          continue;
        }
        const fp = path.join(dir, ent.name);
        let st;
        try {
          st = fs.lstatSync(fp);
        } catch {
          continue;
        }
        if (!st.isFile()) continue; // excludes symlinks and non-regular files
        const rel = path.relative(base, fp);
        if (Sandbox._isEnvFile(rel)) continue; // our private host-side env file, not a user artifact
        out[rel] = [Math.round(st.mtimeMs * 1e6), st.size];
      }
    }
    return out;
  }

  _diff(before) {
    const after = this._snapshot();
    const files = [];
    for (const [rel, meta] of Object.entries(after)) {
      if (!(rel in before)) files.push({ path: rel, size: meta[1], change: "created" });
      else if (before[rel][0] !== meta[0] || before[rel][1] !== meta[1])
        files.push({ path: rel, size: meta[1], change: "modified" });
    }
    return files;
  }

  // -- the two ways to run code --------------------------------------------------------------------

  /** Run a snippet of `code` on the workspace in a fresh, network-off box. File state persists to the
   * next call; in-memory state does NOT. `language` is "python" (default), "bash", "sh" or "node", and
   * the image must provide it: "bash" runs bash, not the POSIX shell. Large
   * code is written to a workspace file and run by path (no argv-size limit). */
  /** Resolve a per-call `timeoutS` override against the constructor default: undefined/null inherits
   * the session's, any override must be a positive number of seconds. */
  _effTimeout(timeoutS) {
    if (timeoutS === undefined || timeoutS === null) return this.timeoutS;
    if (typeof timeoutS !== "number" || !(timeoutS > 0))
      throw new SandboxError("timeoutS must be a positive number of seconds");
    return timeoutS;
  }

  async runCode(code, { language = "python", timeoutS, onStdout = UNSET, onStderr = UNSET } = {}) {
    this._requireEntered();
    // Each runner: [binary, inline-eval-flag, file-extension]. Note node evaluates with `-e`, NOT `-c`
    // (which is node's syntax-CHECK flag and would run nothing); python/sh use `-c`.
    // `bash` runs BASH. It used to run `sh`, and on a Debian image that is `dash`, with bash sitting
    // right there in the image unused: `[[ 1 == 1 ]]` answered `sh: 1: [[: not found`. Nothing was
    // missing, the wrong binary was picked, and an LLM writes bash by reflex. `sh` is the honest name
    // for the old behaviour and is now reachable: POSIX, present in every image, alpine included.
    const runners = {
      python: ["python3", "-c", "py"],
      bash: ["bash", "-c", "sh"],
      sh: ["sh", "-c", "sh"],
      node: ["node", "-e", "js"],
    };
    const spec = runners[language];
    if (!spec)
      throw new SandboxError(
        `unsupported language ${JSON.stringify(language)} (v1: 'python' | 'bash' | 'sh' | 'node')`,
      );
    const [runner, evalFlag, ext] = spec;
    const eff = this._effTimeout(timeoutS);
    if (language === "python")
      return this._runPythonCell(code, { timeoutS: eff, onStdout, onStderr });
    let command;
    if (Buffer.byteLength(code, "utf8") > INLINE_CODE_MAX) {
      const cell = `.cell-${crypto.randomBytes(4).toString("hex")}.${ext}`;
      await this.writeFile(cell, code);
      command = [runner, `${WORKSPACE}/${cell}`];
    } else {
      command = [runner, evalFlag, code];
    }
    return this._spawn(command, { network: this.network, timeoutS: eff, onStdout, onStderr });
  }

  /** Run Python through the cell runner so a trailing expression, display() calls and matplotlib
   * figures are captured as rich mime-typed `result.results` (Jupyter/E2B-style). stdout/stderr/exit
   * are identical to a plain run; capture is best-effort. Internal cell/runner/results files are
   * removed and hidden from `result.files`. */
  async _runPythonCell(code, { timeoutS, onStdout = UNSET, onStderr = UNSET } = {}) {
    const eff = this._effTimeout(timeoutS);
    // Prewarmed fast path, taken ONLY where it is observationally identical to the cold one below.
    // The streaming callback is the gate that is easy to get wrong: a prewarmed box answers with one
    // length-prefixed frame after the cell has finished, so there is no chunk to hand a callback as it
    // arrives. Calling it once at the end would look like streaming without being it, so a streaming
    // call takes the cold path and streams for real.
    const streaming =
      (onStdout === UNSET ? this.onStdout : onStdout) !== null ||
      (onStderr === UNSET ? this.onStderr : onStderr) !== null;
    if (this._pool && !streaming && !code.includes("\0")) {
      const warm = this._pool.claim({ network: this.network, deadlineS: eff });
      if (warm) {
        const before = this.trackFiles ? this._snapshot() : null;
        return warm.runCell(code, { deadlineS: eff, before });
      }
    }
    const uid = crypto.randomBytes(4).toString("hex");
    const cell = `.cell-${uid}.py`;
    const resf = `.res-${uid}.json`;
    const runf = `.run-${uid}.py`;
    await this.writeFile(cell, code);
    const shim = PY_RUNNER.replace("__KERN_CELL__", `${WORKSPACE}/${cell}`).replace(
      "__KERN_RES__",
      `${WORKSPACE}/${resf}`,
    );
    await this.writeFile(runf, shim);
    const result = await this._spawn(["python3", `${WORKSPACE}/${runf}`], {
      network: this.network,
      timeoutS: eff,
      onStdout,
      onStderr,
    });
    try {
      const parsed = JSON.parse(await this.readFile(resf, { maxBytes: RESULTS_MAX }));
      if (Array.isArray(parsed))
        result.results = parsed.filter((r) => r && typeof r === "object").map((r) => new Result(r));
    } catch {
      /* missing / too-large / unreadable / bad JSON: leave results empty, run otherwise intact */
    }
    const internal = new Set([cell, resf, runf]);
    for (const name of internal) {
      try {
        fs.unlinkSync(path.join(this._ws, name));
      } catch {
        /* ignore */
      }
    }
    result.files = result.files.filter((fi) => !internal.has(fi.path));
    return result;
  }

  /** Run an arbitrary `command` (an argv ARRAY, never a shell string) in a fresh box. `timeoutS`,
   * `onStdout` and `onStderr` override the session defaults for this call only (see `runCode`). */
  async run(command, { timeoutS, onStdout = UNSET, onStderr = UNSET } = {}) {
    this._requireEntered();
    if (typeof command === "string")
      throw new SandboxError('run() takes an argv ARRAY, not a string. Use run(["sh","-c","..."]).');
    if (!Array.isArray(command) || command.length === 0)
      throw new SandboxError("run() needs a non-empty command array");
    return this._spawn(command, {
      network: this.network,
      timeoutS: this._effTimeout(timeoutS),
      onStdout,
      onStderr,
    });
  }

  /** Open a persistent, WARM Python interpreter in a long-lived box (warm-start): cells run in ONE
   * resident process, so in-memory state PERSISTS across cells and the per-cell cost drops from a full
   * interpreter boot (~10 ms) to sub-millisecond. Returns an OPEN Kernel; call `await k.close()` when
   * done (or wrap in try/finally). Trade vs runCode: cells share one process and one box, so it is
   * call-fast but NOT call-isolated (still network-off and resource-capped; a fresh session/kernel is
   * clean). A per-cell timeout tears the kernel down. */
  async kernel({ timeoutS } = {}) {
    this._requireEntered();
    const k = new Kernel(this, this._effTimeout(timeoutS));
    await k._open();
    return k;
  }
}

const KERNEL_BACKSTOP_S = 24 * 3600; // long-lived box; close()/timeout owns the real lifetime
const KERNEL_TIMEOUT = Symbol("kernel-timeout");
// The box is UNTRUSTED and controls the reply length prefix + body; without a cap it could stream a
// multi-GB frame and OOM the HOST (its own memory cap bounds what it BUILDS, not what the host ACCEPTS).
// A frame past the cap resolves the waiter with this sentinel, which tears the kernel down. Mirrors the
// one-shot path's RESULTS_MAX guard.
const KERNEL_OVERSIZE = Symbol("kernel-oversize");

// The raw-fd drain cap a PERSISTENT kernel has always used. Named rather than repeated so the one place
// that must not drift from the shipped behaviour says which number it is and why.
const KERNEL_DRAIN_CAP = 64 * 1024 * 1024;

/** Materialize PY_KERNEL_DRIVER for one caller's output budget and handshake.
 *
 * The driver text is byte-identical to the Python binding's, so it carries the same three placeholders
 * and they have to be filled in here too. Substitution and not a runtime read, because the driver runs
 * INSIDE the box where an environment variable is workload-writable: a cap the box can set is not a cap.
 * The values are stringified ints and a literal 0/1 from our own call sites, never from box input.
 *
 * @param {number} outCap  bytes of stdout/stderr kept per stream before the reply says it truncated
 * @param {number} resCap  byte budget for rich results; 0 or less means unbounded (the Kernel contract)
 * @param {boolean} hello  emit a readiness frame before the cell loop
 * @returns {string} */
function kernelDriver(outCap, resCap, hello = false) {
  return PY_KERNEL_DRIVER.replaceAll("__KERN_OUTCAP__", String(Math.trunc(outCap)))
    .replaceAll("__KERN_RESCAP__", String(Math.trunc(resCap)))
    .replaceAll("__KERN_HELLO__", hello ? "1" : "0");
}

/** A warm, persistent Python interpreter living in one long-lived box (see `Sandbox.kernel`). `runCode`
 * sends a cell over a length-prefixed pipe to the resident driver and resolves to an ExecutionResult with
 * captured stdout/stderr, exit code and rich `results`. In-memory state persists across cells; the box
 * stays network-off and resource-capped. `close()` (or a per-cell timeout) tears the box down. */
class Kernel {
  constructor(sbx, timeoutS) {
    this._sbx = sbx;
    this._timeout = timeoutS;
    this._child = null;
    this._name = "";
    this._childEnv = null;
    this._driver = "";
    // Frame reader state: accumulate chunks, concat ONCE per frame (not per chunk) so a large reply is
    // O(n), not O(n^2). `_need`/`_headerBytes` cache the parsed header so the body phase only counts bytes.
    this._chunks = []; // Buffer[]
    this._total = 0; // bytes buffered across _chunks
    this._need = -1; // body length once the header is parsed, else -1
    this._headerBytes = -1; // header line length incl newline, once parsed
    this._cap = 0; // max accepted frame bytes (set from sbx.maxOutputBytes in _open)
    this._waiters = []; // FIFO of { resolve, timer }; one reply per request keeps them in order
    this._stderr = Buffer.alloc(0);
    this._dead = false;
    // kern's memory-cap enforcement byte (2nd byte of KERN_STARTED_FD). For a RESIDENT box kern writes
    // it only at box teardown (a cell kills the kernel), so it arrives ~concurrent with the death we
    // detect on stdout; read once, bounded, on death (`_readCapSignal`). 0 = undetermined / old kern.
    this._capSignal = 0;
  }

  async _open() {
    const sbx = this._sbx;
    this._cap = sbx.maxOutputBytes;
    const uid = crypto.randomBytes(4).toString("hex");
    this._driver = `.kernel-${uid}.py`;
    // The historical constants, restated at the one call site that must not change: 64 MiB of raw drain
    // and no results budget (the host's frame cap stays the only bound), and no readiness frame, which a
    // persistent Kernel does not read and would consume as its first cell's reply.
    await sbx.writeFile(this._driver, kernelDriver(KERNEL_DRAIN_CAP, 0, false));
    this._name = uniqueName();
    this._childEnv = { ...process.env };
    if (!sbx.enforceLimits) this._childEnv.KERN_NO_SCOPE = "1";
    this._childEnv.KERN_STARTED_FD = "3"; // same unforgeable channel; here for the enforcement byte only
    const argv = [
      ...sbx._baseArgv(this._name, { network: sbx.network, timeoutS: KERNEL_BACKSTOP_S }),
      "--", "python3", `${WORKSPACE}/${this._driver}`,
    ];
    // detached: own process group so we can killpg the box + kern as a unit, like _spawn. fd 3 carries
    // the started/enforcement bytes; the workload never holds it.
    this._child = spawn(argv[0], argv.slice(1), {
      env: this._childEnv, detached: true, stdio: ["pipe", "pipe", "pipe", "pipe"],
    });
    const startedCh = this._child.stdio[3];
    if (startedCh) {
      startedCh.on("data", (b) => { if (b.length >= 2) this._capSignal = b[1]; });
      startedCh.on("error", () => {});
    }
    this._child.on("error", () => { this._dead = true; this._flush(null); });
    this._child.on("close", () => { this._dead = true; this._flush(null); });
    this._child.stdout.on("data", (d) => this._onData(d));
    this._child.stderr.on("data", (d) => {
      this._stderr = Buffer.concat([this._stderr, d]);
      if (this._stderr.length > sbx.maxOutputBytes)
        this._stderr = this._stderr.subarray(0, sbx.maxOutputBytes); // bound host RAM on a flooding box
    });
    return this;
  }

  _onData(d) {
    this._chunks.push(d);
    this._total += d.length;
    // Hard cap on buffered bytes (header slack + body): an untrusted box streaming without a valid frame
    // can't grow host RAM past the cap. Tear down rather than accept an unbounded reply.
    if (this._total > this._cap + 64) return this._flush(KERNEL_OVERSIZE);
    this._tryParse();
  }

  _coalesce() {
    // Materialize the buffered chunks into one Buffer (and keep it as the single chunk). Called only when
    // we must search/slice; the body phase avoids it until the whole frame is present, keeping it O(n).
    if (this._chunks.length > 1) this._chunks = [Buffer.concat(this._chunks, this._total)];
    return this._chunks.length ? this._chunks[0] : Buffer.alloc(0);
  }

  _tryParse() {
    for (;;) {
      if (this._need < 0) {
        const buf = this._coalesce();
        const nl = buf.indexOf(0x0a);
        if (nl < 0) {
          if (buf.length > 64) return this._flush(KERNEL_OVERSIZE); // header line with no newline
          return;
        }
        const n = parseInt(buf.subarray(0, nl).toString("ascii").trim(), 10);
        if (!Number.isInteger(n) || n < 0) return this._flush(null); // malformed framing
        if (n > this._cap) return this._flush(KERNEL_OVERSIZE);
        this._headerBytes = nl + 1;
        this._need = n;
      }
      if (this._total < this._headerBytes + this._need) return; // body incomplete: buffer, no concat
      const buf = this._coalesce();
      const body = buf.subarray(this._headerBytes, this._headerBytes + this._need).toString("utf8");
      const rest = buf.subarray(this._headerBytes + this._need);
      this._chunks = rest.length ? [rest] : [];
      this._total = rest.length;
      this._need = -1;
      this._headerBytes = -1;
      const w = this._waiters.shift();
      if (w) {
        clearTimeout(w.timer);
        w.resolve(body);
      }
    }
  }

  _flush(val) {
    // A protocol error (oversize/malformed) marks the kernel dead: the stream is desynced, do not keep it.
    if (val === KERNEL_OVERSIZE || val === null) this._dead = true;
    while (this._waiters.length) {
      const w = this._waiters.shift();
      clearTimeout(w.timer);
      w.resolve(val);
    }
  }

  async runCode(code, { timeoutS } = {}) {
    if (!this._child) throw new SandboxError("kernel not started");
    if (this._dead) throw new SandboxError("kernel is dead (a prior cell timed out, or the box exited)");
    if (typeof code !== "string" || code.includes("\0"))
      throw new SandboxError("code must be a string with no NUL byte");
    const eff = timeoutS != null ? this._sbx._effTimeout(timeoutS) : this._timeout;
    const started = Date.now();
    const payload = Buffer.from(code, "utf8");
    const reply = await new Promise((resolve) => {
      const timer = setTimeout(() => {
        const i = this._waiters.findIndex((w) => w.timer === timer);
        if (i >= 0) this._waiters.splice(i, 1);
        resolve(KERNEL_TIMEOUT);
      }, eff * 1000);
      this._waiters.push({ resolve, timer });
      try {
        this._child.stdin.write(`${payload.length}\n`);
        this._child.stdin.write(payload);
      } catch {
        const i = this._waiters.findIndex((w) => w.timer === timer);
        if (i >= 0) this._waiters.splice(i, 1);
        clearTimeout(timer);
        resolve(null);
      }
    });
    if (reply === KERNEL_TIMEOUT) return this._teardownResult("timeout", `cell exceeded ${eff}s`, started);
    if (reply === KERNEL_OVERSIZE)
      return this._teardownResult("killed", `the kernel reply exceeded the ${this._cap}-byte cap`, started);
    if (reply === null) {
      const err = this._stderr.toString("utf8");
      const [kind, dflt] = this._kernelDeathFault(err, await this._readCapSignal());
      return this._teardownResult(kind, err.trim() || dflt, started);
    }
    return this._resultFromReply(reply, started);
  }

  /** Turn one kernel reply into an `ExecutionResult`.
   *
   * Extracted so the UNTRUSTED-INPUT boundary is one named place a test can drive directly: `reply`
   * is JSON written INSIDE the box, by the same code the sandbox exists to contain. Every field is
   * attacker-chosen, and the question for each is what a missing or wrong-typed value must mean. */
  _resultFromReply(reply, started) {
    let obj;
    try {
      obj = JSON.parse(reply);
    } catch {
      return this._teardownResult("killed", "the kernel sent a malformed reply", started);
    }
    if (!obj || typeof obj !== "object")
      return this._teardownResult("killed", "the kernel sent a non-object reply", started);
    // `rc` is the ONE field whose absence cannot be defaulted. `success` is
    // `exitCode === 0 && fault === null`, so coercing a missing or non-integer `rc` to 0 - which is
    // what this did - reported a SUCCESSFUL run. Since the JSON comes from the box, a cell could
    // declare its own failed run successful by omitting the field or sending a string. An unusable
    // status is not a status: it is a protocol violation by the in-box runner, which always emits
    // `"rc"`, and it is handled like the malformed replies above. `Number.isInteger` also rejects a
    // boolean, a float and a numeric string, which is what it is here for.
    if (!Number.isInteger(obj.rc))
      return this._teardownResult("killed", "the kernel reply carried no usable exit code", started);
    // The REMAINING fields are informational, so a wrong type degrades to an empty value rather than
    // failing the call: coerced so a caller doing `r.stdout.trim()` cannot be crashed by a box that
    // sent a number.
    const results = Array.isArray(obj.results)
      ? obj.results.filter((r) => r && typeof r === "object").map((r) => new Result(r))
      : [];
    return new ExecutionResult({
      stdout: typeof obj.stdout === "string" ? obj.stdout : "",
      stderr: typeof obj.stderr === "string" ? obj.stderr : "",
      exitCode: obj.rc,
      durationMs: Date.now() - started,
      fault: null,
      files: [],
      truncated: false,
      results,
    });
  }

  /** Why the resident kernel box died mid-cell, as `[type, defaultMessage]`. A kern setup marker on
   * stderr means it never came up (startup_failed). Otherwise this is the runCode counterpart of the
   * one-shot _classify SIGKILL branch - a kernel death has no per-cell exit code. `capSignal` is kern's
   * unforgeable enforcement byte (0 = old kern / undetermined, 1 = memory cap enforced, 2 = requested
   * but NOT enforced): with a memoryMb cap AND not-reported-unenforced (`!== 2`), the cgroup OOM-killer
   * is the cause -> `oom`; when kern reports the cap did not bind (2), the kill is not attributable to
   * the box's cgroup -> `killed`; uncapped is also `killed`. */
  _kernelDeathFault(err, capSignal = 0) {
    if (looksLikeStartupFailure(err)) return ["startup_failed", "the kernel box failed to start"];
    if (this._sbx.memoryMb !== null && capSignal !== 2)
      return ["oom", "the kernel box was OOM-killed (it exceeded its memory cap)"];
    if (capSignal === 2)
      return [
        "killed",
        "the kernel box was SIGKILLed, but its memory cap was not enforced here (no cgroup delegation), so it is not attributed to a cgroup OOM",
      ];
    return ["killed", "the kernel box exited"];
  }

  /** kern's memory-cap enforcement byte for the resident box, read ONCE on kernel death. kern writes
   * the two-byte KERN_STARTED_FD signal only at box teardown (a resident box exits when a cell kills it),
   * ~concurrent with the death detected on stdout. The fd-3 `data` handler in `_open` records the byte
   * as it arrives; this awaits a BOUNDED window (the fd's own `end`, or 1 s) so the read is deterministic
   * rather than a race, then returns the byte (0 = EOF / old kern / not yet -> the memoryMb heuristic). */
  async _readCapSignal() {
    const ch = this._child && this._child.stdio && this._child.stdio[3];
    if (!ch) return 0;
    if (this._capSignal === 0 && !ch.destroyed) {
      await new Promise((res) => {
        const t = setTimeout(res, 1000);
        ch.once("end", () => { clearTimeout(t); res(); });
        ch.once("error", () => { clearTimeout(t); res(); });
      });
    }
    return this._capSignal;
  }

  _teardownResult(type, message, started) {
    this._kill();
    // Same rule as the one-shot path: a box that never STARTED (the kernel failed to boot) throws, it
    // does not return a hollow result. timeout/killed stay as data on the returned result.
    if (type === "startup_failed") throw new SandboxError(message || "the box failed to start");
    return new ExecutionResult({
      stdout: "",
      stderr: "",
      exitCode: -1,
      durationMs: Date.now() - started,
      fault: sandboxFault(type, message),
      files: [],
      truncated: false,
      results: [],
    });
  }

  _kill() {
    this._dead = true;
    this._flush(null);
    const child = this._child;
    if (!child) return;
    try {
      spawnSync(this._sbx._kern, ["stop", this._name], { env: this._childEnv, timeout: 5000, stdio: "ignore" });
    } catch {
      /* ignore */
    }
    try {
      if (child.pid) process.kill(-child.pid, "SIGKILL"); // whole process group (detached)
    } catch {
      /* ignore */
    }
    try {
      child.kill("SIGKILL");
    } catch {
      /* ignore */
    }
  }

  async close() {
    const child = this._child;
    if (child && !this._dead) {
      // Graceful: closing stdin makes the driver's _read() return None, so the box exits cleanly.
      try {
        child.stdin.end();
      } catch {
        /* ignore */
      }
      // Wait for the exit EVENT, capped at 150 ms, rather than sleeping 150 ms unconditionally: that
      // fixed sleep cost 152 ms on every close of a persistent kernel (measured) for a box that
      // exits in a few. A child that is already gone has emitted `exit` and will not emit it again,
      // so that case is tested directly instead of waited on.
      if (child.exitCode === null && child.signalCode === null) {
        await new Promise((resolve) => {
          let t = null;
          const onExit = () => {
            if (t !== null) clearTimeout(t);
            resolve();
          };
          t = setTimeout(() => {
            child.removeListener("exit", onExit);
            resolve();
          }, 150);
          child.once("exit", onExit);
        });
      }
      this._kill();
    } else {
      this._kill();
    }
    try {
      fs.unlinkSync(path.join(this._sbx._ws, this._driver));
    } catch {
      /* ignore */
    }
  }
}

// -- prewarm: the fresh-box guarantee at zero marginal cost ------------------------------------------

// How long a prewarmed box may sit unclaimed before it is stale. It bounds the ORPHAN window: every warm
// box carries kern's own --timeout set to this plus the session deadline it was started for, so a host
// process that dies without running close() leaves boxes that expire by themselves rather than living to
// a 24 h backstop. The pool refills continuously, so this is the failure bound, not the working lifetime.
const PREWARM_TTL_S = 300;
// How long a prewarmed box gets to reach its prompt before the pool gives up on it. Generous on purpose:
// it covers a first-run image pull and an aarch64 board. Nothing waits on it, so a large value is free.
const PREWARM_READY_MS = 120_000;

// Every live prewarmed box in this process, so an exit that skips close() still tears the boxes down.
// Best-effort by nature - a SIGKILL runs nothing - which is exactly why the TTL above is the mechanism.
const LIVE_WARM = new Set();
let warmExitHooked = false;

function hookWarmExit() {
  if (warmExitHooked) return;
  warmExitHooked = true;
  process.on("exit", () => {
    for (const b of [...LIVE_WARM]) {
      try {
        b.stopProcesses();
      } catch {
        /* an exit handler must never throw */
      }
    }
  });
}

/** One box that is already started and already holds a booted CPython which has run NO user code.
 *
 * A cold runCode pays two costs on the CALLER's clock: starting the box and booting the interpreter
 * inside it. Neither depends on the cell, so neither has to happen while the caller waits. This starts
 * them in advance and then serves EXACTLY ONE cell before the box is destroyed.
 *
 * The guarantee runCode documents is therefore unchanged. A cell still gets a private box that has
 * executed nothing else, and a virgin interpreter whose only prior action was importing this driver -
 * which is what a cold cell gets once its own boot finishes.
 *
 * One observable DOES differ, stated because "identical" was too broad a word for it: the interpreter
 * is older than the call. A cell that reads its own start time out of /proc/self/stat sees ~0 s cold
 * and up to PREWARM_TTL_S warm (measured: 0.0 s against 3.1 s). Nothing the SDK reports changes and no
 * boundary moves, but code that times itself from process start can tell. */
class WarmBox {
  constructor(sbx, key, budgetS, sweeper) {
    this._sbx = sbx;
    this.key = key;
    this._budgetS = budgetS;
    this._sweeper = sweeper || null;
    this._child = null;
    this._name = "";
    this._born = Date.now();
    this._spent = false;
    this._rc = null;
    this._capSignal = 0;
    this._stderr = Buffer.alloc(0);
    this._chunks = [];
    this._total = 0;
    this._need = -1;
    this._headerBytes = -1;
    this._cap = 0;
    this._waiters = [];
    this._dead = false;
  }

  async start() {
    const sbx = this._sbx;
    // The frame cap has to admit a reply the driver considers legal, or a cell that legitimately
    // truncates at maxOutputBytes would come back as an oversize FAULT instead. Two capped streams plus
    // the results budget plus JSON overhead is the largest well-formed reply, so that is the cap.
    this._cap = 2 * sbx.maxOutputBytes + RESULTS_MAX + 65536;
    this._name = uniqueName();
    // The driver goes in ARGV, not into a workspace file. A pooled box is started BEFORE the cell that
    // will use it, so a driver FILE would sit in the box-writable workspace across the whole inter-call
    // gap and any cell could rewrite it to hijack the next prewarmed box. In argv the source is fixed at
    // exec time and never exists as a path the sandbox can reach.
    const driver = kernelDriver(sbx.maxOutputBytes, RESULTS_MAX, true);
    const argv = [
      ...sbx._baseArgv(this._name, {
        network: sbx.network,
        timeoutS: PREWARM_TTL_S + this._budgetS,
      }),
      "--", "python3", "-c", driver,
    ];
    const childEnv = { ...process.env };
    if (!sbx.enforceLimits) childEnv.KERN_NO_SCOPE = "1";
    childEnv.KERN_STARTED_FD = "3";
    try {
      this._child = spawn(argv[0], argv.slice(1), {
        env: childEnv, detached: true, stdio: ["pipe", "pipe", "pipe", "pipe"],
      });
    } catch {
      return false;
    }
    const startedCh = this._child.stdio[3];
    if (startedCh) {
      startedCh.on("data", (b) => { if (b.length >= 2) this._capSignal = b[1]; });
      startedCh.on("error", () => {});
    }
    this._child.on("error", () => { this._dead = true; this._flush(null); });
    this._child.on("close", (code, signal) => {
      this._dead = true;
      // `toRc` is THE mapping this binding's cold path uses (128 + signum, not Python's negative
      // convention). Each binding has to match its OWN cold path: reporting -9 here made a Node timeout
      // come back as -9 warm and 137 cold, which is the same failure wearing two different faces.
      if (this._rc === null) this._rc = toRc(code, signal);
      this._flush(null);
    });
    this._child.stdout.on("data", (d) => this._onData(d));
    this._child.stderr.on("data", (d) => {
      this._stderr = Buffer.concat([this._stderr, d]);
      if (this._stderr.length > sbx.maxOutputBytes)
        this._stderr = this._stderr.subarray(0, sbx.maxOutputBytes);
    });
    hookWarmExit();
    LIVE_WARM.add(this);
    return true;
  }

  /** Block until the driver says it is at the prompt. This is what makes the box PREWARMED rather than
   * merely SPAWNED: `spawn` resolves at the fork, not when kern has built the box and CPython has
   * booted, so a pool that published on spawn alone hands out boxes that are still starting and the
   * caller pays the rest of the start itself. */
  async waitReady(ms = PREWARM_READY_MS) {
    const body = await this._await(ms);
    if (typeof body !== "string") return false;
    try {
      const o = JSON.parse(body);
      return !!o && o.hello === 1;
    } catch {
      return false;
    }
  }

  /** Whether this box may serve a call. Every term is a correctness gate, not an optimization:
   * `key` is the EXACT argv the call would otherwise produce, which is what stops a box prewarmed with
   * one posture from serving a call that asked for another; `deadlineS` must fit inside the backstop
   * this box was started with, or kern could kill a legal cell mid-run; and past the TTL the same race
   * opens anyway. */
  usableFor(key, deadlineS) {
    return (
      !this._spent && !this._dead && this._child !== null && this.key === key &&
      deadlineS <= this._budgetS && Date.now() - this._born < PREWARM_TTL_S * 1000
    );
  }

  // -- framing (same shape as Kernel's, which is the reader this protocol was written for) -----------

  _onData(d) {
    this._chunks.push(d);
    this._total += d.length;
    if (this._total > this._cap + 64) return this._flush(KERNEL_OVERSIZE);
    this._tryParse();
  }

  _coalesce() {
    if (this._chunks.length > 1) this._chunks = [Buffer.concat(this._chunks, this._total)];
    return this._chunks.length ? this._chunks[0] : Buffer.alloc(0);
  }

  _tryParse() {
    for (;;) {
      if (this._need < 0) {
        const buf = this._coalesce();
        const nl = buf.indexOf(0x0a);
        if (nl < 0) {
          if (buf.length > 64) return this._flush(KERNEL_OVERSIZE);
          return;
        }
        const n = parseInt(buf.subarray(0, nl).toString("ascii").trim(), 10);
        if (!Number.isInteger(n) || n < 0) return this._flush(null);
        if (n > this._cap) return this._flush(KERNEL_OVERSIZE);
        this._headerBytes = nl + 1;
        this._need = n;
      }
      if (this._total < this._headerBytes + this._need) return;
      const buf = this._coalesce();
      const body = buf.subarray(this._headerBytes, this._headerBytes + this._need).toString("utf8");
      const rest = buf.subarray(this._headerBytes + this._need);
      this._chunks = rest.length ? [rest] : [];
      this._total = rest.length;
      this._need = -1;
      this._headerBytes = -1;
      const w = this._waiters.shift();
      if (w) {
        clearTimeout(w.timer);
        w.resolve(body);
      }
    }
  }

  _flush(val) {
    if (val === KERNEL_OVERSIZE || val === null) this._dead = true;
    while (this._waiters.length) {
      const w = this._waiters.shift();
      clearTimeout(w.timer);
      w.resolve(val);
    }
  }

  _await(ms) {
    if (this._dead) return Promise.resolve(null);
    return new Promise((resolve) => {
      const w = { resolve, timer: null };
      w.timer = setTimeout(() => {
        const i = this._waiters.indexOf(w);
        if (i >= 0) this._waiters.splice(i, 1);
        resolve(KERNEL_TIMEOUT);
      }, ms);
      if (w.timer.unref) w.timer.unref();
      this._waiters.push(w);
    });
  }

  // -- the one cell ----------------------------------------------------------------------------------

  /** Run `code` in this box, then destroy it. Callable once; a second call throws rather than quietly
   * reusing a box that has already executed user code. */
  async runCell(code, { deadlineS, before }) {
    if (this._spent) throw new SandboxError("a prewarmed box serves exactly one cell");
    this._spent = true;
    if (this._child === null) throw new SandboxError("prewarmed box was never started");
    const started = Date.now();
    const payload = Buffer.from(code, "utf8");
    let body;
    try {
      this._child.stdin.write(`${payload.length}\n`);
      this._child.stdin.write(payload);
      body = await this._await(deadlineS * 1000);
    } catch {
      return this._faultResult("died", started, before);
    }
    if (body === KERNEL_TIMEOUT)
      return this._faultResult("timeout", started, before, `code exceeded ${deadlineS}s`);
    // Every branch below that rejects the reply produces the same shape, so it is written once. The
    // repetition was three copies of the same call differing only in a string, which is the form where
    // one copy quietly drifts from the others.
    const rejected = (message, truncated = false) =>
      this._result("", "", this._exitCode(), started, before, {
        truncated,
        fault: { type: "killed", message },
      });
    if (body === KERNEL_OVERSIZE) {
      this.retire();
      return rejected(
        `the box sent a reply larger than the ${this._sbx.maxOutputBytes}-byte output cap ` +
          "allows even after truncation",
        true,
      );
    }
    if (body === null) return this._faultResult("died", started, before);
    this.retire();
    let obj = null;
    try {
      obj = JSON.parse(body);
    } catch {
      /* handled below */
    }
    if (!obj || typeof obj !== "object" || Array.isArray(obj))
      return rejected("the box sent a malformed reply");
    // `rc` is the one field whose absence cannot be defaulted: defaulting it to 0 would let a cell
    // declare its own failed run successful. Same rule as Kernel's reply parser.
    if (typeof obj.rc !== "number" || !Number.isInteger(obj.rc))
      return rejected("the box reply carried no usable exit code");
    const results = Array.isArray(obj.results)
      ? obj.results.filter((r) => r && typeof r === "object").map((r) => new Result(r))
      : [];
    return this._result(String(obj.stdout ?? ""), String(obj.stderr ?? ""), obj.rc, started, before, {
      truncated: !!obj.trunc,
      results,
    });
  }

  _faultResult(kind, started, before, msg) {
    const err = this._stderr.toString("utf8");
    if (kind === "timeout") {
      this.retire();
      return this._result("", "", this._exitCode(), started, before, {
        fault: { type: "timeout", message: msg || "the code exceeded its deadline" },
      });
    }
    const capSignal = this._capSignal;
    this.retire();
    if (looksLikeStartupFailure(err)) throw new SandboxError(err.trim() || "the box failed to start");
    let type = "killed";
    let dflt = "the box exited before the code finished";
    if (this._sbx.memoryMb !== null && this._sbx.memoryMb !== undefined && capSignal !== 2) {
      type = "oom";
      dflt = "the box was OOM-killed (it exceeded its memory cap)";
    } else if (capSignal === 2) {
      dflt =
        "the box was SIGKILLed, but its memory cap was not enforced here (no cgroup delegation), " +
        "so it is not attributed to a cgroup OOM";
    }
    return this._result("", "", this._exitCode(), started, before, {
      fault: { type, message: err.trim() || dflt },
    });
  }

  /** The exit status a FAULT reports. The cold path hands back the box process's real wait status - a
   * SIGKILLed box is -9 - so a constant here would make one failure look like two different ones
   * depending on which path served it. */
  _exitCode() {
    return typeof this._rc === "number" ? this._rc : -1;
  }

  /** Assemble the result with the SAME shape the cold path returns, including the workspace diff.
   * `files` is computed here rather than left empty because a fast path that silently stopped reporting
   * created files would be a behaviour change disguised as a speed-up. */
  _result(stdout, stderr, exitCode, started, before, { truncated = false, fault = null, results = [] } = {}) {
    return new ExecutionResult({
      stdout,
      stderr,
      exitCode,
      durationMs: Date.now() - started,
      fault,
      files: before ? this._sbx._diff(before) : [],
      truncated,
      results,
    });
  }

  // -- teardown, split so the slow half never lands on a caller's clock ------------------------------

  /** End the box's workload NOW. Fast, idempotent, never throws.
   *
   * SIGKILLing the supervisor's process group ends everything inside the box: kern arms
   * PR_SET_PDEATHSIG(SIGKILL) on a foreground box, so the supervisor's death takes box PID 1, and PID 1
   * leaving its PID namespace takes every other process in it. Measured on the Python side with a cell
   * that leaves a background writer: it stops at the exact byte it had reached. That is what lets the
   * caller diff the workspace the moment this returns. */
  stopProcesses() {
    LIVE_WARM.delete(this);
    this._spent = true;
    const child = this._child;
    if (child === null) return;
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      /* already gone */
    }
    if (this._rc === null) this._rc = toRc(null, "SIGKILL");
  }

  /** The bookkeeping after the workload is dead: the pipes and the private env file.
   *
   * It deliberately does NOT run `kern stop`, because it is unnecessary: stopProcesses ends every
   * process in the box (measured against a CPU-bound background writer: it stops at the byte it had
   * reached, while the same cell with no kill runs on), and kern's registry entry clears by itself
   * within ~300 ms.
   *
   * A second reason was written here and was WRONG, kept because this binding is where it came from:
   * that `kern stop` does not return once the supervisor is dead. It does, in 2 to 5 ms. The
   * multi-second stalls were OURS - `spawnSync` blocks the single event loop that Node needs in order
   * to REAP the child just SIGKILLed, so the pid was still present from `kern stop`'s point of view and
   * it waited for it, correctly. Alternating sync and async calls shows it: 5, 6009, 4, 5 ms. */
  sweep() {
    const child = this._child;
    this._child = null;
    if (child) {
      for (const s of [child.stdin, child.stdout, child.stderr]) {
        try {
          s?.destroy();
        } catch {
          /* ignore */
        }
      }
    }
    // The private --env-file _baseArgv wrote for THIS box. _spawn removes its own; a prewarmed box has
    // no _spawn, so without this every warm box leaves one behind in a workspace the caller may persist.
    if (this._name) {
      try {
        fs.unlinkSync(this._sbx._envPath(this._name));
      } catch {
        /* ENOENT is fine */
      }
      this._name = "";
    }
  }

  /** Destroy the box completely and synchronously. Used from the pool's close and the start-failure
   * paths, where there is no worker to hand the sweep to. */
  kill() {
    this.stopProcesses();
    this.sweep();
  }

  /** End the workload on the caller's clock and hand the sweep to the pool. This is the hot path: it is
   * what turns a teardown measured in tens of milliseconds into a sub-millisecond one without
   * dropping any of it. */
  retire() {
    this.stopProcesses();
    if (this._sweeper) {
      try {
        this._sweeper(this);
        return;
      } catch {
        /* the pool refused it: fall through and do it here rather than not at all */
      }
    }
    this.sweep();
  }
}

/** Keeps up to `size` WarmBox instances ready for one Sandbox.
 *
 * A claim that finds nothing usable returns null and the caller takes the ordinary cold path: the pool
 * is an accelerator with no authority to change what runs. */
class WarmPool {
  constructor(sbx, size) {
    this._sbx = sbx;
    this._size = Math.max(0, Math.trunc(size) || 0);
    this._ready = [];
    this._starting = 0;
    this._closed = false;
    this._pending = new Set(); // in-flight sweeps, so close() can wait for them
  }

  /** The identity a warm box must match. Built from the REAL argv builder in `dry` mode, so an option
   * this session grows later is folded in automatically instead of needing to be listed here.
   *
   * The argv is not the whole posture, and that was a real hole: kern reads `KERN_*` variables from ITS
   * OWN environment when it builds the box, so a caller who sets `KERN_SECCOMP=denylist` after the pool
   * filled would have been served a box built under the previous filter. Every `KERN_*` variable is
   * folded in, rather than the handful we can name today, because the failure mode is a variable nobody
   * thought to list. */
  _key(network) {
    const argv = this._sbx._baseArgv("", { network, timeoutS: 0, dry: true }).join("\0");
    const env = Object.entries(process.env)
      .filter(([k]) => k.startsWith("KERN_"))
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${k}=${v}`)
      .join("\0");
    return `${argv}\0\0${env}`;
  }

  claim({ network, deadlineS }) {
    if (this._closed || this._size <= 0) return null;
    const key = this._key(network);
    let picked = null;
    const keep = [];
    const stale = [];
    for (const b of this._ready) {
      if (picked === null && b.usableFor(key, deadlineS)) picked = b;
      else if (b.key !== key || Date.now() - b._born >= PREWARM_TTL_S * 1000 || b._dead) stale.push(b);
      else keep.push(b);
    }
    this._ready = keep;
    for (const b of stale) b.kill();
    this.refill({ network, deadlineS });
    return picked;
  }

  /** Top the pool up in the background. Bounded by `size` counting ready AND starting boxes, so a burst
   * of claims cannot spawn an unbounded number of boxes. */
  refill({ network, deadlineS }) {
    if (this._closed || this._size <= 0) return;
    const want = this._size - this._ready.length - this._starting;
    if (want <= 0) return;
    this._starting += want;
    for (let i = 0; i < want; i++) {
      const p = this._startOne(network, deadlineS).catch(() => {});
      this._pending.add(p);
      p.finally(() => this._pending.delete(p));
    }
  }

  /** Start one box and publish it, releasing the reserved slot on EVERY path.
   *
   * The slot release is in a `finally` and the box is built inside the `try`, which is not tidiness:
   * `_key()` calls the real argv builder and that CAN throw (an env value containing a newline is
   * refused there). Thrown before the decrement, the slot stayed reserved forever, `want` went
   * negative, and the pool never refilled again for the rest of the session, silently, with `refill`'s
   * own `.catch(() => {})` swallowing the reason. Same shape as the Python binding's dead-worker
   * case: a permanent stop with no signal. */
  async _startOne(network, deadlineS) {
    let box = null;
    let ok = false;
    try {
      box = new WarmBox(this._sbx, this._key(network), deadlineS, (b) => this._sweep(b));
      ok = (await box.start()) && (await box.waitReady());
    } catch {
      ok = false;
    } finally {
      this._starting -= 1;
    }
    if (box === null) return; // never constructed: there is nothing to publish and nothing to kill
    if (ok && !this._closed) {
      this._ready.push(box);
      return;
    }
    // Three ways to land here and all of them must destroy the box: the start failed, the box came up
    // but never signalled readiness, or the session closed while it was still building.
    box.kill();
  }

  _sweep(box) {
    if (this._closed) {
      box.sweep();
      return;
    }
    // Off the caller's microtask turn: `kern stop` is a synchronous subprocess and must not be awaited
    // by whoever just got their result.
    setImmediate(() => {
      try {
        box.sweep();
      } catch {
        /* best-effort */
      }
    });
  }

  async close() {
    this._closed = true;
    const boxes = this._ready;
    this._ready = [];
    for (const b of boxes) b.kill();
    // Wait for boxes still starting, or close() would return while a `kern box` is being forked and the
    // session's workspace is about to be deleted underneath it.
    if (this._pending.size) await Promise.allSettled([...this._pending]);
  }
}

/** Open a Sandbox, run `fn(sandbox)`, and close it (deleting a temp workspace) even if `fn` throws.
 * The idiomatic session helper - the equivalent of Python's `with Sandbox() as s:`. */
async function withSandbox(opts, fn) {
  if (typeof opts === "function") {
    fn = opts;
    opts = {};
  }
  const sbx = new Sandbox(opts);
  await sbx.open();
  try {
    return await fn(sbx);
  } finally {
    await sbx.close();
  }
}

/** One-shot convenience: run `code` in a throwaway session (workspace created and deleted). Equivalent
 * to `withSandbox(opts, s => s.runCode(code, {language}))`. For multi-step work, use withSandbox(). */
async function runCode(code, opts = {}) {
  const { language = "python", ...rest } = opts;
  return withSandbox(rest, (s) => s.runCode(code, { language }));
}

module.exports = {
  // Exported so a consumer that wants a DIFFERENT default can express it as a multiple of this
  // one rather than declaring a second independent number that drifts from it.
  DEFAULT_TMPFS_MB,
  Sandbox,
  Kernel,
  withSandbox,
  runCode,
  ExecutionResult,
  Result,
  SandboxError,
  MountRefused,
  version: VERSION,
};
