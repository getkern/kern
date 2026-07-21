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

const VERSION = "0.1.8";

const DEFAULT_IMAGE = "python:3.12-slim";
const WORKSPACE = "/workspace"; // where the persistent workspace is mounted inside every box
const DEPS_DIR = ".deps"; // pip --target dir inside the workspace (added to PYTHONPATH for python)
const ENV_FILE = ".kern-env"; // host-side 0600 env file (kept out of argv so values don't show in `ps`)
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
`;

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

/** A PROGRAMMER/config error, THROWN: bad argument, illegal mount, or `kern` not installed. Runtime
 * sandbox events (timeout, blocked escape, OOM-kill) are NOT thrown - they are data in result.fault. */
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
  throw new SandboxError(
    "the `kern` binary was not found on PATH - install it " +
      "(https://github.com/getkern/kern) or set $KERN_BIN",
  );
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

/** Validate one egress-allowlist domain (an FQDN like "pypi.org") before it reaches the argv. */
function validateDomain(domain) {
  if (typeof domain !== "string" || !DOMAIN_RE.test(domain))
    throw new SandboxError(
      `invalid egress domain ${JSON.stringify(domain)}: expected a bare hostname like 'pypi.org' ` +
        "(no scheme, port, path, wildcard or spaces)",
    );
  return domain;
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
  for (const line of stderr.split("\n")) {
    const s = line.replace(/^\s+/, "");
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
      if (rel === skip) continue; // our private --env-file, not user state
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
   * @param {string[]} [opts.profiles] kern resource profiles to attach, e.g. ["vcpu:heavy","vgpio:leds","vdisk:scratch"]; each names a block in your kern.toml. Strictly validated.
   * @param {Object<string,string>} [opts.env] extra environment for the workload.
   * @param {number} [opts.maxOutputBytes]   cap on captured stdout/stderr EACH. Default 64 MiB.
   * @param {boolean} [opts.enforceLimits]   true (default) hard-enforces caps via a systemd scope.
   * @param {boolean} [opts.depsReadonly]    mount setup= deps read-only for runCode (block poisoning).
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
    this.profiles = opts.profiles ?? null;
    this.env = opts.env ?? null;
    this.maxOutputBytes = opts.maxOutputBytes ?? 64 * 1024 * 1024;
    // live output callbacks: called with each Buffer chunk as it arrives. The full capped output is
    // still captured in the result, so you can stream AND read result.stdout.
    this.onStdout = opts.onStdout ?? null;
    this.onStderr = opts.onStderr ?? null;
    this.enforceLimits = opts.enforceLimits ?? true;
    this.depsReadonly = opts.depsReadonly ?? false;
    // trackFiles=true populates result.files by walking the workspace before AND after each call (O(N)
    // in file count); a long session that accretes files slows every runCode. false = result.files [], O(1).
    this.trackFiles = opts.trackFiles ?? true;

    if (!(this.timeoutS > 0)) throw new SandboxError("timeoutS must be a positive number of seconds");
    if (!(this.maxOutputBytes > 0)) throw new SandboxError("maxOutputBytes must be positive");

    this._mountArgs = [];
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
      }
    }
    this._profileArgs = (this.profiles || []).map(validateProfile);
    this._egressAllow = (this.egressAllow || []).map(validateDomain);
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
    return this;
  }

  /** Close the session: delete the workspace iff we created it. Idempotent. */
  async close() {
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

  _baseArgv(name, { network, timeoutS, isSetup = false }) {
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
    argv.push("--timeout", String(Math.floor(timeoutS) + 5));
    if (this.memoryMb !== null) argv.push("--memory", `${this.memoryMb}m`);
    if (this.cpus !== null) argv.push("--cpus", String(this.cpus));
    if (this.pids !== null) argv.push("--pids-limit", String(this.pids));
    // Network mode: egressAllow (a domain allowlist via an isolated netns + kern's filtering proxy)
    // governs the untrusted runCode/run boxes; the setup box keeps the full network it needs to install
    // deps. egressAllow and network are mutually exclusive (checked at construction).
    if (this._egressAllow.length && !isSetup) argv.push("--egress-allow", this._egressAllow.join(","));
    else if (network) argv.push("--net");
    // Resource profiles (vcpu:/vgpio:/vdisk:NAME): positional tokens `kern box` resolves against the
    // user's kern.toml. Validated at construction, so nothing here can be a smuggled flag.
    argv.push(...this._profileArgs);
    argv.push(...this._mountArgs);

    const mergedEnv = { ...(this.env || {}) };
    if (mergedEnv.PYTHONPATH === undefined) mergedEnv.PYTHONPATH = `${WORKSPACE}/${DEPS_DIR}`;
    // Pass env via a private 0600 --env-file, NOT `--env K=V` on argv (an argv value is visible in
    // `ps` to any local user for the box's lifetime; a credential in env= would leak).
    if (Object.keys(mergedEnv).length > 0) {
      const envPath = path.join(this._ws, ENV_FILE);
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

    const started = process.hrtime.bigint();
    return new Promise((resolve, reject) => {
      let child;
      try {
        // detached: own process group, so we can signal the box + kern as a unit (killpg).
        child = spawn(argv[0], argv.slice(1), {
          env: childEnv,
          detached: true,
          stdio: ["ignore", "pipe", "pipe"],
        });
      } catch (e) {
        return reject(new SandboxError(`could not spawn the box: ${e.message}`));
      }

      const out = cappedCollector(child.stdout, this.maxOutputBytes, cbOut);
      const err = cappedCollector(child.stderr, this.maxOutputBytes, cbErr);
      let timedOut = false;
      let settled = false;

      const timer = setTimeout(() => {
        timedOut = true;
        this._teardown(child, name, childEnv);
      }, timeoutS * 1000);

      // Hard safety net: a CPU-bound box can survive our signals until kern's backstop reaps it; never
      // hang the caller. If close hasn't fired a few seconds after our teardown, resolve anyway.
      let hardTimer = null;
      const finish = (code, signal) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (hardTimer) clearTimeout(hardTimer);
        const wallMs = Number((process.hrtime.bigint() - started) / 1000000n);
        const stdout = out.buffer().toString("utf8");
        const stderr = err.buffer().toString("utf8");
        const rc = toRc(code, signal);
        const fault = this._classify(rc, signal, stderr, timedOut, timeoutS);
        const files = before ? this._diff(before) : [];
        resolve(
          new ExecutionResult({
            stdout, stderr, exitCode: rc, durationMs: wallMs, fault, files,
            truncated: out.truncated || err.truncated,
          }),
        );
      };

      child.on("error", (e) => {
        if (e && e.code === "ENOENT")
          return reject(new SandboxError(`could not execute kern (${argv[0]}): not found`));
        return reject(new SandboxError(`could not execute kern: ${e.message}`));
      });
      child.on("close", (code, signal) => {
        finish(code, signal);
      });
      // arm the hard net only once we've decided to kill (teardown sets timedOut)
      const armHardNet = () => {
        if (hardTimer) return;
        hardTimer = setTimeout(() => finish(EXIT_SIGKILL, "SIGKILL"), 10000);
      };
      // re-check shortly after the deadline in case teardown fired
      const watch = setInterval(() => {
        if (settled) {
          clearInterval(watch);
        } else if (timedOut) {
          clearInterval(watch);
          armHardNet();
        }
      }, 250);
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

  _classify(rc, signal, stderr, timedOut, timeoutS) {
    // ORDER IS A SECURITY PROPERTY: deterministic-by-exit-code classes are decided BEFORE the stderr
    // heuristic, because stderr is a channel the workload controls.
    if (timedOut)
      return sandboxFault(
        "timeout",
        `exceeded the ${timeoutS ?? this.timeoutS}s time limit (killed by the binding)`,
      );
    if (rc === EXIT_SIGSYS || signal === "SIGSYS")
      return sandboxFault("escape_blocked", "a syscall was blocked by the seccomp filter (SIGSYS)");
    if (rc === EXIT_SIGKILL || signal === "SIGKILL")
      return sandboxFault("killed", "the box was killed (SIGKILL) - likely out of memory (exit 137)");
    if (rc === EXIT_SIGTERM || signal === "SIGTERM")
      return sandboxFault("timeout", "the box exceeded its time limit (reaped by kern's timeout backstop)");
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
      fd = fs.openSync(
        full,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW,
        0o644,
      );
    } catch (e) {
      throw new SandboxError(`cannot write ${JSON.stringify(rel)}: ${e.message}`);
    }
    try {
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
      fd = fs.openSync(full, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    } catch (e) {
      throw new SandboxError(`cannot read ${JSON.stringify(rel)}: ${e.message}`);
    }
    try {
      this._assertFdInWorkspace(fd, rel); // race-free backstop: a swapped-in parent symlink is caught here
      // maxBytes caps the read so a file a not-fully-trusted box wrote can't OOM the host.
      if (maxBytes !== null && fs.fstatSync(fd).size > maxBytes)
        throw new SandboxError(`${JSON.stringify(rel)} exceeds maxBytes=${maxBytes}`);
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
    fs.writeFileSync(dest, tarPack(fs.realpathSync(this._ws), ENV_FILE));
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
        if (rel === ENV_FILE) continue; // our private host-side env file, not a user artifact
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
   * next call; in-memory state does NOT. `language` is "python" (default), "bash", or "node". Large
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
    const runners = {
      python: ["python3", "-c", "py"],
      bash: ["sh", "-c", "sh"],
      node: ["node", "-e", "js"],
    };
    const spec = runners[language];
    if (!spec)
      throw new SandboxError(`unsupported language ${JSON.stringify(language)} (v1: 'python' | 'bash' | 'node')`);
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
      timeoutS: this._effTimeout(timeoutS),
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
  }

  async _open() {
    const sbx = this._sbx;
    this._cap = sbx.maxOutputBytes;
    const uid = crypto.randomBytes(4).toString("hex");
    this._driver = `.kernel-${uid}.py`;
    await sbx.writeFile(this._driver, PY_KERNEL_DRIVER);
    this._name = uniqueName();
    this._childEnv = { ...process.env };
    if (!sbx.enforceLimits) this._childEnv.KERN_NO_SCOPE = "1";
    const argv = [
      ...sbx._baseArgv(this._name, { network: sbx.network, timeoutS: KERNEL_BACKSTOP_S }),
      "--", "python3", "-S", `${WORKSPACE}/${this._driver}`,
    ];
    // detached: own process group so we can killpg the box + kern as a unit, like _spawn.
    this._child = spawn(argv[0], argv.slice(1), {
      env: this._childEnv, detached: true, stdio: ["pipe", "pipe", "pipe"],
    });
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
      const kind = looksLikeStartupFailure(err) ? "startup_failed" : "killed";
      return this._teardownResult(kind, err.trim() || "the kernel box exited", started);
    }
    let obj;
    try {
      obj = JSON.parse(reply);
    } catch {
      return this._teardownResult("killed", "the kernel sent a malformed reply", started);
    }
    if (!obj || typeof obj !== "object")
      return this._teardownResult("killed", "the kernel sent a non-object reply", started);
    const results = Array.isArray(obj.results)
      ? obj.results.filter((r) => r && typeof r === "object").map((r) => new Result(r))
      : [];
    // obj is UNTRUSTED (box-controlled JSON): coerce scalars so a non-string stdout / non-int rc can't
    // crash a caller doing r.stdout.trim() or arithmetic on r.exitCode.
    return new ExecutionResult({
      stdout: typeof obj.stdout === "string" ? obj.stdout : "",
      stderr: typeof obj.stderr === "string" ? obj.stderr : "",
      exitCode: Number.isInteger(obj.rc) ? obj.rc : 0,
      durationMs: Date.now() - started,
      fault: null,
      files: [],
      truncated: false,
      results,
    });
  }

  _teardownResult(type, message, started) {
    this._kill();
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
      await new Promise((r) => setTimeout(r, 150));
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
