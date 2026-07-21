"""kern-mcp: a Model Context Protocol (stdio) server that exposes the kern sandbox as a **local**
code-interpreter tool for Claude Desktop, Cursor, Windsurf, Goose, and any MCP client.

It speaks MCP over stdio (newline-delimited JSON-RPC 2.0) and is **dependency-free**: it imports only
the stdlib and this package. One long-lived `Sandbox` session backs the connection, so FILE state
persists across tool calls (a workspace on disk) while each call runs in a fresh, network-off box.

Run it directly:  ``python -m kern_sandbox.mcp``  (or the ``kern-mcp`` console script).

Claude Desktop / Cursor config (``claude_desktop_config.json`` / MCP settings):

    {
      "mcpServers": {
        "kern": {
          "command": "kern-mcp",
          "env": { "KERN_MCP_SETUP": "pip install numpy pandas matplotlib" }
        }
      }
    }

Environment knobs (all optional): ``KERN_MCP_IMAGE`` (default python:3.12-slim), ``KERN_MCP_SETUP``
(a one-time ``pip install ...``), ``KERN_MCP_MEMORY_MB`` (default 1024), ``KERN_MCP_TIMEOUT`` (default
60s), ``KERN_MCP_WORKSPACE`` (persist the workspace at this path instead of a temp dir),
``KERN_MCP_PROFILES`` (comma-separated kern.toml profiles, e.g. ``vcpu:heavy,vgpio:sensors``),
``KERN_MCP_KERNEL`` (set to ``1`` to route python run_code through ONE persistent WARM interpreter:
in-memory state persists across calls and each call is sub-ms instead of a ~10 ms interpreter boot; still
NEVER-NET; a runaway cell that times out respawns the kernel, it never dooms the session), ``KERN_BIN``.
"""
from __future__ import annotations

import json
import os
import sys
import traceback

from . import Kernel, Sandbox, SandboxError, __version__

# The single MCP protocol revision we implement; initialize always answers with THIS (we negotiate to
# our version, we never echo a client-chosen string back).
_PROTOCOL = "2024-11-05"

# The box is UNTRUSTED: it controls the workspace files and its own stdout. Bound everything the server
# reads back into host RAM / the JSON-RPC reply so a malicious cell can't flood the client or OOM the host.
_READ_CAP = 16 * 1024 * 1024      # read_file: max bytes pulled from a (box-written) workspace file
_MAX_TEXT = 16_000                # chars per stdout/stderr stream surfaced to the model (LLM-sized, not 64MiB)
_MAX_RICH = 4_000                 # chars of an html/json rich result surfaced as text
_MAX_IMAGE_B64 = 6_000_000        # skip a SINGLE image result larger than ~4.5 MB decoded
_MAX_REPLY_IMG = 8 * 1024 * 1024  # AGGREGATE image budget for one reply (N small images can't sum to GBs)
_MAX_TOTAL_TEXT = 64_000          # AGGREGATE text budget for one reply (unbounded rich-result COUNT can't blow up)
_MAX_FRAME = 8 * 1024 * 1024      # max chars of one inbound JSON-RPC line; bounds a no-newline stdin flood


def _clip(s: str, n: int) -> str:
    """Bound a box-controlled string before it goes into the reply."""
    return s if len(s) <= n else s[:n] + f"\n...[truncated {len(s) - n} chars]"


def _env_int(name: str, default: int) -> int:
    """A positive int from the environment, else the default - so a negative/garbage operator value can't
    poison the session (every later call failing identically in the Sandbox constructor)."""
    try:
        v = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return v if v > 0 else default

_TOOLS = [
    {
        "name": "run_code",
        "description": (
            "Run Python (default), bash, or node code in a fast, LOCAL, isolated kern sandbox on the "
            "user's own machine and return stdout/stderr plus any rich results. A matplotlib figure, "
            "the last bare expression, and every display() call are captured; charts come back as "
            "images you can see. The network is OFF and a mandatory timeout applies. FILE state in the "
            "workspace persists across calls (write a file, read it next call); in-memory state does "
            "not (each call is a fresh box). Use this to compute, analyze data, plot, or test code."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "The code to run."},
                "language": {
                    "type": "string",
                    "enum": ["python", "bash", "node"],
                    "description": "Language of the snippet (default python).",
                },
                "timeout_s": {
                    "type": "number",
                    "description": "Wall-clock limit in seconds for this call (default from server).",
                },
            },
            "required": ["code"],
        },
    },
    {
        "name": "write_file",
        "description": "Write text to a file in the sandbox workspace (path is workspace-relative and "
        "confined; symlink- and ..-safe). Use it to stage data before run_code reads it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Workspace-relative path."},
                "content": {"type": "string", "description": "UTF-8 text to write."},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a UTF-8 text file from the sandbox workspace (workspace-relative, confined). "
        "Returns the text; the read is size-capped to protect the host.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Workspace-relative path."}},
            "required": ["path"],
        },
    },
    {
        "name": "list_files",
        "description": "List regular files in the sandbox workspace (excludes the internal deps dir).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]

# Required arguments (and their types) per tool. Validated UP FRONT as -32602 before any binding call,
# so a KeyError/TypeError from deep in the binding can never be misreported as a "missing argument".
_ARG_SPEC = {
    "run_code": {"code": str},
    "write_file": {"path": str, "content": str},
    "read_file": {"path": str},
    "list_files": {},
}


class _Server:
    """One MCP connection: lazily opens a single Sandbox session that backs every tool call."""

    def __init__(self) -> None:
        self._sbx: "Sandbox | None" = None
        self._kernel: "Kernel | None" = None
        # Opt-in warm kernel: KERN_MCP_KERNEL=1 routes python run_code through ONE persistent, warm
        # interpreter (state persists across calls, per-cell cost ~sub-ms instead of the ~10 ms CPython
        # boot). Still NEVER-NET: the kernel box inherits the session's network=False, so an agent's code
        # cannot reach the network in kernel mode either.
        self._use_kernel = os.environ.get("KERN_MCP_KERNEL", "").strip().lower() in ("1", "true", "yes")

    # -- lifecycle ---------------------------------------------------------------------------------
    def _session(self) -> Sandbox:
        if self._sbx is None:
            image = os.environ.get("KERN_MCP_IMAGE", "python:3.12-slim")
            setup = os.environ.get("KERN_MCP_SETUP") or None
            workspace = os.environ.get("KERN_MCP_WORKSPACE") or None
            memory_mb = _env_int("KERN_MCP_MEMORY_MB", 1024)
            timeout_s = _env_int("KERN_MCP_TIMEOUT", 60)
            # Attach reusable kern.toml resource profiles (comma-separated), e.g.
            # KERN_MCP_PROFILES="vcpu:heavy,vdisk:scratch,vgpio:sensors". vgpio: is the ONLY way to grant
            # the box a hardware device set - the edge/robotics wedge for an MCP agent on a Pi/Jetson.
            # Each token is validated by the SDK (prefix:alphanumeric), so it can't smuggle another flag.
            prof = os.environ.get("KERN_MCP_PROFILES")
            profiles = [t.strip() for t in prof.split(",") if t.strip()] if prof else None
            env = {"MPLCONFIGDIR": "/tmp"}  # matplotlib needs a writable cache in the read-only box
            sbx = Sandbox(
                image=image, setup=setup, workspace=workspace, memory_mb=memory_mb,
                timeout_s=timeout_s, env=env, profiles=profiles,
                # the MCP layer never surfaces result.files (it has a dedicated list_files tool), so skip
                # the per-call O(N) workspace diff: run_code stays O(1) even as a session accretes files.
                track_files=False,
            )
            try:
                sbx.__enter__()
            except BaseException:
                # __enter__ can fail AFTER creating the temp workspace / a setup box (e.g. setup= exits
                # non-zero). Tear it down so a repeatedly-failing setup doesn't leak a workspace per call.
                try:
                    sbx.__exit__(None, None, None)
                except Exception:
                    pass
                raise
            self._sbx = sbx
        return self._sbx

    def _get_kernel(self) -> Kernel:
        """Lazily open (or re-open) the warm kernel on the session. A per-cell timeout tears a kernel
        down; we respawn transparently so one runaway cell never dooms the whole MCP session."""
        sbx = self._session()
        if self._kernel is None:
            k = Kernel(sbx, sbx._eff_timeout(None))
            k.__enter__()
            self._kernel = k
        return self._kernel

    def close(self) -> None:
        if self._kernel is not None:
            try:
                self._kernel.__exit__(None, None, None)
            except Exception:
                pass
            self._kernel = None
        if self._sbx is not None:
            try:
                self._sbx.__exit__(None, None, None)
            except Exception:
                pass
            self._sbx = None

    # -- JSON-RPC plumbing (newline-delimited over stdio) ------------------------------------------
    @staticmethod
    def _send(msg: dict) -> None:
        # ensure_ascii=False keeps non-ASCII as real UTF-8 (1-4 bytes) instead of \uXXXX escapes (6-12
        # bytes): without it a reply "bounded" in code points could be up to 12x larger in wire bytes.
        # main() forces stdout to UTF-8 with errors="replace" so this can never raise UnicodeEncodeError.
        sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    def _result(self, mid: object, result: dict) -> None:
        self._send({"jsonrpc": "2.0", "id": mid, "result": result})

    def _error(self, mid: object, code: int, message: str) -> None:
        self._send({"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}})

    # -- dispatch ----------------------------------------------------------------------------------
    def handle(self, msg: dict) -> None:
        method = msg.get("method")
        mid = msg.get("id")
        is_request = mid is not None
        if method == "initialize":
            # Negotiate, don't echo: always answer with the version WE implement, never a client-chosen
            # string (echoing an arbitrary version back can make a client assume features we lack).
            self._result(mid, {
                "protocolVersion": _PROTOCOL,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "kern-sandbox", "version": __version__},
            })
        elif method in ("notifications/initialized", "initialized", "notifications/cancelled"):
            pass  # notifications: no response
        elif method == "ping":
            if is_request:
                self._result(mid, {})
        elif method == "tools/list":
            self._result(mid, {"tools": self._tools_view()})
        elif method == "resources/list":
            self._result(mid, {"resources": []})
        elif method == "prompts/list":
            self._result(mid, {"prompts": []})
        elif method == "tools/call":
            self._tool_call(mid, msg.get("params") or {})
        elif is_request:
            self._error(mid, -32601, f"method not found: {method}")

    def _tools_view(self) -> list:
        """The tool list. In warm-kernel mode, tell the client the truth: python state now PERSISTS
        across run_code calls (otherwise a model told "fresh box per call" would be misled)."""
        if not self._use_kernel:
            return _TOOLS
        import copy
        tools = copy.deepcopy(_TOOLS)
        for t in tools:
            if t.get("name") == "run_code":
                t["description"] += (
                    " NOTE: this server runs a persistent WARM interpreter, so Python in-memory state"
                    " (variables, imports) PERSISTS across run_code calls within this session."
                )
        return tools

    # -- tools -------------------------------------------------------------------------------------
    def _tool_call(self, mid: object, params: object) -> None:
        # params / arguments are client-controlled SHAPE, not just type: a truthy non-dict (a JSON array
        # or string) would AttributeError on .get() OUTSIDE the try below and kill the whole server loop.
        # Guard the shape here so a malformed tools/call is a clean -32602, never a crash.
        if not isinstance(params, dict):
            self._error(mid, -32602, "params must be an object")
            return
        name = params.get("name")
        args = params.get("arguments")
        if not isinstance(args, dict):
            args = {}
        # Validate tool name + required args + types up front as -32602. The try below then wraps only
        # real work, so a KeyError/TypeError from deep in the binding can't be misreported as a missing
        # argument (nor leak a box-controlled key into a structured error message).
        spec = _ARG_SPEC.get(name)
        if spec is None:
            self._error(mid, -32602, f"unknown tool: {name!r}")
            return
        for key, typ in spec.items():
            if key not in args:
                self._error(mid, -32602, f"missing required argument: {key!r}")
                return
            if not isinstance(args[key], typ):
                self._error(mid, -32602, f"argument {key!r} must be {typ.__name__}")
                return
        try:
            if name == "run_code":
                content, is_err = self._run_code(args)
            elif name == "write_file":
                self._session().write_file(args["path"], args["content"])
                content, is_err = [{"type": "text", "text": f"wrote {_clip(args['path'], 200)}"}], False
            elif name == "read_file":
                data = self._session().read_file(args["path"], max_bytes=_READ_CAP)
                content, is_err = [{"type": "text", "text": _clip(data.decode("utf-8", "replace"), _READ_CAP)}], False
            else:  # list_files (validated present in _ARG_SPEC)
                # The box controls the workspace and can create millions of files; bound the listing by
                # both COUNT and total size so it can't blow the reply up (the only tool without a cap).
                files = self._session().list_files()
                lines, total = [], 0
                for i, f in enumerate(files):
                    line = f"{f.path} ({f.size}B)"
                    if len(lines) >= 10_000 or total + len(line) > _MAX_TOTAL_TEXT:
                        lines.append(f"...[{len(files) - i} more files omitted: reply-size cap]")
                        break
                    lines.append(line)
                    total += len(line) + 1
                content, is_err = [{"type": "text", "text": "\n".join(lines) or "(empty)"}], False
        except SandboxError as e:
            # bound the message too: it can carry a client path or box-influenced startup stderr
            content, is_err = [{"type": "text", "text": _clip(f"kern error: {e}", 2000)}], True
        except Exception as e:  # never crash; log internals to OUR stderr, send the client only the type
            traceback.print_exc(file=sys.stderr)
            content, is_err = [{"type": "text", "text": f"internal error: {type(e).__name__}"}], True
        self._result(mid, {"content": content, "isError": is_err})

    def _run_code(self, args: dict) -> "tuple[list, bool]":
        code = args.get("code", "")
        language = args.get("language", "python")
        if language not in ("python", "bash", "node"):  # defense in depth (the binding also validates)
            return [{"type": "text", "text": f"unsupported language: {language!r}"}], True
        kw = {}
        # bool is an int subclass, so exclude it explicitly (timeout_s=true would pass isinstance(int)
        # and reach the binding as a deadline of 1); also require a positive number, else use the default.
        ts = args.get("timeout_s")
        if isinstance(ts, (int, float)) and not isinstance(ts, bool) and ts > 0:
            kw["timeout_s"] = ts
        if language == "python" and self._use_kernel:
            # Warm-kernel path: python cells run in ONE persistent interpreter (sub-ms, state persists).
            # bash/node still take the fresh-box path below. Kernel.run_code has no `language` kwarg.
            try:
                r = self._get_kernel().run_code(code, **kw)
            except SandboxError:
                # kernel was torn down by a prior timeout: respawn a fresh warm kernel and retry once.
                self._kernel = None
                r = self._get_kernel().run_code(code, **kw)
            if r.fault is not None:
                # this cell tore the kernel down (timeout/kill); drop it so the NEXT call respawns warm.
                self._kernel = None
        else:
            r = self._session().run_code(code, language=language, **kw)
        content: list = []
        # Image results (a chart the model can SEE). The box is untrusted and can emit an UNBOUNDED
        # NUMBER of results, so we cap both the single image (_MAX_IMAGE_B64) AND the AGGREGATE bytes
        # (_MAX_REPLY_IMG); otherwise 500 sub-cap figures would sum to a multi-GB reply.
        img_budget = _MAX_REPLY_IMG
        omitted = 0
        for res in r.results:
            for mime in ("image/png", "image/jpeg"):
                b64 = res.data.get(mime)
                # res.data is UNTRUSTED (box-controlled JSON): a non-str payload would TypeError on
                # len()/slice or land a non-string as image `data` in the reply. Require a str.
                if not isinstance(b64, str) or not b64 or len(b64) > _MAX_IMAGE_B64:
                    continue
                if len(b64) <= img_budget:
                    content.append({"type": "image", "data": b64, "mimeType": mime})
                    img_budget -= len(b64)
                else:
                    omitted += 1
        # Text summary: accumulate against a RUNNING budget (the box can emit an unbounded NUMBER of
        # rich results), stopping as soon as it is spent - so transient host RAM is bounded too, not just
        # the final reply. Mirrors the image budget above.
        body: list = []
        text_budget = _MAX_TOTAL_TEXT
        text_truncated = False

        def take(s: str) -> None:
            nonlocal text_budget, text_truncated
            if text_budget <= 0:
                text_truncated = True
                return
            clip = _clip(s, text_budget)
            if len(clip) < len(s):
                text_truncated = True
            body.append(clip)
            text_budget -= len(clip)

        if r.stdout.strip():
            take(_clip(r.stdout.rstrip(), _MAX_TEXT))
        if r.stderr.strip():
            take("[stderr]\n" + _clip(r.stderr.rstrip(), _MAX_TEXT))
        for res in r.results:
            if text_budget <= 0:
                text_truncated = True
                break  # stop READING further results, not just trimming - bounds transient RAM
            # surface text-shaped rich results: HTML, SVG (XML text), Markdown, JSON. SVG/markdown were
            # dropped before (only html/json were checked), so a cell that returns an SVG was invisible.
            rich = (res.data.get("text/html") or res.data.get("image/svg+xml")
                    or res.data.get("text/markdown") or res.data.get("application/json"))
            if isinstance(rich, str) and rich:  # box-controlled: only surface an actual string
                take("[rich result]\n" + _clip(rich, _MAX_RICH))
        # tail + notes are appended AFTER the budget, so the exit code and the truncation notes can never
        # be clipped away in the high-output case (exactly when they matter most).
        tail = f"[exit {r.exit_code}"
        if r.fault:
            tail += f", sandbox fault: {r.fault.type}"
        tail += "]"
        notes = [tail]
        if omitted:
            notes.append(f"[{omitted} image result(s) omitted: reply-size cap]")
        if text_truncated:
            notes.append("[output truncated: reply-size cap]")
        text = ("\n\n".join(body) if body else "(no output)") + "\n\n" + "\n".join(notes)
        content.append({"type": "text", "text": text})
        return content, (not r.success)


def main() -> None:
    server = _Server()
    # Deterministic stdio encoding regardless of the operator's locale: UTF-8 out (so ensure_ascii=False
    # is safe and never raises), and tolerant in, so a bad byte can't crash the transport.
    for stream, kw in ((sys.stdout, {"errors": "replace"}), (sys.stdin, {"errors": "replace"})):
        try:
            stream.reconfigure(encoding="utf-8", **kw)
        except (AttributeError, ValueError):
            pass
    try:
        while True:
            # readline(_MAX_FRAME) returns AT MOST _MAX_FRAME chars, so a client flooding a gigabyte
            # with no newline is read in bounded chunks instead of buffering into host RAM.
            line = sys.stdin.readline(_MAX_FRAME)
            if line == "":  # EOF
                break
            if len(line) >= _MAX_FRAME and not line.endswith("\n"):
                # Oversize frame with no newline: drain the REST of this line so the next read starts at a
                # fresh message boundary (resync), rather than parsing the tail of a giant frame.
                while True:
                    chunk = sys.stdin.readline(_MAX_FRAME)
                    if chunk == "" or chunk.endswith("\n"):
                        break
                continue
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # malformed frame: skip, keep serving
            if isinstance(msg, dict):
                server.handle(msg)
    except (KeyboardInterrupt, BrokenPipeError):
        pass  # client closed the pipe or Ctrl-C: shut down cleanly (nobody left to answer)
    finally:
        server.close()


if __name__ == "__main__":
    main()
