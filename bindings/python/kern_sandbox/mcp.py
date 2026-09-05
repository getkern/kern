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
(a one-time ``pip install ...``), ``KERN_MCP_MEMORY_MB`` (default 1024; set it to ``0`` to pass no
``--memory`` at all, which is the only way to let a ``vcpu:`` profile's own ``memory=`` apply - simply
unsetting it still sends the 1024 default and shadows the profile), ``KERN_MCP_TIMEOUT`` (default
60s), ``KERN_MCP_WORKSPACE`` (persist the workspace at this path instead of a temp dir),
``KERN_MCP_PROFILES`` (comma-separated kern.toml profiles, e.g. ``vcpu:heavy,vgpio:sensors``),
``KERN_MCP_KERNEL`` (set to ``1`` to route python run_code through ONE persistent WARM interpreter:
in-memory state persists across calls and each call is sub-ms instead of a ~10 ms interpreter boot; still
NEVER-NET; a runaway cell that times out respawns the kernel, it never dooms the session),
``KERN_MCP_QUIET`` (default on: suppress kern's non-fatal notes so a tools/call returns only the cell's
own output; set to ``0`` to restore them), ``KERN_MCP_TMPFS_MB`` (default 64: scratch at ``/tmp``,
charged to the box's own memory cap; ``0`` removes it and puts /tmp back inside the read-only root),
``KERN_BIN``.
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

# `_READ_CAP` bounds what the HOST loads; this bounds what the REPLY carries. They are different limits:
# without the second one a read_file on a 16 MiB workspace file answered with 16 MiB of text in a single
# tools/call - 250x the budget every other tool respects, enough to blow a model's context and stall the
# client's stdio transport. The host cap stays large so a legitimate big file still reads and reports.
_MAX_FILE_TEXT = _MAX_TOTAL_TEXT
# The image this server runs unless the operator names another. Its CONTENTS are a fact we hold and
# state in the tool schema (python, bash and sh; no node); for any other image we can only name it,
# because guessing interpreters from a tag would be inventing a measurement.
_DEFAULT_MCP_IMAGE = "python:3.12-slim"
_MAX_NAME = 200                   # chars of a client-supplied method/tool name echoed back in an error


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


def _env_cap(name: str, default: int) -> int | None:
    """Like ``_env_int``, plus ``0`` as an explicit "none": it returns ``None`` rather than the default.

    Used by two knobs, and both need the sentinel for the same reason: without it every path here
    produces an int, so "off" is unreachable and an operator who typed ``0`` silently gets the default.
    For ``KERN_MCP_MEMORY_MB`` that means no ``--memory`` flag at all, so a ``vcpu:`` profile's own
    ``memory=`` applies; for ``KERN_MCP_TMPFS_MB`` it means no scratch.

    Unsetting the variable is NOT that: it yields ``default``, an explicit flag, and kern's "explicit
    flag wins over profile" rule then shadows the profile's value.

    ``0`` with no profile attached means uncapped, which is the same thing the SDK does for
    ``memory_mb=None``. Garbage and negatives still fall back to ``default``, because a typo is not a
    decision."""
    raw = os.environ.get(name)
    if raw is not None and raw.strip() == "0":
        return None
    return _env_int(name, default)

_TOOLS = [
    {
        "name": "run_code",
        "description": (
            "Run Python (default), bash or POSIX-sh code in a fast, LOCAL, isolated kern sandbox on "
            "the user's own machine and return stdout/stderr plus any rich results. A matplotlib figure, "
            "the last bare expression, and every display() call are captured; charts come back as "
            "images you can see. The network is OFF and a mandatory timeout applies. FILE state in the "
            "workspace persists across calls (write a file, read it next call); in-memory state does "
            "not (each call is a fresh box). Use this to compute, analyze data, plot, or test code."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "The code to run."},
                # The enum is what the RUNNER accepts, not what the image contains, and those are two
                # different facts. A model that reads only the enum concludes node works and tells the
                # user so; the description is the only place that can stop it, because this server
                # cannot narrow the list without probing an image it may not have pulled yet.
                # `_tools_view` appends the configured image name so the sentence is about THIS server.
                "language": {
                    "type": "string",
                    "enum": ["python", "bash", "sh", "node"],
                    "description": (
                        "Language of the snippet (default python). The interpreter must exist IN THE "
                        "IMAGE this server runs: the enum lists what the runner accepts, not what the "
                        "image ships. Asking for a missing one fails immediately and names it. "
                        "'bash' runs bash and 'sh' runs the POSIX shell, which are different shells: "
                        "use 'bash' for [[ ]], arrays or pipefail, and 'sh' where the image may not "
                        "carry bash."
                    ),
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
        # Read ONCE, like _use_kernel, because two readers is one too many: `_tools_view` tells the
        # model which image this is and `_session` starts it, and those two must not be able to
        # disagree about which image "this server" means.
        self._image = os.environ.get("KERN_MCP_IMAGE", _DEFAULT_MCP_IMAGE)

    # -- lifecycle ---------------------------------------------------------------------------------
    def _session(self) -> Sandbox:
        if self._sbx is None:
            image = self._image
            setup = os.environ.get("KERN_MCP_SETUP") or None
            workspace = os.environ.get("KERN_MCP_WORKSPACE") or None
            memory_mb = _env_cap("KERN_MCP_MEMORY_MB", 1024)
            timeout_s = _env_int("KERN_MCP_TIMEOUT", 60)
            # Attach reusable kern.toml resource profiles (comma-separated), e.g.
            # KERN_MCP_PROFILES="vcpu:heavy,vdisk:scratch,vgpio:sensors". vgpio: is the ONLY way to grant
            # the box a hardware device set - the edge/robotics wedge for an MCP agent on a Pi/Jetson.
            # Each token is validated by the SDK (prefix:alphanumeric), so it can't smuggle another flag.
            prof = os.environ.get("KERN_MCP_PROFILES")
            profiles = [t.strip() for t in prof.split(",") if t.strip()] if prof else None
            # Scratch for the read-only box. This is what makes `MPLCONFIGDIR=/tmp` below TRUE: until
            # the SDK mounted a tmpfs there, /tmp was part of the read-only root, so the cache dir this
            # server hands matplotlib was not writable. `0` turns it off for an operator who wants the
            # old shape back; anything else is a MiB size charged to the box's own memory cap.
            # `_env_cap` and not `_env_int`: `0` has to mean "none at all" rather than fall back to the
            # default, and it is the same sentinel (and the same garbage handling) the memory knob uses.
            tmpfs_mb = _env_cap("KERN_MCP_TMPFS_MB", 64)
            tmpfs = {"/tmp": f"{tmpfs_mb}m"} if tmpfs_mb is not None else {}
            env = {"MPLCONFIGDIR": "/tmp"}  # matplotlib needs a writable cache in the read-only box
            # Prewarming is ON by default HERE, and off in the SDK, because this server is the case where
            # the trade is already decided: an MCP session holds one box's worth of memory for its whole
            # life anyway, calls arrive seconds apart (the model is thinking in between, so the pool is
            # always refilled), and the cost it removes is the one the operator actually feels. Measured
            # on this path: 40.9 ms per call without it, 1.3 ms with it, with the fresh-box guarantee
            # untouched - each prewarmed box serves exactly one cell and is destroyed.
            # `_env_cap`, not `_env_int`: `_env_int` maps any non-positive value back to the default, so
            # `KERN_MCP_PREWARM=0` would silently mean 1 and "off" would be unreachable from the
            # environment. This is the same sentinel the memory and tmpfs knobs need, for the same
            # reason, and it is the THIRD one - the table in docs/MCP.md says so.
            prewarm_cap = _env_cap("KERN_MCP_PREWARM", 1)
            prewarm = 0 if prewarm_cap is None else prewarm_cap
            sbx = Sandbox(
                image=image, setup=setup, workspace=workspace, memory_mb=memory_mb,
                timeout_s=timeout_s, env=env, profiles=profiles, tmpfs=tmpfs,
                # the MCP layer never surfaces result.files (it has a dedicated list_files tool), so skip
                # the per-call O(N) workspace diff: run_code stays O(1) even as a session accretes files.
                track_files=False,
                # A warm KERNEL and a warm POOL solve the same cost twice and would fight over it: the
                # kernel path never reaches `run_code`, so a pool behind it would hold boxes nothing
                # claims. The kernel wins when it is asked for, because it is the stronger promise (state
                # persists); prewarming serves the default, where state must NOT persist.
                prewarm=0 if self._use_kernel else max(0, prewarm),
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

    def _drop_kernel(self) -> None:
        """Tear the warm kernel down and forget it, so the next call respawns a fresh one.

        Dropping the reference alone is NOT enough: ``Kernel`` has no ``__del__`` and registers no
        ``weakref.finalize``; its only teardown is ``__exit__``, which kills the process group. Clearing
        the attribute without it strands the interpreter child for the whole life of the MCP server, and
        a session that keeps timing out would strand one per timeout."""
        k, self._kernel = self._kernel, None
        if k is not None:
            try:
                k.__exit__(None, None, None)
            except Exception:
                pass

    def close(self) -> None:
        self._drop_kernel()
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
        if method in ("notifications/initialized", "initialized", "notifications/cancelled"):
            return  # notifications: no response
        if not is_request:
            # JSON-RPC 2.0 section 4.1: a Notification carries no `id`, and the server MUST NOT reply to
            # one. Every branch below answers, so the guard belongs HERE rather than inside each: without
            # it a `tools/list` or `tools/call` sent without an id got `{"id": null, ...}` back, which a
            # strict client may drop or surface as a protocol error. An explicit `"id": null` is not a
            # valid request id either, so it takes the same path.
            return
        if method == "initialize":
            # Negotiate, don't echo: always answer with the version WE implement, never a client-chosen
            # string (echoing an arbitrary version back can make a client assume features we lack).
            self._result(mid, {
                "protocolVersion": _PROTOCOL,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "kern-sandbox", "version": __version__},
            })
        elif method == "ping":
            self._result(mid, {})
        elif method == "tools/list":
            self._result(mid, {"tools": self._tools_view()})
        elif method == "resources/list":
            self._result(mid, {"resources": []})
        elif method == "prompts/list":
            self._result(mid, {"prompts": []})
        elif method == "tools/call":
            self._tool_call(mid, msg.get("params") or {})
        else:
            # Same amplification as the tool name: `method` is client-controlled and arrives inside a
            # frame that may be _MAX_FRAME long, so it is clipped before it goes back out. It also goes
            # out through !r, exactly like the unknown-tool error: JSON accepts a lone surrogate, repr
            # escapes it, and a raw one would instead reach the encoder inside _send. That only survives
            # because main() reconfigured stdout with errors="replace", and that reconfigure is allowed
            # to fail silently, in which case the reply is lost and the client waits for it forever.
            shown = _clip(method, _MAX_NAME) if isinstance(method, str) else type(method).__name__
            self._error(mid, -32601, f"method not found: {shown!r}")

    def _tools_view(self) -> list:
        """The tool list, adapted to what THIS server actually is. Two things the static table cannot
        know: whether a warm kernel makes python state persist, and which image the operator pointed it
        at. Both are cases where a model reading the static text would be told something untrue, so
        both are appended here rather than left to the caller to discover from a failure."""
        import copy
        tools = copy.deepcopy(_TOOLS)
        image = self._image
        for t in tools:
            if t.get("name") != "run_code":
                continue
            if self._use_kernel:
                t["description"] += (
                    " NOTE: this server runs a persistent WARM interpreter, so Python in-memory state"
                    " (variables, imports) PERSISTS across run_code calls within this session."
                )
            lang = t["inputSchema"]["properties"]["language"]
            # Only the DEFAULT image's contents are a fact we hold. For any other image, say which one
            # it is and stop: guessing its interpreters from the tag would be inventing a measurement.
            if image == _DEFAULT_MCP_IMAGE:
                lang["description"] += (
                    " This server runs python:3.12-slim, which provides python, bash and sh but NOT"
                    " node: do not offer node here."
                )
            else:
                lang["description"] += (
                    f" This server runs {image!r}; use a language you know that image provides."
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
        # `name` is client-controlled SHAPE too, and it is used as a DICT KEY below. A JSON object or
        # array arrives as an unhashable dict/list, so `_ARG_SPEC.get(name)` raises TypeError right here,
        # OUTSIDE the try that wraps the real work - it escapes handle(), escapes the serve loop (which
        # only catches KeyboardInterrupt/BrokenPipeError) and kills the whole connection. One malformed
        # tools/call was enough to end the session for every later message.
        if not isinstance(name, str):
            self._error(mid, -32602, f"tool name must be a string, got {type(name).__name__}")
            return
        args = params.get("arguments")
        if not isinstance(args, dict):
            args = {}
        # Validate tool name + required args + types up front as -32602. The try below then wraps only
        # real work, so a KeyError/TypeError from deep in the binding can't be misreported as a missing
        # argument (nor leak a box-controlled key into a structured error message).
        spec = _ARG_SPEC.get(name)
        if spec is None:
            # Clip before echoing: `name` is client-controlled and a frame may carry up to _MAX_FRAME,
            # so an unclipped repr turns an 8 MB request into an 8 MB error reply.
            self._error(mid, -32602, f"unknown tool: {_clip(name, _MAX_NAME)!r}")
            return
        for key, typ in spec.items():
            if key not in args:
                self._error(mid, -32602, f"missing required argument: {key!r}")
                return
            if not isinstance(args[key], typ):
                self._error(mid, -32602, f"argument {key!r} must be {typ.__name__}")
                return
            # JSON accepts a LONE SURROGATE ("\ud800"), and Python's decoder hands it back as a str that
            # no UTF-8 encoder will take. Unchecked it travels all the way to os.open() / the box argv
            # and dies there as UnicodeEncodeError, which the catch-all below reports to the model as
            # "internal error" - a malformed argument misfiled as a server bug, with nothing the model
            # can act on. isascii() is the fast path: it allocates nothing and no ASCII string can carry
            # a surrogate, so only genuinely non-ASCII values pay for the encode.
            if typ is str and not args[key].isascii():
                try:
                    args[key].encode("utf-8")
                except UnicodeEncodeError:
                    self._error(mid, -32602, f"argument {key!r} is not encodable UTF-8 (lone surrogate)")
                    return
        try:
            if name == "run_code":
                content, is_err = self._run_code(args)
            elif name == "write_file":
                self._session().write_file(args["path"], args["content"])
                content, is_err = [{"type": "text", "text": f"wrote {_clip(args['path'], 200)}"}], False
            elif name == "read_file":
                data = self._session().read_file(args["path"], max_bytes=_READ_CAP)
                text = _clip(data.decode("utf-8", "replace"), _MAX_FILE_TEXT)
                content, is_err = [{"type": "text", "text": text}], False
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
                # _drop_kernel, not `= None`: the old one may still be ALIVE here (a SandboxError does not
                # prove the interpreter died), and nothing else would ever reap it.
                self._drop_kernel()
                r = self._get_kernel().run_code(code, **kw)
            if r.fault is not None:
                # this cell tore the kernel down (timeout/kill); drop it so the NEXT call respawns warm.
                self._drop_kernel()
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
        # `code_stderr`: the same reason the LangChain renderer uses it. kern and the workload share
        # one stderr, and this string is read by a model, so kern's own `note:`/`warning:` lines are
        # context spent on the runtime's housekeeping and are easy to mistake for the code's errors.
        if r.code_stderr.strip():
            take("[stderr]\n" + _clip(r.code_stderr.rstrip(), _MAX_TEXT))
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
    # Non-fatal kern notes (the uncapped-caps warning, the overlayfs-scratch note) are diagnostics for a
    # human at a terminal; on the MCP channel they would land in the model's run_code output as if the
    # cell had printed them. Default them off (KERN_QUIET) so tools/call returns only the cell's own
    # stdout/stderr. The unforgeable machine signal the SDK reads for oom/killed is untouched, so fault
    # classification still holds. Set KERN_MCP_QUIET=0 to restore the notes.
    if os.environ.get("KERN_MCP_QUIET", "1").strip().lower() not in ("0", "false", "no", ""):
        os.environ["KERN_QUIET"] = "1"
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
            except (ValueError, RecursionError):
                # JSONDecodeError (a ValueError) is the ordinary malformed frame. RecursionError is the
                # hostile one: `[`*100000 is SYNTACTICALLY valid, so the decoder recurses past the
                # interpreter's limit and raises something that is NOT a JSONDecodeError. Caught only as
                # JSONDecodeError, it escaped the loop and killed the connection - one frame, no reply to
                # anything after it.
                continue  # malformed or abusive frame: skip, keep serving
            if not isinstance(msg, dict):
                continue
            try:
                server.handle(msg)
            except (KeyboardInterrupt, BrokenPipeError):
                raise  # the client is gone or the operator interrupted: leave the loop, do not "recover"
            except MemoryError:
                # Deliberately NOT contained. Answering a MemoryError means composing and writing a
                # reply from a state where the allocator has just failed, so the next _send can die
                # PART WAY THROUGH a frame and leave a truncated line on the wire. For a
                # newline-delimited protocol that is the worst outcome available: the client parses
                # half a message instead of seeing the connection close. Dying clean beats replying
                # from a state that cannot hold. A client cannot reach this by flooding (peak RSS is
                # flat at ~55 MB from 64 MB of input through 2 GB), so if it fires the pressure came
                # from the host, another process or a cgroup limit, and this process is not the one
                # that gets to decide it is fine.
                raise
            except Exception:
                # Defence in depth, not a substitute for the guards above. Every handler already contains
                # its own failures, but this is a long-lived stdio service: an unforeseen bug on ONE
                # message must cost that one reply, never the connection and every request after it.
                traceback.print_exc(file=sys.stderr)
    except (KeyboardInterrupt, BrokenPipeError):
        pass  # client closed the pipe or Ctrl-C: shut down cleanly (nobody left to answer)
    finally:
        server.close()


if __name__ == "__main__":
    main()
