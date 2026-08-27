"""Tests for kern_sandbox.mcp (the MCP stdio server).

  * UNIT tests (always run): the JSON-RPC contract, the stdin framing, and every REPLY BOUND. These
    drive `_Server.handle` / `main()` against a captured stdout and a fake session, so no kern and no
    MCP client is needed.
  * INTEGRATION tests (skipped unless a runnable `kern` is present): a real box behind the tools, the
    network-off claim the tool description makes to the model, and the stdout purity the transport
    depends on.

The bounds are the point. The box is untrusted: it controls the workspace files, its own stdout, and
the NUMBER and shape of its rich results. Every one of those paths is capped in `mcp.py`, and an
uncapped path is a defect even when nothing crashes, because a 16 MB reply blows a model's context and
stalls the client's stdio transport just as effectively as a crash.

Run: `pytest tests/test_mcp.py`  (integration auto-skips without a real kern; set `KERN_BIN=...`).
"""

import io
import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from kern_sandbox import ExecutionResult, FileInfo, Result, SandboxError, SandboxFault
from kern_sandbox import mcp as M

_FAKE_KERN = shutil.which("true") or "/bin/true"


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------


def _drive(server, msg, monkeypatch):
    """Feed one message to `handle` and return the parsed replies it wrote to stdout.

    Returns a LIST because the contract under test is partly about COUNT: a notification must produce
    zero lines, and no handler may ever write more than one reply to a single request.
    """
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    server.handle(msg)
    out = buf.getvalue()
    monkeypatch.undo()
    lines = [ln for ln in out.split("\n") if ln.strip()]
    return [json.loads(ln) for ln in lines]


def _one(server, msg, monkeypatch):
    """Drive one REQUEST and assert exactly one reply came back."""
    replies = _drive(server, msg, monkeypatch)
    assert len(replies) == 1, f"expected exactly one reply, got {len(replies)}: {replies!r}"
    return replies[0]


def _req(method, mid=1, **params):
    m = {"jsonrpc": "2.0", "id": mid, "method": method}
    if params:
        m["params"] = params.get("params", params)
    return m


def _call(name, mid=1, **arguments):
    return {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}}


def _res(stdout="", stderr="", exit_code=0, results=None, fault=None):
    return ExecutionResult(stdout=stdout, stderr=stderr, exit_code=exit_code, duration_ms=1,
                           fault=fault, results=list(results or []))


class _FakeSession:
    """Stands in for a Sandbox. Every method returns exactly what the real one's type says it returns,
    so a bound that holds here holds against the real binding too."""

    def __init__(self, *, read=b"", files=None, result=None, raises=None):
        self._read = read
        self._files = list(files or [])
        self._result = result if result is not None else _res()
        self._raises = raises
        self.written = []
        self.run_calls = []

    def write_file(self, path, content):
        if self._raises:
            raise self._raises
        self.written.append((path, content))

    def read_file(self, path, *, max_bytes=None):
        if self._raises:
            raise self._raises
        if max_bytes is not None and len(self._read) > max_bytes:
            raise SandboxError(f"{path!r} exceeds max_bytes={max_bytes}")
        return self._read

    def list_files(self):
        if self._raises:
            raise self._raises
        return self._files

    def run_code(self, code, **kw):
        if self._raises:
            raise self._raises
        self.run_calls.append((code, kw))
        return self._result


def _server(session=None, **env):
    """A server whose session is already open (or stubbed), with env applied at construction time."""
    prev = {k: os.environ.get(k) for k in env}
    os.environ.update({k: v for k, v in env.items()})
    try:
        s = M._Server()
    finally:
        for k, v in prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    if session is not None:
        s._sbx = session
        s._session = lambda: session  # type: ignore[method-assign]
    return s


def _text_of(reply):
    """Concatenate the text blocks of a tools/call result."""
    return "\n".join(c["text"] for c in reply["result"]["content"] if c["type"] == "text")


# ---------------------------------------------------------------------------
# UNIT - JSON-RPC contract
# ---------------------------------------------------------------------------


def test_initialize_answers_with_our_protocol_not_the_clients(monkeypatch):
    s = _server()
    r = _one(s, _req("initialize", params={"protocolVersion": "1999-01-01"}), monkeypatch)
    assert r["result"]["protocolVersion"] == M._PROTOCOL
    assert r["result"]["protocolVersion"] != "1999-01-01"
    assert r["result"]["serverInfo"]["name"] == "kern-sandbox"


def test_initialize_declares_only_the_capability_we_implement(monkeypatch):
    s = _server()
    caps = _one(s, _req("initialize"), monkeypatch)["result"]["capabilities"]
    assert caps == {"tools": {"listChanged": False}}


def test_ping_request_gets_an_empty_result(monkeypatch):
    s = _server()
    assert _one(s, _req("ping"), monkeypatch)["result"] == {}


def test_unknown_method_request_is_method_not_found(monkeypatch):
    s = _server()
    r = _one(s, _req("does/not/exist"), monkeypatch)
    assert r["error"]["code"] == -32601


def test_resources_and_prompts_list_are_empty_but_present(monkeypatch):
    """A client that probes these must get a well-formed empty list, not method-not-found: several
    clients treat an error here as "this server is broken" and drop the connection."""
    s = _server()
    assert _one(s, _req("resources/list"), monkeypatch)["result"] == {"resources": []}
    assert _one(s, _req("prompts/list"), monkeypatch)["result"] == {"prompts": []}


@pytest.mark.parametrize("method", [
    "initialize", "ping", "tools/list", "resources/list", "prompts/list", "tools/call",
    "does/not/exist",
])
def test_no_reply_to_a_notification(method, monkeypatch):
    """JSON-RPC 2.0 section 4.1: the server MUST NOT reply to a Notification. Every method took its own
    branch before this, and only `ping` and the unknown-method fallback actually checked, so a
    `tools/list` with no id used to be answered with `{"id": null, ...}`."""
    s = _server(_FakeSession())
    assert _drive(s, {"jsonrpc": "2.0", "method": method, "params": {}}, monkeypatch) == []


def test_explicit_null_id_is_treated_as_a_notification(monkeypatch):
    """`"id": null` is not a valid request id, so it must take the notification path rather than
    producing a reply addressed to null."""
    s = _server()
    assert _drive(s, {"jsonrpc": "2.0", "id": None, "method": "tools/list"}, monkeypatch) == []


def test_id_zero_and_empty_string_are_real_requests(monkeypatch):
    """0 and "" are falsy but perfectly legal ids: a truthiness check here would silently drop them."""
    s = _server()
    for mid in (0, ""):
        r = _one(s, _req("ping", mid=mid), monkeypatch)
        assert r["id"] == mid


def test_known_notifications_are_silent(monkeypatch):
    s = _server()
    for m in ("notifications/initialized", "initialized", "notifications/cancelled"):
        assert _drive(s, {"jsonrpc": "2.0", "method": m}, monkeypatch) == []


# ---------------------------------------------------------------------------
# UNIT - tools/list
# ---------------------------------------------------------------------------


def test_tools_list_shape(monkeypatch):
    s = _server()
    tools = _one(s, _req("tools/list"), monkeypatch)["result"]["tools"]
    assert {t["name"] for t in tools} == {"run_code", "write_file", "read_file", "list_files"}
    for t in tools:
        assert t["inputSchema"]["type"] == "object"
        assert isinstance(t["description"], str) and t["description"]


def test_every_advertised_tool_has_an_arg_spec():
    """The two tables are written by hand and must not drift: a tool advertised without a spec would be
    rejected as `unknown tool`, and a spec without a tool would be dead validation."""
    assert {t["name"] for t in M._TOOLS} == set(M._ARG_SPEC)


def test_arg_spec_matches_the_advertised_required_list():
    """What the schema tells the model is required must be exactly what the server enforces."""
    for t in M._TOOLS:
        required = set(t["inputSchema"].get("required", []))
        assert required == set(M._ARG_SPEC[t["name"]]), t["name"]


def test_warm_kernel_mode_tells_the_client_state_persists(monkeypatch):
    """In kernel mode python state PERSISTS, which contradicts the default description. A model told
    "each call is a fresh box" would re-import and re-load data every cell."""
    plain = _one(_server(), _req("tools/list"), monkeypatch)["result"]["tools"]
    warm = _one(_server(KERN_MCP_KERNEL="1"), _req("tools/list"), monkeypatch)["result"]["tools"]
    p = next(t for t in plain if t["name"] == "run_code")["description"]
    w = next(t for t in warm if t["name"] == "run_code")["description"]
    assert "PERSISTS" in w and "PERSISTS" not in p


def test_warm_kernel_view_does_not_mutate_the_module_table(monkeypatch):
    """_tools_view deep-copies; if it ever mutated _TOOLS in place the note would accumulate once per
    tools/list call and leak into every later connection in the same process."""
    before = next(t for t in M._TOOLS if t["name"] == "run_code")["description"]
    s = _server(KERN_MCP_KERNEL="1")
    for _ in range(3):
        _one(s, _req("tools/list"), monkeypatch)
    assert next(t for t in M._TOOLS if t["name"] == "run_code")["description"] == before


# ---------------------------------------------------------------------------
# UNIT - argument validation (-32602 before any real work)
# ---------------------------------------------------------------------------


def test_params_must_be_an_object(monkeypatch):
    """A truthy non-dict (`"params": []`) would AttributeError on .get() outside the handler's try and
    kill the whole serve loop, taking every later tool call with it."""
    s = _server()
    for bad in ([], "x", 7, True):
        r = _one(s, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": bad}, monkeypatch)
        assert r["error"]["code"] == -32602


def test_unknown_tool_is_invalid_params(monkeypatch):
    s = _server()
    r = _one(s, _call("no_such_tool"), monkeypatch)
    assert r["error"]["code"] == -32602 and "unknown tool" in r["error"]["message"]


@pytest.mark.parametrize("name", [{"a": 1}, ["x"], {}, []])
def test_unhashable_tool_name_does_not_kill_the_server(name, monkeypatch):
    """THE severe one. `name` is used as a dict key in `_ARG_SPEC.get(name)`, which sits OUTSIDE the try
    that wraps the real work. A JSON object or array arrives unhashable, so the lookup raised TypeError,
    the exception escaped handle() and the serve loop, and the connection died. `params` and `arguments`
    were both shape-guarded; `name` was not."""
    s = _server()
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": name, "arguments": {}}}
    r = _one(s, msg, monkeypatch)
    assert r["error"]["code"] == -32602 and "must be a string" in r["error"]["message"]


@pytest.mark.parametrize("name", [None, 7, 1.5, True])
def test_non_string_tool_name_is_invalid_params(name, monkeypatch):
    """These are hashable, so they reached `_ARG_SPEC.get` and fell through to "unknown tool" with a
    repr of a non-string. Same guard, one message."""
    s = _server()
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": name, "arguments": {}}}
    assert _one(s, msg, monkeypatch)["error"]["code"] == -32602


def test_missing_tool_name_is_invalid_params(monkeypatch):
    s = _server()
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"arguments": {}}}
    assert _one(s, msg, monkeypatch)["error"]["code"] == -32602


def test_server_survives_an_unhashable_name_in_the_serve_loop(monkeypatch):
    """The unit guard above proves the reply; this proves the CONNECTION. Before the fix the `ping`
    that follows was never answered."""
    bad = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": [], "arguments": {}}}
    stdin = json.dumps(bad) + "\n" + json.dumps(_req("ping", mid=2)) + "\n"
    replies = _lines(_run_main(stdin, monkeypatch))
    assert [r["id"] for r in replies] == [1, 2]
    assert replies[0]["error"]["code"] == -32602


def test_huge_tool_name_is_not_echoed_back_whole(monkeypatch):
    """A frame may carry up to _MAX_FRAME. An unclipped repr turned an 8 MB request into an 8 MB error
    reply: the server amplifying a client's own flood back at it."""
    s = _server()
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "Z" * 2_000_000, "arguments": {}}}
    r = _one(s, msg, monkeypatch)
    assert r["error"]["code"] == -32602
    assert len(r["error"]["message"]) <= M._MAX_NAME + 200


def test_huge_method_name_is_not_echoed_back_whole(monkeypatch):
    s = _server()
    r = _one(s, {"jsonrpc": "2.0", "id": 1, "method": "M" * 2_000_000}, monkeypatch)
    assert r["error"]["code"] == -32601
    assert len(r["error"]["message"]) <= M._MAX_NAME + 200


def test_no_reply_carries_a_raw_surrogate_to_the_encoder(monkeypatch):
    """_send's comment says main() reconfigured stdout with errors="replace", so the write "can never
    raise UnicodeEncodeError". That reconfigure is wrapped in `except (AttributeError, ValueError):
    pass`, so the guarantee is conditional on something allowed to fail silently.

    Against a strict encoder the raw surrogate in the method name raised inside _send: the serve loop
    caught it and kept the connection, but the reply was lost and that client waits for it forever.
    Both error paths now go out through !r, which escapes the surrogate before the encoder ever sees
    it, so neither depends on how the stream was configured."""

    class _Strict(io.TextIOBase):
        def __init__(self):
            self.buf = []

        def reconfigure(self, **kw):
            raise AttributeError("this stream cannot be reconfigured")

        def write(self, s):
            s.encode("utf-8")  # no errors="replace": a lone surrogate raises here
            self.buf.append(s)
            return len(s)

        def flush(self):
            pass

    for msg in ({"jsonrpc": "2.0", "id": 1, "method": "\ud800"},
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": "\ud800", "arguments": {}}}):
        out = _Strict()
        monkeypatch.setattr(sys, "stdout", out)
        M._Server().handle(msg)          # must not raise
        monkeypatch.undo()
        assert json.loads("".join(out.buf))["error"]["code"] in (-32601, -32602)


@pytest.mark.parametrize("method", [None, 7, [], {}, True])
def test_non_string_method_is_method_not_found_not_a_crash(method, monkeypatch):
    """`method` is compared with ==, which is safe for any type, but it then went into an f-string for
    the -32601 message. A non-str must produce a clean error, never a traceback."""
    s = _server()
    r = _one(s, {"jsonrpc": "2.0", "id": 1, "method": method}, monkeypatch)
    assert r["error"]["code"] == -32601


def test_huge_write_path_is_clipped_in_the_confirmation(monkeypatch):
    """write_file echoes the path back on success. It is client-controlled and already clipped; this
    pins it so the bound is not dropped in a later edit."""
    sess = _FakeSession()
    s = _server(sess)
    r = _one(s, _call("write_file", path="p" * 500_000, content="x"), monkeypatch)
    assert len(_text_of(r)) <= 400


@pytest.mark.parametrize("name,args", [
    ("run_code", {}),
    ("write_file", {"path": "a"}),
    ("write_file", {"content": "a"}),
    ("read_file", {}),
])
def test_missing_required_argument(name, args, monkeypatch):
    s = _server(_FakeSession())
    r = _one(s, _call(name, **args), monkeypatch)
    assert r["error"]["code"] == -32602 and "missing required argument" in r["error"]["message"]


@pytest.mark.parametrize("name,args", [
    ("run_code", {"code": 123}),
    ("run_code", {"code": None}),
    ("write_file", {"path": "a", "content": []}),
    ("write_file", {"path": 5, "content": "a"}),
    ("read_file", {"path": {"a": 1}}),
])
def test_wrong_argument_type(name, args, monkeypatch):
    s = _server(_FakeSession())
    r = _one(s, _call(name, **args), monkeypatch)
    assert r["error"]["code"] == -32602 and "must be str" in r["error"]["message"]


@pytest.mark.parametrize("name,args", [
    ("read_file", {"path": "\udfff"}),
    ("write_file", {"path": "ok", "content": "a\ud800b"}),
    ("write_file", {"path": "\ud800", "content": "ok"}),
    ("run_code", {"code": "print(1)\ud800"}),
])
def test_lone_surrogate_argument_is_invalid_params(name, args, monkeypatch):
    """JSON accepts "\\ud800" and Python's decoder hands back a str no UTF-8 encoder will take. Unchecked
    it reached os.open() and the box argv and died there as UnicodeEncodeError, which the catch-all
    reported to the model as "internal error": a malformed argument misfiled as a server bug."""
    s = _server(_FakeSession())
    r = _one(s, _call(name, **args), monkeypatch)
    assert r["error"]["code"] == -32602
    assert "surrogate" in r["error"]["message"]


def test_ordinary_non_ascii_arguments_still_pass(monkeypatch):
    """Counter-proof for the surrogate guard: it must reject only what cannot be encoded, never ordinary
    Unicode. Rejecting "café" or an emoji would break every non-English user."""
    sess = _FakeSession()
    s = _server(sess)
    path, body = "data/café.txt", "nothing ☕ to see 中文"
    r = _one(s, _call("write_file", path=path, content=body), monkeypatch)
    assert r["result"]["isError"] is False
    assert sess.written == [(path, body)]


def test_surrogate_in_the_tool_name_is_a_clean_error(monkeypatch):
    """The name goes out through repr(), which escapes a surrogate instead of handing it to the encoder.
    That is why it never crashed, and it is worth pinning so a switch to plain {name} does not
    reintroduce the encode."""
    s = _server()
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "\ud800BAD", "arguments": {}}}
    assert _one(s, msg, monkeypatch)["error"]["code"] == -32602


def test_arguments_not_a_dict_becomes_missing_argument(monkeypatch):
    """`"arguments": "oops"` must not reach the binding as a string; it degrades to {} and then fails
    the required check, which is a clean -32602 rather than a TypeError deep in the SDK."""
    s = _server(_FakeSession())
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "read_file", "arguments": "oops"}}
    r = _one(s, msg, monkeypatch)
    assert r["error"]["code"] == -32602


def test_list_files_needs_no_arguments(monkeypatch):
    s = _server(_FakeSession(files=[]))
    r = _one(s, _call("list_files"), monkeypatch)
    assert r["result"]["isError"] is False


def test_validation_runs_before_any_session_is_opened(monkeypatch):
    """A malformed call must be rejected without paying for (or failing on) a box start: a server with
    no reachable kern still has to answer -32602 rather than "kern error"."""
    s = M._Server()

    def boom():
        raise AssertionError("_session must not be called for a malformed tools/call")

    s._session = boom  # type: ignore[method-assign]
    assert _one(s, _call("read_file"), monkeypatch)["error"]["code"] == -32602
    assert _one(s, _call("nope"), monkeypatch)["error"]["code"] == -32602


# ---------------------------------------------------------------------------
# UNIT - reply bounds (the box is untrusted)
# ---------------------------------------------------------------------------


def test_clip_leaves_short_strings_alone():
    assert M._clip("abc", 10) == "abc"
    assert M._clip("abc", 3) == "abc"


def test_clip_truncates_and_says_by_how_much():
    out = M._clip("x" * 100, 10)
    assert out.startswith("x" * 10)
    assert "truncated 90 chars" in out


def test_read_file_reply_is_bounded_by_the_reply_budget(monkeypatch):
    """THE regression. `_READ_CAP` (16 MiB) bounds what the HOST loads; it must not be what the REPLY
    carries. Clipping the reply at _READ_CAP made the clip a no-op, because the SDK already refuses
    anything above it: a 1 MB workspace file came back as 1 MB of text in one tools/call, 16x the
    aggregate budget every other tool respects."""
    big = b"A" * 1_000_000
    s = _server(_FakeSession(read=big))
    r = _one(s, _call("read_file", path="big.txt"), monkeypatch)
    text = _text_of(r)
    assert len(text) < len(big) / 10
    assert len(text) <= M._MAX_FILE_TEXT + 200
    assert "truncated" in text


def test_read_file_under_the_budget_is_returned_verbatim(monkeypatch):
    """Counter-proof for the bound above: the cap must not touch an ordinary file, otherwise the fix
    would be indistinguishable from breaking read_file."""
    s = _server(_FakeSession(read=b"hello world"))
    assert _text_of(_one(s, _call("read_file", path="a.txt"), monkeypatch)) == "hello world"


def test_read_file_over_the_host_cap_is_a_clean_error(monkeypatch):
    """Above _READ_CAP the SDK raises rather than loading it; that must surface as an isError result,
    not an internal error."""
    s = _server(_FakeSession(raises=SandboxError("'x' exceeds max_bytes=16777216")))
    r = _one(s, _call("read_file", path="x"), monkeypatch)
    assert r["result"]["isError"] is True
    assert "kern error" in _text_of(r)


def test_read_file_decodes_invalid_utf8_instead_of_raising(monkeypatch):
    """The box writes the file, so the bytes are arbitrary. errors="replace" must absorb them."""
    s = _server(_FakeSession(read=b"\xff\xfe ok"))
    r = _one(s, _call("read_file", path="b.bin"), monkeypatch)
    assert r["result"]["isError"] is False and "ok" in _text_of(r)


def test_list_files_is_bounded_by_total_size(monkeypatch):
    files = [FileInfo(path=f"{'d' * 200}/{i}.txt", size=i, change="created") for i in range(5000)]
    s = _server(_FakeSession(files=files))
    text = _text_of(_one(s, _call("list_files"), monkeypatch))
    assert len(text) <= M._MAX_TOTAL_TEXT + 200
    assert "more files omitted" in text


def test_list_files_is_bounded_by_count(monkeypatch):
    """Short names stay under the size cap, so the COUNT cap is the one that has to fire."""
    files = [FileInfo(path=f"{i}", size=1, change="created") for i in range(20_000)]
    s = _server(_FakeSession(files=files))
    text = _text_of(_one(s, _call("list_files"), monkeypatch))
    assert len(text.splitlines()) <= 10_001
    assert "more files omitted" in text


def test_list_files_empty_says_so(monkeypatch):
    s = _server(_FakeSession(files=[]))
    assert _text_of(_one(s, _call("list_files"), monkeypatch)) == "(empty)"


def test_stdout_is_clipped_per_stream(monkeypatch):
    s = _server(_FakeSession(result=_res(stdout="y" * 100_000)))
    text = _text_of(_one(s, _call("run_code", code="x"), monkeypatch))
    assert len(text) <= M._MAX_TOTAL_TEXT + 500
    assert "truncated" in text


def test_aggregate_text_budget_survives_many_rich_results(monkeypatch):
    """One capped stream is not enough: the box controls the NUMBER of results, so 1000 sub-cap rich
    values must still not sum past the aggregate budget."""
    res = [Result(data={"text/html": "h" * 3_000}) for _ in range(1_000)]
    s = _server(_FakeSession(result=_res(stdout="hi", results=res)))
    text = _text_of(_one(s, _call("run_code", code="x"), monkeypatch))
    assert len(text) <= M._MAX_TOTAL_TEXT + 500
    assert "[output truncated: reply-size cap]" in text


def test_exit_tail_is_never_clipped_away(monkeypatch):
    """The exit code is appended AFTER the budget on purpose: it matters most in exactly the high-output
    case that would otherwise clip it away.

    Note the two truncation notes are NOT interchangeable. A stream that overruns `_MAX_TEXT` is
    reported INLINE by _clip ("...[truncated N chars]"); `[output truncated: reply-size cap]` is only
    for the AGGREGATE budget, which one clipped stream does not reach. Both paths tell the model
    something was dropped, which is the invariant that matters."""
    s = _server(_FakeSession(result=_res(stdout="z" * 500_000, exit_code=3)))
    text = _text_of(_one(s, _call("run_code", code="x"), monkeypatch))
    assert text.rstrip().endswith("[exit 3]")
    assert "truncated 484000 chars" in text


def test_fault_is_named_in_the_tail(monkeypatch):
    s = _server(_FakeSession(result=_res(exit_code=137, fault=SandboxFault(type="oom", message="m"))))
    r = _one(s, _call("run_code", code="x"), monkeypatch)
    assert "sandbox fault: oom" in _text_of(r)
    assert r["result"]["isError"] is True


def test_no_output_is_stated_not_empty(monkeypatch):
    s = _server(_FakeSession(result=_res()))
    assert "(no output)" in _text_of(_one(s, _call("run_code", code="x"), monkeypatch))


def test_single_oversize_image_is_dropped(monkeypatch):
    res = [Result(data={"image/png": "A" * (M._MAX_IMAGE_B64 + 1)})]
    s = _server(_FakeSession(result=_res(results=res)))
    r = _one(s, _call("run_code", code="x"), monkeypatch)
    assert not [c for c in r["result"]["content"] if c["type"] == "image"]


def test_aggregate_image_budget_caps_many_small_images(monkeypatch):
    """Each figure is well under the single-image cap; only the aggregate budget stops 500 of them from
    summing to a multi-GB reply."""
    res = [Result(data={"image/png": "A" * 1_000_000}) for _ in range(500)]
    s = _server(_FakeSession(result=_res(results=res)))
    r = _one(s, _call("run_code", code="x"), monkeypatch)
    imgs = [c for c in r["result"]["content"] if c["type"] == "image"]
    assert sum(len(c["data"]) for c in imgs) <= M._MAX_REPLY_IMG
    assert "image result(s) omitted" in _text_of(r)


def test_non_string_image_payload_is_skipped(monkeypatch):
    """res.data is box-controlled JSON. A non-str payload would TypeError on len()/slice, or land a
    list where the client expects base64."""
    res = [Result(data={"image/png": ["not", "a", "string"]})]
    s = _server(_FakeSession(result=_res(results=res)))
    r = _one(s, _call("run_code", code="x"), monkeypatch)
    assert not [c for c in r["result"]["content"] if c["type"] == "image"]
    assert r["result"]["isError"] is False


def test_non_string_rich_payload_is_skipped(monkeypatch):
    res = [Result(data={"text/html": {"nested": "object"}})]
    s = _server(_FakeSession(result=_res(stdout="ok", results=res)))
    assert "[rich result]" not in _text_of(_one(s, _call("run_code", code="x"), monkeypatch))


@pytest.mark.parametrize("mime", ["text/html", "image/svg+xml", "text/markdown", "application/json"])
def test_every_text_shaped_rich_mime_is_surfaced(mime, monkeypatch):
    """SVG and markdown were invisible when only html and json were checked: a cell returning a chart as
    SVG produced a reply with no trace of it."""
    s = _server(_FakeSession(result=_res(results=[Result(data={mime: "PAYLOAD"})])))
    assert "PAYLOAD" in _text_of(_one(s, _call("run_code", code="x"), monkeypatch))


def test_empty_string_image_is_not_emitted(monkeypatch):
    s = _server(_FakeSession(result=_res(results=[Result(data={"image/png": ""})])))
    r = _one(s, _call("run_code", code="x"), monkeypatch)
    assert not [c for c in r["result"]["content"] if c["type"] == "image"]


# ---------------------------------------------------------------------------
# UNIT - run_code argument handling
# ---------------------------------------------------------------------------


def test_unsupported_language_is_refused_before_the_binding(monkeypatch):
    s = _server(_FakeSession())
    r = _one(s, _call("run_code", code="x", language="perl"), monkeypatch)
    assert r["result"]["isError"] is True and "unsupported language" in _text_of(r)


@pytest.mark.parametrize("lang", ["python", "bash", "node"])
def test_supported_languages_reach_the_session(lang, monkeypatch):
    sess = _FakeSession()
    s = _server(sess)
    _one(s, _call("run_code", code="x", language=lang), monkeypatch)
    assert sess.run_calls[0][1]["language"] == lang


def test_positive_timeout_is_forwarded(monkeypatch):
    sess = _FakeSession()
    s = _server(sess)
    _one(s, _call("run_code", code="x", timeout_s=2.5), monkeypatch)
    assert sess.run_calls[0][1]["timeout_s"] == 2.5


@pytest.mark.parametrize("bad", [True, False, 0, -1, "5", None, [], {}])
def test_bad_timeout_falls_back_to_the_server_default(bad, monkeypatch):
    """bool is an int subclass: `timeout_s=true` would pass isinstance(int) and reach the binding as a
    one-second deadline, silently killing every cell."""
    sess = _FakeSession()
    s = _server(sess)
    _one(s, _call("run_code", code="x", timeout_s=bad), monkeypatch)
    assert "timeout_s" not in sess.run_calls[0][1]


def test_empty_code_is_accepted(monkeypatch):
    """"" is a valid str, so it must run (and produce "(no output)"), not fail validation."""
    s = _server(_FakeSession())
    r = _one(s, _call("run_code", code=""), monkeypatch)
    assert r["result"]["isError"] is False


# ---------------------------------------------------------------------------
# UNIT - error containment
# ---------------------------------------------------------------------------


def test_sandbox_error_is_a_bounded_tool_error(monkeypatch):
    s = _server(_FakeSession(raises=SandboxError("q" * 50_000)))
    r = _one(s, _call("run_code", code="x"), monkeypatch)
    assert r["result"]["isError"] is True
    assert len(_text_of(r)) <= 2_300


def test_unexpected_exception_leaks_only_the_type(monkeypatch, capsys):
    """An internal failure must not put a host path or a box-controlled string in the model's context.
    The details go to OUR stderr, where a human can read them."""
    s = _server(_FakeSession(raises=RuntimeError("/home/secret/path/token=abcdef")))
    r = _one(s, _call("run_code", code="x"), monkeypatch)
    text = _text_of(r)
    assert text == "internal error: RuntimeError"
    assert "secret" not in text
    assert "RuntimeError" in capsys.readouterr().err


def test_server_keeps_serving_after_a_tool_raises(monkeypatch):
    s = _server(_FakeSession(raises=RuntimeError("boom")))
    _one(s, _call("run_code", code="x"), monkeypatch)
    assert _one(s, _req("ping", mid=2), monkeypatch)["result"] == {}


# ---------------------------------------------------------------------------
# UNIT - warm kernel lifecycle
# ---------------------------------------------------------------------------


class _FakeKernel:
    def __init__(self, *, raises=None, result=None):
        self.exited = False
        self._raises = raises
        self._result = result if result is not None else _res()

    def run_code(self, code, **kw):
        if self._raises:
            raise self._raises
        return self._result

    def __exit__(self, *exc):
        self.exited = True


def test_drop_kernel_tears_the_process_down():
    """`Kernel` has no __del__ and registers no weakref.finalize: its only teardown is __exit__, which
    kills the process group. Clearing the attribute alone stranded the interpreter child for the whole
    life of the MCP server."""
    s = M._Server()
    k = _FakeKernel()
    s._kernel = k
    s._drop_kernel()
    assert k.exited is True
    assert s._kernel is None


def test_drop_kernel_is_idempotent():
    s = M._Server()
    s._drop_kernel()
    s._drop_kernel()
    assert s._kernel is None


def test_drop_kernel_survives_an_exit_that_raises():
    class _Angry(_FakeKernel):
        def __exit__(self, *exc):
            raise OSError("already gone")

    s = M._Server()
    s._kernel = _Angry()
    s._drop_kernel()
    assert s._kernel is None


def test_kernel_retry_reaps_the_old_kernel(monkeypatch):
    """The retry path fires on any SandboxError, which does NOT prove the interpreter died. The old
    kernel has to be reaped before the new one is spawned, or a session that keeps erroring strands one
    process per error."""
    dead = _FakeKernel(raises=SandboxError("kernel gone"))
    fresh = _FakeKernel(result=_res(stdout="second"))
    order = [dead, fresh]
    s = _server(_FakeSession(), KERN_MCP_KERNEL="1")
    s._kernel = dead

    def get_kernel():
        if s._kernel is None:
            s._kernel = order.pop(0) if order else fresh
        return s._kernel

    s._get_kernel = get_kernel  # type: ignore[method-assign]
    order.pop(0)  # `dead` is already installed
    r = _one(s, _call("run_code", code="x"), monkeypatch)
    assert dead.exited is True, "the old kernel was dropped without being torn down"
    assert "second" in _text_of(r)


def test_faulted_kernel_is_reaped(monkeypatch):
    """A cell that times out tears the kernel down on the box side; the host object still has to be
    exited so the local process and its pipes go with it."""
    k = _FakeKernel(result=_res(exit_code=137, fault=SandboxFault(type="timeout", message="m")))
    s = _server(_FakeSession(), KERN_MCP_KERNEL="1")
    s._kernel = k
    s._get_kernel = lambda: k  # type: ignore[method-assign]
    _one(s, _call("run_code", code="x"), monkeypatch)
    assert k.exited is True
    assert s._kernel is None


def test_close_clears_the_session_even_when_its_exit_raises():
    """A teardown that fails halfway is the same defect with one more step: if the reference survives
    the failure, the next call reuses a session whose box is in an unknown state."""

    class _Angry:
        def __exit__(self, *exc):
            raise OSError("teardown failed")

    s = M._Server()
    s._sbx = _Angry()
    s.close()
    assert s._sbx is None


def test_close_reaps_both_kernel_and_session():
    class _Sess:
        def __init__(self):
            self.exited = False

        def __exit__(self, *exc):
            self.exited = True

    s = M._Server()
    k, sess = _FakeKernel(), _Sess()
    s._kernel, s._sbx = k, sess
    s.close()
    assert k.exited and sess.exited
    assert s._kernel is None and s._sbx is None


def test_bash_ignores_the_warm_kernel(monkeypatch):
    """Kernel.run_code has no `language` kwarg: routing bash through it would TypeError. Only python
    takes the warm path."""
    sess = _FakeSession()
    s = _server(sess, KERN_MCP_KERNEL="1")
    s._get_kernel = lambda: pytest.fail("bash must not reach the kernel")  # type: ignore[method-assign]
    _one(s, _call("run_code", code="x", language="bash"), monkeypatch)
    assert sess.run_calls[0][1]["language"] == "bash"


# ---------------------------------------------------------------------------
# UNIT - env knobs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [
    ("2048", 2048), ("0", 1024), ("-5", 1024), ("junk", 1024), ("", 1024), ("1.5", 1024),
])
def test_env_int_rejects_values_that_would_poison_every_later_call(raw, expected, monkeypatch):
    """A negative or garbage operator value must not reach the Sandbox constructor, where it would make
    every call in the session fail identically with a confusing error."""
    monkeypatch.setenv("KERN_MCP_MEMORY_MB", raw)
    assert M._env_int("KERN_MCP_MEMORY_MB", 1024) == expected


def test_env_int_uses_the_default_when_unset(monkeypatch):
    monkeypatch.delenv("KERN_MCP_MEMORY_MB", raising=False)
    assert M._env_int("KERN_MCP_MEMORY_MB", 77) == 77


@pytest.mark.parametrize("raw,on", [
    ("1", True), ("true", True), ("YES", True), ("0", False), ("", False), ("no", False),
])
def test_kernel_flag_parsing(raw, on, monkeypatch):
    monkeypatch.setenv("KERN_MCP_KERNEL", raw)
    assert M._Server()._use_kernel is on


# ---------------------------------------------------------------------------
# UNIT - the stdin framing loop
# ---------------------------------------------------------------------------


def _run_main(stdin_text, monkeypatch, env=None):
    """Drive main() over a canned stdin and return the raw stdout it produced."""
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("KERN_BIN", _FAKE_KERN)
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_text))
    monkeypatch.setattr(sys, "stdout", out)
    M.main()
    return out.getvalue()


def _lines(raw):
    return [json.loads(ln) for ln in raw.split("\n") if ln.strip()]


def test_main_answers_a_well_formed_request(monkeypatch):
    raw = _run_main(json.dumps(_req("ping")) + "\n", monkeypatch)
    assert _lines(raw)[0]["result"] == {}


def test_main_skips_malformed_json_and_keeps_serving(monkeypatch):
    """A single bad frame must not end the session: the next message still has to be answered."""
    stdin = "{not json at all\n" + json.dumps(_req("ping", mid=9)) + "\n"
    replies = _lines(_run_main(stdin, monkeypatch))
    assert len(replies) == 1 and replies[0]["id"] == 9


def test_main_skips_blank_lines(monkeypatch):
    stdin = "\n   \n\n" + json.dumps(_req("ping", mid=4)) + "\n"
    assert _lines(_run_main(stdin, monkeypatch))[0]["id"] == 4


@pytest.mark.parametrize("payload", ["[1,2,3]", '"a string"', "42", "null", "true"])
def test_main_ignores_valid_json_that_is_not_an_object(payload, monkeypatch):
    """json.loads succeeds on all of these; .get() would AttributeError on every one."""
    stdin = payload + "\n" + json.dumps(_req("ping", mid=5)) + "\n"
    replies = _lines(_run_main(stdin, monkeypatch))
    assert len(replies) == 1 and replies[0]["id"] == 5


def test_main_resyncs_after_an_oversize_frame(monkeypatch):
    """A client flooding megabytes with no newline must be read in bounded chunks AND must not leave the
    parser mid-frame: the next real message has to be answered."""
    flood = "x" * (M._MAX_FRAME + 5_000) + "\n"
    stdin = flood + json.dumps(_req("ping", mid=7)) + "\n"
    replies = _lines(_run_main(stdin, monkeypatch))
    assert len(replies) == 1 and replies[0]["id"] == 7


def test_main_stops_at_eof(monkeypatch):
    assert _run_main("", monkeypatch) == ""


def test_main_answers_a_last_frame_with_no_trailing_newline(monkeypatch):
    """A client that closes the pipe straight after writing, without the final newline, has still sent
    a complete message. Dropping it would lose the last request of every such session."""
    raw = _run_main(json.dumps(_req("ping", mid=8)), monkeypatch)
    assert _lines(raw)[0]["id"] == 8


def test_main_skips_two_json_objects_concatenated_without_a_newline(monkeypatch):
    """The transport is newline-delimited: two objects on one line are one malformed frame, not two
    messages. Skipping is correct; parsing the first and silently discarding the second would be worse
    than either."""
    glued = json.dumps(_req("ping", mid=1)) + json.dumps(_req("ping", mid=2)) + "\n"
    stdin = glued + json.dumps(_req("ping", mid=3)) + "\n"
    replies = _lines(_run_main(stdin, monkeypatch))
    assert [r["id"] for r in replies] == [3]


def test_main_survives_deeply_nested_json(monkeypatch):
    """`[`*100000 is SYNTACTICALLY valid, so json.loads recurses past the interpreter limit and raises
    RecursionError, which is NOT a JSONDecodeError. Caught only as JSONDecodeError it escaped the serve
    loop and killed the connection: one 200 KB frame and every later request went unanswered."""
    deep = "[" * 100_000 + "]" * 100_000
    stdin = deep + "\n" + json.dumps(_req("ping", mid=11)) + "\n"
    replies = _lines(_run_main(stdin, monkeypatch))
    assert len(replies) == 1 and replies[0]["id"] == 11


def test_main_survives_a_handler_that_raises(monkeypatch):
    """Defence in depth for the serve loop itself: an unforeseen bug on one message must cost that one
    reply, not the connection. Without the guard the `ping` below is never answered."""
    real = M._Server.handle
    calls = {"n": 0}

    def flaky(self, msg):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ZeroDivisionError("unforeseen")
        return real(self, msg)

    monkeypatch.setattr(M._Server, "handle", flaky)
    stdin = json.dumps(_req("ping", mid=1)) + "\n" + json.dumps(_req("ping", mid=2)) + "\n"
    replies = _lines(_run_main(stdin, monkeypatch))
    assert [r["id"] for r in replies] == [2]


def test_main_answers_pipelined_requests_in_order(monkeypatch):
    """A client is entitled to send several requests before reading any reply. The replies must all
    arrive, once each, in the order the requests were made."""
    stdin = "".join(json.dumps(_req("ping", mid=i)) + "\n" for i in range(1, 21))
    replies = _lines(_run_main(stdin, monkeypatch))
    assert [r["id"] for r in replies] == list(range(1, 21))


def test_main_answers_duplicate_ids_once_each(monkeypatch):
    """Reusing an id is the client's problem, not ours: we must still answer both, not collapse them."""
    stdin = (json.dumps(_req("ping", mid=1)) + "\n") * 2
    assert [r["id"] for r in _lines(_run_main(stdin, monkeypatch))] == [1, 1]


def test_tools_work_before_initialize(monkeypatch):
    """Some clients issue a tools/list before initialize. We hold no handshake state, so this is served
    rather than refused. Pinned because it is a deliberate leniency, not an accident."""
    stdin = json.dumps(_req("tools/list", mid=1)) + "\n"
    r = _lines(_run_main(stdin, monkeypatch))[0]
    assert len(r["result"]["tools"]) == 4


def test_main_emits_one_json_object_per_line(monkeypatch):
    """The transport is newline-delimited: an embedded newline in any reply would split one message into
    two unparseable halves."""
    stdin = "".join(json.dumps(_req(m, mid=i)) + "\n"
                    for i, m in enumerate(["initialize", "ping", "tools/list"]))
    raw = _run_main(stdin, monkeypatch)
    lines = [ln for ln in raw.split("\n") if ln.strip()]
    assert len(lines) == 3
    for ln in lines:
        assert isinstance(json.loads(ln), dict)


def test_main_keeps_non_ascii_as_utf8(monkeypatch):
    """ensure_ascii=False: a reply "bounded" in code points would be up to 12x larger on the wire as
    \\uXXXX escapes, blowing past the budget the caps are written against."""
    s = _server(_FakeSession(read="ünïcödé ✓".encode()))
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stdout", buf)
    s.handle(_call("read_file", path="u.txt"))
    monkeypatch.undo()
    assert "ünïcödé ✓" in buf.getvalue()
    assert "\\u" not in buf.getvalue()


def test_main_sets_kern_quiet_by_default(monkeypatch):
    """kern's non-fatal notes would land in the model's run_code output as if the cell had printed
    them."""
    monkeypatch.delenv("KERN_QUIET", raising=False)
    monkeypatch.delenv("KERN_MCP_QUIET", raising=False)
    _run_main("", monkeypatch)
    assert os.environ.get("KERN_QUIET") == "1"


@pytest.mark.parametrize("raw", ["0", "false", "no", ""])
def test_kern_mcp_quiet_can_be_turned_off(raw, monkeypatch):
    monkeypatch.delenv("KERN_QUIET", raising=False)
    _run_main("", monkeypatch, env={"KERN_MCP_QUIET": raw})
    assert os.environ.get("KERN_QUIET") is None


# ---------------------------------------------------------------------------
# INTEGRATION - a real box behind the tools
# ---------------------------------------------------------------------------


def _kern_runnable() -> bool:
    k = os.environ.get("KERN_BIN") or shutil.which("kern")
    return bool(k) and k != _FAKE_KERN and os.access(k, os.X_OK)


integration = pytest.mark.skipif(not _kern_runnable(), reason="no runnable kern (set KERN_BIN)")


def _mcp_exchange(messages, env=None, timeout=180):
    """Run the REAL server as a subprocess, exactly as an MCP client would, and collect its replies.

    A subprocess is the point: it is the only way to catch anything that writes to the process's stdout
    behind the server's back, which would corrupt the newline-delimited transport.
    """
    e = dict(os.environ)
    e.setdefault("KERN_MCP_TIMEOUT", "60")
    e.update(env or {})
    stdin = "".join(json.dumps(m) + "\n" for m in messages)
    p = subprocess.run([sys.executable, "-m", "kern_sandbox.mcp"], input=stdin, text=True,
                       capture_output=True, timeout=timeout, env=e,
                       cwd=str(Path(__file__).resolve().parents[1]))
    return p


def _parse(p):
    out = []
    for ln in p.stdout.split("\n"):
        if not ln.strip():
            continue
        out.append(json.loads(ln))  # a non-JSON line here IS the failure: the transport is corrupt
    return out


@integration
def test_real_run_code_executes_in_a_box():
    p = _mcp_exchange([_req("initialize"), _call("run_code", mid=2, code="print(6 * 7)")])
    replies = {r["id"]: r for r in _parse(p)}
    text = "\n".join(c["text"] for c in replies[2]["result"]["content"] if c["type"] == "text")
    assert "42" in text and "[exit 0]" in text
    assert replies[2]["result"]["isError"] is False


@integration
def test_real_network_is_off():
    """The run_code description tells the model "The network is OFF". That claim is the one a user
    checks first, so it is asserted against a real box rather than a config flag."""
    code = textwrap.dedent("""
        import socket
        try:
            socket.create_connection(("1.1.1.1", 53), timeout=5)
            print("NETWORK_OPEN")
        except OSError as e:
            print("NETWORK_BLOCKED", type(e).__name__)
    """)
    p = _mcp_exchange([_req("initialize"), _call("run_code", mid=2, code=code)])
    text = "\n".join(c["text"] for c in {r["id"]: r for r in _parse(p)}[2]["result"]["content"]
                     if c["type"] == "text")
    assert "NETWORK_BLOCKED" in text
    assert "NETWORK_OPEN" not in text


@integration
def test_real_stdout_carries_only_json(tmp_path):
    """Anything the SDK or kern prints to stdout would be interleaved with the JSON-RPC stream and
    desync the client permanently. _parse raises on the first non-JSON line."""
    p = _mcp_exchange([
        _req("initialize"),
        _call("run_code", mid=2, code="print('hello')"),
        _call("list_files", mid=3),
    ], env={"KERN_MCP_WORKSPACE": str(tmp_path)})
    replies = _parse(p)
    assert len(replies) == 3
    assert {r["id"] for r in replies} == {1, 2, 3}


@integration
def test_real_file_state_persists_across_calls(tmp_path):
    """The tool description promises FILE state survives between calls. It is the difference between a
    usable interpreter and a stateless one, so it is asserted end to end."""
    p = _mcp_exchange([
        _req("initialize"),
        _call("write_file", mid=2, path="data.txt", content="persisted"),
        _call("run_code", mid=3, code="print(open('data.txt').read())"),
        _call("read_file", mid=4, path="data.txt"),
        _call("list_files", mid=5),
    ], env={"KERN_MCP_WORKSPACE": str(tmp_path)})
    r = {x["id"]: x for x in _parse(p)}
    got = {i: "\n".join(c["text"] for c in r[i]["result"]["content"] if c["type"] == "text")
           for i in (2, 3, 4, 5)}
    assert "wrote data.txt" in got[2]
    assert "persisted" in got[3]
    assert got[4] == "persisted"
    assert "data.txt" in got[5]


@integration
def test_real_in_memory_state_does_not_persist_without_the_warm_kernel(tmp_path):
    """The other half of the same promise: each call is a fresh box, so a variable must NOT survive.
    Without this the description would be half-true and a model would build on state that is gone."""
    p = _mcp_exchange([
        _req("initialize"),
        _call("run_code", mid=2, code="MARKER = 'alive'"),
        _call("run_code", mid=3, code="print('MARKER' in dir())"),
    ], env={"KERN_MCP_WORKSPACE": str(tmp_path)})
    r = {x["id"]: x for x in _parse(p)}
    text = "\n".join(c["text"] for c in r[3]["result"]["content"] if c["type"] == "text")
    assert "False" in text


@integration
def test_real_nonzero_exit_is_an_error_result(tmp_path):
    p = _mcp_exchange([
        _req("initialize"),
        _call("run_code", mid=2, code="import sys; sys.exit(3)"),
    ], env={"KERN_MCP_WORKSPACE": str(tmp_path)})
    r = {x["id"]: x for x in _parse(p)}[2]
    assert r["result"]["isError"] is True
    assert "[exit 3" in "\n".join(c["text"] for c in r["result"]["content"] if c["type"] == "text")


@integration
def test_real_bash_and_node_run(tmp_path):
    p = _mcp_exchange([
        _req("initialize"),
        _call("run_code", mid=2, code="echo bash-ok", language="bash"),
    ], env={"KERN_MCP_WORKSPACE": str(tmp_path)})
    r = {x["id"]: x for x in _parse(p)}[2]
    assert "bash-ok" in "\n".join(c["text"] for c in r["result"]["content"] if c["type"] == "text")


@integration
def test_real_write_file_refuses_to_escape_the_workspace(tmp_path):
    """The tool description promises the path is "confined; symlink- and ..-safe". A traversal must come
    back as a clean tool error, never as a host write."""
    p = _mcp_exchange([
        _req("initialize"),
        _call("write_file", mid=2, path="../escaped.txt", content="nope"),
    ], env={"KERN_MCP_WORKSPACE": str(tmp_path)})
    r = {x["id"]: x for x in _parse(p)}[2]
    assert r["result"]["isError"] is True
    assert not (tmp_path.parent / "escaped.txt").exists()


@integration
def test_real_server_exits_cleanly_on_eof():
    p = _mcp_exchange([_req("initialize")])
    assert p.returncode == 0


# ---------------------------------------------------------------------------
# MEMORY - the framing bound, measured rather than asserted
# ---------------------------------------------------------------------------


def _peak_rss_mb_for_flood(tmp_path, megabytes):
    """Run the real server with `megabytes` of newline-free input and return ITS peak RSS.

    Two things here are deliberate and were both learned the hard way.

    The payload is written to a FILE and handed over as a file descriptor, never held in this
    process. subprocess forks, and a child's peak RSS starts at whatever the parent's was, so a test
    that keeps the flood in a Python string measures the PARENT and reports a number that scales
    beautifully with the flood size while proving nothing at all.

    The caller compares two sizes rather than trusting one absolute number, because the inherited
    baseline is still in there and only a DIFFERENCE cancels it out.

    Both sizes must sit on the PLATEAU. Measured, this server ramps from 17 MB at a 1 MB flood to
    55 MB at 64 MB, then stays at 55 MB through 128, 256 and 400: the ramp is the reader reaching its
    steady-state working set, and the plateau is the actual bound. A pair straddling the ramp
    (25 MB against 400 MB) reports an 8 MB difference that is real growth, not slack, and leaves the
    threshold measuring the wrong thing.
    """
    payload = tmp_path / f"flood-{megabytes}"
    with payload.open("wb") as fh:
        block = b"Q" * (1024 * 1024)
        for _ in range(megabytes):
            fh.write(block)
        fh.write(b"\n")
        fh.write(json.dumps(_req("ping", mid=999)).encode() + b"\n")
    reporter = (
        "import atexit,sys,runpy\n"
        "def _hwm():\n"
        "    for ln in open('/proc/self/status'):\n"
        "        if ln.startswith('VmHWM:'): sys.stderr.write(ln)\n"
        "atexit.register(_hwm)\n"
        "runpy.run_module('kern_sandbox.mcp', run_name='__main__')\n"
    )
    with payload.open("rb") as fh:
        p = subprocess.run([sys.executable, "-c", reporter], stdin=fh, capture_output=True,
                           text=True, timeout=300, env=dict(os.environ, KERN_BIN=_FAKE_KERN))
    served = any(json.loads(ln).get("id") == 999
                 for ln in p.stdout.split("\n") if ln.strip())
    hwm = next((int(ln.split()[1]) for ln in p.stderr.splitlines() if ln.startswith("VmHWM:")), None)
    return hwm / 1024 if hwm is not None else None, served


@pytest.mark.skipif(not os.path.exists("/proc/self/status"), reason="no /proc/self/status")
def test_a_newline_free_flood_does_not_grow_the_server(tmp_path):
    """The serve loop claims a client flooding megabytes with no newline is read in bounded chunks
    rather than buffered into host RAM. That is the one claim in this file that cannot be checked by
    reading the code, because TextIOWrapper.readline(size) bounds the string it RETURNS and says
    nothing about what it buffers while scanning for the newline.

    128 MB and 400 MB both sit on the plateau, so a healthy server answers with the same number twice
    and a reader that accumulates fails by hundreds of megabytes, not by a rounding error. Measured
    both ways: 55.1 against 55.4 as it stands, and 150 against 423 with a deliberate leak in the drain
    loop."""
    small, served_small = _peak_rss_mb_for_flood(tmp_path, 128)
    large, served_large = _peak_rss_mb_for_flood(tmp_path, 400)
    assert served_small and served_large, "the ping after the flood must still be answered"
    assert small is not None and large is not None
    assert large - small < 8, f"RSS grew {large - small:.1f} MB when the flood grew 3.1x"
