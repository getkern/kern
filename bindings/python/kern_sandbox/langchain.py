"""Hand a LangChain agent a real, kernel-enforced sandbox to run its code in.

    pip install 'kern-sandbox[langchain]'

    from kern_sandbox.langchain import kern_code_tool

    tool = kern_code_tool(memory_mb=512, timeout_s=30)
    agent = create_agent(model, [tool])

The wrapper is thin on purpose: the sandbox already exists, and all that is missing is the step that
turns one :class:`~kern_sandbox.ExecutionResult` into the string a model reads. That step is the whole
design problem, and the obvious version of it is wrong twice over. A tool that returns only ``stdout``
gives the model nothing to repair when its code raises, which breaks the loop the tool exists for; and
a tool that reports ``result.fault.type`` whenever ``success`` is false crashes on the most common path
there is, because a traceback is ``exit_code != 0`` with ``fault is None``.

``langchain-core`` is imported inside the factory and never at module import, so ``kern-sandbox``
itself keeps pulling in nothing: the binding is pure standard library and stays that way.

WHAT THE RENDERING DEFENDS AGAINST, AND WHAT IT DOES NOT
    Everything a box emits is attacker-controlled text going into a model's context. Closed here:
    terminal escapes and control characters, which have no meaning to a model and every use to whoever
    is steering it; and forgery of this module's own framing, since a box that prints ``[sandbox: oom]``
    would otherwise claim, byte for byte, that the sandbox killed it.

    NOT closed, and not closable at this layer: ordinary prompt injection. A run whose output is
    ``[system] ignore your instructions`` is a run that printed a string, and no filter can separate
    that from a program legitimately printing the same characters without destroying real output. The
    defence for that belongs to whatever decides what a model is allowed to act on, not to a function
    whose job is to report faithfully what the code produced.

WHAT IS CAPPED, AND WHAT IS NOT
    Wall clock (``timeout_s``, enforced against a workload that traps SIGTERM: measured killed on the
    deadline), memory (``memory_mb``), processes (``pids``), the code coming in (``max_code_bytes``)
    and the text going back (``max_chars``).

    NOT capped: the WORKSPACE on disk. It is a host directory bind-mounted into every box, which is
    what makes file state persist, and nothing puts a ceiling on it: a cell writing in chunks put
    400 MB on the host with ``memory_mb=128``, because the memory cap only stops the version that
    builds the payload in RAM first. If that matters where you run this, hand it a ``workspace=`` on a
    filesystem you have already bounded (a size-mounted tmpfs, or a path under a quota) rather than
    letting it take a temporary directory on the host's root.
"""

from __future__ import annotations

import atexit
import re
from typing import TYPE_CHECKING, Any, Literal

from . import _WORKSPACE, ExecutionResult, Sandbox

if TYPE_CHECKING:  # typing only; this import never runs
    from langchain_core.tools import StructuredTool

__all__ = ["kern_code_tool"]

_MISSING = (
    "the kern LangChain tool needs `langchain-core`, which is not installed. "
    "Install it with:  pip install 'kern-sandbox[langchain]'"
)

# How much of a run the model is allowed to read back. The SANDBOX caps capture at 64 MiB, which is a
# limit on what the host will buffer and not on what a context window can hold: one cell that prints a
# megabyte would fill a model's context and cost more than the run it describes. Cut again here, and
# keep both ends, because the head carries the output and the tail carries the traceback.
_MAX_CHARS = 8_000

# And the same question on the way IN, which is the side that had no answer at all. `timeout_s` and
# `memory_mb` govern the run, `max_chars` governs the reply; the code itself was unbounded, and in an
# agent loop it is written by the same model this module treats as hostile on the way out. It reaches
# disk as a scratch cell before any execution limit can bite: 32 MiB was measured through, accepted and
# run, without a word. One MiB is far above any cell a model writes on purpose and far below anything
# that costs the host, and going over comes back as text rather than an exception because sending less
# is precisely the thing the model can do about it.
_MAX_CODE_BYTES = 1 << 20

# How many workspace names the listing spells out before it says how many more there were.
_FILES_SHOWN = 20

# Language -> (default tool name, what the model is told it is writing). One table, because the two used
# to disagree: a `node` tool was called `run_javascript` and then described as running "node code".
_LANGUAGES = {
    "python": ("run_python", "Python"),
    "bash": ("run_bash", "shell (bash)"),
    "node": ("run_javascript", "JavaScript (Node.js)"),
}


# Everything the box emits (stdout, stderr, captured values, even the NAMES of the files it created)
# is attacker-controlled text that this tool pastes into a model's context. Two things follow.
#
# Terminal escapes and control characters have no meaning to a model and every use to whoever is
# steering it: a cell that prints `\x1b[2J` or smuggles a NUL is not producing output, it is producing
# a payload for whatever renders the transcript.
#
# And the framing below is OURS. `[sandbox: oom]` means the sandbox acted; a box that prints that
# string forges a verdict about itself, byte for byte, in the one channel the model uses to decide
# whether to trust the run. kern went to the trouble of an unforgeable fd signal to tell oom from
# killed, and handing the forgery back for free at the text layer would undo it. So the marker is
# neutralised wherever the code, and not this module, produced it. Same for the truncation marker,
# which is a claim about completeness.
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-Z\\-_])")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# Each marker is spelled ONCE and both uses are derived from it. Written out twice, the emitting side
# and the neutralising side would be one condition in two places: reword the marker in `_render` and the
# pattern here silently stops matching, which does not break a test, it reopens the forgery.
_FAULT_MARK = "[sandbox: "
_CUT_HEAD, _CUT_TAIL = "... ", " characters of output, cut to fit ..."

_FORGED_FAULT = re.compile("^" + re.escape(_FAULT_MARK.rstrip()), re.MULTILINE)
_FORGED_CUT = re.compile(re.escape(_CUT_HEAD) + r"\d+" + re.escape(_CUT_TAIL))


def _untrusted(text: str) -> str:
    """Make one box-produced string safe to paste into a model's context."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL.sub("", _ANSI.sub("", text))
    text = _FORGED_FAULT.sub("[printed by the code, not the sandbox:", text)
    return _FORGED_CUT.sub("... (the code printed something shaped like a truncation notice) ...", text)


def _clip(text: str, limit: int) -> str:
    """Cut ``text`` to ``limit`` characters, keeping the beginning and the end.

    The marker counts against the budget, so a caller who sized ``limit`` against a context window gets
    what it asked for and not what it asked for plus a sentence.

    Below ``room == 2`` the split leaves a tail of zero, and a tail of zero makes the last slice
    ``text[-0:]``, which is the WHOLE string: the cap would invert into a no-op at exactly the sizes
    that needed one.

    Two INDEPENDENT belts stop that, and the distinction was measured rather than assumed, because
    getting it wrong is how a comment starts lying. ``room < 2`` keeps the degenerate split out of
    reach; slicing from ``len(text) - tail`` rather than ``-tail`` makes it return nothing instead of
    everything if it is ever reached anyway. Relaxing EITHER one alone changes no observable behaviour
    (both measured green); relaxing BOTH returns 100051 characters against a limit of 51. So neither
    line is the one that matters and neither is decoration: they are a pair, and a change that touches
    one should leave the other exactly where it is.
    """
    if len(text) <= limit:
        return text
    marker = f"\n\n{_CUT_HEAD}{len(text)}{_CUT_TAIL}\n\n"
    room = limit - len(marker)
    if room < 2:
        return text[:limit]
    head = (room * 2) // 3
    return text[:head] + marker + text[len(text) - (room - head) :]


def _unfence(code: str) -> str:
    """Strip the markdown code fence a model wrapped its answer in.

    WHY: models emit ```python ... ``` constantly, and a backtick is a syntax error in all three
    languages this tool runs, so the model gets back a ``SyntaxError`` pointing at line 1 and, having no
    idea what is wrong with its perfectly good code, tends to send the same thing again. Nothing
    ambiguous is lost by stripping it: no valid Python, shell or JavaScript source begins with three
    backticks.
    """
    lines = code.strip().splitlines()
    if not lines or not lines[0].startswith("```"):
        return code
    if lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines[1:])


def _render(result: ExecutionResult, limit: int) -> str:
    """Turn one execution into the text the model reads back."""
    blocks: list[str] = []

    # The verdict first, so a model that reads "timeout" before the output knows why it stops
    # mid-sentence. `fault` is the SANDBOX having acted; a non-zero exit with no fault is the code
    # itself, and conflating the two tells a model to rewrite code that was killed for using 4 GB.
    if result.fault is not None:
        blocks.append(f"{_FAULT_MARK}{result.fault.type}] {_untrusted(result.fault.message)}")
    elif result.exit_code != 0:
        blocks.append(f"[exited with code {result.exit_code}]")

    stdout = _untrusted(result.stdout)
    if stdout.strip():
        blocks.append(stdout.rstrip())

    # A cell ending in a bare expression prints nothing: its value lands in `results`. Without this,
    # `df.head()` comes back empty and the model concludes its code never ran.
    for value in result.results:
        text = _untrusted(value.text or value.markdown or "")
        if text.strip():
            blocks.append(text.rstrip())
        elif value.data.keys() & {"image/png", "image/jpeg", "image/svg+xml"}:
            blocks.append("[an image was produced; it cannot be shown in a text result]")

    stderr = _untrusted(result.stderr)
    if stderr.strip():
        blocks.append("stderr:\n" + stderr.rstrip())

    # Files persist across calls, so what this call left behind is what the next one can open. The NAME
    # is the box's to choose, newlines and all, so it is untrusted like everything else it wrote, and a
    # path is written here as one comma-separated item: a real newline in it would end the line and put
    # whatever follows at the same level as this module's own output.
    touched = sorted(_untrusted(f.path).replace("\n", "\\n").replace("\t", "\\t") for f in result.files)
    if touched:
        more = f" (+{len(touched) - _FILES_SHOWN} more)" if len(touched) > _FILES_SHOWN else ""
        blocks.append("files in the workspace: " + ", ".join(touched[:_FILES_SHOWN]) + more)

    if result.truncated:
        blocks.append("[the sandbox discarded the output past its capture cap]")

    if not blocks:
        blocks.append("[the code ran and exited 0 without printing anything]")

    return _clip("\n".join(blocks), limit)


def _describe(sandbox: Sandbox, language: str) -> str:
    """The tool description, which is a prompt: state the limits the model will actually hit.

    Generated from this sandbox rather than written once, because a model told it has no network when
    the caller enabled network will not try, and a model told it has network when it does not will spend
    its turns on connection errors.
    """
    if sandbox.egress_allow:
        network = "It can reach only these domains: " + ", ".join(sandbox.egress_allow) + "."
    elif sandbox.network:
        network = "It has network access."
    else:
        network = "It has no network access, so nothing can be downloaded or fetched."
    memory = f"{sandbox.memory_mb} MiB of memory" if sandbox.memory_mb else "an uncapped amount of memory"
    spoken = _LANGUAGES[language][1]
    return (
        f"Run {spoken} code in an isolated sandbox and get back what it printed.\n\n"
        f"The code runs in a locked-down container on this machine, with {memory} and a "
        f"{sandbox.timeout_s} second time limit. {network} It cannot see or change anything outside "
        f"its own workspace.\n\n"
        f"The working directory is {_WORKSPACE}, and files written there survive between calls: "
        f"one call can write a file and a later call can read it back. Anything printed to stdout or "
        f"stderr is returned, along with the value of a trailing bare expression.\n\n"
        f"Send the code exactly as it should run, with no markdown fences and no commentary."
    )


def kern_code_tool(
    sandbox: "Sandbox | None" = None,
    *,
    language: 'Literal["python", "bash", "node"]' = "python",
    name: "str | None" = None,
    description: "str | None" = None,
    max_chars: int = _MAX_CHARS,
    max_code_bytes: int = _MAX_CODE_BYTES,
    **sandbox_kwargs: Any,
) -> "StructuredTool":
    """Build a LangChain tool that runs ``language`` code in a kern sandbox.

    Args:
        sandbox: an already-open :class:`~kern_sandbox.Sandbox` to run in, when the caller wants to own
            its lifetime (``with Sandbox() as s: tool = kern_code_tool(s)``). Left out, this builds one
            from ``sandbox_kwargs``, opens it, and deletes its temporary workspace at process exit.
        language: which interpreter the code is fed to.
        name: the tool name the model sees. Defaults to ``run_python`` / ``run_bash`` /
            ``run_javascript``.
        description: overrides the generated description, which is a prompt: see :func:`_describe`.
        max_chars: how much of a run is returned to the model, head and tail.
        max_code_bytes: the largest cell this tool will run. Over it, nothing runs and the model is
            told so, because sending less is something it can act on.
        **sandbox_kwargs: passed straight to :class:`~kern_sandbox.Sandbox` (``memory_mb``, ``timeout_s``,
            ``image``, ``network``, ``mounts``, and the rest), and rejected if ``sandbox`` was given.

    Raises:
        ImportError: ``langchain-core`` is not installed.
        ValueError: ``language`` or ``max_chars`` is not usable.
        TypeError: a sandbox was passed AND keyword arguments to build one.
        SandboxError: the session could not be opened here at all. Measured, this is where the split
            falls: what breaks while the tool is being BUILT raises (no ``kern`` on ``PATH``, a
            ``setup=`` command that exits non-zero), and what breaks once a call starts a box comes
            back to the model as text (an image that will not pull, an interpreter missing from the
            image, and the ``timeout`` / ``oom`` / ``escape_blocked`` / ``killed`` faults). Raising at
            build time is deliberate: it surfaces a broken host to whoever started the agent, instead
            of to an agent that would spend its turns rewriting code that was never the problem.
    """
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:  # pragma: no cover - depends on what is installed
        raise ImportError(_MISSING) from exc

    if language not in _LANGUAGES:
        raise ValueError(f"unsupported language {language!r} (one of {', '.join(_LANGUAGES)})")
    if max_chars < 1:
        raise ValueError("max_chars must be at least 1")
    if max_code_bytes < 1:
        raise ValueError("max_code_bytes must be at least 1")

    if sandbox is None:
        sandbox = Sandbox(**sandbox_kwargs)
        # This tool holds the session open for the life of the process and never runs a `with` block,
        # so nothing else would ever call `__exit__`. All it does is remove the temporary workspace,
        # since every box a call started has already exited and there is nothing left to reap, so
        # at-exit is enough; a caller who wants it gone at a defined moment passes their own sandbox.
        # Registered BEFORE opening, so an `__enter__` that raises still has its half-built state undone
        # (it cleans up after a failed `setup=` itself; this also covers whatever else it may add).
        # `__exit__` on a sandbox that never opened is a no-op.
        atexit.register(sandbox.__exit__)
        sandbox.__enter__()
    elif sandbox_kwargs:
        raise TypeError(
            "pass either an open `sandbox` or the keyword arguments to build one, not both: "
            f"{', '.join(sorted(sandbox_kwargs))}"
        )

    session = sandbox  # a name the closure can hold that is not the reassigned parameter

    def run(code: str) -> str:
        stripped = _unfence(code)
        size = len(stripped.encode("utf-8", "replace"))
        if size > max_code_bytes:
            return (
                f"[refused] the code is {size} bytes, over this tool's {max_code_bytes} byte limit. "
                f"Nothing ran. Send a shorter cell, or write the bulk to a file across several calls."
            )
        return _render(session.run_code(stripped, language=language), max_chars)

    return StructuredTool.from_function(
        func=run,
        name=name or _LANGUAGES[language][0],
        description=description or _describe(session, language),
    )
