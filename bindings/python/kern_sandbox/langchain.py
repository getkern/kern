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
import os
import re
import shutil
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


# =====================================================================================================
# The persistent-shell execution policy
# =====================================================================================================
#
# `kern_code_tool` above gives an agent a CELL: one box per call, fresh process, file state carried on
# the workspace. LangChain's shell middleware wants the other shape, a SESSION: one long-lived shell it
# writes commands into and reads answers out of, so `cd` and `export` persist the way a terminal does.
#
# That shape is an extension point rather than a hardcoded list. `BaseExecutionPolicy` declares one
# abstract method and langchain ships three implementations of it: `HostExecutionPolicy` (no isolation),
# `CodexSandboxExecutionPolicy` (the Codex CLI sandbox) and `DockerExecutionPolicy`. A kern policy is a
# fourth, and it is a peer of the Docker one rather than a wrapper around it.
#
# COMPATIBILITY, STATED RATHER THAN ASSUMED
#     `BaseExecutionPolicy` is exported by `langchain.agents.middleware._execution.__all__`, but that
#     module is private, and neither `langchain.agents.middleware` nor `shell_tool` lists the name in
#     its own `__all__` (only the three concrete policies). So this subclasses a symbol that langchain
#     does not promise: it is imported from the PUBLIC `shell_tool` module first, falls back to the
#     private one, and raises with the installed version in the message if both fail, rather than
#     dying on an AttributeError three frames deep. Verified against langchain 1.3.17.
#
#     It also needs `langchain` itself, not just `langchain-core`: the middleware lives in the umbrella
#     package. That is a different dependency from the tool above, and it has its own extra.

_POLICY_MISSING = (
    "the kern execution policy needs `langchain` (not just `langchain-core`), which is where the shell "
    "middleware lives. Install it with:  pip install 'kern-sandbox[langchain-shell]'"
)

# A box name per session. kern accepts letters, digits, dashes and underscores (measured), and the uid
# keeps two agents on one host from colliding.
_BOX_PREFIX = "lc-shell-"

_POLICY_CACHE: dict = {}


def _policy_bases():
    """Import langchain's policy base and its temp-dir prefix, from the least private place that has them."""
    try:
        from langchain.agents.middleware.shell_tool import BaseExecutionPolicy, SHELL_TEMP_PREFIX

        return BaseExecutionPolicy, SHELL_TEMP_PREFIX
    except ImportError:
        pass
    try:
        from langchain.agents.middleware._execution import BaseExecutionPolicy, SHELL_TEMP_PREFIX

        return BaseExecutionPolicy, SHELL_TEMP_PREFIX
    except ImportError as exc:
        try:
            import langchain

            installed = getattr(langchain, "__version__", "unknown")
        except ImportError:
            raise ImportError(_POLICY_MISSING) from exc
        raise ImportError(
            f"{_POLICY_MISSING}\n(langchain {installed} is installed but does not expose "
            f"BaseExecutionPolicy; this policy was built against 1.3.17)"
        ) from exc


def _build_policy_class():
    """Define ``KernExecutionPolicy`` against whatever langchain is installed, once per process."""
    import dataclasses
    import subprocess
    import tempfile
    import uuid
    import weakref
    from collections.abc import Sequence  # noqa: F401  (used in field annotations)

    base, temp_prefix = _policy_bases()

    @dataclasses.dataclass
    class KernExecutionPolicy(base):  # type: ignore[misc, valid-type]
        """Run langchain's persistent shell inside a kern box.

        A peer of ``DockerExecutionPolicy`` rather than a wrapper: same contract, same one method, and
        the differences are the ones kern exists for. The box is rootless with no daemon, starts in
        single-digit milliseconds, drops every capability by default, and is on no network unless asked.

        WHERE THIS DELIBERATELY DIFFERS FROM THE DOCKER POLICY

        ``image`` defaults to ``python:3.12-slim`` and not to an alpine one. The middleware's default
        shell is ``/bin/bash``, and alpine does not ship bash: measured, ``python:3.12-alpine3.19``
        (the Docker policy's own default) cannot start the default shell at all. A default that cannot
        run the default is not a default.

        Environment variables go in through ``--env-file`` on a 0600 file, not through repeated ``-e``
        flags. A shell session is long-lived, and ``-e SECRET=...`` sits in the host's ``ps`` output for
        its whole life, readable by any local user. The file is unlinked when the process object is
        collected.

        ``--cap-drop ALL`` by default. kern already drops fourteen capabilities; the rest are held over
        the box's own user namespace, and this is the code path whose entire purpose is running commands
        an agent wrote. Measured with the default on: ``CapEff: 0000000000000000``, with bash working.

        ``--init`` by default, because a persistent shell is exactly where reparented children pile up
        as zombies over a long session.

        SECURITY, HONESTLY
            The boundary is the Linux kernel, so a kernel privilege-escalation bug is an escape, the
            same condition Docker and Podman share. This is for your own or semi-trusted code, which
            agent-written commands are: you chose to run them. It is not a boundary against deliberately
            hostile multi-tenant code; for that, a microVM. kern is rootless from the start, where
            Docker's rootless mode is opt-in.

            The WORKSPACE is a host directory bind-mounted in, and nothing bounds it on disk. Point
            ``workspace_root`` at a filesystem you have already limited if that matters where you run.

            A SESSION ACCUMULATES. ``command_timeout`` bounds a command, not what a command started:
            `sleep 600 &` returns at once and is measured still running ten commands later, because
            that is what a terminal does and a developer would be right to expect it. What bounds it is
            the session itself, `--pids-limit` while it lives and the PID namespace when it ends, and
            that boundary was measured: killing the session left nothing on the host. So a long
            conversation can build up state that no per-command limit sees. For your own or
            semi-trusted code that is the feature; if the commands are hostile, the unit to bound is
            the session, not the command.
        """

        binary: str = "kern"
        image: str = "python:3.12-slim"
        network_enabled: bool = False
        memory_bytes: "int | None" = 512 * 1024 * 1024
        cpus: "str | None" = None
        pids_limit: "int | None" = 256
        read_only_rootfs: bool = False
        user: "str | None" = None
        drop_all_capabilities: bool = True
        use_init: bool = True
        mount_workspace: 'Literal["auto", "always", "never"]' = "auto"
        extra_box_args: "Sequence[str] | None" = None

        def __post_init__(self) -> None:
            super().__post_init__()
            if self.memory_bytes is not None and self.memory_bytes <= 0:
                raise ValueError("memory_bytes must be positive if provided.")
            if self.pids_limit is not None and self.pids_limit <= 0:
                raise ValueError("pids_limit must be positive if provided.")
            if self.cpus is not None and not self.cpus.strip():
                raise ValueError("cpus must be a non-empty string when provided.")
            if self.user is not None and not self.user.strip():
                raise ValueError("user must be a non-empty string when provided.")
            if not self.image.strip():
                raise ValueError("image must be a non-empty string.")
            if self.mount_workspace not in ("auto", "always", "never"):
                raise ValueError("mount_workspace must be one of: auto, always, never")
            self.extra_box_args = tuple(self.extra_box_args or ())

        # -- the contract ----------------------------------------------------------------------------

        def spawn(self, *, workspace, env, command):
            """Launch the persistent shell in a fresh box and hand back its pipes."""
            binary = self._resolve_binary()
            env_path, env_fd, env_holder = self._env_source(env)
            ws_holder = None
            try:
                argv, ws_holder = self._build_command(binary, workspace, env_path, command)
                process = subprocess.Popen(  # noqa: S603
                    argv,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=str(workspace),
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    env=os.environ.copy(),
                    start_new_session=True,
                    pass_fds=(env_fd,) if env_fd is not None else (),
                )
            except BaseException:
                _rmtree_quietly(env_holder)
                _rmtree_quietly(ws_holder)
                raise
            finally:
                # Ours is dropped as soon as the child has its own copy: the anonymous file then lives
                # exactly as long as kern needs it and not one instant longer.
                if env_fd is not None:
                    _close_quietly(env_fd)
            # `weakref.finalize` already covers BOTH cases on its own: it fires when the process
            # object is collected, and `finalize.atexit` defaults to True, so a session still alive at
            # an orderly exit is cleaned up there. An explicit `atexit.register` beside it was doing
            # the same job twice and growing the interpreter's handler list once per spawn, which a
            # long-lived agent reaches often because the middleware restarts a session on every
            # command timeout. Measured: two handlers before, six after three spawns.
            #
            # Neither mechanism runs on SIGKILL, which is exactly why the environment above is an
            # anonymous file rather than something needing cleanup at all. Only the fallback path and
            # the mount alias leave anything on a filesystem to regret.
            if env_holder is not None:
                weakref.finalize(process, _rmtree_quietly, env_holder)
            if ws_holder is not None:
                weakref.finalize(process, _rmtree_quietly, ws_holder)
            return process

        # -- argv ------------------------------------------------------------------------------------

        def _build_command(self, binary, workspace, env_file, command):
            argv = [binary, "box", _BOX_PREFIX + uuid.uuid4().hex[:12], "--image", self.image, "-q"]
            argv.extend(["--net", "host" if self.network_enabled else "none"])
            if self.memory_bytes is not None:
                argv.extend(["-m", str(self.memory_bytes)])
            if self.cpus is not None:
                argv.extend(["--cpus", self.cpus])
            if self.pids_limit is not None:
                argv.extend(["--pids-limit", str(self.pids_limit)])
            if self.use_init:
                argv.append("--init")
            if self.read_only_rootfs:
                argv.append("--read-only")
            if self.drop_all_capabilities:
                argv.extend(["--cap-drop", "ALL"])
            if self.user is not None:
                argv.extend(["-u", self.user])
            if env_file is not None:
                argv.extend(["--env-file", env_file])
            holder = None
            if self._should_mount_workspace(workspace, temp_prefix):
                mount_path, holder = self._mount_alias(workspace)
                argv.extend(["-v", f"{mount_path}:{mount_path}", "-w", mount_path])
            else:
                argv.extend(["-w", "/"])
            argv.extend(self.extra_box_args or ())
            argv.append("--")
            argv.extend(command)
            return argv, holder

        @staticmethod
        def _mount_alias(workspace):
            """Give ``workspace`` a mountable name, and say nothing when it already has one.

            A colon separates SRC from DST in a mount specification, so a workspace at ``/tmp/a:b``
            cannot be written as ``-v SRC:DST`` at all: kern refuses it outright (measured, fails
            closed), and a runtime that split on the wrong colon would mount something nobody asked
            for. Refusing the caller's own directory is not a fix either, so this makes a colon-free
            ALIAS: a symlink to the workspace, mounted as ``alias:alias``.

            That keeps the property the Docker policy has and the reason it mounts host-path onto
            host-path, which is that one absolute path means the same thing inside the box and outside
            it. Measured through the alias: `pwd` is the alias, and files written there appear in the
            real directory.

            The link lives in a fresh 0700 directory rather than loose in the temp root, so no other
            local user can swap the target between the symlink being made and kern resolving it.

            Returns (path_to_mount, directory_to_remove_afterwards).
            """
            path = str(workspace)
            if ":" not in path:
                return path, None
            holder = tempfile.mkdtemp(prefix="kern-lc-ws-")
            alias = os.path.join(holder, "workspace")
            try:
                os.symlink(path, alias)
            except BaseException:
                _rmtree_quietly(holder)
                raise
            return alias, holder

        def _should_mount_workspace(self, workspace, prefix) -> bool:
            """Mirror the Docker policy: an ephemeral session gets no mount, so the host is not exposed
            for a workspace nobody asked to keep. `always`/`never` override the inference."""
            if self.mount_workspace == "always":
                return True
            if self.mount_workspace == "never":
                return False
            return not workspace.name.startswith(prefix)

        def _resolve_binary(self) -> str:
            """`$KERN_BIN` first, matching the rest of this binding, then `PATH`."""
            override = os.environ.get("KERN_BIN")
            if override:
                if not os.path.isfile(override) or not os.access(override, os.X_OK):
                    raise RuntimeError(
                        f"$KERN_BIN={override!r} is not an executable file."
                    )
                return override
            path = shutil.which(self.binary)
            if path is None:
                raise RuntimeError(
                    f"kern execution policy requires the {self.binary!r} binary on PATH "
                    f"(or $KERN_BIN). Install it: https://github.com/getkern/kern"
                )
            return path

        @staticmethod
        def _env_records(env) -> "str | None":
            """Serialise ``env`` to the K=V text kern reads, or None when there is nothing to pass.

            Refused rather than mangled: a newline in a value would split the record and smuggle a
            second variable, and a NUL or an `=` in a KEY would produce a line kern reads as something
            else. The caller gets told which key, because silently dropping one is worse.
            """
            if not env:
                return None
            lines = []
            for key, value in env.items():
                key, value = str(key), str(value)
                if not key or "=" in key or "\n" in key or "\0" in key:
                    raise ValueError(f"environment variable name is not usable: {key!r}")
                if "\n" in value or "\0" in value:
                    raise ValueError(
                        f"environment variable {key!r} has a newline or NUL in its value, which "
                        f"cannot be written as one K=V record"
                    )
                lines.append(f"{key}={value}")
            return "\n".join(lines) + "\n"

        @staticmethod
        def _env_source(env):
            """Put the environment somewhere kern can read it and an attacker cannot.

            An ANONYMOUS file, not a path. `memfd_create` gives a file with no name on any filesystem;
            kern reads it as `/proc/self/fd/N` because the descriptor is passed to it, and it ceases to
            exist the moment the last descriptor closes.

            WHAT THIS BUYS, AND WHAT IT DOES NOT, MEASURED RATHER THAN CLAIMED
                Bought: nothing on a filesystem to leak, nothing for a signal to leave behind, and
                nothing in any argv (unlike `-e SECRET=...`, which sits in the world-readable process
                table for the session).

                NOT bought: secrecy from another process of the SAME user. kern holds the passed
                descriptor for the life of the session, so `/proc/<kern-pid>/fd/N` is readable by
                anything running as you. Measured with a sampler over the whole lifecycle: the window
                is the session, not the milliseconds of startup, which is what a first and sloppier
                probe of ours reported. The narrowing over a 0600 temp file is real but smaller than
                it looks: same exposure while the session lives, none after it dies.

                Against a compromised agent process running as the same user, this is not a boundary.
                The remedy is on kern's side, closing the descriptor once the env is parsed, and until
                that lands this is a limit and not a defence.

            That is the fix for the worst failure this module had. A named 0600 temp file is cleaned up
            by a finalizer, and a finalizer does not run when the process is SIGKILLed, which is exactly
            what happens to an agent in production: a supervisor OOM, a stopped container, a `kill -9`.
            Measured before this: SIGKILL left `/tmp/kern-lc-env-*.env` behind, 0600 and readable, with
            the agent's API key inside it. Cleaning up better was never the answer; not having a file
            was.

            The fallback exists for a host without `memfd_create`, and puts the file inside a fresh
            0700 directory rather than loose in the temp root, so the protection does not rest on the
            file mode alone.

            Returns (path_for_kern, fd_to_pass_or_None, directory_to_remove_or_None).
            """
            records = KernExecutionPolicy._env_records(env)
            if records is None:
                return None, None, None
            payload = records.encode("utf-8")
            memfd = getattr(os, "memfd_create", None)
            if memfd is not None:
                fd = memfd("kern-lc-env", 0)
                try:
                    os.write(fd, payload)
                    os.lseek(fd, 0, os.SEEK_SET)
                    os.set_inheritable(fd, True)
                except BaseException:
                    os.close(fd)
                    raise
                return f"/proc/self/fd/{fd}", fd, None
            holder = tempfile.mkdtemp(prefix="kern-lc-env-")
            path = os.path.join(holder, "env")
            try:
                handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(handle, "wb") as out:
                    out.write(payload)
            except BaseException:
                _rmtree_quietly(holder)
                raise
            return path, None, holder

    return KernExecutionPolicy


def _close_quietly(fd) -> None:
    """Drop our copy of a descriptor. Called from a `finally`, so it can never raise."""
    try:
        os.close(fd)
    except OSError:
        pass


def _rmtree_quietly(path) -> None:
    """Remove the alias holder directory. Called from a finalizer, so it can never raise."""
    if not path:
        return
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass



def kern_execution_policy(**kwargs):
    """Build a langchain shell execution policy that runs in a kern box.

        from langchain.agents.middleware import ShellToolMiddleware
        from kern_sandbox.langchain import kern_execution_policy

        middleware = ShellToolMiddleware(execution_policy=kern_execution_policy())

    A factory rather than an exported class, for the same reason the tool above is: the base class
    lives in langchain, so defining the subclass at module import would make `import kern_sandbox`
    require it. The class is built on the first call and reused.

    Args:
        **kwargs: any field of the policy. Inherited from langchain's base: ``command_timeout``,
            ``startup_timeout``, ``termination_timeout``, ``max_output_lines``, ``max_output_bytes``.
            Added here: ``binary``, ``image``, ``network_enabled``, ``memory_bytes``, ``cpus``,
            ``pids_limit``, ``read_only_rootfs``, ``user``, ``drop_all_capabilities``, ``use_init``,
            ``mount_workspace`` (``auto`` / ``always`` / ``never``) and ``extra_box_args``.

    Raises:
        ImportError: `langchain` is not installed, or is a version without the policy base.
        ValueError: a field is not usable.
        RuntimeError: raised at spawn time when no kern binary can be found.
    """
    cls = _POLICY_CACHE.get("cls")
    if cls is None:
        cls = _POLICY_CACHE["cls"] = _build_policy_class()
    return cls(**kwargs)
