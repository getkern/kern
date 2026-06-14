"""kern-sandbox — run LLM/agent-generated code in a fast, local, daemonless kernel sandbox.

    import kern_sandbox as kern

    # one-shot (a throwaway session under the hood)
    r = kern.run_code("import sys; print(sys.version)")
    print(r.stdout, r.success)

    # a session: FILE state persists across steps (a workspace on disk), processes are ephemeral
    with kern.Sandbox(setup="pip install pandas") as sbx:
        sbx.write_file("data.csv", csv_bytes)
        r = sbx.run_code("import pandas as pd; print(pd.read_csv('data.csv').shape)")
        png = sbx.read_file("out.png")

Design — the "middle way" (validated with review):
  * FILE state persists between steps via a workspace DIRECTORY on the host, bind-mounted into each
    box. PROCESSES are ephemeral: every run_code()/run() spawns a FRESH box on that shared workspace.
    There is NO resident interpreter — in-memory REPL state (a `x=40` living in globals) does NOT
    survive between calls; write to disk if you need continuity. This keeps the cold-start/density
    win (100s of ephemeral boxes, not 100s of resident pythons) instead of chasing a cloud-session
    model kern isn't built for.
  * ONE class (`Sandbox`). `run_code(...)` at module level is literally a throwaway session
    (`with Sandbox() as s: return s.run_code(...)`), so there is a single, tested security code path —
    not two Sandbox-like surfaces that drift apart. (# DECISION, reviewer-ratified.)
  * I/O is HOST-DIRECT: the workspace is a host dir and single-uid maps box-root to the host user, so
    files the box creates are host-owned — write_file/read_file are plain host filesystem I/O, no
    `kern cp`, no in-box shim. (`--uid-range` breaks this ownership and is OUT of v1 scope. # DECISION.)

Threat model (honest): kern is a KERNEL-BOUNDARY sandbox for YOUR OWN or SEMI-TRUSTED code. seccomp
is a DENYLIST — suitable for semi-trusted agent code, NOT a hard boundary against deliberately hostile
multi-tenant code (for that: a microVM / gVisor). A deny-by-default allowlist mode is on the roadmap.
"""

from __future__ import annotations

import os
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Mapping, Sequence

__all__ = [
    "Sandbox",
    "ExecutionResult",
    "SandboxFault",
    "FileInfo",
    "SandboxError",
    "MountRefused",
    "run_code",
]

__version__ = "0.1.0"

# DECISION: default image is a small Python base. Criterion "import pandas with no setup" needs a
# batteries-included image; for v1 we start from a PUBLIC image and let `setup=` bake deps, rather than
# building+hosting our own (reviewer-ratified FLAG 4). Ship a datascience default when demand justifies.
_DEFAULT_IMAGE = "python:3.12-slim"

_WORKSPACE = "/workspace"  # where the persistent workspace is mounted inside every box
_DEPS_DIR = ".deps"  # pip --target dir inside the workspace (added to PYTHONPATH for run_code)
_ENV_FILE = ".kern-env"  # host-side 0600 env file (kept out of argv so values don't show in `ps`)

# Host paths a `-v` mount must never target — mounting the host's real root/config/secrets into a
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
    """A PROGRAMMER/config error, RAISED: bad argument, illegal mount, or `kern` not installed.

    Runtime sandbox events (timeout, blocked escape, OOM-kill) are NOT raised — they are reported as
    data in ``ExecutionResult.fault`` (a :class:`SandboxFault`). Raising them would force every
    ``run_code`` into a try/except for what is a normal, expected outcome of running untrusted code.
    """


class MountRefused(SandboxError):
    """A requested host mount was refused as unsafe (sensitive source, or a relative/escaping path)."""


@dataclass
class SandboxFault:
    """A SANDBOX-level event that stopped the code — reported as DATA, never raised. ``None`` in a
    result means the sandbox did nothing: any non-zero exit is the user's code, not a sandbox fault."""

    type: Literal["timeout", "escape_blocked", "killed", "startup_failed"]
    message: str


@dataclass
class FileInfo:
    """A file in the workspace and how this step touched it."""

    path: str  # workspace-relative path
    size: int
    change: Literal["created", "modified"]


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

    @property
    def success(self) -> bool:
        """True iff the code exited 0 AND no sandbox fault fired."""
        return self.exit_code == 0 and self.fault is None

    def __bool__(self) -> bool:
        return self.success


class _CappedReader(threading.Thread):
    """Drain a pipe into a bounded buffer: keep at most ``cap`` bytes but KEEP reading past it
    (discarding overflow) so a flooding box never blocks on a full pipe. RAM is bounded to ``cap``."""

    def __init__(self, pipe, cap: int) -> None:
        super().__init__(daemon=True)
        self._pipe = pipe
        self._cap = cap
        self.buf = bytearray()
        self.truncated = False

    def run(self) -> None:
        try:
            while True:
                chunk = self._pipe.read(65536)
                if not chunk:
                    break
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
            "the `kern` binary was not found on PATH — install it "
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


# Signal-derived exit codes (128 + signum) we classify.
_EXIT_SIGKILL = 137  # 128 + 9  — SIGKILL: timeout backstop or OOM (indistinguishable without cgroup)
_EXIT_SIGSYS = 159  # 128 + 31 — SIGSYS: a seccomp-denied syscall = a blocked escape attempt
_EXIT_SIGTERM = 143  # 128 + 15 — SIGTERM: kern's --timeout backstop reaping the box (SIGTERM→SIGKILL)


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
        memory_mb: RAM cap (kern ``--memory``). Default 512.
        cpus: CPU cap in cores; ``None`` = uncapped (kern ``--cpus``).
        pids: task/fork-bomb ceiling (kern ``--pids-limit``). Default 256.
        timeout_s: MANDATORY per-call wall-clock limit. The BINDING owns this deadline (it kills the
            box), so a ``timeout`` fault is a known fact, never guessed. Default 30.
        network: **RELAXES ISOLATION.** ``True`` shares the host network for every ``run_code`` (kern
            ``--net``). Default ``False``. There is no per-call network override — network is a
            session-level, explicit choice.
        mounts: extra host paths to bind, ``{host_src: box_target}`` (or ``{src: (target, "ro")}``).
            Sensitive sources are refused. The workspace is mounted automatically; this is for extras.
        env: extra environment variables for the workload.
        max_output_bytes: cap on captured stdout/stderr EACH; a flooding box can't OOM the host.
        enforce_limits: ``True`` (default) hard-enforces caps via a systemd scope (~6 ms start);
            ``False`` skips it for a ~3 ms start (best-effort caps).
    """

    image: str = _DEFAULT_IMAGE
    setup: str | None = None
    workspace: str | None = None
    memory_mb: int | None = 512
    cpus: float | None = None
    pids: int | None = 256
    timeout_s: int = 30
    network: bool = False
    mounts: Mapping[str, "str | tuple[str, str]"] | None = None
    env: Mapping[str, str] | None = None
    max_output_bytes: int = 64 * 1024 * 1024
    enforce_limits: bool = True
    deps_readonly: bool = False  # mount setup= deps read-only for run_code (block cross-run poisoning)

    _kern: str = field(default="", repr=False)
    _mount_args: list = field(default_factory=list, init=False, repr=False)
    _ws: str = field(default="", init=False, repr=False)
    _own_ws: bool = field(default=False, init=False, repr=False)  # we created it → we delete it
    _entered: bool = field(default=False, init=False, repr=False)

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
        self._kern = _find_kern()

    # -- lifecycle -----------------------------------------------------------------------------------

    def __enter__(self) -> "Sandbox":
        if self.workspace is None:
            self._ws = tempfile.mkdtemp(prefix="kern-ws-")
            self._own_ws = True
        else:
            # A caller-supplied workspace is host input → validate it like a mount source, and DON'T
            # delete it on exit (its contents persist across sessions — documented).
            _validate_mount(self.workspace, _WORKSPACE)
            self._ws = os.path.realpath(self.workspace)
            Path(self._ws).mkdir(parents=True, exist_ok=True)
            self._own_ws = False
        self._entered = True
        if self.setup:
            self._run_setup(self.setup)
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
        # session for tighter (still semi-trusted) workloads. Default off — deps writable, documented.
        if self.deps_readonly and not is_setup:
            deps = os.path.join(self._ws, _DEPS_DIR)
            if os.path.isdir(deps):
                argv += ["-v", f"{deps}:{_WORKSPACE}/{_DEPS_DIR}:ro"]
        # kern's own --timeout is a tight BACKSTOP just beyond our deadline: it is the RELIABLE killer of
        # the in-PID-namespace box (a CPU-bound box survives a SIGKILL of kern's parent process, but not
        # kern's own timeout teardown). OUR proc.wait deadline is the authority that LABELS a `timeout`
        # fault; kern's backstop guarantees the box is actually gone a few seconds later.
        argv += ["--timeout", str(timeout_s + 5)]
        if self.memory_mb is not None:
            argv += ["--memory", f"{self.memory_mb}m"]
        if self.cpus is not None:
            argv += ["--cpus", str(self.cpus)]
        if self.pids is not None:
            argv += ["--pids-limit", str(self.pids)]
        if network:
            argv += ["--net"]
        argv += self._mount_args
        merged_env = dict(self.env or {})
        # Deps installed by `setup` live in <workspace>/.deps — put them on PYTHONPATH for run_code.
        merged_env.setdefault("PYTHONPATH", f"{_WORKSPACE}/{_DEPS_DIR}")
        # Pass the workload env via a private --env-file, NOT `--env K=V` on argv: an argv value is
        # visible in `ps` / /proc/<pid>/cmdline to any local user for the box's lifetime, and this
        # component's whole point is running untrusted code beside sensitive data (a credential in
        # `env=` would leak). The file lives in our own 0700 mkdtemp workspace, written 0600, so it is
        # not readable by other users; kern reads it before the box's env is set up. (Hacker-mode audit.)
        if merged_env:
            env_path = os.path.join(self._ws, _ENV_FILE)
            fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                # K=V lines; values are single-line by construction (a NUL is rejected in _spawn, and a
                # newline in a value would split the record — reject it here so it can't smuggle a var).
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

    def _spawn(self, command: Sequence[str], *, network: bool, timeout_s: int, is_setup: bool = False) -> ExecutionResult:
        for part in command:
            if "\0" in part:
                raise SandboxError("command/code must not contain a NUL byte")
        before = self._snapshot()
        name = _unique_name()
        argv = self._base_argv(name, network=network, timeout_s=timeout_s, is_setup=is_setup) + ["--"] + list(command)
        child_env = {**os.environ, "KERN_ACCEPT_EULA": "1"}
        if not self.enforce_limits:
            child_env["KERN_NO_SCOPE"] = "1"
        started = time.monotonic()
        try:
            # start_new_session so the box + kern share a process group we can signal as a unit.
            proc = subprocess.Popen(  # noqa: S603 — argv list, no shell
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=child_env,
                start_new_session=True,
            )
        except FileNotFoundError as e:
            raise SandboxError(f"could not execute kern: {e}") from e
        except OSError as e:
            # E2BIG (argv too long) and other spawn-time OS errors → a clean typed error, not a raw
            # OSError leaking out of the binding. (run_code already routes large code via a file.)
            raise SandboxError(f"could not spawn the box: {e}") from e
        out = _CappedReader(proc.stdout, self.max_output_bytes)
        err = _CappedReader(proc.stderr, self.max_output_bytes)
        out.start()
        err.start()
        we_timed_out = False
        try:
            proc.wait(timeout=timeout_s)  # OUR deadline — the authority for a `timeout` fault
        except subprocess.TimeoutExpired:
            we_timed_out = True
            self._teardown(proc, name, child_env)
        # Join readers, but BOUNDED: a CPU-bound box can survive our signals and hold the pipe open
        # until kern's own --timeout backstop reaps it a few seconds later; never hang the caller on it.
        join_deadline = 8.0 if we_timed_out else None
        out.join(join_deadline)
        err.join(join_deadline)
        # Reap the process so returncode is populated and no zombie lingers (bounded — the backstop has
        # reaped the box by now in the timeout case).
        try:
            proc.wait(timeout=8.0)
        except subprocess.TimeoutExpired:
            pass
        wall_ms = int((time.monotonic() - started) * 1000)
        stdout = out.buf.decode("utf-8", "replace")
        stderr = err.buf.decode("utf-8", "replace")
        rc = proc.returncode if proc.returncode is not None else -1
        fault = self._classify(rc, stderr, we_timed_out)
        files = self._diff(before)
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
        PID namespace survives a plain SIGKILL of kern's parent process: (1) `kern stop` — the intended
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

    def _classify(self, rc: int, stderr: str, we_timed_out: bool) -> SandboxFault | None:
        # ORDER IS A SECURITY PROPERTY. The classes that are DETERMINISTIC by exit code are decided
        # FIRST, BEFORE we ever look at stderr — because stderr is a channel the workload controls, and
        # `startup_failed` is recognised by a pattern on it. If we checked the stderr marker first, a
        # workload could print "error: sandbox:" and exit with SIGSYS and we'd mislabel a blocked escape
        # as a mere startup failure — hiding a security event behind a benign one. So: our-deadline →
        # SIGSYS → SIGKILL, all by exit code, THEN the stderr-marker heuristic as the LAST resort.
        # (Same discipline as the tar vetter: never make a security decision by parsing an
        # adversary-influenceable channel.)
        if we_timed_out:
            # OUR deadline fired and we killed the box — a known fact, never guessed.
            return SandboxFault("timeout", f"exceeded the {self.timeout_s}s time limit (killed by the binding)")
        if rc == _EXIT_SIGSYS:
            # A seccomp-denied syscall. Decided by exit code, so no stderr content can mask it.
            return SandboxFault("escape_blocked", "a syscall was blocked by the seccomp filter (SIGSYS)")
        if rc == _EXIT_SIGKILL:
            # SIGKILL not from our deadline: almost always the cgroup OOM-killer, but the binding can't
            # read the box's memory.events (kern doesn't expose the cgroup path — verified), so we do
            # NOT claim "oom" as the type. Honest: type=killed, message carries the likely cause.
            return SandboxFault("killed", "the box was killed (SIGKILL) — likely out of memory (exit 137)")
        if rc in (_EXIT_SIGTERM, -signal.SIGTERM):
            # SIGTERM without our deadline firing = kern's OWN --timeout backstop reaped the box (it
            # SIGTERMs, then SIGKILLs after a grace). The box exceeded its time limit; label it timeout,
            # noting the backstop caught it rather than our own wait.
            return SandboxFault("timeout", "the box exceeded its time limit (reaped by kern's timeout backstop)")
        if rc == -signal.SIGKILL:
            # Negative == killed by signal N (subprocess convention) — SIGKILL surfaced as -9.
            return SandboxFault("killed", "the box was killed (SIGKILL) — likely out of memory")
        # LAST resort, heuristic: a non-zero exit that is none of the deterministic classes above, whose
        # stderr carries kern's OWN setup-diagnostic markers (printed by the parent before the box runs).
        # Heuristic because stderr is workload-influenceable — but it can only ever mislabel an ordinary
        # non-zero user exit as startup_failed, never mask an escape/timeout/kill (those were decided
        # above by exit code). Documented as best-effort.
        if rc != 0 and _looks_like_startup_failure(stderr):
            return SandboxFault("startup_failed", stderr.strip()[:500])
        # exit 139 (SIGSEGV) and any other non-zero exit are the USER's code failing — a normal Result.
        return None

    # -- workspace file I/O (host-direct; single-uid → box files are host-owned) ---------------------

    def _ws_path(self, rel: str) -> str:
        """Resolve a workspace-relative path for host-side I/O, refusing any escape out of the workspace.

        Containment is checked on the requested path LEXICALLY (normalize `..`/`.`), NOT by resolving
        symlinks in it — a symlink the box created can point at a box-absolute target like
        `/workspace/x` that doesn't exist on the host, and `realpath`-ing it would both false-positive
        (a legitimate INTERNAL symlink) and, worse, could be steered to follow a link out of the tree.
        So: lexically contain the requested name here, then open the final component with O_NOFOLLOW
        (in read/write) so a symlinked LAST component can't redirect the host I/O outside the workspace.
        """
        base = os.path.realpath(self._ws)
        # Lexical containment: join + normpath collapses `..`, then require it stays under base.
        full = os.path.normpath(os.path.join(base, rel))
        if full != base and not full.startswith(base + os.sep):
            raise SandboxError(f"path escapes the workspace: {rel!r}")
        return full

    def write_file(self, path: str, data: bytes | str) -> None:
        """Write ``data`` to ``path`` (workspace-relative) — host-direct, so the box sees it next run.
        The final component is opened O_NOFOLLOW: a symlink the box planted there can't redirect the
        write outside the workspace (it fails instead)."""
        self._require_entered()
        full = self._ws_path(path)
        Path(full).parent.mkdir(parents=True, exist_ok=True)
        payload = data.encode() if isinstance(data, str) else data
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(full, flags, 0o644)
        except OSError as e:
            raise SandboxError(f"cannot write {path!r}: {e}") from e
        with os.fdopen(fd, "wb") as f:
            f.write(payload)

    def read_file(self, path: str) -> bytes:
        """Read ``path`` (workspace-relative) from the workspace — host-direct. The final component is
        opened O_NOFOLLOW: a symlink there can't redirect the read outside the workspace."""
        self._require_entered()
        full = self._ws_path(path)
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(full, flags)
        except OSError as e:
            raise SandboxError(f"cannot read {path!r}: {e}") from e
        with os.fdopen(fd, "rb") as f:
            return f.read()

    def list_files(self, subdir: str = "") -> list[FileInfo]:
        """List files under the workspace (excluding the ``.deps`` install dir)."""
        self._require_entered()
        root = self._ws_path(subdir) if subdir else os.path.realpath(self._ws)
        return [FileInfo(path=p, size=s, change="created") for p, (_, s) in self._walk(root).items()]

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
        return self._walk(os.path.realpath(self._ws))

    def _walk(self, root: str) -> dict[str, tuple[int, int]]:
        """Map WORKSPACE-relative path -> (mtime_ns, size), skipping .deps, our env-file, and symlinks.
        `root` is where to walk (the workspace, or a subdir for `list_files(subdir)`); paths are ALWAYS
        made relative to the workspace root so `list_files("sub")` returns `sub/a.txt`, composable with
        `read_file` (that was a regression when `root` doubled as the base). One lstat per file: S_ISREG
        excludes non-regular files AND symlinks in a single syscall (a symlink's lstat mode is never
        S_ISREG) — no extra isfile()/islink() stats."""
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
                if rel == _ENV_FILE:
                    continue  # our private host-side --env-file, not a user artifact
                out[rel] = (st.st_mtime_ns, st.st_size)
        return out

    def _diff(self, before: dict[str, tuple[int, int]]) -> list[FileInfo]:
        after = self._snapshot()
        files: list[FileInfo] = []
        for rel, (mtime, size) in after.items():
            if rel not in before:
                files.append(FileInfo(path=rel, size=size, change="created"))
            elif before[rel] != (mtime, size):
                files.append(FileInfo(path=rel, size=size, change="modified"))
        return files

    # -- the two ways to run code --------------------------------------------------------------------

    # Above this size, pass code via a file in the workspace instead of `-c <code>` on the argv, so a
    # large agent-generated script can't blow ARG_MAX (~2 MB) with a raw OSError. Well under the limit.
    _INLINE_CODE_MAX = 128 * 1024

    def run_code(self, code: str, *, language: Literal["python", "bash"] = "python") -> ExecutionResult:
        """Run a snippet of ``code`` on the workspace in a fresh, network-off box. File state written to
        the workspace persists to the next call; in-memory state does NOT (fresh process each time).
        Large code is written to a workspace file and executed from there (transparent to the caller),
        so an arbitrarily large script works instead of hitting the argv length limit."""
        self._require_entered()
        if language not in ("python", "bash"):
            raise SandboxError(f"unsupported language {language!r} (v1: 'python' | 'bash')")
        runner = "python3" if language == "python" else "sh"
        if len(code.encode()) > self._INLINE_CODE_MAX:
            # Write to a per-call cell file in the workspace and run it by path (no argv-size limit).
            cell = f".cell-{uuid.uuid4().hex[:8]}.{'py' if language == 'python' else 'sh'}"
            self.write_file(cell, code)
            command: list[str] = [runner, f"{_WORKSPACE}/{cell}"]
        else:
            command = [runner, "-c", code]
        return self._spawn(command, network=self.network, timeout_s=self.timeout_s)

    def run(self, command: Sequence[str]) -> ExecutionResult:
        """Run an arbitrary ``command`` (an argv LIST, never a shell string) in a fresh box."""
        self._require_entered()
        if isinstance(command, str):
            raise SandboxError('run() takes an argv LIST, not a string. Use run(["sh","-c","..."]).')
        if not command:
            raise SandboxError("run() needs a non-empty command")
        return self._spawn(command, network=self.network, timeout_s=self.timeout_s)


def _unique_name() -> str:
    return "pysbx-" + uuid.uuid4().hex[:12]


def _looks_like_startup_failure(stderr: str) -> bool:
    """True iff kern (the PARENT, before the box exists) failed to start the box. Anchored on kern's own
    diagnostic prefixes — printed by kern, not by the workload — so the workload can't forge them by
    writing the marker to its own stderr. (Same discipline as the tar vetter: don't trust text the
    adversary controls; kern's setup errors precede any workload output and carry kern's prefixes.)"""
    markers = ("kern:", "error: pull:", "error: sandbox:", "error: box:", "error: oci:", "error: image:")
    for line in stderr.splitlines():
        s = line.lstrip()
        if "sandbox setup failed" in s or any(s.startswith(m) for m in markers):
            return True
    return False


def run_code(code: str, *, language: Literal["python", "bash"] = "python", **kwargs: object) -> ExecutionResult:
    """One-shot convenience: run ``code`` in a throwaway session (workspace created and deleted). This is
    literally ``with Sandbox(**kwargs) as s: return s.run_code(code)`` — one tested code path, no state
    persists. For multi-step work (write a file, then read it), use ``Sandbox`` as a context manager."""
    with Sandbox(**kwargs) as s:  # type: ignore[arg-type]
        return s.run_code(code, language=language)
