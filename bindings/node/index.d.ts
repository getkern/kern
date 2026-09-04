// Type definitions for kern-sandbox
// Run LLM/agent-generated code in a fast, local, daemonless kernel sandbox.
//
// `Buffer` is in this file's public surface (chunk callbacks, readFile, decoded images), so a
// TypeScript consumer needs `@types/node`. Deliberately NOT declared with a
// `/// <reference types="node" />`: that was tried and measured, and it made things worse. Without
// Node's types the reference adds `TS2688: Cannot find type definition file for 'node'` on TOP of the
// six `Buffer` errors, and those six already carry TypeScript's own remedy, verbatim: "Do you need to
// install type definitions for node? Try `npm i --save-dev @types/node`". Seven errors that name the
// fix are not better than six that name it. The README says it in prose instead.
//
// There is a THIRD option, and it is a decision rather than a fix, so it is written down and not
// taken on a delivery day: type this surface as `Uint8Array` instead of `Buffer`. `Buffer extends
// Uint8Array`, so a caller's Buffers still satisfy it, the package stops needing `@types/node` at
// all, and it becomes typable outside Node. That is a change to the published surface, which is a
// 0.2 conversation. Until then the requirement is a consequence of a type choice we made, not a
// law of the platform, and the README should not imply otherwise.

/** What stopped the code at the SANDBOX level. Reported as data on a result, never thrown. */
export type SandboxFaultType = "timeout" | "oom" | "escape_blocked" | "killed" | "startup_failed" | "exec_failed";

export interface SandboxFault {
  type: SandboxFaultType;
  message: string;
}

/** A file in the workspace and how a step touched it. */
export interface FileInfo {
  /** workspace-relative path */
  path: string;
  size: number;
  change: "created" | "modified";
}

/** A rich, mime-typed value captured from a Python `runCode` (Jupyter/E2B-style): the code's last bare
 * expression, every `display(obj)` call, and every open matplotlib figure. `data` maps a MIME type to
 * its payload (text/* and application/json are strings; image/* are base64). One value, several forms. */
export class Result {
  data: Record<string, string>;
  /** text/plain */
  readonly text?: string;
  /** text/html */
  readonly html?: string;
  /** text/markdown */
  readonly markdown?: string;
  /** image/svg+xml */
  readonly svg?: string;
  /** application/json */
  readonly json?: string;
  /** image/png decoded to a Buffer, or null */
  readonly png: Buffer | null;
  /** image/jpeg decoded to a Buffer, or null */
  readonly jpeg: Buffer | null;
  /** The MIME types this value was captured as. */
  formats(): string[];
}

/** The outcome of one runCode()/run(). `fault` is the source of truth for "did the sandbox act";
 * `exitCode`/`stdout` are what the user's code did. `success` requires both clean. */
export class ExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  /** null iff the sandbox did nothing: any non-zero exit is then the user's code, not a sandbox fault. */
  fault: SandboxFault | null;
  files: FileInfo[];
  /** stdout/stderr hit the capture cap and overflow was discarded. */
  truncated: boolean;
  /** Rich mime-typed values (Python runCode): last expression, display(), matplotlib figures. */
  results: Result[];
  /** True iff the code exited 0 AND no sandbox fault fired. */
  readonly success: boolean;
}

/** A PROGRAMMER/config error, THROWN: bad argument, illegal mount, or `kern` not installed. */
export class SandboxError extends Error {}
/** A requested host mount was refused as unsafe (sensitive source, or a relative/escaping path). */
export class MountRefused extends SandboxError {}

export type MountSpec = string | [target: string, mode: "ro" | "rw"];

export interface SandboxOptions {
  /** OCI image the box runs from. Default: "python:3.12-slim". */
  image?: string;
  /** Shell command run ONCE at open() in a NETWORK-ENABLED setup box (e.g. "pip install pandas"). */
  setup?: string;
  /** Host dir to persist as the workspace. Omit -> a temp dir, created on open() and deleted on close(). */
  workspace?: string;
  /** RAM cap in MiB (kern --memory). Default 512. Passed as an explicit --memory, so by kern's
   * "explicit flag wins over profile" rule the default OVERRIDES a `vcpu:` profile's own `memory=`;
   * pass `null` to let the profile's memory apply (uncapped if the profile carries none). */
  memoryMb?: number | null;
  /** CPU cap in cores (kern --cpus). null (default) = uncapped. */
  cpus?: number | null;
  /** Task/fork-bomb ceiling (kern --pids-limit). Default 256. */
  pids?: number | null;
  /** MANDATORY per-call wall-clock limit in seconds. The binding owns this deadline. Default 30. */
  timeoutS?: number;
  /** RELAXES ISOLATION. true shares the host network for every runCode. Default false. */
  network?: boolean;
  /**
   * Restrict runCode/run to a DOMAIN ALLOWLIST instead of all-or-nothing, e.g. ["pypi.org",
   * "files.pythonhosted.org"]. The box runs in an isolated network namespace and reaches the internet
   * only through kern's filtering proxy, which permits just these domains. Mutually exclusive with
   * network:true; the setup box keeps full network to install deps, the allowlist governs the run phase.
   */
  egressAllow?: string[];
  /** Extra host->box binds: { hostSrc: boxTarget } or { src: [target, "ro"] }. Sensitive sources refused. */
  mounts?: Record<string, MountSpec>;
  /**
   * Fresh in-box scratch filesystems (kern `--tmpfs`), as `{ "/path": "64m" }` or `["/path"]`.
   *
   * **A 64 MiB tmpfs is mounted at `/tmp` by default.** The box root is read-only, so without it a
   * write naming `/tmp` fails and temp-file helpers fall back to the current directory, quietly
   * putting scratch into your persistent workspace. Pass `{ "/tmp": "512m" }` to resize, `{}` for
   * none, or bind your own directory at `/tmp` through `mounts` and the default steps aside. The
   * bytes are charged to the box's memory cgroup, so a runaway writer is OOM-killed rather than
   * filling the host disk.
   *
   * **Scratch does not survive a command, EXCEPT in a kernel().** Each `runCode`/`run` is a fresh
   * box, so the tmpfs is fresh too, while the workspace persists. A `kernel()` is one long-lived box,
   * so its `/tmp` persists across cells and the size is CUMULATIVE: measured at 10 MiB per step under
   * the 64 MiB default, ten `runCode` calls all pass while the same ten cells in a kernel fail from
   * the seventh with ENOSPC.
   *
   * A read-only `/tmp` used to fail LOUDLY at the moment of the mistake; now a tool that writes state
   * to the workspace and a lock to `/tmp` writes both, and the next call finds workspace state
   * pointing at a `/tmp` path that is gone. Put anything another call has to find in the workspace.
   *
   * The EFFECTIVE ceiling is `min(size, memoryMb)`, and `df` inside the box
   * does not know that: a `"1t"` scratch shows 1.0T free and the first write past the cap is an OOM,
   * not `ENOSPC`. The `oom` fault names the scratch so the reader is not sent to their allocation.
   */
  tmpfs?: Record<string, string | null> | string[];
  /**
   * kern resource profiles to attach, e.g. ["vcpu:heavy", "vgpio:leds", "vdisk:scratch"]. Each names a
   * [[vcpu]]/[[vgpio]]/[[vdisk]] block in your ~/.config/kern/kern.toml: a CPU+memory slice, a specific
   * GPIO/I2C/SPI device set (the only way to grant the box hardware), or a size-capped scratch disk.
   * Tokens are strictly validated (prefix + alphanumeric name) so an entry can never smuggle a flag.
   */
  profiles?: string[];
  /** Extra environment variables for the workload (passed via a private 0600 file, not argv). */
  env?: Record<string, string>;
  /** Cap on captured stdout/stderr EACH, in bytes. Default 64 MiB. */
  maxOutputBytes?: number;
  /** true (default) hard-enforces caps via a systemd scope (~6 ms start); false = best-effort (~3 ms). */
  enforceLimits?: boolean;
  /** Mount setup= deps read-only for runCode (blocks cross-run dependency poisoning). Default false. */
  depsReadonly?: boolean;
  /** true (default) populates result.files by walking the workspace before AND after each call (O(N) in
   * file count; a long session that accretes files slows every runCode). false = result.files [], O(1). */
  trackFiles?: boolean;
  /** Called with each stdout Buffer chunk as it arrives (live streaming). The full capped output is
   * still captured in the result, so you can stream AND read result.stdout. */
  onStdout?: (chunk: Buffer) => void;
  /** Called with each stderr Buffer chunk as it arrives. */
  onStderr?: (chunk: Buffer) => void;
  /** Keep N boxes started in advance, each holding a booted interpreter that has run nothing, so a
   * python `runCode` claims one instead of starting its own: ~41 ms per call becomes ~2 ms.
   *
   * It does NOT change what a call gets. Each prewarmed box serves exactly one cell and is then
   * destroyed, so the cell still runs in a private box that has executed nothing else; what moves is
   * when the box and interpreter started. A call that streams (`onStdout`/`onStderr`), asks for a
   * non-python language, or differs in posture from the pooled box takes the ordinary path.
   *
   * Default 0: N warm boxes hold N booted interpreters for the life of the session whether or not a
   * call arrives, which is a resource decision the caller owns. A slot refills in ~70 ms, so N is a
   * burst budget - N back-to-back calls run warm and the rest fall back until the pool catches up. */
  prewarm?: number;
}

/** `bash` runs bash and `sh` runs the POSIX shell: they are different shells, and the image must
 * provide the one you ask for. On alpine there is no bash, and asking for it yields an
 * `exec_failed` fault naming it rather than a shell you did not choose. */
export type Language = "python" | "bash" | "sh" | "node";

/** Per-call overrides for runCode()/run(): each defaults to the Sandbox's constructor value; an explicit
 * value applies to this call only (a `null` callback disables streaming for the call). */
export interface PerCallOptions {
  /** Wall-clock limit in seconds for THIS call. Omit to inherit the session's timeoutS. */
  timeoutS?: number;
  /** Stream each stdout Buffer chunk for this call; null disables. Omit to inherit the session's. */
  onStdout?: ((chunk: Buffer) => void) | null;
  /** Stream each stderr Buffer chunk for this call; null disables. Omit to inherit the session's. */
  onStderr?: ((chunk: Buffer) => void) | null;
}

/** A configured kernel sandbox. FILE state persists across runCode/run in a workspace on disk; each
 * call runs in a FRESH ephemeral box. Safe by default; every relaxing option says so. */
export class Sandbox {
  constructor(opts?: SandboxOptions);
  /** Create/validate the workspace and run `setup`. Call before runCode/run/writeFile. */
  open(): Promise<this>;
  /** Delete the workspace iff we created it. Idempotent. */
  close(): Promise<void>;
  /** Run a snippet on the workspace in a fresh, network-off box. File state persists; memory does not.
   * `timeoutS`/`onStdout`/`onStderr` override the session defaults for this call only. */
  runCode(code: string, opts?: { language?: Language } & PerCallOptions): Promise<ExecutionResult>;
  /** Run an argv ARRAY (never a shell string) in a fresh box. `timeoutS`/`onStdout`/`onStderr` override
   * the session defaults for this call only. */
  run(command: string[], opts?: PerCallOptions): Promise<ExecutionResult>;
  /** Write data to a workspace-relative path (host-direct, O_NOFOLLOW on the final component). */
  writeFile(path: string, data: Buffer | string): Promise<void>;
  /** Read a workspace-relative path (host-direct, O_NOFOLLOW). */
  /**
   * Read a workspace file, host-direct, every path component opened `O_NOFOLLOW`.
   *
   * `maxBytes` is a **REFUSAL threshold, not a partial read**: a larger file throws and nothing is
   * returned, it never yields the first `maxBytes` bytes. Safer for a boundary (a silent truncation is
   * how a caller ends up parsing half a file) and not what the name suggests, which is why it is
   * spelled out: asking for 16 bytes to sniff a magic number and wrapping the call in `catch` turns
   * every image in a project into "not an image", in silence.
   */
  readFile(path: string, opts?: { maxBytes?: number }): Promise<Buffer>;
  /** Write a gzip tar of the whole workspace to `dest`, a portable filesystem checkpoint (NOT memory). */
  snapshot(dest: string): void;
  /** Extract a snapshot (from snapshot()) into the workspace, safely (rejects symlink/.. /absolute members). */
  restore(src: string): void;
  /** List regular files under the workspace (excludes .deps). */
  listFiles(subdir?: string): Promise<FileInfo[]>;
  /** Open a persistent, WARM Python interpreter in a long-lived box (warm-start): cells run in ONE
   * resident process, so in-memory state PERSISTS across cells and the per-cell cost drops from a full
   * interpreter boot (~10 ms) to sub-millisecond. Returns an OPEN Kernel; call `await k.close()` when
   * done. Trade vs runCode: call-fast but NOT call-isolated (one process, one box; still network-off and
   * resource-capped; a fresh session/kernel is clean). A per-cell timeout tears the kernel down. */
  kernel(opts?: { timeoutS?: number }): Promise<Kernel>;
}

/** A warm, persistent Python interpreter in one long-lived box (see `Sandbox.kernel`). `runCode` sends a
 * cell over a pipe to the resident interpreter and resolves to an ExecutionResult with captured
 * stdout/stderr, exit code and rich `results`. In-memory state persists across cells; the box stays
 * network-off and resource-capped. `close()` (or a per-cell timeout) tears the box down. */
export class Kernel {
  /** Execute `code` in the warm interpreter; in-memory state persists from the previous cell. A trailing
   * expression, display() calls and matplotlib figures are captured into `results`. `timeoutS` overrides
   * the kernel's deadline for this cell; exceeding it tears the kernel down and returns a timeout fault. */
  runCode(code: string, opts?: { timeoutS?: number }): Promise<ExecutionResult>;
  /** Tear down the kernel box (close its stdin, then SIGKILL its process group) and remove its driver. */
  close(): Promise<void>;
}

/** Open a Sandbox, run `fn(sandbox)`, and close it even if `fn` throws. The session helper. */
export function withSandbox<T>(fn: (sandbox: Sandbox) => Promise<T>): Promise<T>;
export function withSandbox<T>(opts: SandboxOptions, fn: (sandbox: Sandbox) => Promise<T>): Promise<T>;

/** One-shot: run `code` in a throwaway session (workspace created and deleted). */
export function runCode(code: string, opts?: SandboxOptions & { language?: Language }): Promise<ExecutionResult>;

export const version: string;

/** The size, in MiB, of the tmpfs this binding mounts at `/tmp` by default.
 *
 * Exported so a consumer that wants a different default can express it as a multiple of this one
 * rather than declaring a second independent number that drifts from it.
 */
export const DEFAULT_TMPFS_MB: number;
