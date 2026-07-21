// Type definitions for kern-sandbox
// Run LLM/agent-generated code in a fast, local, daemonless kernel sandbox.

/** What stopped the code at the SANDBOX level. Reported as data on a result, never thrown. */
export type SandboxFaultType = "timeout" | "escape_blocked" | "killed" | "startup_failed";

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
  /** RAM cap in MiB (kern --memory). Default 512. null = uncapped default. */
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
  /** Called with each stdout Buffer chunk as it arrives (live streaming). The full capped output is
   * still captured in the result, so you can stream AND read result.stdout. */
  onStdout?: (chunk: Buffer) => void;
  /** Called with each stderr Buffer chunk as it arrives. */
  onStderr?: (chunk: Buffer) => void;
}

export type Language = "python" | "bash" | "node";

/** A configured kernel sandbox. FILE state persists across runCode/run in a workspace on disk; each
 * call runs in a FRESH ephemeral box. Safe by default; every relaxing option says so. */
export class Sandbox {
  constructor(opts?: SandboxOptions);
  /** Create/validate the workspace and run `setup`. Call before runCode/run/writeFile. */
  open(): Promise<this>;
  /** Delete the workspace iff we created it. Idempotent. */
  close(): Promise<void>;
  /** Run a snippet on the workspace in a fresh, network-off box. File state persists; memory does not. */
  runCode(code: string, opts?: { language?: Language }): Promise<ExecutionResult>;
  /** Run an argv ARRAY (never a shell string) in a fresh box. */
  run(command: string[]): Promise<ExecutionResult>;
  /** Write data to a workspace-relative path (host-direct, O_NOFOLLOW on the final component). */
  writeFile(path: string, data: Buffer | string): Promise<void>;
  /** Read a workspace-relative path (host-direct, O_NOFOLLOW). */
  readFile(path: string): Promise<Buffer>;
  /** Write a gzip tar of the whole workspace to `dest`, a portable filesystem checkpoint (NOT memory). */
  snapshot(dest: string): void;
  /** Extract a snapshot (from snapshot()) into the workspace, safely (rejects symlink/.. /absolute members). */
  restore(src: string): void;
  /** List regular files under the workspace (excludes .deps). */
  listFiles(subdir?: string): Promise<FileInfo[]>;
}

/** Open a Sandbox, run `fn(sandbox)`, and close it even if `fn` throws. The session helper. */
export function withSandbox<T>(fn: (sandbox: Sandbox) => Promise<T>): Promise<T>;
export function withSandbox<T>(opts: SandboxOptions, fn: (sandbox: Sandbox) => Promise<T>): Promise<T>;

/** One-shot: run `code` in a throwaway session (workspace created and deleted). */
export function runCode(code: string, opts?: SandboxOptions & { language?: Language }): Promise<ExecutionResult>;

export const version: string;
