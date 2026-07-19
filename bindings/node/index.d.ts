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
  /** Extra host->box binds: { hostSrc: boxTarget } or { src: [target, "ro"] }. Sensitive sources refused. */
  mounts?: Record<string, MountSpec>;
  /** Extra environment variables for the workload (passed via a private 0600 file, not argv). */
  env?: Record<string, string>;
  /** Cap on captured stdout/stderr EACH, in bytes. Default 64 MiB. */
  maxOutputBytes?: number;
  /** true (default) hard-enforces caps via a systemd scope (~6 ms start); false = best-effort (~3 ms). */
  enforceLimits?: boolean;
  /** Mount setup= deps read-only for runCode (blocks cross-run dependency poisoning). Default false. */
  depsReadonly?: boolean;
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
  /** List regular files under the workspace (excludes .deps). */
  listFiles(subdir?: string): Promise<FileInfo[]>;
}

/** Open a Sandbox, run `fn(sandbox)`, and close it even if `fn` throws. The session helper. */
export function withSandbox<T>(fn: (sandbox: Sandbox) => Promise<T>): Promise<T>;
export function withSandbox<T>(opts: SandboxOptions, fn: (sandbox: Sandbox) => Promise<T>): Promise<T>;

/** One-shot: run `code` in a throwaway session (workspace created and deleted). */
export function runCode(code: string, opts?: SandboxOptions & { language?: Language }): Promise<ExecutionResult>;

export const version: string;
