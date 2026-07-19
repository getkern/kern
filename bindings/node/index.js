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
const { spawn, spawnSync } = require("child_process");

const VERSION = "0.1.0";

const DEFAULT_IMAGE = "python:3.12-slim";
const WORKSPACE = "/workspace"; // where the persistent workspace is mounted inside every box
const DEPS_DIR = ".deps"; // pip --target dir inside the workspace (added to PYTHONPATH for python)
const ENV_FILE = ".kern-env"; // host-side 0600 env file (kept out of argv so values don't show in `ps`)
const INLINE_CODE_MAX = 128 * 1024; // above this, pass code via a file instead of argv (ARG_MAX guard)

// Signal-derived exit codes (128 + signum) we classify.
const EXIT_SIGKILL = 137; // SIGKILL: timeout backstop or OOM (indistinguishable without cgroup)
const EXIT_SIGSYS = 159; // SIGSYS: a seccomp-denied syscall = a blocked escape attempt
const EXIT_SIGTERM = 143; // SIGTERM: kern's --timeout backstop reaping the box

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

/** The outcome of one runCode()/run(). `fault` is the source of truth for "did the SANDBOX act";
 * `exitCode`/`stdout` are what the user's code did. `success` requires both clean. */
class ExecutionResult {
  constructor({ stdout, stderr, exitCode, durationMs, fault, files, truncated }) {
    this.stdout = stdout;
    this.stderr = stderr;
    this.exitCode = exitCode;
    this.durationMs = durationMs;
    /** @type {{type: string, message: string} | null} */
    this.fault = fault || null;
    this.files = files || [];
    this.truncated = !!truncated;
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
  const markers = ["kern:", "error: pull:", "error: sandbox:", "error: box:", "error: oci:", "error: image:"];
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
function cappedCollector(stream, cap) {
  const chunks = [];
  let len = 0;
  const state = { truncated: false };
  stream.on("data", (chunk) => {
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
   * @param {Object<string, string|[string,string]>} [opts.mounts] extra host->box binds. Sensitive refused.
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
    this.mounts = opts.mounts ?? null;
    this.env = opts.env ?? null;
    this.maxOutputBytes = opts.maxOutputBytes ?? 64 * 1024 * 1024;
    this.enforceLimits = opts.enforceLimits ?? true;
    this.depsReadonly = opts.depsReadonly ?? false;

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
      validateMount(this.workspace, WORKSPACE);
      fs.mkdirSync(this.workspace, { recursive: true });
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
    argv.push("--timeout", String(timeoutS + 5));
    if (this.memoryMb !== null) argv.push("--memory", `${this.memoryMb}m`);
    if (this.cpus !== null) argv.push("--cpus", String(this.cpus));
    if (this.pids !== null) argv.push("--pids-limit", String(this.pids));
    if (network) argv.push("--net");
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

  _spawn(command, { network, timeoutS, isSetup = false }) {
    for (const part of command)
      if (typeof part !== "string" || part.includes("\0"))
        throw new SandboxError("command/code must be strings with no NUL byte");
    const before = this._snapshot();
    const name = uniqueName();
    const argv = [...this._baseArgv(name, { network, timeoutS, isSetup }), "--", ...command];
    const childEnv = { ...process.env, KERN_ACCEPT_EULA: "1" };
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

      const out = cappedCollector(child.stdout, this.maxOutputBytes);
      const err = cappedCollector(child.stderr, this.maxOutputBytes);
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
        const fault = this._classify(rc, signal, stderr, timedOut);
        const files = this._diff(before);
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

  _classify(rc, signal, stderr, timedOut) {
    // ORDER IS A SECURITY PROPERTY: deterministic-by-exit-code classes are decided BEFORE the stderr
    // heuristic, because stderr is a channel the workload controls.
    if (timedOut)
      return sandboxFault("timeout", `exceeded the ${this.timeoutS}s time limit (killed by the binding)`);
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

  /** Read `path` (workspace-relative) from the workspace - host-direct. Final component O_NOFOLLOW. */
  async readFile(rel) {
    this._requireEntered();
    const full = this._wsPath(rel);
    let fd;
    try {
      fd = fs.openSync(full, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    } catch (e) {
      throw new SandboxError(`cannot read ${JSON.stringify(rel)}: ${e.message}`);
    }
    try {
      return fs.readFileSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }

  /** List regular files under the workspace (excluding the .deps install dir and our env file). */
  async listFiles(subdir = "") {
    this._requireEntered();
    const root = subdir ? this._wsPath(subdir) : this._ws;
    const walked = this._walk(root);
    return Object.entries(walked).map(([p, [, size]]) => ({ path: p, size, change: "created" }));
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
  async runCode(code, { language = "python" } = {}) {
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
    let command;
    if (Buffer.byteLength(code, "utf8") > INLINE_CODE_MAX) {
      const cell = `.cell-${crypto.randomBytes(4).toString("hex")}.${ext}`;
      await this.writeFile(cell, code);
      command = [runner, `${WORKSPACE}/${cell}`];
    } else {
      command = [runner, evalFlag, code];
    }
    return this._spawn(command, { network: this.network, timeoutS: this.timeoutS });
  }

  /** Run an arbitrary `command` (an argv ARRAY, never a shell string) in a fresh box. */
  async run(command) {
    this._requireEntered();
    if (typeof command === "string")
      throw new SandboxError('run() takes an argv ARRAY, not a string. Use run(["sh","-c","..."]).');
    if (!Array.isArray(command) || command.length === 0)
      throw new SandboxError("run() needs a non-empty command array");
    return this._spawn(command, { network: this.network, timeoutS: this.timeoutS });
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
  withSandbox,
  runCode,
  ExecutionResult,
  SandboxError,
  MountRefused,
  version: VERSION,
};
