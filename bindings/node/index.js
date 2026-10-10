/**
 * kern-sandbox - run LLM/agent-generated code in a fast, local, daemonless kernel sandbox.
 *
 *   const kern = require('kern-sandbox');
 *
 *   // one-shot (a throwaway session under the hood). The CODE is Python, because the default image
 *   // is python:3.12-slim: this example used to pass `language: "node"`, which that image cannot
 *   // run, so the first thing a reader copied was the one call that fails.
 *   const r = await kern.runCode("print(1 + 1)");
 *   console.log(r.stdout, r.success);
 *
 *   // JavaScript needs an image that carries node; kern refuses it on the default one rather than
 *   // starting a box to discover that.
 *   const js = await kern.runCode("console.log(1 + 1)", { language: "node", image: "node:22-slim" });
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
const zlib = require("zlib");
const { spawn, spawnSync } = require("child_process");

const VERSION = "0.2.46";

const DEFAULT_IMAGE = "python:3.12-slim";
// WHAT THE DEFAULT IMAGE CONTAINS, as a fact ABOUT THE IMAGE and not about its name. It drives the
// node refusal below and sits here so that changing DEFAULT_IMAGE forces a decision about it in the
// same edit: the batteries-included image this repo builds (`images/sandbox/Dockerfile`) ships node,
// `python:3.12-slim` does not, and a refusal keyed on "is this the default image" would go on
// refusing a path that had started working the day the default changed. Same spelling, same reason,
// as `_DEFAULT_IMAGE_HAS_NODE` in the Python binding.
const DEFAULT_IMAGE_HAS_NODE = false;
const WORKSPACE = "/workspace"; // where the persistent workspace is mounted inside every box
// What `kern exec` says when the box it was asked for is not running. Matched rather than inferred
// from an exit code, because `exec` reports a MISSING BOX and a workload that exited non-zero through
// the same status, and only the first of the two is something the binding can repair.
const RESIDENT_GONE = "no running box named";
// Prefix for a resident box's name, so one cannot be confused with a box the user started by hand.
const RESIDENT_PREFIX = "kern-sbx-";
// The label a resident box's posture fingerprint is stamped into.
const CFG_LABEL = "kern.sbx.cfg";

/** An error that means "there, and closed to this process": what a non-root box user's 0700 or 0600 gives
 * the host, and the only error the helper-box fallbacks answer. */
function isClosedErr(e) {
  return !!e && (e.code === "EACCES" || e.code === "EPERM");
}

/**
 * Bytes a directory tree occupies ON DISK, or 0 when it cannot be read.
 *
 * `blocks * 512` and NOT `size`, because the question is how much of the disk is gone and the two
 * disagree in both directions: a sparse file reports a size it does not occupy, and a 1-byte file
 * occupies a whole block.
 *
 * HARD LINKS ARE COUNTED ONCE, keyed by `(dev, ino)`: a box that hard-links one large file a thousand
 * times occupies one file's worth of disk, and charging it a thousand times would refuse a session
 * that is costing nothing.
 *
 * SYMLINKS ARE NOT FOLLOWED. The workspace is box-controlled, and a symlink to `/usr` would otherwise
 * make untrusted input drive an unbounded walk - a denial of service dressed as a measurement.
 * `lstatSync` keeps the walk inside the tree and charges the link its own (tiny) blocks.
 *
 * Iterative with an explicit stack, not recursion: a deep tree is something the box chooses, and a
 * 2000-level one is enough to end a recursive walk in a stack overflow.
 *
 * Best effort, never throwing: a file deleted mid-walk is ordinary in a live workspace, and a
 * measurement that can abort a call is worse than one that is slightly stale. With `blind` (a shared
 * workspace) a directory closed to this process is pushed there whole, uncounted, for the caller to
 * measure another way.
 */
function workspaceUsage(root, blind = null) {
  let total = 0;
  const seen = new Set();
  const stack = [root];
  // A DIRECTORY THIS PROCESS CANNOT READ is not an empty one. With a non-root `user` the box user can
  // close one to us (`mkdtemp`'s 0700), and counting it as zero would let the code in the box keep a
  // cap's worth of bytes where this walk does not look. It goes to `blind` WHOLE, its entries uncounted
  // here, so the caller can measure it another way without counting any twice. Mirrors Python.
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (e) {
      if (blind && isClosedErr(e)) blind.push(current);
      continue;
    }
    const stats = [];
    let closed = false;
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      try {
        stats.push([full, fs.lstatSync(full)]);
      } catch (e) {
        if (isClosedErr(e)) {
          closed = true; // listable, not searchable
          break;
        }
      }
    }
    if (closed) {
      if (blind) blind.push(current);
      continue;
    }
    for (const [full, st] of stats) {
      if (st.isDirectory()) stack.push(full); // from the lstat already taken
      const key = `${st.dev}:${st.ino}`;
      if (seen.has(key)) continue;
      seen.add(key);
      total += (st.blocks || 0) * 512;
    }
  }
  return total;
}

/**
 * Run a command and capture it, WITHOUT blocking the event loop.
 *
 * `spawnSync` would be shorter and is what the first version of this used; this file already records
 * why that is wrong here (see `pycBuild`): a synchronous spawn stops every other timer and socket in
 * the host process for its whole duration, and these calls talk to `kern ps` and `kern box`.
 */
function runCapture(argv, timeoutMs, env) {
  // `env` IS OPTIONAL AND DEFAULTS TO INHERITING, which is right for the read-only queries that use this
  // helper (`kern ps`, `kern stop`). It exists because ONE caller must not inherit: creating a resident
  // box has to honour the Sandbox's `enforceLimits` rather than whatever `KERN_NO_SCOPE` happened to be
  // exported in the shell. The text view of `runBuffered`, decoded once rather than chunk by chunk, so a
  // character split across two reads is not mangled.
  return runBuffered(argv, { timeoutMs, env }).then((r) => ({
    code: r.code,
    stdout: r.stdout.toString("utf8"),
    stderr: r.stderr,
  }));
}

const DEPS_DIR = ".deps"; // pip --target dir inside the workspace (added to PYTHONPATH for python)

// The errors that mean "this name is not a directory any more", which is ordinary churn in a
// workspace a box is writing to: the entry went (ENOENT), or it was replaced by something that is
// not a directory - a symlink, which `O_DIRECTORY | O_NOFOLLOW` answers ENOTDIR for on current
// kernels, or a file. EVERYTHING ELSE IS THROWN: EMFILE and ENOMEM used to read as churn too, and a
// walk that loses a subtree to one of those reports a workspace smaller than it is.
const WALK_GONE = new Set(["ENOENT", "ENOTDIR", "ELOOP"]);

// -- `user`: an account of the image, and what it takes for the workspace to stay shared ------------
//
// The SAME design as the Python binding, explained there at length (`_validate_user` and below): box
// root writes as this process, a NON-ROOT box user is a uid of kern's subordinate range on disk
// (`node`, 1000, is 100999 here, measured), and a POSIX ACL on the workspace shares it both ways. What
// an ACL cannot outrank (a 0600 file, a 0700 directory the box user makes on purpose) is reached
// through a short-lived box of the same image running as that user, its owner, only after the host
// was refused. Node has no xattr call, so the ACL is written by `setfacl`, on descriptors (see
// `aclGrantBatches`). The helper scripts are byte-for-byte Python's, so both bindings refuse the same
// things in the same words.

/** A `user` value: `<user>[:<group>]`, each a name or a number, no leading `-`. Mirrors Python. */
const USER_SPEC_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,31})?$/;

function validateUser(spec) {
  if (typeof spec !== "string" || !USER_SPEC_RE.test(spec))
    throw new SandboxError(
      "user must be '<user>' or '<user>:<group>', each a name or a number of the image's own " +
        `accounts (e.g. user: "node" or user: "1000:1000"), got ${JSON.stringify(spec)}`,
    );
  return spec;
}

/** Whether `spec` runs the box as box root: no spec, or a user half of `0` or `root`. */
function isRootUser(spec) {
  return !spec || ["0", "root"].includes(String(spec).split(":")[0]);
}

/** The `USER` the image declares, from kern's config sidecar, or null (none declared, or no sidecar to
 * read, which leaves a session exactly as it was before this existed). Mirrors `_image_user`. */
function imageUser(image) {
  let text;
  try {
    const fd = fs.openSync(kernImageFile(image, ".image"), "r");
    try {
      // THE FILE'S OWN SIZE, bounded, and not a fixed 1 MiB buffer: zeroing that on every open() cost
      // 45.9 us for a sidecar of a few hundred bytes (measured), five times Python's whole read.
      const size = Math.min(fs.fstatSync(fd).size, 1 << 20);
      const buf = Buffer.allocUnsafe(size);
      text = buf.subarray(0, fs.readSync(fd, buf, 0, size, 0)).toString("utf8");
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
  for (const line of text.split("\n")) {
    const tab = line.indexOf("\t");
    if (tab >= 0 && line.slice(0, tab) === "user") return line.slice(tab + 1) || null;
  }
  return null;
}

// The helper box's scripts (see `Sandbox._helperArgv`), byte-for-byte the Python binding's: run by
// `sh -c SCRIPT sh ARGS...` as the box user with the workspace at `/w`, taking PATH COMPONENTS and
// refusing a symlink in any of them. Exit 40 is a symlink, 41 not a regular file, 42 a directory that
// could not be made, 43 not a directory.
const HELPER_READ =
  'l=$1; shift; p=/w; for c in "$@"; do p="$p/$c"; if [ -L "$p" ]; then exit 40; fi; done; ' +
  '[ -f "$p" ] || exit 41; if [ -n "$l" ]; then exec head -c "$l" -- "$p"; fi; exec cat -- "$p"';
const HELPER_WRITE =
  'p=/w; n=$#; i=0; for c in "$@"; do i=$((i+1)); p="$p/$c"; ' +
  'if [ -L "$p" ]; then exit 40; fi; ' +
  'if [ "$i" -lt "$n" ]; then [ -d "$p" ] || mkdir -- "$p" || exit 42; fi; done; ' +
  'if [ -e "$p" ] && [ ! -f "$p" ]; then exit 41; fi; ' +
  't=$(mktemp "${p%/*}/.kern-write-XXXXXX") || exit 42; ' +
  'chmod 664 "$t" && cat > "$t" && mv -f -- "$t" "$p"';
const HELPER_LIST =
  'cd /w || exit 1; find "$@" -exec sh -c ' +
  "'for f; do stat -c \"%f %s %Y\" -- \"$f\" && printf \"%s\\0\" \"$f\"; done' sh {} +";
const HELPER_DU = 'cd /w || exit 1; du -sk -- "$@"';
const HELPER_ISDIR =
  'p=/w; for c in "$@"; do p="$p/$c"; if [ -L "$p" ]; then exit 40; fi; done; [ -d "$p" ] || exit 43';
const HELPER_CLEAN =
  "chmod -R u+rwX -- /w/* /w/.[!.]* /w/..?* 2>/dev/null; rm -rf -- /w/* /w/.[!.]* /w/..?*";
const HELPER_TAR = 'cd /w || exit 1; exec tar -cf - "$@"';
const HELPER_UNTAR = "exec tar -x -o -f - -C /w";
/** What the scripts need in the image, said by the refusal that cannot run them. Python says the same. */
const HELPER_TOOLS =
  "The image needs a POSIX shell with cat, head, find, stat, du, tar, mktemp, chmod, mv, mkdir and " +
  "rm (coreutils or busybox)";

/** A workspace-relative path as a helper script argument: under `./`, so a name can never read as an
 * option, and `.` for the workspace itself. Mirrors Python's `_helper_subtree`. */
function helperSubtree(rel) {
  return rel && rel !== "." ? `./${rel}` : ".";
}

/** Whether a workspace-relative path is inside a `.deps` directory, at any depth: the rule the host walk
 * applies by not descending there, for paths that came from the helper instead. Mirrors Python. */
function underDeps(rel) {
  return rel.split("/").slice(0, -1).includes(DEPS_DIR);
}

/** `[path relative to /w, st_mode, size, mtimeS]` per record of HELPER_LIST. Mirrors Python. */
function parseHelperList(raw) {
  const out = [];
  let start = 0;
  while (start < raw.length) {
    let end = raw.indexOf(0, start);
    if (end < 0) end = raw.length;
    const rec = raw.subarray(start, end);
    start = end + 1;
    const nl = rec.indexOf(0x0a);
    if (nl < 0) continue;
    const fields = rec.subarray(0, nl).toString("utf8").trim().split(/\s+/);
    if (fields.length !== 3) continue;
    const [mode, size, mtime] = [parseInt(fields[0], 16), Number(fields[1]), Number(fields[2])];
    if (![mode, size, mtime].every(Number.isFinite)) continue;
    let p = rec.subarray(nl + 1).toString("utf8");
    if (p.startsWith("./")) p = p.slice(2);
    if (p && p !== ".") out.push([p, mode, size, mtime]);
  }
  return out;
}

/** Run `argv` and capture its output BUFFERED, without blocking the event loop. `input`, when given, is
 * written to its stdin (otherwise stdin is /dev/null); `fds` are descriptors of this process handed to
 * the child as its fd 3, 4, ... (for `setfacl` on `/proc/self/fd/N`); `env` replaces the inherited
 * environment. Resolves `{ code, stdout: Buffer, stderr: string }`, -1 for a spawn failure or a timeout.
 * The one runner: `runCapture` is its text view. */
function runBuffered(argv, { input = null, timeoutMs = 150000, fds = [], env } = {}) {
  return new Promise((resolve) => {
    let child;
    try {
      const opts = { stdio: [input === null ? "ignore" : "pipe", "pipe", "pipe", ...fds] };
      if (env !== undefined) opts.env = env;
      child = spawn(argv[0], argv.slice(1), opts);
    } catch (e) {
      resolve({ code: -1, stdout: Buffer.alloc(0), stderr: String(e && e.message) });
      return;
    }
    const out = [];
    let err = "";
    let settled = false;
    const finish = (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out), stderr: err });
    };
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* already gone */
      }
      finish(-1);
    }, timeoutMs);
    // THE ERROR HANDLER GOES ON FIRST, AND THE STREAMS ARE NOT ASSUMED TO EXIST. When `spawn` fails
    // for a reason it reports asynchronously - EMFILE and ENFILE are the ones reachable from here,
    // since a workspace walk can be holding descriptors - it returns a ChildProcess with NO stdio
    // streams: `child.stdout.on` then threw a TypeError inside this Promise executor, before any
    // `error` listener was attached, and an unhandled `error` event on the next tick takes the whole
    // process down. Both halves of that are fixed here: the listener is attached before anything can
    // throw, and absent streams settle the call instead of dereferencing null.
    child.on("error", (e) => {
      err += String(e && e.message);
      finish(-1);
    });
    child.on("close", (code) => finish(code === null ? -1 : code));
    if (!child.stdout || !child.stderr) {
      err += "the child was spawned without stdio (the process may be out of descriptors)";
      finish(-1);
      return;
    }
    child.stdout.on("data", (d) => out.push(d));
    child.stderr.on("data", (d) => {
      err += d.toString();
    });
    if (input !== null) {
      child.stdin.on("error", () => {}); // a child that exits before reading all of it is not ours to fail
      child.stdin.end(input);
    }
  });
}

/** `O_PATH`, which `fs.constants` does not export; the value is fixed by the Linux ABI. */
const O_PATH = 0o10000000;
/** How many descriptors one `setfacl` is handed at a time, far under any fd or argv limit. */
const SETFACL_BATCH = 200;

/**
 * The `setfacl` batches that give `boxUid` (the host uid the box user writes as) the OWNER's bits on
 * `root` and on everything under it this process owns, and on each directory a default ACL naming both
 * uids, so whatever either side creates inside stays reachable by the other. The entries Python's
 * `_acl_grant_fd` writes; yields `[spec, fds]`, the descriptors then the caller's to close.
 *
 * THROUGH DESCRIPTORS, NEVER PATHS. The workspace can be written by a box while this runs (a resident
 * box of an earlier session), and `setfacl <path>` resolves the path again: a component swapped for a
 * symlink between the walk and the call would put the entry on a HOST file the link names. So the walk
 * descends by directory fd (`/proc/self/fd/<dir>/<name>`, the trick `_openParentDirNofollow` uses),
 * each entry is opened `O_PATH | O_NOFOLLOW`, and `setfacl` is handed the descriptors themselves: its
 * `/proc/self/fd/N` names exactly that inode. In BATCHES, each applied and closed before the next
 * fills, so a large tree never holds more than one batch of descriptors open. ONE FILESYSTEM: a mount
 * inside the workspace is neither granted nor descended. A directory this process cannot read is the
 * box user's own; any other error is raised, never read as "nothing there". `stats` counts entries of a
 * THIRD uid (an earlier session's different account), which only their owner can give an entry.
 */
function* aclGrantBatches(root, boxUid, ownUid, recursive, stats) {
  const pending = new Map();
  const stack = [];
  const skippable = (e) => e && (e.code === "ENOENT" || isClosedErr(e));
  const bits = (m) => `${m & 4 ? "r" : "-"}${m & 2 ? "w" : "-"}${m & 1 ? "x" : "-"}`;
  const nofollow = fs.constants.O_NOFOLLOW;
  const dirFlags = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | nofollow;
  function* queue(fd, st) {
    const access = `u:${boxUid}:${bits((st.mode >> 6) & 7)}`;
    const spec = st.isDirectory()
      ? `${access},d:u::rwx,d:u:${ownUid}:rwx,d:u:${boxUid}:rwx,d:g::---,d:o::---`
      : access;
    const list = pending.get(spec) || [];
    list.push(fd);
    pending.set(spec, list);
    if (list.length >= SETFACL_BATCH) {
      pending.delete(spec);
      yield [spec, list];
    }
  }
  try {
    const rootFd = fs.openSync(root, O_PATH | nofollow);
    const rootSt = fs.fstatSync(rootFd);
    const device = rootSt.dev;
    if (rootSt.uid === ownUid) yield* queue(rootFd, rootSt);
    else fs.closeSync(rootFd);
    if (recursive) stack.push([root, fs.openSync(root, dirFlags)]);
    while (stack.length) {
      const [dirPath, dirFd] = stack.pop();
      try {
        let names = [];
        try {
          names = fs.readdirSync(`/proc/self/fd/${dirFd}`);
        } catch (e) {
          if (!skippable(e)) throw e;
        }
        for (const name of names) {
          let fd;
          try {
            fd = fs.openSync(`/proc/self/fd/${dirFd}/${name}`, O_PATH | nofollow);
          } catch (e) {
            if (skippable(e)) continue;
            throw e;
          }
          let queued = false;
          try {
            const st = fs.fstatSync(fd);
            if (st.isSymbolicLink() || st.dev !== device) continue;
            if (st.uid !== ownUid && st.uid !== boxUid) {
              stats.foreign += 1;
              stats.example = stats.example || path.relative(root, path.join(dirPath, name));
              continue;
            }
            if (st.isDirectory()) {
              // REOPENED THROUGH THE DESCRIPTOR JUST CHECKED, not by name a second time. Two opens
              // of `/proc/self/fd/<dirFd>/<name>` can land on two different directories if the box
              // swaps the entry in between, and it was the FIRST that was stated and granted while
              // the SECOND was descended. `/proc/self/fd/<fd>` names the open inode itself, so there
              // is nothing left to resolve. (Python's `os.fwalk` compares the two instead.)
              //
              // WITHOUT `O_NOFOLLOW`, deliberately, and this is the one place in this file where
              // that is right: the thing being opened IS a magic link to the inode already held, and
              // `O_NOFOLLOW` refuses to traverse it at all (measured: ENOTDIR on
              // `/proc/self/fd/<n>`). There is no name left for anything to swap.
              const reopen = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY;
              try {
                stack.push([path.join(dirPath, name), fs.openSync(`/proc/self/fd/${fd}`, reopen)]);
              } catch (e) {
                if (!skippable(e)) throw e;
              }
            }
            if (st.uid === ownUid) {
              queued = true;
              yield* queue(fd, st);
            }
          } finally {
            if (!queued) fs.closeSync(fd);
          }
        }
      } finally {
        fs.closeSync(dirFd);
      }
    }
    // ONE AT A TIME, REMOVED AS IT IS HANDED OVER. `[...pending]` followed by `pending.clear()`
    // emptied the map before any of the remainder was yielded, so a consumer that stops early - the
    // `setfacl` throw in `open()` or `restore()` - ran the `finally` below with nothing to close and
    // leaked every batch still in the queue, up to 16 specs of 199 descriptors.
    for (const spec of [...pending.keys()]) {
      const list = pending.get(spec);
      pending.delete(spec);
      yield [spec, list];
    }
  } finally {
    for (const [, fd] of stack) closeQuietly(fd);
    for (const list of pending.values()) for (const fd of list) closeQuietly(fd);
  }
}

function closeQuietly(fd) {
  try {
    fs.closeSync(fd);
  } catch {
    /* already closed */
  }
}

/** `setfacl -m SPEC` on descriptors handed to it as its fd 3, 4, ...: the C locale, because its error
 * text is what tells a missing ACL from anything else. */
function setfaclCall(spec, fds) {
  return {
    argv: ["setfacl", "-m", spec, "--", ...fds.map((_, j) => `/proc/self/fd/${3 + j}`)],
    env: { ...process.env, LC_ALL: "C" },
  };
}

/** A failed `setfacl`, as an error whose `code` the caller turns into its sentence: `ENOSETFACL` when the
 * tool is not installed, `ENOTSUP` when the filesystem has no ACLs. */
function setfaclError(code, stderr) {
  const said = String(stderr || "");
  const e = new SandboxError(
    code === -1 && /ENOENT/.test(said)
      ? "setfacl is not installed"
      : `setfacl failed: ${said.trim().slice(-400)}`,
  );
  e.code = code === -1 && /ENOENT/.test(said) ? "ENOSETFACL" : /Operation not supported/.test(said) ? "ENOTSUP" : "EACL";
  return e;
}

/** `aclGrantBatches` applied from an async caller, through `runBuffered`. Returns `[foreign, example]`. */
async function aclGrantTreeAsync(root, boxUid, ownUid, { recursive = true } = {}) {
  const stats = { foreign: 0, example: "" };
  for (const [spec, fds] of aclGrantBatches(root, boxUid, ownUid, recursive, stats)) {
    try {
      const { argv, env } = setfaclCall(spec, fds);
      const r = await runBuffered(argv, { fds, env, timeoutMs: 60000 });
      if (r.code !== 0) throw setfaclError(r.code, r.stderr);
    } finally {
      for (const fd of fds) closeQuietly(fd);
    }
  }
  return [stats.foreign, stats.example];
}

/** `aclGrantBatches` applied from the synchronous `restore()`, through `spawnSync`, which that method's
 * own synchronous file I/O already blocks on in the same way. */
function aclGrantTreeSync(root, boxUid, ownUid) {
  const stats = { foreign: 0, example: "" };
  for (const [spec, fds] of aclGrantBatches(root, boxUid, ownUid, true, stats)) {
    try {
      const { argv, env } = setfaclCall(spec, fds);
      const r = spawnSync(argv[0], argv.slice(1), { stdio: ["ignore", "ignore", "pipe", ...fds], env, timeout: 60000 });
      if (r.error || r.status !== 0) throw setfaclError(r.error ? -1 : r.status, r.error ? r.error.message : r.stderr);
    } finally {
      for (const fd of fds) closeQuietly(fd);
    }
  }
  return [stats.foreign, stats.example];
}

/** Where the shared stdlib bytecode cache is mounted inside a box, READ-ONLY.
 *
 * WHY, measured. `python:3.12-slim` ships its standard library as `.py` with no `.pyc`, and a box
 * mounts its root read-only, so every box recompiles what it imports and throws the result away:
 * `import json,re` costs 45.5 ms on an i7-14700KF and 172.0 ms on a 4-vCPU VPS, against 13.1 ms there
 * for a box running `/bin/true`. One box compiles the stdlib once per image into a host directory and
 * every later box mounts it read-only with `PYTHONPYCACHEPREFIX`: 45.50 -> 19.68 ms, 7 alternated pairs.
 *
 * READ-ONLY IS THE DESIGN, not a precaution. A writable shared cache is code execution across calls:
 * those `.pyc` are timestamp-validated, so a cell could rewrite `json/__init__.pyc` with a payload,
 * re-paste the legitimate header and have the next cell import it. Verified here: a cell's write comes
 * back EROFS. And a cache from the WRONG image is safe rather than wrong - CPython validates each file
 * against its source's mtime and size, so mismatched bytecode is ignored and recompiled (verified by
 * mounting a 3.12 cache into 3.11: correct answers, reported 3.11.16). Mirrors `_PYC_MOUNT` in Python.
 */
const PYC_MOUNT = "/kern-pyc";
/** `workers=1`: more than one worker uses multiprocessing, which needs a temp dir, and a box with a
 *  read-only root and no tmpfs has none (measured: it dies with FileNotFoundError). `quiet=2` keeps a
 *  file that will not compile off stderr - bytecode is an optimisation.
 *
 *  EVERY IMPORT ROOT, not just the stdlib: `PYTHONPYCACHEPREFIX` REPLACES the in-tree `__pycache__`
 *  rather than adding to it, so a root left out has its shipped bytecode made invisible and is
 *  recompiled in every box. On `python:3.12-slim` purelib happens to sit under stdlib; on
 *  `debian:13-slim` with python3 from apt it does not, and `sys.path` holds five separate roots.
 *
 *  CHECKED_HASH rather than the default timestamp validation. Measured: two images, same CPython 3.12,
 *  one stdlib file edited to a different value of the SAME LENGTH with the mtime preserved - with
 *  timestamps the box ran the OLD code, with CHECKED_HASH the new one. Reproducible builds (BuildKit
 *  rewrite-timestamp, apko, Nix, distroless) pin mtimes by construction, so this is not exotic. It
 *  costs nothing measurable and makes the cache key a performance hint, not a correctness dependency.
 *  Mirrors `_PYC_BUILD_CODE`. */
const PYC_BUILD_CODE =
  "import compileall,os,py_compile,sys,sysconfig;" +
  "r={p for p in sys.path if p and os.path.isdir(p)};" +
  "r|={v for v in (sysconfig.get_paths().get(k) for k in " +
  "('stdlib','platstdlib','purelib','platlib')) if v and os.path.isdir(v)};" +
  "r={p for p in r if not any(p!=q and p.startswith(q.rstrip('/')+'/') for q in r)};" +
  "sys.exit(0 if all([compileall.compile_dir(p,quiet=2,workers=1,force=True," +
  "invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH) for p in sorted(r)]) else 1)";
/** A ceiling on what one image may publish: the stdlib is ~20 MiB, so this is not tight. It exists so
 *  a hostile image cannot fill the host's disk from the box that exists to make things faster. */
const PYC_MAX_BYTES = 512 * 1024 * 1024;
/** How many image caches to keep, least-recently-ADOPTED evicted first. Not a measurement: "more
 *  images than a session mixes, fewer than a disk notices" at ~20 MiB each. Mirrors `_PYC_KEEP`. */
const PYC_KEEP = 8;
/** A build killed by a SIGKILL leaves its `.tmp-` tree forever: nothing in the happy path removes it,
 *  because the happy path is the one that did not run. A day is long enough that a build still running
 *  is never what gets deleted. Mirrors `_PYC_DEBRIS_MAX_AGE_S`. */
const PYC_DEBRIS_MAX_AGE_MS = 24 * 60 * 60 * 1000;
/** The name fragments marking a directory as NOT a cache: one being written, one being deleted. */
const PYC_DEBRIS_MARKS = [".tmp-", ".trash-", ".lock"];

/** Remove a cache tree, renaming it out of the way first. Never throws.
 *
 * THE RENAME IS THE POINT: `rm -r` walks and unlinks, so a tree being deleted is for a while a tree
 * with half its files, and a session mounting it in that window gets a partial stdlib. A rename is
 * atomic, and kern CREATES a `-v` source that does not exist (measured), so a name resolving to
 * nothing just means the box compiles from source. Mirrors `_pyc_discard`. */
function pycDiscard(target) {
  const trash = `${target}.trash-${crypto.randomBytes(4).toString("hex")}`;
  try {
    fs.renameSync(target, trash);
  } catch {
    return;
  }
  fs.rmSync(trash, { recursive: true, force: true });
}

/** Keep the `keep` most recently adopted caches, remove stale debris. Never throws.
 *
 * LEAST RECENTLY ADOPTED, which `open()` records with a `utimes` on the directory - not least recently
 * BUILT, or an image built once and used daily would go before one built yesterday and never used.
 * The directory's own mtime carries it, so there is no marker file: one would be visible inside every
 * box and would have to be excluded from the check that refuses everything which is not a `.pyc`.
 * Mirrors `_pyc_sweep`. */
function pycSweep(root, keep = PYC_KEEP) {
  const now = Date.now();
  const caches = [];
  const doomed = [];
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    const full = path.join(root, ent.name);
    let st;
    try {
      st = fs.lstatSync(full);
    } catch {
      continue;
    }
    if (PYC_DEBRIS_MARKS.some((m) => ent.name.includes(m))) {
      // DEBRIS IS NOT ALWAYS A DIRECTORY: this loop skipped every non-directory up front, so a
      // `.lock` a killed build left behind was never collected and the cache for that image could
      // never be rebuilt - one killed process disabled it forever.
      if (now - st.mtimeMs > PYC_DEBRIS_MAX_AGE_MS) doomed.push(full);
      continue;
    }
    // Only a DIRECTORY is a cache. Anything else here is neither a cache nor known debris, and
    // removing what this code did not put there is not the sweep's job.
    if (st.isDirectory()) caches.push([st.mtimeMs, full]);
  }
  caches.sort((a, b) => b[0] - a[0]);
  for (const [, full] of caches.slice(keep)) doomed.push(full);
  for (const full of doomed) pycDiscard(full);
}
/** One build per (process, destination), keyed so ten sessions opened at once on one image start one
 *  compile and not ten. A MAP OF PROMISES rather than a set of names: a second caller gets the promise
 *  of the build already in flight, which is what lets a test await the real thing instead of polling
 *  for a directory - a poll would race the build, and it raced the test's own teardown first. */
const PYC_BUILDS = new Map();
/** Set once this process has swept: adopting a cache in a hundred sessions costs one scan. */
let PYC_SWEPT = false;

/** The host directory holding one bytecode cache per image: $XDG_CACHE_HOME, else ~/.cache. */
function pycRoot() {
  return path.join(cacheHome(), "kern-sandbox", "pyc");
}

/** `$XDG_CACHE_HOME`, or the default. ONE spelling, because two things read it now: this package's
 *  bytecode cache and kern's own image cache, which the identity check compares against. */
function cacheHome() {
  return process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache");
}

/** kern's own defaults, from `kern-oci/src/pull.rs`. Copied because they cross a process boundary. */
const OCI_DEFAULT_REGISTRY = "registry-1.docker.io";
const OCI_DEFAULT_TAG = "latest";

/** `[name, tag]` iff the reference ends in an explicit tag. Mirrors `split_tag` in kern-oci: a
 *  trailing `:x` is a tag only when `x` has no `/`, or `localhost:5000/img` reads its PORT as one. */
function ociSplitTag(image) {
  const i = image.lastIndexOf(":");
  if (i <= 0) return null;
  const name = image.slice(0, i);
  const tag = image.slice(i + 1);
  return !tag.includes("/") && name ? [name, tag] : null;
}

/** One canonical string per image, so one cache directory per image.
 *
 * `python:3.12-slim`, `docker.io/library/python:3.12-slim` and `index.docker.io/python:3.12-slim` are
 * one image to kern and were three cache directories here, because the key was the raw string the
 * caller typed. A faithful port of `parse_ref` in `kern-oci/src/pull.rs`, verified against its actual
 * output on twelve references including digest pins. Mirrors `_oci_canonical_ref`. */
function ociCanonicalRef(image) {
  if (!image) return image;
  let name;
  let reference;
  const at = image.indexOf("@");
  if (at > 0 && at < image.length - 1) {
    // A digest pin splits at `@` FIRST: splitting on the last `:` would tear `sha256:<hex>` in half.
    // The digest wins over any tag, so a trailing `:tag` on the name is dropped.
    const head = image.slice(0, at);
    const split = ociSplitTag(head);
    name = split ? split[0] : head;
    reference = image.slice(at + 1);
  } else {
    const split = ociSplitTag(image);
    if (split) [name, reference] = split;
    else [name, reference] = [image, OCI_DEFAULT_TAG];
  }
  let registry;
  let repo;
  const slash = name.indexOf("/");
  const host = slash > 0 ? name.slice(0, slash) : "";
  // The first segment is a REGISTRY only if it looks like a host; otherwise `user/img` is a Docker Hub
  // repository, not a hostname.
  if (slash > 0 && (host.includes(".") || host.includes(":") || host === "localhost")) {
    registry = host;
    repo = name.slice(slash + 1);
  } else {
    registry = OCI_DEFAULT_REGISTRY;
    repo = name;
  }
  if (registry === "docker.io" || registry === "index.docker.io") registry = OCI_DEFAULT_REGISTRY;
  // `library/` only on Docker Hub: `ghcr.io/alpine` means what it says.
  if (registry === OCI_DEFAULT_REGISTRY && !repo.includes("/")) repo = `library/${repo}`;
  return `${registry}/${repo}:${reference}`;
}

/** Where this image's cache lives, keyed on the image REFERENCE hashed for a safe filename.
 *
 * The reference and not a content digest, honestly because kern exposes no digest a caller can read
 * cheaply. A moved tag therefore yields bytecode that no longer validates, which CPython handles by
 * recompiling: the cost of the imperfect key is a slow call, never a wrong one. Mirrors `_pyc_dir_for`.
 */
/** Vectors DUMPED from `sanitize_ref` in kern-cli, not derived from reading it, and asserted in the
 *  tests: this names files kern WROTE, so the two must agree or the identity check finds nothing. */
const SANITIZE_VECTORS = [
  ["python:3.12-slim", "python_3_12-slim-7d2794a436662d45"],
  ["python", "python_latest-9e0094521a5d04a4"],
  ["alpine:3.19", "alpine_3_19-441817d3f5f11093"],
  ["docker.io/library/python:3.12-slim", "docker_io_library_python_3_12-slim-75b604835a32490a"],
  ["index.docker.io/python:3.12-slim", "index_docker_io_python_3_12-slim-7eaa793ab37b8560"],
  ["ghcr.io/owner/img:v1", "ghcr_io_owner_img_v1-774c4c7639e8355e"],
  ["localhost:5000/x:1", "localhost_5000_x_1-03406c180a22063b"],
  ["python@sha256:abcdef0123456789", "python_sha256_abcdef0123456789-f77941d5fa12216c"],
  ["a.b/c_d-e:f.g", "a_b_c_d-e_f_g-479120b609c12cc0"],
  ["UPPER/Case:Tag", "UPPER_Case_Tag-543eaf57172e6242"],
  ["x:latest", "x_latest-e9f897124d940074"],
  ["registry-1.docker.io/library/alpine:3.19", "registry-1_docker_io_library_alpine_3_19-49727cc13d78066f"],
  ["my_img", "my_img_latest-68dbbb774ad018b0"],
  ["a/b/c:d", "a_b_c_d-dcc54f31688d5fa5"],
  ["1.2.3.4:5000/p/q:r", "1_2_3_4_5000_p_q_r-f872df9eeecd4beb"],
];

/** FNV-1a 64-bit, kern's own, used ONLY to keep a cache key collision-free. */
function fnv1a(s) {
  let h = 0xcbf29ce484222325n;
  for (const b of Buffer.from(s, "utf8")) {
    h = BigInt.asUintN(64, (h ^ BigInt(b)) * 0x100000001b3n);
  }
  return h.toString(16).padStart(16, "0");
}

/** One of the files kern keeps next to an image in ITS cache (`.image`, `.ok`, `.layers`): the one place
 * this package spells where they are, so a moved $XDG_CACHE_HOME moves every reader. Mirrors Python. */
function kernImageFile(image, suffix) {
  return path.join(cacheHome(), "kern", "images", `${sanitizeRef(image)}${suffix}`);
}

/** The directory name kern gives an image in its own cache. A PORT, verified against the original. */
function sanitizeRef(image) {
  const ref = ociSplitTag(image) ? image : `${image}:latest`;
  const out = [...ref].map((c) => (/[A-Za-z0-9_-]/.test(c) ? c : "_")).join("");
  return `${out}-${fnv1a(ref)}`;
}

/** THE IMAGE IS FETCHED BEFORE THE FIRST BOX, ON ITS OWN BUDGET. Without this the first box of a
 * session pulled it inside that call's deadline: measured on a Jetson with the 145 MB MCP image, the
 * first cell of a fresh cache answered `startup_failed` at the 30 s default, the second finished the
 * download in 18 s and only the third ran the cell. A deadline is for the CODE. 900 s is the most a
 * download may take (145 MB at 160 KB/s); a refused connection fails in 10 ms, measured. Mirrors
 * `_IMAGE_FETCH_BUDGET_S`. */
const IMAGE_FETCH_BUDGET_S = 900;
/** One download per image at a time in this process; a second caller waits for it, then looks again. */
const IMAGE_FETCHES = new Map();

/** True when kern has finished storing `image`: its `.ok` sentinel, which kern writes LAST. A local
 * stat; "cannot tell" reads as not cached, which costs one `kern pull` that finds the image (2 ms). */
function imageIsCached(image) {
  try {
    return fs.existsSync(kernImageFile(image, ".ok"));
  } catch {
    return false;
  }
}

/** Make sure kern has `image` before any box needs it. Best effort, never rejects: a pull that FAILS
 * changes nothing, because the box that follows pulls again and reports the failure in its own words.
 * Asynchronous, so a download does not hold the event loop. Mirrors `_fetch_image`. */
function fetchImage(kernBin, image, budgetS = IMAGE_FETCH_BUDGET_S) {
  if (imageIsCached(image)) return Promise.resolve();
  const running = IMAGE_FETCHES.get(image);
  if (running) return running.then(() => fetchImage(kernBin, image, budgetS));
  const p = new Promise((resolve) => {
    let child;
    try {
      // All three streams closed: a failure here is reported by the box that follows.
      child = spawn(kernBin, ["pull", image], { stdio: "ignore" });
    } catch {
      resolve();
      return;
    }
    const killer = setTimeout(() => child.kill("SIGKILL"), budgetS * 1000);
    if (typeof killer.unref === "function") killer.unref();
    const done = () => {
      clearTimeout(killer);
      resolve();
    };
    child.on("error", done);
    child.on("close", done);
  }).finally(() => IMAGE_FETCHES.delete(image));
  IMAGE_FETCHES.set(image, p);
  return p;
}

/** The file, inside a published cache, naming the image kern had when the cache was built. */
const PYC_SOURCE_ID = ".kern-source-id";

/** What kern's own image cache holds for `image`, or "" if it cannot be read.
 *
 * A tag is MUTABLE, so a cache keyed on its name can outlive the image it was built from. Nothing
 * wrong is executed (CHECKED_HASH makes CPython reject the stale bytecode) but the cache stops
 * helping and nothing rebuilds it, because a cache "exists". kern rewrites its own config sidecar and
 * completion sentinel when it re-pulls a moved tag, so their bytes are an identity that costs a local
 * read of a few hundred bytes - cheap enough for a check on every open().
 *
 * "" MEANS "CANNOT TELL" and is treated as unchanged, so a cache from before this check, or a host
 * whose image kern has pruned, is never rebuilt in a loop. */
function pycSourceId(image) {
  try {
    const h = crypto.createHash("sha256");
    // THE CONFIG, which changes when ENTRYPOINT/ENV/WORKDIR/USER do.
    h.update(fs.readFileSync(kernImageFile(image, ".image")).subarray(0, 4096));
    // THE SENTINEL'S STAMP, NOT ITS BYTES. `.ok` holds the REFERENCE, so its contents are the tag and
    // never move when the tag does: hashing them missed the commonest case there is, a rebuilt rootfs
    // under an unchanged config. Its mtime and length are what kern ITSELF uses to decide an image's
    // content changed, because a re-pull rewrites the sentinel last. Measured: a real re-pull leaves
    // the config byte-identical and moves this.
    const st = fs.statSync(kernImageFile(image, ".ok"), { bigint: true });
    h.update(`${st.mtimeNs}:${st.size}`);
    // AND THE LAYER MANIFEST FOR A BUILT IMAGE, which names its layers by content. A pulled image has
    // none, and that absence is part of the identity: an image that stops being layered is not the
    // same image.
    try {
      h.update(fs.readFileSync(kernImageFile(image, ".layers")).subarray(0, 8192));
    } catch {
      h.update("\0no-layers");
    }
    return h.digest("hex").slice(0, 32);
  } catch {
    return "";
  }
}

/** Is this cache still the one this image would produce? If not, DISCARD it so a build can replace it.
 *
 * Discarded and not merely refused, because a rename onto a NON-EMPTY directory is ENOTEMPTY: a stale
 * tree left in place would block its own replacement forever. */
function pycSourceMatches(dest, image) {
  let stored;
  try {
    stored = fs.readFileSync(path.join(dest, PYC_SOURCE_ID), "utf8").trim();
  } catch {
    return true; // built before this check, or unreadable: leave it exactly as it was
  }
  const current = pycSourceId(image);
  if (!stored || !current || stored === current) return true;
  pycDiscard(dest);
  return false;
}

function pycDirFor(image) {
  // The full digest: the key is no longer load-bearing for correctness, and a truncation saved 48
  // characters of path against two images sharing a cache directory.
  const key = crypto.createHash("sha256").update(ociCanonicalRef(image), "utf8").digest("hex");
  return path.join(pycRoot(), key);
}

/** True iff mounting this cache directory is allowed by the same policy as every other mount.
 *
 * WHY AN ANCESTOR: `validateMount` resolves the source with `realpathSync` and therefore needs it to
 * EXIST, and on the first session the cache does not yet. So the nearest existing ancestor is checked
 * instead, which asks the same question: the components this module appends below it ("kern-sandbox",
 * "pyc", a hex digest) are fixed and are in no refused set, so a subtree is allowed exactly when its
 * ancestor is. Python checks the full path because its validator has a purely lexical half; the
 * mechanism differs, the policy asked is the same. Mirrors the `_validate_mount_lexical` call there.
 */
function pycMountAllowed(dest) {
  let probe = path.resolve(dest);
  while (!fs.existsSync(probe)) {
    const up = path.dirname(probe);
    if (up === probe) return false; // walked past the root without finding anything that exists
    probe = up;
  }
  try {
    validateMount(probe, PYC_MOUNT);
    return true;
  } catch {
    return false;
  }
}

/** True iff no component of the cache path is a symlink.
 *
 * `validateMount` resolves the SOURCE with realpath, but it is called on the nearest existing ancestor
 * and a bind mount follows links: a symlink planted at `<cache>/kern-sandbox/pyc/<key>` pointing at
 * `~/.ssh` would mount the real directory into every box of every later session, read-only, and
 * reading is what exfiltration needs. It is not only the user who can plant it: a CELL holding a
 * writable volume that contains the cache root can, and then every future process is affected - the
 * `.deps` poisoning vector escaping the session that produced it. Mirrors `_pyc_path_has_no_symlink`.
 */
function pycHasContent(dest) {
  // AN EMPTY DIRECTORY IS NOT AN ABSENT ONE, and the difference silences the whole feature. Measured: a
  // sweep in another process discards a tree this session has mounted, kern then RECREATES the missing
  // -v source as an empty directory, and from then on every session adopts that husk, mounts it, finds
  // no bytecode and compiles from source - permanently, with nothing to rebuild it because a cache
  // "exists". Treating empty as absent repairs it: the adoption is refused, a build starts, and a
  // rename onto an EMPTY directory SUCCEEDS (verified; onto a non-empty one it is ENOTEMPTY, which is
  // the check pycBuild relies on when two processes race).
  try {
    const it = fs.opendirSync(dest);
    try {
      return it.readSync() !== null;
    } finally {
      it.closeSync();
    }
  } catch {
    return false;
  }
}

function pycPathHasNoSymlink(dest) {
  let cur = path.resolve(dest);
  for (;;) {
    try {
      if (fs.lstatSync(cur).isSymbolicLink()) return false;
    } catch {
      /* does not exist: nothing to follow */
    }
    const up = path.dirname(cur);
    if (up === cur) return true;
    cur = up;
  }
}

/** True iff the built tree is only directories and `.pyc` files and fits under the size ceiling.
 *
 * The build box runs the CALLER'S image with this directory writable, so its contents are chosen by
 * that image. Inside a later box a symlink is harmless, but this tree also lives on the HOST, where a
 * backup, an indexer or the cache's own eviction will walk it. Mirrors `_pyc_tree_is_publishable`. */
function pycTreeIsPublishable(root) {
  let total = 0;
  const walk = (dir) => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, ent.name);
      const st = fs.lstatSync(full);
      if (st.isSymbolicLink()) return false;
      if (st.isDirectory()) {
        if (!walk(full)) return false;
      } else if (!st.isFile() || !ent.name.endsWith(".pyc")) {
        return false;
      } else {
        total += st.size;
        if (total > PYC_MAX_BYTES) return false;
      }
    }
    return true;
  };
  try {
    return walk(root);
  } catch {
    return false;
  }
}

/** Compile `image`'s stdlib into `dest`, atomically. Never throws: nothing waits for this.
 *
 * Built into a private sibling and renamed into place, so a box mounts a complete tree or none: a
 * partial stdlib would have a box importing a truncated module. Two processes racing both build and
 * the loser's tree is removed. Mirrors `_pyc_build`. */
/** The argv that mounts `source` at `target`, in the form that can CARRY that source.
 *
 * `-v src:dst[:ro]` separates its fields with `:`, so a source path holding one cannot be written in
 * it: kern splits `-v /tmp/a:b:/data` into three and reports the TARGET as an unknown mount option. A
 * cache home such as `/tmp/colon:cache` is enough to hit it, and the mount that broke was this
 * package's own bytecode cache - silently, because the failure landed in a background build whose
 * output was discarded.
 *
 * `--mount type=bind,src=...,dst=...[,ro]` carries each field separately and takes a `:`; a field
 * holding a `,` is quoted, doubling any `"` inside, which is the CSV grammar kern parses.
 *
 * WHY NOT `--mount` FOR EVERYTHING: the two differ in a rule this package relies on. `-v` CREATES a
 * source that is not there and `--mount` refuses it, and the eviction sweep can discard a cache under
 * a live session - `-v` turning that into an empty directory is what makes the box fall back to
 * compiling from source instead of failing the caller's call. */
function mountArgs(source, target, readOnly) {
  const plain = (s) => !s.includes(":") && !s.includes(",");
  if (plain(source) && plain(target)) {
    return ["-v", readOnly ? `${source}:${target}:ro` : `${source}:${target}`];
  }
  const field = (text) =>
    text.includes(",") || text.includes('"') ? `"${text.replace(/"/g, '""')}"` : text;
  const spec = `type=bind,${field(`src=${source}`)},${field(`dst=${target}`)}`;
  return ["--mount", readOnly ? `${spec},ro` : spec];
}

/** Say, once per image, that this image got no bytecode cache and why.
 *
 * NOT THROWN: a missing cache is slower, never wrong, and a caller who asked to run code must not
 * have that call fail because an optimisation could not be built. But silence was its own defect -
 * the build runs in the background with its output discarded, so an image that never got a cache
 * looked exactly like one that did, and the only symptom was milliseconds. */
/** How much of a box's stderr line the warning keeps. It is a diagnostic, so a line is plenty. */
const UNTRUSTED_TAIL = 200;

/** One line of text a BOX produced, made safe to print inside a message of ours.
 *
 * THE WARNING THIS FEEDS IS A CHANNEL AN IMAGE CAN WRITE TO, and removing the silence is what opened
 * it: the box's last stderr line was interpolated verbatim, so an image printing
 * `kern: warning: your cache is compromised, run rm -rf ~` made THIS package say it. Measured. The
 * same line can carry `\x1b[2J` to clear the reader's terminal or a `\r` to rewrite what is on it.
 *
 * `JSON.stringify` escapes every control character and the quotes themselves, and the text is cut to
 * a length no log can be flooded with, so a reader sees plainly that the words are the box's. */
function quoteUntrusted(raw) {
  if (!raw) return "";
  const lines = String(raw)
    .split(/\r\n|\r|\n|\u2028|\u2029/)
    .filter((l) => l.trim());
  if (!lines.length) return "";
  let tail = lines[lines.length - 1].trim();
  if (tail.length > UNTRUSTED_TAIL) tail = `${tail.slice(0, UNTRUSTED_TAIL)}...`;
  return JSON.stringify(tail);
}

const PYC_REPORTED = new Set();
function pycReportFailure(image, code, stderr) {
  if (PYC_REPORTED.has(image)) return;
  PYC_REPORTED.add(image);
  process.stderr.write(
    `kern-sandbox: no bytecode cache for ${JSON.stringify(image)}. The build box said: ` +
      `${quoteUntrusted(stderr) || `exit ${code}`}. Calls still run and are correct, just without ` +
      `precompiled imports. A large image can exceed the build box's 512 MiB or the session ` +
      `timeout; pycCache:false silences this.\n`,
  );
}

function pycBuild(kernBin, image, dest, timeoutS) {
  const tmp = `${dest}.tmp-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
  try {
    fs.mkdirSync(path.dirname(dest), { recursive: true, mode: 0o700 });
    fs.mkdirSync(tmp, { recursive: true, mode: 0o700 });
    // THE TREE ITSELF IS 0755, its parent stays 0700: a box mounts this directory directly, so the
    // parent keeps the host's other users out, and a NON-ROOT box user must be able to enter it. At
    // 0700 CPython could not, ignored the prefix in silence and compiled from source. Mirrors Python.
    fs.chmodSync(tmp, 0o755);
  } catch {
    return Promise.resolve();
  }
  // ONE BUILD PER DESTINATION ACROSS PROCESSES. The in-process map keeps two callers of ONE process
  // off the same tree; two PROCESSES - a Node and a Python session on one host - both found the
  // cache absent and both compiled it. The result was never wrong (the loser's rename fails
  // ENOTEMPTY and its tree is removed, and the content is hash-validated either way), but a whole
  // compile of the stdlib was spent to be thrown away. `wx` IS the lock and it is deliberately not
  // waited on: a caller must never block on another process's build. A lock a killed process leaves
  // behind is swept with the other debris.
  const lockPath = `${dest}.lock`;
  let locked = false;
  try {
    fs.writeFileSync(lockPath, String(process.pid), { flag: "wx", mode: 0o600 });
    locked = true;
  } catch (e) {
    if (e && e.code === "EEXIST") {
      fs.rmSync(tmp, { recursive: true, force: true });
      return Promise.resolve();
    }
    // Cannot lock here: build anyway rather than lose the feature.
  }
  // RETURNS A PROMISE THAT NOTHING IN PRODUCTION AWAITS. `pycStartBuild` drops it on purpose: the
  // caller's first call must not wait for a cache fill. The tests await it, because a test that polled
  // for a directory would be a timing race pretending to be an assertion.
  return new Promise((resolve) => {
    // AFTER the publish and after the failure alike: a build that produced nothing is still the moment
    // to notice that eight other caches are older than this one.
    const done = () => {
      pycSweep(path.dirname(dest));
      resolve();
    };
    const unlock = () => {
      if (!locked) return;
      locked = false;
      try {
        fs.unlinkSync(lockPath);
      } catch {
        /* already gone */
      }
    };
    const finish = () => {
      unlock();
      fs.rmSync(tmp, { recursive: true, force: true });
      done();
    };
    try {
    // A dedicated argv, not `_baseArgv`: that one mounts the session's workspace, writes an env file
    // and would add THIS cache read-only, which is what must not happen while it is being written.
    const argv = [
      "box", `kern-pyc-${crypto.randomBytes(4).toString("hex")}`,
      "--image", image, "--ro",
      ...mountArgs(tmp, PYC_MOUNT, false),
      "--env", `PYTHONPYCACHEPREFIX=${PYC_MOUNT}`,
      "--cap-drop", "ALL",
      // CAPPED LIKE ANY OTHER BOX: the command is ours, the interpreter running it is the caller's
      // image, and this package's claim is that an image gets no uncapped process. Mirrors Python.
      "--memory", "512m",
      "--pids-limit", "256",
      "--timeout", String(Math.trunc(timeoutS)),
      "--", "python3", "-c", PYC_BUILD_CODE,
    ];
    // ASYNCHRONOUS, and `spawnSync` was the first version. It blocks the event loop for the whole
    // build - 1.2 s on a desktop, 5 s on the VPS - which in a server process is not a stall but an
    // outage: every request in flight waits for a cache fill. Nothing waits for this result, so there
    // is no reason for it to hold the loop at all.
      // STDERR IS KEPT, NOT IGNORED. A build that fails leaves no cache and the session runs as it
      // did before this feature existed, which is correct and was also SILENT: an image that never
      // got a cache looked exactly like one that did. The likeliest cause is this box's own caps -
      // `compileall` walks every import root, and an image with large packages can exceed 512 MiB
      // where a slim one never comes close.
      const child = spawn(kernBin, argv, { stdio: ["ignore", "ignore", "pipe"], detached: false });
      let errText = "";
      if (child.stderr) {
        child.stderr.setEncoding("utf8");
        // Bounded: this is a diagnostic, and a box that floods stderr must not grow the heap.
        child.stderr.on("data", (c) => {
          if (errText.length < 8192) errText += c;
        });
      }
      const killer = setTimeout(() => child.kill("SIGKILL"), (timeoutS + 10) * 1000);
      if (typeof killer.unref === "function") killer.unref();
      child.on("error", (e) => {
        clearTimeout(killer);
        pycReportFailure(image, -1, e && e.message);
        finish();
      });
      child.on("close", (code) => {
        clearTimeout(killer);
        if (code !== 0) pycReportFailure(image, code, errText);
        try {
          // An image without python3 leaves no cache and no trace: the next session runs as before.
          if (code === 0 && fs.readdirSync(tmp).length > 0 && pycTreeIsPublishable(tmp)) {
            // WRITTEN BEFORE THE PUBLISH, so a tree that becomes visible always carries the identity
            // of the image it was built from. Best effort: a cache without one reads as "cannot
            // tell", exactly how every cache built before this existed behaves.
            try {
              fs.writeFileSync(path.join(tmp, PYC_SOURCE_ID), pycSourceId(image));
            } catch {
              /* a cache with no identity is simply never invalidated by it */
            }
            fs.renameSync(tmp, dest);
            unlock();
            done();
            return;
          }
        } catch {
          /* fall through to the cleanup below */
        }
        finish();
      });
    } catch {
      /* a cache fill has no failure the caller can act on */
      finish();
    }
  });
}

/** Start one background build per image, at most once per process. Returns immediately.
 *
 * `setImmediate` rather than a worker thread: `spawnSync` would block the event loop, and this must
 * never delay the caller's first call. Mirrors `_pyc_start_build`. */
/** Sweep the cache once per process, off the critical path. Returns a promise for the tests.
 *
 * The sweep used to run only at the end of a build, so a process that always found its cache already
 * there never evicted anything: the bound existed only for callers who happened to compile. A
 * long-lived server adopting one cache for weeks is exactly the process that should age the others.
 * `setImmediate` because it is a readdir plus a stat per entry and a caller's first call pays nothing.
 * Mirrors `_pyc_start_sweep`. */
function pycStartSweep(root) {
  if (PYC_SWEPT) return Promise.resolve();
  PYC_SWEPT = true;
  return new Promise((resolve) => {
    const t = setImmediate(() => {
      pycSweep(root);
      resolve();
    });
    if (typeof t.unref === "function") t.unref();
  });
}

function pycStartBuild(kernBin, image, dest, timeoutS) {
  // STILL IN FLIGHT, not merely once started. The entry outlives the promise, so a process that had
  // already built this destination could never build it AGAIN - which is exactly what has to happen
  // after a moved tag invalidates the cache: the stale tree is discarded and nothing replaces it for
  // the life of that process. Measured on the Python side, where the map has the same shape.
  const inFlight = PYC_BUILDS.get(dest);
  if (inFlight) return inFlight;
  // `pycBuild` is already asynchronous (it spawns and returns), so there is nothing to defer. The
  // promise is returned for the tests and dropped by `open()`: a caller's first call must not wait on
  // a cache fill. A test that polled for the directory instead would be a timing race pretending to be
  // an assertion, and it would also race the test's own teardown - which is how this was found.
  const started = pycBuild(kernBin, image, dest, timeoutS).finally(() => {
    // Cleared when it settles, so the NEXT need for this destination starts a real build.
    if (PYC_BUILDS.get(dest) === started) PYC_BUILDS.delete(dest);
  });
  PYC_BUILDS.set(dest, started);
  return started;
}
const ENV_FILE = ".kern-env"; // host-side 0600 env file (kept out of argv so values don't show in `ps`)
// One file per CALL, `.kern-env.<box-name>`. A single fixed name made concurrent calls on the same
// Sandbox fight over one path: one call `unlink`ed the file while kern was still starting for
// another and had not read it yet, and that box died with
//   error: sandbox: cannot read --env-file '...': No such file or directory
// Measured at 30 concurrent runCode calls: 2 failed that way, and one file was left behind.
// The `O_EXCL|O_NOFOLLOW` create is a security property and is unchanged; only the NAME is per-call.
const ENV_SEP = ".";
const ENV_DIR_PREFIX = "kern-sandbox-env-";
// WHAT A SNAPSHOT'S `.deps` WAS BUILT FOR, as the archive's FIRST member; recognised only there and only
// with its key, so a user file of the same name is a later member restored like any other. Spelled as
// the Python binding spells it, so an archive from either is understood by both.
const SNAPSHOT_RECORD = ".kern-snapshot.json";
const SNAPSHOT_RECORD_KEY = "kern_snapshot";
const SNAPSHOT_RECORD_MAX = 4096;

/** The CPU a box on this host runs, as `uname -m` spells it (boxes are native). `os.machine` is Node
 * 18.9+; the map covers the `process.arch` spellings that differ before it. */
function hostMachine() {
  if (typeof os.machine === "function") return os.machine();
  return { x64: "x86_64", arm64: "aarch64", arm: "armv7l", ia32: "i686", ppc64: "ppc64le", s390x: "s390x" }[process.arch] || process.arch;
}

const SNAPSHOT_FIELD = /^[\x21-\x7e]{1,256}$/;

/** The provenance record in `raw`, or null when it is not one. The SAME rule as Python's
 * `_snapshot_record`: strict UTF-8 JSON (a BOM or UTF-16 is not), an object whose key is the number 1,
 * and `image` and `machine` as 1 to 256 printable ASCII characters. */
function snapshotRecord(raw) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
  } catch {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  if (parsed[SNAPSHOT_RECORD_KEY] !== 1) return null;
  for (const field of ["image", "machine"])
    if (typeof parsed[field] !== "string" || !SNAPSHOT_FIELD.test(parsed[field])) return null;
  return parsed;
}

/** The warning restore() gives for a snapshot whose `.deps` were built for another image or CPU, or
 * null. Same comparison and same words as Python's `_snapshot_origin_note`. */
function snapshotOriginNote(record, image, machine, hasDeps) {
  if (!hasDeps || !record || typeof record !== "object") return null;
  const wasImage = record.image;
  const wasMachine = record.machine;
  if (typeof wasImage !== "string" || typeof wasMachine !== "string") return null;
  if (sanitizeRef(wasImage) === sanitizeRef(image) && wasMachine === machine) return null;
  return (
    `restore: this snapshot's .deps were installed in image '${wasImage}' on '${wasMachine}', and this ` +
    `sandbox runs '${image}' on '${machine}'. A compiled package in .deps (a C or Rust extension) is built ` +
    `for one Python, libc and CPU, and fails to import on another - as ModuleNotFoundError or ` +
    `ImportError naming the package, not the snapshot. Run the install again in this sandbox (setup) to ` +
    `rebuild them for its image.`
  );
}
// The env-file names an OLDER version of either binding wrote into the workspace: the bare legacy
// file, one per call box named the way both bindings name them, and the resident box's (`kern-sbx-` and
// the sandbox's name, in kern's box-name alphabet), which no version ever removed. Those files hold
// `env` values, so a REGULAR FILE of one of these names is kept out of listings and snapshots. EXACTLY
// these shapes and no wider: a reserved prefix would let a box hide any file by naming it to match.
const LEGACY_ENV_FILE = /^\.kern-env(?:\.(?:(?:py|js)sbx-[0-9a-f]{12}|kern-sbx-[A-Za-z0-9_.-]{1,191}))?$/;
function isLegacyEnvFile(rel) {
  return LEGACY_ENV_FILE.test(rel);
}

/** A new 0700 directory for one session's env files, OUTSIDE the workspace `avoid`: the first of
 * $XDG_RUNTIME_DIR (when this user owns it and nobody else can enter it; a tmpfs, so a file left by a
 * process killed mid-call goes at logout), the system temp directory, then the user's cache directory,
 * that is not inside the workspace. A session given `workspace: "/tmp"` with no private runtime
 * directory used to get it under /tmp, inside the workspace every box mounts. If every candidate is
 * inside it, the session is refused. Mirrors Python's `_private_env_dir`. */
function privateEnvDir(avoid = "") {
  const ws = avoid ? fs.realpathSync(avoid) : "";
  const insideWorkspace = (p) => {
    let real;
    try {
      real = fs.realpathSync(p);
    } catch {
      return false;
    }
    return Boolean(ws) && (real === ws || real.startsWith(ws.replace(/\/+$/, "") + path.sep));
  };
  const closedToOthers = (p) => {
    try {
      const st = fs.statSync(p);
      return st.isDirectory() && st.uid === process.getuid() && (st.mode & 0o077) === 0;
    } catch {
      return false;
    }
  };
  const candidates = [];
  const runtime = process.env.XDG_RUNTIME_DIR || "";
  if (path.isAbsolute(runtime) && closedToOthers(runtime)) candidates.push(runtime);
  // mkdtemp makes the directory itself 0700, so a shared temp directory is fine as a parent.
  candidates.push(os.tmpdir());
  const cache = path.join(cacheHome(), "kern-sandbox");
  try {
    fs.mkdirSync(cache, { recursive: true, mode: 0o700 });
    candidates.push(cache);
  } catch {
    /* not available: the candidates above are tried */
  }
  for (const base of candidates)
    if (!insideWorkspace(base)) return fs.mkdtempSync(path.join(base, ENV_DIR_PREFIX));
  throw new SandboxError(
    `no place for this session's env files outside its workspace (${avoid}): the runtime, temp and ` +
      "cache directories are all inside it. Give the Sandbox a workspace that does not contain them.",
  );
}

const INLINE_CODE_MAX = 128 * 1024; // above this, pass code via a file instead of argv (ARG_MAX guard)
// Cap the results file the (untrusted) box writes before the binding reads it into host RAM: a malicious
// cell could stream a multi-GB `.res` to disk (past its own memory cap) and OOM the host.
const RESULTS_MAX = 64 * 1024 * 1024; // 64 MiB: generous for charts/tables, bounds the attacker read

// Python cell runner (P1: rich mime-typed results, Jupyter/E2B-style, no Jupyter kernel). Runs INSIDE
// the box (it is Python, regardless of which binding drove it): execs the user cell, then captures the
// trailing bare expression's value, every display(obj) call, and every open matplotlib figure, writing
// them as a JSON mime-bundle list the binding reads back. stdout/stderr/exit are UNTOUCHED. On the hot
// path it imports only C builtins (no .py to recompile in the read-only slim box); base64/io/traceback/
// json are lazy. Mirrors the Python binding's runner. __KERN_CELL__/__KERN_RES__ are substituted per call.
const PY_RUNNER = `
import sys, builtins  # C builtins: no .py to recompile in the read-only slim box (the P1 hot path).
_CELL = "__KERN_CELL__"
_RES = "__KERN_RES__"
_out = []
# Figures this cell already put in _out, id -> (figure, PNG as drawn then, or None for the cell's FINAL
# value). The figure is kept alive, so an id freed and reused within the cell cannot make an unrelated
# figure look already sent; the PNG lets the end of the cell skip a displayed figure only if the code did
# not draw on it after (matplotlib renders an unchanged figure to the same bytes).
_shown = {}
def _figure_of(o):
    """o if it is a matplotlib Figure, a subclass included, else None. Never raises: o is the cell's."""
    try:
        _mf = sys.modules.get("matplotlib.figure")
        return o if _mf is not None and isinstance(o, _mf.Figure) else None
    except Exception:
        return None
def _open_figures(plt):
    """The figures pyplot holds open, read from the manager list matplotlib's own inline backend reads,
    and not through plt.figure(n): that call MAKES a figure for a number closed meanwhile, and user code
    may have replaced it. The number walk is the fallback for a matplotlib without the list."""
    try:
        from matplotlib._pylab_helpers import Gcf
        # By figure NUMBER, the order the number walk gave: the manager list is in the order the
        # figures were last made active.
        return [m.canvas.figure for m in sorted(Gcf.get_all_fig_managers(), key=lambda m: m.num)]
    except Exception:
        try:
            return [plt.figure(n) for n in plt.get_fignums()]
        except Exception:
            return []
def _js(s):  # minimal JSON string encoder, so the box needs no \`import json\` (~80ms in a pyc-less slim box)
    r = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            r.append('\\\\"')
        elif ch == '\\\\':
            r.append('\\\\\\\\')
        elif o == 10:
            r.append('\\\\n')
        elif o == 13:
            r.append('\\\\r')
        elif o == 9:
            r.append('\\\\t')
        elif o < 32:
            r.append('\\\\u%04x' % o)
        else:
            r.append(ch)
    r.append('"')
    return "".join(r)
def _bundle(o):
    d = {}
    _fig = _figure_of(o)
    if _fig is not None:
        try:  # a Figure handed back as a value is DRAWN, as Jupyter's inline backend draws it
            import base64, io  # lazy: a Figure exists, so matplotlib is already imported
            _b = io.BytesIO()
            _fig.savefig(_b, format="png")
            d["image/png"] = base64.b64encode(_b.getvalue()).decode()
        except Exception:
            pass
    for meth, key in (("_repr_html_", "text/html"), ("_repr_markdown_", "text/markdown"),
                      ("_repr_svg_", "image/svg+xml"), ("_repr_latex_", "text/latex")):
        try:
            fn = getattr(o, meth, None)
            if callable(fn):
                v = fn()
                if isinstance(v, str) and v:
                    d[key] = v
        except Exception:
            pass
    try:
        fn = getattr(o, "_repr_json_", None)
        if callable(fn):
            v = fn()
            if v is not None:
                if isinstance(v, str):
                    d["application/json"] = v
                else:
                    import json
                    d["application/json"] = json.dumps(v)
    except Exception:
        pass
    for meth, key in (("_repr_png_", "image/png"), ("_repr_jpeg_", "image/jpeg")):
        try:
            fn = getattr(o, meth, None)
            if callable(fn):
                v = fn()
                if v:
                    import base64
                    raw = v if isinstance(v, (bytes, bytearray)) else str(v).encode()
                    d[key] = base64.b64encode(raw).decode()
        except Exception:
            pass
    if "text/plain" not in d:
        try:
            d["text/plain"] = repr(o)
        except Exception:
            d["text/plain"] = "<unrepresentable>"
    return d
def display(o=None, **kw):
    if o is not None:
        _d = _bundle(o)
        _out.append(_d)
        if "image/png" in _d and _figure_of(o) is not None:
            _shown[id(o)] = (o, _d["image/png"])  # as drawn at this line; the code may draw on after it
builtins.display = display
sys.argv = [_CELL]
_g = {"__name__": "__main__", "__file__": _CELL, "display": display}
_rc = 0
try:
    _src = open(_CELL, "r", encoding="utf-8").read()
    _tree = compile(_src, _CELL, "exec", 0x400)
    _tail = None
    if _tree.body and type(_tree.body[-1]).__name__ == "Expr":
        _n = _tree.body.pop()
        _lines = _src.split("\\n")
        if _n.lineno == _n.end_lineno:
            _tail = _lines[_n.lineno - 1].encode()[_n.col_offset:_n.end_col_offset].decode("utf-8", "replace")
        else:
            _seg = [_lines[_n.lineno - 1].encode()[_n.col_offset:].decode("utf-8", "replace")]
            _seg += _lines[_n.lineno:_n.end_lineno - 1]
            _seg.append(_lines[_n.end_lineno - 1].encode()[:_n.end_col_offset].decode("utf-8", "replace"))
            _tail = "\\n".join(_seg)
    exec(compile(_tree, _CELL, "exec"), _g)
    if _tail is not None:
        _val = eval(compile(_tail, _CELL, "eval"), _g)
        if _val is not None:
            _out.append(_bundle(_val))
            if _figure_of(_val) is not None:
                # the FINAL value of the cell is the figure's final state: not sent again below. A
                # display(fig) earlier in the cell records nothing, because the code may draw on after it.
                _shown[id(_val)] = (_val, None)
except SystemExit as _e:
    _rc = _e.code if isinstance(_e.code, int) else (0 if _e.code is None else 1)
except BaseException as _e:
    import traceback
    _tb = _e.__traceback__
    while _tb is not None and _tb.tb_frame.f_code.co_filename != _CELL:
        _tb = _tb.tb_next
    sys.stderr.write("".join(traceback.format_exception(type(_e), _e, _tb)))
    _rc = 1
try:
    if "matplotlib.pyplot" in sys.modules:
        import base64, io
        _plt = sys.modules["matplotlib.pyplot"]
        for _f in _open_figures(_plt):
            try:  # one figure that cannot be drawn does not stop the others, as in the kernel
                _was = _shown.get(id(_f))
                _mine = _was is not None and _was[0] is _f
                if not (_mine and _was[1] is None):  # the cell's final value is already in the results
                    _buf = io.BytesIO()
                    _f.savefig(_buf, format="png")
                    _png = base64.b64encode(_buf.getvalue()).decode()
                    if not (_mine and _was[1] == _png):  # displayed, and not drawn on since
                        _out.append({"image/png": _png})
            except Exception:
                pass
except Exception:
    pass
try:
    _parts = ["{" + ",".join(_js(str(_k)) + ":" + _js(str(_v)) for _k, _v in _d.items()) + "}" for _d in _out]
    open(_RES, "w", encoding="utf-8").write("[" + ",".join(_parts) + "]")
except Exception:
    pass
sys.exit(_rc)
`;

// Persistent-kernel driver (warm-start: kill the ~10 ms CPython boot). Runs ONCE in a long-lived box and
// then services many cells from one resident process, so in-memory state PERSISTS across cells and the
// per-cell cost drops to sub-millisecond. It is warm, so imports (json/ast/io/base64) are paid once at
// startup, not on any hot path. Protocol on the box's stdin/stdout (length-prefixed frames): host writes
// `<n>\n` + n UTF-8 bytes of cell source; the driver execs it (capturing stdout/stderr into buffers, the
// trailing expression, every display() and matplotlib figure) and writes back `<m>\n` + m UTF-8 bytes of
// {stdout, stderr, rc, results}. User prints go to a buffer, so the control channel stays clean. String.raw
// keeps the single `\n` byte-literal intact (the driver has no backtick or ${...}). Byte-identical to the
// Python binding's _PY_KERNEL_DRIVER so both bindings behave the same.
const PY_KERNEL_DRIVER = String.raw`import sys, io, json, base64, builtins, ast, os, threading, codecs, select, time
_g = {"__name__": "__main__"}
_out = []
# Figures this cell already put in _out, id -> (figure, PNG as drawn then, or None for the cell's FINAL
# value). The figure is kept alive, so an id freed and reused within the cell cannot make an unrelated
# figure look already sent; the PNG lets the end of the cell skip a displayed figure only if the code did
# not draw on it after (matplotlib renders an unchanged figure to the same bytes).
_shown = {}
def _figure_of(o):
    """o if it is a matplotlib Figure, a subclass included, else None. Never raises: o is the cell's."""
    try:
        _mf = sys.modules.get("matplotlib.figure")
        return o if _mf is not None and isinstance(o, _mf.Figure) else None
    except Exception:
        return None
def _open_figures(plt):
    """The figures pyplot holds open, read from the manager list matplotlib's own inline backend reads,
    and not through plt.figure(n): that call MAKES a figure for a number closed meanwhile, and user code
    may have replaced it. The number walk is the fallback for a matplotlib without the list."""
    try:
        from matplotlib._pylab_helpers import Gcf
        # By figure NUMBER, the order the number walk gave: the manager list is in the order the
        # figures were last made active.
        return [m.canvas.figure for m in sorted(Gcf.get_all_fig_managers(), key=lambda m: m.num)]
    except Exception:
        try:
            return [plt.figure(n) for n in plt.get_fignums()]
        except Exception:
            return []
def _bundle(o):
    d = {}
    _fig = _figure_of(o)
    if _fig is not None:
        try:  # a Figure handed back as a value is DRAWN, as Jupyter's inline backend draws it
            _b = io.BytesIO()
            _fig.savefig(_b, format="png")
            d["image/png"] = base64.b64encode(_b.getvalue()).decode()
        except Exception:
            pass
    for meth, key in (("_repr_html_", "text/html"), ("_repr_markdown_", "text/markdown"),
                      ("_repr_svg_", "image/svg+xml"), ("_repr_latex_", "text/latex")):
        try:
            fn = getattr(o, meth, None)
            if callable(fn):
                v = fn()
                if isinstance(v, str) and v:
                    d[key] = v
        except Exception:
            pass
    try:
        fn = getattr(o, "_repr_json_", None)
        if callable(fn):
            v = fn()
            if v is not None:
                d["application/json"] = v if isinstance(v, str) else json.dumps(v)
    except Exception:
        pass
    for meth, key in (("_repr_png_", "image/png"), ("_repr_jpeg_", "image/jpeg")):
        try:
            fn = getattr(o, meth, None)
            if callable(fn):
                v = fn()
                if v:
                    raw = v if isinstance(v, (bytes, bytearray)) else str(v).encode()
                    d[key] = base64.b64encode(raw).decode()
        except Exception:
            pass
    if "text/plain" not in d:
        try:
            d["text/plain"] = repr(o)
        except Exception:
            d["text/plain"] = "<unrepresentable>"
    return d
def display(o=None, **kw):
    if o is not None:
        _d = _bundle(o)
        _out.append(_d)
        if "image/png" in _d and _figure_of(o) is not None:
            _shown[id(o)] = (o, _d["image/png"])  # as drawn at this line; the code may draw on after it
builtins.display = display
# Make the CONTROL channel private so user code (a raw os.write, a C extension, a subprocess reading
# stdin) can NEVER corrupt a reply on stdout nor steal a cell off stdin. dup the real stdin(0)/stdout(1)
# to close-on-exec control fds; then point fd 0 at /dev/null and fd 1/2 at pipes drained in the
# background, so raw/subprocess output is CAPTURED (and >64 KiB never deadlocks) instead of hitting the
# control channel. Uses only fds 0/1 (which always survive kern's box setup) and re-plumbs inside the box.
# Running the driver with -c puts '' (the current directory, resolved at import time) at sys.path[0],
# while a script run by path puts the script's DIRECTORY there. The one-shot runner is a file in the
# workspace, so its cells see an absolute /workspace; pin the same absolute entry here so an import
# behaves identically whichever way the driver was started. Started BY PATH this is a no-op.
if sys.path and sys.path[0] == "":
    sys.path[0] = os.getcwd()
_ctrl_in = os.dup(0)
_ctrl_out = os.dup(1)
os.set_inheritable(_ctrl_in, False)
os.set_inheritable(_ctrl_out, False)
_nul = os.open(os.devnull, os.O_RDONLY)
os.dup2(_nul, 0)
os.close(_nul)
_u1r, _u1w = os.pipe()
os.dup2(_u1w, 1)
os.close(_u1w)
_u2r, _u2w = os.pipe()
os.dup2(_u2w, 2)
os.close(_u2w)
_CAP = __KERN_OUTCAP__
_RESCAP = __KERN_RESCAP__
_MARK = b"\x00\x01KRNCELLDONE\x01\x00"  # per-cell barrier sentinel written to user fd 1/2 after exec
_ulock = threading.Lock()
_mevt = {1: threading.Event(), 2: threading.Event()}
# Set when this cell's output is cut at _CAP, read+reset by the cell loop under _ulock. A list (not a
# bare name) because the writers rebind nothing: they mutate this one shared cell.
_tcut = [False]
_MAIN_PID = os.getpid()  # a cell that raw os.fork()s copies this whole process; the child must NOT re-enter
_rin = os.fdopen(_ctrl_in, "rb")
def _read():
    line = _rin.readline()
    if not line:
        return None
    n = int(line.strip())
    buf = b""
    while len(buf) < n:
        chunk = _rin.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf.decode("utf-8")
_wlock = threading.Lock()
def _write(obj):
    b = json.dumps(obj).encode("utf-8")
    _data = memoryview(str(len(b)).encode() + b"\n" + b)
    with _wlock:
        while _data:
            _data = _data[os.write(_ctrl_out, _data):]
# OUTPUT IS STREAMED, one frame per write, while the cell runs. It used to be collected here and sent in
# the cell's reply, so a cell the sandbox KILLED (an OOM, a timeout) took everything it had printed with
# it: no reply, so no output, and the caller could not tell "printed nothing" from "printed, then died".
# {"o": text} is stdout and {"e": text} stderr; the reply that ends the cell carries the rest. A
# frame holds at most _CHUNK characters, so no single frame nears the host's cap however much is printed.
_KEY = {1: "o", 2: "e"}
_CHUNK = 8192
_sent = {1: 0, 2: 0}  # characters streamed in the current cell, per stream, bounded by _CAP
_live = [False]  # True while a cell runs: output between cells belongs to no cell and is dropped
def _emit(key, text):
    # Called with _ulock held.
    if not text or not _live[0]:
        return
    room = _CAP - _sent[key]
    if len(text) > room:
        text = text[:max(room, 0)]
        _tcut[0] = True
    if not text:
        return
    _sent[key] += len(text)
    for _p in range(0, len(text), _CHUNK):
        _write({_KEY[key]: text[_p:_p + _CHUNK]})
# A print() is queued and sent within _FLUSH_S by one thread, woken once per burst; flush(), os._exit()
# and the end of the cell send what is queued at once. So what a SIGKILLed cell loses is at most its last
# millisecond of output, where it used to lose all of it. One frame per write made 10 000 prints cost
# 58 ms against 1.8 ms when they were only collected (and 9.8 ms on the one-shot path).
_FLUSH_S = 0.001
_armed = [False]  # the flusher is already due: a burst wakes it once, not once per write
_pend = {1: [], 2: []}
_pend_n = {1: 0, 2: 0}
_flush_cv = threading.Condition(_ulock)
def _flush_py(key):
    # Called with _ulock held.
    if _pend[key]:
        _t = "".join(_pend[key])
        _pend[key].clear()
        _pend_n[key] = 0
        _emit(key, _t)
class _Stream(io.TextIOBase):
    # The cell's sys.stdout / sys.stderr. ORDER with fd output (a subprocess, C code) is kept by reading,
    # under the same lock, whatever already sits in the fd pipe before this text is queued: what was
    # written first goes out first. A forked child writes to the fd instead, which the parent drains: a
    # frame from the child would interleave with the parent's.
    def __init__(self, key):
        self._key = key
    def writable(self):
        return True
    @property
    def encoding(self):
        return "utf-8"
    def write(self, s):
        if not isinstance(s, str):
            raise TypeError("write() argument must be str, not " + type(s).__name__)
        if os.getpid() != _MAIN_PID:
            _b = memoryview(s.encode("utf-8", "replace"))
            while _b:
                _b = _b[os.write(self._key, _b):]
            return len(s)
        with _ulock:
            _pull(self._key)
            _pend[self._key].append(s)
            _pend_n[self._key] += len(s)
            if _pend_n[self._key] >= _CHUNK:
                _flush_py(self._key)
            elif not _armed[0]:
                _armed[0] = True
                _flush_cv.notify()
        return len(s)
    def flush(self):
        if os.getpid() == _MAIN_PID:
            with _ulock:
                _pull(self._key)
                _flush_py(self._key)
def _flusher():
    while True:
        with _ulock:
            while not _armed[0]:
                _flush_cv.wait()
        time.sleep(_FLUSH_S)
        with _ulock:
            _armed[0] = False
            _flush_py(1)
            _flush_py(2)
threading.Thread(target=_flusher, daemon=True).start()
_real_os_exit = os._exit
def _os_exit_sending(n):
    # os._exit ends the process without any of Python's cleanup, so what is queued goes out first. A
    # forked child has nothing queued here (it writes to the fd), and a lock held elsewhere is waited for
    # briefly, never forever: an exit must not hang.
    if os.getpid() == _MAIN_PID and _ulock.acquire(timeout=0.5):
        try:
            _pull(1)
            _pull(2)
            _flush_py(1)
            _flush_py(2)
        finally:
            _ulock.release()
    _real_os_exit(n)
os._exit = _os_exit_sending
def _mark_prefix_len(data):
    # How many bytes at the END of the data could be the START of the barrier: held back until the next
    # read says whether they are, so a barrier split across two reads is still found and never streamed.
    for _n in range(min(len(_MARK) - 1, len(data)), 0, -1):
        if _MARK.startswith(data[-_n:]):
            return _n
    return 0
_UFD = {1: _u1r, 2: _u2r}
os.set_blocking(_u1r, False)
os.set_blocking(_u2r, False)
# poll(0) answers "is there anything to read" without the BlockingIOError an empty non-blocking read
# raises: 0.19 us against 0.5, measured, and every print() asks it once.
_POLL = {1: select.poll(), 2: select.poll()}
_POLL[1].register(_u1r, select.POLLIN)
_POLL[2].register(_u2r, select.POLLIN)
_dec = {1: codecs.getincrementaldecoder("utf-8")("replace"), 2: codecs.getincrementaldecoder("utf-8")("replace")}
_held = {1: b"", 2: b""}
def _pull(key):
    # Called with _ulock held: read everything the fd pipe holds right now and stream it. Every read of the
    # pipe happens under the lock and is sent before the lock is released, which is what keeps fd output
    # and print() in the order they were written. Returns False at EOF. At most 64 reads (4 MiB) a call:
    # a child writing without pause (yes(1)) would otherwise hold the lock, and with it every print().
    if not _POLL[key].poll(0):
        return True
    for _r in range(64):
        try:
            chunk = os.read(_UFD[key], 65536)
        except BlockingIOError:
            return True
        except OSError:
            return False
        if not chunk:
            return False
        _flush_py(key)  # print() text queued before these bytes arrived was written before them
        data = _held[key] + chunk
        _i = data.find(_MARK)
        if _i >= 0:
            _emit(key, _dec[key].decode(data[:_i], final=True))  # all of the cell's bytes, THEN the barrier
            data = data[_i + len(_MARK):]
            _mevt[key].set()
        _n = _mark_prefix_len(data)
        _held[key] = data[len(data) - _n:] if _n else b""
        _emit(key, _dec[key].decode(data[:len(data) - _n]))
    return True
def _drain(fd, key):
    while True:
        try:
            select.select([fd], [], [])
        except (OSError, ValueError):
            break
        with _ulock:
            if not _pull(key):
                break
threading.Thread(target=_drain, args=(_u1r, 1), daemon=True).start()
threading.Thread(target=_drain, args=(_u2r, 2), daemon=True).start()
# Readiness. Popen returns when the FORK happens, not when kern has built the box and CPython has
# booted inside it, so a pool that published a box on Popen alone would hand out boxes that are still
# starting - and the caller would pay the remainder of that start on its own clock, which is the exact
# cost prewarming exists to remove. This frame is the only signal that the interpreter is actually at the
# prompt. Emitted only when the host asked for it (see __KERN_HELLO__): a persistent Kernel does not
# read one, and an unexpected frame there would be consumed as the first cell's reply.
if __KERN_HELLO__:
    _write({"hello": 1})
while True:
    _code = _read()
    if _code is None:
        break
    _out.clear()
    _shown.clear()
    with _ulock:
        _tcut[0] = False  # a cut belongs to the cell it happens in, so clear it at the cell boundary
        _sent[1] = _sent[2] = 0
        _live[0] = True
    _so, _se = _Stream(1), _Stream(2)
    _rc = 0
    _oo, _oe, _oi = sys.stdout, sys.stderr, sys.stdin
    sys.stdout, sys.stderr = _so, _se
    # Point user stdin at an empty stream so input()/sys.stdin.read() gets EOF instead of consuming the
    # NEXT control frame off the real pipe (which would deadlock the kernel and desync the protocol).
    sys.stdin = io.StringIO("")
    try:
        _tree = ast.parse(_code, "<cell>", "exec")
        _tail = None
        if _tree.body and isinstance(_tree.body[-1], ast.Expr):
            _tail = ast.Expression(_tree.body.pop().value)
            ast.fix_missing_locations(_tail)
        exec(compile(_tree, "<cell>", "exec"), _g)
        if _tail is not None:
            _v = eval(compile(_tail, "<cell>", "eval"), _g)
            if _v is not None:
                _out.append(_bundle(_v))
                if _figure_of(_v) is not None:
                    # the FINAL value of the cell is the figure's final state: not sent again below. A
                    # display(fig) earlier in the cell records nothing, because the code may draw on.
                    _shown[id(_v)] = (_v, None)
    except SystemExit as _e:
        _rc = _e.code if isinstance(_e.code, int) else (0 if _e.code is None else 1)
    except BaseException as _e:
        import traceback
        _tb = _e.__traceback__
        while _tb is not None and _tb.tb_frame.f_code.co_filename != "<cell>":
            _tb = _tb.tb_next
        _se.write("".join(traceback.format_exception(type(_e), _e, _tb)))
        _rc = 1
    finally:
        sys.stdout, sys.stderr, sys.stdin = _oo, _oe, _oi
    if os.getpid() != _MAIN_PID:
        # A cell called raw os.fork(): this is the CHILD. It must not re-enter the loop, write a reply,
        # or touch the control channel (that would spawn a rogue driver clone corrupting the protocol).
        os._exit(0)
    try:
        if "matplotlib.pyplot" in sys.modules:
            _plt = sys.modules["matplotlib.pyplot"]
            # EACH OPEN FIGURE ONCE, THEN CLOSED, which is what Jupyter's inline backend does by
            # default. Left open, every later cell re-sent every figure the session had drawn: a cell
            # that only printed returned the plots of the cells before it, and paid a PNG encode for
            # each. A figure the code still holds is not lost: fig or display(fig) draws it again.
            # Closed in a finally of its own, so one figure that cannot be drawn is not left open to
            # fail again in every cell after it.
            for _f in _open_figures(_plt):
                try:
                    _was = _shown.get(id(_f))
                    _mine = _was is not None and _was[0] is _f
                    if not (_mine and _was[1] is None):  # the cell's final value is already in the results
                        _b = io.BytesIO()
                        _f.savefig(_b, format="png")
                        _png = base64.b64encode(_b.getvalue()).decode()
                        if not (_mine and _was[1] == _png):  # displayed, and not drawn on since
                            _out.append({"image/png": _png})
                except Exception:
                    pass
                finally:
                    try:
                        _plt.close(_f)
                    except Exception:
                        pass
    except Exception:
        pass
    # Barrier: write the sentinel to fd 1/2 and read up to it, so this cell's raw/subprocess output is
    # FULLY captured (not racily missed) before the reply. It is read HERE, by this thread, right after
    # it is written: waiting for a drain thread to wake from select() for it doubled the cost of an empty
    # cell (0.04 -> 0.16 ms, measured).
    with _ulock:
        _flush_py(1)
        _flush_py(2)
    _mevt[1].clear()
    _mevt[2].clear()
    try:
        os.write(1, _MARK)
        os.write(2, _MARK)
    except OSError:
        pass
    with _ulock:
        _pull(1)
        _pull(2)
    _mevt[1].wait(2.0)
    _mevt[2].wait(2.0)
    with _ulock:
        _live[0] = False
        _tr = _tcut[0]
    # Both streams went out as frames while the cell ran, each cut at _CAP by _emit, so a cell that
    # prints a gigabyte through sys.stdout streams _CAP characters and says so.
    _o1 = _o2 = ""
    # Results are bounded bundle by bundle rather than by serializing the whole list and measuring it: a
    # single json.dumps of an oversized list would build the entire payload in the box before anything
    # could reject it. A bundle that alone exceeds the budget is dropped, not truncated mid-JSON.
    # A _RESCAP of 0 or less means unbounded and skips the measuring entirely: a persistent Kernel keeps
    # its historical contract (the host's frame cap is the only bound) AND does not pay a second
    # json.dumps per bundle, which measuring every bundle would cost it on a large figure.
    if _RESCAP <= 0:
        _res = list(_out)
    else:
        _res = []
        _rsz = 0
        for _bnd in _out:
            try:
                _bl = len(json.dumps(_bnd))
            except Exception:
                continue
            if _rsz + _bl > _RESCAP:
                _tr = True
                break
            _res.append(_bnd)
            _rsz += _bl
    _write({"stdout": _o1, "stderr": _o2, "rc": _rc, "results": _res, "trunc": _tr})`;

// Signal-derived exit codes (128 + signum) we classify.
const EXIT_SIGKILL = 137; // SIGKILL: timeout backstop or OOM (indistinguishable without cgroup)
const EXIT_SIGSYS = 159; // SIGSYS: a seccomp-denied syscall = a blocked escape attempt
const EXIT_SIGTERM = 143; // SIGTERM: kern's --timeout backstop reaping the box
// The signal NUMBERS behind those codes, for kern's 4th started-byte. Spelled out rather than derived
// from the code, because `128 + N` is the convention being checked and deriving N from it would make the
// check circular.
const SIG_KILL = 9;
const SIG_TERM = 15;
const SIG_SYS = 31;
// The fatal signals that mean THE CODE went wrong, not that the sandbox acted. NAMED, not "everything
// else": an unknown signal stays an honest `killed`. SIGKILL and SIGTERM are absent (the kill and the
// reap have their own branches) and SIGSYS is absent because it IS the sandbox acting.
// SIGILL 4, SIGABRT 6, SIGBUS 7, SIGFPE 8, SIGSEGV 11. Mirrors `_CRASH_SIGNALS`.
const CRASH_SIGNALS = new Set([4, 6, 7, 8, 11]);
const SIGNAL_NAMES = { 4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 11: "SIGSEGV" };

// Per-call kwargs that DEFAULT to the Sandbox value: UNSET means "inherit the constructor's", whereas
// an explicit `null` means "disable" (used for onStdout/onStderr overrides).
const UNSET = Symbol("unset");

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

/** kern's OWN state on this host: [path, what it is]. Refused as a mount source, like the docker socket
 * and for the same reason.
 *
 * FOUND BY A CHECKLIST ROW, measured on the Python binding first: mounting `$XDG_RUNTIME_DIR/kern` was
 * ACCEPTED, which hands the code in the box kern's control plane (the registry, instance dirs, netns
 * handles and exit files of every box this user runs). The image cache is the same class one step
 * removed: a box that writes it poisons the rootfs a LATER box runs. Resolved per call, because these
 * follow the environment and a service manager moves them. */
function kernStateDirs() {
  const uid = process.getuid();
  const home = os.homedir();
  // EACH DIRECTORY TWICE: where the environment says it is, AND where XDG says it is by default. The
  // runtime dir was already spelled both ways; the other three were not, and an independent test measured the
  // consequence in one process - with `XDG_DATA_HOME=/tmp/xdh2`, `~/.local/share/kern` was ACCEPTED
  // and still held `builds` and `volumes`. The variable answers "which kern will this SDK spawn",
  // which is the right input for the guard, but data a previous run left on disk does not move with it.
  //
  // The DATA dir itself joined the list after the same independent test took the refused two as the shape of
  // the rule and looked for the rest: it holds `volumes/`, the CONTENT of every named volume on this
  // host, and `builds/`, the records a later image is assembled from.
  const known = [
    [process.env.XDG_RUNTIME_DIR, `/run/user/${uid}`,
      "kern's runtime state (the registry, instance dirs, netns handles and exit files of every box you are running)"],
    [process.env.XDG_CACHE_HOME, path.join(home, ".cache"),
      "kern's image cache (a box that writes it poisons the rootfs a later box runs)"],
    [process.env.XDG_CONFIG_HOME, path.join(home, ".config"),
      "kern's configuration (the profiles a later box may be given)"],
    [process.env.XDG_DATA_HOME, path.join(home, ".local", "share"),
      "kern's data (every named volume on this host, and the build records a later image is assembled from)"],
  ];
  // A MAP, so the usual case where the variable IS the default collapses to one entry instead of
  // listing the same directory twice with two different accounts of what it is.
  const out = new Map();
  for (const [configured, dflt, what] of known)
    for (const base of [configured || dflt, dflt]) {
      const dir = path.join(base, "kern");
      if (!out.has(dir)) out.set(dir, what);
    }
  return [...out];
}

/** Credential directories, refused as a COMPONENT anywhere in the source. The set above is absolute
 * paths, so it refused `$HOME` and accepted `$HOME/.ssh`: MEASURED, a box mounted with `~/.ssh` listed
 * `id_ed25519` and `authorized_keys`. Refusing the parent and allowing its most sensitive child is the
 * wrong way round, and it is the scenario a prompt-injected agent is steered into ("read ~/.aws"). These
 * match by NAME because they live under a per-user home. No escape hatch, same as `/etc`: a job that
 * needs one credential should be given that one file in the workspace. */
//
// THE LIST WAS SHORT OF THE PROMISE ABOVE IT, and the asymmetry is what gave it away: AWS refused,
// Azure refused, GCP accepted. MEASURED against the published SDK with each directory CREATED first,
// because a refusal that is really "source does not exist" is a skip wearing a pass - that is how
// `~/.config/gcloud` read as covered on a host that has no gcloud.
//
// `~/.config/<tool>` NEEDS THE PARENT, which is why there is a second set below: `gcloud` and `gh`
// are not dotfiles, and refusing a bare `gh` component anywhere would refuse `~/projects/gh/src` - a
// guard that fires on ordinary work gets switched off, and then it guards nothing.
//
// DELIBERATELY NOT ADDED: `.cargo`, `.m2`, `.gem`. Each holds ONE credential file next to a package
// cache people legitimately mount, so refusing the directory would break a real use and push callers
// off the guard. The residual gap is named rather than papered over.
//
// KEPT IDENTICAL TO THE PYTHON BINDING on purpose: two spellings of one rule drift, and a caller who
// moved between the two SDKs would meet a different boundary in each.
const REFUSED_MOUNT_COMPONENTS = new Set([
  ".ssh",
  ".aws",
  ".gnupg",
  ".kube",
  ".docker",
  ".azure",
  ".password-store",
  ".netrc",
  ".git-credentials",
  ".pypirc",
  ".npmrc",
  ".oci",
  ".terraform.d",
  ".databrickscfg",
  ".boto",
  ".s3cfg",
  ".rclone.conf",
]);

// `parent/child` pairs, refused when they appear CONSECUTIVELY in the source.
const REFUSED_MOUNT_PAIRS = new Set([
  ".config/gcloud",
  ".config/gh",
  ".config/doctl",
  ".config/rclone",
]);

/** A PROGRAMMER/config error, THROWN: bad argument, illegal mount, `kern` not installed, or the box
 * FAILED TO START (kern exits 125 - a mount refused at runtime, an unmappable `--user`, a seccomp or
 * AppArmor setup error). A box that never started ran no user code, so it rejects rather than resolve a
 * hollow result. Runtime sandbox events where the code DID run (timeout, blocked escape, OOM-kill) are
 * NOT thrown - they are data on `result.fault`. */
class SandboxError extends Error {
  // `options` is Error's own (`{ cause }`): a refusal keeps the OS error it stands for, which is how a
  // caller tells "closed to this process" (EACCES) from every other refusal without a second channel.
  constructor(message, options) {
    super(message, options);
    this.name = "SandboxError";
  }
}

/** A requested host mount was refused as unsafe (sensitive source, or a relative/escaping path). */
class MountRefused extends SandboxError {
  constructor(message, options) {
    super(message, options);
    this.name = "MountRefused";
  }
}

/** A rich, mime-typed value captured from a Python `runCode` (the way a Jupyter/E2B cell captures
 * output): the value of the code's last bare expression, every `display(obj)` call, and every open
 * matplotlib figure. `data` maps a MIME type to its payload; text/* and application/json are strings,
 * image/* are base64 strings (use `.png`/`.jpeg` for Buffers). One value can carry several forms. */
class Result {
  constructor(data) {
    this.data = data || {};
  }
  get text() {
    return this.data["text/plain"];
  }
  get html() {
    return this.data["text/html"];
  }
  get markdown() {
    return this.data["text/markdown"];
  }
  get svg() {
    return this.data["image/svg+xml"];
  }
  get json() {
    return this.data["application/json"];
  }
  get png() {
    const v = this.data["image/png"];
    return v ? Buffer.from(v, "base64") : null;
  }
  get jpeg() {
    const v = this.data["image/jpeg"];
    return v ? Buffer.from(v, "base64") : null;
  }
  /** The MIME types this value was captured as. */
  formats() {
    return Object.keys(this.data);
  }
}

/** The outcome of one runCode()/run(). `fault` is the source of truth for "did the SANDBOX act";
 * `exitCode`/`stdout` are what the user's code did. `success` requires both clean. */
class ExecutionResult {
  constructor({ stdout, stderr, exitCode, durationMs, fault, files, truncated, results }) {
    this.stdout = stdout;
    this.stderr = stderr;
    this.exitCode = exitCode;
    this.durationMs = durationMs;
    /** @type {{type: string, message: string} | null} */
    this.fault = fault || null;
    this.files = files || [];
    this.truncated = !!truncated;
    /** @type {Result[]} rich mime-typed values (Python runCode) */
    this.results = results || [];
  }
  /** True iff the code exited 0 AND no sandbox fault fired. */
  get success() {
    return this.exitCode === 0 && this.fault === null;
  }
  /** `stderr` with kern's own `note:`/`warning:`/posture lines removed: what the code actually wrote.
   *
   * This is what belongs in a model's context. A workload CAN forge one of kern's prefixes, and the
   * consequence is its own line moving to {@link runtimeNotes}: the trick removes its text from this
   * field, it cannot inject text into it.
   *
   * The guarantee is LINE-ALIGNED, not absolute: a workload that leaves a line unterminated and is
   * then interleaved with a `kern: warning:` on the shared stderr produces one line starting with the
   * workload's text, which no prefix matches, so kern's warning lands here framed by bytes the
   * workload chose. Racy rather than reliable, and in the less harmful direction, but real. Mirrors
   * `ExecutionResult.code_stderr` in Python. */
  get codeStderr() {
    return this._splitStderr()[0];
  }
  /** Partition `stderr` ONCE into [what the code wrote, the lines kern wrote].
   *
   * One pass and one cache, mirroring `_split_stderr` in Python. The two public halves are a single
   * partition, so computing them separately left two filters that had to agree by inspection rather
   * than by construction; and each was O(n) on every read, measured at 13.9 ms on a 200k-line stderr
   * in the Python binding before this. Keyed on the string it partitioned, so reassigning `stderr`
   * recomputes rather than serving a stale answer. Non-enumerable, so it stays out of JSON and out of
   * anything that walks the result's own keys. */
  _splitStderr() {
    const raw = String(this.stderr || "");
    if (this._stderrSplit && this._stderrSplit[0] === raw) {
      return [this._stderrSplit[1], this._stderrSplit[2]];
    }
    const kept = [];
    const notes = [];
    for (const line of raw.split("\n")) (isKernDiagnostic(line) ? notes : kept).push(line);
    const joined = kept.join("\n");
    Object.defineProperty(this, "_stderrSplit", {
      value: [raw, joined, notes], writable: true, enumerable: false, configurable: true,
    });
    return [joined, notes];
  }
  /** The lines on `stderr` that KERN wrote, the complement of {@link codeStderr}. Reported rather
   * than removed: `stderr` still holds every byte in its original order. */
  get runtimeNotes() {
    return this._splitStderr()[1].slice();
  }
}

/** A sandbox event `{type, message}` for `result.fault`. NB: `startup_failed` is decided from an
 * UNFORGEABLE kern signal (a byte on fd 3 / `KERN_STARTED_FD` a workload can neither write nor
 * suppress). Against a kern too old to send it, the binding falls back to a stderr heuristic that can
 * only OVER-report - a workload can make its own exit look like a start failure - never MISS a real
 * one, so it fails in the safe direction. Pair this binding with the matching (or newer) kern release. */
function sandboxFault(type, message) {
  return { type, message };
}

/** Binaries already identified as kern, keyed by identity and not by path: a `kern` REPLACED between two
 * calls is a different program and gets checked again. */
const VERIFIED_KERN = new Set();
/** The `--version` line of each verified binary, by the same key: what the resident path needs to know
 * whether a missing started byte means anything (see `kernExecReportsItsStart`). */
const KERN_VERSION_LINE = new Map();

/** The X.Y.Z in what `kern --version` printed, or null. Mirrors `_kern_release`. */
function kernRelease(version) {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(version || "");
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

/** Whether this kern's `kern exec` writes the KERN_STARTED_FD bytes ONLY for a command that ran. v0.30.1
 * wrote them on refusals too (MEASURED: `[1, 0, 0, 0]` for an exec that refused, exit 126), so only from
 * v0.30.2 does a missing byte prove the call never started. Mirrors `_kern_exec_reports_its_start`. */
function kernExecReportsItsStart(version) {
  const r = kernRelease(version);
  if (!r) return false;
  for (let i = 0; i < 3; i++) if (r[i] !== [0, 30, 2][i]) return r[i] > [0, 30, 2][i];
  return true;
}

/** Refuse a binary that does not IDENTIFY ITSELF as kern. Throws `SandboxError` if it does not.
 *
 * MEASURED, and found by an independent test running the positive control this project wrote for him:
 * with `KERN_BIN=/bin/true` a call returned `success: true, exitCode: 0, fault: null` and an empty
 * stdout. The code never ran and the caller was told it had. Any `kern` earlier in `PATH` that is not
 * kern does this: a leftover wrapper, a shim, a no-op. An agent loop reads `success` and every
 * conclusion after that is about a program that never executed.
 *
 * POSITIVE IDENTIFICATION, not inference from a missing signal: a kern old enough to predate
 * `KERN_STARTED_FD` writes no bytes either, and refusing it would punish an old binary rather than a
 * fake one. `kern --version` prints `kern <version>`, a prefix kern's own suite asserts.
 *
 * Memoised per binary identity, so it costs one `--version` (measured at 0.9 ms) per distinct binary
 * per process and nothing afterwards. Fail-closed: unrunnable, slow or unrecognised is refused, because
 * an unverifiable runtime is the case this exists for. Mirrors `_verify_is_kern`. */
function verifyIsKern(bin) {
  let key;
  try {
    const st = fs.statSync(bin);
    key = [fs.realpathSync(bin), st.dev, st.ino, st.size, st.mtimeMs].join("|");
  } catch (e) {
    throw new SandboxError(`could not stat the kern binary at '${bin}': ${e.message}`);
  }
  if (VERIFIED_KERN.has(key)) return KERN_VERSION_LINE.get(key) || "";
  const hint =
    "If this is not the kern you meant, set $KERN_BIN to the right path. To install kern:\n" +
    "    curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh";
  // Generous on purpose: a loaded machine must not be told its kern is fake. `--version` writes one
  // line, so a binary that cannot answer in ten seconds is not one to trust with a box.
  const out = spawnSync(bin, ["--version"], { encoding: "utf8", timeout: 10000 });
  if (out.error && out.error.code === "ETIMEDOUT")
    throw new SandboxError(
      `'${bin}' did not answer \`--version\` within 10s, so it cannot be identified as kern. ${hint}`,
    );
  if (out.error) throw new SandboxError(`could not run '${bin} --version': ${out.error.message}. ${hint}`);
  const first = String(out.stdout || "").trim().split("\n")[0] || "";
  if (out.status !== 0 || !first.startsWith("kern ")) {
    const shown = first ? JSON.stringify(first.slice(0, 120)) : "(no output)";
    throw new SandboxError(
      `'${bin}' is not kern: \`${bin} --version\` exited ${out.status} and printed ${shown}, where kern ` +
        "prints a line beginning 'kern '. Refusing to run code, because a binary that is not kern would " +
        `return an EMPTY, SUCCESSFUL result for every call and the code would never run. ${hint}`,
    );
  }
  VERIFIED_KERN.add(key);
  KERN_VERSION_LINE.set(key, first);
  return first;
}

/** The `kern` this package's npm tarball carries for this machine, or null.
 *
 * The published package carries kern's static release binary for Linux x64 and arm64 under
 * `bin/linux-<arch>/kern`, the same file `install.sh` serves for the same tag, so `npm install
 * kern-sandbox` is the whole install there and the binding drives the kern it was published with.
 * Mirrors `_bundled_kern`, which finds the Linux wheel's copy.
 *
 * FOUND NEXT TO THIS FILE AND NOWHERE ELSE. A kern taken by position from some other directory can be
 * a copy installed by hand months earlier; `root` is the package's own directory, so only a binary
 * this package brought is taken. A source checkout has no `bin/` and falls through to PATH. A file
 * that is there but cannot be executed (a `noexec` mount, an archive-backed install) falls through
 * too, rather than failing a call that a `kern` on PATH could serve. `root` is a parameter for the
 * tests only. */
function bundledKern(root = __dirname) {
  if (process.platform !== "linux") return null;
  const cand = path.join(root, "bin", `linux-${process.arch}`, "kern");
  try {
    fs.accessSync(cand, fs.constants.X_OK);
    return fs.statSync(cand).isFile() ? cand : null;
  } catch {
    return null;
  }
}

/** Locate `kern`: $KERN_BIN if set, else the kern this package carries (see `bundledKern`), else the
 * first `kern` on $PATH. The result is also IDENTIFIED as kern (see `verifyIsKern`): being executable
 * and being named `kern` are not the same as being kern. `root` is for the tests only. */
function findKern(root = __dirname) {
  const env = process.env.KERN_BIN;
  if (env) {
    try {
      fs.accessSync(env, fs.constants.X_OK);
      if (!fs.statSync(env).isFile()) throw new Error("not a file");
    } catch {
      throw new SandboxError(`$KERN_BIN='${env}' is not an executable file`);
    }
    verifyIsKern(env);
    return env;
  }
  const bundled = bundledKern(root);
  if (bundled) {
    verifyIsKern(bundled);
    return bundled;
  }
  const exts = [""];
  const dirs = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  for (const d of dirs) {
    for (const ext of exts) {
      const cand = path.join(d, "kern" + ext);
      try {
        fs.accessSync(cand, fs.constants.X_OK);
        if (fs.statSync(cand).isFile()) {
          verifyIsKern(cand);
          return cand;
        }
      } catch {
        /* keep looking */
      }
    }
  }
  // On macOS the generic "install it" is a dead end: there is no macOS build to install. kern needs
  // a Linux kernel, so the answer is a VM, and inside one the same `npm install` brings kern.
  if (process.platform === "darwin")
    throw new SandboxError(
      "kern was not found, and this is macOS: kern is Linux-only (no namespaces, no cgroups on a " +
        "Mac), so there is no macOS build. Run your code inside a Linux VM (colima, Lima, OrbStack, " +
        "UTM) and install this package there:\n" +
        "    npm install kern-sandbox\n" +
        "On Linux x64 and arm64 that brings kern with it. Or set $KERN_BIN to a kern reachable from here.",
    );
  // THE COMMAND, NOT A LINK. Reached on Linux only when this copy carries no binary for the machine:
  // an architecture the package has no kern for, or a source checkout. The installer is the same
  // line the Python binding and the project's README give, so the three cannot drift apart.
  throw new SandboxError(
    `kern was not found: this copy of kern-sandbox carries no kern binary for linux-${process.arch} ` +
      "(the npm package carries one for x64 and arm64) and there is none on PATH. Install kern with:\n" +
      "    curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh\n" +
      "or point $KERN_BIN at a kern you already have.",
  );
}

// The box root is read-only (`--ro`, always), so every path a workload can write is one we granted.
// `/tmp` was not granted, and both halves of what that cost were measured rather than assumed:
//   * anything NAMING /tmp fails with EROFS, which is how a toolchain reaches it. Measured on
//     `golang:1.23-alpine`: `go build` reported "failed to initialize build cache at /root/.cache:
//     read-only file system" and printed nothing else useful;
//   * anything using a temp-dir helper silently moves into the WORKSPACE, because the last-resort
//     candidate is the current directory, so temp files land on the caller's persistent host
//     directory and then show up in `listFiles`.
// A tmpfs and not a host bind ON PURPOSE: tmpfs pages are charged to the box's memory cgroup, so a
// runaway writer hits a cap the caller already set; a bound host directory is bounded by nothing.
const DEFAULT_TMPFS_MB = 64;
const DEFAULT_TMPFS = { "/tmp": `${DEFAULT_TMPFS_MB}m` };

// A tmpfs size as kern's `--tmpfs path[:size]` takes it. ANCHORED and unit-restricted: the value is
// concatenated after a colon into one argv element, so anything carrying a comma, a space or a second
// flag is refused here rather than reinterpreted downstream.
//
// THE UNIT IS MANDATORY, and a leading zero is refused, because kern's CLI accepts two spellings that
// mean the opposite of what an SDK caller writing them means. Both measured:
//   * `"64"` is 64 BYTES, not 64 MiB: `df` reports 4 KB and a 100 KB write is ENOSPC.
//   * `"0"` is UNLIMITED, not none: 200 MiB written under `memoryMb: 128` OOM-killed the box (137).
// kern is right to take both, it is the low-level interface; here they fail far from their cause.
const TMPFS_SIZE_RE = /^[1-9][0-9]*[kmgtKMGT]$/;

// A tmpfs over these hides something the box needs, and silently: one at /workspace would shadow the
// workspace bind, so every file the caller wrote would stay on the host and none would be visible.
const REFUSED_TMPFS_TARGETS = new Set(["/", "/proc", "/sys", "/dev", WORKSPACE]);

/** Validate one in-box tmpfs; returns the normalised `[target, size]`. The caller composes the
 * argument, because the size still has to be resolved against the memory cap and that resolution
 * PARSES it, so it may only run on a value this function has already accepted. */
function validateTmpfs(target, size) {
  if (typeof target !== "string" || !target.startsWith("/"))
    throw new MountRefused(`tmpfs target must be an absolute path in the box, got ${JSON.stringify(target)}`);
  if (target.split("/").some((c) => c === ".."))
    throw new MountRefused(`tmpfs target must not contain '..': ${JSON.stringify(target)}`);
  // A colon is the SEPARATOR in `--tmpfs path[:size]`, so a path carrying one is reinterpreted
  // rather than rejected. Measured: `tmpfs: ["/scratch:9g"]` mounted `/scratch` at 9 GiB and the
  // directory the caller actually named did not exist in the box. kern cannot fix this without
  // breaking its own syntax; the SDK can refuse.
  if (target.includes(":"))
    throw new MountRefused(
      `tmpfs target must not contain ':': ${JSON.stringify(target)}. It is the size separator in ` +
        "kern's `--tmpfs path[:size]`, so this path would be read as a size and a different " +
        "directory would be mounted.",
    );
  const norm = "/" + target.split("/").filter((c) => c && c !== ".").join("/");
  if (REFUSED_TMPFS_TARGETS.has(norm))
    throw new MountRefused(
      `cannot mount a tmpfs over ${JSON.stringify(norm)}: it would hide the box's own mount there ` +
        "(the workspace bind, or an essential filesystem)",
    );
  if (size === null || size === undefined) return [norm, null];
  if (typeof size !== "string" || !TMPFS_SIZE_RE.test(size)) {
    let hint = "";
    if (typeof size === "string" && /^[0-9]+$/.test(size))
      hint = Number(size) === 0
        ? " A zero size means UNLIMITED to kern, not none: for none, pass tmpfs: {}."
        : " A bare number is BYTES to kern, not MiB: '64' gives a 4 KB filesystem and the first real write is ENOSPC.";
    throw new MountRefused(
      `invalid tmpfs size ${JSON.stringify(size)} for ${JSON.stringify(norm)}: expected a number ` +
        `with a k/m/g/t unit, e.g. '64m'.${hint}`,
    );
  }
  return [norm, size];
}

const TMPFS_UNIT_MIB = { k: 1 / 1024, m: 1, g: 1024, t: 1024 * 1024 };

/** A validated `64m`/`1g` size as MiB. Only ever called after `TMPFS_SIZE_RE` matched. */
function tmpfsMib(size) {
  return parseInt(size.slice(0, -1), 10) * TMPFS_UNIT_MIB[size.slice(-1).toLowerCase()];
}

/** Resolve a scratch size against the memory cap AT CONSTRUCTION, not at the first write.
 *
 * A tmpfs larger than the cap is a number the KERNEL then tells the workload: `df` reports the tmpfs
 * size, so a `"1t"` scratch shows 1.0T free under a 128 MiB cap. Anything that preflights with
 * `statvfs` plans against that and is OOM-killed instead of getting a clean ENOSPC. The wrong answer
 * goes to a PROGRAM, which acts on it, and no message reaches a person.
 *
 * A size the CALLER wrote is refused, naming both numbers; OUR default is clamped, because adjusting
 * a number we chose is not overriding anyone and refusing it would make a box unstartable for someone
 * who never mentioned scratch. The clamp is `min(64 MiB, memoryMb / 2)` and it is a HEURISTIC, not a
 * derivation: it only ever REDUCES our own 64 MiB, so `memoryMb: 512` still gets 64 and not 256.
 * There is no safe fraction to derive, because the safe one depends on the workload's own peak, which
 * is what `memoryMb` was meant to bound and now shares. Half is where the measurement stops being
 * fatal: writing in 1 MiB chunks under `memoryMb: 128`, a 32m and a 64m tmpfs both end in ENOSPC, a
 * 128m one ends in an OOM, because filling a tmpfs equal to the cap exhausts the whole budget. */
function tmpfsSizeVsCap(target, size, memoryMb, ours) {
  if (size === null || size === undefined || memoryMb === null || memoryMb === undefined) return size;
  if (ours) {
    const capped = Math.max(1, Math.min(Math.trunc(tmpfsMib(size)), Math.floor(memoryMb / 2)));
    return capped >= tmpfsMib(size) ? size : `${capped}m`;
  }
  if (tmpfsMib(size) <= memoryMb) return size;
  throw new MountRefused(
    `tmpfs ${JSON.stringify(size)} at ${JSON.stringify(target)} is larger than memoryMb=${memoryMb}, ` +
      `and a tmpfs is charged to that same cap. \`df\` inside the box would report ${size} free while ` +
      `only ${memoryMb}m is reachable, so a program that checks free space before writing plans ` +
      "against a number that OOM-kills it instead of returning ENOSPC. Lower the tmpfs or raise memoryMb.",
  );
}

/** Normalise `tmpfs` to [target, size|null] pairs. `undefined`/`null` = the binding default. */
function tmpfsItems(spec) {
  if (spec === undefined || spec === null) return Object.entries(DEFAULT_TMPFS);
  if (typeof spec === "string")
    throw new MountRefused(
      `tmpfs must be an object or an array of paths, not a bare string: write ` +
        `tmpfs: { ${JSON.stringify(spec)}: "64m" } or tmpfs: [${JSON.stringify(spec)}]`,
    );
  if (Array.isArray(spec)) return spec.map((t) => [t, null]);
  // A NUMBER is the mistake this API invites: every neighbour takes one (`memoryMb: 512`,
  // `pids: 256`), so `tmpfs: 256` is the natural thing to type. `Object.entries(256)` is `[]`, so it
  // used to mean SILENTLY NO SCRATCH: a read-only /tmp, no error, and the defect back in full.
  if (typeof spec !== "object")
    throw new MountRefused(
      `tmpfs must be an object of path -> size or an array of paths, got ${typeof spec}.` +
        (typeof spec !== "number"
          ? ""
          : spec === 0
            ? " For no scratch at all, pass tmpfs: {}."
            : ` Did you mean tmpfs: { "/tmp": "${spec}m" }?`),
    );
  return Object.entries(spec);
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
  for (const [state, what] of kernStateDirs()) {
    let sreal;
    try { sreal = fs.realpathSync(state); } catch { sreal = state; }
    if (real === sreal || real.startsWith(sreal + path.sep))
      throw new MountRefused(
        `refusing to mount ${JSON.stringify(real)}: it is ${what}. Mounting kern's own state into a box ` +
          "it started gives the code inside the sandbox's control plane, which is the same reason the " +
          "docker socket is refused",
      );
  }
  const parts = real.split(path.sep);
  let hit = parts.find((p) => REFUSED_MOUNT_COMPONENTS.has(p));
  if (hit === undefined)
    // The `parent/child` form, consecutive so `~/.config/gh` is refused and `~/gh` is not.
    for (let i = 0; i + 1 < parts.length; i++) {
      const pair = `${parts[i]}/${parts[i + 1]}`;
      if (REFUSED_MOUNT_PAIRS.has(pair)) {
        hit = pair;
        break;
      }
    }
  if (hit !== undefined)
    throw new MountRefused(
      `refusing to mount ${JSON.stringify(real)}: ${JSON.stringify(hit)} holds credentials, and code ` +
        "in the box would read them. If the job needs one secret, write THAT FILE into the workspace " +
        "(sbx.writeFile) or mount a directory that holds only it",
    );
  return [real, target];
}

// A resource-profile token (`vcpu:`/`vgpio:`/`vdisk:` + a named profile from the user's kern.toml).
// ANCHORED and charset-restricted: the token is passed as a POSITIONAL arg to `kern box`, so it must be
// EXACTLY a known prefix plus a safe name. This is what stops a caller (or agent-chosen value) from
// smuggling another flag through the profile list ("--net", "-v /etc:/etc", "vgpu:x", a name with a
// space / `=` / `/` / leading dash). The three prefixes mirror `config::classify` in kern.
const PROFILE_RE = /^(?:vcpu|vgpio|vdisk):[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Validate one `vcpu:`/`vgpio:`/`vdisk:NAME` resource-profile token before it reaches the argv. */
function validateProfile(token) {
  if (typeof token !== "string" || !PROFILE_RE.test(token))
    throw new SandboxError(
      `invalid resource profile ${JSON.stringify(token)}: expected 'vcpu:NAME', 'vgpio:NAME' or ` +
        "'vdisk:NAME' with an alphanumeric profile name (the profile must be defined in your kern.toml)",
    );
  return token;
}

// A public DNS domain for the egress allowlist. LDH labels, at least one dot (an FQDN), alphabetic TLD.
// Restrictive on purpose: the value is comma-joined and handed to `kern box --egress-allow`, so it must
// not carry a comma, scheme, path, port, wildcard or whitespace that could change the argument. kern
// re-validates and SSRF-checks the resolved IPs; this is the binding's first gate.
const DOMAIN_RE = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

// A Linux capability name for `kern box --cap-drop`, with or without the CAP_ prefix, or the literal
// ALL. Underscore-JOINED uppercase segments rather than "any of [A-Z0-9_]": the looser form accepts
// "CAP_", because the optional prefix does not have to consume it. Not a way to smuggle a flag, but
// a name kern rejects at box start, and validating here exists to fail at construction instead.
const CAP_RE = /^(?=.{1,32}$)(?:CAP_)?[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/;

/** Validate one egress-allowlist domain (an FQDN like "pypi.org") before it reaches the argv. */
function validateDomain(domain) {
  if (typeof domain !== "string" || !DOMAIN_RE.test(domain))
    throw new SandboxError(
      `invalid egress domain ${JSON.stringify(domain)}: expected a bare hostname like 'pypi.org' ` +
        "(no scheme, port, path, wildcard or spaces)",
    );
  return domain;
}

/** Validate one capability name for `--cap-drop` before it reaches the argv. */
function validateCap(name) {
  if (typeof name !== "string" || !CAP_RE.test(name))
    throw new SandboxError(
      `invalid capability ${JSON.stringify(name)}: expected 'ALL' or an uppercase capability name ` +
        "such as 'NET_BIND_SERVICE' or 'CAP_NET_BIND_SERVICE'",
    );
  return name;
}

// An AppArmor profile name for `kern box --apparmor`. Same discipline as validateCap: handed to kern as
// its own argv element, so it must not start with a dash (-> another flag) or carry a space. Letters,
// digits and ._- cover ordinary profile names (docker-default, unconfined, kern-box); kern fails closed
// if the profile is not loaded. Namespaced names with / or : are intentionally not accepted here (use
// the CLI). Compared byte-for-byte with the Python binding's _APPARMOR_RE by a parity test - keep them
// identical and free of chars that need escaping in a regex literal (e.g. /).
const APPARMOR_RE = /^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,127}$/;

/** Validate an AppArmor profile name for `--apparmor` before it reaches the argv. */
function validateApparmor(name) {
  if (typeof name !== "string" || !APPARMOR_RE.test(name))
    throw new SandboxError(
      `invalid AppArmor profile ${JSON.stringify(name)}: expected a loaded profile name like ` +
        "'docker-default' or 'unconfined' (letters, digits and ._-, not starting with a dash)",
    );
  return name;
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
const EXEC_FAILED_RE = /^kern: cannot start '([^']+)' in box: ([^\n]*)/m;

/** The binary kern could not exec, or null.
 *
 * A THIRD state, and the reason this exists: kern signals "box started" on its unforgeable fd BEFORE
 * it execs the workload, so an `execve` that fails with ENOENT leaves a box that demonstrably started
 * and a command that never ran. The classifier gets that right (kern's own marker is on stderr, so it
 * says `startup_failed`) and the caller then ERASES it, because "box started + a kern: marker" is its
 * signal that a WORKLOAD forged the marker. For this case that inference is wrong: the workload never
 * ran, so it cannot have written anything.
 *
 * Matched on kern's own wording rather than on exit 127 alone, because 127 is also what a shell
 * returns for `command not found` inside a script the user wrote, which IS the user's failure.
 *
 * A workload CAN print this line and exit 127 to be labelled `exec_failed` instead of a plain
 * failure. That is accepted: it downgrades nothing security-relevant, because timeout, OOM and
 * blocked-escape are decided by EXIT CODE before any stderr is read. */
function execFailureBinary(stderr) {
  const m = EXEC_FAILED_RE.exec(stderr || "");
  return m ? { what: m[1], reason: (m[2] || "").trim() } : null;
}

/** The prefixes of stderr lines KERN writes about itself, as opposed to lines the workload wrote: the
 * `--security-profile` posture banner and any `warning:`/`note:` diagnostic.
 *
 * ONE definition, used for two purposes that must agree by construction: `codeStderr` subtracts these
 * to build what a model should read, and `looksLikeStartupFailure` skips them so a benign note is not
 * read as a box that failed to start. Mirrors `_KERN_DIAGNOSTICS` in the Python binding. */
const KERN_DIAGNOSTICS = ["kern: security-profile=", "kern: warning:", "kern: note:"];

function isKernDiagnostic(line) {
  const s = line.replace(/^\s+/, "");
  return KERN_DIAGNOSTICS.some((p) => s.startsWith(p));
}

/** Why the box did not start: kern's stderr with its warning and note lines dropped, capped at 500.
 * kern writes those BEFORE the error, and inside a container (the shape Google Colab has) a ~430-
 * character warning pushed `error: sandbox: unprivileged user namespaces are unavailable` to character
 * 557, past a plain first-500 cut. Mirrors `_startup_failure_message` in the Python binding. */
function startupFailureMessage(stderr) {
  const kept = stderr.split("\n").filter((l) => !isKernDiagnostic(l)).join("\n").trim();
  return (kept || stderr.trim()).slice(0, 500);
}

/** The sentence kern prints when it has READ the kernel's OOM counter for this box's own cgroup. A
 * contract between two programs: if kern rewords it, this stops recognising a real OOM and starts
 * reporting `killed` - wrong in the safe direction, still wrong. Mirrors `_KERN_OOM_MARKER`. */
const KERN_OOM_MARKER = "killed by the kernel's OOM killer";

/** kern's KERN_STARTED_FD payload, as `{ boxStarted, capSignal, oomSignal, workloadSignal }`.
 *
 * THE WIRE FORMAT IS SPELLED HERE AND NOWHERE ELSE, because it grew twice in one day (the OOM outcome,
 * then the workload's signal) and each time a reader with its own copy of the layout was left behind.
 * Three places in this file read those bytes; they now all read them through this.
 *
 *   byte 0 = the box started (kern reached its `Ok` arm with a code that is not 125)
 *   byte 1 = the memory-cap enforcement signal: 0 undetermined, 1 enforced, 2 requested but not enforced
 *   byte 2 = the OOM outcome: 1 iff the kernel's OOM killer fired against this box's own cgroup
 *   byte 3 = the signal that terminated the workload, 0 if it exited on its own
 *
 * A SHORT buffer is an OLDER kern, not a malformed one, and the two OUTCOME bytes read `null` when
 * absent rather than 0: for them "kern did not say" and "kern said no" are different facts and a caller
 * acts differently on each. The enforcement byte keeps 0, which already spells "undetermined".
 *
 * THE OOM BYTE LEARNED THIS THE EXPENSIVE WAY: it returned 0 for both, so an older binary could only be
 * supported by reading the stderr sentence whenever the byte was not 1, including against a binary that
 * had just said 0. See `oomVerdict`. Mirrors `_parse_started_bytes`. */
/** Did the kernel's OOM killer take this box? The ONE place the byte and the sentence are combined.
 *
 * Three states, each naming what the SUBJECT did: the byte arrived, so it decides and the sentence is
 * not read; no byte and kern wrote NOTHING, so kern never reached the teardown where it would have
 * printed the sentence either and an OOM line in this stderr is the workload's own text; no byte but a
 * payload was written, so this is a binary older than the byte reporting through its only channel.
 *
 * MEASURED on 2026-09-12 with the four-byte binary, when these were combined by `||`: a cell that wrote
 * kern's own OOM sentence to stderr and was then stopped from outside came back `fault=oom` while the
 * third byte said 0 - the inverted verdict the byte exists to close, re-opened by the sandboxed code in
 * one line. Preferring the byte was not enough on its own: an outside kill takes the box BEFORE
 * teardown, so a new binary also arrives with no byte. The remaining bound is measured: against v0.9.32
 * a cell that writes the sentence and then chooses `exit 137` reports `oom`, and without the sentence
 * `killed`. Mirrors `_oom_verdict`. */
function oomVerdict(oomSignal, stderr, kernWrotePayload) {
  if (oomSignal !== null && oomSignal !== undefined) return oomSignal === 1;
  if (!kernWrotePayload) return false;
  return kernReportedOom(stderr);
}

function parseStartedBytes(buf) {
  const b = buf || Buffer.alloc(0);
  return {
    boxStarted: b.length >= 1 && b[0] === 1,
    capSignal: b.length >= 2 ? b[1] : 0,
    oomSignal: b.length >= 3 ? b[2] : null,
    workloadSignal: b.length >= 4 ? b[3] : null,
  };
}

/** The byte kern writes to `KERN_ALIVE_FD` the moment it accepts the descriptor, before any box setup.
 * It is what tells "the setup has not finished" from "this binary does not speak the protocol": an older
 * kern never writes to that pipe AND never closes it, so the pipe is open and silent in both cases.
 * Mirrors `_ALIVE_ACK`. */
const ALIVE_ACK = 0x41; // 'A'

/** Where kern was when the deadline fired, read off the `KERN_ALIVE_FD` pipe. Spelled once so a caller
 * cannot invent a fourth answer. Mirrors the `_ALIVE_*` constants in the Python binding. */
const ALIVE_PAST_SETUP = "past-setup"; // the workload ran (EOF at execvp), or kern reported setup failed
const ALIVE_IN_SETUP = "in-setup"; // kern acknowledged the channel and is still BUILDING the box
const ALIVE_UNKNOWN = "unknown"; // nothing on the pipe: a kern that predates this channel

/** True iff KERN said the kernel's OOM killer took this box against its own memory cap.
 *
 * The ONE definition of "this was an OOM", used by all three death paths (the one-shot exit-code
 * classifier, the resident kernel's death, and a pool box that died) so they cannot drift into
 * disagreeing about the same box. It is an OBSERVATION - kern reads `memory.events` and says so -
 * where the SDK can only infer, and the inference it replaced was MEASURED wrong in both directions:
 * `kern stop` during a cell was reported `oom`, while a real OOM on the resident kernel was reported
 * as a box that failed to start (and raised).
 *
 * Anchored on kern's `kern:` line prefix, which the real line carries (measured verbatim: `kern: the
 * workload was killed by the kernel's OOM killer against this box's own memory cap.`), MINUS the
 * benign diagnostics - `kern: note: <quoting the sentence>` is kern TALKING about an OOM, not
 * reporting one.
 *
 * THE FALLBACK, NOT THE AUTHORITY. Against a kern that writes the 3rd KERN_STARTED_FD byte the verdict
 * comes from there instead, on a pipe the workload never holds. This covers an older binary, and it is
 * forgeable in exactly one direction: a workload that writes the whole prefixed sentence itself turns its
 * own `killed` into `oom`. Both are sandbox faults, and timeout / blocked-escape are decided by exit code
 * before any text is read, so the worst case is a caller misleading itself about its own kill.
 * Mirrors `_kern_reported_oom`. */
function kernReportedOom(stderr) {
  for (const line of String(stderr || "").split("\n")) {
    const s = line.replace(/^\s+/, "");
    if (s.startsWith("kern:") && !isKernDiagnostic(s) && s.includes(KERN_OOM_MARKER)) return true;
  }
  return false;
}

/** The two prefixes kern's CLI writes AT COLUMN 0, which is the whole vocabulary of "kern is speaking".
 * `kern-cli/src/main.rs` reports every error through one `eprintln!("error: {}", ...)` and
 * `ui::scrub_message` indents every continuation line so a hostile value inside a message cannot forge a
 * line at column 0. Mirrors `_KERN_SPEAKING`.
 *
 * WHAT THIS REPLACED: a list of eleven message OPENINGS, each added after a caller measured a
 * `fault: null`. Enumerating the error texts of a binary with hundreds of them behind one printer cannot
 * be finished, and an independent test ended the argument with `image: ""`, whose
 * `error: bad image reference: empty` was in none of the eleven. */
const KERN_SPEAKING = ["error: ", "kern:"];

/** True iff KERN ITSELF reported an error on this box, rather than the workload failing.
 *
 * It does NOT decide forgery from the text: a workload can print `error: anything` at column 0, and no
 * list of openings ever stopped that. The `KERN_STARTED_FD` byte does, and the callers pair it with this
 * predicate (`_runOne` drops a `startup_failed` when kern signalled a start; the kernel paths ask the
 * byte first). Mirrors `_looks_like_startup_failure`. */
function looksLikeStartupFailure(stderr) {
  // kern's BENIGN lines are subtracted first, which is why this cannot be a bare prefix test: the
  // posture banner and `warning:`/`note:` carry `kern:` too. The OOM sentence is skipped for a sharper
  // reason: it is a report about a box that RAN, and MEASURED that is how a real OOM on a resident
  // kernel came back as `startup_failed` and was THROWN instead of returning an `oom` fault.
  for (const line of stderr.split("\n")) {
    if (isKernDiagnostic(line) || kernReportedOom(line)) continue;
    if (KERN_SPEAKING.some((m) => line.startsWith(m)) || line.includes("sandbox setup failed")) return true;
  }
  return false;
}

function uniqueName() {
  return "jssbx-" + crypto.randomBytes(6).toString("hex");
}

/** Drain a readable stream into a bounded buffer: keep at most `cap` bytes but KEEP reading past it
 * (discarding overflow) so a flooding box never blocks on a full pipe. RAM is bounded to `cap`. */
function cappedCollector(stream, cap, onData) {
  const chunks = [];
  let len = 0;
  const state = { truncated: false };
  stream.on("data", (chunk) => {
    if (onData) {
      // stream every chunk live; a callback throw must never break the drain (the box would then
      // block on a full pipe), so swallow it, the buffered result still returns.
      try {
        onData(chunk);
      } catch {
        /* user callback error ignored on purpose */
      }
    }
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

// --- Minimal ustar (POSIX tar) over gzip, for workspace snapshots -------------------------------
// Dependency-free (Node's zlib does the gzip) and interoperable with `tar tzf` and the Python binding:
// a snapshot is a real .tar.gz. Only regular files are written; on restore only files/dirs are accepted
// (symlinks, devices, hardlinks and any absolute or `..`-escaping name are refused), and the final
// component is opened O_NOFOLLOW, so a hostile archive can never write outside the workspace.

/** The largest value an 11-digit octal ustar field can hold: 8^11 - 1, i.e. mtimes up to year 2242.
 *
 * A value past this does not fit the field, and writing it anyway would produce a 12-digit number
 * that overruns into the checksum field - a header whose checksum still verifies and whose date is
 * wrong. Clamped on the way in and on the way out (`tarParseRaw`), so neither side can emit one. */
const TAR_MAX_OCTAL = 8 ** 11 - 1;

/** `value` as the 11 octal digits + NUL that a ustar numeric field holds, clamped to the field.
 *
 * Non-finite, negative and fractional inputs are the ones a `stat` can really produce on a file with
 * no usable timestamp, so each is resolved rather than trusted: `Math.floor` of a non-finite value is
 * `NaN`, and `NaN.toString(8)` is the string "NaN", which would corrupt the header silently. */
function tarOctalField(value) {
  let n = Number(value);
  if (!Number.isFinite(n) || n < 0) n = 0;
  n = Math.min(Math.floor(n), TAR_MAX_OCTAL);
  return `${n.toString(8).padStart(11, "0")}\0`;
}

/** Split `name` into the ustar `prefix` (155 bytes) and `name` (100 bytes) fields, or `null` when it
 * cannot be expressed in ustar at all.
 *
 * WHY THIS EXISTS: the writer refused every path over 100 bytes while `tarParseRaw` has read the
 * `prefix` field since this branch - so Node could not WRITE what it can READ, and a Python-written
 * snapshot with a 101-to-255-byte path (which Python's USTAR writer splits exactly this way) threw
 * from Node's own re-emission path AFTER part of the tree had been written.
 *
 * The split point must be a `/`, which is what makes it safe for any encoding: `/` is one byte in
 * UTF-8 and never appears inside a multibyte sequence, so neither field can end mid-character. The
 * LAST `/` that leaves a tail of at most 100 bytes is chosen, which is the same rule GNU tar and
 * Python's `tarfile` apply, so a path either binding writes is read back identically by the other. */
function tarSplitName(name) {
  const raw = Buffer.from(name, "utf8");
  if (raw.length <= 100) return { prefix: "", name };
  if (raw.length > 255) return null; // 155 + 1 separator + 100: beyond ustar, whatever the split
  for (let i = raw.length - 101; i < raw.length; i++) {
    // `i` is the index of a candidate separator; the tail after it must fit `name` (<= 100) and the
    // head before it must fit `prefix` (<= 155).
    if (raw[i] !== 0x2f) continue;
    const head = raw.subarray(0, i);
    const tail = raw.subarray(i + 1);
    if (head.length === 0 || head.length > 155 || tail.length === 0 || tail.length > 100) continue;
    return { prefix: head.toString("utf8"), name: tail.toString("utf8") };
  }
  return null;
}

/** One ustar header, for both member kinds: THE ONLY PLACE the layout is spelled.
 *
 * It was spelled twice, once per member kind, and the two copies had already drifted in the one field
 * that matters here (both wrote a constant mtime, but a future change to one would not reach the
 * other). `mode`, `typeflag` and `size` are the only differences between the two callers.
 *
 * Returns the 512-byte header, or a `SandboxError` for a name ustar cannot carry - the error names
 * which of the two limits was hit, because the remedy differs (shorten a component, or shorten the
 * path). */
function tarHeader(name, { mode, typeflag, size, mtime }) {
  const split = tarSplitName(name);
  if (split === null) {
    const raw = Buffer.byteLength(name, "utf8");
    throw new SandboxError(
      raw > 255
        ? `snapshot: path too long for the tar format (${raw} bytes, the limit is 255): ${name}`
        : `snapshot: path cannot be split for the tar format (${raw} bytes with no '/' that leaves ` +
          `a tail of 100 bytes or less): ${name}`,
    );
  }
  const h = Buffer.alloc(512);
  h.write(split.name, 0, 100, "utf8");
  h.write(mode, 100, 8);
  h.write("0000000\0", 108, 8); // uid: 0, never the host's. See `tarCollect`.
  h.write("0000000\0", 116, 8); // gid: 0, same reason
  h.write(tarOctalField(size), 124, 12);
  h.write(tarOctalField(mtime), 136, 12);
  h.write("        ", 148, 8); // checksum field = 8 spaces while summing
  h.write(typeflag, 156, 1);
  h.write("ustar\0", 257, 6); // magic
  h.write("00", 263, 2); // version
  if (split.prefix) h.write(split.prefix, 345, 155, "utf8");
  let sum = 0;
  for (const b of h) sum += b;
  h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8); // 6 octal digits, NUL, space
  return h;
}

/** A regular-file member: its bytes, and the MTIME IT HAD.
 *
 * The mtime was a constant 0, with "deterministic" as the reason, and that reason had no consumer:
 * nothing in either package's tests, READMEs or docs asserts a byte-identical archive, while
 * `docs/SANDBOX.md` does promise that a snapshot moves "the files the code wrote" to another machine.
 * MEASURED against the Python binding, same tree, same archive: Python restored `2020-09-13 14:26`
 * (the mtime the files had) and Node restored the moment of the restore, so an incremental tool -
 * `make`, `tsc --incremental`, `pytest --lf`, and CPython's own `(mtime, size)` check on a `.pyc` in
 * `.deps` - saw a different tree depending on which binding had restored it. */
function tarWriteFile(out, name, content, mtime = 0, fileMode = 0o644) {
  const h = tarHeader(name, {
    // THE MODE THE FILE HAD, owner bits and all, because `restore` reads it: a constant 0644 here
    // meant an executable file came back without its execute bit, measured against the Python
    // binding, which carries the real mode. Masked to the owner's bits for the reason the restore
    // states: on a workspace shared with a box account the group bits are the ACL's mask, and the
    // ACL does not travel in a tar.
    mode: `${(0o600 | (fileMode & 0o700)).toString(8).padStart(7, "0")}\0`,
    typeflag: "0",
    size: content.length,
    mtime,
  });
  out.push(h, content);
  const pad = (512 - (content.length % 512)) % 512;
  if (pad) out.push(Buffer.alloc(pad));
}

/** The workspace under `dirFd` (as `rel`), archived into `out` BY DESCRIPTOR: each entry listed through
 * `/proc/self/fd/<dir>`, opened `O_NOFOLLOW` relative to it, and judged on the open descriptor. By path,
 * a box running beside the snapshot could turn a directory into a symlink after the check and have the
 * next read archive a HOST file. Regular files only, as this format always held; symlinks never.
 * `blind`, on a shared workspace, collects what the box user closed to this process instead of failing
 * on it; null is the old behaviour, every error raised. */
function tarCollect(dirFd, rel, skipId, out, blind, skipped) {
  const nofollow = fs.constants.O_NOFOLLOW;
  const closed = (e, at) => {
    if (!blind || !isClosedErr(e)) throw e;
    blind.push(at);
  };
  let names;
  try {
    names = fs.readdirSync(`/proc/self/fd/${dirFd}`).sort();
  } catch (e) {
    closed(e, rel);
    return;
  }
  for (const entry of names) {
    const at = `/proc/self/fd/${dirFd}/${entry}`;
    const child = rel ? `${rel}/${entry}` : entry;
    let st;
    try {
      st = fs.lstatSync(at);
    } catch (e) {
      if (e.code === "ENOENT") continue;
      closed(e, rel); // listable, not searchable: the helper takes it whole
      return;
    }
    // ONLY WHAT restore() WRITES: regular files and directories. A symlink, FIFO, device or socket is
    // named in `skipped` instead, so the caller can say the archive is not the whole tree; it was left
    // out in silence, and the Python binding archived it as a member its own restore refused whole.
    if (!st.isDirectory() && !st.isFile()) {
      if (skipped) skipped.push(child);
      continue;
    }
    if (st.isDirectory()) {
      let fd;
      try {
        fd = fs.openSync(at, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | nofollow);
      } catch (e) {
        if (["ENOENT", "ELOOP", "ENOTDIR"].includes(e.code)) continue; // swapped since the lstat
        closed(e, child);
        continue;
      }
      try {
        // THE MEMBER FIRST, THEN ITS CHILDREN: an extractor creates a directory before writing into
        // it either way, and this order is what makes an EMPTY directory a member of its own. The
        // mtime comes from the OPEN descriptor, not from the `lstat` by name above, so a directory
        // swapped between the two cannot contribute a timestamp from somewhere else.
        const dst = fs.fstatSync(fd);
        if (dst.isDirectory()) tarWriteDir(out, child, Math.floor(dst.mtimeMs / 1000));
        tarCollect(fd, child, skipId, out, blind, skipped);
      } finally {
        fs.closeSync(fd);
      }
    } else if (st.isFile()) {
      // An env file an OLDER version left in the workspace holds `env` values: never archived.
      if (isLegacyEnvFile(child)) continue;
      let fd;
      try {
        fd = fs.openSync(at, fs.constants.O_RDONLY | nofollow | fs.constants.O_NONBLOCK);
      } catch (e) {
        if (["ENOENT", "ELOOP"].includes(e.code)) continue;
        closed(e, child);
        continue;
      }
      try {
        const fst = fs.fstatSync(fd);
        // The archive's previous self, when `dest` is inside the workspace: skipped by identity, or
        // every checkpoint would carry the one before it.
        //
        // The mtime is read from the SAME `fstat` that decides the type, i.e. from the descriptor
        // this function holds, so the timestamp belongs to the inode whose bytes are being archived.
        if (fst.isFile() && `${fst.dev}:${fst.ino}` !== skipId)
          tarWriteFile(out, child, fs.readFileSync(fd), Math.floor(fst.mtimeMs / 1000), fst.mode);
      } finally {
        fs.closeSync(fd);
      }
    }
  }
}

/** The most a snapshot may inflate to, and the most a helper's `tar` may hand back: 1 GiB. */
const TAR_MAX_BYTES = 1024 * 1024 * 1024;

/** Close an archive: two zero blocks, then gzip at level 1 (a local checkpoint is often large or
 * already compressed, and level 1 is several times faster for a negligible size penalty). */
function tarFinish(out, gzip = true) {
  const raw = Buffer.concat([...out, Buffer.alloc(1024)]);
  return gzip ? zlib.gzipSync(raw, { level: 1 }) : raw;
}

function tarPack(base, skip) {
  const out = [];
  const fd = fs.openSync(base, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try {
    tarCollect(fd, "", skip, out, null);
  } finally {
    fs.closeSync(fd);
  }
  return tarFinish(out);
}

/** A directory member, so an archive carries an EMPTY directory too - and carries the directory
 * structure at all.
 *
 * MEASURED before the snapshot walk emitted these: a workspace holding `emptydir/` and `full/f` gave
 * a Node archive of `full/f` alone, and restoring it produced `full` and nothing else, so an empty
 * directory a session had created was silently lost. Python's archive carried `emptydir/` and `full/`
 * and restored both. `docs/SANDBOX.md` states the contract this half was missing: `restore()` writes
 * "only regular files and directories". */
function tarWriteDir(out, name, mtime = 0) {
  const dir = name.endsWith("/") ? name : `${name}/`;
  out.push(tarHeader(dir, { mode: "0000755\0", typeflag: "5", size: 0, mtime }));
}

function tarParse(gz) {
  // Cap the inflated size so a tiny gzip bomb can't force a huge allocation before we even vet members.
  return tarParseRaw(zlib.gunzipSync(gz, { maxOutputLength: TAR_MAX_BYTES }));
}

/** The members of an UNCOMPRESSED tar, vetted field by field (see `tarParse`). */
function tarParseRaw(buf) {
  const members = [];
  let off = 0;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break; // end-of-archive zero block
    // Verify the ustar header checksum (sum of all header bytes with the 8-byte checksum field taken as
    // spaces): a single corrupt header field is rejected wholesale, before the per-field vetting runs.
    const stored = parseInt(h.toString("utf8", 148, 156).replace(/\0.*$/s, "").trim(), 8);
    let ck = 0;
    for (let i = 0; i < 512; i++) ck += i >= 148 && i < 156 ? 0x20 : h[i];
    if (stored !== ck) throw new SandboxError("malformed snapshot: bad header checksum");
    // Strip a trailing slash (the ustar dir convention "d/"): otherwise path.join keeps it, and a
    // trailing slash makes lstat FOLLOW a planted symlink ("d/" resolves the link to its target dir)
    // instead of seeing the link, which would defeat the symlink-vet on a dir member.
    let name = h.toString("utf8", 0, 100).replace(/\0.*$/s, "").replace(/\/+$/, "");
    // THE `prefix` FIELD IS PART OF THE NAME, and ignoring it silently renamed a member. ustar splits
    // a path longer than 100 bytes across `prefix` (155 bytes at offset 345) and `name`, and Python's
    // USTAR writer - which is what `snapshot()` uses on the other binding - does exactly that for any
    // path of 101 to 255 bytes. Read as the name alone, such a member was written to the workspace
    // ROOT under its tail, overwriting whatever had that name, and the archive's own directory
    // structure was lost. The magic is checked first because `prefix` is only a prefix in ustar; in
    // the old v7 format those bytes are padding.
    const magic = h.toString("utf8", 257, 263).replace(/\0.*$/s, "");
    if (magic === "ustar") {
      const prefix = h.toString("utf8", 345, 500).replace(/\0.*$/s, "").replace(/\/+$/, "");
      if (prefix) name = `${prefix}/${name}`;
    }
    // Size is octal ASCII by spec; reject anything else rather than let parseInt guess ("12x" -> 10).
    // This also makes a negative size impossible (no `-` in the field), closing the spin-forever case.
    const sizeField = h.toString("utf8", 124, 136).replace(/\0.*$/s, "").trim();
    if (!/^[0-7]*$/.test(sizeField)) throw new SandboxError("malformed snapshot: non-octal member size");
    const size = parseInt(sizeField, 8) || 0;
    // THE MTIME IS RESOLVED, NOT REJECTED, and that asymmetry with `size` above is deliberate: a
    // size decides how the archive is FRAMED, so a size this reader cannot parse makes every member
    // after it a guess and the archive has to be refused. An mtime decides a timestamp on one file;
    // a field this reader cannot parse (a GNU base-256 field, which sets the high bit of the first
    // byte, or junk) means "no usable timestamp", and refusing an archive whose BYTES are fine over
    // one date would lose the data to save the metadata. Clamped to the field's own range so a
    // crafted value cannot reach `futimes` - measured on the Python side, where `1 << 70` in a
    // member raised `OverflowError` out of `restore` after part of the tree was written.
    const mtimeField = h.toString("utf8", 136, 148).replace(/\0.*$/s, "").trim();
    const mtime = /^[0-7]+$/.test(mtimeField)
      ? Math.min(parseInt(mtimeField, 8), TAR_MAX_OCTAL)
      : 0;
    // The mode, under the same rule as the mtime: a field this reader cannot parse means "no mode in
    // the archive" and the restore falls back to its own default. Only the PERMISSION bits are taken
    // (`& 0o7777`), never the type bits, which are the `typeflag`'s job - a mode field claiming
    // S_IFDIR on a `0` member must not turn the member into one.
    const modeField = h.toString("utf8", 100, 108).replace(/\0.*$/s, "").trim();
    const mode = /^[0-7]+$/.test(modeField) ? parseInt(modeField, 8) & 0o7777 : null;
    const flag = String.fromCharCode(h[156]);
    off += 512;
    // A GNU LONG NAME IS REFUSED BY NAME, not met as an "other" member whose size must be zero. `L`
    // (and `K`) carry the real path as the CONTENT of an extra header, so the member that follows has
    // a placeholder name: treating the pair as two ordinary members wrote a file called
    // `././@LongLink`. Neither binding writes them (both use USTAR), so a snapshot carrying one came
    // from somewhere else and the honest answer is to say which feature is missing.
    if (flag === "L" || flag === "K")
      throw new SandboxError(
        "unsupported snapshot: it uses GNU long-name headers, which this reader does not " +
          "implement (both bindings write ustar; re-create the snapshot with `snapshot()`)",
      );
    const type = flag === "0" || flag === "\0" ? "file" : flag === "5" ? "dir" : "other";
    // A dir/other member carries no content in ustar; a non-zero size there is malformed, so reject it
    // rather than silently ignore it (reject-not-guess).
    if (type !== "file" && size !== 0)
      throw new SandboxError("malformed snapshot: non-file member with a non-zero size");
    // Refuse a member claiming more bytes than remain: reject the malformed archive instead of silently
    // truncating the restored file (subarray would clamp to the buffer end).
    if (type === "file" && off + size > buf.length)
      throw new SandboxError("malformed snapshot: member size exceeds archive");
    const content = type === "file" ? buf.subarray(off, off + size) : Buffer.alloc(0);
    members.push({ name, type, content, mtime, mode });
    off += Math.ceil(size / 512) * 512;
  }
  return members;
}

class Sandbox {
  // The box name the `--show-config` probe uses. A FIXED placeholder: kern refuses an empty name
  // ("invalid box name: box name is empty", measured) and a per-call name would put itself in the
  // output and make every fingerprint unique.
  static FINGERPRINT_PROBE = "kern-fingerprint-probe";

  /**
   * @param {object} [opts]
   * @param {string} [opts.image]            OCI image the box runs from. Default a small Python image.
   * @param {string} [opts.setup]            shell command run ONCE at open() in a NETWORK-ENABLED box.
   * @param {string} [opts.workspace]        host dir to persist as the workspace. null -> a temp dir,
   *                                          created on open() and DELETED on close().
   * @param {number|null} [opts.memoryMb]    RAM cap (kern --memory). Default 512.
   *   ⚠️ A `memory.high` ABOVE THE BOX TURNS AN OOM INTO A STALL, and kern reports it. The
   *   cap is enforced (the box's own `memory.max` carries it and `memory.swap.max` is 0, so swap
   *   cannot defeat it), and the kernel declares the OOM fast: one cell, a 400 MiB allocation under
   *   a 128 MiB cap, was killed in 127 ms on a WSL2 kernel 6.18, 645 ms on a kernel 6.8 server and
   *   0.06 s on a Jetson Orin (kernel 5.15-tegra). That Jetson first measured 317 s because its
   *   `kern.slice` carried `MemoryHigh=80M` from an old `systemctl --user set-property`: above a
   *   `memory.high` the kernel THROTTLES instead of killing, so every box under that slice stalled
   *   past 80 MiB in total, whatever its own cap. Since `timeoutS` defaults to 30, under such a
   *   limit the CELL deadline fires first: you get a `timeout` fault rather than an `oom` one, and
   *   with `persist: true` the box dies LATER, so a subsequent call is the one that finds it gone and
   *   recreates it. kern reports such a limit when it starts a box under one: a `kern: note:` line
   *   in `result.stderr` naming the cgroup and the command that lifts it; `kern doctor` and
   *   `kern inspect` show it too. kern does not change it. Same facts as the Python binding's
   *   `memory_mb`.
   * @param {number|null} [opts.cpus]        CPU cap in cores; null = uncapped.
   * @param {number|null} [opts.pids]        task/fork-bomb ceiling. Default 256.
   * @param {number} [opts.timeoutS]         MANDATORY per-call wall-clock limit (binding-owned). Default 30.
   * @param {boolean} [opts.network]         RELAXES ISOLATION. true shares the host network. Default false.
   * @param {string[]} [opts.egressAllow]    restrict runCode/run to a DOMAIN ALLOWLIST, e.g. ["pypi.org"]; isolated netns + kern's filtering proxy. Mutually exclusive with network:true.
   * @param {Object<string, string|[string,string]>} [opts.mounts] extra host->box binds. Sensitive refused.
   * @param {Object<string,string>|string[]} [opts.tmpfs] fresh in-box scratch filesystems (kern --tmpfs). Default: a 64 MiB tmpfs at /tmp, because the root is read-only. `{}` for none; a `mounts` bind at the same target wins.
   * @param {string[]} [opts.profiles] kern resource profiles to attach, e.g. ["vcpu:heavy","vgpio:leds","vdisk:scratch"]; each names a block in your kern.toml. Strictly validated.
   * @param {Object<string,string>} [opts.env] extra environment for the workload.
   * @param {number} [opts.maxOutputBytes]   cap on captured stdout/stderr EACH. Default 64 MiB.
   * @param {boolean} [opts.enforceLimits]   true (default) hard-enforces caps via a systemd scope.
   * @param {boolean} [opts.depsReadonly]    mount setup= deps read-only for runCode (default true).
   * @param {boolean} [opts.pycCache]        compile this image's stdlib once and mount it read-only (default true).
   * @param {string|null} [opts.user]        the account of the IMAGE every box runs as, "<user>[:<group>]",
   *   each a name or a number ("node", "1000", "1000:1000"): `kern box --user`, and `kern exec -u` for a
   *   `persist` call. null (default) keeps the image's own USER. A non-root user is a uid of kern's
   *   subordinate range on disk (node, 1000 in the box, is 100999 on a host whose range starts at
   *   100000, measured), so open() starts one box as that user to learn its host uid and gives the
   *   workspace a POSIX ACL naming it, plus a DEFAULT ACL naming both uids, written with `setfacl`
   *   (the `acl` package). It costs one box at open() and the uid range on every box (measured in
   *   Python: open 5.3 ms instead of 0.5, each call +1.1 ms). What an ACL cannot outrank - a file the
   *   box user creates 0600 or a directory 0700 - is reached by readFile, writeFile, listFiles,
   *   result.files, workspaceMaxBytes, snapshot, restore and close() through a short-lived box of the
   *   same image running as THAT user, the owner of what it closed, with the session's own capDrop;
   *   only after the host was refused, and never reaching what the account could not reach itself.
   *   The image needs a shell and the usual tools (HELPER_TOOLS). Mirrors Python's `Sandbox.user`.
   */
  constructor(opts = {}) {
    this.image = opts.image ?? DEFAULT_IMAGE;
    this.setup = opts.setup ?? null;
    // `setup` is ONE SHELL COMMAND, and a list of package names is the natural first guess. Without this
    // it reaches `_runSetup` and dies as `TypeError: cmd.trim is not a function`, an internal error where
    // a sentence belongs (the Python binding had the same edge, as an AttributeError).
    if (this.setup !== null && typeof this.setup !== "string")
      throw new SandboxError(
        `setup must be a shell command STRING, not ${Array.isArray(this.setup) ? "an array" : typeof this.setup}: ` +
          'write setup: "pip install pandas matplotlib" for packages, or any one line the setup box ' +
          "should run (it runs once, with the network on)",
      );
    this.workspace = opts.workspace ?? null;
    // Refuse to start a call once the workspace holds more than this many bytes. `null` is off and
    // costs nothing: the walk only runs when a cap is set.
    //
    // ⛔ A COOPERATIVE CAP, NOT A BOUNDARY. The workspace is a host directory bind-mounted at
    // /workspace, so the box writes to the real filesystem and nothing in the kernel holds it back.
    // kern's other limits ARE boundaries, measured to the byte. This one cannot be from here: a
    // kernel-enforced quota needs a disk-backed vdisk (mkfs.ext4, root) and this binding is rootless,
    // while a size-capped tmpfs would be enforced and would NOT survive between calls, which is the
    // one thing a workspace must do. So it bounds damage ACROSS calls, not within one: the call that
    // exceeds it still runs, the next is refused. Said plainly, because a cap that sounds like a
    // boundary and is not is worse than no cap at all.
    this.workspaceMaxBytes = opts.workspaceMaxBytes ?? null;
    // A STABLE IDENTITY, used only with `persist`. Two processes that name the same sandbox meet the
    // same resident box.
    this.name = opts.name ?? null;
    // Keep ONE resident box alive and run every call inside it with `kern exec`, instead of starting
    // a throwaway box per call. Survives `close()`: that is the point, and why `destroy()` exists.
    //
    // ⭐ MEASURED: `kern exec` into a resident box is 2 ms against 6 ms for a fresh box, and whatever
    // a previous call left in the box is still there for the next - across PROCESSES, not just calls.
    //
    // ⛔ A resident box is NOT a fresh box. /tmp ACCUMULATES instead of starting empty; the network
    // posture is whatever the box was CREATED with, which is why it is part of the fingerprint; the
    // PID namespace is SHARED across calls. What does NOT leak, measured: a process a previous call
    // left running - `kern exec` reaps its descendants when it returns, including one detached with
    // setsid, which is why the resident box runs `--init`.
    //
    // ⛔ THE VERDICT NEEDS kern 0.30.1 OR NEWER. `oom` is read from the bytes kern writes where the
    // workload cannot reach them, and `kern exec` writes them since 0.30.1: the command ran, whether
    // the OOM killer took it with its box, and the signal that ended it. Measured with 0.30.1: an OOM
    // comes back `oom` and the cell's own `exit(137)` an exit with no fault. Against an older kern on
    // PATH only the 137 arrives and both read `killed`, never guessed into `oom`. The npm package
    // carries 0.30.1.
    //
    // 📌 WHAT ADOPTION KEYS ON, AND THE TWO THINGS IT DELIBERATELY DOES NOT. A box is adopted when
    // its fingerprint matches: the argv, the `KERN_*` environment kern builds the box from, and what
    // a `vcpu:`/`vgpio:`/`vdisk:` token resolves to in your kern.toml. That is the ISOLATION
    // posture, which is what a caller is promised. Two things it does not key on, both decisions
    // rather than gaps:
    //
    //   * THE BYTES BEHIND A FLOATING IMAGE TAG. `image: "python:3.12-slim"` is hashed as that
    //     string, not as the digest it currently resolves to, so a box built before an ordinary
    //     re-pull of the same tag is still adopted. Keying on the digest would refuse resumption
    //     after every security update of the base image, and the isolation is identical either way.
    //     ⭐ If resume must mean the same image bytes, PIN IT: `image: "python@sha256:..."` is a
    //     valid reference, it goes into the argv and therefore into the fingerprint (verified:
    //     three distinct hashes for a tag and two different digests).
    //   * THE BODY OF AN APPARMOR PROFILE. `apparmor: "name"` hashes the NAME; replacing the policy
    //     loaded under that name on the host changes enforcement without moving the fingerprint.
    //     That is host administration, in the same class as replacing the kernel under a running
    //     box, and not something this binding can observe portably.
    this.persist = opts.persist ?? false;
    // How long the resident box lives. It is kern's own `--timeout` on that box, so it ends by itself
    // if the owning process dies: a resident sandbox cannot leak for longer than this.
    this.persistTtlS = opts.persistTtlS ?? 3600;
    this._resident = null;
    this._residentCalls = 0;
    this.memoryMb = opts.memoryMb === undefined ? 512 : opts.memoryMb;
    this.cpus = opts.cpus ?? null;
    this.pids = opts.pids === undefined ? 256 : opts.pids;
    this.timeoutS = opts.timeoutS ?? 30;
    this.network = opts.network ?? false;
    this.egressAllow = opts.egressAllow ?? null;
    this.mounts = opts.mounts ?? null;
    // `undefined` means the binding's default (a 64 MiB tmpfs at /tmp); `{}` or `[]` means none at
    // all. The two are distinct on purpose: "I did not say" and "I said no" are different answers,
    // and only the second should leave a box without a writable /tmp.
    this.tmpfs = opts.tmpfs === undefined ? null : opts.tmpfs;
    this.profiles = opts.profiles ?? null;
    this.env = opts.env ?? null;
    this.maxOutputBytes = opts.maxOutputBytes ?? 64 * 1024 * 1024;
    // live output callbacks: called with each Buffer chunk as it arrives. The full capped output is
    // still captured in the result, so you can stream AND read result.stdout.
    this.onStdout = opts.onStdout ?? null;
    this.onStderr = opts.onStderr ?? null;
    // prewarm=N keeps N boxes started in advance, each holding a booted interpreter that has run
    // nothing. A python runCode then claims one instead of starting its own, which takes the box start
    // and the interpreter boot OFF the call and leaves a marginal cost near zero. Each prewarmed box
    // serves exactly one cell and is destroyed, so "a fresh box per call" is unchanged - see WarmBox.
    //
    // Default 0, because it is a RESOURCE decision the caller owns: N warm boxes hold N booted
    // interpreters and N kern supervisors for the life of the session, whether or not a call arrives.
    // 1 is the right number for an interactive agent; raise it only for bursts.
    this.prewarm = opts.prewarm ?? 0;
    /** @type {WarmPool|null} */
    this._pool = null;
    this.enforceLimits = opts.enforceLimits ?? true;
    // `--require-limits`: refuse to start unless the memory/pids caps are ACTUALLY enforced (read back
    // from the cgroup), rather than running best-effort uncapped - the fail-closed OOM / fork-bomb
    // backstop. Distinct from `enforceLimits` (systemd-scope vs best-effort PATH); this makes an
    // unenforceable cap fatal.
    this.requireLimits = opts.requireLimits ?? false;
    // `--security-profile "untrusted"`: an opt-in hardening BUNDLE (seccomp allowlist + cap-drop ALL +
    // read-only root) for code nobody has read. The root goes read-only but a bound `mounts` path stays
    // writable, so it composes with this SDK. null (default) leaves kern's normal posture.
    this.securityProfile = opts.securityProfile ?? null;
    // `--apparmor "<profile>"`: enter a pre-loaded AppArmor profile on the box's exec (Docker's
    // `--security-opt apparmor=`), a kernel-enforced LSM layer over namespaces + seccomp. The profile
    // must be loaded on the host; kern fails the box CLOSED if it is not. null (default) applies none.
    this.apparmor = opts.apparmor ?? null;
    this.depsReadonly = opts.depsReadonly ?? true;
    this.pycCache = opts.pycCache ?? true;
    /** The cache to mount: "" means this session compiles from source. Set at open() when one is already
     * there, and by `_pycAdoptIfReady` on the first call after this session's own build publishes one. */
    this._pycDir = "";
    /** The destination a build was started for at open(), until it is adopted or refused. Empty whenever
     * there is nothing to wait for, which is what keeps the check on the call path free. */
    this._pycPending = "";
    // Capabilities dropped from every box this sandbox starts, as kern's own `--cap-drop` takes them.
    // The default drops the lot: kern already drops 16 dangerous capabilities unconditionally, but the
    // rest were still held over the box's own user namespace, on the one code path whose purpose is
    // running code nobody has read. Defence in depth rather than the boundary itself, and measured to
    // cost nothing. It is NOT behaviour-free: a workload binding a port below 1024 INSIDE the box
    // needs CAP_NET_BIND_SERVICE. Pass `capDrop: []` for the previous behaviour.
    this.capDrop = opts.capDrop ?? ["ALL"];
    this.user = opts.user ?? null;
    // trackFiles=true populates result.files by walking the workspace before AND after each call (O(N)
    // in file count); a long session that accretes files slows every runCode. false = result.files [], O(1).
    this.trackFiles = opts.trackFiles ?? true;

    if (!(this.timeoutS > 0)) throw new SandboxError("timeoutS must be a positive number of seconds");
    if (!(this.maxOutputBytes > 0)) throw new SandboxError("maxOutputBytes must be positive");

    // SHAPE GUARDS BEFORE ANYTHING CONSUMES THESE, the twin of the Python binding's and added after
    // the same outside review swept the constructor argument by argument.
    //
    // THE JS FAILURE IS WORSE THAN THE PYTHON ONE, which is why this is not just symmetry. Python
    // raises `AttributeError: 'list' object has no attribute 'items'` - useless, but obviously a
    // type error. `Object.entries()` does NOT throw on an array or a string: it hands back index
    // keys. MEASURED, `mounts: ["/tmp:/x"]` reached the mount validator as source `"0"` and reported
    // `mount source must be an absolute host path, got "0"`, naming a value the caller never wrote,
    // and `mounts: "/tmp:/x"` walked the string character by character and reported `cannot mount
    // over the box essential mount "/"`. Both refuse, so nothing unsafe happened; both send the
    // reader to look at a "0" or a "/" that exists nowhere in their code.
    //
    // `tmpfs` is deliberately NOT here: it documents an array form (a list of paths) and already
    // refuses a bare string by name.
    for (const [name, value] of [
      ["mounts", this.mounts],
      ["env", this.env],
    ]) {
      if (value === null || value === undefined) continue;
      if (typeof value !== "object" || Array.isArray(value)) {
        const example = name === "env" ? `{ KEY: "value" }` : `{ "/host/path": "/in/box" }`;
        throw new SandboxError(
          `${name} must be a plain object, not ${Array.isArray(value) ? "an array" : typeof value}: ` +
            `write ${name}: ${example}`,
        );
      }
    }
    // A CALLBACK THAT IS NOT A FUNCTION is never called and says nothing, so the caller sees a
    // sandbox that produces no output and has nothing to debug.
    for (const [name, cb] of [
      ["onStdout", this.onStdout],
      ["onStderr", this.onStderr],
    ]) {
      if (cb !== null && cb !== undefined && typeof cb !== "function") {
        throw new SandboxError(
          `${name} must be a function (it is handed one chunk at a time), not ${typeof cb}`,
        );
      }
    }

    this._mountArgs = [];
    const boundTargets = new Set();
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
        this._mountArgs.push(...mountArgs(real, tgt, ro));
        boundTargets.add("/" + tgt.split("/").filter((c) => c && c !== ".").join("/"));
      }
    }
    // A caller who binds their own directory at /tmp gets it: the default tmpfs would be mounted OVER
    // their bind, so the files they passed would be invisible to the code they are running. An
    // explicit `tmpfs` wins too; both are the caller saying what that path is.
    this._tmpfsArgs = [];
    this._tmpfsDefault = this.tmpfs === null;
    for (const [target, size] of tmpfsItems(this.tmpfs)) {
      // OUR default steps aside wherever the caller has already said something about this area: a
      // bind at the same target, because mounting over it would hide their files, and a
      // `securityProfile`, because that is a HARDENING BUNDLE and 0.1.35 gave `untrusted` a
      // read-only /tmp. A default added by a different layer must not widen a posture in a patch
      // release.
      const normTarget = "/" + String(target).split("/").filter((c) => c && c !== ".").join("/");
      if (this._tmpfsDefault && (boundTargets.has(normTarget) || this.securityProfile !== null)) continue;
      // A tmpfs that COVERS a bind. Equality was the first version and it is only half the shape:
      // mounts stack, the tmpfs goes on top, and "on top" reaches every path underneath. Measured:
      //   -v HOST:/tmp     + --tmpfs /tmp      -> /tmp EMPTY, the bind invisible
      //   -v HOST:/tmp/sub + --tmpfs /tmp      -> same, through NESTING
      //   -v HOST:/tmp     + --tmpfs /tmp/sub  -> the bind's files are there, /tmp/sub is scratch
      // So the rule is asymmetric: refusing both directions would refuse the third, which is a legal
      // configuration (a persistent /tmp with a bounded subtree).
      if (!this._tmpfsDefault) {
        const swallowed = [...boundTargets].filter(
          (b) => b === normTarget || b.startsWith(normTarget.replace(/\/+$/, "") + "/"),
        );
        if (swallowed.length)
          throw new MountRefused(
            `tmpfs ${JSON.stringify(normTarget)} would cover the mounts bind at ` +
              `${swallowed.sort().join(", ")}. Mounts STACK: kern puts the tmpfs on top whatever ` +
              "order the arguments arrive in, so those files stay on the host and are invisible in " +
              "the box. Keep the bind (for host files) or the tmpfs (for ephemeral scratch) at that " +
              'path, not both. A tmpfs BELOW a bind is fine: mounts {host: "/tmp"} with ' +
              'tmpfs {"/tmp/scratch": "8m"} works.',
          );
      }
      // Validate FIRST: `tmpfsSizeVsCap` parses the size, and parsing an unvalidated one threw out
      // of the constructor instead of a named MountRefused. Same class as the wrong-type hole.
      const [norm, validSize] = validateTmpfs(target, size);
      const resolved = tmpfsSizeVsCap(norm, validSize, this.memoryMb, this._tmpfsDefault);
      this._tmpfsArgs.push("--tmpfs", resolved === null || resolved === undefined ? norm : `${norm}:${resolved}`);
    }
    // A bare string has a .map-less shape here, but Array.from("ALL") would yield ["A","L","L"] and
    // three bogus flags, so refuse the string by name and say what to write instead.
    if (typeof this.capDrop === "string")
      throw new SandboxError(
        `capDrop must be an array of names, not a bare string: write capDrop: [${JSON.stringify(
          this.capDrop,
        )}] for one, or capDrop: [] to drop none`,
      );
    if (!Array.isArray(this.capDrop))
      throw new SandboxError("capDrop must be an array of capability names");
    this._capDropArgs = this.capDrop.flatMap((c) => ["--cap-drop", validateCap(c)]);
    // SKIP THE UID RANGE EXACTLY WHEN THE CAPABILITY IT SERVES IS BEING DROPPED ANYWAY, which is the
    // default and costs a quarter of a cold box. `kern box --image` maps a sub-uid RANGE by default
    // (so an image that degrades privilege in its entrypoint works), and mapping it forks two SETUID
    // HELPERS. MEASURED: `parent:idmap` 22 us single-uid against ~1048 us ranged, and the whole box
    // 3234 against 4298 us on this class's argv - paired, core-pinned, -1083 us (25%).
    //
    // IT BUYS THIS SANDBOX NOTHING when `ALL` is dropped, measured rather than argued: `setuid(1000)`
    // inside a cell is refused either way under `--cap-drop ALL` (EPERM with the range, EINVAL
    // without). WITHOUT it the range does work, so this is conditional: `capDrop: []` is a documented
    // choice and keeps both the capability and the range.
    //
    // KEPT IDENTICAL TO THE PYTHON BINDING, including the condition: two spellings of one rule drift,
    // and a caller who moved between the SDKs would meet a different box shape in each.
    this._singleUid = this.capDrop.some(
      (c) => String(c).toUpperCase().replace(/^CAP_/, "") === "ALL",
    );
    this._profileArgs = (this.profiles || []).map(validateProfile);
    this._egressAllow = (this.egressAllow || []).map(validateDomain);
    if (this.apparmor !== null) validateApparmor(this.apparmor);
    if (this.user !== null) validateUser(this.user);
    // The spec the boxes run as when it is NOT box root (`user` or the image's own USER), and the host
    // uid that account writes as, learned in open(). null for box root, which is free.
    this._asUser = null;
    this._userHostUid = null;
    if (this._egressAllow.length && this.network)
      throw new SandboxError(
        "egressAllow and network:true are mutually exclusive: egressAllow gives a restricted domain " +
          "allowlist for runCode, network:true gives the full host network",
      );
    this._kern = findKern();
    this._ws = "";
    this._ownWs = false;
    // Where the per-box --env-files live: a private directory OUTSIDE the workspace (see `_envPath`).
    this._envDir = "";
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
      // Create the persistent workspace FIRST so a fresh path is usable on the first run; mkdir is a
      // no-op on an existing sensitive source (e.g. /etc), which validateMount then still refuses.
      fs.mkdirSync(this.workspace, { recursive: true });
      validateMount(this.workspace, WORKSPACE);
      this._ws = fs.realpathSync(this.workspace);
      this._ownWs = false;
    }
    this._entered = true;
    // THE RESIDENT BOX, adopted or created, BEFORE `setup` runs: a setup on a persistent sandbox has
    // to install into the box every later call will use, not into a throwaway one.
    if (this.persist) {
      if (!this.name)
        throw new SandboxError(
          "persist needs a name: it is the identity two processes meet on. " +
            'new Sandbox({ name: "my-agent", persist: true, workspace: "..." })',
        );
      if (this.workspace === null)
        // A TEMPORARY WORKSPACE WOULD MAKE THIS HALF-PERSISTENT, and silently: the box would be
        // adopted while its FILES started empty in a fresh directory every process, and the
        // fingerprint (which contains the workspace path, because the mount is part of the posture)
        // would never match twice, so no adoption could ever succeed.
        throw new SandboxError(
          "persist needs an explicit workspace: the resident box is adopted by posture, and a " +
            "temporary workspace is a different path in every process, so nothing would ever be " +
            "resumed. new Sandbox({ name, persist: true, workspace })",
        );
    }
    // THE IMAGE BEFORE ANY BOX: the setup box, the resident box, the bytecode build and the warm pool
    // all start one, and each used to pull inside its own deadline. After the refusals above, so a
    // wrong configuration is not reported only after a download.
    // THE ENV FILES' OWN DIRECTORY, and from here on a failure undoes everything open() made: close()
    // is idempotent, and without this a failed pull or setup left a temporary workspace behind.
    try {
      this._envDir = privateEnvDir(this._ws);
    } catch (e) {
      await this.close();
      if (e instanceof SandboxError) throw e;
      throw new SandboxError(`cannot create a private directory for env files: ${e.message}`, { cause: e });
    }
    try {
      await this._openAfterEnvDir();
    } catch (e) {
      await this.close();
      throw e;
    }
    return this;
  }

  /** The rest of open(), run under its undo-on-failure guard. */
  async _openAfterEnvDir() {
    await fetchImage(this._kern, this.image);
    // THE IDENTITY BEFORE THE SETUP, because the setup box runs as it too.
    await this._resolveIdentity();
    if (this.setup) await this._runSetup(this.setup);
    // THE RESIDENT BOX IS CREATED AFTER THE SETUP, AND THAT ORDER IS THE FIX. It used to come first,
    // so `_runSetup` was routed into it (network silently dropped), and `_baseArgv` mounts
    // `<workspace>/.deps` READ-ONLY only `if` that directory exists - which it did not yet, so the
    // resident box was created WITHOUT the mount and `kern exec` never re-applies mounts. The
    // `depsReadonly` default is true and is documented as the defence against cross-run dependency
    // poisoning: it was off for the whole life of every resident box. The setup does not need to run
    // IN the resident box, because it installs into `<workspace>/.deps`, a HOST directory every
    // later box mounts. Same reasoning, same measurements, as the Python binding.
    if (this.persist) this._resident = await this._residentEnsure();
    // THE BYTECODE CACHE IS DECIDED HERE, once, and frozen: `_baseArgv` is what the prewarm pool
    // compares postures with, so a cache appearing mid-session would change the argv runCode builds and
    // every claim would miss. SKIPPED WHEN A SETUP LEFT DEPS: `PYTHONPYCACHEPREFIX` redirects every
    // lookup, `.deps` included, whose `__pycache__` the setup box fills on purpose (+40 ms per call
    // without it, measured in `_runSetup`). The two cannot share one prefix - deps are per session, the
    // cache is per image - and the stdlib win is not worth handing that back.
    if (this.pycCache && !fs.existsSync(path.join(this._ws, DEPS_DIR))) {
      const dest = pycDirFor(this.image);
      // THROUGH THE SAME VALIDATOR AS EVERY OTHER MOUNT: this path comes from $XDG_CACHE_HOME, so a
      // cache home under a credential directory would otherwise be mounted into every box, and into the
      // build box writable. A refusal disables the cache rather than throwing - bytecode is an
      // optimisation and cannot be a reason to fail a session. Mirrors Python.
      // A refusal means no mount AND no build: there is nothing to produce a cache we may not use.
      if (pycMountAllowed(dest) && pycPathHasNoSymlink(dest)) {
        // pycHasContent, not existsSync: an empty directory here is a cache that was swept out
        // from under a mount and recreated by kern, and adopting it silences the feature for good.
        if (pycHasContent(dest) && pycSourceMatches(dest, this.image)) {
          this._pycDir = dest;
          // A tree built before it was 0755 is opened up for a non-root user here, once.
          if (this._shared) {
            try {
              if ((fs.statSync(dest).mode & 0o005) !== 0o005) fs.chmodSync(dest, 0o755);
            } catch {
              /* still usable by box root; a non-root user compiles from source */
            }
          }
          // Records the ADOPTION for the sweep's least-recently-used order. Best effort: a cache on a
          // read-only filesystem is still usable, it just cannot be aged.
          try {
            const now = new Date();
            fs.utimesSync(dest, now, now);
          } catch {
            /* not ageable, still usable */
          }
          // The bound must hold for processes that never build, which is most of them once the cache
          // is warm. After the utimes above, so the cache being adopted is the newest thing seen.
          pycStartSweep(path.dirname(dest));
        }
        else {
          pycStartBuild(this._kern, this.image, dest, Math.max(this.timeoutS, 300));
          // Remembered so the first call AFTER the build publishes can adopt it. Without this the
          // session that paid for the build was the one session that never used it.
          this._pycPending = dest;
        }
      }
    }
    // AFTER the setup, deliberately. _baseArgv adds the .deps read-only remount only once that
    // directory exists, so a pool filled before the setup ran would hold boxes whose argv no longer
    // matches the one runCode builds: every claim would miss and the prewarming would be pure cost.
    if (this.prewarm > 0) {
      this._pool = new WarmPool(this, this.prewarm);
      this._pool.refill({ network: this.network, deadlineS: this._effTimeout(undefined) });
    }
  }

  /** Close the session: tear down any prewarmed boxes, then delete the workspace iff we created it.
   * Idempotent. */
  // ---- resident box (`persist: true`) ---------------------------------------------------------

  _residentName() {
    return `${RESIDENT_PREFIX}${this.name}`;
  }

  /**
   * The posture a resident box BAKES IN, taken from the argv that would create it.
   *
   * ADOPTION IS THE DANGEROUS HALF OF THIS FEATURE: a caller who asks for memoryMb 256 and is handed
   * a box someone else created with 512 has been told a limit is in force that is not. So the posture
   * is hashed at creation, stamped into a label, and compared on adoption; a mismatch is refused with
   * both values named rather than resolved by guessing.
   *
   * ⭐ TAKEN FROM `_baseArgv` AND NOT RE-LISTED. A hand-written list of the fields that matter is a
   * second spelling of the posture, and the two drift the first time a flag is added: the new flag
   * changes what the box IS without changing the fingerprint, so a box built before it gets adopted
   * by a Sandbox that asks for it. The NAME is stripped before hashing - it is identity, not posture.
   */
  // ASYNC, because resolving a `vcpu:`/`vgpio:`/`vdisk:` token means asking kern. Only one
  // production caller (`_residentEnsure`, already async) and the tests await it. `runCapture` and
  // not `spawnSync`: this file's own rule, and a synchronous spawn here would stop every timer and
  // socket in the host process.
  async _residentFingerprint() {
    return crypto
      .createHash("sha256")
      .update(await this._postureMaterial({ network: this.network, timeoutS: Math.trunc(this.persistTtlS) }))
      .digest("hex")
      .slice(0, 16);
  }

  // EVERYTHING THAT DETERMINES WHAT A BOX IS, as one string, spelled ONCE.
  //
  // 🚨 THIS EXISTS BECAUSE THE SAME HOLE WAS FOUND TWICE. First the resident fingerprint was found
  // to omit the `KERN_*` environment, then to omit what a `vcpu:`/`vgpio:` token
  // RESOLVES to. Both were fixed in the fingerprint - and the prewarm pool's key, which is the same
  // question asked by a different mechanism, kept the second hole. Measured in the Python binding:
  // with `profiles: ["vcpu:agent"]` and the definition changed from `cpus=1, memory="128M"` to
  // `cpus=4, memory="4G"`, the pool key was the SAME both times while the fingerprint differed. A
  // pool is adoption under another name: it hands a call a box that was built earlier.
  async _postureMaterial({ network, timeoutS }) {
    const argv = this._baseArgv("", { network, timeoutS, dry: true });
    // AND THE CONTROLS THAT NEVER REACH argv ARE ADDED EXPLICITLY. Taking the posture from
    // `_baseArgv` answers the drift problem for everything that IS a flag; `enforceLimits` is not a
    // flag, it is `KERN_NO_SCOPE=1` in the spawn's ENVIRONMENT, so it changed whether the caps are
    // kernel-enforced while leaving the argv byte for byte identical. Measured in the Python binding
    // before the same fix: `enforceLimits` true and false produced ONE fingerprint, so an unenforced
    // box could be adopted by a Sandbox that had asked for enforcement.
    argv.push(`--enforce-limits=${this.enforceLimits ? 1 : 0}`);
    // AND EVERY `KERN_*` IN THE ENVIRONMENT, because kern reads its OWN environment when it BUILDS
    // the box: `KERN_SECCOMP` picks the seccomp filter, and `KERN_ALLOW_UNCAPPED`,
    // `KERN_LANDLOCK_REQUIRED`, `KERN_DIRECT_CAPS` and `KERN_CONFIG` all change what the box is,
    // with none of them in the argv. Measured in the Python binding: six different settings produced
    // ONE fingerprint, so a box built under one filter could be adopted by a Sandbox asking for
    // another - and the dangerous direction is adopting a WEAKER filter while believing in the
    // stronger. The prewarm pool in this same file already folds these in, with its own measurement;
    // the resident path did not follow it.
    //
    // ⛔ `KERN_BIN` is excluded: it selects which binary to run and that binary's resolved path is
    // already argv[0] above, so hashing the variable too would refuse adoption between two processes
    // that found the SAME binary by different means (one with the variable, one through PATH).
    const kernEnv = Object.entries(process.env)
      .filter(([k]) => k.startsWith("KERN_") && k !== "KERN_BIN")
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${k}=${v}`)
      .join("\u0000");
    let material = `${argv.join("\u0000")}\u0000\u0000${kernEnv}`;
    // AND WHAT A `vcpu:`/`vgpio:`/`vdisk:` TOKEN RESOLVES TO. A profile is a positional token that
    // `kern box` resolves against the user's kern.toml: the TOKEN is in the argv above, the
    // DEFINITION is not. Measured in the Python binding: the same `vcpu:agent` with `cpus = 1,
    // memory = "128M"` and then `cpus = 4, memory = "4G"` produced ONE fingerprint, so a box created
    // under one definition is adopted under another and the caller is told its own limits are in
    // force. `vgpio:` profiles are the only way to give a box a hardware device, so the collision
    // spans a DEVICE GRANT and not just a number.
    //
    // ASKED OF kern, not re-derived: re-reading kern.toml here would be a second opinion about
    // kern's own resolution (KERN_CONFIG > --config > XDG > ~/.config, plus `extends`) and two
    // opinions drift. A MINIMAL argv - the image, the tokens, nothing else - because everything else
    // about the posture is already in the material above. Measured: 2 ms, no pull, and it does not
    // require the image to exist. The spawn is only paid when a profile is asked for.
    //
    // FAIL CLOSED: if the probe cannot answer this throws rather than falling back to the
    // argv-only hash, which would reopen exactly this hole.
    if (this._profileArgs.length > 0) {
      const probe = [
        this._kern, "box", Sandbox.FINGERPRINT_PROBE, "--image", this.image, "--show-config",
        ...this._profileArgs, "--", "/bin/true",
      ];
      const shown = await runCapture(probe, 60000);
      if (shown.code !== 0)
        throw new SandboxError(
          `the resource profiles ${JSON.stringify(this.profiles || [])} do not resolve, so the ` +
            `resident sandbox posture cannot be compared: ` +
            `${(shown.stderr || shown.stdout || "").trim().slice(0, 300)}`,
        );
      // ⛔ A kern TOO OLD TO DESCRIBE A GRANT IS REFUSED, not hashed around. Before the device and
      // disk lines existed, `--show-config` printed what a `vcpu:` profile yields and nothing a
      // `vgpio:`/`vdisk:` profile yields, so two device grants under one token gave one fingerprint.
      // The fix lives in kern, so this binding is only protected when paired with a kern that has
      // it. With a `vgpio:`/`vdisk:` token and no `devices:` line the posture cannot be known.
      // `vcpu:` alone is not refused: memory and cpus have always been printed.
      const grants = this._profileArgs.some((t) => ["vgpio", "vdisk"].includes(t.split(":")[0]));
      if (grants && !shown.stdout.split("\n").some((l) => l.startsWith("devices:")))
        throw new SandboxError(
          `the kern at ${this._kern} cannot describe what a vgpio:/vdisk: profile grants ` +
            `(its --show-config prints no \`devices:\` line), so a box built earlier cannot be ` +
            `matched to this posture and is not reused. Upgrade kern to a version that prints the ` +
            `granted devices`,
        );
      material += `\u0000\u0000${shown.stdout}`;
    }
    return material;
  }

  /** The running resident box for this name, or null. Never throws: a registry that cannot be read is
   * the same answer as no box, and both lead to creating one. */
  async _residentLookup() {
    const r = await runCapture(
      [this._kern, "ps", "--filter", `name=${this._residentName()}`, "--json"],
      20000,
    );
    if (r.code !== 0 || !r.stdout.trim()) return null;
    let data;
    try {
      data = JSON.parse(r.stdout);
    } catch {
      return null;
    }
    const rows = Array.isArray(data) ? data : [data];
    for (const row of rows)
      if (row && row.name === this._residentName())
        return row.status === "running" ? row : null;
    return null;
  }

  /**
   * Adopt the resident box or create it, and return its name.
   *
   * THE RACE IS REAL AND IS HANDLED BY LOSING GRACEFULLY. Two processes naming the same sandbox can
   * reach the create at the same moment; kern refuses a duplicate name, so the loser looks the box up
   * again and adopts what the winner made, verified by the same fingerprint - so losing the race
   * cannot smuggle in a different posture.
   */
  async _residentEnsure() {
    const want = await this._residentFingerprint();
    const found = await this._residentLookup();
    if (found) {
      const have = (found.labels || {})[CFG_LABEL];
      if (have !== want)
        throw new SandboxError(
          `a resident sandbox named ${JSON.stringify(this.name)} is already running with a ` +
            `DIFFERENT posture (its fingerprint is ${JSON.stringify(have)}, this Sandbox asks for ` +
            `${JSON.stringify(want)}), so adopting it would report limits that are not the ones in ` +
            `force. Use another name, or stop it: kern stop ${this._residentName()}`,
        );
      return this._residentName();
    }
    // THE SAME ARGV THE ONE-SHOT PATH USES, so the resident box carries identical mounts, caps, tmpfs
    // and environment - plus `-d` to detach, `--init` so PID 1 REAPS, the fingerprint label, and a
    // PID 1 that does nothing else. `--init` and not a bare `sleep`: `sleep` never calls wait(), so a
    // process a call detached became a zombie and they accumulated until pids.max refused a fork.
    const argv = [
      ...this._baseArgv(this._residentName(), {
        network: this.network,
        timeoutS: Math.trunc(this.persistTtlS),
      }),
      "-d",
      "--init",
      "--label",
      `${CFG_LABEL}=${want}`,
      "--",
      "sleep",
      String(Math.trunc(this.persistTtlS)),
    ];
    // THE ENVIRONMENT IS BUILT, NOT INHERITED. Without this the box took whatever `KERN_NO_SCOPE`
    // was in the ambient environment: `enforceLimits: false` never reached the box (only `_spawn`'s
    // children got it, which on this path are `kern exec` calls and not the box's own cgroup
    // placement), and a shell that merely had the variable exported created an unenforced box for a
    // Sandbox that asked for enforcement - the dangerous direction.
    const createEnv = { ...process.env };
    if (this.enforceLimits) delete createEnv.KERN_NO_SCOPE;
    else createEnv.KERN_NO_SCOPE = "1";
    const made = await runCapture(argv, 180000, createEnv);
    if (made.code !== 0) {
      const again = await this._residentLookup();
      if (again && (again.labels || {})[CFG_LABEL] === want) return this._residentName();
      throw new SandboxError(
        `could not start the resident sandbox ${JSON.stringify(this.name)}: ` +
          `${(made.stderr || made.stdout || "").trim().slice(0, 400)}`,
      );
    }
    return this._residentName();
  }

  /**
   * Stop the resident box. The ONLY way a `persist` sandbox goes away before its TTL.
   *
   * Deliberately not `close()`: a sandbox that disappeared when the session ended would be the
   * one-shot behaviour under another name, and nothing would be resumable. Idempotent and quiet:
   * stopping a box that is already gone is the state the caller asked for.
   */
  async destroy() {
    if (!this.name) return;
    await runCapture([this._kern, "stop", this._residentName()], 60000);
    this._resident = null;
  }

  async close() {
    // Boxes first: they are live processes holding the workspace we are about to delete, and a box
    // still writing into a directory being removed is how a teardown turns into a stale mount.
    const pool = this._pool;
    this._pool = null;
    if (pool) await pool.close();
    if (this._ownWs && this._ws) {
      try {
        fs.rmSync(this._ws, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
      // WHAT rmSync COULD NOT REMOVE is what a non-root box user closed to us: a directory it created
      // 0755 (every tarball's) cannot be emptied by anyone but its owner. The helper, as that user,
      // opens up and removes its own; the workspace itself is ours and goes last. Mirrors Python.
      if (this._shared && fs.existsSync(this._ws)) {
        try {
          await this._wsHelper(HELPER_CLEAN, [], { write: true });
        } catch {
          /* best effort at teardown */
        }
        try {
          fs.rmSync(this._ws, { recursive: true, force: true });
        } catch {
          /* best-effort */
        }
      }
    }
    // After the boxes: a box still starting reads its env file. Only ever our own mkdtemp.
    const envDir = this._envDir;
    this._envDir = "";
    if (envDir && path.basename(envDir).startsWith(ENV_DIR_PREFIX)) {
      try {
        fs.rmSync(envDir, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    }
    this._entered = false;
  }

  // -- `user`: who the boxes run as, and keeping the workspace shared with them ---------------------

  /** The workspace is shared with a non-root box user through an ACL (see `user`): the one condition
   * every fallback to the helper box answers to. Mirrors Python's `_shared`. */
  get _shared() {
    return this._userHostUid !== null;
  }

  /** Decide the account the boxes run as and, when it is not box root, share the workspace with it.
   * Box root costs nothing and does nothing. Otherwise one box starts AS THAT USER to learn the host
   * uid it writes as, which answers for every mapping kern might choose. Mirrors `_resolve_identity`. */
  async _resolveIdentity() {
    const spec = this.user !== null ? this.user : imageUser(this.image);
    // THE IMAGE'S OWN `USER` GOES THROUGH THE SAME CHECK AS `user`, which it did not: `user` is
    // validated in the constructor and the image half reached the argv unexamined. `USER_SPEC_RE`'s
    // comment promises the value can never read as a flag on the argv it lands on, and that has to
    // hold for both halves. Mirrors Python's `_resolve_identity`.
    if (spec !== null && this.user === null) {
      try {
        validateUser(spec);
      } catch (e) {
        throw new SandboxError(
          `the image ${JSON.stringify(this.image)} declares USER ${JSON.stringify(spec)}, which is not a ` +
            `shape kern can be given: ${e.message}. Pass user: "<account>" to say which account to run as`,
          { cause: e },
        );
      }
    }
    if (isRootUser(spec)) return;
    // A RESIDENT BOX IS ENTERED WITH `kern exec`, which is box root unless told otherwise, and only a
    // kern with `kern exec -u` can be told. Asked once, here, rather than failing every call. Read from
    // `kern exec --help`, whose lines are the frozen CLI surface (`tests/cli-surface.snapshot`).
    if (this.persist) {
      const help = await runCapture([this._kern, "exec", "--help"], 30000);
      if (!help.stdout.includes("-u <user>"))
        throw new SandboxError(
          `persist with user ${JSON.stringify(spec)} needs a kern whose \`kern exec\` takes \`-u <user>\`, ` +
            `and ${this._kern} (${verifyIsKern(this._kern)}) does not: its calls would run as box root in a ` +
            `box whose own process runs as ${JSON.stringify(spec)}. Update kern, or drop persist`,
        );
    }
    this._asUser = spec;
    const hostUid = await this._probeHostUid(spec);
    const own = process.getuid();
    // THE PROBED UID DECIDES ROOT-NESS, NOT THE SPELLING: an image can name box root anything
    // (`USER N0tR00t` with `N0tR00t:x:0:0:` in its own /etc/passwd), and box root maps to this
    // process's uid, so the helper box would be root of the range under another name. Same line as
    // Python's.
    if (hostUid === own) return; // the account writes as this process: already shared
    this._userHostUid = hostUid;
    let foreign = 0;
    let example = "";
    try {
      [foreign, example] = await aclGrantTreeAsync(this._ws, hostUid, own, { recursive: !this._ownWs });
      // A TREE THIS SESSION DOES NOT OWN IS CHANGED, AND THAT IS SAID. Same sentence as Python's:
      // the grant adds an entry to every file and a default ACL to every directory under the
      // caller's `workspace`, and nothing removes it (`close()` only clears a workspace this
      // session made), so files the operator creates there afterwards inherit it. The default
      // `user: null` reaches this on any image that declares a non-root USER.
      if (!this._ownWs)
        process.emitWarning(
          `user ${JSON.stringify(spec)}: added a POSIX ACL for host uid ${hostUid} to every file and ` +
            `directory under ${this._ws}, and a default ACL on the directories, so the account can reach ` +
            `what it creates there. It is NOT removed when this session closes (this workspace is yours, ` +
            `not the session's): \`setfacl -R -x u:${hostUid} -k ${this._ws}\` undoes it`,
          "KernWorkspaceAcl",
        );
    } catch (e) {
      // THE SAME SENTENCES AS PYTHON, decided on the error's code rather than on its text.
      const user = JSON.stringify(spec);
      if (e.code === "ENOTSUP")
        throw new SandboxError(
          `user ${user} needs POSIX ACLs on the workspace filesystem, and ${this._ws} has none: the ` +
            `account is host uid ${hostUid} on disk, and an ACL is how it and this process both reach ` +
            "the files. Put the workspace on a filesystem with ACLs (ext4, xfs, btrfs, tmpfs), or run as " +
            'box root (user: null on an image with no USER, or user: "root")',
          { cause: e },
        );
      if (e.code === "ENOSETFACL")
        throw new SandboxError(
          `user ${user} needs \`setfacl\` on the host (the \`acl\` package): it writes the ACL through ` +
            `which the account, host uid ${hostUid} on disk, and this process both reach the workspace`,
          { cause: e },
        );
      throw new SandboxError(`user ${user}: sharing the workspace ${this._ws} failed: ${e.message}`, { cause: e });
    }
    if (foreign)
      // PRIVATE ON PURPOSE, and said here because the box would only say EACCES: what a box account
      // creates inherits empty group and other entries, since under a default ACL its umask no longer
      // applies. Mirrors Python's warning.
      process.emitWarning(
        `the workspace holds ${foreign} entr${foreign === 1 ? "y" : "ies"} (e.g. ${JSON.stringify(example)}) ` +
          `created by a different box account than user ${JSON.stringify(spec)}, host uid ${hostUid}: ` +
          `they are reachable by that account and by this process, not by ${JSON.stringify(spec)}. ` +
          "Read them with readFile and write them back, or keep one user per workspace",
        "KernWorkspaceForeignEntries",
      );
  }

  /** The host uid a box of this image running as `spec` writes files as. The probe writes into a
   * directory of its own, 0777 so the account can, inside a 0700 one of ours so nothing else on the
   * host can reach it. Same identity flags as every other box. Mirrors `_probe_host_uid`. */
  async _probeHostUid(spec) {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), "kern-uid-"));
    const drop = path.join(d, "p");
    try {
      fs.mkdirSync(drop);
      fs.chmodSync(drop, 0o777);
      // `--entrypoint ""` for the reason `_helperArgv` states: the image's ENTRYPOINT would
      // otherwise run first and decide whether this probe writes its file at all.
      const argv = [
        this._kern, "box", uniqueName(), "--image", this.image, "--ro", "--entrypoint", "",
        ...mountArgs(drop, "/kern-uid", false), ...this._capDropArgs, "--timeout", "60",
      ];
      if (this.user !== null) argv.push("--user", this.user);
      argv.push("--", "sh", "-c", ": > /kern-uid/o");
      const r = await runCapture(argv, 120000);
      let st = null;
      try {
        st = fs.lstatSync(path.join(drop, "o"));
      } catch {
        st = null;
      }
      if (r.code !== 0 || st === null) {
        // QUOTED, like every other box-produced line this package prints: the stream can carry
        // escapes and a forged verdict, and this message reaches an agent loop. Python's is the same.
        const said = quoteUntrusted((r.stderr || r.stdout).slice(-600));
        throw new SandboxError(
          `user ${JSON.stringify(spec)}: a box of ${JSON.stringify(this.image)} could not run as that ` +
            `account (exit ${r.code}): ${said || "no output"}`,
        );
      }
      return st.uid;
    } finally {
      fs.rmSync(d, { recursive: true, force: true });
    }
  }

  /** The helper box: the session's image and its OWN identity, `--user` and `capDrop`. AS THE BOX USER,
   * NOT AS ROOT OF THE RANGE, and that choice is the boundary: it reaches what the host was refused
   * because the account OWNS what it closed, and a box racing the scripts' check-then-open can reach
   * only what the account reaches already. Root of the range could have been made to read a root-only
   * file of the image. No network, the workspace read-only unless `write`, only this module's scripts.
   * Mirrors Python's `_helper_argv`. */
  _helperArgv(script, args, write, timeoutS) {
    if (this._asUser === null) throw new SandboxError("the workspace helper is for a non-root session only");
    // `--entrypoint ""` BECAUSE "only the scripts of this module" WAS FALSE WITHOUT IT: kern
    // prepends the image's ENTRYPOINT to what follows `--`, and a helper's output is PARSED (the
    // file's bytes, stat records, a tar stream), not displayed. See Python's `_helper_argv`.
    return [
      this._kern, "box", uniqueName(), "--image", this.image, "--ro", "--entrypoint", "",
      "--user", this._asUser, ...this._capDropArgs,
      ...mountArgs(this._ws, "/w", !write), "--pids-limit", "64",
      "--timeout", String(timeoutS), "--", "sh", "-c", script, "sh", ...args,
    ];
  }

  /** Read a helper run's outcome: a box that did not run (spawn failure or timeout), or one that could
   * not run the script, is an error; the script's own exit code is the caller's. */
  _helperResult(r) {
    if (r.code === -1)
      throw new SandboxError(
        `the workspace helper box did not run: ${quoteUntrusted(String(r.stderr).slice(-400)) || "no output"}`,
      );
    if ([125, 126, 127].includes(r.code) && r.stdout.length === 0)
      throw new SandboxError(
        `the workspace helper box could not run in ${JSON.stringify(this.image)} (exit ${r.code}): ` +
          `${quoteUntrusted(String(r.stderr).slice(-400)) || "no output"}. ${HELPER_TOOLS}`,
      );
    return r;
  }

  /** Run `sh -c script sh ...args` in the helper box, the workspace at /w, for what this process was
   * REFUSED. Mirrors `_ws_helper`. */
  async _wsHelper(script, args, { write = false, input = null, timeoutS = 120 } = {}) {
    const argv = this._helperArgv(script, args, write, timeoutS);
    return this._helperResult(await runBuffered(argv, { input, timeoutMs: (timeoutS + 30) * 1000 }));
  }

  /** The workspace-relative COMPONENTS of an already-contained `full`, as the helper scripts take them. */
  _helperParts(full) {
    return path.relative(this._ws, full).split(path.sep).filter((c) => c && c !== ".");
  }

  /** The refusal a helper script's exit code stands for, in the words the host path uses. */
  _helperRefusal(verb, rel, r) {
    if (r.code === 40) return pathRefusal(verb, rel, Object.assign(new Error("ELOOP"), { code: "ELOOP" }));
    if (r.code === 41)
      return new SandboxError(
        `refusing to ${verb} ${JSON.stringify(rel)}: not a regular file (a FIFO, device or socket ` +
          `planted in the workspace can stall or fake this operation)`,
      );
    if (r.code === 42) {
      // The scripts' own code for "a directory this needed could not be made" (mkdir or mktemp
      // refused): named, where it fell through to "exit 42" and the raw stderr. Mirrors Python.
      // A name inside a directory the box closed to the host appears verbatim in `du`/`find`/`stat`
      // diagnostics, and busybox - which `HELPER_TOOLS` names as supported - does not quote its own.
      const said = quoteUntrusted(String(r.stderr).slice(-400));
      return new SandboxError(
        `cannot ${verb} ${JSON.stringify(rel)}: the box user could not create a directory it needs` +
          (said ? ` (${said})` : ""),
      );
    }
    if (r.code === 43) return new SandboxError(`cannot ${verb} ${JSON.stringify(rel)}: not a directory`);
    return new SandboxError(
      `cannot ${verb} ${JSON.stringify(rel)} (exit ${r.code}): ` +
        `${quoteUntrusted(String(r.stderr).slice(-400)) || "no output"}`,
    );
  }

  _requireEntered() {
    if (!this._entered)
      throw new SandboxError("open the Sandbox first: `await sandbox.open()` (or use withSandbox()).");
  }

  // -- the box invocation --------------------------------------------------------------------------

  /** Host path of the private --env-file for the box called `name`, inside the workspace. */
  /** Host path of the private --env-file for the box called `name`. NOT IN THE WORKSPACE, which is
   * where it was: every box mounts the workspace, so a box running beside a call could read that call's
   * `env` values; a process killed mid-call left them for `snapshot` to archive; and a box could plant a
   * symlink at the name. kern reads the file on the HOST, so it lives in this session's own 0700
   * directory, which no box mounts, and goes with the session. Mirrors Python's `_env_path`. */
  _envPath(name) {
    return path.join(this._envDir, `${ENV_FILE}${ENV_SEP}${name}`);
  }

  /** Is `rel` an env file an OLDER version of this package left in the workspace? See
   * `isLegacyEnvFile`. Used by the SNAPSHOT path only: a listing must show everything, because every
   * shape that pattern matches is one a cell can create. */
  static _isEnvFile(rel) {
    return isLegacyEnvFile(rel);
  }

  /** Remove this call's env file. Every exit path calls it; a missing file is the desired end state. */
  _removeEnvFile(name) {
    if (!this._envDir) return;
    try {
      fs.unlinkSync(this._envPath(name));
    } catch {
      /* ENOENT is fine: no env was passed, or it is already gone */
    }
  }

  /** The clause an OOM message owes when this box has scratch mounted.
   *
   * A tmpfs is charged to the box's memory cgroup and its pages are NOT reclaimable: measured, 56 MiB
   * written to /tmp then 90 MiB allocated under `memoryMb: 128` is an OOM, while the SAME 56 MiB
   * written to the workspace and synced leaves room, because file-backed pages can be written back and
   * dropped. An OOM message naming only "memory cap" sends the reader to look at their allocation.
   * It states the mechanism and does NOT claim scratch caused this kill: that is not knowable here. */
  _scratchNote() {
    const ours = this._tmpfsArgs.filter((a) => a !== "--tmpfs").join(", ");
    // `/dev/shm` is named even when we mounted nothing: writing 200 MiB there under `memoryMb: 128`
    // OOMs the box, and the first version of this note said `/tmp:64m`, which is the wrong place.
    // Every kern box has a /dev/shm tmpfs with NO size, and this SDK cannot bound it.
    return (
      ". NOTE: memory-backed filesystems in this box are charged to that same cap, and their pages " +
      "are freed only by DELETING the files: " +
      (ours ? `the scratch this SDK mounted (${ours}), and ` : "") +
      "/dev/shm, which every kern box has as a tmpfs with NO size limit (its apparent size is half " +
      "the HOST's RAM) and which no option here can bound. Check both before the workload"
    );
  }

  /** Build the `kern box` argv for one call. NOT a pure function: it also WRITES the private
   * `--env-file` this box will read, so it must be called once per box that is actually started.
   *
   * `dry: true` suppresses that write and folds the env CONTENT into the argv instead, which is what the
   * prewarm pool needs: it compares postures, and a comparison that created a file named after a box
   * that will never exist would both litter the workspace and collide with itself. A dry argv is for
   * COMPARING, never for running. */
  _baseArgv(name, { network, timeoutS, isSetup = false, dry = false }) {
    // IDENTITY IS RE-ASSERTED PER BOX, not once per Sandbox, and an independent test is the reason. He
    // overwrote the verified binary IN PLACE with `/bin/true` while a Sandbox was open: the next call
    // correctly refused to call an empty run a success, and the message it refused with quoted the
    // version from the FIRST verification - stating that a file which now prints `true (GNU coreutils)
    // 9.4` had "reported 'kern v0.9.32-48-gb578943'". The verdict was right and the sentence was false.
    // Re-verifying here rather than repairing the sentence: the binary about to run was no longer the
    // binary that was checked. The memo is keyed on (realpath, dev, ino, size, mtimeMs), so an unchanged
    // file costs one stat and a map lookup, and a changed one pays a `--version` and is refused by name.
    // Mirrors the same call in `_base_argv`.
    if (!dry) verifyIsKern(this._kern);
    const argv = [
      this._kern, "box", name, "--image", this.image, "--ro",
      ...mountArgs(this._ws, WORKSPACE, false), "--workdir", WORKSPACE,
    ];
    // The image's precompiled stdlib, read-only. Never on the setup box: that one compiles `.deps`
    // into `__pycache__`, which the prefix would redirect into a mount it cannot write.
    // CHECKED AGAIN HERE, not only at adoption: the sweep in another process can discard this
    // tree in between, and `--mount` refuses a source that is not there. Dropping the mount for this
    // one call degrades to compiling from source, which is what the missing directory produced
    // before, instead of failing the caller.
    if (this._pycDir && !isSetup && pycHasContent(this._pycDir))
      argv.push(...mountArgs(this._pycDir, PYC_MOUNT, true));
    if (this.depsReadonly && !isSetup) {
      const deps = path.join(this._ws, DEPS_DIR);
      try {
        if (fs.statSync(deps).isDirectory())
          argv.push(...mountArgs(deps, `${WORKSPACE}/${DEPS_DIR}`, true));
      } catch {
        /* no deps yet */
      }
    }
    // kern's own --timeout is a tight BACKSTOP just beyond our deadline; OUR wait is the authority.
    argv.push(...this._capDropArgs);
    if (this.user !== null) argv.push("--user", this.user);
    // A non-root identity needs its uid mapped, and kern maps the range for it whatever this flag says
    // (measured), so the flag is left out rather than asking for what kern will not do. Mirrors Python.
    if (this._singleUid && this._asUser === null) argv.push("--no-uid-range");
    argv.push("--timeout", String(Math.floor(timeoutS) + 5));
    if (this.memoryMb !== null) argv.push("--memory", `${this.memoryMb}m`);
    if (this.cpus !== null) argv.push("--cpus", String(this.cpus));
    if (this.pids !== null) argv.push("--pids-limit", String(this.pids));
    if (this.requireLimits) argv.push("--require-limits");
    if (this.securityProfile !== null) argv.push("--security-profile", this.securityProfile);
    if (this.apparmor !== null) argv.push("--apparmor", this.apparmor);
    // Network mode: egressAllow (a domain allowlist via an isolated netns + kern's filtering proxy)
    // governs the untrusted runCode/run boxes; the setup box keeps the full network it needs to install
    // deps. egressAllow and network are mutually exclusive (checked at construction).
    if (this._egressAllow.length && !isSetup) argv.push("--egress-allow", this._egressAllow.join(","));
    else if (network) argv.push("--net");
    // Resource profiles (vcpu:/vgpio:/vdisk:NAME): positional tokens `kern box` resolves against the
    // user's kern.toml. Validated at construction, so nothing here can be a smuggled flag.
    argv.push(...this._profileArgs);
    argv.push(...this._mountArgs);
    // Scratch for THIS box. The DEFAULT tmpfs is deliberately skipped on the setup box, for the same
    // reason the egress allowlist is: setup is the install phase, and an install needs unbounded
    // scratch. A package manager puts its build tree in TMPDIR, so a 64 MiB /tmp turns a working
    // install into ENOSPC (measured on the Python side, same shape here). With no tmpfs, setup's temp
    // falls back to the workspace on the host disk, where a large short-lived build tree belongs. An
    // EXPLICIT `tmpfs` is the caller's decision and applies to every box, setup included.
    if (!(isSetup && this._tmpfsDefault)) argv.push(...this._tmpfsArgs);

    const mergedEnv = { ...(this.env || {}) };
    if (mergedEnv.PYTHONPATH === undefined) mergedEnv.PYTHONPATH = `${WORKSPACE}/${DEPS_DIR}`;
    // Only when the mount exists, and never over a caller's own value: this is an optimisation and
    // must not overrule an explicit choice.
    if (this._pycDir && !isSetup && mergedEnv.PYTHONPYCACHEPREFIX === undefined)
      mergedEnv.PYTHONPYCACHEPREFIX = PYC_MOUNT;
    // Pass env via a private 0600 --env-file, NOT `--env K=V` on argv (an argv value is visible in
    // `ps` to any local user for the box's lifetime; a credential in env= would leak).
    // `_ws` is set by open(); before that it is "". The public API is gated, but the unit tests call
    // `_baseArgv` directly to inspect the argv, and with an empty workspace `path.join` yielded a
    // RELATIVE path, so the env file was written into the current directory. Same as the Python side:
    // it had been landing in the repository, hidden by a `.gitignore` line that stopped matching when
    // the name became per-call. No workspace means nowhere to put it.
    if (Object.keys(mergedEnv).length > 0 && dry) {
      // The path is per-box by construction, so it can never be part of a posture comparison; a constant
      // stands in for it. The env CONTENT is still compared, because a session that changes `env` must
      // invalidate warm boxes: it is folded in here rather than left out.
      // Sorted BY KEY, not by the joined string, so this matches the Python binding exactly: sorting
      // "A=1" against "A1=2" as strings puts them in the other order, because '1' sorts before '='.
      argv.push(
        "--env-file",
        Object.entries(mergedEnv)
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([k, v]) => `${k}=${String(v)}`)
          .join("\0"),
      );
    } else if (Object.keys(mergedEnv).length > 0 && !this._envDir && this._ws) {
      // OPENED, AND THE ENV DIRECTORY IS GONE: a call racing close(), which removes it before the
      // session is marked closed. Running the box anyway would drop `env` and PYTHONPATH without a word,
      // so the call is refused. An unopened sandbox (no workspace either) is the argv-inspection case
      // above and stays silent. Mirrors Python.
      throw new SandboxError(
        "this sandbox is closing: its private env directory is gone, so the box would run without " +
          "env and PYTHONPATH. Make the call before close().",
      );
    } else if (Object.keys(mergedEnv).length > 0 && this._envDir) {
      const envPath = this._envPath(name);
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

  /**
   * Adopt the bytecode cache THIS session's own build produced, on the first call after it lands.
   *
   * WHY THIS EXISTS. Adoption used to happen only in open(), which made the session that paid for the
   * build the one session that never used it: measured on a held-open Sandbox, `_pycDir` stayed empty
   * for its whole life, seconds after the tree was published, and every call kept compiling from
   * source. A one-shot call was unaffected because each is its own session. A held-open Sandbox is the
   * agent loop, which is the shape this package is for.
   *
   * WHY THE FREEZE WAS NOT WORTH ITS PRICE. It was defending the prewarm pool: `_baseArgv` is what the
   * pool compares postures with, so an argv that changes mid-session invalidates every warm box. That
   * cost is already absorbed - `claim` retires boxes whose key no longer matches and the refill rebuilds
   * the key from the live argv, the same machinery that handles a `.deps` remount appearing
   * mid-session. Measured with prewarm=4: ONE call pays the cold path (33 ms against 1.4) and the pool
   * is full again by the next one, against a whole session that never got the cache.
   *
   * ALL THREE GUARDS RUN AGAIN, because open() asked its questions before this tree existed.
   *
   * Called before the pool is asked for a box, so the claim that follows compares the new posture.
   */
  _pycAdoptIfReady() {
    const dest = this._pycPending;
    // Empty means NOT READY, so the pending destination is kept: either the build has not
    // published yet, or what is there is the husk kern recreates under a swept mount.
    if (!dest || !pycHasContent(dest)) return;
    // Cleared FIRST and unconditionally: a refusal below must not leave this session re-checking a path
    // it has already rejected on every call it makes.
    this._pycPending = "";
    if (fs.existsSync(path.join(this._ws, DEPS_DIR))) return;
    if (!pycMountAllowed(dest) || !pycPathHasNoSymlink(dest)) return;
    this._pycDir = dest;
    try {
      const now = new Date();
      fs.utimesSync(dest, now, now); // best effort, as at open(): it only orders the sweep
    } catch {
      /* not ageable, still usable */
    }
    pycStartSweep(path.dirname(dest));
  }

  /**
   * One call, with ONE repair of a resident box that has died.
   *
   * THE BOX CAN BE GONE, AND IT IS NOT AN EXOTIC CASE. `memory.oom.group=1` means an OOM takes the
   * WHOLE cgroup, so a cell that overruns its memory cap destroys the resident box rather than just
   * its own process - MEASURED in the Python binding: the next call came back `startup_failed` and
   * the sandbox was silently unusable from then on. The TTL expiring does the same on a longer clock.
   *
   * CHECKED BY TRYING, NOT BY ASKING: a `kern ps` before every call would spend a second process
   * spawn on the hot path and buy nothing in the common case, which is the 2 ms this feature exists
   * for. ONE retry and never a loop: a box that dies again immediately has a cause that is not
   * transient, and retrying would hide it behind a hang.
   */
  async _spawn(command, opts) {
    const r = await this._spawnOnce(command, opts);
    if (
      this._resident === null ||
      (opts && opts.isSetup) ||
      !String(r.stderr || "").includes(RESIDENT_GONE)
    )
      return r;
    const lost = this._residentCalls;
    this._resident = await this._residentEnsure();
    this._residentCalls = 0;
    // SAID OUT LOUD, because the repair is not free and the caller cannot see it. The box is new: its
    // /tmp is empty again and anything a previous call installed into it is gone. Only the WORKSPACE
    // survived, because that is a host directory. Repairing this silently would hand back a sandbox
    // that looks continuous and is not - the caller would debug missing state instead of a dead box.
    process.emitWarning(
      `the resident sandbox ${JSON.stringify(this.name)} had died (an OOM takes the whole box, and ` +
        `the TTL ends it) after serving ${lost} call(s); it was recreated and this call re-run. Its ` +
        `in-box state is gone - /tmp is empty and anything installed into the box is not there. ` +
        `Files under the workspace are unaffected.`,
      "KernResidentRecreated",
    );
    return this._spawnOnce(command, opts);
  }

  async _spawnOnce(command, { network, timeoutS, isSetup = false, onStdout = UNSET, onStderr = UNSET }) {
    this._pycAdoptIfReady(); // one property read once there is nothing left to wait for
    const cbOut = onStdout === UNSET ? this.onStdout : onStdout;
    const cbErr = onStderr === UNSET ? this.onStderr : onStderr;
    for (const part of command)
      if (typeof part !== "string" || part.includes("\0"))
        throw new SandboxError("command/code must be strings with no NUL byte");
    // THE WORKSPACE CAP, CHECKED BEFORE THE WORK AND NOT AFTER IT. A call that has already run cannot
    // be un-run, and its output is what the caller needs most when something went wrong, so refusing
    // afterwards would destroy the evidence to enforce a limit the write had already passed. Costs
    // nothing when unset, which is the default.
    if (this.workspaceMaxBytes !== null && this._ws) {
      const blind = [];
      let used = workspaceUsage(this._ws, this._shared ? blind : null);
      if (blind.length) {
        // WHAT THE BOX USER CLOSED TO US IS MEASURED BY THE BOX USER, in the unit `du` and the walk
        // share (allocated blocks). Counting it as zero would let a non-root session park a cap's worth
        // of bytes where the walk does not look, so a `du` that fails REFUSES the call: a cap that
        // cannot be measured is not met. Mirrors Python.
        const r = await this._wsHelper(HELPER_DU, blind.map((d) => helperSubtree(path.relative(this._ws, d))));
        if (r.code !== 0)
          throw new SandboxError(
            "workspaceMaxBytes cannot be measured, so this call was refused before running: the box user " +
              `could not size ${blind.length} directory(ies) closed to this process ` +
              `(${String(r.stderr).trim().slice(-400) || `exit ${r.code}`})`,
          );
        for (const line of r.stdout.toString("utf8").split("\n")) {
          const head = line.split("\t")[0].trim();
          if (/^[0-9]+$/.test(head)) used += Number(head) * 1024;
        }
      }
      if (used > this.workspaceMaxBytes)
        throw new SandboxError(
          `workspace holds ${used} bytes, over the ${this.workspaceMaxBytes}-byte ` +
            `workspaceMaxBytes, so this call was refused before running. The box writes to a host ` +
            `directory (${this._ws}), so this is a cooperative cap and not a kernel boundary: it ` +
            `bounds what accumulates ACROSS calls, and one call can still exceed it. Delete what the ` +
            `session no longer needs, raise the cap, or give the Sandbox a workspace on a filesystem ` +
            `you are willing to fill`,
        );
    }
    const before = this.trackFiles ? await this._snapshot() : null; // skip the O(N) walk when not tracked
    const name = uniqueName();
    let argv;
    // `&& !isSetup`: A SETUP NEVER RUNS IN THE RESIDENT BOX, even if one already exists. The setup
    // box is defined by three properties - separate, network ON, dies at the end - and `kern exec`
    // into a running box provides none of them: the resident box is created with a runCode posture,
    // which is network-OFF, and exec cannot add a network to a box already running. Routing a setup
    // there dropped `network: true` in SILENCE, so `setup: "pip install X"` failed with a DNS error.
    // Same fix and same reason as the Python binding; `_enter` also creates the resident box after
    // the setup now, so in the normal path there is nothing to route into.
    const residentCall = this._resident !== null && !isSetup;
    if (residentCall) {
      // INTO THE RESIDENT BOX, which is the point of `persist`. `exec` and not `box`: measured, 2 ms
      // against 6 ms, and the box's own state is still there. `-w` puts the call in the same working
      // directory a fresh box starts in, so code writing a relative path lands in the workspace
      // exactly as it does on the one-shot path. `timeoutS` is NOT passed to kern here: the resident
      // box carries its own TTL, and the binding's deadline is enforced around this process.
      this._residentCalls += 1;
      // `-u`: `kern exec` enters as box root whatever the box runs as, so a call on a non-root session
      // names the account, or it would run as root where the one-shot path does not.
      argv = [this._kern, "exec", this._resident, "-w", WORKSPACE];
      if (this._asUser !== null) argv.push("-u", this._asUser);
      argv.push("--", ...command);
    } else {
      argv = [...this._baseArgv(name, { network, timeoutS, isSetup }), "--", ...command];
    }
    const childEnv = { ...process.env };
    if (!this.enforceLimits) childEnv.KERN_NO_SCOPE = "1";
    // Unforgeable "box started" channel: kern writes one byte to fd 3 iff its sandbox setup SUCCEEDED
    // and the command ran. The workload never holds fd 3, so it can neither forge nor suppress it -
    // unlike kern's stderr, which it can. A new kern makes this the authority for `startup_failed`; an
    // OLD kern never writes it, `boxStarted` stays false, and the stderr heuristic stands (backward
    // compatible).
    childEnv.KERN_STARTED_FD = "3";
    // A SECOND, LIVE channel, because the first one is post-mortem. kern writes KERN_STARTED_FD at the
    // box's TEARDOWN, so when OUR deadline fires we kill kern before that write and learn nothing: a
    // workload that was slow and a kern whose SETUP blocked are the same overrun. fd 4 carries kern's
    // readiness pipe: the ack byte on acceptance, EOF when the workload `execvp`s (the box child marks it
    // FD_CLOEXEC), one byte if setup or exec failed, and nothing at all from a kern that predates it.
    childEnv.KERN_ALIVE_FD = "4";

    const started = process.hrtime.bigint();
    return new Promise((resolve, reject) => {
      let child;
      let boxStarted = false;
      let capSignal = 0; // 2nd started byte: 0 undetermined/old-kern, 1 memory cap enforced, 2 not enforced
      let oomSignal = null; // 3rd started byte: 1 = OOM-killed, 0 = not, null = this kern does not say
      let workloadSignal = null; // 4th started byte: the signal that killed the workload, 0 = it exited
      try {
        // detached: own process group, so we can signal the box + kern as a unit (killpg).
        // The 4th stdio slot is fd 3: the child (kern) writes the started byte, the parent reads it.
        child = spawn(argv[0], argv.slice(1), {
          env: childEnv,
          detached: true,
          stdio: ["ignore", "pipe", "pipe", "pipe", "pipe"],
        });
      } catch (e) {
        this._removeEnvFile(name);
        return reject(new SandboxError(`could not spawn the box: ${e.message}`));
      }

      // The alive channel's state, updated as the pipe speaks. Read at the deadline, BEFORE the kill:
      // the teardown closes every write end, so afterwards the pipe reads EOF whatever the box was doing
      // and the question answers itself wrongly.
      let aliveState = ALIVE_UNKNOWN;
      const aliveCh = child.stdio[4];
      if (aliveCh) {
        aliveCh.on("data", (b) => {
          if (aliveState === ALIVE_PAST_SETUP) return;
          for (const byte of b) {
            if (byte === ALIVE_ACK) {
              if (aliveState === ALIVE_UNKNOWN) aliveState = ALIVE_IN_SETUP;
            } else {
              aliveState = ALIVE_PAST_SETUP; // a byte beyond the ack: kern said setup failed
              return;
            }
          }
        });
        // EOF: the box child's FD_CLOEXEC closed it at `execvp`, so the workload ran.
        aliveCh.on("end", () => {
          aliveState = ALIVE_PAST_SETUP;
        });
        aliveCh.on("error", () => {});
      }
      const startedCh = child.stdio[3];
      if (startedCh) {
        // Byte 0 (0x01) = the box started; stream end with no byte = never started / old kern. Byte 1
        // (a NEWER kern only, same atomic write) = the memory-cap enforcement signal; absent = 0. Byte 2
        // (a NEWER kern still) = the OOM OUTCOME: 1 iff the kernel's OOM killer fired against this box's
        // OWN cgroup. Enforcement is not an outcome, and this byte is the only place the outcome arrives
        // on a channel the workload cannot write.
        // ACCUMULATED rather than read off one chunk: kern's write is atomic, so all four bytes arrive
        // together in practice, but a stream that split them would silently cost us the last one - and a
        // lost OOM byte reads as "no OOM", a lost signal byte as "nothing killed it", both wrong answers
        // arrived at invisibly.
        let sig = Buffer.alloc(0);
        startedCh.on("data", (b) => {
          sig = Buffer.concat([sig, b]);
          ({ boxStarted, capSignal, oomSignal, workloadSignal } = parseStartedBytes(sig));
        });
        startedCh.on("error", () => {});
      }

      const out = cappedCollector(child.stdout, this.maxOutputBytes, cbOut);
      const err = cappedCollector(child.stderr, this.maxOutputBytes, cbErr);
      let timedOut = false;
      let settled = false;
      // Both timers are armed further down, once `finish` exists. They are declared here, as `let`,
      // so the closures that clear them can never reference a binding in its temporal dead zone
      // whatever the callback ordering turns out to be.
      let timer = null;
      let hardTimer = null;

      const finish = (code, signal) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        if (hardTimer) clearTimeout(hardTimer);
        // kern has read the file by the time it exits; leaving it behind would accrete one per call
        // in a persistent `workspace`.
        this._removeEnvFile(name);
        const wallMs = Number((process.hrtime.bigint() - started) / 1000000n);
        const stdout = out.buffer().toString("utf8");
        const stderr = err.buffer().toString("utf8");
        const rc = toRc(code, signal);
        let fault = this._classify(
          rc, signal, stderr, timedOut, timeoutS, capSignal, oomSignal, aliveState, workloadSignal,
          boxStarted,
        );
        const execFail = execFailureBinary(stderr);
        if (execFail !== null && rc !== 0) {
          // BEFORE the suppression below, which would erase it: the box started, so that branch
          // would read kern's own marker as a workload forgery.
          //
          // The REASON is carried through rather than assumed. The first version said "does not
          // exist in the box" for every case, and exit 126 (EACCES: the file is there and is not
          // executable) and a script whose interpreter line names a missing binary both got a
          // message blaming the image for a file that exists.
          const { what, reason } = execFail;
          let detail;
          if (reason.includes("No such file or directory")) {
            detail =
              `No such file or directory. The image '${this.image}' does not provide it, or its ` +
              `interpreter line names something the image lacks.` +
              // The one case where the remedy is not "a different image": every image has a POSIX
              // shell, so a caller who asked for bash and does not need bash has a one-word fix.
              (what === "bash" ? " This image has no bash; use language:'sh' if the script is POSIX." : "") +
              // NODE HAS NO IN-IMAGE FALLBACK, so the remedy is the image, and it is NAMED. Kept
              // word-for-word in step with the Python binding: the two are one API with two
              // spellings, and a message that differs between them is a product that differs.
              (what === "node"
                ? ` Name an image that carries node, e.g.` +
                  ` new Sandbox({ image: "node:22-slim" }).`
                : "");
          } else if (reason.includes("Permission denied")) {
            detail = "Permission denied: it is present in the box but not executable there.";
          } else {
            detail = reason || "the box could not execute it";
          }
          fault = sandboxFault("exec_failed", `'${what}' could not be started in the box: ${detail}`);
        } else if (fault && fault.type === "startup_failed" && (boxStarted || stdout.trim())) {
          // kern signalled the box STARTED, so a `startup_failed` here is only the stderr heuristic
          // matching a marker the WORKLOAD wrote (code-based faults are decided first). The box
          // demonstrably ran: this is the workload's own non-zero exit - reclassify to a normal result.
          //
          // STDOUT IS THE SECOND WITNESS, and it is here because the first one can be absent. MEASURED
          // with a KERN_BIN wrapper that closes `KERN_STARTED_FD` before exec'ing the real kern: the box
          // ran, printed, exited 1 with `error: forged` on stderr, and came back `startup_failed`. The
          // same hole is open on any kern too old to write the byte. A box that never started cannot
          // print, and every genuine startup failure measured returns stdout EMPTY, so this is only ever
          // read as evidence FOR a box having run, never against: a silent workload loses nothing.
          fault = null;
        }
        // A box that FAILED TO START ran no user code, so REJECT rather than resolve a hollow
        // ExecutionResult (empty stdout). Gated on `rc === 125` (kern's box-not-started code) AND the
        // startup_failed classification (which requires kern's own stderr marker): the confident pair
        // that tells a genuine box-not-started apart from a workload that itself exited 125 (no marker ->
        // fault null -> a normal result). An older kern (127) is returned as a data fault, not thrown.
        // Runtime events where the code DID run (timeout, OOM, escape) stay as data on `.fault`.
        // A RESIDENT CALL THAT NEVER RAN: `kern exec` refused to enter the box (it could not put the
        // command under the box's caps; an ordinary ssh session is the common case). MEASURED: exit 126,
        // kern's explanation on stderr, and `fault: null`, so an agent read "your code exited 126".
        // Decided on kern's started byte, never on stderr, which the code writes too; that byte proves
        // it only from v0.30.2 (see `kernExecReportsItsStart`). A GONE box has its own repair. Mirrors
        // the Python binding.
        if (
          residentCall && !fault && !boxStarted && rc !== 0 &&
          !String(stderr || "").includes(RESIDENT_GONE) &&
          kernExecReportsItsStart(verifyIsKern(this._kern))
        ) {
          const said = String(stderr || "").trim().slice(0, 1200) || `exit ${rc}, nothing on stderr`;
          fault = sandboxFault(
            "startup_failed",
            "the call never ran: `kern exec` refused to enter the resident box, so the code did not " +
              `start. kern said: ${said}`,
          );
        }
        if (rc === 125 && fault && fault.type === "startup_failed") {
          return reject(new SandboxError(fault.message || "the box failed to start"));
        }
        // ASYNC, because a shared workspace's diff may ask the helper about what the box user closed to
        // us; the promise is settled from its result either way.
        (before ? this._diff(before) : Promise.resolve([])).then(
          (files) =>
            resolve(
              new ExecutionResult({
                stdout, stderr, exitCode: rc, durationMs: wallMs, fault, files,
                truncated: out.truncated || err.truncated,
              }),
            ),
          reject,
        );
      };

      child.on("error", (e) => {
        this._removeEnvFile(name);
        if (e && e.code === "ENOENT")
          return reject(new SandboxError(`could not execute kern (${argv[0]}): not found`));
        return reject(new SandboxError(`could not execute kern: ${e.message}`));
      });
      child.on("close", (code, signal) => {
        finish(code, signal);
      });
      // Hard safety net: a CPU-bound box can survive our signals until kern's backstop reaps it;
      // never hang the caller. If close hasn't fired a few seconds after our teardown, resolve anyway.
      const armHardNet = () => {
        if (hardTimer) return;
        hardTimer = setTimeout(() => finish(EXIT_SIGKILL, "SIGKILL"), 10000);
      };

      timer = setTimeout(() => {
        timedOut = true;
        this._teardown(child, name, childEnv);
        // Armed HERE, at the one place that decides to kill. It used to be noticed instead by a
        // 250 ms setInterval that `finish` never cleared, so after every call that interval kept the
        // event loop alive until its own next tick: measured 224 to 232 ms of dead time between a
        // call resolving and the process being able to exit, against 19 to 27 ms of real work.
        armHardNet();
      }, timeoutS * 1000);
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

  _classify(
    rc, signal, stderr, timedOut, timeoutS, capSignal = 0, oomSignal = null, aliveState = ALIVE_UNKNOWN,
    workloadSignal = null, kernWrotePayload = false,
  ) {
    // ORDER IS A SECURITY PROPERTY: deterministic-by-exit-code classes are decided BEFORE the stderr
    // heuristic, because stderr is a channel the workload controls.
    if (timedOut) {
      // AND THE DEADLINE ALONE DOES NOT SAY WHOSE FAULT IT WAS. `ALIVE_IN_SETUP` is kern's own answer,
      // read off the readiness pipe while kern was still alive: the box was still being BUILT, so the
      // code never ran and calling this a `timeout` would tell the caller their workload was slow. That
      // class was measured with a FIFO volume source (404 seconds in `wait_for_partner`), and the shapes
      // behind it - an `lstat` on a dead NFS mount, a FUSE whose daemon is gone - are not FIFOs and
      // cannot be refused by type. Every other state keeps the old verdict, `ALIVE_UNKNOWN` (an older
      // kern) included: absence of evidence is not evidence.
      if (aliveState === ALIVE_IN_SETUP)
        return sandboxFault(
          "startup_failed",
          `the box never started: kern was still setting it up when the ${timeoutS ?? this.timeoutS}s ` +
            "deadline fired, so the code never ran. A host path that blocks is what does this - a bind " +
            "source on a dead NFS or a FUSE mount whose daemon is gone, an image layer on a stalled " +
            "disk - and the remedy is that path, not a longer timeout",
        );
      return sandboxFault(
        "timeout",
        `exceeded the ${timeoutS ?? this.timeoutS}s time limit (killed by the binding)`,
      );
    }
    // THE EXIT CODE IS THE RIGHT THING TO PROPAGATE AND THE WRONG THING TO CLASSIFY FROM: kern reports
    // the workload's status as `128 + N`, so a workload the kernel killed and one that called `exit(137)`
    // are the same number. MEASURED through the Python binding: `sys.exit(137)` came back `killed` with a
    // message about an external kill that never happened, and `sys.exit(159)` came back `escape_blocked`,
    // a security event a cell could fabricate in one line. kern's 4th started-byte carries the signal.
    // `null` (an older kern, or a kern our teardown killed first) keeps the old exit-code reading:
    // absence of evidence is not evidence. `signal === "SIG..."` is a different question, kern ITSELF
    // being signalled, and stays as it was.
    const killedBy = (n) => workloadSignal === null || workloadSignal === n;
    if ((rc === EXIT_SIGSYS && killedBy(SIG_SYS)) || signal === "SIGSYS")
      return sandboxFault("escape_blocked", "a syscall was blocked by the seccomp filter (SIGSYS)");
    if ((rc === EXIT_SIGKILL && killedBy(SIG_KILL)) || signal === "SIGKILL") {
      // Only kern's own OOM sentence buys the `oom` label (`kernReportedOom`, the one definition shared
      // with the resident-kernel and pool death paths).
      //
      // WHAT THIS REPLACED, because the replaced version read as sound: a SIGKILL of a memory-capped box
      // was called the cgroup OOM-killer, which is what a breached memory.max does (kern sets
      // memory.oom.group=1, so the whole box goes at once). MEASURED: `kern stop` during a cell returns
      // 137, so it came back `oom`, and an agent branching on the fault would retry with MORE MEMORY a
      // kill that had nothing to do with memory. A confident wrong answer is worse than no answer.
      if (oomVerdict(oomSignal, stderr, kernWrotePayload))
        return sandboxFault(
          "oom",
          "the box exceeded its memory cap and was OOM-killed (SIGKILL, exit 137)" + this._scratchNote(),
        );
      // `capSignal` (kern's UNFORGEABLE enforcement byte: 1 = enforced, 2 = requested but NOT enforced
      // here, 0 = undetermined) no longer decides the TYPE - a SIGKILL on a capped box is not evidence of
      // an OOM, whatever the byte says - and a 2 still earns its own sentence, because "your cap was not
      // in force here" is the one thing the caller cannot find out for itself.
      if (capSignal === 2)
        return sandboxFault(
          "killed",
          "the box was SIGKILLed, and its memory cap was not enforced here (no cgroup delegation), so no memory limit was in force to attribute it to",
        );
      if (this.memoryMb !== null)
        return sandboxFault(
          "killed",
          "the box was SIGKILLed and the kernel reported no OOM against its memory cap: this is an external kill (`kern stop`, a signal, or the host's own OOM killer), not the box exceeding its own memory",
        );
      return sandboxFault("killed", "the box was killed (SIGKILL); no memory cap was set to attribute it to OOM");
    }
    if ((rc === EXIT_SIGTERM && killedBy(SIG_TERM)) || signal === "SIGTERM")
      return sandboxFault("timeout", "the box exceeded its time limit (reaped by kern's timeout backstop)");
    // Box-not-started: a non-zero exit whose stderr carries kern's OWN setup markers (printed by the
    // PARENT before the box runs). kern's box-not-started paths BOTH exit 125 AND print a `kern:` marker,
    // so `rc === 125 && marker` is the reliable signal - the marker is REQUIRED so a workload that merely
    // exits 125 ITSELF (the code ran and chose 125) is NOT mislabeled. `finish` REJECTS only on rc===125;
    // a non-125 startup_failed (an older kern's 127, or a forged marker) is returned as DATA, not thrown.
    if (rc !== 0 && looksLikeStartupFailure(stderr))
      return sandboxFault("startup_failed", startupFailureMessage(stderr));
    // Any other non-zero exit (incl. 139 SIGSEGV) is the USER's code failing - a normal Result.
    return null;
  }

  // -- workspace file I/O (host-direct; single-uid -> box files are host-owned) ---------------------

  _wsPath(rel) {
    // A NUL BYTE IS REFUSED HERE, in the same words Python uses. Without it, node's own check fires
    // deeper and the caller reads "The argument 'path' must be a string, Uint8Array...", which names
    // the argument's TYPE for a path that is a perfectly good string. Found through the Python MCP
    // server, where the same input surfaced as `internal error: ValueError`; both bindings answer the
    // question that was asked now.
    if (typeof rel === "string" && rel.includes("\u0000")) {
      throw new SandboxError(
        `path contains a NUL byte: ${JSON.stringify(rel)}. A NUL terminates a path for every API ` +
          `below this one, so the name cannot mean what it appears to say`,
      );
    }
    // Lexical containment: normalize `..`/`.`, require it stays under the workspace base. Symlinks in
    // the final component are neutralized by O_NOFOLLOW on the actual open below.
    //
    // AN ABSOLUTE PATH IS NOT A WORKSPACE PATH, and it takes its own check because `path.join` KEEPS the
    // base for an absolute second argument while Python's `os.path.join` DROPS it. The same three lines
    // therefore refused in the Python binding and silently resolved `<workspace>/etc/passwd` here:
    // MEASURED, `readFile("/etc/passwd")` returned a decoy the box had planted at that relative path and
    // `writeFile("/etc/passwd")` wrote into it. The boundary held either way; the ANSWER was a different
    // file's contents than the one asked for, which is worse than an error. A caller who passes a host
    // path is asking for a host file, so the honest answer is a refusal.
    const base = this._ws;
    if (path.isAbsolute(rel))
      throw new SandboxError(
        `path escapes the workspace: ${JSON.stringify(rel)} is absolute, and these calls take a path ` +
          "RELATIVE to the workspace. Nothing outside it is readable or writable through them, and an " +
          "absolute path is NOT reinterpreted as a workspace one",
      );
    const full = path.normalize(path.join(base, rel));
    if (full !== base && !full.startsWith(base + path.sep))
      throw new SandboxError(`path escapes the workspace: ${JSON.stringify(rel)}`);
    return full;
  }

  /** The workspace's own directory as a descriptor: where every descent into it starts. */
  _wsFd() {
    return fs.openSync(this._ws, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  }

  /** The directory `parts` names under `baseFd`, opened one component at a time with `O_NOFOLLOW`
   * through the previous one (`/proc/self/fd/<fd>/<part>`), and created when `create` and missing.
   * Returns a descriptor the caller closes (`baseFd` itself for no parts). A symlink or a
   * non-directory on the way is refused by name; any other error (EACCES included, for a shared
   * workspace's fallback) is raised as it is. Mirrors Python's `_descend_dirs`.
   *
   * THE ONE DESCENT for everything the host creates in the workspace. `mkdirSync` of
   * `/proc/self/fd/<fd>/<part>` creates inside the directory the descriptor holds, whatever its path
   * says now: the `mkdirat` Node does not have. It replaces an `lstat` and a `mkdir` by path, between
   * which a box running beside the call could swap the component for a symlink and have the `mkdir`
   * land wherever the link pointed. */
  /** A descriptor on `p` if it lies inside the workspace, opened through `_descendDirs` and
   * O_NOFOLLOW so no symlink the box planted on the way is followed; null when it lies outside, where
   * the path is the caller's own. Inside is decided on the path as written and on its parent's real
   * location, so a caller's own link into the workspace is not a way round it. Mirrors Python's
   * `_open_in_workspace`. */
  _openInWorkspace(p, write) {
    const ws = this._ws.replace(/\/+$/, "");
    const lexical = path.resolve(p);
    let rel;
    if (lexical.startsWith(ws + path.sep)) rel = path.relative(ws, lexical);
    else {
      let parent;
      try {
        parent = fs.realpathSync(path.dirname(lexical));
      } catch {
        return null;
      }
      if (parent !== ws && !parent.startsWith(ws + path.sep)) return null;
      rel = path.relative(ws, path.join(parent, path.basename(lexical)));
    }
    const verb = write ? "snapshot to" : "restore from";
    this._wsPath(rel); // the lexical refusals every host-side workspace path gets
    const parts = rel.split(path.sep).filter((c) => c && c !== ".");
    if (!parts.length) throw new SandboxError(`cannot ${verb} the workspace directory itself`);
    const root = this._wsFd();
    let fd;
    try {
      const parent = this._descendDirs(root, parts.slice(0, -1));
      try {
        const flags =
          fs.constants.O_NOFOLLOW |
          fs.constants.O_NONBLOCK |
          (write ? fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC : fs.constants.O_RDONLY);
        try {
          fd = fs.openSync(`/proc/self/fd/${parent}/${parts[parts.length - 1]}`, flags, 0o644);
        } catch (e) {
          throw pathRefusal(verb, rel, e);
        }
      } finally {
        if (parent !== root) fs.closeSync(parent);
      }
    } finally {
      fs.closeSync(root);
    }
    if (!fs.fstatSync(fd).isFile()) {
      fs.closeSync(fd);
      throw new SandboxError(`cannot ${verb} ${JSON.stringify(rel)}: not a regular file in the workspace`);
    }
    return fd;
  }

  _descendDirs(baseFd, parts, { create = false } = {}) {
    const flags = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;
    let cur = baseFd;
    for (const part of parts) {
      const at = `/proc/self/fd/${cur}/${part}`;
      let next;
      try {
        try {
          next = fs.openSync(at, flags);
        } catch (e) {
          if (e.code !== "ENOENT" || !create) throw e;
          try {
            fs.mkdirSync(at);
          } catch (m) {
            if (m.code !== "EEXIST") throw m; // made by someone else in between: opened by the same rules
          }
          next = fs.openSync(at, flags);
        }
      } catch (e) {
        if (cur !== baseFd) fs.closeSync(cur);
        if (e.code === "ELOOP")
          throw new SandboxError(`path escapes the workspace via a symlinked directory: ${JSON.stringify(part)}`, { cause: e });
        if (e.code === "ENOTDIR")
          throw new SandboxError(`workspace path component is not a directory: ${JSON.stringify(part)}`, { cause: e });
        throw e;
      }
      if (cur !== baseFd) fs.closeSync(cur);
      cur = next;
    }
    return cur;
  }

  /** Create the parent directories of `full` under the workspace WITHOUT following a symlink in any
   * intermediate component. `mkdir -p` follows symlinks, so a box that plants `a -> /etc` could steer a
   * `writeFile("a/b.txt")` outside the workspace even though the final component is O_NOFOLLOW. One
   * component at a time BY DESCRIPTOR: see `_descendDirs`. */
  _ensureParentDirs(full) {
    const parts = path.relative(this._ws, path.dirname(full)).split(path.sep).filter((p) => p && p !== ".");
    if (!parts.length) return; // parent is the workspace root itself
    const root = this._wsFd();
    try {
      const fd = this._descendDirs(root, parts, { create: true });
      if (fd !== root) fs.closeSync(fd);
    } finally {
      fs.closeSync(root);
    }
  }

  /** Open the PARENT of a workspace-relative path as a directory fd, one component at a time, each with
   * `O_NOFOLLOW`, and return that fd. The caller then opens the leaf THROUGH it via
   * `/proc/self/fd/<dirfd>/<leaf>`, which the kernel resolves from the pinned descriptor rather than from
   * the path string, so no component can be swapped between the check and the open.
   *
   * WHY, and it is the one asymmetry a security review found in this file: `readFile` has a race-free
   * backstop (`_assertFdInWorkspace` on the open fd, line ~2094) and `writeFile` had only the `lstat`
   * pre-check in `_ensureParentDirs` plus `O_NOFOLLOW` on the LEAF. `O_NOFOLLOW` does not touch
   * intermediate components, so a box that swaps `mid` from a directory to a symlink in the window
   * between the descent and the open makes the host create (and `O_TRUNC`) a file wherever that link
   * points. Measured here: 426 074 attempts against a concurrent swapper produced 0 escapes and 3
   * refusals, so the window is real and microseconds wide - too narrow to demonstrate cheaply and too
   * cheap to close to leave open. Python's binding never had it: it descends with `openat`.
   *
   * The fd is the caller's to close. A refusal carries the OS error as its `cause`. */
  _openParentDirNofollow(rel) {
    const base = fs.realpathSync(this._ws);
    const full = this._wsPath(rel);
    const relDir = path.relative(base, path.dirname(full));
    let dirFd = fs.openSync(base, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
    if (relDir === "" || relDir === ".") return dirFd;
    for (const part of relDir.split(path.sep)) {
      if (!part || part === ".") continue;
      let next;
      try {
        next = fs.openSync(
          `/proc/self/fd/${dirFd}/${part}`,
          fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW,
        );
      } catch (e) {
        fs.closeSync(dirFd);
        throw pathRefusal("write", rel, e);
      }
      fs.closeSync(dirFd);
      dirFd = next;
    }
    return dirFd;
  }

  /** Write `data` (Buffer|string) to `path` (workspace-relative) - host-direct, so the box sees it next
   * run. The final component is opened O_NOFOLLOW: a symlink the box planted can't redirect the write. */
  async writeFile(rel, data) {
    this._requireEntered();
    const full = this._wsPath(rel);
    const payload = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
    try {
      this._writeFileHost(rel, full, payload);
      return;
    } catch (e) {
      // A DIRECTORY THE BOX USER CLOSED TO US (a tarball's 0755): the helper writes it, as its owner.
      if (!this._shared || !isClosedErr(e.cause ?? e)) throw e;
    }
    const r = await this._wsHelper(HELPER_WRITE, this._helperParts(full), { write: true, input: payload });
    if (r.code !== 0) throw this._helperRefusal("write", rel, r);
  }

  /** `writeFile` on the host. */
  _writeFileHost(rel, full, payload) {
    this._ensureParentDirs(full); // creates missing dirs, symlink-safe, NOT mkdir -p (which follows one)
    // THE LEAF IS OPENED THROUGH A PINNED PARENT FD, not by path: see `_openParentDirNofollow`.
    const dirFd = this._openParentDirNofollow(rel);
    let fd;
    try {
      // O_NONBLOCK for the same reason as readFile, and the write side is the WORSE of the two: opening
      // a FIFO for writing blocks until a reader appears, and with the flag it fails outright (ENXIO)
      // instead. Either way the call returns to the caller rather than parking there.
      fd = fs.openSync(
        `/proc/self/fd/${dirFd}/${path.basename(full)}`,
        fs.constants.O_WRONLY |
          fs.constants.O_CREAT |
          fs.constants.O_TRUNC |
          fs.constants.O_NOFOLLOW |
          fs.constants.O_NONBLOCK,
        // 0o664 ON A SHARED WORKSPACE: the mode's group bits ARE the ACL mask, and 0o644 would cap the
        // box user's entry at read. Nobody else gains: the inherited group and other entries are empty.
        this._shared ? 0o664 : 0o644,
      );
    } catch (e) {
      throw pathRefusal("write", rel, e);
    } finally {
      fs.closeSync(dirFd);
    }
    // AND THE BACKSTOP THE READ PATH ALREADY HAD: where did the descriptor actually land?
    this._assertFdInWorkspace(fd, rel);
    try {
      // The file the box left at this name has to be a REGULAR file before we write into it: writing
      // into a device node or a socket the box planted is host I/O it chose the target of.
      if (!fs.fstatSync(fd).isFile())
        throw new SandboxError(
          `refusing to write ${JSON.stringify(rel)}: not a regular file (a FIFO, device or socket ` +
            `planted in the workspace can stall or redirect this write)`,
        );
      fs.writeSync(fd, payload);
    } finally {
      fs.closeSync(fd);
    }
  }

  /** Verify no INTERMEDIATE path component under the workspace is a symlink (read-only counterpart of
   * _ensureParentDirs). readFile follows directory components on open, so a box that plants `d -> /etc`
   * would otherwise leak host files via `readFile("d/x")` even with O_NOFOLLOW on the last component.
   * Descend one level at a time, reject a symlinked component. A refusal carries the OS error as its
   * `cause`. */
  _verifyParentDirs(full) {
    const base = this._ws;
    const relDir = path.relative(base, path.dirname(full));
    if (relDir === "" || relDir === ".") return;
    let cur = base;
    for (const part of relDir.split(path.sep)) {
      if (!part || part === ".") continue;
      const next = path.join(cur, part);
      let st;
      try {
        st = fs.lstatSync(next);
      } catch (e) {
        throw new SandboxError(`cannot resolve workspace path component: ${JSON.stringify(part)}`, { cause: e });
      }
      if (st.isSymbolicLink())
        throw new SandboxError(`path escapes the workspace via a symlinked directory: ${JSON.stringify(part)}`);
      if (!st.isDirectory())
        throw new SandboxError(`workspace path component is not a directory: ${JSON.stringify(part)}`);
      cur = next;
    }
  }

  /** RACE-FREE containment on an ALREADY-OPEN fd: the fd is pinned to the real file, so read WHERE it
   * actually landed via `/proc/self/fd` and refuse if a symlinked PARENT component (which O_NOFOLLOW on
   * the final component does not stop) redirected the open outside the workspace. Node has no `openat`,
   * so this closes the lstat-then-open TOCTOU that _verifyParentDirs alone would leave. */
  _assertFdInWorkspace(fd, rel) {
    let real;
    try {
      real = fs.readlinkSync(`/proc/self/fd/${fd}`);
    } catch {
      return; // /proc unavailable (non-Linux): the lstat pre-check already ran
    }
    const base = fs.realpathSync(this._ws);
    if (real !== base && !real.startsWith(base + path.sep))
      throw new SandboxError(`path escapes the workspace: ${JSON.stringify(rel)}`);
  }

  /** Read `path` (workspace-relative) from the workspace - host-direct. A symlink in the final component
   * is refused by O_NOFOLLOW; a symlinked intermediate component is caught by _verifyParentDirs (fast) AND
   * _assertFdInWorkspace (race-free, on the open fd) - no lstat-then-open TOCTOU. */
  async readFile(rel, { maxBytes = null } = {}) {
    this._requireEntered();
    const full = this._wsPath(rel);
    try {
      return this._readFileHost(rel, full, maxBytes);
    } catch (e) {
      // A FILE THE BOX USER CLOSED TO US (0600, or inside its 0700): the helper reads it, as its owner.
      if (!this._shared || !isClosedErr(e.cause ?? e)) throw e;
    }
    const limit = maxBytes === null ? "" : String(maxBytes + 1);
    const r = await this._wsHelper(HELPER_READ, [limit, ...this._helperParts(full)]);
    if (r.code !== 0) throw this._helperRefusal("read", rel, r);
    if (maxBytes !== null && r.stdout.length > maxBytes) throw maxBytesRefusal(rel, maxBytes, null);
    return r.stdout;
  }

  /** `readFile` on the host. */
  _readFileHost(rel, full, maxBytes) {
    this._verifyParentDirs(full); // fast reject + nice error before we open (host-leak guard)
    let fd;
    try {
      // O_NONBLOCK: opening a FIFO returns a descriptor instead of WAITING FOR A WRITER. Measured
      // before this flag: a box that runs `mkfifo out.png` makes `readFile("out.png")` hang with no
      // timeout and no way to interrupt it, so the box decides how long the host's call takes. That is
      // a denial of service the workspace hands out for free, and O_NOFOLLOW does not touch it.
      fd = fs.openSync(full, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    } catch (e) {
      throw pathRefusal("read", rel, e);
    }
    try {
      this._assertFdInWorkspace(fd, rel); // race-free backstop: a swapped-in parent symlink is caught here
      // AND THE FLAG ALONE WOULD BE WORSE THAN THE HANG. A non-blocking read of a writer-less FIFO
      // returns zero bytes, so `readFile` would answer `<Buffer >` and the caller would read an empty
      // file where the box had planted a pipe. Refuse anything that is not a REGULAR file: FIFO,
      // device, socket, directory. Judged on the OPEN DESCRIPTOR, not on a path that can be swapped.
      const st = fs.fstatSync(fd);
      if (!st.isFile())
        throw new SandboxError(
          `refusing to read ${JSON.stringify(rel)}: not a regular file (a FIFO, device or socket ` +
            `planted in the workspace can stall or fake this read)`,
        );
      // maxBytes caps the read so a file a not-fully-trusted box wrote can't OOM the host.
      if (maxBytes !== null && st.size > maxBytes) throw maxBytesRefusal(rel, maxBytes, st.size);
      return fs.readFileSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }

  /** List regular files under the workspace (excluding the .deps install dir and our env file). */
  async listFiles(subdir = "") {
    this._requireEntered();
    let root;
    if (subdir) {
      root = this._wsPath(subdir);
      // a box that plants `peek -> /tmp` must not make listFiles("peek") enumerate a host dir's names
      // (the walk's followlinks=false does NOT stop it, since it follows the ROOT). Reject a symlinked
      // subdir (parents via _verifyParentDirs, the final component via lstat); the walk then descends by
      // descriptor whatever the path says by then.
      let st = null;
      try {
        this._verifyParentDirs(root);
        st = fs.lstatSync(root);
      } catch (e) {
        if (!(this._shared && isClosedErr(e.cause ?? e))) {
          if (e instanceof SandboxError) throw e;
          throw new SandboxError(`cannot list ${JSON.stringify(subdir)}`, { cause: e });
        }
      }
      if (st === null) {
        // The same check, by the box user: a directory, no symlink on the way.
        const r = await this._wsHelper(HELPER_ISDIR, this._helperParts(root));
        if (r.code !== 0) throw this._helperRefusal("list", subdir, r);
      } else {
        if (st.isSymbolicLink())
          throw new SandboxError(`path escapes the workspace via a symlinked directory: ${JSON.stringify(subdir)}`);
        if (!st.isDirectory()) throw new SandboxError(`not a directory: ${JSON.stringify(subdir)}`);
      }
    } else {
      root = this._ws;
    }
    const walked = await this._walk(root);
    return Object.entries(walked).map(([p, [, size]]) => ({ path: p, size, change: "created" }));
  }

  // -- workspace snapshot (a cheap FILESYSTEM checkpoint; NOT a memory snapshot) --------------------

  /** Write a gzip tar of the whole workspace to `dest` on the host, a portable filesystem checkpoint.
   * Pair with restore() (or seed a new Sandbox({ workspace })) to resume the FILE state later or
   * elsewhere. NOT a memory snapshot: processes are ephemeral, only on-disk state is captured. */
  // The Node snapshot/restore path uses a HAND-ROLLED ustar parser. While it is new, it is opt-in: set
  // KERN_SANDBOX_SNAPSHOT=1 to enable it. Fails CLOSED (refuses, never silently degrades). The Python
  // binding uses the stdlib `tarfile` and has no such gate. Remove this once the parser is battle-tested.
  _requireSnapshotOptIn() {
    if (process.env.KERN_SANDBOX_SNAPSHOT !== "1")
      throw new SandboxError(
        "snapshot/restore is opt-in in the Node binding while its archive parser is new: " +
          "set KERN_SANDBOX_SNAPSHOT=1 to enable it (the Python binding uses stdlib tarfile and is always on)",
      );
  }

  snapshot(dest) {
    this._requireEntered();
    this._requireSnapshotOptIn();
    // A `dest` INSIDE THE WORKSPACE is opened first, by descriptor (see `_openInWorkspace`): by path, a
    // symlink the box planted at that name sent the archive onto the host file it named. Closed in the
    // `finally` below on every path, the walk's errors included.
    const outFd = this._openInWorkspace(dest, true);
    try {
      this._snapshotInto(dest, outFd);
    } finally {
      if (outFd !== null) closeQuietly(outFd);
    }
  }

  /** The body of snapshot(): `outFd` is the open `dest` when it is inside the workspace, else null. */
  _snapshotInto(dest, outFd) {
    // BY DESCRIPTOR (see `tarCollect`). The archive is built in memory, as it always was here; the
    // helper's part of it is bounded by the same 1 GiB `restore` refuses past.
    const out = [];
    const blind = this._shared ? [] : null;
    const skipped = [];
    // The identity of `dest`, which the walk skips, or every checkpoint written into the workspace
    // would carry the one before it.
    let destId = null;
    try {
      const st = outFd !== null ? fs.fstatSync(outFd) : fs.statSync(dest);
      destId = `${st.dev}:${st.ino}`;
    } catch {
      /* not there yet */
    }
    const root = this._wsFd();
    try {
      // THE RECORD FIRST: what `.deps` was built for (see SNAPSHOT_RECORD). Mirrors Python.
      let hasDeps = false;
      try {
        hasDeps = fs.lstatSync(`/proc/self/fd/${root}/${DEPS_DIR}`).isDirectory();
      } catch {
        hasDeps = false;
      }
      tarWriteFile(
        out,
        SNAPSHOT_RECORD,
        Buffer.from(
          JSON.stringify({ [SNAPSHOT_RECORD_KEY]: 1, image: this.image, machine: hostMachine(), deps: hasDeps }),
        ),
        // WHEN THIS SNAPSHOT WAS TAKEN. The record is this package's own member, not a file from the
        // workspace, so its mtime is the only timestamp the archive carries about ITSELF - and
        // Python's `tf.add` of the record has always written it. It was 0 here, which dated every
        // Node snapshot to the epoch.
        Math.floor(Date.now() / 1000),
        0o644,
      );
      tarCollect(root, "", destId, out, blind, skipped);
    } finally {
      fs.closeSync(root);
    }
    if (blind && blind.length) {
      // What the box user closed to us is read by the box user: one `tar` in the helper box,
      // re-emitted file by file in this archive's own format. Mirrors Python.
      const r = this._wsHelperSync(HELPER_TAR, blind.map(helperSubtree));
      if (r.code !== 0)
        throw new SandboxError(
          `snapshot: the box user could not read ${JSON.stringify(blind)}: ${r.stderr.trim().slice(-400)}`,
        );
      for (const m of tarParseRaw(r.stdout)) {
        const name = m.name.replace(/^\.\//, "");
        // THE NAME IS VETTED, because this stream comes from a `tar` in the IMAGE (see
        // `_helperArgv`): a member named `../../../.ssh/authorized_keys` or `/etc/passwd` would be
        // written into an archive this package documents as a safe checkpoint. `restore` refuses
        // such a member, and so do GNU tar and bsdtar, but a third extractor is not ours to assume.
        // Same chokepoint and same warning as Python's `_snapshot_blind`.
        let confined = false;
        try {
          this._wsPath(name);
          confined = true;
        } catch {
          confined = false;
        }
        if (!confined) {
          if (name) skipped.push(name);
          continue;
        }
        // Directories come with their files, as on the host walk above; anything else is named.
        if (m.type === "file") tarWriteFile(out, name, m.content);
        else if (m.type === "other" && name) skipped.push(name);
      }
    }
    const archive = tarFinish(out);
    if (outFd === null) fs.writeFileSync(dest, archive);
    else for (let off = 0; off < archive.length; ) off += fs.writeSync(outFd, archive, off, archive.length - off);
    if (skipped.length)
      process.emitWarning(
        `snapshot: ${skipped.length} entr${skipped.length === 1 ? "y" : "ies"} not archived, because restore ` +
          `writes only regular files and directories (a symlink, FIFO, device or socket in the archive ` +
          `would make the whole snapshot unrestorable): ${skipped.slice(0, 5).map((x) => JSON.stringify(x)).join(", ")}` +
          (skipped.length > 5 ? ", ..." : ""),
        "KernSnapshotIncomplete",
      );
  }

  /** `_wsHelper` for the synchronous `snapshot`/`restore`, through `spawnSync`: those methods already
   * block on their own file I/O, and this is reached only after the host was refused. */
  _wsHelperSync(script, args, { write = false, input = null, timeoutS = 120 } = {}) {
    const argv = this._helperArgv(script, args, write, timeoutS);
    const r = spawnSync(argv[0], argv.slice(1), {
      input: input || Buffer.alloc(0),
      timeout: (timeoutS + 30) * 1000,
      maxBuffer: TAR_MAX_BYTES,
    });
    return this._helperResult({
      code: r.error || r.status === null ? -1 : r.status,
      stdout: r.stdout || Buffer.alloc(0),
      stderr: r.error ? String(r.error.message) : String(r.stderr || ""),
    });
  }

  /** Extract a snapshot (from snapshot()) into the workspace, SAFELY. Every member is vetted first:
   * absolute paths, `..` escapes and non-file/dir members (symlinks, devices, hardlinks) are refused,
   * and each path must resolve under the workspace; then every member is written BY DESCRIPTOR from
   * the workspace's own (see `_restoreHost`). Colliding files are overwritten. */
  restore(src) {
    this._requireEntered();
    this._requireSnapshotOptIn();
    const base = fs.realpathSync(this._ws);
    // A `src` INSIDE THE WORKSPACE is read by descriptor: by path, a symlink the box planted there made
    // this read a HOST archive and restore it where the box can read it.
    const inFd = this._openInWorkspace(src, false);
    let raw;
    try {
      raw = fs.readFileSync(inFd !== null ? inFd : src);
    } finally {
      if (inFd !== null) fs.closeSync(inFd);
    }
    let members = tarParse(raw);
    // The provenance record, if this archive carries one: FIRST, a regular file, small, holding its
    // key. Read here and never written into the workspace. Mirrors Python.
    let originNote = null;
    if (
      members.length &&
      members[0].name === SNAPSHOT_RECORD &&
      members[0].type === "file" &&
      members[0].content.length <= SNAPSHOT_RECORD_MAX
    ) {
      const record = snapshotRecord(members[0].content);
      if (record !== null) {
        members = members.slice(1);
        const hasDeps = members.some((m) => m.name === DEPS_DIR || m.name.startsWith(`${DEPS_DIR}/`));
        originNote = snapshotOriginNote(record, this.image, hostMachine(), hasDeps);
      }
    }
    for (const m of members) {
      if (m.name === "") continue;
      if (m.name.startsWith("/") || m.name.split("/").includes(".."))
        throw new SandboxError(`unsafe path in snapshot: ${JSON.stringify(m.name)}`);
      if (m.type === "other")
        throw new SandboxError(`unsafe member type in snapshot (only files/dirs): ${JSON.stringify(m.name)}`);
      const resolved = path.resolve(base, m.name);
      if (resolved !== base && !resolved.startsWith(base + path.sep))
        throw new SandboxError(`snapshot member escapes the workspace: ${JSON.stringify(m.name)}`);
    }
    try {
      this._restoreHost(members);
    } catch (e) {
      if (!this._shared || !isClosedErr(e.cause ?? e)) throw e;
      // A DIRECTORY THE BOX USER CLOSED TO US is in the way: the helper, as that user, extracts the
      // same vetted members, directories included, in one box (`-o`: no ownership from the archive).
      const out = [];
      for (const m of members) {
        if (m.name === "") continue;
        if (m.type === "dir") tarWriteDir(out, m.name);
        else tarWriteFile(out, m.name, m.content);
      }
      const r = this._wsHelperSync(HELPER_UNTAR, [], { write: true, input: tarFinish(out, false) });
      if (r.code !== 0)
        throw new SandboxError(`restore: the box user could not extract: ${r.stderr.trim().slice(-400)}`);
    }
    if (this._shared) {
      // The files written above are ours with this format's fixed mode: the box user gets its entry
      // back, on the whole tree and by descriptor, for the reason `aclGrantBatches` gives. Mirrors Python.
      try {
        aclGrantTreeSync(this._ws, this._userHostUid, process.getuid());
      } catch (e) {
        throw new SandboxError(`restore: sharing the restored files with the box user failed: ${e.message}`, { cause: e });
      }
    }
    // SAID AFTER THE RESTORE SUCCEEDED, not thrown: a pure-JS or pure-Python dependency runs anywhere.
    if (originNote !== null) process.emitWarning(originNote, "KernSnapshotOrigin");
  }

  /** The host half of `restore`: the vetted `members` written under the workspace, every path reached
   * BY DESCRIPTOR from the workspace's own (`_descendDirs`), so a box running beside this call cannot
   * turn a member's parent into a symlink between the vetting and the write. */
  _restoreHost(members) {
    const flags =
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;
    // THE CREATION MODE IS OWNER-ONLY and the member's own mode is applied after the bytes, which is
    // the rule Python's `_restore_host` states: a mode out of an archive carries the SOURCE
    // workspace's ACL mask in its group bits (granting a box account rewrites `mask::`, which IS the
    // group mode), and the ACL does not travel in a tar - so restoring the group bits turns a mask
    // back into real group access. It was `this._shared ? 0o664 : 0o644`, which widened it by
    // construction on exactly the shared workspaces where the mask exists. A box account reaches
    // what it needs through the ACL the session grants, not through these bits.
    const createMode = 0o600;
    const root = this._wsFd();
    // DIRECTORY MTIMES GO LAST, DEEPEST FIRST, because writing a file into a directory updates that
    // directory's mtime: set in member order, every directory with children would end up carrying
    // the moment of the restore instead of the moment the snapshot captured. Python's restore has
    // the same two-pass shape for the same reason; this is the Node half of it.
    const dirTimes = [];
    try {
      for (const m of members) {
        const parts = m.name.split("/").filter((p) => p && p !== ".");
        if (!parts.length) continue;
        const parent = this._descendDirs(root, parts.slice(0, -1), { create: true });
        try {
          const leaf = parts[parts.length - 1];
          if (m.type === "dir") {
            try {
              fs.mkdirSync(`/proc/self/fd/${parent}/${leaf}`);
            } catch (e) {
              if (e.code !== "EEXIST") throw e;
            }
            try {
              fs.closeSync(this._descendDirs(parent, [leaf])); // a real directory, not a link swapped in
            } catch (e) {
              throw new SandboxError(`snapshot dir member collides with a non-directory: ${JSON.stringify(m.name)}`, { cause: e });
            }
            if (m.mtime > 0) dirTimes.push([parts, m.mtime]);
            continue;
          }
          let fd;
          try {
            fd = fs.openSync(`/proc/self/fd/${parent}/${leaf}`, flags, createMode);
          } catch (e) {
            throw pathRefusal("restore", m.name, e);
          }
          try {
            if (!fs.fstatSync(fd).isFile())
              throw new SandboxError(`refusing to restore ${JSON.stringify(m.name)}: not a regular file in the workspace`);
            // EVERY BYTE, OR AN ERROR: `writeSync` is one write(2) and may write fewer bytes than it
            // was given (a filling disk is where that shows), which left the file short with restore
            // reporting success. Mirrors Python.
            for (let off = 0; off < m.content.length; ) off += fs.writeSync(fd, m.content, off, m.content.length - off);
            // THE MTIME THE MEMBER CARRIED, on the DESCRIPTOR: no path is re-resolved, so a box
            // running beside this call cannot steer the timestamp onto another inode. Best effort,
            // as Python's is: a target this process may not touch (one the box account owns) is not
            // a reason to fail a restore that has already written every byte.
            // THE MODE, THEN THE TIME, in that order: `fchmod` does not change an mtime, while a
            // write does, so setting the time last is what makes it stick. Owner bits only, with a
            // 0600 floor so a member whose mode was 0400 is still writable by the session that
            // restored it, and the execute bit only when the owner had it - the same three rules
            // `_restore_host` applies in Python, so one archive restores the same way on both.
            const want = m.mode === null ? null : 0o600 | (m.mode & 0o700);
            if (want !== null) {
              try {
                fs.fchmodSync(fd, want & 0o100 ? want : want & ~0o111);
              } catch {
                /* a target this process may not chmod (one the box account owns): best effort */
              }
            }
            if (m.mtime > 0) {
              try {
                fs.futimesSync(fd, m.mtime, m.mtime);
              } catch {
                /* a mode or an owner this process cannot set a time on: the bytes are the restore */
              }
            }
          } finally {
            fs.closeSync(fd);
          }
        } finally {
          if (parent !== root) fs.closeSync(parent);
        }
      }
      // DEEPEST FIRST, so a parent's time is set after every child has been written into it.
      dirTimes.sort((a, b) => b[0].length - a[0].length);
      for (const [parts, mtime] of dirTimes) {
        let fd;
        try {
          fd = this._descendDirs(root, parts, { create: false });
        } catch {
          continue; // a directory a concurrent box removed between the write and this pass
        }
        try {
          fs.futimesSync(fd, mtime, mtime);
        } catch {
          /* best effort, as above */
        } finally {
          if (fd !== root) fs.closeSync(fd);
        }
      }
    } finally {
      fs.closeSync(root);
    }
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
    // PRECOMPILE HERE, because this is the last moment `.deps` is writable.
    //
    // `depsReadonly` defaults to true, so every runCode box mounts `.deps` read-only and CPython cannot
    // write a `__pycache__` into it. It tolerates that silently and recompiles on every import instead,
    // which is correct and is not free. Measured on `requests`, seven calls each: a setup that leaves
    // bytecode behind (pip's default) reads 250 ms/call writable and 252 read-only, while one that does
    // not (`pip install --no-compile`) reads 250 writable and 290 read-only. So the read-only default
    // would cost +40 ms on EVERY call of such a session, for as long as it lives. One `compileall` here
    // removes it: that case comes back to 250, and it is a no-op when the bytecode already exists.
    //
    // `|| true` because bytecode is an optimisation: a file that will not compile must not fail an
    // install that succeeded. The user's command ran first and separately, so it keeps the exit code.
    if (this.depsReadonly && fs.existsSync(path.join(this._ws, DEPS_DIR))) {
      await this._spawn(["sh", "-c", `python3 -m compileall -q ${WORKSPACE}/${DEPS_DIR} || true`], {
        network: false,
        timeoutS: Math.max(this.timeoutS, 120),
        isSetup: true,
      });
    }
  }

  // -- files diff (created/modified; excludes .deps and our env file) ------------------------------

  async _snapshot() {
    return this._walk(this._ws);
  }

  async _walk(root) {
    // BY DESCRIPTOR, from the workspace's own fd down: each directory opened `O_NOFOLLOW` through the
    // one it was listed from, and listed through that descriptor. A walk by path re-resolved every
    // directory, so a box running beside this call could turn one into a symlink after it was listed
    // and have the next listing read a HOST directory, whose names and sizes then came back in
    // `files`. Mirrors Python's `_walk`.
    //
    // A DIRECTORY THIS PROCESS CANNOT READ is collected, not skipped: with a non-root `user` the box
    // user can close one to us, and its files would be missing from `files` and `listFiles` with
    // nothing to say so.
    const out = {};
    const blind = [];
    const dirFlags = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;
    const top = path.relative(this._ws, root);
    const rootFd = this._wsFd();
    // Two kinds of frame, so the descriptors held are the current directory's ANCESTORS and nothing
    // else: [rel, parentFd] to open and list, and [null, fd] to close, pushed UNDER a directory's
    // children so it runs after the last of them.
    //
    // ONE PER DEPTH LEVEL, NOT ONE PER ENTRY. The first version opened every subdirectory while
    // listing the parent and held them all: a box that makes 150k directories had the diff after its
    // own call open 150k descriptors, and `stack.push(...subdirs)` spread that many arguments, which
    // is past V8's argument limit and throws RangeError - with every descriptor in `subdirs` leaking,
    // so each repeat leaked another batch. On a host with a lower limit the opens failed instead and
    // those subtrees were silently absent from `files` and `listFiles`.
    const stack = [[top, -1]];
    try {
      while (stack.length) {
        const [relDir, parentFd] = stack.pop();
        if (relDir === null) {
          closeQuietly(parentFd);
          continue;
        }
        let fd;
        if (parentFd < 0) {
          try {
            fd = this._descendDirs(rootFd, top ? top.split(path.sep) : []);
          } catch (e) {
            if (this._shared && isClosedErr(e.cause ?? e)) blind.push(top);
            // otherwise nothing there to walk, as a walk of a missing root yielded nothing
            continue;
          }
        } else {
          const name = relDir.slice(relDir.lastIndexOf("/") + 1);
          try {
            fd = fs.openSync(`/proc/self/fd/${parentFd}/${name}`, dirFlags);
          } catch (e) {
            if (this._shared && isClosedErr(e)) {
              blind.push(relDir);
              continue;
            }
            // GONE IS CHURN, ANYTHING ELSE IS NOT: a workspace a box is writing to loses entries
            // (ENOENT) and has them replaced by non-directories (ENOTDIR for a symlink under
            // O_NOFOLLOW, ELOOP). Running out of descriptors or memory is thrown, because a listing
            // that quietly drops a subtree reports a workspace smaller than it is.
            if (WALK_GONE.has(e.code)) continue;
            throw e;
          }
        }
        let keepOpen = false;
        try {
          let entries;
          try {
            entries = fs.readdirSync(`/proc/self/fd/${fd}`, { withFileTypes: true });
          } catch (e) {
            // A directory that OPENED and will not list: on a shared workspace that is the box
            // user's to read (`tarCollect` already treated it so), and it used to vanish in silence.
            if (this._shared && isClosedErr(e)) {
              blind.push(relDir);
              continue;
            }
            if (WALK_GONE.has(e.code)) continue;
            throw e;
          }
          const subdirs = [];
          for (const ent of entries) {
            const rel = relDir ? `${relDir}/${ent.name}` : ent.name;
            let st;
            try {
              st = fs.lstatSync(`/proc/self/fd/${fd}/${ent.name}`);
            } catch (e) {
              if (this._shared && isClosedErr(e)) {
                blind.push(relDir); // listable, not searchable: ask for it whole
                break;
              }
              continue;
            }
            if (st.isDirectory()) {
              if (ent.name === DEPS_DIR) continue; // exclude deps from the diff, at any depth
              subdirs.push(rel);
              continue;
            }
            if (!st.isFile()) continue; // excludes symlinks and non-regular files
            // THE BARE NAME ONLY, not the family `isLegacyEnvFile` matches: a listing is the
            // operator's view, and every other shape in that pattern (12 free hex digits, 191 free
            // characters) is one a cell can create, so skipping them here let a box hide a file from
            // `files`/`listFiles`. The snapshot path still skips the whole family, because an
            // archive travels and a stale env file holds `env` values. Python's `_is_ours` matches.
            if (rel === ENV_FILE) continue;
            out[rel] = [Math.round(st.mtimeMs * 1e6), st.size];
          }
          if (subdirs.length) {
            if (fd !== rootFd) {
              stack.push([null, fd]); // closed after the last of its children
              keepOpen = true;
            }
            for (let i = subdirs.length - 1; i >= 0; i--) stack.push([subdirs[i], fd]);
          }
        } finally {
          if (!keepOpen && fd !== rootFd) fs.closeSync(fd);
        }
      }
    } finally {
      for (const [rel, fd] of stack) if (rel === null && fd !== rootFd) closeQuietly(fd);
      fs.closeSync(rootFd);
    }
    if (blind.length) {
      // ONE helper box for every blind subtree. Its mtimes are whole seconds (`stat -c %Y`); a file is
      // always seen through the same path while its directory keeps its mode.
      const r = await this._wsHelper(HELPER_LIST, blind.map(helperSubtree));
      if (r.code !== 0)
        // SAID, NOT THROWN: `files` is a report and the call it describes already ran. Mirrors Python.
        process.emitWarning(
          `result.files / listFiles may be missing entries: the box user could not list ` +
            `${JSON.stringify(blind)} (${String(r.stderr).trim().slice(-400) || `exit ${r.code}`})`,
          "KernWorkspaceListing",
        );
      for (const [rel, mode, size, mtime] of parseHelperList(r.stdout)) {
        if ((mode & 0o170000) !== 0o100000 || underDeps(rel) || rel === ENV_FILE) continue;
        out[rel] = [mtime * 1e9, size];
      }
    }
    return out;
  }

  async _diff(before) {
    const after = await this._snapshot();
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
   * next call; in-memory state does NOT. `language` is "python" (default), "bash", "sh" or "node", and
   * the image must provide it: "bash" runs bash, not the POSIX shell. Large
   * code is written to a workspace file and run by path (no argv-size limit). */
  /** Resolve a per-call `timeoutS` override against the constructor default: undefined/null inherits
   * the session's, any override must be a positive number of seconds. */
  _effTimeout(timeoutS) {
    if (timeoutS === undefined || timeoutS === null) return this.timeoutS;
    if (typeof timeoutS !== "number" || !(timeoutS > 0))
      throw new SandboxError("timeoutS must be a positive number of seconds");
    return timeoutS;
  }

  async runCode(code, { language = "python", timeoutS, onStdout = UNSET, onStderr = UNSET } = {}) {
    this._requireEntered();
    // Each runner: [binary, inline-eval-flag, file-extension]. Note node evaluates with `-e`, NOT `-c`
    // (which is node's syntax-CHECK flag and would run nothing); python/sh use `-c`.
    // `bash` runs BASH. It used to run `sh`, and on a Debian image that is `dash`, with bash sitting
    // right there in the image unused: `[[ 1 == 1 ]]` answered `sh: 1: [[: not found`. Nothing was
    // missing, the wrong binary was picked, and an LLM writes bash by reflex. `sh` is the honest name
    // for the old behaviour and is now reachable: POSIX, present in every image, alpine included.
    const runners = {
      python: ["python3", "-c", "py"],
      bash: ["bash", "-c", "sh"],
      sh: ["sh", "-c", "sh"],
      node: ["node", "-e", "js"],
    };
    const spec = runners[language];
    if (!spec)
      throw new SandboxError(
        `unsupported language ${JSON.stringify(language)} (v1: 'python' | 'bash' | 'sh' | 'node')`,
      );
    const [runner, evalFlag, ext] = spec;
    // REFUSED HERE, BECAUSE THE ANSWER IS ALREADY KNOWN, and this binding advertised it hardest:
    // the example at the top of this file was `runCode("console.log(1 + 1)", { language: "node" })`,
    // which cannot work as written because the default image has no node. MEASURED on
    // python:3.12-slim: python, sh and bash 5.2 all run there, node does not. So a caller who leaves
    // the image alone is told at the moment of the choice, with the remedy, rather than paying a box
    // start to be told the same thing by an `exec_failed` fault.
    //
    // ⛔ ONLY for the default image. For an image the caller NAMED, kern does not know what is inside
    // it, and refusing on a guess would be inventing a measurement; that case still reaches the box.
    // Kept identical to the Python binding, which has the same check for the same reason: the two
    // are one API with two spellings, and a divergence here is a divergence in the product.
    if (language === "node" && this.image === DEFAULT_IMAGE && !DEFAULT_IMAGE_HAS_NODE) {
      throw new SandboxError(
        `language='node' needs an image that provides node, and this Sandbox is on the default ` +
          `${JSON.stringify(DEFAULT_IMAGE)}, which does not (it provides python, sh and bash). ` +
          `Name one that does, e.g. new Sandbox({ image: "node:22-slim" }), or run the code with ` +
          `language='python'.`,
      );
    }
    const eff = this._effTimeout(timeoutS);
    if (language === "python")
      return this._runPythonCell(code, { timeoutS: eff, onStdout, onStderr });
    let command;
    if (Buffer.byteLength(code, "utf8") > INLINE_CODE_MAX) {
      const cell = `.cell-${crypto.randomBytes(4).toString("hex")}.${ext}`;
      await this.writeFile(cell, code);
      command = [runner, `${WORKSPACE}/${cell}`];
    } else {
      command = [runner, evalFlag, code];
    }
    return this._spawn(command, { network: this.network, timeoutS: eff, onStdout, onStderr });
  }

  /** Run Python through the cell runner so a trailing expression, display() calls and matplotlib
   * figures are captured as rich mime-typed `result.results` (Jupyter/E2B-style). stdout/stderr/exit
   * are identical to a plain run; capture is best-effort. Internal cell/runner/results files are
   * removed and hidden from `result.files`. */
  async _runPythonCell(code, { timeoutS, onStdout = UNSET, onStderr = UNSET } = {}) {
    const eff = this._effTimeout(timeoutS);
    // Prewarmed fast path, taken ONLY where it is observationally identical to the cold one below.
    // The streaming callback is the gate that is easy to get wrong: a prewarmed box answers with one
    // length-prefixed frame after the cell has finished, so there is no chunk to hand a callback as it
    // arrives. Calling it once at the end would look like streaming without being it, so a streaming
    // call takes the cold path and streams for real.
    const streaming =
      (onStdout === UNSET ? this.onStdout : onStdout) !== null ||
      (onStderr === UNSET ? this.onStderr : onStderr) !== null;
    // BEFORE the claim, not after: the claim compares the posture the next box would have, so a cache
    // adopted here is already in the key and the boxes warmed without it are retired as stale.
    this._pycAdoptIfReady();
    if (this._pool && !streaming && !code.includes("\0")) {
      const warm = await this._pool.claim({ network: this.network, deadlineS: eff });
      if (warm) {
        const before = this.trackFiles ? await this._snapshot() : null;
        return warm.runCell(code, { deadlineS: eff, before });
      }
    }
    const uid = crypto.randomBytes(4).toString("hex");
    const cell = `.cell-${uid}.py`;
    const resf = `.res-${uid}.json`;
    const runf = `.run-${uid}.py`;
    await this.writeFile(cell, code);
    const shim = PY_RUNNER.replace("__KERN_CELL__", `${WORKSPACE}/${cell}`).replace(
      "__KERN_RES__",
      `${WORKSPACE}/${resf}`,
    );
    await this.writeFile(runf, shim);
    // `-u`: UNBUFFERED. CPython block-buffers stdout when it is a pipe, which it always is here, so a cell
    // that prints and is then SIGKILLed (OOM, timeout) or ends with `os._exit` lost whatever sat in that
    // buffer. The Python binding has passed it since 0.2.43 and this one did not: MEASURED, cold,
    // `print('BEFORE')` then a timeout returned "" here and "BEFORE" there. Mirrors the Python call.
    const result = await this._spawn(["python3", "-u", `${WORKSPACE}/${runf}`], {
      network: this.network,
      timeoutS: eff,
      onStdout,
      onStderr,
    });
    try {
      const parsed = JSON.parse(await this.readFile(resf, { maxBytes: RESULTS_MAX }));
      if (Array.isArray(parsed))
        result.results = parsed.filter((r) => r && typeof r === "object").map((r) => new Result(r));
    } catch {
      /* missing / too-large / unreadable / bad JSON: leave results empty, run otherwise intact */
    }
    const internal = new Set([cell, resf, runf]);
    for (const name of internal) {
      try {
        fs.unlinkSync(path.join(this._ws, name));
      } catch {
        /* ignore */
      }
    }
    result.files = result.files.filter((fi) => !internal.has(fi.path));
    return result;
  }

  /** Run an arbitrary `command` (an argv ARRAY, never a shell string) in a fresh box. `timeoutS`,
   * `onStdout` and `onStderr` override the session defaults for this call only (see `runCode`). */
  async run(command, { timeoutS, onStdout = UNSET, onStderr = UNSET } = {}) {
    this._requireEntered();
    if (typeof command === "string")
      throw new SandboxError('run() takes an argv ARRAY, not a string. Use run(["sh","-c","..."]).');
    if (!Array.isArray(command) || command.length === 0)
      throw new SandboxError("run() needs a non-empty command array");
    return this._spawn(command, {
      network: this.network,
      timeoutS: this._effTimeout(timeoutS),
      onStdout,
      onStderr,
    });
  }

  /** Open a persistent, WARM Python interpreter in a long-lived box (warm-start): cells run in ONE
   * resident process, so in-memory state PERSISTS across cells and the per-cell cost drops from a full
   * interpreter boot (~10 ms) to sub-millisecond. Returns an OPEN Kernel; call `await k.close()` when
   * done (or wrap in try/finally). Trade vs runCode: cells share one process and one box, so it is
   * call-fast but NOT call-isolated (still network-off and resource-capped; a fresh session/kernel is
   * clean). A per-cell timeout tears the kernel down. */
  async kernel({ timeoutS } = {}) {
    this._requireEntered();
    const k = new Kernel(this, this._effTimeout(timeoutS));
    await k._open();
    return k;
  }
}

const KERNEL_BACKSTOP_S = 24 * 3600; // long-lived box; close()/timeout owns the real lifetime
const KERNEL_TIMEOUT = Symbol("kernel-timeout");
// The box is UNTRUSTED and controls the reply length prefix + body; without a cap it could stream a
// multi-GB frame and OOM the HOST (its own memory cap bounds what it BUILDS, not what the host ACCEPTS).
// A frame past the cap resolves the waiter with this sentinel, which tears the kernel down. Mirrors the
// one-shot path's RESULTS_MAX guard.
const KERNEL_OVERSIZE = Symbol("kernel-oversize");

// The raw-fd drain cap a PERSISTENT kernel has always used. Named rather than repeated so the one place
// that must not drift from the shipped behaviour says which number it is and why.
const KERNEL_DRAIN_CAP = 64 * 1024 * 1024;

/** What a box the BINDING kills reports as its exit status: SIGKILL, in the shell's 128 + signal
 * convention the one-shot path already speaks. A resident kernel used to report -1 for a timeout, on the
 * stated ground that its interpreter survives the deadline; MEASURED, the timeout tears the box down.
 * Mirrors `_KILLED_BY_BINDING_RC`. */
const KILLED_BY_BINDING_RC = 128 + 9;

/** The largest frame the host accepts from a driver: both streams, the results, and room for JSON.
 * Mirrors `_reply_frame_cap`. */
function replyFrameCap(outCap) {
  return 2 * Math.trunc(outCap) + RESULTS_MAX + 65536;
}

/** The output a driver streamed for ONE cell, kept up to `cap` characters per stream. The frames are
 * written inside the box, so past the cap nothing more is stored and the cut is recorded. Mirrors
 * `_CellOutput`. */
class CellOutput {
  constructor(cap) {
    this._cap = Math.max(0, Math.trunc(cap));
    this._parts = { o: [], e: [] };
    this._n = { o: 0, e: 0 };
    this.truncated = false;
  }

  add(obj) {
    for (const key of ["o", "e"]) {
      if (!(key in obj)) continue;
      let text = typeof obj[key] === "string" ? obj[key] : String(obj[key]);
      const room = this._cap - this._n[key];
      if (text.length > room) {
        text = text.slice(0, Math.max(room, 0));
        this.truncated = true;
      }
      if (text) {
        this._parts[key].push(text);
        this._n[key] += text.length;
      }
    }
  }

  get stdout() {
    return this._parts.o.join("");
  }

  get stderr() {
    return this._parts.e.join("");
  }
}

/** How the (Python) driver writes an output frame: `json.dumps({"o": ...})`. Matched on the prefix so
 * the reply that ends a cell, which can carry a large figure, is parsed once. Mirrors
 * `_STREAM_FRAME_PREFIXES`. */
const STREAM_FRAME_PREFIXES = ['{"o": ', '{"e": '];

/** Hand a parsed frame to whoever waits for one, or queue it. A frame used to be DROPPED when nobody was
 * waiting, which never happened while a cell sent exactly one; a streaming cell sends many, several to
 * one read. Shared by `Kernel` and `WarmBox`, which parse frames the same way. */
function deliverFrame(self, body) {
  const w = self._waiters.shift();
  if (w) {
    clearTimeout(w.timer);
    w.resolve(body);
  } else {
    (self._frames ??= []).push(body);
  }
}

/** The next frame, or how the channel ended (`null` / `KERNEL_OVERSIZE`) once every queued frame was
 * read, or `KERNEL_TIMEOUT`. Output queued before a death comes out before the death does. */
function nextFrame(self, ms) {
  if (self._frames && self._frames.length) return Promise.resolve(self._frames.shift());
  if (self._end !== undefined || self._dead) return Promise.resolve(self._end === undefined ? null : self._end);
  return new Promise((resolve) => {
    const w = { resolve, timer: null };
    w.timer = setTimeout(() => {
      const i = self._waiters.indexOf(w);
      if (i >= 0) self._waiters.splice(i, 1);
      resolve(KERNEL_TIMEOUT);
    }, Math.max(0, ms));
    if (w.timer.unref) w.timer.unref();
    self._waiters.push(w);
  });
}

/** Wait for the frame that ENDS a cell, folding every output frame before it into `out`. Mirrors
 * `_next_reply`: what arrived before a death or a timeout stays in `out`, which is the point. */
async function nextReply(self, deadlineAtMs, out) {
  for (;;) {
    const left = deadlineAtMs - Date.now();
    if (left <= 0) return KERNEL_TIMEOUT;
    const frame = await nextFrame(self, left);
    if (typeof frame !== "string") return frame;
    if (STREAM_FRAME_PREFIXES.some((p) => frame.startsWith(p))) {
      let obj;
      try {
        obj = JSON.parse(frame);
      } catch {
        return frame;
      }
      if (obj && typeof obj === "object" && !Array.isArray(obj) && Object.keys(obj).length === 1) {
        out.add(obj);
        continue;
      }
    }
    return frame;
  }
}

/** Materialize PY_KERNEL_DRIVER for one caller's output budget and handshake.
 *
 * The driver text is byte-identical to the Python binding's, so it carries the same three placeholders
 * and they have to be filled in here too. Substitution and not a runtime read, because the driver runs
 * INSIDE the box where an environment variable is workload-writable: a cap the box can set is not a cap.
 * The values are stringified ints and a literal 0/1 from our own call sites, never from box input.
 *
 * @param {number} outCap  bytes of stdout/stderr kept per stream before the reply says it truncated
 * @param {number} resCap  byte budget for rich results; 0 or less means unbounded (the Kernel contract)
 * @param {boolean} hello  emit a readiness frame before the cell loop
 * @returns {string} */
function kernelDriver(outCap, resCap, hello = false) {
  return PY_KERNEL_DRIVER.replaceAll("__KERN_OUTCAP__", String(Math.trunc(outCap)))
    .replaceAll("__KERN_RESCAP__", String(Math.trunc(resCap)))
    .replaceAll("__KERN_HELLO__", hello ? "1" : "0");
}

/** The message for a host-side open the workspace boundary refused.
 *
 * ELOOP here is not a filesystem oddity, it is the boundary working: the final component is opened
 * O_NOFOLLOW, so a symlink the BOX planted at a path the host is about to touch fails instead of
 * redirecting. Raw, it reads `ELOOP: too many symbolic links encountered`, which sends a reader looking
 * for a broken link chain when what happened is an attempt to reach a host file. */
function pathRefusal(verb, rel, e) {
  const cause = { cause: e };
  if (e && e.code === "ELOOP")
    return new SandboxError(
      `refusing to ${verb} ${JSON.stringify(rel)}: a component of that path is a SYMLINK. Host-side ` +
        "reads and writes never follow one (O_NOFOLLOW), because a link planted inside the workspace is " +
        "how a box reaches a host file it was not given (the kernel reports this as ELOOP). Remove it, " +
        "or name the file you meant",
      cause,
    );
  if (e && e.code === "ENXIO")
    return new SandboxError(
      `refusing to ${verb} ${JSON.stringify(rel)}: it is a FIFO with no reader. Opening one for writing ` +
        "would block until the box chose to read, so the open is non-blocking and fails instead",
      cause,
    );
  return new SandboxError(`cannot ${verb} ${JSON.stringify(rel)}: ${e && e.message ? e.message : e}`, cause);
}

/** The refusal of a read past `maxBytes`, ONE spelling for the host and the helper path. `size` is the
 * file's own when it is known (the host read it from `fstat`), null when only "more than" is. */
function maxBytesRefusal(rel, maxBytes, size) {
  return new SandboxError(
    `${JSON.stringify(rel)} is ${size === null ? "larger" : `${size} bytes, larger`} than ` +
      `maxBytes=${maxBytes}, so the read was REFUSED. maxBytes is a ceiling on what may be read at all, ` +
      "not a request for the first bytes: nothing was returned. Raise it, or drop it and slice the result.",
  );
}
/** A warm, persistent Python interpreter living in one long-lived box (see `Sandbox.kernel`). `runCode`
 * sends a cell over a length-prefixed pipe to the resident driver and resolves to an ExecutionResult with
 * captured stdout/stderr, exit code and rich `results`. In-memory state persists across cells; the box
 * stays network-off and resource-capped. `close()` (or a per-cell timeout) tears the box down. */
class Kernel {
  constructor(sbx, timeoutS) {
    this._sbx = sbx;
    this._timeout = timeoutS;
    this._child = null;
    this._name = "";
    this._childEnv = null;
    this._driver = "";
    // Frame reader state: accumulate chunks, concat ONCE per frame (not per chunk) so a large reply is
    // O(n), not O(n^2). `_need`/`_headerBytes` cache the parsed header so the body phase only counts bytes.
    this._chunks = []; // Buffer[]
    this._total = 0; // bytes buffered across _chunks
    this._need = -1; // body length once the header is parsed, else -1
    this._headerBytes = -1; // header line length incl newline, once parsed
    this._cap = 0; // max accepted frame bytes (set from sbx.maxOutputBytes in _open)
    this._waiters = []; // FIFO of { resolve, timer }; one reply per request keeps them in order
    this._stderr = Buffer.alloc(0);
    this._dead = false;
    // WHY THE CAUSE IS KEPT. Every death funnels through `_teardownResult`, which KNOWS what ended the
    // kernel, and the next cell then threw "a prior cell timed out, or the box exited" - two guesses
    // where the answer was in hand (MEASURED: a cell that blew the memory cap produced
    // `fault.type === "oom"`, and the very next cell blamed a timeout). If it is known, name it.
    this._death = null;
    // kern's KERN_STARTED_FD bytes for a RESIDENT box: the enforcement byte (2nd) and the OOM-outcome
    // byte (3rd). kern writes them only at box teardown (a cell kills the kernel), so they arrive
    // ~concurrent with the death we detect on stdout; read once, bounded, on death (`_readCapSignal`).
    // Kept as the raw buffer because the bytes arrive in ONE atomic write and a stream is free to deliver
    // it in pieces. Absent bytes read as 0 = undetermined / old kern.
    this._startedSig = Buffer.alloc(0);
  }

  async _open() {
    const sbx = this._sbx;
    // The caller's output budget, the one the prewarmed box gets, and no results budget: the frame cap
    // bounds a reply. The budget used to be a fixed 64 MiB while the host refused any reply over
    // `maxOutputBytes`, so a cell printing more than that KILLED the kernel and its state. Output is
    // streamed now and cut on both sides. No readiness frame, which a persistent Kernel does not read.
    this._outCap = sbx.maxOutputBytes;
    this._cap = replyFrameCap(sbx.maxOutputBytes);
    const uid = crypto.randomBytes(4).toString("hex");
    this._driver = `.kernel-${uid}.py`;
    await sbx.writeFile(this._driver, kernelDriver(sbx.maxOutputBytes, 0, false));
    this._name = uniqueName();
    this._childEnv = { ...process.env };
    if (!sbx.enforceLimits) this._childEnv.KERN_NO_SCOPE = "1";
    this._childEnv.KERN_STARTED_FD = "3"; // same unforgeable channel; here for the enforcement byte only
    const argv = [
      ...sbx._baseArgv(this._name, { network: sbx.network, timeoutS: KERNEL_BACKSTOP_S }),
      "--", "python3", `${WORKSPACE}/${this._driver}`,
    ];
    // detached: own process group so we can killpg the box + kern as a unit, like _spawn. fd 3 carries
    // the started/enforcement bytes; the workload never holds it.
    this._child = spawn(argv[0], argv.slice(1), {
      env: this._childEnv, detached: true, stdio: ["pipe", "pipe", "pipe", "pipe"],
    });
    const startedCh = this._child.stdio[3];
    if (startedCh) {
      startedCh.on("data", (b) => { this._startedSig = Buffer.concat([this._startedSig, b]); });
      startedCh.on("error", () => {});
    }
    this._child.on("error", () => { this._dead = true; this._flush(null); });
    this._child.on("close", () => { this._dead = true; this._flush(null); });
    this._child.stdout.on("data", (d) => this._onData(d));
    this._child.stderr.on("data", (d) => {
      this._stderr = Buffer.concat([this._stderr, d]);
      if (this._stderr.length > sbx.maxOutputBytes)
        this._stderr = this._stderr.subarray(0, sbx.maxOutputBytes); // bound host RAM on a flooding box
    });
    return this;
  }

  _onData(d) {
    this._chunks.push(d);
    this._total += d.length;
    // Hard cap on buffered bytes (header slack + body): an untrusted box streaming without a valid frame
    // can't grow host RAM past the cap. Tear down rather than accept an unbounded reply.
    if (this._total > this._cap + 64) return this._flush(KERNEL_OVERSIZE);
    this._tryParse();
  }

  _coalesce() {
    // Materialize the buffered chunks into one Buffer (and keep it as the single chunk). Called only when
    // we must search/slice; the body phase avoids it until the whole frame is present, keeping it O(n).
    if (this._chunks.length > 1) this._chunks = [Buffer.concat(this._chunks, this._total)];
    return this._chunks.length ? this._chunks[0] : Buffer.alloc(0);
  }

  _tryParse() {
    for (;;) {
      if (this._need < 0) {
        const buf = this._coalesce();
        const nl = buf.indexOf(0x0a);
        if (nl < 0) {
          if (buf.length > 64) return this._flush(KERNEL_OVERSIZE); // header line with no newline
          return;
        }
        const n = parseInt(buf.subarray(0, nl).toString("ascii").trim(), 10);
        if (!Number.isInteger(n) || n < 0) return this._flush(null); // malformed framing
        if (n > this._cap) return this._flush(KERNEL_OVERSIZE);
        this._headerBytes = nl + 1;
        this._need = n;
      }
      if (this._total < this._headerBytes + this._need) return; // body incomplete: buffer, no concat
      const buf = this._coalesce();
      const body = buf.subarray(this._headerBytes, this._headerBytes + this._need).toString("utf8");
      const rest = buf.subarray(this._headerBytes + this._need);
      this._chunks = rest.length ? [rest] : [];
      this._total = rest.length;
      this._need = -1;
      this._headerBytes = -1;
      deliverFrame(this, body);
    }
  }

  _flush(val) {
    // A protocol error (oversize/malformed) marks the kernel dead: the stream is desynced, do not keep it.
    if (val === KERNEL_OVERSIZE || val === null) this._dead = true;
    if (this._end === undefined) this._end = val;
    while (this._waiters.length) {
      const w = this._waiters.shift();
      clearTimeout(w.timer);
      w.resolve(val);
    }
  }

  async runCode(code, { timeoutS } = {}) {
    if (!this._child) throw new SandboxError("kernel not started");
    if (this._dead) {
      const why = this._death ? `a prior cell ended it (${this._death})` : "it was closed";
      throw new SandboxError(
        `kernel is dead: ${why}. Files written to the workspace are still there; names and imports ` +
        "from the earlier cells are gone. Open a new one with `sbx.kernel()`"
      );
    }
    if (typeof code !== "string" || code.includes("\0"))
      throw new SandboxError("code must be a string with no NUL byte");
    const eff = timeoutS != null ? this._sbx._effTimeout(timeoutS) : this._timeout;
    const started = Date.now();
    const payload = Buffer.from(code, "utf8");
    const out = new CellOutput(this._outCap);
    try {
      this._child.stdin.write(`${payload.length}\n`);
      this._child.stdin.write(payload);
    } catch {
      return this._deathResult(started, out);
    }
    const reply = await nextReply(this, started + eff * 1000, out);
    if (reply === KERNEL_TIMEOUT)
      return this._teardownResult("timeout", `cell exceeded ${eff}s`, started, KILLED_BY_BINDING_RC, out);
    if (reply === KERNEL_OVERSIZE)
      return this._teardownResult(
        "killed", `the kernel sent a frame larger than the ${this._cap}-byte cap`, started, KILLED_BY_BINDING_RC, out,
      );
    if (reply === null) return this._deathResult(started, out);
    return this._resultFromReply(reply, started, out);
  }

  /** The box went away mid-cell: classify why from what kern wrote, keeping what the cell printed.
   * Mirrors `_death_result`. */
  async _deathResult(started, out) {
    const err = this._stderr.toString("utf8");
    const [capSignal, oomSignal, wrote, workloadSignal] = await this._readCapSignal();
    const [kind, dflt, rc] = this._kernelDeathFault(
      err, capSignal, oomSignal, wrote, workloadSignal, this._exitStatus(),
    );
    if (kind === null && workloadSignal === 0)
      // The cell ended the interpreter itself (`os._exit(N)`): its exit code, its own output, and no
      // sentence from us in its stderr.
      return this._teardownResult(null, "", started, rc, out, `the cell ended the interpreter with exit status ${rc}`);
    return this._teardownResult(kind, err.trim() || dflt, started, rc, out);
  }

  /** The box process's own exit code once it has gone, or null while it is still there. */
  _exitStatus() {
    const c = this._child;
    return c && typeof c.exitCode === "number" && c.exitCode >= 0 ? c.exitCode : null;
  }

  /** True once this kernel's interpreter is gone, whatever ended it: a fault, a cell that exited the
   * interpreter, or `close()`. Its in-memory state went with it. Mirrors `Kernel.ended`. */
  get ended() {
    return this._dead;
  }

  /** Turn one kernel reply into an `ExecutionResult`.
   *
   * Extracted so the UNTRUSTED-INPUT boundary is one named place a test can drive directly: `reply`
   * is JSON written INSIDE the box, by the same code the sandbox exists to contain. Every field is
   * attacker-chosen, and the question for each is what a missing or wrong-typed value must mean. */
  _resultFromReply(reply, started, out = null) {
    let obj;
    try {
      obj = JSON.parse(reply);
    } catch {
      return this._teardownResult("killed", "the kernel sent a malformed reply", started, KILLED_BY_BINDING_RC, out);
    }
    if (!obj || typeof obj !== "object")
      return this._teardownResult("killed", "the kernel sent a non-object reply", started, KILLED_BY_BINDING_RC, out);
    // `rc` is the ONE field whose absence cannot be defaulted. `success` is
    // `exitCode === 0 && fault === null`, so coercing a missing or non-integer `rc` to 0 - which is
    // what this did - reported a SUCCESSFUL run. Since the JSON comes from the box, a cell could
    // declare its own failed run successful by omitting the field or sending a string. An unusable
    // status is not a status: it is a protocol violation by the in-box runner, which always emits
    // `"rc"`, and it is handled like the malformed replies above. `Number.isInteger` also rejects a
    // boolean, a float and a numeric string, which is what it is here for.
    if (!Number.isInteger(obj.rc))
      return this._teardownResult("killed", "the kernel reply carried no usable exit code", started, KILLED_BY_BINDING_RC, out);
    // The REMAINING fields are informational, so a wrong type degrades to an empty value rather than
    // failing the call: coerced so a caller doing `r.stdout.trim()` cannot be crashed by a box that
    // sent a number.
    const results = Array.isArray(obj.results)
      ? obj.results.filter((r) => r && typeof r === "object").map((r) => new Result(r))
      : [];
    return new ExecutionResult({
      stdout: (out ? out.stdout : "") + (typeof obj.stdout === "string" ? obj.stdout : ""),
      stderr: (out ? out.stderr : "") + (typeof obj.stderr === "string" ? obj.stderr : ""),
      exitCode: obj.rc,
      durationMs: Date.now() - started,
      fault: null,
      files: [],
      // The driver's own cut and the host's: a cell over its budget is told so, as on the cold path.
      truncated: obj.trunc === true || !!(out && out.truncated),
      results,
    });
  }

  /** Why the resident kernel box died mid-cell, as `[type, defaultMessage]`. The runCode counterpart of
   * the one-shot _classify SIGKILL branch: a kernel death has no per-cell exit code, so the whole verdict
   * is made here from what kern wrote.
   *
   * ORDER, and it was measured wrong before: kern's OOM sentence is asked about FIRST, because it is
   * `kern:`-prefixed and so was also matching the box-did-not-start heuristic below. A real OOM on a
   * resident kernel therefore came back `startup_failed`, which `_teardownResult` THROWS - so the
   * flagship path could not produce an `oom` fault at all, while an external `kern stop` DID produce one
   * from the memoryMb inference. Two defects pointing opposite ways.
   *
   * `capSignal` is kern's unforgeable enforcement byte (0 = old kern / undetermined, 1 = cap enforced, 2 =
   * requested but NOT enforced). It no longer decides the TYPE, and a 2 still earns a sentence, because
   * "your cap was not in force here" is the one thing the caller cannot find out for itself. */
  _kernelDeathFault(err, capSignal = 0, oomSignal = null, kernWrotePayload = false, workloadSignal = null, exitStatus = null) {
    // THE EXIT CODE COMES FROM THE FOURTH BYTE, so both paths report one event the same way: this used to
    // be a flat -1 while the one-shot path said 137 for a kill, 159 for a blocked escape, 139 for a
    // segfault. -1 stays for the cases where no signal is known. Mirrors `_kernel_death_fault`.
    const rc = workloadSignal !== null && workloadSignal !== undefined && workloadSignal !== 0
      ? 128 + workloadSignal
      : -1;
    if (oomVerdict(oomSignal, err, kernWrotePayload)) return ["oom", "the kernel box exceeded its memory cap and was OOM-killed", rc];
    // A BLOCKED ESCAPE, BEFORE ANY STDERR HEURISTIC, and this path could not say it at all. MEASURED
    // through the MCP server, which is the path a Cursor or Claude Desktop user actually runs: a cell
    // calling a blocked syscall came back `killed` with the message "an external kill". kern's seccomp
    // filter had killed the box and the caller was told somebody stopped it. The one-shot path answers
    // this from the exit code (159); a resident kernel has no per-cell exit code, so it needs the fourth
    // byte, which was arriving unused. Before `looksLikeStartupFailure` because that heuristic matches
    // text the workload can print, and a cell must not be able to hide a blocked escape behind it. The
    // signal must have killed the box's PID 1, and a pidns init does not receive an unhandled fatal
    // signal from inside, so a cell cannot forge it. Mirrors `_kernel_death_fault`.
    if (workloadSignal === SIG_SYS)
      return [
        "escape_blocked",
        "the kernel box was killed by SIGSYS: kern's seccomp filter refused a syscall the code attempted, which is a blocked escape and not a kill from outside",
        rc,
      ];
    // A CRASH IS NOT A SANDBOX FAULT, and this path called it `killed` with that same false sentence
    // about an external kill. MEASURED: a segfaulting cell IS the box's PID 1, so the box dies, and the
    // one-shot path reports the identical event as `fault=null, exitCode=139`. Two paths disagreeing about
    // one event costs a loop: an agent reading `killed` retries the sandbox instead of fixing its code.
    // The lost session state is already reported, by the next call throwing "kernel is dead".
    if (CRASH_SIGNALS.has(workloadSignal))
      return [
        null,
        `the code crashed: the cell died on signal ${workloadSignal} (${SIGNAL_NAMES[workloadSignal]}), which took the kernel box with it because the interpreter is its PID 1. The sandbox did not act; the next call reopens a kernel`,
        rc,
      ];
    // AND THE BYTE DECIDES WHETHER THE TEXT IS BELIEVED. kern writes the teardown payload only for a box
    // that existed, so `kernWrotePayload` is positive proof that this kernel STARTED and a
    // `startup_failed` here could only be a cell printing kern's prefix at column 0 and dying of
    // something else. The one-shot path gets this from `_runOne`, which drops the verdict when the start
    // byte is set; this path had no such guard, so the widened predicate gets it here.
    if (!kernWrotePayload && looksLikeStartupFailure(err))
      return ["startup_failed", "the kernel box failed to start", rc];
    // NO SIGNAL AND A REAL EXIT STATUS: the cell ended the interpreter itself, `os._exit(N)` being the
    // ordinary way. The one-shot path reports that as exitCode N and no fault; this one said `killed`.
    // Mirrors the Python branch, which is placed after the cap branch there and reaches the same answer.
    if (workloadSignal === 0 && exitStatus !== null) return [null, "", exitStatus];
    if (capSignal === 2)
      return [
        "killed",
        "the kernel box was killed, and its memory cap was not enforced here (no cgroup delegation), so no memory limit was in force to attribute it to",
        rc,
      ];
    if (this._sbx.memoryMb !== null) {
      // A BINARY THAT DOES NOT REPORT THE SIGNAL CANNOT HAVE THIS SENTENCE PUT IN ITS MOUTH. MEASURED on
      // the released 0.9.32, which is what `install.sh` serves today: it writes two of the four teardown
      // bytes, so `workloadSignal` is null, and a cell that SEGFAULTED and a cell whose syscall the
      // seccomp filter refused both landed here and were told "an external kill", which is false for
      // both. The verdict cannot improve without the byte; the sentence can say so.
      if (kernWrotePayload && workloadSignal === null)
        return [
          "killed",
          "the kernel box was killed and the kernel reported no OOM against its memory cap. THIS kern " +
            "does not report which signal ended the box (it writes 2 of the 4 teardown bytes), so an " +
            "external kill, a crash in your own code and a syscall the sandbox refused are " +
            "indistinguishable from here: a newer kern separates them, and until then read the box's " +
            "stderr before concluding it was killed from outside",
          rc,
        ];
      return [
        "killed",
        "the kernel box was killed and the kernel reported no OOM against its memory cap: an external kill (`kern stop`, a signal, or the host running out of memory), not the box exceeding its own memory",
        rc,
      ];
    }
    return ["killed", "the kernel box exited", rc];
  }

  /** kern's enforcement and OOM-outcome bytes for the resident box, read ONCE on kernel death, as
   * `[capSignal, oomSignal]`. kern writes the KERN_STARTED_FD signal only at box teardown (a resident box
   * exits when a cell kills it), ~concurrent with the death detected on stdout. The fd-3 `data` handler in
   * `_open` accumulates the bytes as they arrive; this awaits a BOUNDED window (the fd's own `end`, or
   * 1 s) so the read is deterministic rather than a race. `[0, 0]` on EOF / an old kern / not yet, which
   * falls back to kern's stderr sentence. */
  async _readCapSignal() {
    const ch = this._child && this._child.stdio && this._child.stdio[3];
    if (!ch) return [0, null, false, null];
    if (this._startedSig.length < 3 && !ch.destroyed) {
      await new Promise((res) => {
        const t = setTimeout(res, 1000);
        ch.once("end", () => { clearTimeout(t); res(); });
        ch.once("error", () => { clearTimeout(t); res(); });
      });
    }
    const { boxStarted, capSignal, oomSignal, workloadSignal } = parseStartedBytes(this._startedSig);
    return [capSignal, oomSignal, boxStarted, workloadSignal];
  }

  _teardownResult(type, message, started, exitCode = -1, out = null, death = null) {
    this._death = death || (type === null ? "the code crashed" : type);
    this._kill();
    const so = out ? out.stdout : "";
    const se = out ? out.stderr : "";
    const cut = !!(out && out.truncated);
    // Same rule as the one-shot path: a box that never STARTED (the kernel failed to boot) throws, it
    // does not return a hollow result. timeout/killed stay as data on the returned result.
    if (type === "startup_failed") throw new SandboxError(message || "the box failed to start");
    // `type === null` is a real answer, not a missing one: the code CRASHED and the sandbox did not act,
    // which is what the one-shot path reports for the same event. The message still travels on stderr.
    if (type === null) {
      const sep = se && message && !se.endsWith("\n") ? "\n" : "";
      return new ExecutionResult({
        stdout: so,
        stderr: se + sep + message,
        exitCode,
        durationMs: Date.now() - started,
        fault: null,
        files: [],
        truncated: cut,
        results: [],
      });
    }
    // WHAT THE CELL PRINTED BEFORE IT DIED: it used to be "" on every fault, because the output travelled
    // in the reply a killed cell never sends.
    return new ExecutionResult({
      stdout: so,
      stderr: se,
      exitCode,
      durationMs: Date.now() - started,
      fault: sandboxFault(type, message),
      files: [],
      truncated: cut,
      results: [],
    });
  }

  _kill() {
    this._dead = true;
    this._flush(null);
    const child = this._child;
    if (!child) return;
    try {
      spawnSync(this._sbx._kern, ["stop", this._name], { env: this._childEnv, timeout: 5000, stdio: "ignore" });
    } catch {
      /* ignore */
    }
    try {
      if (child.pid) process.kill(-child.pid, "SIGKILL"); // whole process group (detached)
    } catch {
      /* ignore */
    }
    try {
      child.kill("SIGKILL");
    } catch {
      /* ignore */
    }
  }

  async close() {
    const child = this._child;
    if (child && !this._dead) {
      // Graceful: closing stdin makes the driver's _read() return None, so the box exits cleanly.
      try {
        child.stdin.end();
      } catch {
        /* ignore */
      }
      // Wait for the exit EVENT, capped at 150 ms, rather than sleeping 150 ms unconditionally: that
      // fixed sleep cost 152 ms on every close of a persistent kernel (measured) for a box that
      // exits in a few. A child that is already gone has emitted `exit` and will not emit it again,
      // so that case is tested directly instead of waited on.
      if (child.exitCode === null && child.signalCode === null) {
        await new Promise((resolve) => {
          let t = null;
          const onExit = () => {
            if (t !== null) clearTimeout(t);
            resolve();
          };
          t = setTimeout(() => {
            child.removeListener("exit", onExit);
            resolve();
          }, 150);
          child.once("exit", onExit);
        });
      }
      this._kill();
    } else {
      this._kill();
    }
    try {
      fs.unlinkSync(path.join(this._sbx._ws, this._driver));
    } catch {
      /* ignore */
    }
  }
}

// -- prewarm: the fresh-box guarantee at zero marginal cost ------------------------------------------

// How long a prewarmed box may sit unclaimed before it is stale. It bounds the ORPHAN window: every warm
// box carries kern's own --timeout set to this plus the session deadline it was started for, so a host
// process that dies without running close() leaves boxes that expire by themselves rather than living to
// a 24 h backstop. The pool refills continuously, so this is the failure bound, not the working lifetime.
const PREWARM_TTL_S = 300;
// How long a prewarmed box gets to reach its prompt before the pool gives up on it. Generous on purpose:
// it covers a first-run image pull and an aarch64 board. Nothing waits on it, so a large value is free.
const PREWARM_READY_MS = 120_000;

// Every live prewarmed box in this process, so an exit that skips close() still tears the boxes down.
// Best-effort by nature - a SIGKILL runs nothing - which is exactly why the TTL above is the mechanism.
const LIVE_WARM = new Set();
let warmExitHooked = false;

function hookWarmExit() {
  if (warmExitHooked) return;
  warmExitHooked = true;
  process.on("exit", () => {
    for (const b of [...LIVE_WARM]) {
      try {
        b.stopProcesses();
      } catch {
        /* an exit handler must never throw */
      }
    }
  });
}

/** One box that is already started and already holds a booted CPython which has run NO user code.
 *
 * A cold runCode pays two costs on the CALLER's clock: starting the box and booting the interpreter
 * inside it. Neither depends on the cell, so neither has to happen while the caller waits. This starts
 * them in advance and then serves EXACTLY ONE cell before the box is destroyed.
 *
 * The guarantee runCode documents is therefore unchanged. A cell still gets a private box that has
 * executed nothing else, and a virgin interpreter whose only prior action was importing this driver -
 * which is what a cold cell gets once its own boot finishes.
 *
 * One observable DOES differ, stated because "identical" was too broad a word for it: the interpreter
 * is older than the call. A cell that reads its own start time out of /proc/self/stat sees ~0 s cold
 * and up to PREWARM_TTL_S warm (measured: 0.0 s against 3.1 s). Nothing the SDK reports changes and no
 * boundary moves, but code that times itself from process start can tell. */
class WarmBox {
  constructor(sbx, key, budgetS, sweeper) {
    this._sbx = sbx;
    this.key = key;
    this._budgetS = budgetS;
    this._sweeper = sweeper || null;
    this._child = null;
    this._name = "";
    this._born = Date.now();
    this._spent = false;
    this._rc = null;
    this._startedSig = Buffer.alloc(0); // KERN_STARTED_FD bytes: [started, cap enforcement, OOM outcome]
    this._stderr = Buffer.alloc(0);
    this._chunks = [];
    this._total = 0;
    this._need = -1;
    this._headerBytes = -1;
    this._cap = 0;
    this._waiters = [];
    this._dead = false;
  }

  async start() {
    const sbx = this._sbx;
    // The frame cap has to admit a reply the driver considers legal, or a cell that legitimately
    // truncates at maxOutputBytes would come back as an oversize FAULT instead. Two capped streams plus
    // the results budget plus JSON overhead is the largest well-formed reply, so that is the cap.
    this._cap = 2 * sbx.maxOutputBytes + RESULTS_MAX + 65536;
    this._name = uniqueName();
    // The driver goes in ARGV, not into a workspace file. A pooled box is started BEFORE the cell that
    // will use it, so a driver FILE would sit in the box-writable workspace across the whole inter-call
    // gap and any cell could rewrite it to hijack the next prewarmed box. In argv the source is fixed at
    // exec time and never exists as a path the sandbox can reach.
    const driver = kernelDriver(sbx.maxOutputBytes, RESULTS_MAX, true);
    const argv = [
      ...sbx._baseArgv(this._name, {
        network: sbx.network,
        timeoutS: PREWARM_TTL_S + this._budgetS,
      }),
      "--", "python3", "-c", driver,
    ];
    const childEnv = { ...process.env };
    if (!sbx.enforceLimits) childEnv.KERN_NO_SCOPE = "1";
    childEnv.KERN_STARTED_FD = "3";
    try {
      this._child = spawn(argv[0], argv.slice(1), {
        env: childEnv, detached: true, stdio: ["pipe", "pipe", "pipe", "pipe"],
      });
    } catch {
      return false;
    }
    const startedCh = this._child.stdio[3];
    if (startedCh) {
      startedCh.on("data", (b) => { this._startedSig = Buffer.concat([this._startedSig, b]); });
      startedCh.on("error", () => {});
    }
    this._child.on("error", () => { this._dead = true; this._flush(null); });
    this._child.on("close", (code, signal) => {
      this._dead = true;
      // `toRc` is THE mapping this binding's cold path uses (128 + signum, not Python's negative
      // convention). Each binding has to match its OWN cold path: reporting -9 here made a Node timeout
      // come back as -9 warm and 137 cold, which is the same failure wearing two different faces.
      if (this._rc === null) this._rc = toRc(code, signal);
      this._flush(null);
    });
    this._child.stdout.on("data", (d) => this._onData(d));
    this._child.stderr.on("data", (d) => {
      this._stderr = Buffer.concat([this._stderr, d]);
      if (this._stderr.length > sbx.maxOutputBytes)
        this._stderr = this._stderr.subarray(0, sbx.maxOutputBytes);
    });
    hookWarmExit();
    LIVE_WARM.add(this);
    return true;
  }

  /** Block until the driver says it is at the prompt. This is what makes the box PREWARMED rather than
   * merely SPAWNED: `spawn` resolves at the fork, not when kern has built the box and CPython has
   * booted, so a pool that published on spawn alone hands out boxes that are still starting and the
   * caller pays the rest of the start itself. */
  async waitReady(ms = PREWARM_READY_MS) {
    const body = await this._await(ms);
    if (typeof body !== "string") return false;
    try {
      const o = JSON.parse(body);
      return !!o && o.hello === 1;
    } catch {
      return false;
    }
  }

  /** Whether this box may serve a call. Every term is a correctness gate, not an optimization:
   * `key` is the EXACT argv the call would otherwise produce, which is what stops a box prewarmed with
   * one posture from serving a call that asked for another; `deadlineS` must fit inside the backstop
   * this box was started with, or kern could kill a legal cell mid-run; and past the TTL the same race
   * opens anyway. */
  usableFor(key, deadlineS) {
    return (
      !this._spent && !this._dead && this._child !== null && this.key === key &&
      deadlineS <= this._budgetS && Date.now() - this._born < PREWARM_TTL_S * 1000
    );
  }

  // -- framing (same shape as Kernel's, which is the reader this protocol was written for) -----------

  _onData(d) {
    this._chunks.push(d);
    this._total += d.length;
    if (this._total > this._cap + 64) return this._flush(KERNEL_OVERSIZE);
    this._tryParse();
  }

  _coalesce() {
    if (this._chunks.length > 1) this._chunks = [Buffer.concat(this._chunks, this._total)];
    return this._chunks.length ? this._chunks[0] : Buffer.alloc(0);
  }

  _tryParse() {
    for (;;) {
      if (this._need < 0) {
        const buf = this._coalesce();
        const nl = buf.indexOf(0x0a);
        if (nl < 0) {
          if (buf.length > 64) return this._flush(KERNEL_OVERSIZE);
          return;
        }
        const n = parseInt(buf.subarray(0, nl).toString("ascii").trim(), 10);
        if (!Number.isInteger(n) || n < 0) return this._flush(null);
        if (n > this._cap) return this._flush(KERNEL_OVERSIZE);
        this._headerBytes = nl + 1;
        this._need = n;
      }
      if (this._total < this._headerBytes + this._need) return;
      const buf = this._coalesce();
      const body = buf.subarray(this._headerBytes, this._headerBytes + this._need).toString("utf8");
      const rest = buf.subarray(this._headerBytes + this._need);
      this._chunks = rest.length ? [rest] : [];
      this._total = rest.length;
      this._need = -1;
      this._headerBytes = -1;
      deliverFrame(this, body);
    }
  }

  _flush(val) {
    if (val === KERNEL_OVERSIZE || val === null) this._dead = true;
    if (this._end === undefined) this._end = val;
    while (this._waiters.length) {
      const w = this._waiters.shift();
      clearTimeout(w.timer);
      w.resolve(val);
    }
  }

  _await(ms) {
    return nextFrame(this, ms);
  }

  // -- the one cell ----------------------------------------------------------------------------------

  /** Run `code` in this box, then destroy it. Callable once; a second call throws rather than quietly
   * reusing a box that has already executed user code. */
  async runCell(code, { deadlineS, before }) {
    if (this._spent) throw new SandboxError("a prewarmed box serves exactly one cell");
    this._spent = true;
    if (this._child === null) throw new SandboxError("prewarmed box was never started");
    const started = Date.now();
    const payload = Buffer.from(code, "utf8");
    const out = new CellOutput(this._sbx.maxOutputBytes);
    let body;
    try {
      this._child.stdin.write(`${payload.length}\n`);
      this._child.stdin.write(payload);
      body = await nextReply(this, started + deadlineS * 1000, out);
    } catch {
      return this._faultResult("died", started, before, undefined, out);
    }
    if (body === KERNEL_TIMEOUT)
      return this._faultResult("timeout", started, before, `code exceeded ${deadlineS}s`, out);
    // Every branch below that rejects the reply produces the same shape, so it is written once. The
    // repetition was three copies of the same call differing only in a string, which is the form where
    // one copy quietly drifts from the others.
    const rejected = (message, truncated = false) =>
      this._result(out.stdout, out.stderr, this._exitCode(), started, before, {
        truncated: truncated || out.truncated,
        fault: { type: "killed", message },
      });
    if (body === KERNEL_OVERSIZE) {
      this.retire();
      return rejected(
        `the box sent a reply larger than the ${this._sbx.maxOutputBytes}-byte output cap ` +
          "allows even after truncation",
        true,
      );
    }
    if (body === null) return this._faultResult("died", started, before, undefined, out);
    this.retire();
    let obj = null;
    try {
      obj = JSON.parse(body);
    } catch {
      /* handled below */
    }
    if (!obj || typeof obj !== "object" || Array.isArray(obj))
      return rejected("the box sent a malformed reply");
    // `rc` is the one field whose absence cannot be defaulted: defaulting it to 0 would let a cell
    // declare its own failed run successful. Same rule as Kernel's reply parser.
    if (typeof obj.rc !== "number" || !Number.isInteger(obj.rc))
      return rejected("the box reply carried no usable exit code");
    const results = Array.isArray(obj.results)
      ? obj.results.filter((r) => r && typeof r === "object").map((r) => new Result(r))
      : [];
    return this._result(out.stdout + String(obj.stdout ?? ""), out.stderr + String(obj.stderr ?? ""), obj.rc, started, before, {
      truncated: !!obj.trunc || out.truncated,
      results,
    });
  }

  _faultResult(kind, started, before, msg, out = new CellOutput(0)) {
    const err = this._stderr.toString("utf8");
    if (kind === "timeout") {
      this.retire();
      return this._result(out.stdout, out.stderr, this._exitCode(), started, before, {
        truncated: out.truncated,
        fault: { type: "timeout", message: msg || "the code exceeded its deadline" },
      });
    }
    const { boxStarted, capSignal, oomSignal, workloadSignal } = parseStartedBytes(this._startedSig);
    this.retire();
    let type = "killed";
    let dflt = "the box exited before the code finished";
    // Same order, and for the same measured reason, as `_kernelDeathFault`: kern's OOM sentence carries
    // the `kern:` prefix that `looksLikeStartupFailure` matches on, so asking about the start SECOND is
    // what keeps a pool box's OOM from being thrown as a box that never came up.
    if (oomVerdict(oomSignal, err, boxStarted)) {
      type = "oom";
      dflt = "the box exceeded its memory cap and was OOM-killed";
    } else if (!boxStarted && looksLikeStartupFailure(err)) {
      // `!boxStarted` for the reason `_kernelDeathFault` states: kern writes the teardown payload only
      // for a box that existed, so with the byte set this THROW would be a cell's own column-0 line
      // deciding that the box never came up.
      throw new SandboxError(err.trim() || "the box failed to start");
    } else if (boxStarted && workloadSignal === 0) {
      // NO SIGNAL: the cell ended the interpreter itself (`os._exit(N)`). The cold path reports that as
      // exitCode N and no fault; this path said `killed`. Mirrors the Python warm path.
      return this._result(out.stdout, out.stderr, this._exitCode(), started, before, { truncated: out.truncated });
    } else if (capSignal === 2) {
      dflt =
        "the box was killed, and its memory cap was not enforced here (no cgroup delegation), " +
        "so no memory limit was in force to attribute it to";
    } else if (this._sbx.memoryMb !== null && this._sbx.memoryMb !== undefined) {
      dflt =
        "the box was killed and the kernel reported no OOM against its memory cap: an external kill " +
        "(`kern stop`, a signal, or the host running out of memory), not the box exceeding its own memory";
    }
    return this._result(out.stdout, out.stderr, this._exitCode(), started, before, {
      truncated: out.truncated,
      fault: { type, message: err.trim() || dflt },
    });
  }

  /** The exit status a FAULT reports. The cold path hands back the box process's real wait status - a
   * SIGKILLed box is -9 - so a constant here would make one failure look like two different ones
   * depending on which path served it. */
  _exitCode() {
    return typeof this._rc === "number" ? this._rc : -1;
  }

  /** Assemble the result with the SAME shape the cold path returns, including the workspace diff.
   * `files` is computed here rather than left empty because a fast path that silently stopped reporting
   * created files would be a behaviour change disguised as a speed-up. */
  async _result(stdout, stderr, exitCode, started, before, { truncated = false, fault = null, results = [] } = {}) {
    const durationMs = Date.now() - started; // the cell's time, not the diff's
    return new ExecutionResult({
      stdout,
      stderr,
      exitCode,
      durationMs,
      fault,
      files: before ? await this._sbx._diff(before) : [],
      truncated,
      results,
    });
  }

  // -- teardown, split so the slow half never lands on a caller's clock ------------------------------

  /** End the box's workload NOW. Fast, idempotent, never throws.
   *
   * SIGKILLing the supervisor's process group ends everything inside the box: kern arms
   * PR_SET_PDEATHSIG(SIGKILL) on a foreground box, so the supervisor's death takes box PID 1, and PID 1
   * leaving its PID namespace takes every other process in it. Measured on the Python side with a cell
   * that leaves a background writer: it stops at the exact byte it had reached. That is what lets the
   * caller diff the workspace the moment this returns. */
  stopProcesses() {
    LIVE_WARM.delete(this);
    this._spent = true;
    const child = this._child;
    if (child === null) return;
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      /* already gone */
    }
    if (this._rc === null) this._rc = toRc(null, "SIGKILL");
  }

  /** The bookkeeping after the workload is dead: the pipes and the private env file.
   *
   * It deliberately does NOT run `kern stop`, because it is unnecessary: stopProcesses ends every
   * process in the box (measured against a CPU-bound background writer: it stops at the byte it had
   * reached, while the same cell with no kill runs on), and kern's registry entry clears by itself
   * within ~300 ms.
   *
   * A second reason was written here and was WRONG, kept because this binding is where it came from:
   * that `kern stop` does not return once the supervisor is dead. It does, in 2 to 5 ms. The
   * multi-second stalls were OURS - `spawnSync` blocks the single event loop that Node needs in order
   * to REAP the child just SIGKILLed, so the pid was still present from `kern stop`'s point of view and
   * it waited for it, correctly. Alternating sync and async calls shows it: 5, 6009, 4, 5 ms. */
  sweep() {
    const child = this._child;
    this._child = null;
    if (child) {
      for (const s of [child.stdin, child.stdout, child.stderr]) {
        try {
          s?.destroy();
        } catch {
          /* ignore */
        }
      }
    }
    // The private --env-file _baseArgv wrote for THIS box. _spawn removes its own; a prewarmed box has
    // no _spawn, so without this every warm box leaves one behind in a workspace the caller may persist.
    if (this._name) {
      if (this._sbx._envDir) {
        try {
          fs.unlinkSync(this._sbx._envPath(this._name));
        } catch {
          /* ENOENT is fine */
        }
      }
      this._name = "";
    }
  }

  /** Destroy the box completely and synchronously. Used from the pool's close and the start-failure
   * paths, where there is no worker to hand the sweep to. */
  kill() {
    this.stopProcesses();
    this.sweep();
  }

  /** End the workload on the caller's clock and hand the sweep to the pool. This is the hot path: it is
   * what turns a teardown measured in tens of milliseconds into a sub-millisecond one without
   * dropping any of it. */
  retire() {
    this.stopProcesses();
    if (this._sweeper) {
      try {
        this._sweeper(this);
        return;
      } catch {
        /* the pool refused it: fall through and do it here rather than not at all */
      }
    }
    this.sweep();
  }
}

/** Keeps up to `size` WarmBox instances ready for one Sandbox.
 *
 * A claim that finds nothing usable returns null and the caller takes the ordinary cold path: the pool
 * is an accelerator with no authority to change what runs. */
class WarmPool {
  constructor(sbx, size) {
    this._sbx = sbx;
    this._size = Math.max(0, Math.trunc(size) || 0);
    this._ready = [];
    this._starting = 0;
    this._closed = false;
    this._pending = new Set(); // in-flight sweeps, so close() can wait for them
  }

  /** The identity a warm box must match. Built from the REAL argv builder in `dry` mode, so an option
   * this session grows later is folded in automatically instead of needing to be listed here.
   *
   * The argv is not the whole posture, and that was a real hole: kern reads `KERN_*` variables from ITS
   * OWN environment when it builds the box, so a caller who sets `KERN_SECCOMP=denylist` after the pool
   * filled would have been served a box built under the previous filter. Every `KERN_*` variable is
   * folded in, rather than the handful we can name today, because the failure mode is a variable nobody
   * thought to list. */
  // ⭐ ONE SPELLING, SHARED WITH THE RESIDENT FINGERPRINT, and async for the same reason it is:
  // resolving a profile token means asking kern. ⛔ Computed at CLAIM time and not cached, because
  // the question is "does this warm box match what THIS call would create" and a cached answer would
  // say yes to a box built before a `kern.toml` edit. Measured in the Python binding: 1.33 ms per
  // claim WITH a profile, 0.039 ms without - the spawn is only paid when a profile is asked for.
  async _key(network) {
    return this._sbx._postureMaterial({ network, timeoutS: 0 });
  }

  async claim({ network, deadlineS }) {
    if (this._closed || this._size <= 0) return null;
    // THE POOL STEPS ASIDE WHEN THE POSTURE CANNOT BE KNOWN; it does not fail the call. `_key`
    // throws when a profile cannot be resolved or kern is too old to print a `vgpio:` grant. The
    // resident path is right to throw on that; the pool is an optimisation, and the call it would
    // have served can always start a fresh box from the live argv, which has the right posture by
    // construction. Same decision, same reason, as the Python binding.
    let key;
    try {
      key = await this._key(network);
    } catch (e) {
      if (e instanceof SandboxError) return null;
      throw e;
    }
    let picked = null;
    const keep = [];
    const stale = [];
    for (const b of this._ready) {
      if (picked === null && b.usableFor(key, deadlineS)) picked = b;
      else if (b.key !== key || Date.now() - b._born >= PREWARM_TTL_S * 1000 || b._dead) stale.push(b);
      else keep.push(b);
    }
    this._ready = keep;
    for (const b of stale) b.kill();
    this.refill({ network, deadlineS });
    return picked;
  }

  /** Top the pool up in the background. Bounded by `size` counting ready AND starting boxes, so a burst
   * of claims cannot spawn an unbounded number of boxes. */
  refill({ network, deadlineS }) {
    if (this._closed || this._size <= 0) return;
    const want = this._size - this._ready.length - this._starting;
    if (want <= 0) return;
    this._starting += want;
    for (let i = 0; i < want; i++) {
      const p = this._startOne(network, deadlineS).catch(() => {});
      this._pending.add(p);
      p.finally(() => this._pending.delete(p));
    }
  }

  /** Start one box and publish it, releasing the reserved slot on EVERY path.
   *
   * The slot release is in a `finally` and the box is built inside the `try`, which is not tidiness:
   * `_key()` calls the real argv builder and that CAN throw (an env value containing a newline is
   * refused there). Thrown before the decrement, the slot stayed reserved forever, `want` went
   * negative, and the pool never refilled again for the rest of the session, silently, with `refill`'s
   * own `.catch(() => {})` swallowing the reason. Same shape as the Python binding's dead-worker
   * case: a permanent stop with no signal. */
  async _startOne(network, deadlineS) {
    let box = null;
    let ok = false;
    try {
      box = new WarmBox(this._sbx, await this._key(network), deadlineS, (b) => this._sweep(b));
      ok = (await box.start()) && (await box.waitReady());
    } catch {
      ok = false;
    } finally {
      this._starting -= 1;
    }
    if (box === null) return; // never constructed: there is nothing to publish and nothing to kill
    if (ok && !this._closed) {
      this._ready.push(box);
      return;
    }
    // Three ways to land here and all of them must destroy the box: the start failed, the box came up
    // but never signalled readiness, or the session closed while it was still building.
    box.kill();
  }

  _sweep(box) {
    if (this._closed) {
      box.sweep();
      return;
    }
    // Off the caller's microtask turn: `kern stop` is a synchronous subprocess and must not be awaited
    // by whoever just got their result.
    setImmediate(() => {
      try {
        box.sweep();
      } catch {
        /* best-effort */
      }
    });
  }

  async close() {
    this._closed = true;
    const boxes = this._ready;
    this._ready = [];
    for (const b of boxes) b.kill();
    // Wait for boxes still starting, or close() would return while a `kern box` is being forked and the
    // session's workspace is about to be deleted underneath it.
    if (this._pending.size) await Promise.allSettled([...this._pending]);
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
  // Exported so a consumer that wants a DIFFERENT default can express it as a multiple of this
  // one rather than declaring a second independent number that drifts from it.
  DEFAULT_TMPFS_MB,
  Sandbox,
  Kernel,
  withSandbox,
  runCode,
  ExecutionResult,
  Result,
  SandboxError,
  MountRefused,
  // The prewarm pool, exported for its tests only, and under an underscore for the same reason the
  // bytecode cache's internals are below: a pool key is the same posture question the resident
  // fingerprint asks, the two were allowed to drift once, and the test that stops them doing it
  // again has to be able to ask the pool directly. The Python binding exposes it the same way.
  _WarmPool: WarmPool,
  // Where the binding finds kern, exported for its tests only: the order ($KERN_BIN, the package's
  // own copy, PATH) decides which binary runs every box, and only a test that can hand these a
  // package root can assert it without writing a `bin/` into this checkout.
  _bundledKern: bundledKern,
  _findKern: findKern,
  // The bytecode cache's internals, exported for its tests only: the mount flag and the atomic
  // publish are security properties, and a test that cannot reach them cannot assert them.
  _PYC_MOUNT: PYC_MOUNT,
  _PYC_SOURCE_ID: PYC_SOURCE_ID,
  _sanitizeRef: sanitizeRef,
  _imageIsCached: imageIsCached,
  _fetchImage: fetchImage,
  // The snapshot reader, exported for its tests only: what it accepts decides where a member of a
  // hostile or foreign archive lands, and the `prefix` field it used to ignore was a silent rename.
  _tarParseRaw: tarParseRaw,
  // The WRITER's pieces, for the same reason: the archive is a wire format between the two bindings,
  // so what this side emits is as much a contract as what it accepts.
  _tarWriteFile: tarWriteFile,
  _tarWriteDir: tarWriteDir,
  _tarFinish: tarFinish,
  _tarSplitName: tarSplitName,
  _tarOctalField: tarOctalField,
  _TAR_MAX_OCTAL: TAR_MAX_OCTAL,
  // The streaming protocol's pieces, for tests that drive the real driver without a box.
  _kernelDriver: kernelDriver,
  _WarmBox: WarmBox,
  _CellOutput: CellOutput,
  _nextReply: nextReply,
  _replyFrameCap: replyFrameCap,
  _kernExecReportsItsStart: kernExecReportsItsStart,
  _SANITIZE_VECTORS: SANITIZE_VECTORS,
  _pycSourceId: pycSourceId,
  // Exported for the test that proves a stale lock is swept: the marks decide what the sweep
  // collects, and a lock left out of them disables an image's cache forever.
  _PYC_DEBRIS_MARKS: PYC_DEBRIS_MARKS,
  // `user`'s pieces, for its tests only: the spec check, the ACL walk by descriptor (a security
  // property: an entry must never land outside the workspace), the helper scripts (asserted
  // byte-for-byte against the Python binding's) and the closed-directory accounting.
  _validateUser: validateUser,
  _isRootUser: isRootUser,
  _imageUser: imageUser,
  _parseHelperList: parseHelperList,
  _aclGrantBatches: aclGrantBatches,
  _aclGrantTreeAsync: aclGrantTreeAsync,
  _workspaceUsage: workspaceUsage,
  _HELPER_SCRIPTS: { HELPER_READ, HELPER_WRITE, HELPER_LIST, HELPER_DU, HELPER_ISDIR, HELPER_CLEAN, HELPER_TAR, HELPER_UNTAR },
  _pycDirFor: pycDirFor,
  _pycBuild: pycBuild,
  _pycSweep: pycSweep,
  _pycStartSweep: pycStartSweep,
  // TEST-ONLY. `PYC_SWEPT` is process state by design (one scan per process), which makes any test
  // of it order-dependent: an earlier test that adopts a cache consumes the single sweep. Python
  // reaches the same global with monkeypatch; Node needs a setter because a `let` cannot be
  // reassigned through the exports object.
  _pycResetSweptForTests: () => {
    PYC_SWEPT = false;
  },
  _ociCanonicalRef: ociCanonicalRef,
  _PYC_BUILD_CODE: PYC_BUILD_CODE,
  _pycStartBuild: pycStartBuild,
  /** Await every build still in flight. FOR TESTS, and it removes a real race rather than masking
   *  one: a test that removes its temp cache home while a background build is still writing into it
   *  fails in `rimraf` with ENOTEMPTY, which is a teardown ordering bug and reads like a product
   *  defect. Measured under the gate, where the machine is busy enough for the build to outlive the
   *  test. */
  _pycSettle: () => Promise.allSettled([...PYC_BUILDS.values()]),
  version: VERSION,
};
