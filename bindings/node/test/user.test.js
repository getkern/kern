"use strict";
// `user`: the account of the image every box runs as, and the workspace that has to stay shared with it.
// The same cases as the Python binding's tests/test_user.py. UNIT tests run everywhere (the ACL ones need
// `setfacl` and a filesystem with POSIX ACLs); INTEGRATION tests need a runnable kern AND a uid range for
// this user, and skip naming which one is missing.

const { test } = require("node:test");
const assert = require("node:assert");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const zlibGunzip = (b) => require("node:zlib").gunzipSync(b);

const { FAKE_KERN, kernBin } = require("./_fake_kern.js");

const kern = require("../index.js");
const { Sandbox, SandboxError } = kern;

function cfg(opts = {}) {
  const prev = process.env.KERN_BIN;
  process.env.KERN_BIN = FAKE_KERN;
  try {
    return new Sandbox(opts);
  } finally {
    if (prev === undefined) delete process.env.KERN_BIN;
    else process.env.KERN_BIN = prev;
  }
}

function tmpdir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `kern-user-${tag}-`));
}

function getfacl(p, def = false) {
  const r = spawnSync("getfacl", ["-n", "-p", "-c", ...(def ? ["-d"] : []), p], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.split("\n").filter(Boolean) : null;
}

function aclsHere() {
  const d = tmpdir("acl");
  try {
    return spawnSync("setfacl", ["-m", "u:4242:r", d]).status === 0;
  } finally {
    fs.rmSync(d, { recursive: true, force: true });
  }
}
const ACL = { skip: !aclsHere() && "no setfacl, or no POSIX ACLs on the temp filesystem" };

// -- UNIT ------------------------------------------------------------------------------------------

test("a user spec is an account name or number", () => {
  for (const spec of ["node", "1000", "1000:1000", "node:staff", "a.b-c_d", "_x", "x".repeat(32)]) {
    assert.strictEqual(kern._validateUser(spec), spec);
    assert.strictEqual(cfg({ user: spec }).user, spec);
  }
});

test("anything else is refused by name before it reaches an argv", () => {
  for (const spec of ["", "-u", "--user=root", "a b", "a:b:c", ":x", "x:", "a;b", "x".repeat(33), "n\node", 1000])
    assert.throws(() => cfg({ user: spec }), (e) => e instanceof SandboxError && /user must be/.test(e.message), String(spec));
});

test("root is root by number or name and with any group", () => {
  for (const spec of [null, "", "0", "root", "0:0", "root:wheel", "0:5"]) assert.ok(kern._isRootUser(spec), String(spec));
  for (const spec of ["1000", "node", "nobody:0", "10", "rooty"]) assert.ok(!kern._isRootUser(spec), spec);
});

test("the helper box and the uid probe clear the image's entrypoint", () => {
  // kern PREPENDS the image's ENTRYPOINT to what follows `--`, so without `--entrypoint ""` the
  // helper ran `ENTRYPOINT sh -c SCRIPT` and the IMAGE chose what came out - and a helper's output
  // is PARSED, not displayed (the file's bytes, stat records, a tar stream). An audit of this branch
  // found it; `_helperArgv`'s own comment had promised the opposite. Python's twin asserts the same.
  const s = cfg();
  s._asUser = "app";
  // A literal script, not an export: this asserts the FLAGS the builder puts around it, and
  // `_HELPER_READ` is not one of Node's test-only exports (passing `undefined` would still pass).
  const argv = s._helperArgv("read-script", ["f.txt"], false, 60);
  const i = argv.indexOf("--entrypoint");
  assert.ok(i !== -1, `no --entrypoint in ${JSON.stringify(argv)}`);
  assert.strictEqual(argv[i + 1], "", "an empty value is what clears it");
  assert.ok(i < argv.indexOf("--"), "before the `--`, or it is an argument of the workload");
  // AND THE FLAG IS REAL on this host, with this meaning: asked of the real binary when there is
  // one (`cfg` runs against a fake).
  const real = kernBin();
  if (!real) return;
  const said = require("node:child_process").execFileSync(real, ["box", "--help"], {
    encoding: "utf8",
    timeout: 60000,
  });
  assert.ok(said.includes('`--entrypoint ""` clears it'), "kern's own help must still say so");
});

test("an image whose USER is not a user is refused by name", () => {
  // `user` is validated in the constructor; the image's own USER reached the argv unexamined, so an
  // image declaring `USER --privileged` put that after `--user`. Not an argv injection (kern's
  // parser takes the next token whatever it is), but `USER_SPEC_RE` promises it cannot read as a
  // flag, and that has to hold for both halves.
  const d = tmpdir("xdg-user");
  const prev = process.env.XDG_CACHE_HOME;
  process.env.XDG_CACHE_HOME = d;
  try {
    const images = path.join(d, "kern", "images");
    fs.mkdirSync(images, { recursive: true });
    const side = path.join(images, `${kern._sanitizeRef("evil/img:1")}.image`);
    for (const bad of ["--privileged", " root", "x".repeat(300), "a:b:c"]) {
      fs.writeFileSync(side, `fmt\t3\nuser\t${bad}\n`);
      assert.strictEqual(kern._imageUser("evil/img:1"), bad, "the premise: the sidecar says so");
      const s = cfg({ image: "evil/img:1" });
      assert.rejects(s._resolveIdentity(), /declares USER/);
    }
    // THE CONTROL: a spec that IS a shape kern can be given gets past this check.
    fs.writeFileSync(side, "fmt\t3\nuser\tnode\n");
    assert.strictEqual(kern._imageUser("evil/img:1"), "node");
  } finally {
    if (prev === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = prev;
  }
});

test("the image user is read from the sidecar kern starts the box from", () => {
  const d = tmpdir("xdg");
  const prev = process.env.XDG_CACHE_HOME;
  process.env.XDG_CACHE_HOME = d;
  try {
    const images = path.join(d, "kern", "images");
    fs.mkdirSync(images, { recursive: true });
    const side = path.join(images, `${kern._sanitizeRef("example/app:1")}.image`);
    fs.writeFileSync(side, "fmt\t3\nentrypoint\t/bin/app\nuser\tapp:staff\nworkdir\t/srv\n");
    assert.strictEqual(kern._imageUser("example/app:1"), "app:staff");
    fs.writeFileSync(side, "fmt\t3\nuser\t\n");
    assert.strictEqual(kern._imageUser("example/app:1"), null);
    fs.writeFileSync(side, "fmt\t3\nworkdir\t/srv\n");
    assert.strictEqual(kern._imageUser("example/app:1"), null);
    assert.strictEqual(kern._imageUser("never/pulled:1"), null);
  } finally {
    if (prev === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = prev;
    fs.rmSync(d, { recursive: true, force: true });
  }
});

/** Whether `python3` can be started at all: its ABSENCE is a skip, any other failure is a failure. */
const PYTHON3 = !spawnSync("python3", ["-c", "pass"]).error;
const PY = { skip: !PYTHON3 && "no python3 here: the Python suite asserts its own half" };

test("the helper scripts are byte-for-byte the Python binding's", PY, () => {
  const py = spawnSync(
    "python3",
    ["-I", "-c", [
      "import json, sys",
      `sys.path.insert(0, ${JSON.stringify(path.join(__dirname, "..", "..", "python"))})`,
      "import kern_sandbox as k",
      "print(json.dumps({n: getattr(k, '_' + n) for n in " +
        "['HELPER_READ','HELPER_WRITE','HELPER_LIST','HELPER_DU','HELPER_ISDIR','HELPER_CLEAN','HELPER_TAR','HELPER_UNTAR']}))",
    ].join("\n")],
    { encoding: "utf8" },
  );
  assert.strictEqual(py.status, 0, py.stderr);
  assert.deepStrictEqual(kern._HELPER_SCRIPTS, JSON.parse(py.stdout));
});

test("the tree grant gives the owner's bits and a default, and never follows a symlink", ACL, async () => {
  const t = tmpdir("tree");
  try {
    const own = process.getuid();
    const box = 4242424;
    const root = path.join(t, "ws");
    const outside = path.join(t, "outside");
    fs.mkdirSync(path.join(root, "a"), { recursive: true });
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, "secret"), "host");
    fs.writeFileSync(path.join(root, "a", "f"), "f");
    fs.chmodSync(path.join(root, "a", "f"), 0o644);
    fs.writeFileSync(path.join(root, "a", "ro"), "r");
    fs.chmodSync(path.join(root, "a", "ro"), 0o444);
    fs.writeFileSync(path.join(root, "a", "x"), "#!/bin/sh\n");
    fs.chmodSync(path.join(root, "a", "x"), 0o755);
    fs.symlinkSync(outside, path.join(root, "a", "dirlink"));
    fs.symlinkSync(path.join(outside, "secret"), path.join(root, "filelink"));
    assert.deepStrictEqual(await kern._aclGrantTreeAsync(root, box, own), [0, ""]);
    assert.ok(getfacl(root).includes(`user:${box}:rwx`));
    assert.ok(getfacl(path.join(root, "a")).includes(`user:${box}:rwx`));
    assert.ok(getfacl(path.join(root, "a", "f")).includes(`user:${box}:rw-`), "the owner's bits: rw-");
    assert.ok(getfacl(path.join(root, "a", "ro")).includes(`user:${box}:r--`), "read-only to its owner, read-only to the box user");
    assert.ok(getfacl(path.join(root, "a", "x")).includes(`user:${box}:rwx`));
    const d = getfacl(path.join(root, "a"), true);
    for (const want of ["user::rwx", `user:${own}:rwx`, `user:${box}:rwx`, "group::---", "other::---"])
      assert.ok(d.includes(want), `${want} in ${d}`);
    for (const p of [outside, path.join(outside, "secret")])
      assert.ok(!getfacl(p).some((l) => l.startsWith("user:4")), `an entry landed on ${p}: ${getfacl(p)}`);
  } finally {
    fs.rmSync(t, { recursive: true, force: true });
  }
});

test("the grant applies to the inodes the walk saw, even if a directory becomes a symlink in between", ACL, () => {
  // DETERMINISTIC, the swap injected at the one point that matters: after the walk, before `setfacl`.
  // By descriptor the entries land on the files the walk opened (now under `d.real`); by path they
  // would land on the outside tree, every time. Mirrors the Python test.
  const box = 4242428;
  const t = tmpdir("swap");
  try {
    const root = path.join(t, "ws");
    const outside = path.join(t, "outside");
    fs.mkdirSync(path.join(root, "d"), { recursive: true });
    fs.mkdirSync(outside);
    for (let i = 0; i < 5; i++) {
      fs.writeFileSync(path.join(root, "d", `f${i}`), "x");
      fs.writeFileSync(path.join(outside, `f${i}`), "host");
    }
    const batches = [...kern._aclGrantBatches(root, box, process.getuid(), true, { foreign: 0, example: "" })];
    fs.renameSync(path.join(root, "d"), path.join(root, "d.real"));
    fs.symlinkSync(outside, path.join(root, "d"));
    for (const [spec, fds] of batches) {
      const names = fds.map((_, j) => `/proc/self/fd/${3 + j}`);
      const r = spawnSync("setfacl", ["-m", spec, "--", ...names], { stdio: ["ignore", "ignore", "pipe", ...fds] });
      for (const fd of fds) fs.closeSync(fd);
      assert.strictEqual(r.status, 0, String(r.stderr));
    }
    for (const p of [outside, ...fs.readdirSync(outside).map((n) => path.join(outside, n))])
      assert.ok(![...getfacl(p), ...(getfacl(p, true) || [])].some((l) => l.startsWith(`user:${box}:`)), `an entry landed on ${p}`);
    for (let i = 0; i < 5; i++)
      assert.ok(getfacl(path.join(root, "d.real", `f${i}`)).includes(`user:${box}:rw-`), `f${i} under d.real lost its entry`);
  } finally {
    fs.rmSync(t, { recursive: true, force: true });
  }
});

test("the tree grant never lands outside the tree while a box swaps a directory for a symlink", ACL, async (t) => {
  // THE RACE THE DESCRIPTOR WALK EXISTS FOR, against a concurrent swapper (a separate process: this one
  // is single-threaded). The positive control is the same swapper against `setfacl` BY PATH, which has to
  // lose at least once, or this test could not see the class. Mirrors the Python test.
  const box = 4242427;
  const dir = tmpdir("race");
  const arena = (name) => {
    const root = path.join(dir, name, "ws");
    const outside = path.join(dir, name, "outside");
    fs.mkdirSync(path.join(root, "d"), { recursive: true });
    fs.mkdirSync(outside);
    for (let i = 0; i < 20; i++) {
      fs.writeFileSync(path.join(root, "d", `f${i}`), "x");
      fs.writeFileSync(path.join(outside, `f${i}`), "host");
    }
    return [root, outside];
  };
  // THE OUTSIDE DIRECTORY ITSELF COUNTS, not only its files: a swapped `d` resolved by path takes the
  // directory entry (and its default ACL) to the outside tree first. Measured: a detector that read
  // only the files missed every leak of a path-based grant.
  const leaked = (outside) =>
    [outside, ...fs.readdirSync(outside).map((n) => path.join(outside, n))].filter((p) =>
      [...(getfacl(p) || []), ...(getfacl(p, true) || [])].some((l) => l.startsWith(`user:${box}:`)),
    );
  const byPath = async (root) => {
    const names = [];
    try {
      for (const n of fs.readdirSync(path.join(root, "d"))) names.push(path.join(root, "d", n));
    } catch {}
    if (names.length) spawnSync("setfacl", ["-m", `u:${box}:rw`, "--", ...names]);
  };
  const results = {};
  try {
    for (const [name, grant] of [["fd", (root) => kern._aclGrantTreeAsync(root, box, process.getuid())], ["path", byPath]]) {
      const [root, outside] = arena(name);
      // A TIGHT LOOP IN PYTHON when there is one: a shell spawns a process per `mv`/`ln`, and a swapper
      // that slow let a path-based grant through only 2 runs in 3 (measured), too weak a control.
      const loop =
        "import os\nos.chdir(" + JSON.stringify(root) + ")\nwhile True:\n" +
        "    try:\n        os.rename('d', 'd.real'); os.symlink(" + JSON.stringify(outside) + ", 'd'); os.unlink('d'); os.rename('d.real', 'd')\n" +
        "    except OSError:\n        pass\n";
      const swapper =
        spawnSync("python3", ["-c", "pass"]).status === 0
          ? require("node:child_process").spawn("python3", ["-I", "-c", loop], { stdio: "ignore" })
          : require("node:child_process").spawn(
              "sh",
              ["-c", `cd ${JSON.stringify(root)} && while :; do mv d d.real 2>/dev/null; ln -s ${JSON.stringify(outside)} d 2>/dev/null; rm -f d; mv d.real d 2>/dev/null; done`],
              { stdio: "ignore" },
            );
      const deadline = Date.now() + 2000;
      try {
        while (Date.now() < deadline && leaked(outside).length === 0) {
          try {
            await grant(root);
          } catch {}
        }
      } finally {
        swapper.kill("SIGKILL");
      }
      results[name] = leaked(outside);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  assert.deepStrictEqual(results.fd, [], "the descriptor walk put an entry outside the tree");
  if (results.path.length === 0) t.skip("the path-based control never lost the race here, so this host cannot see the class");
});

// -- the host-side walk, snapshot, restore and mkdir BY DESCRIPTOR ----------------------------------
//
// Each test swaps a workspace directory for a symlink to a HOST directory at the one moment that tells a
// descriptor implementation from a path one, by wrapping the `fs` call that moment sits next to. By
// descriptor the host directory is never reached; by path it is, every time: the same tests run against
// the path-based code these replaced fail (measured).

/** Swap `<ws>/dswap` for a symlink to `outside`, once, at the first matching `fs` call: AFTER it returns
 * for the names in `after`, BEFORE it runs for the names in `before`. Returns the undo. */
function swapOnce(ws, outside, { after = [], before = [] }) {
  let done = false;
  const swap = () => {
    if (done) return;
    done = true;
    fs.renameSync(path.join(ws, "dswap"), path.join(ws, "dswap.real"));
    fs.symlinkSync(outside, path.join(ws, "dswap"));
  };
  const names = (a) => typeof a === "string" && a.includes("dswap") && !a.includes("dswap.real");
  const saved = {};
  for (const fn of new Set([...after, ...before])) {
    saved[fn] = fs[fn];
    fs[fn] = function (...args) {
      if (before.includes(fn) && names(args[0])) swap();
      const r = saved[fn].apply(this, args);
      if (after.includes(fn) && names(args[0])) swap();
      return r;
    };
  }
  return () => Object.assign(fs, saved);
}

function arena(tag) {
  const t = fs.realpathSync(tmpdir(tag));
  const ws = path.join(t, "ws");
  const outside = path.join(t, "outside");
  fs.mkdirSync(path.join(ws, "dswap"), { recursive: true });
  fs.mkdirSync(outside);
  fs.writeFileSync(path.join(ws, "dswap", "mine.txt"), "mine");
  fs.writeFileSync(path.join(outside, "hostsecret"), "host");
  const s = cfg();
  s._ws = ws;
  s._entered = true;
  return { t, ws, outside, s };
}

test("the walk never lists a host directory a box swapped in for one it had", async () => {
  const { t, ws, outside, s } = arena("walk");
  const undo = swapOnce(ws, outside, { before: ["openSync", "readdirSync", "lstatSync"] });
  try {
    const names = (await s.listFiles()).map((f) => f.path);
    assert.ok(!names.some((n) => n.includes("hostsecret")), `a host file reached the listing: ${names}`);
  } finally {
    undo();
    fs.rmSync(t, { recursive: true, force: true });
  }
});

test("a snapshot never archives a host directory a box swapped in for one it had", () => {
  const { t, ws, outside, s } = arena("snap");
  const prev = process.env.KERN_SANDBOX_SNAPSHOT;
  process.env.KERN_SANDBOX_SNAPSHOT = "1";
  const dest = path.join(t, "snap.tgz");
  const undo = swapOnce(ws, outside, { after: ["lstatSync"] });
  try {
    s.snapshot(dest);
  } finally {
    undo();
    if (prev === undefined) delete process.env.KERN_SANDBOX_SNAPSHOT;
    else process.env.KERN_SANDBOX_SNAPSHOT = prev;
  }
  const raw = zlibGunzip(fs.readFileSync(dest)).toString("latin1");
  fs.rmSync(t, { recursive: true, force: true });
  assert.ok(!raw.includes("hostsecret"), "a host file was archived");
});

test("a restore never writes through a directory a box swapped for a symlink", () => {
  const { t, ws, outside, s } = arena("restore");
  const prev = process.env.KERN_SANDBOX_SNAPSHOT;
  process.env.KERN_SANDBOX_SNAPSHOT = "1";
  const src = path.join(t, "in.tgz");
  // An archive holding `dswap/planted`, made by this binding from a scratch tree.
  const scratch = path.join(t, "scratch");
  fs.mkdirSync(path.join(scratch, "dswap"), { recursive: true });
  fs.writeFileSync(path.join(scratch, "dswap", "planted"), "x");
  const maker = cfg();
  maker._ws = scratch;
  maker._entered = true;
  maker.snapshot(src);
  const undo = swapOnce(ws, outside, { before: ["openSync", "mkdirSync"] });
  let refused = null;
  try {
    s.restore(src);
  } catch (e) {
    refused = e;
  } finally {
    undo();
    if (prev === undefined) delete process.env.KERN_SANDBOX_SNAPSHOT;
    else process.env.KERN_SANDBOX_SNAPSHOT = prev;
  }
  const landed = fs.existsSync(path.join(outside, "planted"));
  fs.rmSync(t, { recursive: true, force: true });
  assert.ok(!landed, "the restore wrote into the host directory");
  assert.ok(refused instanceof SandboxError, `the swapped component was not refused: ${refused}`);
});

test("writeFile never makes a directory inside a host directory a box swapped in", async () => {
  const { t, ws, outside, s } = arena("mkdir");
  const undo = swapOnce(ws, outside, { after: ["lstatSync"], before: ["openSync", "mkdirSync"] });
  let refused = null;
  try {
    await s.writeFile("dswap/sub/x.txt", "x");
  } catch (e) {
    refused = e;
  } finally {
    undo();
  }
  const made = fs.existsSync(path.join(outside, "sub"));
  fs.rmSync(t, { recursive: true, force: true });
  assert.ok(!made, "a directory was made inside the host directory");
  assert.ok(refused instanceof SandboxError, `the swapped component was not refused: ${refused}`);
});

test("both bindings write the same ACLs on the same tree", { skip: ACL.skip || PY.skip }, async () => {
  const t = tmpdir("parity");
  try {
    const own = process.getuid();
    const trees = ["node", "python"].map((n) => {
      const r = path.join(t, n);
      fs.mkdirSync(path.join(r, "d", "e"), { recursive: true });
      fs.writeFileSync(path.join(r, "d", "f"), "f");
      fs.chmodSync(path.join(r, "d", "f"), 0o640);
      fs.writeFileSync(path.join(r, "x"), "x");
      fs.chmodSync(path.join(r, "x"), 0o750);
      spawnSync("setfacl", ["-m", "u:7000:r", path.join(r, "x")]);
      return r;
    });
    await kern._aclGrantTreeAsync(trees[0], 4242426, own);
    const r = spawnSync(
      "python3",
      ["-I", "-c", [
        "import sys",
        `sys.path.insert(0, ${JSON.stringify(path.join(__dirname, "..", "..", "python"))})`,
        "import kern_sandbox as k",
        `k._acl_grant_tree(${JSON.stringify(trees[1])}, 4242426, ${own})`,
      ].join("\n")],
      { encoding: "utf8" },
    );
    assert.strictEqual(r.status, 0, r.stderr);
    for (const rel of [".", "d", "d/e", "d/f", "x"])
      for (const def of [false, true])
        assert.deepStrictEqual(
          getfacl(path.join(trees[0], rel), def),
          getfacl(path.join(trees[1], rel), def),
          `${rel}${def ? " (default)" : ""}`,
        );
  } finally {
    fs.rmSync(t, { recursive: true, force: true });
  }
});

test("the helper list parses a name with a newline and skips junk", () => {
  const raw = Buffer.concat([
    Buffer.from("81a4 5 100\n./a\nb\0"),
    Buffer.from("41ed 4096 7\n./d\0garbage\0"),
    Buffer.from("81a4 x 1\n./bad\0"),
  ]);
  assert.deepStrictEqual(kern._parseHelperList(raw), [["a\nb", 0o100644, 5, 100], ["d", 0o40755, 4096, 7]]);
});

test("a directory closed to this process is reported whole and not counted", { skip: process.getuid() === 0 && "root reads it" }, () => {
  const t = tmpdir("usage");
  const closed = path.join(t, "closed");
  const half = path.join(t, "half");
  try {
    fs.mkdirSync(path.join(t, "open"));
    fs.writeFileSync(path.join(t, "open", "f"), Buffer.alloc(8192));
    fs.mkdirSync(closed);
    fs.writeFileSync(path.join(closed, "big"), Buffer.alloc(1 << 20));
    fs.chmodSync(closed, 0);
    fs.mkdirSync(half);
    for (let i = 0; i < 50; i++) fs.writeFileSync(path.join(half, `f${String(i).padStart(2, "0")}`), Buffer.alloc(65536));
    fs.chmodSync(half, 0o444); // listable, not searchable: every lstat refused
    const blind = [];
    const used = kern._workspaceUsage(t, blind);
    assert.deepStrictEqual(blind.sort(), [closed, half].sort());
    assert.ok(used < 1 << 20, `a closed directory's contents were counted from here: ${used}`);
    assert.strictEqual(kern._workspaceUsage(t), used, "without a list, the count is unchanged");
  } finally {
    for (const d of [closed, half])
      try {
        fs.chmodSync(d, 0o700);
      } catch {}
    fs.rmSync(t, { recursive: true, force: true });
  }
});

function argvRecorder() {
  const d = tmpdir("argv");
  const out = path.join(d, "argv");
  const p = path.join(d, "kern");
  fs.writeFileSync(p, `#!/bin/sh\ncase "$1" in --version) echo "kern v0.0.0-test-double"; exit 0;; esac\nprintf "%s\\n" "$@" > ${out}\nexit 0\n`);
  fs.chmodSync(p, 0o755);
  return { dir: d, bin: p, out };
}

test("a non-root session names the user on every box and on kern exec", async () => {
  const rec = argvRecorder();
  const prev = process.env.KERN_BIN;
  process.env.KERN_BIN = rec.bin;
  try {
    const s = new Sandbox({ user: "node" });
    s._ws = rec.dir;
    let argv = s._baseArgv("b", { network: false, timeoutS: 5, dry: true });
    assert.strictEqual(argv[argv.indexOf("--user") + 1], "node");
    assert.ok(argv.includes("--no-uid-range"), "before the identity is resolved nothing is known to be non-root");
    s._asUser = "node";
    argv = s._baseArgv("b", { network: false, timeoutS: 5, dry: true });
    assert.ok(!argv.includes("--no-uid-range"), "kern maps the range for a non-root user whatever this says");
    s._entered = true;
    s._resident = "kern-sbx-t";
    await s._spawn(["true"], { network: false, timeoutS: 5 });
    assert.deepStrictEqual(fs.readFileSync(rec.out, "utf8").split("\n").slice(0, 6), ["exec", "kern-sbx-t", "-w", "/workspace", "-u", "node"]);
    const r = new Sandbox();
    r._ws = rec.dir;
    argv = r._baseArgv("b", { network: false, timeoutS: 5, dry: true });
    assert.ok(!argv.includes("--user") && argv.includes("--no-uid-range"));
    r._entered = true;
    r._resident = "kern-sbx-t";
    await r._spawn(["true"], { network: false, timeoutS: 5 });
    assert.ok(!fs.readFileSync(rec.out, "utf8").split("\n").includes("-u"));
  } finally {
    if (prev === undefined) delete process.env.KERN_BIN;
    else process.env.KERN_BIN = prev;
    fs.rmSync(rec.dir, { recursive: true, force: true });
  }
});

test("persist as a non-root user is refused by a kern without exec -u", async () => {
  const rec = argvRecorder();
  const prev = process.env.KERN_BIN;
  process.env.KERN_BIN = rec.bin;
  try {
    const s = new Sandbox({ user: "node", persist: true, name: "n" });
    s._ws = rec.dir;
    await assert.rejects(s._resolveIdentity(), /needs a kern whose `kern exec` takes `-u <user>`/);
  } finally {
    if (prev === undefined) delete process.env.KERN_BIN;
    else process.env.KERN_BIN = prev;
    fs.rmSync(rec.dir, { recursive: true, force: true });
  }
});

// -- INTEGRATION -----------------------------------------------------------------------------------

/** Why a box cannot run as a non-root account here, or null. Asked on the first integration test, not
 * at import, so a unit-only run starts no box and pulls nothing. */
let noUserBoxMemo;
function whyNoUserBox() {
  if (noUserBoxMemo === undefined) noUserBoxMemo = probeUserBox();
  return noUserBoxMemo;
}

function probeUserBox() {
  const k = kernBin();
  if (!k) return "no runnable kern (set KERN_BIN)";
  // THESE TESTS ARE FOR THE KERN BUILT WITH THIS SDK: `exec -u`, and the kern fixes they assert. An
  // older one on PATH (the installed release) is named and skipped, not failed: against it the SDK
  // refuses `persist` by name, which is its contract with an older kern.
  const help = spawnSync(k, ["exec", "--help"], { encoding: "utf8" });
  if (!String(help.stdout).includes("-u <user>"))
    return `${k} predates \`kern exec -u\`: build this tree's kern and set KERN_BIN`;
  if (!aclsHere()) return "no setfacl, or no POSIX ACLs on the temp filesystem";
  const r = spawnSync(k, ["box", `probe-${crypto.randomBytes(4).toString("hex")}`, "--image", "python:3.12-alpine", "--user", "1000", "--", "true"], { encoding: "utf8", timeout: 300000 });
  return r.status === 0 ? null : `no box as uid 1000 here: ${String(r.stderr).trim().slice(-200)}`;
}
const integration = { timeout: 600000 };

test("an image that declares a user works without user and runs as it", integration, async (tc) => {
  if (whyNoUserBox()) return tc.skip(whyNoUserBox());
  const d = tmpdir("img");
  const tag = `kern-sdk-user-test:${crypto.randomBytes(4).toString("hex")}`;
  try {
    fs.writeFileSync(path.join(d, "Dockerfile"), "FROM python:3.12-alpine\nRUN adduser -D -u 1000 app\nUSER app\n");
    const built = spawnSync(kernBin(), ["build", "-q", "-t", tag, d], { encoding: "utf8" });
    assert.strictEqual(built.status, 0, built.stderr);
    let s = await new Sandbox({ image: tag, pycCache: false }).open();
    let r = await s.runCode("import os; print(os.getuid()); open('x.txt', 'w').write('1')");
    assert.ok(r.exitCode === 0 && r.stdout.trim() === "1000", JSON.stringify(r));
    assert.strictEqual(String(await s.readFile("x.txt")), "1");
    const ws = s._ws;
    await s.close();
    assert.ok(!fs.existsSync(ws));
    s = await new Sandbox({ image: tag, user: "root", pycCache: false }).open();
    r = await s.runCode("import os; print(os.getuid())");
    assert.strictEqual(r.stdout.trim(), "0", JSON.stringify(r));
    assert.ok(!/could not give the workload the group/.test(r.stderr), r.stderr);
    await s.close();
  } finally {
    spawnSync(kernBin(), ["image", "rm", tag]);
    fs.rmSync(d, { recursive: true, force: true });
  }
});

test("what the box user closes to the host is still read, listed, counted, snapshotted and removed", integration, async (tc) => {
  if (whyNoUserBox()) return tc.skip(whyNoUserBox());
  const prevSnap = process.env.KERN_SANDBOX_SNAPSHOT;
  process.env.KERN_SANDBOX_SNAPSHOT = "1";
  const t = tmpdir("closed");
  try {
    let s = await new Sandbox({ image: "python:3.12-alpine", user: "nobody", pycCache: false, workspaceMaxBytes: 64 << 20 }).open();
    let r = await s.runCode(
      "import os, tempfile\n" +
        "print(os.getuid(), os.getgid())\n" +
        "os.mkdir('priv', 0o700)\n" +
        "fd = os.open('priv/k', os.O_CREAT | os.O_WRONLY, 0o600); os.write(fd, b'secret' * 1000); os.close(fd)\n" +
        "os.mkdir('pub', 0o755); open('pub/a.txt', 'w').write('A')\n" +
        "fd, p = tempfile.mkstemp(dir='.'); os.write(fd, b'tmp'); os.close(fd); print(os.path.basename(p))\n",
    );
    assert.strictEqual(r.exitCode, 0, JSON.stringify(r));
    const [ids, made] = r.stdout.split("\n");
    assert.strictEqual(ids, "65534 65534");
    assert.throws(() => fs.readdirSync(path.join(s._ws, "priv")), /EACCES/, "the premise: the host really is refused");
    const files = new Set(r.files.map((f) => f.path));
    for (const want of ["priv/k", "pub/a.txt", made]) assert.ok(files.has(want), `${want} in ${[...files]}`);
    assert.strictEqual(String(await s.readFile("priv/k")), "secret".repeat(1000));
    assert.strictEqual(String(await s.readFile(made)), "tmp");
    await assert.rejects(s.readFile("priv/k", { maxBytes: 10 }), /larger than maxBytes/);
    await s.writeFile("pub/new.txt", "hello");
    r = await s.runCode("print(open('pub/new.txt').read()); open('pub/new.txt', 'a').write('!')");
    assert.ok(r.exitCode === 0 && r.stdout.trim() === "hello", JSON.stringify(r));
    await s.writeFile("host.txt", "H");
    r = await s.runCode("open('host.txt', 'a').write('+'); print(open('host.txt').read())");
    assert.strictEqual(r.stdout.trim(), "H+", JSON.stringify(r));
    assert.deepStrictEqual((await s.listFiles("priv")).map((f) => f.path), ["priv/k"]);
    r = await s.runCode("open('priv/big', 'wb').write(b'z' * (80 << 20))");
    assert.strictEqual(r.exitCode, 0, JSON.stringify(r));
    await assert.rejects(s.runCode("print(1)"), /workspaceMaxBytes/, "80 MiB behind a 0700 directory still counts");
    await s._wsHelper("rm -f /w/priv/big", [], { write: true });
    const snap = path.join(t, "snap.tgz");
    s.snapshot(snap);
    const ws = s._ws;
    await s.close();
    assert.ok(!fs.existsSync(ws), "a workspace with closed directories was left behind");
    s = await new Sandbox({ image: "python:3.12-alpine", user: "nobody", pycCache: false }).open();
    s.restore(snap);
    r = await s.runCode("print(open('priv/k').read()[:6]); open('priv/k', 'a').write('x')");
    assert.ok(r.exitCode === 0 && r.stdout.trim() === "secret", JSON.stringify(r));
    await s.close();
  } finally {
    if (prevSnap === undefined) delete process.env.KERN_SANDBOX_SNAPSHOT;
    else process.env.KERN_SANDBOX_SNAPSHOT = prevSnap;
    fs.rmSync(t, { recursive: true, force: true });
  }
});

test("every path runs as the user: prewarm, kernel, setup and persist", integration, async (tc) => {
  if (whyNoUserBox()) return tc.skip(whyNoUserBox());
  let s = await new Sandbox({ image: "python:3.12-alpine", user: "1000:1000", prewarm: 1, pycCache: false }).open();
  let r = await s.runCode("import os; print(os.getuid(), os.getgid())");
  assert.strictEqual(r.stdout.trim(), "1000 1000", JSON.stringify(r));
  const k = await s.kernel();
  r = await k.runCode("import os; print(os.getuid())");
  assert.strictEqual(r.stdout.trim(), "1000", JSON.stringify(r));
  await k.close();
  await s.close();
  s = await new Sandbox({ image: "python:3.12-alpine", user: "1000", setup: "pip install six", pycCache: false }).open();
  r = await s.runCode("import os, six; print(os.stat(six.__file__).st_uid)");
  assert.ok(r.exitCode === 0 && r.stdout.trim() === "1000", JSON.stringify(r));
  await s.close();
  const t = tmpdir("persist");
  const ws = path.join(t, "ws");
  const name = `user-${crypto.randomBytes(4).toString("hex")}`;
  const warnings = [];
  const onWarning = (w) => warnings.push(String(w.message));
  process.on("warning", onWarning);
  try {
    s = await new Sandbox({ image: "python:3.12-alpine", user: "nobody", name, persist: true, workspace: ws, pycCache: false }).open();
    r = await s.runCode("import os; print(os.getuid()); open('p.txt', 'w').write('p')");
    assert.strictEqual(r.stdout.trim(), "65534", JSON.stringify(r));
    assert.strictEqual(String(await s.readFile("p.txt")), "p");
    await s.destroy();
    await s.close();
    s = await new Sandbox({ image: "python:3.12-alpine", user: "1000", workspace: ws, pycCache: false }).open();
    await new Promise((res) => setImmediate(res));
    assert.strictEqual(String(await s.readFile("p.txt")), "p", "this process still reaches the first account's file");
    await s.close();
    assert.ok(warnings.some((w) => /different box account/.test(w) && /p\.txt/.test(w)), warnings.join(" | "));
  } finally {
    process.off("warning", onWarning);
    spawnSync(kernBin(), ["stop", `kern-sbx-${name}`]);
    spawnSync(kernBin(), ["box", `clean-${name}`, "--image", "python:3.12-alpine", "--user", "0", "-v", `${ws}:/w`, "--", "sh", "-c", "rm -rf /w/* /w/.[!.]*"]);
    fs.rmSync(t, { recursive: true, force: true });
  }
});

test("the helper refuses what the host refuses", integration, async (tc) => {
  if (whyNoUserBox()) return tc.skip(whyNoUserBox());
  const s = await new Sandbox({ image: "python:3.12-alpine", user: "nobody", pycCache: false }).open();
  try {
    const r = await s.runCode(
      "import os\nos.mkdir('priv', 0o700)\nos.symlink('/etc/passwd', 'priv/link')\n" +
        "os.mkfifo('priv/fifo')\nopen('priv/file', 'w').write('f')\n",
    );
    assert.strictEqual(r.exitCode, 0, JSON.stringify(r));
    await assert.rejects(s.readFile("priv/link"), /SYMLINK|symlink/);
    await assert.rejects(s.readFile("priv/fifo"), /not a regular file/);
    await assert.rejects(s.listFiles("priv/file"), /not a directory/);
    await assert.rejects(s.writeFile("priv/link", "x"), /SYMLINK|symlink/);
    await assert.rejects(s.writeFile("priv/fifo", "x"), /not a regular file/);
    assert.strictEqual(String(await s.readFile("priv/file")), "f", "the control: a regular file there is read");
  } finally {
    await s.close();
  }
});

test("a restore into a directory the box user closed goes through the helper, empty directories included", integration, async (tc) => {
  if (whyNoUserBox()) return tc.skip(whyNoUserBox());
  const prev = process.env.KERN_SANDBOX_SNAPSHOT;
  process.env.KERN_SANDBOX_SNAPSHOT = "1";
  const t = tmpdir("hrestore");
  const s = await new Sandbox({ image: "python:3.12-alpine", user: "nobody", pycCache: false }).open();
  try {
    // An archive with a file and an EMPTY directory under `pub`, which the box user then creates 0755.
    const scratch = path.join(t, "scratch");
    fs.mkdirSync(path.join(scratch, "pub", "emptydir"), { recursive: true });
    fs.writeFileSync(path.join(scratch, "pub", "new.txt"), "restored");
    const src = path.join(t, "in.tgz");
    const made = spawnSync("tar", ["--format=ustar", "-czf", src, "-C", scratch, "pub/emptydir", "pub/new.txt"]);
    assert.strictEqual(made.status, 0, String(made.stderr));
    const r = await s.runCode("import os\nos.mkdir('pub', 0o755)\n");
    assert.strictEqual(r.exitCode, 0, JSON.stringify(r));
    assert.throws(() => fs.writeFileSync(path.join(s._ws, "pub", "probe"), "x"), /EACCES/, "the premise: closed to the host");
    s.restore(src);
    const check = await s.runCode("import os\nprint(open('pub/new.txt').read(), os.path.isdir('pub/emptydir'))");
    assert.strictEqual(check.stdout.trim(), "restored True", JSON.stringify(check));
  } finally {
    await s.close();
    if (prev === undefined) delete process.env.KERN_SANDBOX_SNAPSHOT;
    else process.env.KERN_SANDBOX_SNAPSHOT = prev;
    fs.rmSync(t, { recursive: true, force: true });
  }
});

test("the bytecode cache is readable by a non-root user", integration, async (tc) => {
  if (whyNoUserBox()) return tc.skip(whyNoUserBox());
  const image = "python:3.12-alpine";
  const s0 = await new Sandbox({ image, user: "1000" }).open();
  await s0.close();
  await kern._pycSettle();
  const dest = kern._pycDirFor(image);
  if (!fs.existsSync(dest)) return tc.skip("no bytecode cache could be built here");
  fs.chmodSync(dest, 0o700); // the shape an older build left
  const s = await new Sandbox({ image, user: "1000" }).open();
  try {
    assert.strictEqual(s._pycDir, dest);
    assert.strictEqual(fs.statSync(dest).mode & 0o777, 0o755);
    const r = await s.runCode(
      "import os, json, importlib.util\np = os.environ['PYTHONPYCACHEPREFIX']\n" +
        "print(os.getuid(), os.access(p, os.R_OK | os.X_OK), os.path.exists(importlib.util.cache_from_source(json.__file__)))",
    );
    assert.deepStrictEqual(r.stdout.trim().split(/\s+/), ["1000", "True", "True"], JSON.stringify(r));
  } finally {
    await s.close();
  }
});

// ---------------------------------------------------------------------------
// THE WALK, THE SNAPSHOT READER AND THE HELPER SPAWN
// ---------------------------------------------------------------------------

test("a wide workspace is listed whole, holding one descriptor per depth level", async () => {
  // The walk may hold one descriptor per DEPTH level, never one per entry. Its first
  // descriptor-based version opened every subdirectory while listing the parent and held them all,
  // so the count grew with the tree's WIDTH: a box that makes many directories had the diff after
  // its own call open that many at once, `stack.push(...subdirs)` spread them as call arguments
  // (past V8's limit, a RangeError that leaked every one of them), and on a host with a lower limit
  // the opens failed and those subtrees were absent from `files` and `listFiles` with nothing said.
  //
  // Measured here as the descriptor count this process holds DURING the walk, since Node raises its
  // own soft limit to the hard one and a width that would exhaust it is not something to build in a
  // test: the open count is the property, and it must not grow with the width.
  const s = cfg();
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-node-wide-"));
  s._ws = ws;
  const width = 500;
  for (let i = 0; i < width; i++) {
    fs.mkdirSync(path.join(ws, `d${i}`));
    fs.writeFileSync(path.join(ws, `d${i}`, "f.txt"), String(i));
  }
  // A deep branch too, so the per-depth descriptors are exercised rather than just the width.
  const deep = path.join(ws, "deep", ...Array.from({ length: 12 }, (_, i) => `l${i}`));
  fs.mkdirSync(deep, { recursive: true });
  fs.writeFileSync(path.join(deep, "bottom.txt"), "bottom");

  const openCount = () => fs.readdirSync("/proc/self/fd").length;
  const before = openCount();
  let peak = before;
  const realOpen = fs.openSync;
  fs.openSync = (...a) => {
    const fd = realOpen(...a);
    const now = openCount();
    if (now > peak) peak = now;
    return fd;
  };
  let got;
  try {
    got = await s._walk(ws);
  } finally {
    fs.openSync = realOpen;
  }

  const missing = [];
  for (let i = 0; i < width; i++) if (!(`d${i}/f.txt` in got)) missing.push(`d${i}/f.txt`);
  assert.deepStrictEqual(missing, [], `${missing.length} of ${width} subtrees were dropped`);
  assert.ok(
    `deep/${Array.from({ length: 12 }, (_, i) => `l${i}`).join("/")}/bottom.txt` in got,
    "the deep branch was dropped",
  );
  // The ceiling: ancestors plus a handful of slack, nowhere near the width.
  assert.ok(
    peak - before < 40,
    `the walk held ${peak - before} descriptors at once over a ${width}-wide tree, which grows with width`,
  );
  fs.rmSync(ws, { recursive: true, force: true });
});

test("the walk throws on a resource error instead of reporting a smaller workspace", async () => {
  // A descriptor it could not get is not a subtree that is not there. `files` and `listFiles` are
  // what a caller reads to find out what the code wrote, and an answer that is short because the
  // host ran out of descriptors, with nothing said, is the one failure shape this must not have.
  const s = cfg();
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-node-emfile-"));
  s._ws = ws;
  fs.mkdirSync(path.join(ws, "sub"));
  fs.writeFileSync(path.join(ws, "sub", "f.txt"), "x");
  fs.writeFileSync(path.join(ws, "top.txt"), "kept");

  const realOpen = fs.openSync;
  const failOn = (code) => (p, ...rest) => {
    if (typeof p === "string" && p.endsWith("/sub")) {
      const e = new Error(`${code}: injected`);
      e.code = code;
      throw e;
    }
    return realOpen(p, ...rest);
  };

  fs.openSync = failOn("EMFILE");
  try {
    await assert.rejects(() => s._walk(ws), /EMFILE/);
  } finally {
    fs.openSync = realOpen;
  }

  // The control, same shape: a directory that really did go away is churn, and the walk goes on.
  fs.openSync = failOn("ENOENT");
  let got;
  try {
    got = await s._walk(ws);
  } finally {
    fs.openSync = realOpen;
  }
  assert.ok("top.txt" in got && !("sub/f.txt" in got));
  fs.rmSync(ws, { recursive: true, force: true });
});

test("a member's mtime and mode survive this writer and this reader", () => {
  // THE ARCHIVE IS A WIRE FORMAT between the two bindings, and three of its fields were constants
  // here: mtime 0 ("deterministic", with no consumer anywhere in either package's tests, READMEs or
  // docs), mode 0644, and no directory members at all. Measured against the Python binding on the
  // same tree, the restored trees differed in all three. This asserts the writer's half; the
  // four-way cross-binding check lives in the Python suite, which can drive both.
  const out = [];
  kern._tarWriteDir(out, "d", 1600000000);
  kern._tarWriteFile(out, "d/exec.sh", Buffer.from("#!/bin/sh\n"), 1600000000, 0o755);
  kern._tarWriteFile(out, "d/plain.txt", Buffer.from("p"), 1600000001, 0o644);
  const members = kern._tarParseRaw(kern._tarFinish(out, false));
  assert.deepStrictEqual(
    members.map((m) => [m.name, m.type, m.mtime, (m.mode & 0o777).toString(8)]),
    [
      ["d", "dir", 1600000000, "755"],
      ["d/exec.sh", "file", 1600000000, "700"],
      ["d/plain.txt", "file", 1600000001, "600"],
    ],
  );
  // The owner bits only, and that is the rule, not an accident: on a workspace shared with a box
  // account the GROUP bits are the ACL's mask, and the ACL does not travel in a tar.
  assert.strictEqual(members[1].mode & 0o077, 0, "group and other bits must not be carried");
});

test("a path of 101 to 255 bytes round trips through the ustar prefix field", () => {
  // The writer refused every path over 100 bytes while this reader has always read `prefix`, so
  // Node could not write what Node could read - and a Python-written archive with such a path threw
  // from Node's own re-emission path AFTER part of the tree had been written.
  const name = `${"a".repeat(60)}/${"b".repeat(60)}/${"c".repeat(55)}/deep.txt`;
  assert.ok(Buffer.byteLength(name) > 100 && Buffer.byteLength(name) <= 255, `${name.length}`);
  const out = [];
  kern._tarWriteFile(out, name, Buffer.from("D"), 1600000000, 0o644);
  const members = kern._tarParseRaw(kern._tarFinish(out, false));
  assert.deepStrictEqual(members.map((m) => m.name), [name]);
  // The split is on a `/`, which is what keeps it safe for any encoding: one byte in UTF-8, never
  // part of a multibyte sequence, so neither field can end mid-character.
  const split = kern._tarSplitName(name);
  assert.strictEqual(`${split.prefix}/${split.name}`, name);
  assert.ok(Buffer.byteLength(split.prefix) <= 155 && Buffer.byteLength(split.name) <= 100);
  // Beyond ustar, and a name with no usable split, are REFUSED by name rather than truncated into
  // the 100-byte field (which is what `Buffer.write` would do in silence).
  assert.strictEqual(kern._tarSplitName("x".repeat(256)), null);
  assert.strictEqual(kern._tarSplitName(`${"d".repeat(120)}/${"e".repeat(101)}`), null);
  assert.throws(() => kern._tarWriteFile([], "x".repeat(256), Buffer.alloc(0)), /too long for the tar format/);
  assert.throws(
    () => kern._tarWriteFile([], `${"d".repeat(120)}/${"e".repeat(101)}`, Buffer.alloc(0)),
    /cannot be split for the tar format/,
  );
});

test("a numeric field a crafted archive cannot overflow", () => {
  // An 11-digit octal field holds up to 8^11-1. A larger value written as-is would be 12 digits and
  // would overrun into the checksum field - a header whose checksum still verifies and whose date is
  // wrong - and on the READ side an unclamped value reaches `futimes`: measured on the Python side,
  // where a member carrying `1 << 70` raised `OverflowError` out of `restore` after part of the tree
  // had been written.
  assert.strictEqual(kern._tarOctalField(0), `${"0".repeat(11)}\0`);
  assert.strictEqual(kern._tarOctalField(kern._TAR_MAX_OCTAL), `${"7".repeat(11)}\0`);
  assert.strictEqual(kern._tarOctalField(kern._TAR_MAX_OCTAL + 1), `${"7".repeat(11)}\0`);
  assert.strictEqual(kern._tarOctalField(2 ** 70), `${"7".repeat(11)}\0`);
  // The inputs a real `stat` can produce on a file with no usable timestamp. `Math.floor` of a
  // non-finite value is NaN, and `NaN.toString(8)` is the string "NaN", which would corrupt the
  // header in silence.
  for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY, undefined, null, "x"])
    assert.strictEqual(kern._tarOctalField(bad), `${"0".repeat(11)}\0`, String(bad));
  assert.strictEqual(kern._tarOctalField(1600000000.9), `${(1600000000).toString(8).padStart(11, "0")}\0`);
  // And a field this reader cannot parse means "no timestamp", not a refused archive: a size decides
  // how the archive is FRAMED, an mtime decides a date on one file.
  const out = [];
  kern._tarWriteFile(out, "f", Buffer.from("x"), 1600000000, 0o644);
  const raw = kern._tarFinish(out, false);
  const base256 = Buffer.from(raw);
  base256[136] = 0x80; // GNU base-256 marker, which this reader does not implement
  // The checksum must be recomputed or the archive is refused for the wrong reason.
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 0x20 : base256[i];
  base256.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8);
  const got = kern._tarParseRaw(base256);
  assert.strictEqual(got.length, 1);
  assert.strictEqual(got[0].mtime, 0, "an unparsable mtime is no timestamp, not a refusal");
  assert.strictEqual(got[0].content.toString(), "x", "and the bytes are still restored");
});

test("a snapshot member longer than 100 bytes keeps the directory the archive put it in", () => {
  // ustar splits a path of 101 to 255 bytes across `prefix` (155 bytes at offset 345) and `name`,
  // and Python's USTAR writer - what the other binding's `snapshot()` uses - does exactly that.
  // Read as `name` alone, such a member was written to the workspace ROOT under its tail: it
  // overwrote whatever had that name there and lost the archive's own structure. Built here with
  // Python's own tarfile, so the fixture is the writer this has to interoperate with rather than
  // this test's idea of one.
  const dir = `d${"x".repeat(120)}`;
  const want = `${dir}/leaf.txt`;
  const py = spawnSync(
    "python3",
    [
      "-c",
      [
        "import io,sys,tarfile",
        "buf=io.BytesIO()",
        "tf=tarfile.open(fileobj=buf,mode='w:',format=tarfile.USTAR_FORMAT)",
        `i=tarfile.TarInfo(${JSON.stringify(want)})`,
        "i.size=5",
        "tf.addfile(i,io.BytesIO(b'hello'))",
        "tf.close()",
        "sys.stdout.buffer.write(buf.getvalue())",
      ].join("\n"),
    ],
    { maxBuffer: 1 << 20 },
  );
  if (py.status !== 0) {
    assert.ok(true, "skip: no python3 to build the ustar fixture");
    return;
  }
  const members = kern._tarParseRaw(py.stdout);
  assert.strictEqual(members.length, 1);
  assert.strictEqual(
    members[0].name,
    want,
    "the prefix field was dropped, so the member would be written to the workspace root",
  );
  assert.strictEqual(members[0].content.toString(), "hello");
});

test("a snapshot with GNU long-name headers is refused by name", () => {
  // `L` carries the real path as the CONTENT of an extra header, so the member after it has a
  // placeholder name: met as an ordinary member, the reader wrote a file called `././@LongLink`.
  // Neither binding writes them, so saying which feature is missing is the honest answer.
  const py = spawnSync(
    "python3",
    [
      "-c",
      [
        "import io,sys,tarfile",
        "buf=io.BytesIO()",
        "tf=tarfile.open(fileobj=buf,mode='w:',format=tarfile.GNU_FORMAT)",
        `i=tarfile.TarInfo('${"a".repeat(300)}/leaf.txt')`,
        "i.size=0",
        "tf.addfile(i)",
        "tf.close()",
        "sys.stdout.buffer.write(buf.getvalue())",
      ].join("\n"),
    ],
    { maxBuffer: 1 << 20 },
  );
  if (py.status !== 0) {
    assert.ok(true, "skip: no python3 to build the GNU fixture");
    return;
  }
  assert.throws(() => kern._tarParseRaw(py.stdout), /GNU long-name/);
});

// ---------------------------------------------------------------------------
// SNAPSHOT: WHAT IT CARRIES, WHAT IT LEAVES OUT, AND WHERE ITS .deps CAME FROM
// ---------------------------------------------------------------------------

function enteredSandbox(opts = {}) {
  const s = cfg(opts);
  s._ws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-node-s2-"));
  s._entered = true;
  return s;
}

async function withWarnings(fn) {
  const seen = [];
  const on = (w) => seen.push(w);
  process.on("warning", on);
  const prev = process.env.KERN_SANDBOX_SNAPSHOT;
  process.env.KERN_SANDBOX_SNAPSHOT = "1";
  try {
    await fn();
    await new Promise((r) => setImmediate(r)); // emitWarning delivers on a later tick
  } finally {
    process.off("warning", on);
    if (prev === undefined) delete process.env.KERN_SANDBOX_SNAPSHOT;
    else process.env.KERN_SANDBOX_SNAPSHOT = prev;
  }
  return seen;
}

function tarNames(gzPath) {
  return kern._tarParseRaw(zlibGunzip(fs.readFileSync(gzPath))).map((m) => m.name);
}

test("a snapshot records what its .deps were built for first, and restore warns only on a different image", async () => {
  // MEASURED without it: a compiled package from a python 3.12 glibc image, restored into
  // python:3.10-alpine, failed to import as ModuleNotFoundError naming the package, not the snapshot.
  const a = enteredSandbox({ image: "example.org/py:3.12" });
  fs.mkdirSync(path.join(a._ws, ".deps"));
  fs.writeFileSync(path.join(a._ws, ".deps", "x.py"), "");
  const arc = path.join(os.tmpdir(), `kern-node-s2-${process.pid}.tgz`);
  await withWarnings(() => a.snapshot(arc));
  const members = kern._tarParseRaw(zlibGunzip(fs.readFileSync(arc)));
  assert.strictEqual(members[0].name, ".kern-snapshot.json");
  const rec = JSON.parse(members[0].content.toString());
  assert.deepStrictEqual(rec, { kern_snapshot: 1, image: "example.org/py:3.12", machine: os.machine(), deps: true });

  const same = enteredSandbox({ image: "example.org/py:3.12" });
  const w1 = await withWarnings(() => same.restore(arc));
  assert.deepStrictEqual(w1.filter((w) => w.name === "KernSnapshotOrigin"), [], "same image: no warning");
  assert.ok(!fs.existsSync(path.join(same._ws, ".kern-snapshot.json")), "the record is read, never restored");
  assert.ok(fs.existsSync(path.join(same._ws, ".deps", "x.py")));

  const other = enteredSandbox({ image: "python:3.10-alpine" });
  const w2 = await withWarnings(() => other.restore(arc));
  const notes = w2.filter((w) => w.name === "KernSnapshotOrigin").map((w) => w.message);
  assert.strictEqual(notes.length, 1, String(notes));
  assert.ok(notes[0].includes("'example.org/py:3.12'") && notes[0].includes("'python:3.10-alpine'"), notes[0]);
});

test("a Python snapshot's record is understood here, and a user file of the same name is restored", async () => {
  // Built with the Python binding's own snapshot code path shape: the record first, then the tree.
  const py = spawnSync("python3", ["-c", [
    "import io, json, sys, tarfile",
    "buf = io.BytesIO()",
    "tf = tarfile.open(fileobj=buf, mode='w:gz', format=tarfile.USTAR_FORMAT)",
    "def add(n, b):",
    "    i = tarfile.TarInfo(n); i.size = len(b); tf.addfile(i, io.BytesIO(b))",
    "add('.kern-snapshot.json', json.dumps({'kern_snapshot': 1, 'image': 'img-a', 'machine': 'x86_64', 'deps': True}).encode())",
    "add('.deps/m.py', b'')",
    "add('.kern-snapshot.json', b'{\"mine\": true}')",
    "tf.close(); sys.stdout.buffer.write(buf.getvalue())",
  ].join("\n")], { maxBuffer: 1 << 20 });
  if (py.status !== 0) return; // no python3 here
  const arc = path.join(os.tmpdir(), `kern-node-s2py-${process.pid}.tgz`);
  fs.writeFileSync(arc, py.stdout);
  const s = enteredSandbox({ image: "img-b" });
  const w = await withWarnings(() => s.restore(arc));
  assert.strictEqual(w.filter((x) => x.name === "KernSnapshotOrigin").length, 1, "another image: warned");
  assert.strictEqual(fs.readFileSync(path.join(s._ws, ".kern-snapshot.json"), "utf8"), '{"mine": true}');

  // THE NAME ALONE IS NOT THE RECORD. A first member with the name and without the key - a tar made
  // by hand - is an ordinary file, restored as one and warned about by nobody.
  const hand = spawnSync("python3", ["-c", [
    "import io, sys, tarfile",
    "buf = io.BytesIO()",
    "tf = tarfile.open(fileobj=buf, mode='w:gz', format=tarfile.USTAR_FORMAT)",
    "b = b'{\"kern_snapshot\": 2, \"image\": \"elsewhere\"}'",
    "i = tarfile.TarInfo('.kern-snapshot.json'); i.size = len(b); tf.addfile(i, io.BytesIO(b))",
    "i = tarfile.TarInfo('.deps/m.py'); i.size = 0; tf.addfile(i, io.BytesIO(b''))",
    "tf.close(); sys.stdout.buffer.write(buf.getvalue())",
  ].join("\n")], { maxBuffer: 1 << 20 });
  const handArc = path.join(os.tmpdir(), `kern-node-s2hand-${process.pid}.tgz`);
  fs.writeFileSync(handArc, hand.stdout);
  const t = enteredSandbox({ image: "img-b" });
  const w2 = await withWarnings(() => t.restore(handArc));
  assert.strictEqual(w2.filter((x) => x.name === "KernSnapshotOrigin").length, 0);
  assert.strictEqual(
    fs.readFileSync(path.join(t._ws, ".kern-snapshot.json"), "utf8"),
    '{"kern_snapshot": 2, "image": "elsewhere"}',
  );
});

test("a snapshot names what it leaves out and never holds a member restore refuses", async () => {
  // The Python binding archived a symlink as a link member, which every restore refuses whole:
  // measured on 0.2.45, one symlink made a snapshot that could not be restored. Here it was left out
  // in silence; now it is named.
  const a = enteredSandbox();
  fs.writeFileSync(path.join(a._ws, "data.txt"), "x");
  fs.symlinkSync("data.txt", path.join(a._ws, "latest"));
  fs.linkSync(path.join(a._ws, "data.txt"), path.join(a._ws, "hard.txt"));
  spawnSync("mkfifo", [path.join(a._ws, "pipe")]);
  const arc = path.join(os.tmpdir(), `kern-node-s2l-${process.pid}.tgz`);
  const w = await withWarnings(() => a.snapshot(arc));
  const said = w.filter((x) => x.name === "KernSnapshotIncomplete").map((x) => x.message);
  assert.strictEqual(said.length, 1, String(said));
  assert.ok(said[0].includes('"latest"') && said[0].includes('"pipe"'), said[0]);
  const b = enteredSandbox();
  await withWarnings(() => b.restore(arc));
  assert.strictEqual(fs.readFileSync(path.join(b._ws, "hard.txt"), "utf8"), "x");
});

test("a snapshot written into the workspace does not carry the previous one", async () => {
  // The archive is built in memory and written after the walk, so the file the walk meets at `dest`
  // is the PREVIOUS checkpoint: archived, it nests every checkpoint inside the next.
  const a = enteredSandbox();
  fs.writeFileSync(path.join(a._ws, "kept.txt"), "k");
  const dest = path.join(a._ws, "ckpt.tar.gz");
  await withWarnings(() => a.snapshot(dest));
  await withWarnings(() => a.snapshot(dest));
  assert.ok(!tarNames(dest).includes("ckpt.tar.gz"), String(tarNames(dest)));
  assert.ok(tarNames(dest).includes("kept.txt"));
});

test("restore writes every byte of a member, or fails", async () => {
  // One write(2) may write fewer bytes than it was given; the loop must finish the member. Driven by a
  // writeSync that writes at most 3 bytes per call, the way a filling disk answers.
  const a = enteredSandbox();
  fs.writeFileSync(path.join(a._ws, "big.txt"), "0123456789abcdef");
  const arc = path.join(os.tmpdir(), `kern-node-s2w-${process.pid}.tgz`);
  await withWarnings(() => a.snapshot(arc));
  const b = enteredSandbox();
  const real = fs.writeSync;
  fs.writeSync = (fd, buf, off = 0, len = buf.length - off, ...rest) => real(fd, buf, off, Math.min(len, 3), ...rest);
  try {
    await withWarnings(() => b.restore(arc));
  } finally {
    fs.writeSync = real;
  }
  assert.strictEqual(fs.readFileSync(path.join(b._ws, "big.txt"), "utf8"), "0123456789abcdef");
});

test("a snapshot path inside the workspace never follows what the box planted", async () => {
  // `snapshot(<ws>/ckpt.tar.gz)` is tested and documented, so the name is one a box can predict. By path,
  // a symlink planted there sent the archive onto the host file it named; one at a restore source read a
  // HOST archive into the box's reach. The controls are the same calls with nothing planted. Mirrors Python.
  const a = enteredSandbox();
  fs.writeFileSync(path.join(a._ws, "kept.txt"), "k");
  const host = fs.mkdtempSync(path.join(os.tmpdir(), "kern-node-host-"));
  const victim = path.join(host, "host-file");
  fs.writeFileSync(victim, "HOST");
  fs.symlinkSync(victim, path.join(a._ws, "ckpt.tar.gz"));
  await withWarnings(async () => {
    assert.throws(() => a.snapshot(path.join(a._ws, "ckpt.tar.gz")), SandboxError);
  });
  assert.strictEqual(fs.readFileSync(victim, "utf8"), "HOST", "the archive was written through the box's symlink");
  fs.symlinkSync(host, path.join(a._ws, "out"));
  await withWarnings(async () => {
    assert.throws(() => a.snapshot(path.join(a._ws, "out", "ckpt.tar.gz")), SandboxError);
  });
  assert.ok(!fs.existsSync(path.join(host, "ckpt.tar.gz")));

  const hostArc = path.join(host, "host.tgz");
  await withWarnings(async () => {
    const donor = enteredSandbox();
    fs.writeFileSync(path.join(donor._ws, "secret.txt"), "SECRET");
    donor.snapshot(hostArc);
  });
  fs.symlinkSync(hostArc, path.join(a._ws, "incoming.tgz"));
  await withWarnings(async () => {
    assert.throws(() => a.restore(path.join(a._ws, "incoming.tgz")), SandboxError);
  });
  assert.ok(!fs.existsSync(path.join(a._ws, "secret.txt")));

  // The controls: nothing planted, both work.
  fs.unlinkSync(path.join(a._ws, "ckpt.tar.gz"));
  await withWarnings(() => a.snapshot(path.join(a._ws, "ckpt.tar.gz")));
  const b = enteredSandbox();
  fs.copyFileSync(path.join(a._ws, "ckpt.tar.gz"), path.join(b._ws, "in.tgz"));
  await withWarnings(() => b.restore(path.join(b._ws, "in.tgz")));
  assert.strictEqual(fs.readFileSync(path.join(b._ws, "kept.txt"), "utf8"), "k");
});
