"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const kern = require("../index.js");
const { Sandbox, withSandbox, runCode, SandboxError, MountRefused } = kern;

// Execution tests need a real `kern`; findKern() throws if absent. Detect once and skip if missing.
let KERN_OK = false;
try {
  const findKern = () => {
    if (process.env.KERN_BIN) return process.env.KERN_BIN;
    const dirs = (process.env.PATH || "").split(path.delimiter);
    for (const d of dirs) {
      const c = path.join(d, "kern");
      try {
        fs.accessSync(c, fs.constants.X_OK);
        return c;
      } catch {}
    }
    throw new Error("no kern");
  };
  findKern();
  KERN_OK = true;
} catch {
  KERN_OK = false;
}
const exec = { skip: !KERN_OK && "kern binary not found (set KERN_BIN)" };

// ---- pure logic (no kern needed) ---------------------------------------------------------------

test("version is exported", () => {
  assert.strictEqual(typeof kern.version, "string");
});

test("bad timeout throws SandboxError", () => {
  assert.throws(() => new Sandbox({ timeoutS: 0 }), SandboxError);
  assert.throws(() => new Sandbox({ timeoutS: -1 }), SandboxError);
});

test("bad maxOutputBytes throws SandboxError", () => {
  assert.throws(() => new Sandbox({ maxOutputBytes: 0 }), SandboxError);
});

test("sensitive mount source is refused", () => {
  assert.throws(() => new Sandbox({ mounts: { "/etc": "/host-etc" } }), MountRefused);
  assert.throws(() => new Sandbox({ mounts: { "/": "/root-fs" } }), MountRefused);
});

test("relative mount target is refused", () => {
  assert.throws(() => new Sandbox({ mounts: { "/tmp": "relative/target" } }), MountRefused);
});

test("mount target over an essential mount is refused", () => {
  assert.throws(() => new Sandbox({ mounts: { "/tmp": "/proc" } }), MountRefused);
});

test("'..' in a mount target is refused", () => {
  assert.throws(() => new Sandbox({ mounts: { "/tmp": "/a/../../etc" } }), MountRefused);
});

// ---- real execution (needs kern) ---------------------------------------------------------------

test("runCode python prints and succeeds", exec, async () => {
  const r = await runCode("print(1 + 1)");
  assert.strictEqual(r.success, true);
  assert.strictEqual(r.exitCode, 0);
  assert.strictEqual(r.stdout.trim(), "2");
  assert.strictEqual(r.fault, null);
});

test("runCode bash works", exec, async () => {
  const r = await runCode("echo hello", { language: "bash" });
  assert.strictEqual(r.success, true);
  assert.strictEqual(r.stdout.trim(), "hello");
});

test("runCode node evaluates JS (uses -e, not -c)", exec, async () => {
  const r = await runCode("console.log(2 * 21)", { image: "node:20-slim", language: "node" });
  assert.strictEqual(r.success, true, r.stderr);
  assert.strictEqual(r.stdout.trim(), "42");
});

test("a seccomp-blocked syscall is reported as escape_blocked", exec, async () => {
  // mount() is on kern's always-on seccomp denylist -> SIGSYS -> exit 159.
  const r = await runCode(
    "import ctypes; libc = ctypes.CDLL(None); libc.mount(None, None, None, 0, None)",
  );
  assert.strictEqual(r.fault && r.fault.type, "escape_blocked");
});

test("non-zero user exit is NOT a fault (success=false, fault=null)", exec, async () => {
  const r = await runCode("import sys; sys.exit(3)");
  assert.strictEqual(r.success, false);
  assert.strictEqual(r.exitCode, 3);
  assert.strictEqual(r.fault, null);
});

test("file state persists across runCode; in-memory does not", exec, async () => {
  await withSandbox(async (s) => {
    let r = await s.runCode("open('n.txt','w').write('42')");
    assert.strictEqual(r.success, true, r.stderr);
    r = await s.runCode("print(open('n.txt').read())"); // file state persists
    assert.strictEqual(r.stdout.trim(), "42");
    // in-memory does NOT persist: a var set in a prior call is gone in a fresh box
    await s.runCode("yy = 7");
    r = await s.runCode("print('yy' in dir())");
    assert.strictEqual(r.stdout.trim(), "False");
  });
});

test("writeFile/readFile roundtrip through the workspace", exec, async () => {
  await withSandbox(async (s) => {
    await s.writeFile("in.txt", "kern");
    const r = await s.runCode("print(open('in.txt').read().upper())");
    assert.strictEqual(r.stdout.trim(), "KERN");
    await s.runCode("open('out.txt','w').write('done')");
    const back = await s.readFile("out.txt");
    assert.strictEqual(back.toString(), "done");
  });
});

test("result.files reports created files", exec, async () => {
  await withSandbox(async (s) => {
    const r = await s.runCode("open('made.txt','w').write('hi')");
    assert.ok(r.files.some((f) => f.path === "made.txt" && f.change === "created"), JSON.stringify(r.files));
  });
});

test("writeFile refuses a path escaping the workspace", exec, async () => {
  await withSandbox(async (s) => {
    await assert.rejects(() => s.writeFile("../escape.txt", "x"), SandboxError);
  });
});

test("timeout is owned by the binding (fault=timeout)", exec, async () => {
  const r = await runCode("import time; time.sleep(30)", { timeoutS: 2 });
  assert.strictEqual(r.success, false);
  assert.strictEqual(r.fault && r.fault.type, "timeout");
});

test("network is OFF by default", exec, async () => {
  // With no network, a socket connect to a public IP must fail. Keep it quick.
  const r = await runCode(
    "import socket; socket.setdefaulttimeout(3); socket.create_connection(('1.1.1.1',53))",
  );
  assert.strictEqual(r.success, false); // no route / blocked -> user code raises
});

test("output is capped and truncated flag set", exec, async () => {
  const r = await runCode("print('A' * 100000)", { maxOutputBytes: 1024 });
  assert.ok(r.stdout.length <= 1024, `len=${r.stdout.length}`);
  assert.strictEqual(r.truncated, true);
});

test("env vars reach the workload via the private env file", exec, async () => {
  await withSandbox({ env: { SECRET_TOKEN: "s3cr3t" } }, async (s) => {
    const r = await s.runCode("import os; print(os.environ.get('SECRET_TOKEN'))");
    assert.strictEqual(r.stdout.trim(), "s3cr3t");
  });
});

test("SECURITY: a box-planted .kern-env symlink cannot clobber a host file", exec, async () => {
  const victim = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "kern-victim-")), "precious.txt");
  fs.writeFileSync(victim, "PRECIOUS");
  await withSandbox({ env: { X: "1" } }, async (s) => {
    // the box replaces /workspace/.kern-env with a symlink to the host victim file
    await s.runCode(
      "import os\n" +
        "p='/workspace/.kern-env'\n" +
        "os.path.lexists(p) and os.remove(p)\n" +
        `os.symlink(${JSON.stringify(victim)}, p)`,
    );
    // the next call writes .kern-env (env is set); it must NOT follow the symlink
    await s.runCode("print('ok')");
  });
  assert.strictEqual(fs.readFileSync(victim, "utf8"), "PRECIOUS", "victim file was clobbered!");
});

test("SECURITY: writeFile refuses to traverse a box-planted intermediate symlink", exec, async () => {
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "kern-outside-"));
  await withSandbox(async (s) => {
    await s.runCode(`import os; os.symlink(${JSON.stringify(outside)}, '/workspace/evil')`);
    await assert.rejects(() => s.writeFile("evil/pwned.txt", "x"), SandboxError);
  });
  assert.ok(!fs.existsSync(path.join(outside, "pwned.txt")), "wrote through a symlinked directory!");
});

test("run() takes an argv array, not a string", exec, async () => {
  await withSandbox(async (s) => {
    await assert.rejects(() => s.run("echo hi"), SandboxError);
    const r = await s.run(["echo", "hi"]);
    assert.strictEqual(r.stdout.trim(), "hi");
  });
});
