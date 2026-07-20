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

// snapshot/restore is opt-in in the Node binding (KERN_SANDBOX_SNAPSHOT=1); enable it for the suite.
// The dedicated gate test below temporarily unsets it to prove it fails closed.
process.env.KERN_SANDBOX_SNAPSHOT = "1";

// ---- pure logic (no kern needed) ---------------------------------------------------------------

test("version is exported", () => {
  assert.strictEqual(typeof kern.version, "string");
});

test("profiles validated and placed in argv", () => {
  // valid vcpu:/vgpio:/vdisk: profiles land as positional tokens (fake kern so the ctor completes)
  const prev = process.env.KERN_BIN;
  process.env.KERN_BIN = "/bin/true";
  try {
    const s = new Sandbox({ profiles: ["vcpu:heavy", "vgpio:leds", "vdisk:scratch"] });
    const argv = s._baseArgv("n", { network: false, timeoutS: s.timeoutS });
    for (const tok of ["vcpu:heavy", "vgpio:leds", "vdisk:scratch"])
      assert.ok(argv.includes(tok), `${tok} missing from argv`);
  } finally {
    if (prev === undefined) delete process.env.KERN_BIN;
    else process.env.KERN_BIN = prev;
  }
  // a profile entry can never smuggle a flag / unknown prefix / unsafe name (rejected before findKern)
  for (const bad of ["--net", "-v /etc:/etc", "vgpu:x", "vcpu:", "vcpu:bad name", "vcpu:a;b",
                     "vdisk:../x", "vgpio:a/b", "vcpu:x=y", "vcpu:-lead", "", "profile"])
    assert.throws(() => new Sandbox({ profiles: [bad] }), SandboxError, `should reject ${JSON.stringify(bad)}`);
});

test("egressAllow validated and scoped to run boxes", () => {
  const prev = process.env.KERN_BIN;
  process.env.KERN_BIN = "/bin/true";
  try {
    const s = new Sandbox({ egressAllow: ["pypi.org", "files.pythonhosted.org"] });
    const run = s._baseArgv("n", { network: false, timeoutS: 30, isSetup: false });
    const setup = s._baseArgv("n", { network: true, timeoutS: 30, isSetup: true });
    assert.ok(run.includes("--egress-allow") && run.includes("pypi.org,files.pythonhosted.org"));
    assert.ok(!run.includes("--net"));
    assert.ok(!setup.includes("--egress-allow") && setup.includes("--net"));
    assert.throws(() => new Sandbox({ egressAllow: ["x.com"], network: true }), SandboxError);
  } finally {
    if (prev === undefined) delete process.env.KERN_BIN;
    else process.env.KERN_BIN = prev;
  }
  for (const bad of ["http://x.com", "x.com/p", "x.com:80", "*.x.com", "a,b.com", "localhost", "", "-x.com", "no dom"])
    assert.throws(() => new Sandbox({ egressAllow: [bad] }), SandboxError, `should reject ${JSON.stringify(bad)}`);
});

test("snapshot/restore roundtrips and rejects hostile archives", async () => {
  const zlib = require("node:zlib");
  const prev = process.env.KERN_BIN;
  process.env.KERN_BIN = "/bin/true"; // file ops are host-side; no real box is run
  const tmp = () => path.join(os.tmpdir(), "kt-" + Math.random().toString(36).slice(2));
  try {
    const snap = tmp() + ".tgz";
    const s = new Sandbox({});
    await s.open();
    try {
      await s.writeFile("a.txt", "hi");
      await s.writeFile("sub/b.txt", "deep");
      s.snapshot(snap);
    } finally {
      await s.close();
    }
    const s2 = new Sandbox({});
    await s2.open();
    try {
      s2.restore(snap);
      assert.strictEqual((await s2.readFile("a.txt")).toString(), "hi");
      assert.strictEqual((await s2.readFile("sub/b.txt")).toString(), "deep");
    } finally {
      await s2.close();
    }
    const badTar = (name, flag) => {
      const h = Buffer.alloc(512);
      h.write(name, 0, 100);
      h.write("0000644\0", 100, 8);
      h.write("0000000\0", 108, 8);
      h.write("0000000\0", 116, 8);
      h.write("00000000000\0", 124, 12);
      h.write("00000000000\0", 136, 12);
      h.write("        ", 148, 8);
      h.write(flag, 156, 1);
      h.write("ustar\0", 257, 6);
      h.write("00", 263, 2);
      let sum = 0;
      for (const b of h) sum += b;
      h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8);
      return zlib.gzipSync(Buffer.concat([h, Buffer.alloc(1024)]));
    };
    for (const [name, flag] of [
      ["/etc/evil", "0"],
      ["../escape", "0"],
      ["link", "2"],
    ]) {
      const p = tmp() + ".tgz";
      fs.writeFileSync(p, badTar(name, flag));
      const s3 = new Sandbox({});
      await s3.open();
      try {
        assert.throws(() => s3.restore(p), SandboxError, `should reject ${name}`);
      } finally {
        await s3.close();
      }
    }
  } finally {
    if (prev === undefined) delete process.env.KERN_BIN;
    else process.env.KERN_BIN = prev;
  }
});

test("restore refuses a member routed through a planted symlink, and a negative-size tar", async () => {
  const zlib = require("node:zlib");
  const prev = process.env.KERN_BIN;
  process.env.KERN_BIN = "/bin/true";
  const wsdir = () => {
    const d = path.join(os.tmpdir(), "kt-" + Math.random().toString(36).slice(2));
    fs.mkdirSync(d);
    return d;
  };
  const tmpf = () => path.join(os.tmpdir(), "ktf-" + Math.random().toString(36).slice(2)) + ".tgz";
  const hdr = (name, size, flag) => {
    const h = Buffer.alloc(512);
    h.write(name, 0, 100);
    h.write("0000644\0", 100, 8);
    h.write("0000000\0", 108, 8);
    h.write("0000000\0", 116, 8);
    h.write(size + "\0", 124, 12);
    h.write("00000000000\0", 136, 12);
    h.write("        ", 148, 8);
    h.write(flag, 156, 1);
    h.write("ustar\0", 257, 6);
    h.write("00", 263, 2);
    let s = 0;
    for (const b of h) s += b;
    h.write(s.toString(8).padStart(6, "0") + "\0 ", 148, 8);
    return h;
  };
  const fileTar = (name, content) => {
    const pad = (512 - (content.length % 512)) % 512;
    return zlib.gzipSync(
      Buffer.concat([
        hdr(name, content.length.toString(8).padStart(11, "0"), "0"),
        content,
        Buffer.alloc(pad),
        Buffer.alloc(1024),
      ]),
    );
  };
  try {
    // HIGH: a symlink the box planted in the workspace must not let a member escape through it.
    const ws = wsdir();
    const target = wsdir();
    fs.symlinkSync(target, path.join(ws, "evil"));
    const p = tmpf();
    fs.writeFileSync(p, fileTar("evil/pwned.txt", Buffer.from("owned")));
    const s = new Sandbox({ workspace: ws });
    await s.open();
    try {
      assert.throws(() => s.restore(p), SandboxError);
      assert.ok(!fs.existsSync(path.join(target, "pwned.txt")), "must not write outside the workspace");
    } finally {
      await s.close();
    }
    // MEDIUM: a negative octal size must throw, never spin forever.
    const p2 = tmpf();
    fs.writeFileSync(p2, zlib.gzipSync(Buffer.concat([hdr("x", "-1000", "0"), Buffer.alloc(1024)])));
    const s2 = new Sandbox({ workspace: wsdir() });
    await s2.open();
    try {
      assert.throws(() => s2.restore(p2), SandboxError);
    } finally {
      await s2.close();
    }
  } finally {
    if (prev === undefined) delete process.env.KERN_BIN;
    else process.env.KERN_BIN = prev;
  }
});

test("restore rejects a malformed ustar header (bad checksum, non-octal or over-long size)", async () => {
  const zlib = require("node:zlib");
  const prev = process.env.KERN_BIN;
  process.env.KERN_BIN = "/bin/true";
  const wsdir = () => {
    const d = path.join(os.tmpdir(), "kt-" + Math.random().toString(36).slice(2));
    fs.mkdirSync(d);
    return d;
  };
  const tmpf = () => path.join(os.tmpdir(), "ktf-" + Math.random().toString(36).slice(2)) + ".tgz";
  const mk = (sizeField, { badck = false, content = Buffer.alloc(0) } = {}) => {
    const h = Buffer.alloc(512);
    h.write("f", 0, 100);
    h.write("0000644\0", 100, 8);
    h.write("0000000\0", 108, 8);
    h.write("0000000\0", 116, 8);
    h.write(sizeField + "\0", 124, 12);
    h.write("00000000000\0", 136, 12);
    h.write("        ", 148, 8);
    h.write("0", 156, 1);
    h.write("ustar\0", 257, 6);
    h.write("00", 263, 2);
    let s = 0;
    for (const b of h) s += b;
    h.write((badck ? s + 1 : s).toString(8).padStart(6, "0") + "\0 ", 148, 8);
    const pad = (512 - (content.length % 512)) % 512;
    return zlib.gzipSync(Buffer.concat([h, content, Buffer.alloc(pad), Buffer.alloc(1024)]));
  };
  try {
    for (const [label, gz] of [
      ["bad checksum", mk("00000000000", { badck: true })],
      ["non-octal size", mk("0000000012x")],
      ["size exceeds archive", mk("77777777777", { content: Buffer.from("short") })],
    ]) {
      const p = tmpf();
      fs.writeFileSync(p, gz);
      const s = new Sandbox({ workspace: wsdir() });
      await s.open();
      try {
        assert.throws(() => s.restore(p), SandboxError, `should reject: ${label}`);
      } finally {
        await s.close();
      }
    }
  } finally {
    if (prev === undefined) delete process.env.KERN_BIN;
    else process.env.KERN_BIN = prev;
  }
});

test("snapshot/restore fails closed when KERN_SANDBOX_SNAPSHOT is unset", async () => {
  const prevKern = process.env.KERN_BIN;
  process.env.KERN_BIN = "/bin/true";
  const prevSnap = process.env.KERN_SANDBOX_SNAPSHOT;
  delete process.env.KERN_SANDBOX_SNAPSHOT;
  try {
    const s = new Sandbox({});
    await s.open();
    try {
      assert.throws(() => s.snapshot("/tmp/none.tgz"), /KERN_SANDBOX_SNAPSHOT=1/);
      assert.throws(() => s.restore("/tmp/none.tgz"), /KERN_SANDBOX_SNAPSHOT=1/);
    } finally {
      await s.close();
    }
  } finally {
    if (prevKern === undefined) delete process.env.KERN_BIN;
    else process.env.KERN_BIN = prevKern;
    if (prevSnap === undefined) delete process.env.KERN_SANDBOX_SNAPSHOT;
    else process.env.KERN_SANDBOX_SNAPSHOT = prevSnap;
  }
});

test("restore rejects a dir member colliding with a planted symlink, and a dir with non-zero size", async () => {
  const zlib = require("node:zlib");
  const prevKern = process.env.KERN_BIN;
  process.env.KERN_BIN = "/bin/true";
  const wsdir = () => {
    const d = path.join(os.tmpdir(), "kt-" + Math.random().toString(36).slice(2));
    fs.mkdirSync(d);
    return d;
  };
  const tmpf = () => path.join(os.tmpdir(), "ktf-" + Math.random().toString(36).slice(2)) + ".tgz";
  const one = (name, sizeField, flag, content = Buffer.alloc(0)) => {
    const h = Buffer.alloc(512);
    h.write(name, 0, 100);
    h.write("0000644\0", 100, 8);
    h.write("0000000\0", 108, 8);
    h.write("0000000\0", 116, 8);
    h.write(sizeField + "\0", 124, 12);
    h.write("00000000000\0", 136, 12);
    h.write("        ", 148, 8);
    h.write(flag, 156, 1);
    h.write("ustar\0", 257, 6);
    h.write("00", 263, 2);
    let s = 0;
    for (const b of h) s += b;
    h.write(s.toString(8).padStart(6, "0") + "\0 ", 148, 8);
    const pad = (512 - (content.length % 512)) % 512;
    return zlib.gzipSync(Buffer.concat([h, content, Buffer.alloc(pad), Buffer.alloc(1024)]));
  };
  try {
    // a dir member named `d` while the box has planted `d` as a symlink out of the workspace
    const ws = wsdir();
    fs.symlinkSync(wsdir(), path.join(ws, "d"));
    const p1 = tmpf();
    fs.writeFileSync(p1, one("d/", "00000000000", "5"));
    const s = new Sandbox({ workspace: ws });
    await s.open();
    try {
      assert.throws(() => s.restore(p1), SandboxError);
    } finally {
      await s.close();
    }
    // a dir member carrying a non-zero size is malformed
    const p2 = tmpf();
    fs.writeFileSync(p2, one("d/", "00000000001", "5"));
    const s2 = new Sandbox({ workspace: wsdir() });
    await s2.open();
    try {
      assert.throws(() => s2.restore(p2), SandboxError);
    } finally {
      await s2.close();
    }
  } finally {
    if (prevKern === undefined) delete process.env.KERN_BIN;
    else process.env.KERN_BIN = prevKern;
  }
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
