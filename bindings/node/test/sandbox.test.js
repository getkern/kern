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

test("capabilities are dropped by default and the opt-out is explicit", () => {
  // kern always drops 14 dangerous capabilities; the rest were held over the box's own user
  // namespace, on the one code path whose purpose is running code nobody has read. Measured before
  // this change: a box held CapEff 00000110bdacffff, and with the flag it holds 0000000000000000.
  const prev = process.env.KERN_BIN;
  process.env.KERN_BIN = "/bin/true";
  try {
    const argv = new Sandbox()._baseArgv("n", { network: false, timeoutS: 30 });
    assert.ok(argv.includes("--cap-drop"), "the default must drop capabilities");
    assert.strictEqual(argv[argv.indexOf("--cap-drop") + 1], "ALL");
    assert.ok(argv.indexOf("--cap-drop") > argv.indexOf("--image"));

    // The opt-out exists because the change is not behaviour-free: a workload binding a port below
    // 1024 inside the box needs CAP_NET_BIND_SERVICE. It has to be asked for by name.
    const off = new Sandbox({ capDrop: [] })._baseArgv("n", { network: false, timeoutS: 30 });
    assert.ok(!off.includes("--cap-drop"));

    // A narrower set is passed through one flag per name, in order.
    const narrow = new Sandbox({ capDrop: ["SYS_ADMIN", "CAP_NET_RAW"] })._baseArgv("n", {
      network: false,
      timeoutS: 30,
    });
    assert.strictEqual(narrow.filter((a) => a === "--cap-drop").length, 2);
    assert.strictEqual(narrow[narrow.indexOf("--cap-drop") + 1], "SYS_ADMIN");

    // The setup box is hardened the same way: it installs dependencies, from the network, which is
    // exactly when a hostile package would run its own code.
    const setup = new Sandbox()._baseArgv("n", { network: true, timeoutS: 30, isSetup: true });
    assert.ok(setup.includes("--cap-drop"));

    // The names that MUST work, or the opt-out is useless.
    for (const good of ["ALL", "SYS_ADMIN", "CAP_NET_BIND_SERVICE", "DAC_OVERRIDE", "MKNOD"])
      assert.deepStrictEqual(new Sandbox({ capDrop: [good] })._capDropArgs, ["--cap-drop", good]);
  } finally {
    if (prev === undefined) delete process.env.KERN_BIN;
    else process.env.KERN_BIN = prev;
  }

  // capDrop reaches kern's argv, so it is validated like a profile token rather than trusted.
  for (const bad of ["--net", "-v /etc:/etc", "net_admin", "NET ADMIN", "NET;rm", "NET\n", "",
                     "CAP_", "1NET", "A".repeat(40), "--cap-add", "NET_", "_NET", "NET__RAW", "ALL "])
    assert.throws(
      () => new Sandbox({ capDrop: [bad] }),
      SandboxError,
      `should reject ${JSON.stringify(bad)}`,
    );
  // A bare string would spread into single characters and produce three bogus flags from "ALL".
  assert.throws(() => new Sandbox({ capDrop: "ALL" }), SandboxError);
});

test("apparmor profile reaches the argv and bad names are refused", () => {
  const prev = process.env.KERN_BIN;
  process.env.KERN_BIN = "/bin/true";
  try {
    const argv = new Sandbox({ apparmor: "docker-default" })._baseArgv("n", {
      network: false,
      timeoutS: 30,
    });
    assert.ok(argv.includes("--apparmor"));
    assert.strictEqual(argv[argv.indexOf("--apparmor") + 1], "docker-default");
    assert.ok(argv.indexOf("--apparmor") > argv.indexOf("--image"));
    // The default (no apparmor) adds no flag - the box keeps kern's normal posture.
    const none = new Sandbox()._baseArgv("n", { network: false, timeoutS: 30 });
    assert.ok(!none.includes("--apparmor"));
    // Names that MUST work, or the flag is useless: plain profiles and the special "unconfined".
    for (const good of ["unconfined", "kern-box", "docker-default", "lxc-container-default"]) {
      const a = new Sandbox({ apparmor: good })._baseArgv("n", { network: false, timeoutS: 30 });
      assert.strictEqual(a[a.indexOf("--apparmor") + 1], good);
    }
  } finally {
    if (prev === undefined) delete process.env.KERN_BIN;
    else process.env.KERN_BIN = prev;
  }
  // The name reaches kern's argv, so a value that could smuggle another flag, carry a space, be
  // namespaced (`/` or `:`), empty, or too long is refused AT CONSTRUCTION.
  for (const bad of ["--privileged", "-net", "a b", "prof;rm", "prof\n", "", "a/b", "ns:prof",
                     "x".repeat(200)])
    assert.throws(
      () => new Sandbox({ apparmor: bad }),
      SandboxError,
      `should reject ${JSON.stringify(bad)}`,
    );
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

test("per-call timeoutS is validated", () => {
  const s = new Sandbox({ timeoutS: 30 });
  for (const bad of [0, -1, "x"]) assert.throws(() => s._effTimeout(bad), SandboxError);
  assert.strictEqual(s._effTimeout(undefined), 30);
  assert.strictEqual(s._effTimeout(2), 2);
});

test("pull network failure classifies as startup_failed (curl marker)", () => {
  // A box that never started because the PULL failed (network/DNS down) prints kern's
  // "error: curl failed:" prefix -> a startup failure, not the user's code failing.
  const s = new Sandbox({ timeoutS: 30 });
  const curl =
    "-> resolving bad.invalid/x (linux/amd64)\n" +
    "error: curl failed: exit Some(28): curl: (28) Resolving timed out after 10000 ms\n";
  assert.strictEqual(s._classify(1, null, curl, false).type, "startup_failed");
  assert.strictEqual(s._classify(1, null, "boom\n", false), null); // plain user error stays null
});

test("exit 125 startup failure requires the kern marker, not a bare 125", () => {
  // kern's box-not-started exits 125 AND prints a `kern:` marker. The marker is REQUIRED: a workload
  // that ITSELF exits 125 (the code ran and chose 125) has no marker and must stay a NORMAL result -
  // else the SDK would reject "box failed to start" on the user's own exit code.
  const s = new Sandbox({ timeoutS: 30 });
  const marker = "kern: sandbox setup failed: --apparmor demo: could not enter the profile\n";
  assert.strictEqual(s._classify(125, null, marker, false).type, "startup_failed"); // 125 + kern marker
  assert.strictEqual(s._classify(125, null, "", false), null); // bare 125 = the WORKLOAD's own exit
  assert.strictEqual(s._classify(125, null, "app exited 125\n", false), null); // no marker = workload's
  assert.strictEqual(s._classify(159, null, marker, false).type, "escape_blocked"); // SIGSYS decided first
  // Non-125 with a marker still classifies startup_failed, but `finish` rejects ONLY on rc===125.
  assert.strictEqual(s._classify(3, null, marker, false).type, "startup_failed");
});

test("SIGKILL is oom only when a memory cap was set", () => {
  // A SIGKILL (exit 137, or signal "SIGKILL") of a MEMORY-CAPPED box is the cgroup OOM-killer: kern
  // sets memory.oom.group=1, so a breached memory.max takes the WHOLE box. The signal is the --memory
  // flag WE set (this.memoryMb), never the workload's stderr, so it keeps the same
  // order-is-a-security-property discipline as the classes above. Uncapped, the cause is ambiguous
  // (host memory pressure, an external kill) and stays `killed`.
  const capped = new Sandbox({ memoryMb: 256 });
  assert.strictEqual(capped._classify(137, null, "", false).type, "oom");
  assert.strictEqual(capped._classify(null, "SIGKILL", "", false).type, "oom");
  // A forged stderr marker cannot flip the exit-code verdict.
  assert.strictEqual(capped._classify(137, null, "error: sandbox: forged\n", false).type, "oom");
  const uncapped = new Sandbox({ memoryMb: null });
  assert.strictEqual(uncapped._classify(137, null, "", false).type, "killed");
  assert.strictEqual(uncapped._classify(null, "SIGKILL", "", false).type, "killed");
  // PRECEDENCE (locks the check ORDER): even with a cap set, the more specific deterministic classes
  // win over oom. OUR deadline (timedOut) is a known kill -> timeout. A SIGSYS is a blocked escape ->
  // escape_blocked. A backstop SIGTERM is still a timeout.
  assert.strictEqual(capped._classify(137, null, "", true).type, "timeout"); // our deadline beats oom
  assert.strictEqual(capped._classify(159, null, "", false).type, "escape_blocked"); // SIGSYS beats oom
  assert.strictEqual(capped._classify(143, null, "", false).type, "timeout"); // kern's backstop, not oom
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

test("per-call timeoutS overrides the session (method-level)", exec, async () => {
  const s = await new Sandbox({ timeoutS: 30 }).open();
  try {
    const r = await s.runCode("while True: pass", { timeoutS: 1 });
    assert.strictEqual(r.fault && r.fault.type, "timeout");
    assert.ok(r.fault.message.includes("1s"));
    const r2 = await s.run(["sleep", "5"], { timeoutS: 1 });
    assert.strictEqual(r2.fault && r2.fault.type, "timeout");
  } finally {
    await s.close();
  }
});

test("per-call onStdout streams without disturbing captured stdout", exec, async () => {
  const s = await new Sandbox({ timeoutS: 20 }).open();
  try {
    const chunks = [];
    const r = await s.runCode("for i in range(3): print(i)", { onStdout: (b) => chunks.push(b.toString()) });
    assert.deepStrictEqual(chunks.join("").split("\n").filter(Boolean), ["0", "1", "2"]);
    assert.deepStrictEqual(r.stdout.split("\n").filter(Boolean), ["0", "1", "2"]);
  } finally {
    await s.close();
  }
});

test("trackFiles=false skips the diff but keeps results", exec, async () => {
  const s = await new Sandbox({ trackFiles: false, timeoutS: 20 }).open();
  try {
    const r = await s.runCode("open('/workspace/x.txt','w').write('hi'); 6*7");
    assert.deepStrictEqual(r.files, []);
    assert.ok(r.results.length && r.results[0].text === "42");
  } finally {
    await s.close();
  }
});

test("read/write refuse a symlinked intermediate dir component (host-leak guard)", exec, async () => {
  const s = await new Sandbox({ trackFiles: false }).open();
  try {
    await s.runCode("import os; os.makedirs('/workspace/d', exist_ok=True); os.symlink('/etc', '/workspace/d/esc')");
    await assert.rejects(() => s.readFile("d/esc/hostname"), SandboxError); // would leak host /etc/hostname
    await assert.rejects(() => s.listFiles("d/esc"), SandboxError); // would enumerate a host dir's names
    await s.writeFile("sub/ok.txt", "hi"); // normal nested I/O still works
    assert.strictEqual((await s.readFile("sub/ok.txt")).toString(), "hi");
    assert.deepStrictEqual((await s.listFiles("sub")).map((f) => f.path), ["sub/ok.txt"]);
  } finally {
    await s.close();
  }
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

// -- P1: rich mime-typed results (Jupyter/E2B-style), non-network --------------------------------

test("P1 trailing expression is captured as a result", exec, async () => {
  const r = await runCode("a = 20\nb = 22\na + b");
  assert.strictEqual(r.success, true);
  assert.ok(r.results.length >= 1);
  assert.strictEqual(r.results[0].text, "42");
});

test("P1 a statement makes no result and leaves stdout intact", exec, async () => {
  const r = await runCode("print('hello')");
  assert.strictEqual(r.stdout.trim(), "hello");
  assert.deepStrictEqual(r.results, []); // print returns None -> no spurious result
});

test("P1 display() and rich _repr_html_", exec, async () => {
  const r = await runCode("display(1); display(2); print('done')");
  assert.strictEqual(r.results.length, 2);
  assert.strictEqual(r.results[0].text, "1");
  assert.strictEqual(r.stdout.trim(), "done");
  const rh = await runCode('class H:\n    def _repr_html_(self): return "<b>hi</b>"\nH()');
  assert.strictEqual(rh.results[0].html, "<b>hi</b>");
  assert.ok(rh.results[0].text); // html AND text/plain both present
});

test("P1 capture never alters exit code or traceback", exec, async () => {
  const rc = await runCode("import sys; sys.exit(3)");
  assert.strictEqual(rc.exitCode, 3);
  const rx = await runCode('def boom():\n    raise ValueError("kaboom")\nboom()');
  assert.strictEqual(rx.success, false);
  assert.strictEqual(rx.fault, null);
  assert.ok(rx.stderr.includes("ValueError: kaboom"));
  assert.ok(!rx.stderr.includes("PY_RUNNER") && rx.stderr.includes(".cell-")); // user frames only
});

test("P1 internal cell/runner/result files are hidden and cleaned", exec, async () => {
  await withSandbox(async (s) => {
    const r = await s.runCode("open('user.txt', 'w').write('hi')\n'done'");
    const names = r.files.map((f) => f.path);
    assert.ok(names.includes("user.txt"));
    assert.ok(!names.some((n) => n.startsWith(".cell-") || n.startsWith(".run-") || n.startsWith(".res-")));
    const left = fs.readdirSync(s._ws).filter((n) => /^\.(cell|run|res)-/.test(n));
    assert.deepStrictEqual(left, []);
    assert.strictEqual(r.results[0].text, "'done'");
  });
});

test("P1 readFile maxBytes caps the read (results DoS guard)", exec, async () => {
  await withSandbox(async (s) => {
    await s.runCode("open('big.bin','wb').write(b'x'*200000)");
    await assert.rejects(() => s.readFile("big.bin", { maxBytes: 1000 }), SandboxError);
    const d = await s.readFile("big.bin", { maxBytes: 500000 });
    assert.strictEqual(d.length, 200000);
  });
});

// ---- warm kernel (persistent interpreter, warm-start) ------------------------------------------

test("kernel: state persists across cells and captures results", exec, async () => {
  await withSandbox(async (s) => {
    const k = await s.kernel();
    try {
      assert.ok(k instanceof kern.Kernel);
      let r = await k.runCode("x = 40");
      assert.ok(r.success && r.results.length === 0);
      r = await k.runCode("y = x + 2\nprint('y =', y)");
      assert.strictEqual(r.stdout.trim(), "y = 42"); // x survived the previous cell
      r = await k.runCode("x * 100"); // trailing expression -> rich result
      assert.strictEqual(r.results[0].text, "4000");
    } finally {
      await k.close();
    }
  });
});

test("kernel: survives a cell error, state intact", exec, async () => {
  await withSandbox(async (s) => {
    const k = await s.kernel();
    try {
      await k.runCode("z = 7");
      const r = await k.runCode("1 / 0");
      assert.strictEqual(r.exitCode, 1);
      assert.ok(!r.success && r.stderr.includes("ZeroDivisionError") && r.fault === null);
      const r2 = await k.runCode("z"); // kernel alive, z still here
      assert.strictEqual(r2.results[0].text, "7");
    } finally {
      await k.close();
    }
  });
});

test("kernel: per-cell timeout tears down and then guards", exec, async () => {
  await withSandbox(async (s) => {
    const k = await s.kernel({ timeoutS: 2 });
    const t = Date.now();
    const r = await k.runCode("while True: pass");
    assert.ok(r.fault && r.fault.type === "timeout" && !r.success);
    assert.ok(Date.now() - t < 8000);
    await assert.rejects(() => k.runCode("1 + 1"), SandboxError);
    await k.close();
  });
});

test("kernel: stdin is EOF, not the control channel", exec, async () => {
  await withSandbox(async (s) => {
    const k = await s.kernel();
    try {
      const r = await k.runCode("import sys; print('in=' + repr(sys.stdin.readline()))");
      assert.strictEqual(r.stdout.trim(), "in=''");
      assert.ok(r.success);
      const r2 = await k.runCode("print(2 + 2)"); // protocol still aligned
      assert.strictEqual(r2.stdout.trim(), "4");
    } finally {
      await k.close();
    }
  });
});

test("kernel: raw fd writes are captured, not corrupting", exec, async () => {
  await withSandbox(async (s) => {
    const k = await s.kernel();
    try {
      let r = await k.runCode("import os; os.write(1, b'RAW\\n'); print('P')");
      assert.ok(r.success && r.stdout.includes("RAW") && r.stdout.includes("P")); // both captured
      assert.strictEqual((await k.runCode("print(6 * 7)")).stdout.trim(), "42"); // still aligned
      r = await k.runCode("import subprocess; subprocess.run(['printf', 'sub'])");
      assert.ok(r.stdout.includes("sub") && r.success); // subprocess stdout captured
      r = await k.runCode("import sys; print('in=' + repr(sys.stdin.read()))");
      assert.strictEqual(r.stdout.trim(), "in=''"); // stdin is EOF, never a cell frame
    } finally {
      await k.close();
    }
  });
});

test("kernel: survives raw fork and multiprocessing", exec, async () => {
  await withSandbox({ memoryMb: 512, pids: 128, timeoutS: 15 }, async (s) => {
    const k = await s.kernel();
    try {
      let r = await k.runCode(
        "import os\n" +
          "for _ in range(15):\n" +
          "    pid = os.fork()\n" +
          "    if pid == 0: os._exit(0)\n" +
          "    os.waitpid(pid, 0)\n" +
          "print('forked-clean')",
      );
      assert.ok(r.stdout.trim() === "forked-clean" && r.success);
      assert.strictEqual((await k.runCode("print(7 * 7)")).stdout.trim(), "49"); // aligned after forks
      r = await k.runCode(
        "from concurrent.futures import ProcessPoolExecutor as P\n" +
          "with P(2) as e: print('mp', sum(e.map(abs, [-1, -2, -3])))",
      );
      assert.ok(r.stdout.includes("mp 6") && r.success); // multiprocessing works
      assert.strictEqual((await k.runCode("print('alive')")).stdout.trim(), "alive");
    } finally {
      await k.close();
    }
  });
});

test("kernel: oversize reply is capped, not host-OOM", exec, async () => {
  await withSandbox({ maxOutputBytes: 4 * 1024 * 1024, timeoutS: 20 }, async (s) => {
    const k = await s.kernel();
    const r = await k.runCode("print('A' * 20_000_000)"); // 20 MB reply vs a 4 MB cap
    assert.ok(r.fault && r.fault.type === "killed" && r.fault.message.includes("cap"));
    await assert.rejects(() => k.runCode("1 + 1"), SandboxError); // torn down
    await k.close();
  });
});

test("kernel: warm cells are far faster than a cold one-shot", exec, async () => {
  await withSandbox(async (s) => {
    let t = Date.now();
    await s.runCode("1 + 1"); // cold: fresh interpreter boot
    const cold = Date.now() - t;
    const k = await s.kernel();
    try {
      await k.runCode("1 + 1"); // warm up the pipe
      t = Date.now();
      for (let i = 0; i < 20; i++) await k.runCode("sum(range(1000))");
      const warm = (Date.now() - t) / 20;
      assert.ok(warm < cold / 10, `warm ${warm}ms should be << cold ${cold}ms`);
    } finally {
      await k.close();
    }
  });
});

test("a reply without a usable exit code is a fault, not a success", () => {
  // The kernel reply is JSON written INSIDE the box, by the code the sandbox exists to contain.
  // `rc` was read as `Number.isInteger(obj.rc) ? obj.rc : 0`, so a missing field or a wrong type
  // became exit code 0 - and `success` is `exitCode === 0 && fault === null`. A cell could therefore
  // report its own failed run as successful by omitting one key. Every shape below is what an
  // untrusted payload can send.
  const k = new kern.Kernel(new Sandbox(), 5);
  const started = Date.now();

  for (const reply of [
    '{"stdout":"","stderr":"","results":[]}', // no rc at all
    '{"rc":"0","stdout":"","stderr":""}', // rc as a string
    '{"rc":null,"stdout":"","stderr":""}', // rc explicitly null
    '{"rc":0.5,"stdout":"","stderr":""}', // rc as a non-integer number
    '{"rc":true,"stdout":"","stderr":""}', // rc as a bool
    '{"rc":[0],"stdout":"","stderr":""}', // rc as an array
  ]) {
    const r = k._resultFromReply(reply, started);
    assert.equal(r.success, false, `${reply} must not be reported as a successful run`);
    assert.notEqual(r.fault, null, `${reply} must carry a fault explaining why`);
    assert.notEqual(r.exitCode, 0, `${reply} must not present exit code 0`);
  }

  // Positive control: a well-formed reply still produces an ordinary successful result, or the
  // assertions above would pass on a binding that rejects everything.
  const ok = k._resultFromReply('{"rc":0,"stdout":"hi","stderr":"","results":[]}', started);
  assert.equal(ok.success, true);
  assert.equal(ok.exitCode, 0);
  assert.equal(ok.stdout, "hi");
  // And a genuine non-zero exit is preserved rather than coerced.
  const bad = k._resultFromReply('{"rc":3,"stdout":"","stderr":"boom"}', started);
  assert.equal(bad.success, false);
  assert.equal(bad.exitCode, 3);
  assert.equal(bad.fault, null);
});

test("kernel death is oom only when a memory cap was set", () => {
  // A resident kernel that dies mid-cell has no per-cell exit code, so it does NOT flow through
  // _classify; its OOM attribution lives in _kernelDeathFault, the runCode counterpart of the one-shot
  // SIGKILL branch. Capped -> oom, uncapped -> killed, a kern setup marker -> startup_failed. The
  // signal is the --memory flag WE set, not the box's (workload-influenceable) stderr.
  const capped = new kern.Kernel(new Sandbox({ memoryMb: 256 }), 5);
  assert.strictEqual(capped._kernelDeathFault("")[0], "oom");
  assert.strictEqual(capped._kernelDeathFault("some traceback\n")[0], "oom"); // stderr does not flip it
  const marker = "kern: sandbox setup failed: --apparmor demo: could not enter the profile\n";
  assert.strictEqual(capped._kernelDeathFault(marker)[0], "startup_failed");
  const uncapped = new kern.Kernel(new Sandbox({ memoryMb: null }), 5);
  assert.strictEqual(uncapped._kernelDeathFault("")[0], "killed");
});

test("concurrent calls on one Sandbox do not fight over the env file", exec, async () => {
  // The env file used to be a single fixed `.kern-env` in the workspace, unlinked and re-created with
  // O_EXCL|O_NOFOLLOW on every call (a deliberate refusal to write through a symlink the box may have
  // planted). Concurrent calls therefore fought over one path, and here the loser did not even get a
  // clean error: one call removed the file while kern was still starting for another and had not read
  // it yet, so that box died with
  //   error: sandbox: cannot read --env-file '...': No such file or directory
  // Measured at 30 concurrent runCode calls before the fix: 2 failed that way and one file was left
  // behind. The security property is unchanged; only the NAME is per-call.
  const sb = new Sandbox({ env: { KERN_TEST_VAR: "x" } });
  await sb.open();
  try {
    const n = 16;
    const res = await Promise.allSettled(
      Array.from({ length: n }, () => sb.run(["true"])),
    );
    const rejected = res.filter((r) => r.status === "rejected").map((r) => String(r.reason?.message).slice(0, 90));
    const faulted = res
      .filter((r) => r.status === "fulfilled" && !r.value.success)
      .map((r) => `${r.value.fault?.type}: ${String(r.value.fault?.message ?? "").slice(0, 90)}`);
    assert.deepStrictEqual(rejected, [], "concurrent calls must not reject");
    assert.deepStrictEqual(faulted, [], "concurrent calls must not fault");
    const leftover = fs.readdirSync(sb._ws).filter((f) => f.startsWith(".kern-env"));
    assert.deepStrictEqual(leftover, [], "env files left behind in the workspace");
  } finally {
    await sb.close();
  }
});

test("our env file is hidden from listings but a user file is not", () => {
  // The filter became prefix-based when the env file went per-call. A bare startsWith would have
  // swallowed a user's `.kern-environment` from `files` and from a snapshot, so it is anchored on the
  // separator, and asserted in both directions.
  assert.strictEqual(Sandbox._isEnvFile(".kern-env"), true);
  assert.strictEqual(Sandbox._isEnvFile(".kern-env.box-abc123"), true);
  assert.strictEqual(Sandbox._isEnvFile(".kern-environment"), false);
  assert.strictEqual(Sandbox._isEnvFile("kern-env"), false);
  assert.strictEqual(Sandbox._isEnvFile("notes.txt"), false);
});

test("the version in the code matches the one in package.json", () => {
  // Same number written twice: npm publishes what package.json says, while anything reading
  // `kern.version` reads the constant. A bumped manifest with a stale constant ships a package that
  // misreports its own version. Its Python twin pins the other pair.
  const pkg = require("../package.json");
  assert.strictEqual(
    kern.version,
    pkg.version,
    `kern.version is ${kern.version} but package.json says ${pkg.version}`,
  );
});

test("a resolved call leaves no timer holding the event loop", exec, async () => {
  // A call used to arm a 250 ms setInterval that `finish` never cleared, so it survived the call and
  // kept the loop alive until its own next tick: measured 224 to 232 ms of dead time between the call
  // resolving and the process being able to exit, against 19 to 27 ms of real work. A one-shot script
  // therefore spent ten times longer waiting on a stale timer than running the box.
  //
  // Asserted as a count of live handles rather than as a duration, so it cannot flap: the deadline
  // timer is cleared by `finish`, and nothing else may be left behind.
  await withSandbox({ image: "alpine", timeoutS: 30 }, async (s) => {
    const live = () => process.getActiveResourcesInfo().filter((r) => r === "Timeout").length;
    const before = live();
    await s.run(["/bin/true"]);
    assert.strictEqual(
      live(),
      before,
      "a resolved call must not leave a timer behind (the 250 ms interval used to outlive it)",
    );
  });
});

test("closing a persistent kernel waits for the exit instead of sleeping a fixed 150 ms", exec, async () => {
  // `close()` used to `await setTimeout(150)` unconditionally, whether or not the box was already
  // gone: 152 ms measured on every close, for a box that exits in a few. It now waits on the child's
  // own exit event with that 150 ms only as a cap.
  //
  // The bound is deliberately just under the old hard floor: 150 ms was a sleep, so ANY value below
  // it fails against the previous code no matter how fast the machine, while 145 leaves nine times
  // the measured 16 ms of headroom for a loaded runner.
  await withSandbox({ image: "python:3.12-slim", timeoutS: 30 }, async (s) => {
    const k = await s.kernel();
    await k.runCode("x = 1");
    const t = Date.now();
    await k.close();
    const ms = Date.now() - t;
    assert.ok(ms < 145, `close() took ${ms} ms; it used to sleep a fixed 150 ms regardless`);
  });
});
