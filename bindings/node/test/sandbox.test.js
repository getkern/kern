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
  // capSignal (kern's unforgeable enforcement byte) refines the SIGKILL verdict: 1 = enforced -> oom, 2
  // = requested-but-not-enforced -> killed (no overclaim), 0 = undetermined (old kern) -> heuristic.
  // NB: capSignal is the 6th arg (timeoutS is the 5th) - pass null for timeoutS.
  assert.strictEqual(capped._classify(137, null, "", false, null, 1).type, "oom"); // enforced: certain OOM
  assert.strictEqual(capped._classify(137, null, "", false, null, 2).type, "killed"); // not enforced: no overclaim
  assert.strictEqual(capped._classify(137, null, "", false, null, 0).type, "oom"); // undetermined: heuristic
  assert.strictEqual(capped._classify(null, "SIGKILL", "", false, null, 2).type, "killed");
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

test("the default tmpfs is a writable /tmp, and the two kinds of empty differ", () => {
  // The root is read-only, so /tmp only exists as scratch because the binding asks for it.
  assert.deepStrictEqual(new Sandbox()._tmpfsArgs, ["--tmpfs", "/tmp:64m"]);
  // "I did not say" (omitted) and "I said no" ({} / []) must NOT be the same answer.
  assert.deepStrictEqual(new Sandbox({ tmpfs: {} })._tmpfsArgs, []);
  assert.deepStrictEqual(new Sandbox({ tmpfs: [] })._tmpfsArgs, []);
  assert.deepStrictEqual(new Sandbox({ tmpfs: { "/tmp": "512m" } })._tmpfsArgs, ["--tmpfs", "/tmp:512m"]);
  assert.deepStrictEqual(new Sandbox({ tmpfs: ["/scratch"] })._tmpfsArgs, ["--tmpfs", "/scratch"]);
});

test("a dangerous tmpfs target or size is refused", () => {
  for (const bad of [
    { "/workspace": "64m" }, // would shadow the workspace bind: files written stay invisible
    { "/": "1m" }, { "/proc": null }, { "/sys": null }, { "/dev": null },
    { tmp: "1m" }, { "/a/../b": "1m" },
    { "/tmp": "64mb" }, { "/tmp": "64m,x" }, { "/tmp": "64m /etc" },
    { "/tmp": "-1m" }, { "/tmp": "" }, { "/tmp": "m" }, { "/tmp": 64 },
    { "/tmp": "64" },  // BYTES to kern, not MiB: measured 4 KB and ENOSPC at 100 KB
    { "/tmp": "0" }, { "/tmp": "0m" }, // UNLIMITED to kern, not none: measured, OOM at exit 137
    ["/scratch:9g"], { "/tmp/a:b": "1m" }, // ':' is the size separator: measured, mounted /scratch at 9 GiB
    "/tmp", // a bare string would iterate into one mount per character
    256, 0, true, // a NUMBER is what the neighbouring options take (memoryMb, pids)
  ]) {
    assert.throws(() => new Sandbox({ tmpfs: bad }), MountRefused, JSON.stringify(bad));
  }
});

test("the two tmpfs spellings kern reads backwards are refused by name", () => {
  // kern takes both and means the opposite of what a caller writing them means. Measured against a
  // real box: `/tmp:64` is 64 BYTES (df reports 4 KB, a 100 KB write is ENOSPC) and `/tmp:0` is
  // UNLIMITED (200 MiB under memoryMb:128 exited 137). The refusal has to NAME the trap, otherwise
  // "invalid size" sends the reader to a docs page to learn that a unit is required.
  assert.throws(() => new Sandbox({ tmpfs: { "/tmp": "64" } }), /BYTES/);
  assert.throws(() => new Sandbox({ tmpfs: { "/tmp": "0" } }), /UNLIMITED/);
  // `Object.entries(256)` is `[]`, so a number used to mean SILENTLY NO SCRATCH: a read-only /tmp,
  // no error, and the defect back in full. It is also the mistake this API invites, since every
  // neighbouring option takes a number.
  assert.throws(() => new Sandbox({ tmpfs: 256 }), /Did you mean tmpfs: \{ "\/tmp": "256m" \}/);
  assert.throws(() => new Sandbox({ tmpfs: 0 }), /pass tmpfs: \{\}/);
  // A ':' in the TARGET is the same shape one level up: kern splits `path[:size]` on it, so a path
  // carrying one is reinterpreted. Measured before the gate: `["/scratch:9g"]` mounted `/scratch` at
  // 9 GiB and the directory the caller named did not exist in the box.
  assert.throws(() => new Sandbox({ tmpfs: ["/scratch:9g"] }), /size separator/);
  // Control: the spelling the message asks for is accepted, and `t` is a unit kern takes.
  assert.deepStrictEqual(new Sandbox({ tmpfs: { "/tmp": "256m" } })._tmpfsArgs, ["--tmpfs", "/tmp:256m"]);
  // `t` is only REACHABLE on an uncapped box now: a tmpfs larger than the cap is refused.
  assert.deepStrictEqual(new Sandbox({ memoryMb: null, tmpfs: { "/tmp": "1t" } })._tmpfsArgs, ["--tmpfs", "/tmp:1t"]);
  assert.throws(() => new Sandbox({ memoryMb: 128, tmpfs: { "/tmp": "1t" } }), /larger than memoryMb=128/);
});

test("the default tmpfs yields to a caller bind and skips the setup box", () => {
  const here = __dirname;
  // A caller who binds their own directory at /tmp must GET it: the default mounted over that bind
  // would hide every file they passed in, and nothing would say so.
  assert.deepStrictEqual(new Sandbox({ mounts: { [here]: "/tmp" } })._tmpfsArgs, []);
  assert.deepStrictEqual(new Sandbox({ mounts: { [here]: "/data" } })._tmpfsArgs, ["--tmpfs", "/tmp:64m"]);
  // A tmpfs that COVERS a bind is refused, and "covers" is the mountpoint relation, not a string
  // compare: measured, `-v HOST:/tmp/sub --tmpfs /tmp` hides the bind through NESTING exactly as
  // equality does, while `-v HOST:/tmp --tmpfs /tmp/sub` is legal and the bind's files are there.
  for (const [bind, tmpfs] of [["/tmp", "/tmp"], ["/tmp/sub", "/tmp"], ["/tmp/", "/tmp"],
                               ["//tmp", "/tmp"], ["/tmp", "/tmp/"]]) {
    assert.throws(() => new Sandbox({ mounts: { [here]: bind }, tmpfs: { [tmpfs]: "8m" } }), /would cover/);
  }
  assert.deepStrictEqual(
    new Sandbox({ mounts: { [here]: "/tmp" }, tmpfs: { "/tmp/sub": "8m" } })._tmpfsArgs,
    ["--tmpfs", "/tmp/sub:8m"],
  );
  assert.deepStrictEqual(new Sandbox({ mounts: { [here]: "/tmpx" }, tmpfs: { "/tmp": "8m" } })._tmpfsArgs, ["--tmpfs", "/tmp:8m"]);
  // The setup box is the install phase and needs UNBOUNDED scratch: a 64 MiB /tmp turns a package
  // install into ENOSPC. Same shape as egressAllow, which setup also skips.
  const s = new Sandbox();
  const run = s._baseArgv("n", { network: false, timeoutS: s.timeoutS, isSetup: false });
  const setup = s._baseArgv("n", { network: true, timeoutS: s.timeoutS, isSetup: true });
  assert.ok(run.includes("--tmpfs") && !setup.includes("--tmpfs"));
  // ...but an explicit one applies everywhere, including setup: the caller said so.
  const e = new Sandbox({ tmpfs: { "/tmp": "256m" } });
  assert.ok(e._baseArgv("n", { network: true, timeoutS: e.timeoutS, isSetup: true }).includes("--tmpfs"));
});

// ---- real execution (needs kern) ---------------------------------------------------------------

test("bash is bash and sh is the POSIX shell", exec, async () => {
  // `language: "bash"` ran `sh`, which on a Debian image is dash, WITH BASH PRESENT and unused. A
  // caller got a shell chosen for them that fails on the syntax the name promised: an LLM writes
  // `[[ ]]` by reflex and got `sh: 1: [[: not found`, which names neither cause nor remedy.
  const probe = "readlink -f /proc/$$/exe; [[ 1 == 1 ]] && echo BRACKETS-OK || echo BRACKETS-NO";
  const s = new Sandbox({ image: "python:3.12-slim", timeoutS: 30 });
  await s.open();
  try {
    const b = await s.runCode(probe, { language: "bash" });
    assert.ok(b.stdout.includes("/bash") && b.stdout.includes("BRACKETS-OK"), b.stdout);
    // The control: the old behaviour still exists under the name that describes it.
    const p = await s.runCode(probe, { language: "sh" });
    assert.ok(!p.stdout.includes("/bash") && p.stdout.includes("BRACKETS-NO"), p.stdout);
  } finally {
    await s.close();
  }
  // An image with no bash must SAY so rather than silently run something else.
  const alp = new Sandbox({ image: "alpine:3.19", timeoutS: 30 });
  await alp.open();
  try {
    const miss = await alp.runCode("echo hi", { language: "bash" });
    assert.ok(miss.fault && miss.fault.type === "exec_failed", JSON.stringify(miss.fault));
    assert.ok(miss.fault.message.includes("bash") && miss.fault.message.includes("language:'sh'"), miss.fault.message);
    const okSh = await alp.runCode("echo hi", { language: "sh" });
    assert.strictEqual(okSh.stdout.trim(), "hi"); // control: sh works there
  } finally {
    await alp.close();
  }
});

test("a read-only /tmp broke two things and the default tmpfs fixes both", exec, async () => {
  // The control is the whole test. `tmpfs: {}` is the shape this binding shipped before, so both
  // halves of the defect are reproduced HERE and not asserted from memory: a write naming /tmp fails,
  // and a temp-file helper silently relocates into the caller's persistent workspace.
  const probe =
    "import tempfile\n" +
    "try:\n" +
    "    open('/tmp/named','w').write('x'); print('TMP-WRITE ok')\n" +
    "except OSError as e:\n" +
    "    print('TMP-WRITE failed', e.errno)\n" +
    "f = tempfile.NamedTemporaryFile(delete=False); f.write(b'x'); f.close(); print('TEMP', f.name)\n";

  const control = new Sandbox({ tmpfs: {} });
  await control.open();
  let before, leaked;
  try {
    before = await control.runCode(probe);
    leaked = (await control.listFiles()).map((f) => f.path);
  } finally {
    await control.close();
  }
  assert.ok(before.stdout.includes("TMP-WRITE failed"), before.stdout);
  assert.ok(before.stdout.includes("TEMP /workspace/"), "the control must show the fallback into the workspace");
  assert.ok(leaked.length > 0, "the control must leave the temp file on the persistent workspace");

  const s = new Sandbox();
  await s.open();
  let after, clean;
  try {
    after = await s.runCode(probe);
    clean = (await s.listFiles()).map((f) => f.path);
  } finally {
    await s.close();
  }
  assert.ok(after.stdout.includes("TMP-WRITE ok"), after.stdout);
  assert.ok(after.stdout.includes("TEMP /tmp/"), "scratch must land in /tmp, not in the workspace");
  assert.deepStrictEqual(clean, [], "the workspace must stay clean");
});

test("the tmpfs is bounded and charged to the box, not the host", exec, async () => {
  const s = new Sandbox({ tmpfs: { "/tmp": "8m" } });
  await s.open();
  try {
    const r = await s.runCode(
      "import errno\n" +
        "try:\n" +
        "    open('/tmp/fill','wb').write(b'\\0' * (20 << 20)); print('UNBOUNDED')\n" +
        "except OSError as e:\n" +
        "    print('bounded', e.errno == errno.ENOSPC)\n",
    );
    assert.ok(r.stdout.includes("bounded true") || r.stdout.includes("bounded True"), r.stdout);
  } finally {
    await s.close();
  }
  // A tmpfs EQUAL to the memory cap is the cell where the cap binds before the filesystem does:
  // filling it exhausts the whole budget, so the box is killed instead of the write failing. Larger
  // than the cap is now REFUSED at construction, and the binding's own default is clamped to half,
  // so this is reachable only by writing both numbers. In chunks, so the allocation is not what dies.
  const capped = new Sandbox({ memoryMb: 128, tmpfs: { "/tmp": "128m" } });
  await capped.open();
  try {
    const r = await capped.runCode(
      "chunk = b'\\0' * (1 << 20)\n" +
        "with open('/tmp/fill','wb') as f:\n" +
        "    for _ in range(400):\n        f.write(chunk); f.flush()\n" +
        "print('SURVIVED')\n",
    );
    assert.ok(r.fault && r.fault.type === "oom", JSON.stringify({ fault: r.fault, out: r.stdout }));
    assert.ok(!r.stdout.includes("SURVIVED"));
    assert.ok(r.fault.message.includes("/tmp:128m") && r.fault.message.includes("/dev/shm"));
  } finally {
    await capped.close();
  }
});

test("a scratch bigger than the cap is refused and the default is clamped to half", () => {
  // `df` reports the tmpfs size TO A PROGRAM, and a preflighting installer plans against it. A size
  // the CALLER wrote is refused; OUR default is clamped, because refusing it would make a box
  // unstartable for someone who never mentioned scratch. Half rather than the cap is measured: under
  // memoryMb 128, a 32m and a 64m tmpfs end in ENOSPC, a 128m one ends in an OOM.
  assert.throws(() => new Sandbox({ memoryMb: 128, tmpfs: { "/tmp": "1t" } }), /larger than memoryMb=128/);
  assert.throws(() => new Sandbox({ memoryMb: 64, tmpfs: { "/tmp": "65m" } }), /ENOSPC/);
  assert.deepStrictEqual(new Sandbox({ memoryMb: 64, tmpfs: { "/tmp": "64m" } })._tmpfsArgs, ["--tmpfs", "/tmp:64m"]);
  assert.deepStrictEqual(new Sandbox({ memoryMb: 512 })._tmpfsArgs, ["--tmpfs", "/tmp:64m"]);
  assert.deepStrictEqual(new Sandbox({ memoryMb: 64 })._tmpfsArgs, ["--tmpfs", "/tmp:32m"]);
  assert.deepStrictEqual(new Sandbox({ memoryMb: 1 })._tmpfsArgs, ["--tmpfs", "/tmp:1m"]);
  assert.deepStrictEqual(new Sandbox({ memoryMb: null })._tmpfsArgs, ["--tmpfs", "/tmp:64m"]);
  // The hardening bundle: 0.1.35 gave `untrusted` a read-only /tmp, and a default added by a
  // different layer must not widen that posture in a patch release.
  assert.deepStrictEqual(new Sandbox({ securityProfile: "untrusted" })._tmpfsArgs, []);
  assert.deepStrictEqual(new Sandbox({ securityProfile: "untrusted", tmpfs: { "/tmp": "8m" } })._tmpfsArgs, ["--tmpfs", "/tmp:8m"]);
});

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
  // capSignal refines it, same as the one-shot path: enforced (1) -> oom, not-enforced (2) -> killed
  // (no overclaim), undetermined (0) -> heuristic. A startup marker still wins over the byte.
  assert.strictEqual(capped._kernelDeathFault("", 1)[0], "oom");
  assert.strictEqual(capped._kernelDeathFault("", 2)[0], "killed");
  assert.strictEqual(capped._kernelDeathFault("", 0)[0], "oom");
  assert.strictEqual(capped._kernelDeathFault(marker, 2)[0], "startup_failed");
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

test("a missing interpreter is a typed fault naming the binary and the image", { skip: !KERN_OK && "kern not installed" }, async () => {
  // `language: "node"` on the default image is the case a model hits: the enum advertises three
  // languages and `python:3.12-slim` carries two.
  //
  // Before this, the classifier said `startup_failed` and the caller ERASED it, because "box started
  // + a kern: marker" is its signal that a workload forged the marker. kern signals started BEFORE it
  // execs, so an ENOENT on `execve` lands in exactly that hole and arrived as a bare exit 127 with
  // `fault === null`: indistinguishable from the user's own code failing.
  const r = await runCode("console.log(1)", { language: "node", image: "python:3.12-slim" });
  assert.strictEqual(r.exitCode, 127);
  assert.ok(r.fault, "a missing interpreter must not arrive as an ordinary non-zero exit");
  assert.strictEqual(r.fault.type, "exec_failed");
  assert.match(r.fault.message, /node/);
  assert.match(r.fault.message, /python:3\.12-slim/);
  assert.match(r.fault.message, /No such file or directory/);
  assert.strictEqual(r.success, false);
});

test("command-not-found inside the user's own script is not a fault", { skip: !KERN_OK && "kern not installed" }, async () => {
  // The control for the test above, and the reason the recogniser matches kern's WORDING rather than
  // exit 127: a shell returning 127 for a command the USER misspelled is the user's failure, and
  // labelling it `exec_failed` would blame the image for the script's own bug.
  const r = await runCode("nosuchcommandanywhere", { language: "bash", image: "python:3.12-slim" });
  assert.strictEqual(r.exitCode, 127);
  assert.strictEqual(r.fault, null, "a shell's own command-not-found must stay an ordinary result");
});

test("an interpreter the image does have is untouched", { skip: !KERN_OK && "kern not installed" }, async () => {
  const r = await runCode("print(1)", { language: "python", image: "python:3.12-slim" });
  assert.strictEqual(r.fault, null);
  assert.strictEqual(r.exitCode, 0);
  assert.strictEqual(r.success, true);
});

test("exit 126 says permission, not absence", { skip: !KERN_OK && "kern not installed" }, async () => {
  // EACCES at `execve` is the same third state as ENOENT with a different exit code. The classifier
  // catches it because it keys on kern's WORDING rather than on 127, and the message must not blame
  // the image for a file that is present and merely not executable.
  const os = require("node:os");
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-126-"));
  const p = path.join(ws, "noexec.sh");
  fs.writeFileSync(p, "#!/bin/sh\necho hi\n", { mode: 0o644 });
  const box = new Sandbox({ image: "python:3.12-slim", workspace: ws });
  await box.open();
  try {
    const r = await box.run(["/workspace/noexec.sh"]);
    assert.strictEqual(r.exitCode, 126);
    assert.ok(r.fault && r.fault.type === "exec_failed");
    assert.match(r.fault.message, /Permission denied/);
    assert.doesNotMatch(r.fault.message, /does not exist/);
  } finally {
    await box.close();
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

// A box that plants a FIFO in the workspace must not be able to hang the host's call, and must not be
// able to make it report an empty file either.
//
// MEASURED BEFORE THE FIX, both halves, because the second is what makes the first one's obvious
// remedy wrong on its own. `open(fifo, O_RDONLY)` with no writer does not return: the box decides how
// long `readFile` takes, with no timeout to interrupt it. Adding O_NONBLOCK alone turns that into a
// read of zero bytes, so `readFile` answered an empty Buffer and the caller read an empty file where
// a pipe had been planted: the stall became a silent lie, which is worse than the stall.
test("a FIFO the box planted cannot stall or fake a read", exec, async () => {
  await withSandbox(async (s) => {
    await s.runCode("import os; os.mkfifo('/workspace/pipe.bin')");
    const started = Date.now();
    await assert.rejects(() => s.readFile("pipe.bin"), /not a regular file/);
    assert.ok(Date.now() - started < 5000, "readFile waited on a writer-less FIFO");
    // The control: refusing everything would satisfy the assertion above just as well.
    await s.writeFile("real.txt", "still works");
    assert.strictEqual((await s.readFile("real.txt")).toString(), "still works");
  });
});

// The write side, which is the worse of the two: `open(fifo, O_WRONLY)` blocks until a READER appears,
// so a box that plants a FIFO where the caller is about to write parks the host there indefinitely.
test("a FIFO the box planted cannot stall a write either", exec, async () => {
  await withSandbox(async (s) => {
    await s.runCode("import os; os.mkfifo('/workspace/target.txt')");
    const started = Date.now();
    await assert.rejects(() => s.writeFile("target.txt", "payload"));
    assert.ok(Date.now() - started < 5000, "writeFile waited on a reader-less FIFO");
  });
});

// -- prewarm: the fresh-box guarantee at zero marginal cost -------------------------------------------
//
// Every test below is a GATE on the claim that the prewarmed path is observationally identical to the
// cold one, not a benchmark. A fast path that quietly reported different files, a different exit status
// or a different posture would be a behaviour change wearing a speed-up's clothes.

/** Wait until the pool has a box ready, so a test measures the warm path and not a pool miss. */
async function poolReady(s, ms = 90000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (s._pool && s._pool._ready.length) return true;
    await new Promise((r) => setTimeout(r, 20));
  }
  return false;
}

/** Run `fn` on a cold session and a prewarmed one and return both answers, for direct comparison. */
async function coldAndWarm(fn, opts = {}) {
  const out = [];
  for (const prewarm of [0, 1]) {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-pw-"));
    const s = new Sandbox({ prewarm, workspace: ws, timeoutS: 60, ...opts });
    await s.open();
    try {
      if (prewarm) assert.ok(await poolReady(s), "the pool never became ready");
      out.push(await fn(s, ws));
    } finally {
      await s.close();
    }
  }
  return out;
}

test("prewarm is off by default and holds no boxes", () => {
  const s = new Sandbox({});
  assert.strictEqual(s.prewarm, 0);
  assert.strictEqual(s._pool, null);
});

test("the prewarm key is pure and folds in every posture option", () => {
  const s = new Sandbox({ env: { A: "1" } });
  s._ws = ""; // no workspace: the live path skips the env file, the dry path must still key on it
  // WarmPool is not exported, so drive the key through the very argv builder it uses: that is the
  // point of the check, since the key exists to be whatever the real argv is.
  const key = (network) => s._baseArgv("", { network, timeoutS: 0, dry: true }).join("\0");
  assert.strictEqual(key(false), key(false), "the key must be stable, or every claim misses");
  assert.ok(key(false).includes("A=1"), "the env is part of the posture and must be in the key");
  assert.notStrictEqual(key(true), key(false), "network must change the key");
  const before = key(false);
  s._mountArgs = ["-v", "/tmp:/mnt:ro"];
  assert.notStrictEqual(key(false), before, "a mount must change the key");
});

test("a dry argv writes no env file", () => {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-dry-"));
  const s = new Sandbox({ env: { K: "V" } });
  s._ws = ws;
  s._baseArgv("", { network: false, timeoutS: 0, dry: true });
  assert.deepStrictEqual(fs.readdirSync(ws), [], "a dry argv must leave the workspace untouched");
  s._baseArgv("realbox", { network: false, timeoutS: 0 });
  assert.strictEqual(fs.readdirSync(ws).length, 1, "the live path still writes exactly one env file");
});

test("prewarm serves a cell identical to the cold one", exec, async () => {
  const [cold, warm] = await coldAndWarm(async (s) => {
    const r = await s.runCode("open('/workspace/made.txt','w').write('x')\n21*2");
    return JSON.stringify([
      r.stdout, r.exitCode, r.results.map((x) => x.text),
      r.files.map((f) => [f.path, f.change]).sort(), r.truncated, r.fault,
    ]);
  });
  assert.strictEqual(cold, warm);
  assert.ok(cold.includes("made.txt"), "the file diff must survive the fast path");
});

test("a prewarmed box serves exactly one cell", exec, async () => {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-pw1-"));
  const s = new Sandbox({ prewarm: 1, workspace: ws, timeoutS: 60 });
  await s.open();
  try {
    assert.ok(await poolReady(s));
    await s.runCode("SENTINEL = 'leaked'");
    const r = await s.runCode("print('SENTINEL' in dir())");
    assert.strictEqual(r.stdout.trim(), "False", "in-memory state must NOT survive a prewarmed call");
    assert.ok(await poolReady(s));
    const box = s._pool._ready.pop();
    await box.runCell("print(1)", { deadlineS: 30, before: null });
    await assert.rejects(() => box.runCell("print(2)", { deadlineS: 30, before: null }), SandboxError);
  } finally {
    await s.close();
  }
});

test("prewarm faults carry this binding's own exit-status convention", exec, async () => {
  // Node's cold path maps a signal to 128 + signum; Python's maps it to a negative. Each binding has to
  // match ITS OWN cold path, or the same failure looks like two different ones.
  const [cold, warm] = await coldAndWarm(async (s) => {
    const r = await s.runCode("import time; time.sleep(30)", { timeoutS: 2 });
    return JSON.stringify([r.fault && r.fault.type, r.exitCode]);
  });
  assert.ok(cold.includes("timeout"), cold);
  assert.strictEqual(cold, warm);
});

test("a streaming call refuses the pool and really streams", exec, async () => {
  const chunks = [];
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-pws-"));
  const s = new Sandbox({ prewarm: 1, workspace: ws, timeoutS: 60, onStdout: (b) => chunks.push(b) });
  await s.open();
  try {
    assert.ok(await poolReady(s));
    const r = await s.runCode("print('streamed')");
    assert.strictEqual(r.exitCode, 0);
    assert.ok(Buffer.concat(chunks).toString().includes("streamed"), "it must stream for real");
    assert.strictEqual(s._pool._ready.length, 1, "a streaming call must not consume a warm box");
  } finally {
    await s.close();
  }
});

test("prewarmed boxes are torn down with the session", exec, async () => {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-pwt-"));
  const s = new Sandbox({ prewarm: 2, workspace: ws, timeoutS: 60 });
  await s.open();
  assert.ok(await poolReady(s));
  const names = s._pool._ready.map((b) => b._name);
  assert.ok(names.length > 0);
  await s.close();
  await new Promise((r) => setTimeout(r, 1500));
  const listed = require("node:child_process")
    .spawnSync(s._kern, ["ps", "-q"], { encoding: "utf8", timeout: 30000 })
    .stdout.split(/\s+/);
  assert.deepStrictEqual(names.filter((n) => listed.includes(n)), [], "a warm box outlived its session");
  assert.deepStrictEqual(
    fs.readdirSync(ws).filter((f) => f.startsWith(".kern-env")), [],
    "a warm box left its private env file behind",
  );
});

test("the prewarm key covers the kern environment, not only the argv", () => {
  // kern reads KERN_* from ITS OWN environment when it builds a box, so the argv is not the whole
  // posture. Before this, setting KERN_SECCOMP=denylist after the pool had filled left the key
  // unchanged and the stale box - built under the PREVIOUS filter - was handed to the call.
  const s = new Sandbox({});
  s._ws = "";
  const key = () => {
    const argv = s._baseArgv("", { network: false, timeoutS: 0, dry: true }).join("\0");
    const env = Object.entries(process.env)
      .filter(([k]) => k.startsWith("KERN_"))
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${k}=${v}`)
      .join("\0");
    return `${argv}\0\0${env}`;
  };
  const before = key();
  const prev = process.env.KERN_SECCOMP;
  process.env.KERN_SECCOMP = "denylist";
  try {
    assert.notStrictEqual(key(), before, "a KERN_* change must invalidate warm boxes");
    // And a name we have never heard of, which is the point of not keeping a list.
    process.env.KERN_SOMETHING_NOBODY_LISTED = "1";
    assert.notStrictEqual(key(), before);
  } finally {
    delete process.env.KERN_SOMETHING_NOBODY_LISTED;
    if (prev === undefined) delete process.env.KERN_SECCOMP;
    else process.env.KERN_SECCOMP = prev;
  }
  assert.strictEqual(key(), before, "restoring the environment must restore the key");
});

test("every python path sees the same sys.path and the image packages", exec, async () => {
  // The one the whole prewarm parity suite missed, because every cell in it was stdlib. A prewarmed
  // box ran the driver as `python3 -S -c`, and -S skips `site`, which is what puts site-packages on
  // sys.path: `import pip` succeeded cold and raised ModuleNotFoundError warm. The shipped kernel()
  // had it too, since before this branch. sys.path equality is the assertion rather than "the import
  // works", because the import is a property of one image and the path is the mechanism.
  const cell =
    "import sys, json\n" +
    "try:\n" +
    "    import pip; p = 'OK'\n" +
    "except Exception as e:\n" +
    "    p = type(e).__name__\n" +
    "print(json.dumps({'path': sys.path, 'pip': p}))\n";
  const seen = {};
  for (const prewarm of [0, 1]) {
    const s = new Sandbox({
      prewarm, workspace: fs.mkdtempSync(path.join(os.tmpdir(), "kern-sp-")), timeoutS: 90,
    });
    await s.open();
    try {
      if (prewarm) assert.ok(await poolReady(s));
      seen[prewarm ? "warm" : "cold"] = JSON.parse((await s.runCode(cell)).stdout);
    } finally {
      await s.close();
    }
  }
  const s = new Sandbox({
    workspace: fs.mkdtempSync(path.join(os.tmpdir(), "kern-spk-")), timeoutS: 90,
  });
  await s.open();
  const k = await s.kernel();
  try {
    seen.kernel = JSON.parse((await k.runCode(cell)).stdout);
  } finally {
    await k.close();
    await s.close();
  }
  assert.deepStrictEqual(seen.warm.path, seen.cold.path, "a prewarmed cell imports from a different path");
  assert.deepStrictEqual(seen.kernel.path, seen.cold.path, "a kernel cell imports from a different path");
  assert.ok(
    seen.cold.path.some((p) => p.includes("site-packages")),
    "positive control: without site-packages anywhere this cannot fail for the right reason",
  );
  assert.strictEqual(seen.cold.pip, seen.warm.pip);
  assert.strictEqual(seen.cold.pip, seen.kernel.pip);
});

test("a start that throws still releases its pool slot", exec, async () => {
  // `_startOne` reserves a slot in `refill` and used to release it AFTER the awaits, outside any
  // `finally`. `_key()` calls the real argv builder, which throws on an env value containing a
  // newline, so a throw there left the slot reserved forever: `want` went negative and the pool never
  // refilled again for the rest of the session, silently, because refill's own `.catch(() => {})` ate
  // the reason. Same shape as the Python binding's dead-worker case: a permanent stop, no signal.
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-slot-"));
  const s = new Sandbox({ prewarm: 1, workspace: ws, timeoutS: 60 });
  await s.open();
  try {
    assert.ok(await poolReady(s));
    const pool = s._pool;
    pool._ready.pop().kill();
    const good = pool._key.bind(pool);
    pool._key = () => {
      throw new Error("argv builder refused this posture");
    };
    pool.refill({ network: false, deadlineS: 30 });
    // Let the rejected start settle before reading the counter.
    for (let i = 0; i < 100 && pool._starting !== 0; i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.strictEqual(pool._starting, 0, "a throwing start must release the slot it reserved");
    pool._key = good;
    pool.refill({ network: false, deadlineS: 30 });
    assert.ok(await poolReady(s), "the pool must refill once the posture is buildable again");
  } finally {
    await s.close();
  }
});

// The DEFAULT, asserted on the constructor, because the whole point of the change is which value a
// caller who passes nothing gets.
test("depsReadonly defaults to true, and is still an opt-out", () => {
  assert.strictEqual(new Sandbox({}).depsReadonly, true);
  assert.strictEqual(new Sandbox({ depsReadonly: false }).depsReadonly, false);
});

// A cell rewrites a dependency's BYTECODE, leaves the source alone, and the next cell in the same
// session imports it. On the old default that ran the attacker's code.
//
// WHY THE BYTECODE: `.pyc` files in this image are timestamp-based, so re-pasting the legitimate
// 16-byte header makes the file look current and CPython never consults the `.py`. It is invisible to
// the surfaces a caller would audit: the poisoning call reports no files and `listFiles()` never shows
// a `__pycache__`.
//
// NOT a sandbox escape: both cells are the untrusted workload. What it defends is the in-session
// assumption that `import six` in call N+1 runs the `six` call N could see. The last assertion is the
// CONTROL, since refusing every write would satisfy the other two.
test("the default closes the .pyc poisoning vector", exec, async () => {
  const poison = [
    "import six, marshal, importlib.util",
    "pyc = importlib.util.cache_from_source(six.__file__)",
    "try:",
    "    d = open(pyc, 'rb').read()",
    "    c = compile(\"open('/workspace/PWNED','w').write('x')\", '<p>', 'exec')",
    "    open(pyc, 'wb').write(d[:16] + marshal.dumps(c))",
    "    print('POISONED')",
    "except OSError as e:",
    "    print('REFUSED', e.errno)",
  ].join("\n");
  await withSandbox({ setup: "pip install six", timeoutS: 120 }, async (s) => {
    const first = await s.runCode(poison);
    const victim = await s.runCode("import six, os; print(os.path.exists('/workspace/PWNED'))");
    const control = await s.runCode("import six; print(six.__name__)");
    assert.match(first.stdout, /REFUSED/, "the write into .deps was allowed");
    assert.strictEqual(victim.stdout.trim(), "False", "the next cell ran the planted bytecode");
    assert.strictEqual(control.stdout.trim(), "six", "importing a dependency must still work");
  });
});

// The read-only default has a cost nobody would look for: CPython cannot write `__pycache__` into a
// read-only `.deps`, tolerates it silently, and recompiles on every import for the life of the
// session (250 ms/call against 290, measured on requests). The setup box compiles before the mount
// closes; `--no-compile` is the discriminant, being the ordinary way to reach a bytecode-less `.deps`.
test("the setup leaves bytecode behind, so the default costs nothing", exec, async () => {
  await withSandbox({ setup: "pip install --no-compile six", timeoutS: 120 }, async (s) => {
    const n = await s.runCode(
      "import glob; print(len(glob.glob('/workspace/.deps/**/__pycache__/*.pyc', recursive=True)))",
    );
    assert.ok(Number(n.stdout.trim()) > 0, "the setup box left no bytecode: every call now recompiles");
  });
});

// kern and the workload share ONE stderr, so the raw field carries the launcher's own voice. An
// external audit found kern's `note:` lines inside a LangChain tool result, spending a model's
// context on the runtime's housekeeping where they can be misread as the program's own errors.
// `codeStderr` and `runtimeNotes` are the two halves.
//
// The CASES are byte-for-byte the Python binding's, because this pair is exactly where the two
// bindings drifted last time: the timeout exit code agreed on the fault and disagreed on the number.
// A first cut of this very fix had the same shape, Python dropping a trailing newline Node kept.
test("kern's own notes are separated from the code's stderr, identically to Python", () => {
  const cases = [
    ["kern: note: x\nreale\n", "reale\n", ["kern: note: x"]],
    ["a\nkern: warning: w\nb", "a\nb", ["kern: warning: w"]],
    ["", "", []],
    ["kern: note: solo\n", "", ["kern: note: solo"]],
    ["nessuna newline finale", "nessuna newline finale", []],
    ["  kern: note: rientrata\nx", "x", ["  kern: note: rientrata"]],
  ];
  for (const [raw, code, notes] of cases) {
    const r = new kern.ExecutionResult({ stdout: "", stderr: raw, exitCode: 0, durationMs: 0 });
    assert.strictEqual(r.codeStderr, code, `codeStderr of ${JSON.stringify(raw)}`);
    assert.deepStrictEqual(r.runtimeNotes, notes, `runtimeNotes of ${JSON.stringify(raw)}`);
    // Every line lands in exactly one half: nothing invented, nothing lost.
    assert.strictEqual(
      r.codeStderr.split("\n").length + r.runtimeNotes.length,
      raw.split("\n").length,
      `the two halves must partition ${JSON.stringify(raw)}`,
    );
    // The operator's field keeps every byte: this is a second view, not a replacement.
    assert.strictEqual(r.stderr, raw);
  }
});

// A workload CAN print one of kern's prefixes. The consequence is its line moving to `runtimeNotes`,
// the harmless direction: the trick takes text OUT of what a model reads and cannot put text in.
test("a forging workload can only remove its own line from codeStderr", () => {
  const r = new kern.ExecutionResult({
    stdout: "", stderr: "kern: note: forged by the box\n", exitCode: 0, durationMs: 0,
  });
  assert.strictEqual(r.codeStderr, "");
  assert.match(r.runtimeNotes[0], /forged/);
});
