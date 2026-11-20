"use strict";
// Labels and `Sandbox.list`, `getMetrics`, `setTimeout`, `watchDir`, egress deny and ranges, ports and
// `getHost`, `startCmd` and `readyCmd`, `pty`, `fork`. The same cases as the Python binding's
// tests/test_e2b_surface.py. The UNIT tests need no kern; the INTEGRATION ones start real boxes and need a
// kern with `kern update --timeout`, `ends_at`, `--egress-deny`, `KERN_TTY_SIZE_FILE` and `__watch-dir`
// (this tree's).

const { test } = require("node:test");
const assert = require("node:assert");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");

const { FAKE_KERN, kernBin } = require("./_fake_kern.js");

const kern = require("../index.js");
const { Sandbox, SandboxError } = kern;

const KERN = kernBin();
// A kern from before these features (the pre-push gate keeps PATH, where an installed release may be)
// is skipped by name rather than failed: `__watch-dir` arrived with the rest of them.
const KERN_TOO_OLD =
  KERN &&
  /unknown command/.test(
    String(spawnSync(KERN, ["__watch-dir", "/", "kern-probe-none", "0"], { encoding: "utf8" }).stderr),
  );
const integration = {
  skip: (!KERN && "no runnable kern (set KERN_BIN)") || (KERN_TOO_OLD && `${KERN} predates __watch-dir (set KERN_BIN)`),
};

/** A Sandbox built against the fake kern, the real `$KERN_BIN` put back afterwards. */
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

const uid = () => crypto.randomBytes(4).toString("hex");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function tmpdir(tag) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), `kern-e2b-${tag}-`));
  fs.chmodSync(d, 0o700);
  return d;
}

async function rejectsWith(promiseOrFn, re) {
  await assert.rejects(
    typeof promiseOrFn === "function" ? promiseOrFn() : promiseOrFn,
    (e) => e instanceof SandboxError && re.test(e.message),
  );
}

function throwsWith(fn, re) {
  assert.throws(fn, (e) => e instanceof SandboxError && re.test(e.message));
}

/** A persist sandbox with a label naming the test run, opened; `fn(sb)`, then destroyed and closed. */
async function withPersist(fn, extra = {}) {
  const name = `e2b${uid()}`;
  const ws = tmpdir("ws");
  const sb = new Sandbox({ persist: true, name, workspace: ws, labels: { suite: name }, ...extra });
  await sb.open();
  try {
    return await fn(sb);
  } finally {
    await sb.destroy();
    await sb.close();
    fs.rmSync(ws, { recursive: true, force: true });
  }
}

async function withOneShot(fn, opts = {}) {
  const sb = new Sandbox(opts);
  await sb.open();
  try {
    return await fn(sb);
  } finally {
    await sb.close();
  }
}

// -- UNIT ------------------------------------------------------------------------------------------------

test("labels become --label flags and bad ones are refused by name", () => {
  const s = cfg({ labels: { run: "r-42", "team/x": "a b,c=d" } });
  assert.deepStrictEqual(s._labelArgs, ["--label", "run=r-42", "--label", "team/x=a b,c=d"]);
  const many = {};
  for (let i = 0; i < 65; i += 1) many[`k${i}`] = "v";
  for (const [bad, says] of [
    [{ "kern.sbx.cfg": "x" }, /kern's own/],
    [{ "-x": "y" }, /letters, digits/],
    [{ "a b": "y" }, /letters, digits/],
    [{ k: "two\nlines" }, /one line/],
    [{ k: 3 }, /must be a string/],
    [["k=v"], /mapping/],
    [many, /at most 64/],
  ])
    throwsWith(() => cfg({ labels: bad }), says);
});

test("labels are not posture", async () => {
  // Two processes meeting on one persist sandbox may label it differently and must still meet: labels
  // stay out of every dry argv (the resident fingerprint and the prewarm key).
  const mats = new Set();
  for (const s of [cfg({ labels: { run: "1" } }), cfg({ labels: { run: "2" } }), cfg()])
    mats.add(await s._postureMaterial({ network: false, timeoutS: 60 }));
  assert.strictEqual(mats.size, 1);
  const a = cfg({ labels: { run: "1" } });
  assert.ok(!a._baseArgv("", { network: false, timeoutS: 60, dry: true }).includes("--label"));
  assert.ok(a._baseArgv("x", { network: false, timeoutS: 60 }).includes("run=1"), "a box that runs carries them");
});

test("setTimeout is refused without persist before any box", async () => {
  await rejectsWith(cfg().setTimeout(5), /persist: true/);
});

test("egress entries take domains, ranges and *, and deny alone means *", () => {
  const s = cfg({
    egressAllow: ["pypi.org", "10.1.2.9/24", "2001:db8::1", "*"],
    egressDeny: ["bad.io", "10.9.0.0/16"],
  });
  let argv = s._baseArgv("x", { network: false, timeoutS: 10, dry: true });
  assert.strictEqual(argv[argv.indexOf("--egress-allow") + 1], "pypi.org,10.1.2.0/24,2001:db8::1/128,*");
  assert.strictEqual(argv[argv.indexOf("--egress-deny") + 1], "bad.io,10.9.0.0/16");
  argv = cfg({ egressDeny: ["github.com"] })._baseArgv("x", { network: false, timeoutS: 10, dry: true });
  assert.strictEqual(argv[argv.indexOf("--egress-allow") + 1], "*");
  for (const [bad, says] of [
    [{ egressDeny: ["*"] }, /denies everything/],
    [{ egressAllow: ["http://x.com"] }, /invalid egressAllow/],
    [{ egressDeny: ["a b"] }, /invalid egressDeny/],
    [{ egressAllow: "pypi.org" }, /array of entries/],
    [{ egressDeny: ["x.com"], network: true }, /mutually exclusive/],
  ])
    throwsWith(() => cfg(bad), says);
});

test("egress addresses are written as Python's ipaddress writes them", () => {
  // Vectors measured with Python 3.12's `str(ipaddress.ip_network(x, strict=False))`.
  for (const [given, want] of [
    ["::ffff:1.2.3.4", "::ffff:102:304/128"],
    ["2001:DB8:0:0:1:0:0:1", "2001:db8::1:0:0:1/128"],
    ["10.0.0.0/255.0.0.0", "10.0.0.0/8"],
    ["10.1.2.3/0.0.0.255", "10.1.2.0/24"],
    ["::", "::/128"],
    ["fe80::1/10", "fe80::/10"],
    ["0.0.0.0/0", "0.0.0.0/0"],
    ["1:0:0:2:0:0:0:3", "1:0:0:2::3/128"],
    ["[2001:db8::1]", "2001:db8::1/128"],
    ["1.2.3.4", "1.2.3.4/32"],
  ])
    assert.strictEqual(kern._validateEgressEntry(given, true), want, given);
  for (const bad of ["010.1.1.1", "1.2.3.4/33", "::1::2", "1:2:3:4:5:6:7:8:9", "1.2.3", "g::1"])
    throwsWith(() => kern._validateEgressEntry(bad, true), /invalid egressAllow/);
});

test("ports, startCmd and readyCmd are validated and ports are loopback only", async () => {
  const base = { persist: true, name: "p", workspace: "/tmp", ports: [8000, 9000], readyCmd: "ok" };
  const s = cfg({ ...base, startCmd: "srv" });
  const argv = s._baseArgv("x", { network: false, timeoutS: 10, dry: true, resident: true });
  assert.strictEqual(argv.filter((a) => a === "-p").length, 2);
  assert.ok(argv.includes("127.0.0.1::8000") && argv.includes("127.0.0.1::9000"));
  assert.ok(!s._baseArgv("x", { network: false, timeoutS: 10, dry: true }).includes("-p"), "a call box publishes nothing");
  const a = await s._postureMaterial({ network: false, timeoutS: 10, resident: true });
  const b = await cfg({ ...base, startCmd: "other" })._postureMaterial({ network: false, timeoutS: 10, resident: true });
  assert.notStrictEqual(a, b, "startCmd is posture");
  for (const [bad, says] of [
    [{ ports: [0] }, /not a port/],
    [{ ports: [80, 80] }, /twice/],
    [{ ports: "8000" }, /array of box ports/],
    [{ startCmd: "x" }, /needs persist: true/],
    [{ readyCmd: "x" }, /needs persist: true/],
    [{ persist: true, name: "p", workspace: "/tmp", readyTimeoutS: 0 }, /positive/],
  ])
    throwsWith(() => cfg(bad), says);
});

test("the resident box and its fingerprint never carry the bytecode cache", () => {
  const s = cfg({ persist: true, name: "p", workspace: "/tmp" });
  s._pycDir = os.tmpdir(); // any directory with content stands in for an adopted cache
  const resident = s._baseArgv("x", { network: false, timeoutS: 10, dry: true, resident: true });
  assert.ok(!resident.join(" ").includes(kern._PYC_MOUNT), resident.join(" "));
  const call = s._baseArgv("x", { network: false, timeoutS: 10, dry: true });
  assert.ok(call.join(" ").includes(kern._PYC_MOUNT), "a call box still mounts it");
});

test("pty arguments are checked", async () => {
  const s = cfg();
  s._entered = true;
  await rejectsWith(s.pty(null, { onData: null }), /onData/);
  await rejectsWith(s.pty("bash", { onData: () => {} }), /argv array/);
  await rejectsWith(s.pty(["sh"], { onData: () => {}, cols: 0 }), /cols must be/);
});

test("fork needs a count from 1 to 64", async () => {
  const s = cfg();
  s._entered = true;
  for (const bad of [0, 65, true, "2", 1.5]) await rejectsWith(s.fork(bad), /from 1 to 64/);
});

// -- INTEGRATION -----------------------------------------------------------------------------------------

test("a resident box carries the fingerprint this process computes", integration, async () => {
  // MEASURED on 0.2.53: the box was made with one fingerprint and the same Sandbox, after open() decided
  // the bytecode cache, computed another.
  await withPersist(async (sb) => {
    await sb.runCode("print(1)");
    const row = await sb._residentLookup();
    assert.strictEqual((row.labels || {})["kern.sbx.cfg"], await sb._residentFingerprint());
  });
});

test("list finds a sandbox by its labels and only while it runs", integration, async () => {
  await withPersist(async (sb) => {
    await sb.runCode("print(1)");
    const label = { ...sb.labels };
    const found = await Sandbox.list(label);
    assert.deepStrictEqual(found.map((i) => [i.name, i.kind]), [[sb.name, "persist"]]);
    assert.deepStrictEqual(found[0].labels, label);
    assert.ok(found[0].pid > 0 && found[0].started > 0);
    assert.deepStrictEqual(await Sandbox.list({ suite: "no-such-label" }), []);
    await sb.destroy();
    assert.deepStrictEqual(await Sandbox.list(label), []);
  });
});

test("setTimeout moves the resident box deadline both ways", integration, async () => {
  await withPersist(async (sb) => {
    await sb.runCode("print(1)");
    await sb.setTimeout(600);
    const left = (await sb.getMetrics({ intervalS: 0 })).endsAt - Math.floor(Date.now() / 1000);
    assert.ok(left >= 590 && left <= 601, String(left));
    await sb.setTimeout(2);
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline && (await sb._residentLookup()) !== null) await sleep(200);
    assert.strictEqual(await sb._residentLookup(), null, "setTimeout(2) did not end the box");
    // The next call recreates it, as after any expiry.
    const r = await sb.runCode("print('again')");
    assert.strictEqual(r.stdout.trim(), "again", r.stderr);
  });
});

test("setTimeout(0) removes the deadline", integration, async () => {
  await withPersist(async (sb) => {
    await sb.runCode("print(1)");
    await sb.setTimeout(0);
    assert.strictEqual((await sb.getMetrics({ intervalS: 0 })).endsAt, null);
  });
});

test("getMetrics reads the box and the workspace", integration, async () => {
  await withPersist(async (sb) => {
    await sb.runCode("open('blob', 'wb').write(b'x' * 300_000)");
    const m = await sb.getMetrics({ intervalS: 0.1 });
    assert.ok(m.memoryBytes > 0, JSON.stringify(m));
    assert.ok([512 * 2 ** 20, null].includes(m.memoryLimitBytes), JSON.stringify(m));
    assert.ok(m.pids >= 1, JSON.stringify(m));
    assert.ok(m.cpuSeconds !== null && m.cpuPercent !== null, JSON.stringify(m));
    assert.ok(m.diskBytes >= 300_000, JSON.stringify(m));
  });
});

test("getMetrics of a one-shot sandbox has no box fields", integration, async () => {
  await withOneShot(async (sb) => {
    const m = await sb.getMetrics({ intervalS: 0 });
    assert.deepStrictEqual([m.memoryBytes, m.cpuSeconds, m.pids, m.endsAt], [null, null, null, null]);
  });
});

test("a kernel reports its own box", integration, async () => {
  await withOneShot(async (sb) => {
    const k = await sb.kernel();
    try {
      await k.runCode("x = bytearray(20_000_000)");
      const m = await k.getMetrics({ intervalS: 0 });
      assert.ok(m.memoryBytes >= 20_000_000, JSON.stringify(m));
    } finally {
      await k.close();
    }
  });
});

test("watchDir reports what the box and the host do", integration, async () => {
  await withOneShot(async (sb) => {
    await sb.writeFile("data/keep.txt", "x");
    const got = [];
    const w = await sb.watchDir("data", (e) => got.push(e));
    try {
      const r = await sb.runCode(
        "import os\n" +
          "open('data/a.txt','w').write('1')\n" +
          "os.rename('data/a.txt','data/b.txt')\n" +
          "os.chmod('data/b.txt', 0o600)\n" +
          "os.makedirs('data/sub/deep')\n" +
          "open('data/sub/deep/c.txt','w').write('2')\n" +
          "os.remove('data/keep.txt')\n",
      );
      assert.strictEqual(r.exitCode, 0, r.stderr);
      await sb.writeFile("data/host.txt", "h");
      await sleep(500);
    } finally {
      await w.stop();
    }
    const seen = new Set(got.map((e) => JSON.stringify([e.type, e.path, e.oldPath])));
    for (const want of [
      ["create", "data/a.txt", null],
      ["write", "data/a.txt", null],
      ["rename", "data/b.txt", "data/a.txt"],
      ["chmod", "data/b.txt", null],
      ["create", "data/sub", null],
      ["create", "data/sub/deep/c.txt", null],
      ["remove", "data/keep.txt", null],
      ["create", "data/host.txt", null],
    ])
      assert.ok(seen.has(JSON.stringify(want)), `${JSON.stringify(want)} not in ${[...seen].sort().join(" ")}`);
  });
});

test("watchDir never follows a symlink out of the workspace", integration, async () => {
  const outside = tmpdir("outside");
  try {
    await withOneShot(async (sb) => {
      fs.symlinkSync(outside, path.join(sb._ws, "link"));
      await rejectsWith(sb.watchDir("link", () => {}), /not a directory in the workspace/);
      await rejectsWith(() => sb.watchDir("../x", () => {}), /escapes the workspace/);
      // A directory under the watch swapped for a link to the outside is not followed either.
      await sb.writeFile("d/x", "1");
      const got = [];
      const w = await sb.watchDir("", (e) => got.push(e));
      try {
        fs.rmSync(path.join(sb._ws, "d"), { recursive: true });
        fs.symlinkSync(outside, path.join(sb._ws, "d"));
        await sleep(200);
        fs.writeFileSync(path.join(outside, "secret.txt"), "host");
        await sleep(400);
      } finally {
        await w.stop();
      }
      assert.ok(!got.some((e) => e.path.includes("secret")), JSON.stringify(got));
      assert.ok(got.some((e) => e.type === "remove" && e.path === "d/x"), JSON.stringify(got));
    });
  } finally {
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

const EGRESS_PROBE = `
import urllib.request, ssl
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
for u in ["https://example.com", "https://github.com"]:
    try:
        urllib.request.urlopen(u, timeout=10, context=ctx).read(16); print(u, "OPEN")
    except Exception as e:
        print(u, "SHUT")
`;

test(
  "egressDeny refuses what the allowlist would open",
  { skip: integration.skip || (process.env.KERN_TEST_NO_INTERNET === "1" && "no internet here") },
  async () => {
    const out = await withOneShot(async (sb) => (await sb.runCode(EGRESS_PROBE)).stdout, { egressDeny: ["github.com"] });
    assert.ok(out.includes("https://example.com OPEN"), out);
    assert.ok(out.includes("https://github.com SHUT"), out);
  },
);

function httpGet(hostPort, urlPath = "/") {
  return new Promise((resolve, reject) => {
    const req = http.get(`http://${hostPort}${urlPath}`, { timeout: 10000 }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("timeout")));
  });
}

test("a started server is waited for and reached through getHost", integration, async () => {
  await withPersist(
    async (sb) => {
      const host = await sb.getHost(8000);
      assert.ok(host.startsWith("127.0.0.1:"), host);
      assert.strictEqual((await httpGet(host, "/index.html")).body, "served\n");
      await rejectsWith(sb.getHost(9000), /not published/);
    },
    {
      ports: [8000],
      startCmd: "cd /workspace && echo served > index.html && python3 -m http.server 8000",
      readyCmd: "python3 -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000')\"",
    },
  );
});

test("a box that never gets ready is refused by name", integration, async () => {
  const ws = tmpdir("ws");
  const sb = new Sandbox({ persist: true, name: `nr${uid()}`, workspace: ws, readyCmd: "false", readyTimeoutS: 2 });
  try {
    await rejectsWith(sb.open(), /was not ready within 2/);
  } finally {
    await sb.destroy();
    await sb.close();
    fs.rmSync(ws, { recursive: true, force: true });
  }
});

test("a kernel publishes its ports", integration, async () => {
  await withOneShot(
    async (sb) => {
      const k = await sb.kernel();
      try {
        await k.runCode(
          "import subprocess; subprocess.Popen(['python3','-m','http.server','7000'], " +
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
        );
        const host = await k.getHost(7000);
        const deadline = Date.now() + 10000;
        for (;;) {
          try {
            assert.strictEqual((await httpGet(host)).status, 200);
            break;
          } catch (e) {
            if (Date.now() > deadline) throw e;
            await sleep(200);
          }
        }
      } finally {
        await k.close();
      }
    },
    { ports: [7000] },
  );
});

/** Size, resize, interrupt and exit a shell in `sb`'s pty; resolve [exit code, screen]. */
async function drivePty(sb) {
  let buf = "";
  const waitFor = async (text, within = 10000) => {
    const end = Date.now() + within;
    while (Date.now() < end) {
      if (buf.includes(text)) return;
      await sleep(50);
    }
    throw new Error(`${JSON.stringify(text)} never appeared: ${JSON.stringify(buf)}`);
  };
  const t = await sb.pty(null, { onData: (b) => (buf += b.toString()), cols: 100, rows: 30 });
  try {
    t.sendInput("stty size; echo mark-$((6*7))\n");
    await waitFor("mark-42");
    t.resize(120, 40);
    await sleep(200);
    t.sendInput("stty size; echo after-resize\n");
    await waitFor("after-resize\r\n");
    t.sendInput("sleep 30\n");
    await sleep(500);
    t.sendInput("\x03");
    t.sendInput("exit 5\n");
    const rc = await t.wait({ timeoutS: 15 });
    return [rc, buf.replace(/\r/g, "")];
  } finally {
    await t.kill();
  }
}

test("a pty in a one-shot sandbox sizes, resizes, interrupts and exits", integration, async () => {
  const [rc, screen] = await withOneShot(drivePty);
  assert.strictEqual(rc, 5, screen);
  assert.ok(screen.includes("30 100") && screen.includes("40 120"), screen);
});

test("a pty in a persist sandbox runs in the resident box", integration, async () => {
  await withPersist(async (sb) => {
    await sb.runCode("open('/tmp/resident-mark','w').write('x')");
    const [rc, screen] = await drivePty(sb);
    assert.strictEqual(rc, 5, screen);
    assert.ok(screen.includes("30 100") && screen.includes("40 120"), screen);
    let got = "";
    const t = await sb.pty(["sh", "-c", "cat /tmp/resident-mark; echo; echo done"], { onData: (b) => (got += b) });
    assert.strictEqual(await t.wait({ timeoutS: 15 }), 0);
    assert.ok(got.includes("x") && got.includes("done"), got);
    assert.strictEqual(t.exitCode, 0);
    assert.throws(() => t.sendInput("late"), /closed/);
  });
});

/** Run `fn` with snapshot/restore opted in, as `fork` requires in this binding. */
async function withSnapshots(fn) {
  const prev = process.env.KERN_SANDBOX_SNAPSHOT;
  process.env.KERN_SANDBOX_SNAPSHOT = "1";
  try {
    return await fn();
  } finally {
    if (prev === undefined) delete process.env.KERN_SANDBOX_SNAPSHOT;
    else process.env.KERN_SANDBOX_SNAPSHOT = prev;
  }
}

test("fork gives copies their own workspace with the files and deps", integration, async () => {
  await withSnapshots(() =>
    withOneShot(async (sb) => {
      await sb.runCode(
        "import os\n" +
          "os.makedirs('d/e', exist_ok=True); open('d/e/a.txt','w').write('orig')\n" +
          "os.makedirs('.deps', exist_ok=True); open('.deps/forkmod.py','w').write('X = 1')\n",
      );
      const copies = await sb.fork(3);
      assert.strictEqual(copies.length, 3);
      const dirs = [];
      for (const [i, c] of copies.entries()) {
        await c.open();
        try {
          dirs.push(c._ws);
          const r = await c.runCode(
            `import forkmod; print(open('d/e/a.txt').read(), forkmod.X); open('d/e/a.txt','w').write('c${i}')`,
          );
          assert.strictEqual(r.stdout.trim(), "orig 1", r.stderr);
        } finally {
          await c.close();
        }
      }
      assert.strictEqual(new Set(dirs).size, 3);
      assert.ok(!dirs.some((d) => fs.existsSync(d)), "a one-shot copy removes its workspace");
      assert.strictEqual((await sb.readFile("d/e/a.txt")).toString(), "orig");
    }),
  );
});

test("a persist fork has its own name and keeps its workspace", integration, async () => {
  await withSnapshots(() =>
    withPersist(async (sb) => {
      await sb.runCode("open('s.txt','w').write('p')");
      const [c] = await sb.fork(1);
      assert.ok(c.name.startsWith(`${sb.name}-fork1-`) && c.workspace !== sb.workspace, c.name);
      await c.open();
      try {
        assert.strictEqual((await c.runCode("print(open('s.txt').read())")).stdout.trim(), "p");
      } finally {
        await c.destroy();
        await c.close();
      }
      assert.ok(fs.statSync(c.workspace).isDirectory());
      fs.rmSync(c.workspace, { recursive: true, force: true });
    }),
  );
});

test("fork is refused without the snapshot opt-in", async () => {
  const prev = process.env.KERN_SANDBOX_SNAPSHOT;
  delete process.env.KERN_SANDBOX_SNAPSHOT;
  try {
    const s = cfg();
    s._entered = true;
    await rejectsWith(s.fork(1), /opt-in/);
  } finally {
    if (prev !== undefined) process.env.KERN_SANDBOX_SNAPSHOT = prev;
  }
});

// -- TRANSCRIPTS -------------------------------------------------------------------------------------

/** `kern sandbox show --json` rows in an isolated world, waited for until `want` arrive. */
async function shownRows(env, want) {
  let rows = [];
  for (let i = 0; i < 100; i++) {
    const r = spawnSync(KERN, ["sandbox", "show", "-n", "50", "--json"], { env, encoding: "utf8" });
    rows = String(r.stdout)
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l));
    if (rows.length >= want) break;
    await sleep(100);
  }
  return rows;
}

test("each call is handed to kern as a transcript, and transcripts:false keeps none", integration, async () => {
  const base = tmpdir("tr");
  const run = path.join(base, "run");
  fs.mkdirSync(run, { mode: 0o700 });
  const keys = ["XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME"];
  const old = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  process.env.XDG_RUNTIME_DIR = run;
  process.env.XDG_CONFIG_HOME = path.join(base, "cfg");
  process.env.XDG_DATA_HOME = path.join(base, "data");
  const env = { ...process.env };
  try {
    await withOneShot(async (sb) => {
      await sb.runCode("print('tr-python')");
      await sb.run(["sh", "-c", "echo tr-run; exit 3"]);
      const k = await sb.kernel();
      try {
        await k.runCode("print('tr-kernel')");
      } finally {
        await k.close();
      }
    });
    await withOneShot(async (sb) => {
      await sb.runCode("print('tr-not-kept')");
    }, { transcripts: false });
    const rows = await shownRows(env, 3);
    const byOut = Object.fromEntries(rows.map((r) => [String(r.stdout).trim(), r]));
    assert.strictEqual(byOut["tr-python"]?.language, "python", JSON.stringify(rows));
    assert.strictEqual(byOut["tr-python"]?.code, "print('tr-python')");
    assert.strictEqual(byOut["tr-run"]?.exit, 3);
    assert.strictEqual(byOut["tr-run"]?.language, "command");
    assert.ok(byOut["tr-kernel"], JSON.stringify(rows));
    assert.ok(!("tr-not-kept" in byOut), "transcripts:false kept a call");
  } finally {
    for (const k of keys) {
      if (old[k] === undefined) delete process.env[k];
      else process.env[k] = old[k];
    }
    fs.rmSync(base, { recursive: true, force: true });
  }
});
