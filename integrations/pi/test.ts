/**
 * Exercise every operation this extension gives pi, against a REAL kern box.
 *
 * Not a unit test of pi: pi's own tools are already tested in pi's repo. What is untested until this
 * runs is the half this file owns, the one that talks to kern and the one that decides which paths
 * are allowed, and both of those can only be wrong against a live box.
 *
 *   node --experimental-strip-types test.ts
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Sandbox, type SandboxOptions } from "kern-sandbox";
import { fatal, ok, report, throws } from "./harness.ts";
import {
	boxOptions,
	detectImageMimeType,
	guestHome,
	globMatches,
	kernBashOps,
	kernEditOps,
	kernFindOps,
	kernGrepOps,
	kernLsOps,
	kernReadOps,
	kernWriteOps,
	refuseOutsideWorkspace,
	detectShell,
	requireScratchSupport,
	scratchFromEnv,
} from "./index.ts";

const IMAGE = process.env.KERN_PI_IMAGE ?? "python:3.12-slim";



async function main() {
	// ---- the containment check, with no box: it is pure and it is the security boundary ----
	console.log("\ncontainment");
	ok("workspace root maps to empty", refuseOutsideWorkspace("/workspace") === "");
	ok("a file maps to a relative path", refuseOutsideWorkspace("/workspace/src/main.rs") === "src/main.rs");
	ok("trailing slash tolerated", refuseOutsideWorkspace("/workspace/") === "");
	await throws("absolute outside is refused", () => refuseOutsideWorkspace("/etc/passwd"), /outside/);
	await throws("dotdot escape is refused", () => refuseOutsideWorkspace("/workspace/../etc/passwd"), /outside/);
	await throws("deep dotdot escape is refused", () => refuseOutsideWorkspace("/workspace/a/b/../../../etc"), /outside/);
	await throws("a relative path is refused", () => refuseOutsideWorkspace("src/main.rs"), /relative/);
	await throws("a lookalike prefix is refused", () => refuseOutsideWorkspace("/workspace-evil/x"), /outside/);

	// ---- the box a toolchain actually lands in, before any box is opened ----
	console.log("\nthe two writable places");
	const opts = boxOptions("/some/host/workspace");
	// Both were MISSING, and the documented README example (`KERN_PI_IMAGE=node:22`, then an agent
	// running `npm install`) could not work without them. Measured on node:22: neither -> exit 2,
	// HOME alone with a read-only /tmp -> still exit 2, both -> exit 0 and the cache moves to
	// /workspace/.npm. So both are asserted, not just the one that is easier to remember.
	ok("the box gets scratch at /tmp", JSON.stringify(opts.tmpfs) === JSON.stringify({ "/tmp": "256m" }), JSON.stringify(opts.tmpfs));
	ok("the box gets a writable HOME", JSON.stringify(opts.env) === JSON.stringify({ HOME: "/workspace" }), JSON.stringify(opts.env));
	ok("no network unless KERN_PI_EGRESS names a host", !("egressAllow" in opts));
	// The knobs, at their edges, through the functions that decide. `0` had to mean "none" here
	// because `KERN_MCP_TMPFS_MB=0` already means that: two knobs with the same name and opposite
	// behaviour is the defect this whole round has been about, and before this it silently gave 256.
	// Garbage still falls back, because a typo is not a decision.
	for (const [raw, expected] of [["0", 0], ["-5", 256], ["abc", 256], ["512", 512], [undefined, 256]] as [string | undefined, number][]) {
		const saved = process.env.KERN_PI_SCRATCH_PROBE;
		if (raw === undefined) delete process.env.KERN_PI_SCRATCH_PROBE;
		else process.env.KERN_PI_SCRATCH_PROBE = raw;
		const seen = scratchFromEnv("KERN_PI_SCRATCH_PROBE", 256);
		if (saved === undefined) delete process.env.KERN_PI_SCRATCH_PROBE;
		else process.env.KERN_PI_SCRATCH_PROBE = saved;
		ok(`scratch knob ${JSON.stringify(raw)} -> ${seen}`, seen === expected, `atteso ${expected}`);
	}
	// The premise under the HOME default, because a reviewer argued for pointing it at the scratch and
	// the argument stands or falls on this: EVERY COMMAND IS A FRESH BOX, so the scratch is fresh too.
	// A cache under $HOME on the scratch would be rebuilt from the network on every single command.
	// Asserted here rather than in prose because it is the reason the default is what it is.
	{
		const ws2 = fs.mkdtempSync(path.join(os.tmpdir(), "kern-pi-fresh-"));
		const fb = new Sandbox({ image: IMAGE, workspace: ws2, timeoutS: 30, tmpfs: { "/tmp": "8m" } });
		await fb.open();
		let a = "", b2 = "", c2 = "";
		try {
			const ops = kernBashOps(fb, "sh");
			await ops.exec("echo x > /tmp/marker && echo WRITTEN", "/workspace", { onData: (c) => { a += c.toString(); } });
			await ops.exec("cat /tmp/marker 2>/dev/null && echo SURVIVED || echo GONE", "/workspace", { onData: (c) => { b2 += c.toString(); } });
			await ops.exec("echo y > /workspace/marker; cat /workspace/marker && echo WS-SURVIVED", "/workspace", { onData: (c) => { c2 += c.toString(); } });
		} finally {
			await fb.close();
			fs.rmSync(ws2, { recursive: true, force: true });
		}
		ok("scratch does NOT survive between two commands", a.includes("WRITTEN") && b2.includes("GONE"), `${a.trim()} | ${b2.trim()}`);
		ok("the workspace does, which is why HOME points there", c2.includes("WS-SURVIVED"), c2.trim());
	}

	// An empty or relative $HOME puts the toolchain cache back inside the read-only root, which is
	// the defect the knob exists to fix, arriving again with no message.
	ok("an absolute HOME passes", guestHome("/tmp/home") === "/tmp/home");
	await throws("an empty HOME is refused", () => guestHome(""), /absolute path/);
	await throws("a relative HOME is refused", () => guestHome("workspace"), /absolute path/);

	// An SDK that silently ignores `tmpfs` is the failure this guards: an unknown constructor option
	// throws in neither binding, so the box would come up with a read-only /tmp and the first install
	// would blame the network. It must pass HERE, against the SDK this checkout resolves.
	requireScratchSupport();
	ok("the installed kern-sandbox honours tmpfs", true);

	// ---- activation must touch NOTHING ----------------------------------------------------------
	console.log("\nactivation");
	// A reviewer spent an afternoon on a pi startup hang and cleared this extension by running pi
	// with and without `-e`. That clearing should be a PROPERTY we hold, not a result they had to go
	// and measure: registering tools must not open a box, spawn kern, or pull an image.
	//
	// The discriminant is a KERN_BIN that does not exist. `new Sandbox(...)` resolves the binary in
	// its CONSTRUCTOR and throws when it cannot, so if activation built one, this throws. It also
	// covers the weaker shape: a box opened at activation would cost an image pull before the user
	// has asked for anything.
	const savedBin = process.env.KERN_BIN;
	process.env.KERN_BIN = "/nonexistent/kern-that-is-not-there";
	let registered = 0;
	let commands = 0;
	let hooks = 0;
	const tAct = Date.now();
	try {
		const stub = {
			registerTool: () => {
				registered++;
			},
			registerCommand: () => {
				commands++;
			},
			on: () => {
				hooks++;
			},
		};
		(await import("./index.ts")).default(stub as never);
		ok("activation registers the tools without a kern binary present", registered >= 7 && commands >= 1 && hooks >= 2, `${registered} tools, ${commands} commands, ${hooks} hooks`);
	} catch (e) {
		ok("activation registers the tools without a kern binary present", false, e instanceof Error ? e.message : String(e));
	} finally {
		if (savedBin === undefined) delete process.env.KERN_BIN;
		else process.env.KERN_BIN = savedBin;
	}
	const activateMs = Date.now() - tAct;
	// A box open is ~90 ms on a warm image and unbounded on a cold one. Activation is arithmetic.
	ok(`activation is instant (${activateMs} ms), so no box and no pull`, activateMs < 200, `${activateMs} ms`);

	// ---- the glob, also pure ----
	console.log("\nglob");
	ok("* does not cross a separator", globMatches("*.ts", "a.ts") && !globMatches("*.ts", "d/a.ts"));
	ok("** crosses separators", globMatches("**/*.ts", "a/b/c.ts"));
	ok("**/ matches zero directories", globMatches("**/*.ts", "c.ts"));
	ok("? is one non-separator", globMatches("a?.ts", "ab.ts") && !globMatches("a?.ts", "a/.ts"));
	ok("a dot is literal, not any-char", !globMatches("*.ts", "axts"));
	ok("regex metacharacters are escaped", globMatches("a+b.ts", "a+b.ts"));
	ok("anchored: no partial match", !globMatches("*.ts", "a.ts.bak"));

	// ---- everything below needs a real box ----
	const ws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-pi-test-"));
	fs.writeFileSync(path.join(ws, "hello.txt"), "hello from the host\n");
	fs.mkdirSync(path.join(ws, "sub"));
	fs.writeFileSync(path.join(ws, "sub", "deep.py"), "print('needle in here')\n");
	// a 1x1 PNG, so the mime sniffer has something real to look at
	fs.writeFileSync(
		path.join(ws, "pixel.png"),
		Buffer.from(
			"89504e470d0a1a0a0000000d494844520000000100000001080600000" +
				"01f15c4890000000a49444154789c6300010000050001",
			"hex",
		),
	);
	// the escape a box could plant to redirect a host-side read
	fs.symlinkSync("/etc", path.join(ws, "escape"));

	console.log(`\nopening a box on ${IMAGE} (workspace ${ws})`);
	const box = new Sandbox({ image: IMAGE, workspace: ws, memoryMb: 1024, pids: 256, timeoutS: 60 });
	const t0 = Date.now();
	await box.open();
	console.log(`  box open in ${Date.now() - t0} ms`);

	try {
		console.log("\nread");
		const r = kernReadOps(box, ws);
		ok("readFile returns the bytes", (await r.readFile("/workspace/hello.txt")).toString() === "hello from the host\n");
		await r.access("/workspace/hello.txt");
		ok("access resolves for a file that exists", true);
		await throws("access rejects a missing file", () => r.access("/workspace/nope.txt"));
		await throws("read refuses a path outside", () => r.readFile("/etc/passwd"), /outside/);
		await throws("read refuses a dotdot escape", () => r.readFile("/workspace/../etc/passwd"), /outside/);
		await throws("read refuses through a planted symlink", () => r.readFile("/workspace/escape/passwd"));

		console.log("\nimage sniffing");
		ok("a real PNG is detected", (await detectImageMimeType(ws, "pixel.png")) === "image/png");
		ok("a text file is not an image", (await detectImageMimeType(ws, "hello.txt")) === null);
		ok("a missing file is not an image", (await detectImageMimeType(ws, "gone.bin")) === null);

		console.log("\nwrite and edit");
		const w = kernWriteOps(box);
		await w.mkdir("/workspace/made/deeper");
		ok("mkdir is recursive", fs.existsSync(path.join(ws, "made", "deeper")));
		await w.writeFile("/workspace/made/out.txt", "written\n");
		ok("writeFile lands on the host", fs.readFileSync(path.join(ws, "made", "out.txt"), "utf8") === "written\n");
		await throws("write refuses a path outside", () => w.writeFile("/tmp/pwned", "x"), /outside/);
		const e = kernEditOps(box, ws);
		await e.writeFile("/workspace/made/out.txt", "edited\n");
		ok("edit round-trips", (await e.readFile("/workspace/made/out.txt")).toString() === "edited\n");

		console.log("\nls");
		const l = kernLsOps(box);
		ok("exists is true for a real file", (await l.exists("/workspace/hello.txt")) === true);
		ok("exists is false for a missing one", (await l.exists("/workspace/nope")) === false);
		ok("stat sees a directory", (await l.stat("/workspace/sub")).isDirectory() === true);
		ok("lstat does NOT follow a symlink to a dir", (await l.stat("/workspace/escape")).isDirectory() === false);
		const names = await l.readdir("/workspace");
		ok("readdir lists the workspace", names.includes("hello.txt") && names.includes("sub"));

		console.log("\ngrep");
		const g = kernGrepOps(box, ws);
		ok("isDirectory is true for a dir", (await g.isDirectory("/workspace/sub")) === true);
		ok("isDirectory is false for a file", (await g.isDirectory("/workspace/hello.txt")) === false);
		ok("isDirectory is false for a missing path", (await g.isDirectory("/workspace/nope")) === false);
		ok("readFile returns a string", (await g.readFile("/workspace/sub/deep.py")).includes("needle"));

		console.log("\nfind");
		const f = kernFindOps(box);
		const py = await f.glob("**/*.py", "/workspace", { ignore: [], limit: 100 });
		ok("glob finds a nested file, guest-absolute", py.includes("/workspace/sub/deep.py"), JSON.stringify(py));
		const ignored = await f.glob("**/*.py", "/workspace", { ignore: ["sub/**"], limit: 100 });
		ok("glob honours ignore", ignored.length === 0, JSON.stringify(ignored));
		const limited = await f.glob("**/*", "/workspace", { ignore: [], limit: 1 });
		ok("glob honours limit", limited.length === 1, JSON.stringify(limited));

		console.log("\nbash (the half that crosses into the box)");
		const b = kernBashOps(box);
		let out = "";
		const onData = (c: Buffer) => {
			out += c.toString();
		};
		const rc = await b.exec("echo streamed; echo to-stderr 1>&2", "/workspace", { onData });
		ok("exit code is 0", rc.exitCode === 0, JSON.stringify(rc));
		ok("stdout streamed", out.includes("streamed"));
		ok("stderr streamed to the same sink", out.includes("to-stderr"));

		out = "";
		const rc2 = await b.exec("exit 3", "/workspace", { onData });
		ok("a non-zero exit is reported, not thrown", rc2.exitCode === 3, JSON.stringify(rc2));

		out = "";
		await b.exec("pwd", "/workspace/sub", { onData });
		ok("cwd is honoured", out.trim() === "/workspace/sub", JSON.stringify(out));

		out = "";
		await b.exec("echo $PI_MARKER", "/workspace", { onData, env: { PI_MARKER: "seen" } });
		ok("env reaches the command", out.includes("seen"), JSON.stringify(out));

		out = "";
		// `/home` EXISTS in a Debian image, so its absence was never the discriminant: the first
		// version of this assertion failed on a correct box. What must be true is that the host
		// user's home is not reachable, and that the box's own /home is empty.
		await b.exec("ls -A /home | wc -l; test -d /home/" + (process.env.USER ?? "nobody") + " && echo LEAKED || echo isolated", "/workspace", { onData });
		ok("the host's home is not visible in the box", out.includes("isolated") && !out.includes("LEAKED"), JSON.stringify(out));

		out = "";
		await b.exec("ls /workspace | tr '\\n' ' '", "/workspace", { onData });
		ok("the box sees the workspace", out.includes("hello.txt"), JSON.stringify(out));

		// THE UNIT BUG THIS FILE EXISTS FOR. pi's `timeout` is SECONDS. A version that divided by
		// 1000 turned 2 into 0 and inherited the session's 60 s, so a command that must die at 2 s
		// would have run for a minute. Two seconds of wall clock is the only thing that proves it.
		console.log("\ntimeout unit (seconds, not milliseconds)");
		out = "";
		const t1 = Date.now();
		await throws("a 2 s timeout fires as a timeout", () => b.exec("sleep 30", "/workspace", { onData, timeout: 2 }), /^timeout:2$/);
		const elapsed = Date.now() - t1;
		ok(`it fired at ~2 s, not 30 or 60 (took ${elapsed} ms)`, elapsed > 1000 && elapsed < 12000, `${elapsed} ms`);

		console.log("\nabort");
		out = "";
		const ac = new AbortController();
		setTimeout(() => ac.abort(), 300);
		await throws("an aborted call rejects with 'aborted'", () => b.exec("sleep 20", "/workspace", { onData, signal: ac.signal }), /^aborted$/);

		await throws("bash refuses a cwd outside the workspace", () => b.exec("pwd", "/etc", { onData }), /outside/);

		// ---- the option set, against a real box, with the old shape as the control ----------------
		// ---- the shell the agent actually gets -----------------------------------------------------
		console.log("\nthe shell behind pi's `bash` tool");
		// pi's tool is called `bash` and a model writes bash by reflex. This used to hand the command
		// to `sh`, which on a Debian image is dash, WITH BASH PRESENT AND UNUSED: `[[ 1 == 1 ]]`
		// answered `sh: 1: [[: not found`, arrays and process substitution answered `Syntax error:
		// "(" unexpected`. Nothing was missing; the wrong binary was chosen. Found by a reviewer.
		ok("the shell is measured, not assumed", (await detectShell(box)) === "bash");
		out = "";
		await b.exec("readlink -f /proc/$$/exe; [[ 1 == 1 ]] && echo BRACKETS-OK || echo BRACKETS-NO", "/workspace", { onData });
		ok("pi's `bash` tool really runs bash", out.includes("/bash") && out.includes("BRACKETS-OK"), out.trim().replace(/\n/g, " | "));
		out = "";
		await b.exec("a=(1 2 3); echo ${#a[@]}", "/workspace", { onData });
		ok("an array, which dash cannot parse, works", out.includes("3"), out.trim());

		console.log("\nboth writable places, in a box opened the way the extension opens one");
		const probe =
			'touch /tmp/p 2>/dev/null && echo TMP-OK || echo TMP-RO; ' +
			'touch "$HOME/.p" 2>/dev/null && echo HOME-OK || echo HOME-RO; echo HOME=$HOME';
		const cases: [string, SandboxOptions, boolean][] = [
			["as the extension opens one", boxOptions(ws), true],
			// The control is the shape that shipped: no tmpfs, no HOME. If it does NOT fail, this test
			// is proving nothing and the two lines above it are decoration.
			["the control, as it shipped", { image: IMAGE, workspace: ws, timeoutS: 30, tmpfs: {} }, false],
		];
		for (const [label, options, shouldWork] of cases) {
			const probeBox = new Sandbox(options);
			await probeBox.open();
			let seen = "";
			try {
				await kernBashOps(probeBox).exec(probe, "/workspace", {
					onData: (c: Buffer) => {
						seen += c.toString();
					},
				});
			} finally {
				await probeBox.close();
			}
			const writable = seen.includes("TMP-OK") && seen.includes("HOME-OK");
			ok(`${label}: /tmp and $HOME writable = ${writable}`, writable === shouldWork, seen.trim().replace(/\n/g, " | "));
		}
	} finally {
		await box.close();
		fs.rmSync(ws, { recursive: true, force: true });
	}

	report();
}

main().catch(fatal);
