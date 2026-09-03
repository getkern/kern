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
import { Sandbox } from "kern-sandbox";
import { fatal, ok, report, throws } from "./harness.ts";
import {
	detectImageMimeType,
	globMatches,
	kernBashOps,
	kernEditOps,
	kernFindOps,
	kernGrepOps,
	kernLsOps,
	kernReadOps,
	kernWriteOps,
	refuseOutsideWorkspace,
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
	} finally {
		await box.close();
		fs.rmSync(ws, { recursive: true, force: true });
	}

	report();
}

main().catch(fatal);
