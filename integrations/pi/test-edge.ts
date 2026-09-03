/**
 * Adversarial edges for the two functions that are this extension's whole security story.
 *
 * `test.ts` asks whether the seven operations WORK. This asks whether the containment can be talked
 * out of its job, because everything else here trusts it: if `refuseOutsideWorkspace` can be made to
 * return a path outside the workspace, every file tool follows it there.
 *
 * The model is a PROMPT-INJECTED agent, not a kernel exploit: it chooses the strings, it can plant
 * files and symlinks in the workspace, and it cannot patch this process.
 *
 *   node --experimental-strip-types test-edge.ts
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Sandbox } from "kern-sandbox";
import { fatal, ok, report } from "./harness.ts";
import {
	detectImageMimeType,
	globMatches,
	kernBashOps,
	kernFindOps,
	kernLsOps,
	kernReadOps,
	kernWriteOps,
	refuseOutsideWorkspace,
} from "./index.ts";


/** Refused = threw. Anything that RETURNS is a hole, and the returned value says how big. */
function refused(name: string, input: string) {
	try {
		const out = refuseOutsideWorkspace(input);
		ok(name, false, `returned ${JSON.stringify(out)} for ${JSON.stringify(input)}`);
	} catch {
		ok(name, true);
	}
}

function allowed(name: string, input: string, expect: string) {
	try {
		const out = refuseOutsideWorkspace(input);
		ok(name, out === expect, `got ${JSON.stringify(out)}, wanted ${JSON.stringify(expect)}`);
	} catch (e) {
		ok(name, false, `threw: ${e instanceof Error ? e.message : String(e)}`);
	}
}

async function main() {
	console.log("\npath containment, adversarial");

	// The obvious escapes, and the ones that look like the workspace but are not.
	refused("parent of the workspace", "/");
	refused("sibling with a shared prefix", "/workspace2/x");
	refused("sibling with a dash", "/workspace-evil/x");
	refused("a dotfile above", "/workspace/../.ssh/id_rsa");
	refused("many dotdots", "/workspace/../../../../etc/shadow");
	refused("dotdot in the middle", "/workspace/a/../../etc/passwd");
	refused("bare tmp", "/tmp/pwned");
	refused("proc self environ", "/proc/self/environ");
	refused("empty string", "");
	refused("only whitespace", "   ");
	refused("a relative dotdot", "../etc/passwd");
	refused("a bare filename", "passwd");
	refused("a dot", ".");
	refused("a windows-ish drive", "C:\\Windows");

	// Normalisation: these ARE inside, and refusing them would break ordinary use.
	allowed("double slash is normalised", "//workspace/a", "a");
	allowed("a dot segment is normalised", "/workspace/./a", "a");
	allowed("dotdot that stays inside", "/workspace/a/../b", "b");
	allowed("trailing slash on a subdir", "/workspace/a/", "a");
	allowed("leading and trailing spaces are trimmed", "  /workspace/a  ", "a");
	allowed("the workspace itself", "/workspace", "");
	allowed("a name containing dotdot is not an escape", "/workspace/..hidden", "..hidden");
	allowed("a name ending in dotdot", "/workspace/a..", "a..");
	allowed("unicode survives", "/workspace/città/файл.txt", "città/файл.txt");
	allowed("a space in a name", "/workspace/my file.txt", "my file.txt");
	allowed("a quote in a name", "/workspace/it's.txt", "it's.txt");

	// A NUL truncates a C string, so a name carrying one is refused rather than passed to a syscall
	// that would see only the part before it. Node throws on the syscall, but the refusal should
	// happen here, where the reason is legible.
	const nul = "/workspace/ok.txt\u0000/../../etc/passwd";
	try {
		const out = refuseOutsideWorkspace(nul);
		ok("a NUL byte does not smuggle a second path", !out.includes("etc"), JSON.stringify(out));
	} catch {
		ok("a NUL byte does not smuggle a second path", true);
	}

	// A very long path must not be a way to crash the process rather than be refused.
	const deep = `/workspace/${"a/".repeat(4000)}x`;
	try {
		const out = refuseOutsideWorkspace(deep);
		ok("a 4000-deep path is handled, not fatal", out.endsWith("x"));
	} catch {
		ok("a 4000-deep path is handled, not fatal", true);
	}
	refused("4000 dotdots", `/workspace/${"../".repeat(4000)}etc/passwd`);

	console.log("\nglob, adversarial");
	// The glob comes from the agent. It must not be a denial of service, and it must not match more
	// than the glob said. 149 SECONDS was the measurement that killed the RegExp version.
	const evil = `${"a*".repeat(60)}b`;
	const t0 = Date.now();
	globMatches(evil, "a".repeat(400));
	const ms = Date.now() - t0;
	ok(`a nested-star pattern does not hang (${ms} ms)`, ms < 2000, `${ms} ms`);
	ok("a regex injected as a glob is literal", !globMatches("(.*)", "anything"));
	ok("an anchor injected as a glob is literal", !globMatches("^x$", "x"));
	ok("an alternation is literal", !globMatches("a|b", "a"));
	ok("a backslash is literal", globMatches("a\\b", "a\\b"));
	ok("an empty glob matches only empty", globMatches("", "") && !globMatches("", "a"));

	// ---- the rest needs a box ----
	const ws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-pi-edge-"));
	fs.writeFileSync(path.join(ws, "ok.txt"), "inside\n");
	fs.mkdirSync(path.join(ws, "d"));
	// three shapes of planted link: a file link, a directory link, and a chain
	fs.symlinkSync("/etc/passwd", path.join(ws, "linkfile"));
	fs.symlinkSync("/etc", path.join(ws, "linkdir"));
	fs.symlinkSync("linkdir", path.join(ws, "linkchain"));
	fs.symlinkSync("/etc/passwd", path.join(ws, "d", "inner"));

	const box = new Sandbox({ image: "python:3.12-slim", workspace: ws, memoryMb: 1024, pids: 256, timeoutS: 30 });
	await box.open();

	try {
		console.log("\nplanted symlinks (the agent CAN create these in its own workspace)");
		const r = kernReadOps(box, ws);
		for (const [name, p] of [
			["a link to a host FILE", "/workspace/linkfile"],
			["a link to a host DIR, then a file", "/workspace/linkdir/passwd"],
			["a CHAIN of links", "/workspace/linkchain/passwd"],
			["a link inside a subdirectory", "/workspace/d/inner"],
		] as const) {
			try {
				const buf = await r.readFile(p);
				ok(`read through ${name} is refused`, !buf.toString().includes("root:"), `LEAKED ${buf.length} bytes`);
			} catch {
				ok(`read through ${name} is refused`, true);
			}
		}

		const w = kernWriteOps(box);
		try {
			await w.writeFile("/workspace/linkfile", "pwned");
			const still = fs.readFileSync("/etc/passwd", "utf8");
			ok("write through a link does not clobber the host file", still.includes("root:"), "HOST FILE WAS WRITTEN");
		} catch {
			ok("write through a link does not clobber the host file", true);
		}
		try {
			await w.mkdir("/workspace/linkdir/newdir");
			ok("mkdir through a link to /etc is refused", !fs.existsSync("/etc/newdir"), "CREATED /etc/newdir");
		} catch {
			ok("mkdir through a link to /etc is refused", true);
		}

		const l = kernLsOps(box);
		const listed = await l.readdir("/workspace");
		ok("readdir does not follow links into the host", !listed.includes("passwd"), JSON.stringify(listed));
		ok("stat on a link to a dir reports NOT a directory", (await l.stat("/workspace/linkdir")).isDirectory() === false);

		const f = kernFindOps(box);
		const hits = await f.glob("**/*", "/workspace", { ignore: [], limit: 500 });
		ok(
			"glob never leaves the workspace",
			hits.every((h) => h.startsWith("/workspace/")),
			JSON.stringify(hits.slice(0, 5)),
		);
		ok("glob does not enumerate a linked host dir", !hits.some((h) => h.includes("passwd")), JSON.stringify(hits.slice(0, 8)));

		ok("mime sniff on a link to a host file returns null", (await detectImageMimeType(ws, "linkfile")) === null);

		console.log("\nbash, adversarial");
		const b = kernBashOps(box);
		let out = "";
		const onData = (c: Buffer) => {
			out += c.toString();
		};

		// The cwd is the only agent-influenced string this file puts in a shell script. It is quoted,
		// and it is validated first, so both halves would have to fail together.
		await (async () => {
			try {
				await b.exec("echo SHOULD-NOT-RUN", "/workspace'; id; echo '", { onData });
				ok("a quote-breaking cwd is refused", !out.includes("uid="), JSON.stringify(out.slice(0, 80)));
			} catch {
				ok("a quote-breaking cwd is refused", true);
			}
		})();

		out = "";
		await b.exec("echo done", "/workspace/d", { onData });
		ok("an ordinary subdirectory cwd still works", out.includes("done"));

		// env keys are validated because they are pasted into `export K=V`. A key that is not a shell
		// name is DROPPED rather than escaped: there is nothing a shell would do with it.
		out = "";
		await b.exec("echo ${EVIL:-unset}", "/workspace", { onData, env: { "EVIL; id": "x", EVIL: "safe" } });
		ok("a malformed env key cannot inject", !out.includes("uid="), JSON.stringify(out.slice(0, 80)));
		ok("a well-formed env key still arrives", out.includes("safe"));

		out = "";
		await b.exec("echo \"$Q\"", "/workspace", { onData, env: { Q: "a'b\"c$(id)`id`" } });
		ok("a hostile env VALUE is not evaluated", !out.includes("uid="), JSON.stringify(out.slice(0, 90)));
		ok("the hostile value arrives verbatim", out.includes("a'b\"c$(id)`id`"));

		out = "";
		const big = await b.exec("head -c 300000 /dev/zero | tr '\\0' 'x'", "/workspace", { onData });
		ok("300 KB of output does not break the stream", big.exitCode === 0 && out.length > 100000, `${out.length} bytes`);

		// Unbounded output is the glob finding with a different lever: the agent picks the command and
		// every chunk is forwarded into a single-threaded renderer. Two things must hold: the capture
		// stops, and the process in the box actually dies rather than merely going unread.
		out = "";
		await b.exec("yes AAAAAAAAAAAAAAAA", "/workspace", { onData, timeout: 6 }).catch((e) => e);
		ok(
			"an endless writer is bounded, not unbounded",
			out.length < 40 * 1024 * 1024,
			`${Math.round(out.length / 1024)} KB forwarded`,
		);
		out = "";
		await b.exec("i=0; while :; do i=$((i+1)); echo $i > /workspace/beat; sleep 1; done", "/workspace", {
			onData,
			timeout: 3,
		}).catch(() => {});
		const beatA = fs.readFileSync(path.join(ws, "beat"), "utf8").trim();
		await new Promise((r) => setTimeout(r, 3500));
		const beatB = fs.readFileSync(path.join(ws, "beat"), "utf8").trim();
		ok("a timed-out command is KILLED, not just unread", beatA === beatB, `${beatA} then ${beatB}`);

		out = "";
		const bin = await b.exec("head -c 256 /dev/urandom", "/workspace", { onData });
		ok("binary output does not throw", bin.exitCode === 0);

		out = "";
		const nz = await b.exec("exit 255", "/workspace", { onData });
		ok("exit 255 is reported as data", nz.exitCode === 255 && Number.isInteger(nz.exitCode));

		// A fork bomb is the case the caps exist for, and per the SDK's own docs an enforced pids cap
		// produces NO fault: the refused fork is EAGAIN, which the shell handles and exits cleanly.
		out = "";
		const fb = await b.exec(":(){ :|:& };: 2>/dev/null; echo survived", "/workspace", { onData, timeout: 20 });
		ok("a fork bomb does not take the host down", typeof fb.exitCode === "number", JSON.stringify(fb));

		out = "";
		const mem = await b.exec("python3 -c \"a='x'*(2*1024*1024*1024)\" 2>/dev/null; echo after", "/workspace", {
			onData,
			timeout: 30,
		});
		ok("a 2 GB allocation under a 1 GB cap is contained", typeof mem.exitCode === "number", JSON.stringify(mem));

		out = "";
		await b.exec("cat /proc/1/environ 2>/dev/null | head -c 50; echo .", "/workspace", { onData });
		ok("the host's pid 1 environment is not readable", !out.includes("KERN_"), JSON.stringify(out.slice(0, 80)));

		out = "";
		await b.exec("ls /workspace/.. 2>/dev/null | head -3 | tr '\\n' ' '; echo .", "/workspace", { onData });
		ok("the parent of the workspace is the box's root, not the host's", !out.includes("kern-pi-edge"), JSON.stringify(out.slice(0, 90)));
	} finally {
		await box.close();
		fs.rmSync(ws, { recursive: true, force: true });
	}

	// ---- the positive control the reviewer asked for: legal-but-awkward paths that must be ALLOWED.
	// A containment function that refuses everything passes every assertion above it. These are the
	// ones an agent hits on a real project, and a refusal here reads to the model as "no such file".
	console.log("\npositive control: awkward but legal");
	{
		const legal = fs.mkdtempSync(path.join(os.tmpdir(), "kern-pi-legal-"));
		const names = ["..foo", "-", "--", "a b", "a\nb", "-rf", "it's", "città", "#hash", "a;b", "$HOME"];
		for (const n of names) fs.writeFileSync(path.join(legal, n), "x");
		fs.mkdirSync(path.join(legal, "real"));
		fs.writeFileSync(path.join(legal, "real", "f.txt"), "x");
		// three legitimate shapes of INTERNAL symlink. `../real` from the ROOT would resolve to /real,
		// which is outside and correctly refused: the first draft of this test used it and blamed the
		// code for its own fixture.
		fs.symlinkSync("real", path.join(legal, "rel"));
		fs.symlinkSync("/workspace/real", path.join(legal, "abs"));
		fs.mkdirSync(path.join(legal, "sub"));
		fs.symlinkSync("../real", path.join(legal, "sub", "up"));

		const lbox = new Sandbox({ image: "python:3.12-slim", workspace: legal, memoryMb: 1024, timeoutS: 30 });
		await lbox.open();
		try {
			const ll = kernLsOps(lbox);
			const lr = kernReadOps(lbox, legal);
			for (const n of names) {
				ok(`a file named ${JSON.stringify(n)} is readable`, (await lr.readFile(`/workspace/${n}`)).toString() === "x");
			}
			const entries = await ll.readdir("/workspace");
			ok("readdir returns every awkward name", names.every((n) => entries.includes(n)), JSON.stringify(entries));
			ok("a newline in a name survives readdir", entries.includes("a\nb"), JSON.stringify(entries.filter((e) => e.includes("\n"))));
			ok("an internal relative symlink is allowed", (await ll.exists("/workspace/rel/f.txt")) === true);
			ok("an internal absolute symlink is allowed", (await ll.exists("/workspace/abs/f.txt")) === true);
			ok("an internal ../ symlink from a subdir is allowed", (await ll.exists("/workspace/sub/up/f.txt")) === true);
			ok("the workspace root itself exists", (await ll.exists("/workspace")) === true);
			ok("a trailing slash on a directory is allowed", (await ll.stat("/workspace/real/")).isDirectory() === true);
			const w2 = kernWriteOps(lbox);
			await w2.mkdir("/workspace/new/deep/deeper");
			ok("mkdir -p creates a legitimate nested path", fs.existsSync(path.join(legal, "new", "deep", "deeper")));
		} finally {
			await lbox.close();
			fs.rmSync(legal, { recursive: true, force: true });
		}
	}

	// ---- every failure names the side that spoke ----
	console.log("\nfailure vocabulary");
	{
		// ITS OWN workspace. The first version reused the one 79 assertions had been writing to, and a
		// case failed for reasons that had nothing to do with the vocabulary: a test that depends on
		// accumulated state cannot say what it means when it goes red.
		const vws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-pi-vocab-"));
		fs.writeFileSync(path.join(vws, "ok.txt"), "x");
		fs.symlinkSync("/etc", path.join(vws, "linkdir"));
		const vbox = new Sandbox({ image: "python:3.12-slim", workspace: vws, timeoutS: 30 });
		await vbox.open();
		try {
			const vr = kernReadOps(vbox, vws);
			const vw = kernWriteOps(vbox);
			const vl = kernLsOps(vbox);
			const cases: Array<[string, RegExp, () => Promise<unknown>]> = [
				["a path outside is refused by the gate", /^kern\[gate\]/, () => vr.readFile("/etc/passwd")],
				["a relative path is refused by the gate", /^kern\[gate\]/, () => vr.readFile("rel/path")],
				["the workspace root is not writable, gate", /^kern\[gate\]/, () => vw.writeFile("/workspace", "x")],
				["a missing file is the box speaking", /^kern\[box\]/, () => vr.access("/workspace/gone")],
				["listing a non-directory is the box", /^kern\[box\]/, async () => vl.readdir("/workspace/ok.txt")],
				["a write through a link is the box", /^kern\[box\]/, () => vw.writeFile("/workspace/linkdir/x", "y")],
				["an unreadable file is the host", /^kern\[host\]/, () => vr.readFile("/workspace/nope.bin")],
			];
			for (const [name, want, fn] of cases) {
				try {
					await fn();
					ok(name, false, "did not throw");
				} catch (e) {
					const m = e instanceof Error ? e.message : String(e);
					ok(name, want.test(m), `message was: ${m.slice(0, 70)}`);
				}
			}
		} finally {
			await vbox.close();
			fs.rmSync(vws, { recursive: true, force: true });
		}
	}

	// ---- the scratch predicate must agree with the SDK's, not merely look like it ----
	console.log("\nscratch predicate, against the SDK's own behaviour");
	{
		const sw2 = fs.mkdtempSync(path.join(os.tmpdir(), "kern-pi-scratch-"));
		// The corpus is the one that separates the two errors: names the LIBRARY owns, and names a
		// user could plausibly choose that look like them. A copy of a string the SDK owns stays
		// correct only if something fails when it drifts, and this is that something.
		const names = [".kern-env", ".kern-env.box1", ".kern-env.backup", ".kern-environment", ".kern-envx", "kern-env", "a.txt"];
		for (const n of names) fs.writeFileSync(path.join(sw2, n), "x");
		const sbx = new Sandbox({ image: "python:3.12-slim", workspace: sw2, timeoutS: 30 });
		await sbx.open();
		try {
			const sdkSees = new Set((await sbx.listFiles()).map((f) => f.path));
			const mineSees = new Set(await kernLsOps(sbx).readdir("/workspace"));
			const disagree = names.filter((n) => sdkSees.has(n) !== mineSees.has(n));
			ok(
				"my readdir hides exactly what listFiles hides",
				disagree.length === 0,
				`disagree on ${JSON.stringify(disagree)} | sdk=${JSON.stringify([...sdkSees])} mine=${JSON.stringify([...mineSees])}`,
			);
			// and the control: the corpus must contain at least one hidden and one shown, or the
			// assertion above passes for a predicate that hides everything or nothing
			ok("the corpus discriminates", sdkSees.size > 0 && sdkSees.size < names.length, `sdk shows ${sdkSees.size}/${names.length}`);
		} finally {
			await sbx.close();
			fs.rmSync(sw2, { recursive: true, force: true });
		}
	}

	report();
}

main().catch(fatal);
