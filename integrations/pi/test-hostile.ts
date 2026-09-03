/**
 * What an agent can plant in its own workspace, and what it can ask for concurrently.
 *
 * `test-edge.ts` attacks the PATH: strings, symlinks, races. This attacks the OBJECTS and the
 * SCHEDULE: file types that block a reader forever, names the filesystem accepts and UTF-8 does not,
 * resolution that never terminates, and several tool calls arriving at once on one box.
 *
 * The threat model is unchanged and it is the one that makes these reachable: the agent runs `bash`
 * in the box, the box has the workspace bind-mounted read-write, and pi calls the file tools on the
 * host. Anything `mkfifo` can make, the agent can make.
 *
 * A hang is the finding here, not an exception. node is single-threaded and pi shares the loop, so a
 * file tool that blocks takes the session with it, which is the same shape as the glob that took 149
 * seconds. Every assertion below is therefore under a deadline, and a deadline that fires IS the
 * failure rather than the harness giving up.
 *
 *   node --experimental-strip-types test-hostile.ts
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Sandbox } from "kern-sandbox";
import { fatal, ok, report } from "./harness.ts";
import { detectImageMimeType, kernBashOps, kernFindOps, kernLsOps, kernReadOps, kernWriteOps } from "./index.ts";

const IMAGE = process.env.KERN_PI_IMAGE ?? "python:3.12-slim";

/** Resolve to a marker rather than reject, so a hang is reported as a hang and not as an error. */
async function within<T>(ms: number, p: Promise<T>): Promise<T | "HUNG"> {
	let timer: NodeJS.Timeout | undefined;
	const deadline = new Promise<"HUNG">((res) => {
		timer = setTimeout(() => res("HUNG"), ms);
	});
	try {
		return await Promise.race([p, deadline]);
	} finally {
		if (timer) clearTimeout(timer);
	}
}

/** Did it finish at all, whatever it answered? A throw counts: it returned control. */
async function settles(name: string, ms: number, fn: () => Promise<unknown>): Promise<void> {
	const r = await within(
		ms,
		fn().then(
			() => "returned",
			() => "threw",
		),
	);
	ok(`${name} (${r === "HUNG" ? `no answer in ${ms} ms` : r})`, r !== "HUNG");
}

async function main() {
	const ws = fs.mkdtempSync(path.join(os.tmpdir(), "kern-pi-hostile-"));
	const box = new Sandbox({ image: IMAGE, workspace: ws, memoryMb: 1024, pids: 256, timeoutS: 30 });
	await box.open();
	const r = kernReadOps(box, ws);
	const w = kernWriteOps(box);
	const l = kernLsOps(box);
	const f = kernFindOps(box);
	const b = kernBashOps(box);

	try {
		// ---- file types a regular open blocks on ----------------------------------------------
		console.log("\nobjects that are not files");
		// A FIFO with no writer blocks `open(O_RDONLY)` forever. The agent plants it with one command.
		await b.exec("mkfifo /workspace/pipe", "/workspace", { onData: () => {} });
		ok("the agent could plant a FIFO", fs.existsSync(path.join(ws, "pipe")));
		await settles("readFile on a FIFO", 6000, () => r.readFile("/workspace/pipe"));
		await settles("access on a FIFO", 6000, () => r.access("/workspace/pipe"));
		await settles("stat on a FIFO", 6000, async () => (await l.stat("/workspace/pipe")).isDirectory());
		await settles("the image sniffer on a FIFO", 6000, () => detectImageMimeType(ws, "pipe"));
		await settles("readdir with a FIFO present", 6000, async () => l.readdir("/workspace"));

		// /dev/zero is infinite: a reader with no cap never returns.
		await b.exec("ln -s /dev/zero /workspace/infinite 2>/dev/null || true", "/workspace", { onData: () => {} });
		await settles("readFile through a link to /dev/zero", 8000, () => r.readFile("/workspace/infinite"));

		// ---- resolution that does not terminate ----------------------------------------------
		console.log("\nresolution that does not terminate");
		fs.symlinkSync("loopB", path.join(ws, "loopA"));
		fs.symlinkSync("loopA", path.join(ws, "loopB"));
		await settles("exists on a symlink loop", 6000, async () => l.exists("/workspace/loopA"));
		await settles("readFile on a symlink loop", 6000, () => r.readFile("/workspace/loopA"));
		await settles("mkdir through a symlink loop", 8000, () => w.mkdir("/workspace/loopA/x"));
		await settles("glob with a loop in the tree", 8000, async () => f.glob("**/*", "/workspace", { ignore: [], limit: 50 }));

		// ---- names the filesystem accepts and UTF-8 does not ---------------------------------
		console.log("\nnames that are not text");
		// A filename is bytes, not a string. `find -print0` output decoded as UTF-8 mangles this one,
		// and a mangled name handed back to `readFile` is a different file or none.
		const rawName = Buffer.from([0xff, 0xfe, 0x41, 0x42]); // invalid UTF-8, then "AB"
		let planted = false;
		try {
			fs.writeFileSync(Buffer.concat([Buffer.from(`${ws}/`), rawName]) as unknown as string, "x");
			planted = true;
		} catch {
			planted = false;
		}
		ok("a non-UTF-8 filename could be planted", planted);
		if (planted) {
			await settles("readdir with a non-UTF-8 name present", 8000, async () => l.readdir("/workspace"));
			const names = (await within(8000, Promise.resolve(l.readdir("/workspace")))) as string[] | "HUNG";
			if (names !== "HUNG") {
				// The contract is that it does not CRASH and does not claim the directory is empty.
				ok("the listing still contains the readable names", names.includes("pipe"), JSON.stringify(names.slice(0, 6)));
			}
		}

		// ---- size ----------------------------------------------------------------------------
		console.log("\nsize");
		await b.exec("head -c 120000000 /dev/zero > /workspace/big.bin", "/workspace", { onData: () => {}, timeout: 60 });
		const big = fs.existsSync(path.join(ws, "big.bin")) ? fs.statSync(path.join(ws, "big.bin")).size : 0;
		ok("a 120 MB file could be planted", big > 100_000_000, `${Math.round(big / 1e6)} MB`);
		const before = process.memoryUsage().heapUsed;
		await settles("readFile on 120 MB returns", 20000, () => r.readFile("/workspace/big.bin"));
		const grew = Math.round((process.memoryUsage().heapUsed - before) / 1e6);
		// It is host memory by construction: the point is that it is BOUNDED by the file, not that it
		// is free. A cap belongs in the caller, and pi has one; this asserts it does not run away.
		ok(`the heap grew by the file, not a multiple of it (${grew} MB)`, grew < 600, `${grew} MB`);
		await settles("the image sniffer on 120 MB is still O(1)", 3000, () => detectImageMimeType(ws, "big.bin"));

		// ---- several calls at once on one box -------------------------------------------------
		console.log("\nconcurrency on one box");
		fs.writeFileSync(path.join(ws, "shared.txt"), "base\n");
		const reads = await within(
			30000,
			Promise.all(Array.from({ length: 12 }, () => r.readFile("/workspace/shared.txt"))),
		);
		ok("12 concurrent reads all answer", reads !== "HUNG" && (reads as Buffer[]).every((x) => x.toString() === "base\n"));

		// The write path stages through a random temp name. Concurrent writes must not collide on it,
		// and every one must land: a collision would show as a lost write or a stray temp.
		const targets = Array.from({ length: 12 }, (_, i) => `/workspace/conc/f${i}.txt`);
		const writes = await within(60000, Promise.all(targets.map((t2, i) => w.writeFile(t2, `v${i}\n`))));
		ok("12 concurrent writes all complete", writes !== "HUNG");
		const landed = targets.filter((t2, i) => {
			const p = path.join(ws, t2.replace("/workspace/", ""));
			return fs.existsSync(p) && fs.readFileSync(p, "utf8") === `v${i}\n`;
		});
		ok("every concurrent write landed with its own content", landed.length === 12, `${landed.length}/12`);
		ok("no staging file was left behind", fs.readdirSync(ws).filter((n) => n.startsWith(".kern-pi.")).length === 0);

		const mixed = await within(
			40000,
			Promise.all([
				Promise.resolve(l.readdir("/workspace")),
				Promise.resolve(f.glob("**/*.txt", "/workspace", { ignore: [], limit: 20 })),
				r.readFile("/workspace/shared.txt"),
				b.exec("echo mixed", "/workspace", { onData: () => {} }),
			]),
		);
		ok("read, list, glob and exec interleave without deadlock", mixed !== "HUNG");

		// ---- the box going away underneath the session ---------------------------------------
		console.log("\nthe box going away");
		const closed = new Sandbox({ image: IMAGE, workspace: ws, timeoutS: 20 });
		await closed.open();
		await closed.close();
		await settles("a call on a closed box fails rather than hangs", 8000, () =>
			kernReadOps(closed, ws).readFile("/workspace/shared.txt"),
		);
		const badImage = new Sandbox({ image: "kern-pi-no-such-image:0", workspace: ws, timeoutS: 20 });
		await settles("opening an image that does not exist fails rather than hangs", 30000, () => badImage.open());
	} finally {
		await box.close();
		fs.rmSync(ws, { recursive: true, force: true });
	}

	report();
}

main().catch(fatal);
