/**
 * Route pi's built-in coding tools into a kern box.
 *
 * The host working directory is mounted at /workspace inside every box, so file changes write
 * through to the host and everything else the agent's commands touch is discarded with the box.
 *
 * Setup:
 *   cd integrations/pi && npm install
 *
 * Usage:
 *   cd /path/to/project
 *   pi -e /path/to/kern/integrations/pi
 *
 * Requirements:
 *   - Linux (kern is a cgroup + namespace sandbox; on macOS run it inside the Linux VM you already
 *     have, and see the README for what does and does not hold there)
 *   - the `kern` binary on PATH, or KERN_BIN pointing at it
 *
 * WHAT CROSSES THE KERNEL BOUNDARY, AND WHAT DOES NOT. Say this out loud, because the shape differs
 * from the gondolin example this file is modelled on and a reader who assumes they are the same will
 * assume too much:
 *
 *   - `bash` runs INSIDE the box: its own namespaces, a seccomp allowlist, and memory/pids/CPU caps.
 *     A command cannot see the host filesystem outside /workspace, and cannot reach the network
 *     unless KERN_PI_EGRESS names a host.
 *   - `read`, `write`, `edit`, `ls`, `grep`, `find` are HOST filesystem I/O confined to the workspace
 *     by [[refuseOutsideWorkspace]] and, for reads and writes, by the SDK's own O_NOFOLLOW and
 *     directory-descent guards. That is a path check plus a syscall flag, not a namespace.
 *
 * The second half is deliberate: an agent that cannot read the project it was asked to work on is
 * useless, and the workspace is a bind mount, so the host's view and the box's view of those bytes
 * are the same bytes. What it means is that the boundary protecting your $HOME from the agent's
 * FILE TOOLS is one function in this file, while the boundary protecting it from the agent's
 * COMMANDS is the kernel's. Read that function. It is short on purpose.
 *
 * gondolin resolves an absolute path that falls outside the workspace onto the guest's own root,
 * which is harmless in a VM. Here it is refused instead: there is no second filesystem to land on.
 */

import path from "node:path";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
	type BashOperations,
	createBashTool,
	createEditTool,
	createFindTool,
	createGrepTool,
	createLsTool,
	createReadTool,
	createWriteTool,
	type EditOperations,
	type FindOperations,
	type GrepOperations,
	type LsOperations,
	type ReadOperations,
	type WriteOperations,
} from "@earendil-works/pi-coding-agent";
import { Sandbox } from "kern-sandbox";

/** Where the kern SDK mounts the workspace inside every box (`kern-sandbox`'s own constant). */
const GUEST_WORKSPACE = "/workspace";

/** Knobs, all optional. Deliberately env vars rather than a config file: an extension a user drops in
 * with `pi -e` should need nothing else, and the two that matter are the image and egress. */
const IMAGE = process.env.KERN_PI_IMAGE ?? "python:3.12-slim";
const MEMORY_MB = intFromEnv("KERN_PI_MEMORY_MB", 2048);
const PIDS = intFromEnv("KERN_PI_PIDS", 512);
const TIMEOUT_S = intFromEnv("KERN_PI_TIMEOUT", 120);
/** Cap on captured stdout and stderr, EACH, per command. The SDK's own default is 64 MiB, and this
 * lowers it by two orders of magnitude on purpose: `onData` forwards every chunk into pi's renderer
 * as it arrives, pi is single-threaded, and the agent picks the command. `yes` or
 * `cat /dev/urandom` is the same premise as the glob that took 149 seconds, with the output as the
 * lever instead of the pattern. pi truncates tool output for the model anyway, so the bytes above
 * this are spent rendering something nobody reads. Measured: the timeout does kill the process in the
 * box rather than merely stop reading it, so the cap bounds the burst and the deadline ends it. */
const MAX_OUTPUT = intFromEnv("KERN_PI_MAX_OUTPUT", 1024 * 1024);
/** Comma-separated hosts the box may reach, e.g. "registry.npmjs.org,pypi.org". Empty = no network.
 * NOT a boolean: `network: true` would share the host's whole network on every command, and an agent
 * that needs one registry does not need that. */
const EGRESS = (process.env.KERN_PI_EGRESS ?? "")
	.split(",")
	.map((s) => s.trim())
	.filter(Boolean);

function intFromEnv(name: string, fallback: number): number {
	const raw = process.env[name];
	if (raw === undefined) return fallback;
	const n = Number.parseInt(raw, 10);
	return Number.isFinite(n) && n > 0 ? n : fallback;
}


/**
 * THE SIDE THAT REFUSED IS PART OF THE MESSAGE.
 *
 * Six verbs fail with box-side errors and two with host-side ones, and until now the agent saw both
 * and could not tell which spoke. That is the same defect as kern's `--memory` hint and the `126`
 * message: a reader sent to the wrong place. `ENOENT: /workspace/x` says nothing about whether the
 * box could not find it, the workspace refused it, or this extension declined to look.
 *
 * Three sides, and every throw in this file names one:
 *   `kern[gate]` this extension refused before anything ran, from the path alone
 *   `kern[box]`  a command in the box answered, or the box could not do it
 *   `kern[host]` the SDK's host-side guard refused, or a host syscall failed
 *
 * pi renders the message to the model, so the prefix is the only channel that survives to the reader.
 */
type Side = "gate" | "box" | "host";

function refuse(side: Side, message: string): Error {
	return new Error(`kern[${side}]: ${message}`);
}

/** Wrap an SDK or syscall failure so the host side is named, keeping the original text. */
function fromHost(e: unknown, what: string): Error {
	const msg = e instanceof Error ? e.message : String(e);
	return refuse("host", `${what}: ${msg}`);
}

/**
 * THE CONTAINMENT CHECK. Every path from pi passes through here, and nothing else in this file
 * touches the filesystem without it.
 *
 * pi hands us absolute GUEST paths because each tool is built with `GUEST_WORKSPACE` as its cwd, so
 * `/workspace/src/main.rs` arrives and `src/main.rs` is what the SDK and the host both want.
 *
 * Refused, rather than clamped or remapped:
 *   - anything not under /workspace (`/etc/passwd`, `/workspace/../etc/passwd`)
 *   - a relative path, which would mean pi's cwd is not what we configured and the caller and this
 *     function disagree about the frame of reference. Guessing which one is right is how an escape
 *     gets written.
 *
 * `path.posix.resolve` collapses `..` BEFORE the prefix test, so `/workspace/../etc` is normalised to
 * `/etc` and then refused. Testing the raw string would pass it.
 */
export function refuseOutsideWorkspace(absolutePath: string): string {
	const raw = absolutePath.trim();
	if (!path.posix.isAbsolute(raw)) {
		throw refuse("gate", `refusing a relative path from the agent: ${absolutePath}`);
	}
	const resolved = path.posix.resolve(raw);
	if (resolved === GUEST_WORKSPACE) return "";
	if (!resolved.startsWith(`${GUEST_WORKSPACE}/`)) {
		throw refuse(
			"gate",
			`refusing a path outside ${GUEST_WORKSPACE}: ${absolutePath}\n` +
				`The box cannot see it and neither will these tools. Start pi from the directory you want the agent to work in.`,
		);
	}
	return resolved.slice(GUEST_WORKSPACE.length + 1);
}

/** The guest absolute path for a workspace-relative one. Every verb below that the SDK has no method
 * for is answered by running a command IN THE BOX with this path, so containment is the kernel's.
 *
 * WHY NOT THE HOST. The first version answered `access`, `exists`, `stat`, `readdir`, `mkdir` and
 * `isDirectory` with `node:fs` on `path.join(workspace, rel)`, and that is a hole, not a race:
 * `path.join` resolves nothing, so a symlink at an INTERMEDIATE component is followed. Measured, with
 * `dir -> /etc` planted in the workspace:
 *
 *     readdir("/workspace/dir")        ->  .pwd.lock, .resolv.conf, ...   the host's /etc
 *     exists("/workspace/dir/passwd")  ->  true
 *     mkdir("/workspace/dir/pwned")    ->  CREATED, outside the workspace
 *
 * `O_NOFOLLOW` does not close it: it refuses only a final component that is a link, and every
 * component above is still followed. The earlier `mkdir` test passed only because `/etc` is not
 * writable by the user running it; against a writable victim directory it wrote outside.
 *
 * Resolving with `realpath` and testing the prefix would close the STATIC hole and leave a TOCTOU
 * window, because the agent drives `bash` in the box against the same inodes and can swap a component
 * between the resolution and the syscall. Node exposes no `openat2(RESOLVE_BENEATH)` and no `openat`,
 * so the walk that would be atomic cannot be written here at all.
 *
 * Running the verb in the box removes the class instead of narrowing it: the box has no view of the
 * host outside /workspace, so a symlink pointing out of it resolves inside the box's own rootfs and
 * there is nothing to leak. `readFile`/`writeFile` stay on the SDK, which does the component-by-
 * component descent itself and refuses with "path escapes the workspace via a symlinked directory". */
function guestPath(rel: string): string {
	return rel ? `${GUEST_WORKSPACE}/${rel}` : GUEST_WORKSPACE;
}

/**
 * Resolve a workspace-relative path INSIDE the box: is it beneath /workspace, does it exist, and is
 * it a directory. One call, because `ls` asks all three about the same path.
 *
 * PORTABLE ON PURPOSE, and this was a defect. The first version used `realpath -e` and
 * `find -printf`, which are GNU findutils and coreutils. On BusyBox, which is what every Alpine image
 * ships, `find -printf` exits 1 and `realpath` prints the right answer and STILL exits 1, so every
 * verb that went through it reported "no such directory" for a directory that has files. Measured on
 * `python:3.12-alpine` and `alpine:latest`, and the default image being Debian is not a defence: the
 * image is the caller's choice and the Jetson run in this repo's own notes used Alpine.
 *
 * `readlink -f` and `find -print0` are in both. The script takes the path as a POSITIONAL argument,
 * so nothing derived from the agent is ever interpolated into the text of a shell command.
 *
 * WHAT THE CONTAINMENT ACTUALLY IS. The prefix test below is a DIAGNOSTIC, not the boundary. The
 * boundary is the box's mount namespace: it has no view of the host outside /workspace, so a symlink
 * pointing out of the workspace resolves inside the box's own rootfs and there is nothing to reach.
 * That distinction matters for whoever reads this next: moving one of these verbs back to the host
 * for speed would keep the prefix test and lose the boundary, which is exactly the hole this
 * replaced.
 */
const PROBE = [
	'p=$(readlink -f -- "$1") || exit 2',
	'case "$p" in /workspace|/workspace/*) ;; *) exit 3 ;; esac',
	'printf %s "$p"',
	'[ -e "$p" ] || exit 4',
	'[ -d "$p" ] && exit 0',
	"exit 1",
].join("\n");

type Probe = { resolved: string; exists: boolean; isDir: boolean };

async function probeInBox(box: Sandbox, rel: string): Promise<Probe | null> {
	const r = await box.run(["sh", "-c", PROBE, "_", guestPath(rel)]);
	if (r.fault !== null) return null;
	if (r.exitCode === 2 || r.exitCode === 3) return null; // unresolvable, or outside the workspace
	const resolved = r.stdout.trim();
	if (resolved !== GUEST_WORKSPACE && !resolved.startsWith(`${GUEST_WORKSPACE}/`)) return null;
	if (r.exitCode === 4) return { resolved, exists: false, isDir: false };
	return { resolved, exists: true, isDir: r.exitCode === 0 };
}

/** Resolved path if it is beneath the workspace AND exists, else null. */
async function resolveInBox(box: Sandbox, rel: string): Promise<string | null> {
	const p = await probeInBox(box, rel);
	return p && p.exists ? p.resolved : null;
}

/**
 * For `mkdir -p`, where the path does not exist yet and NEITHER DOES ITS PARENT. `readlink -f` needs
 * every component but the last, so `/workspace/a/b/c` on an empty workspace fails outright and the
 * first version of this refused every legitimate nested mkdir.
 *
 * Walks up to the nearest component that DOES exist and resolves that. If the nearest existing
 * ancestor is beneath the workspace, everything `mkdir -p` then creates is beneath it too. And a
 * symlink pointing out of the workspace EXISTS, so the walk stops on it and the prefix test refuses:
 * `mkdir -p /workspace/link-to-etc/x` is rejected rather than followed. */
const MKDIR_PROBE = [
	'p="$1"',
	'while [ ! -e "$p" ] && [ "$p" != "/" ]; do p=$(dirname "$p"); done',
	'r=$(readlink -f -- "$p") || exit 2',
	'case "$r" in /workspace|/workspace/*) ;; *) exit 3 ;; esac',
	'printf %s "$r"',
].join("\n");

async function resolveMissingInBox(box: Sandbox, rel: string): Promise<string | null> {
	const r = await box.run(["sh", "-c", MKDIR_PROBE, "_", guestPath(rel)]);
	if (r.fault !== null || r.exitCode !== 0) return null;
	const anc = r.stdout.trim();
	if (anc !== GUEST_WORKSPACE && !anc.startsWith(`${GUEST_WORKSPACE}/`)) return null;
	return guestPath(rel); // the ancestor is inside, so the path mkdir -p will build is too
}

/** Run one short command in the box and report only whether it succeeded. */
async function boxTest(box: Sandbox, argv: string[]): Promise<boolean> {
	const r = await box.run(argv);
	return r.exitCode === 0 && r.fault === null;
}

// ---------------------------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------------------------

/**
 * The MIME type of an image, from its MAGIC BYTES rather than its extension.
 *
 * pi's read tool needs this to hand an image to the model as an image instead of as bytes, and it is
 * optional in the interface, so leaving it out silently downgrades every screenshot in the project to
 * garbage text. Sniffing beats trusting the name: a `.png` that is really a JPEG would be described
 * wrongly to the model, and an agent renaming a file cannot change what it is.
 *
 * Only the four formats pi itself resizes. Anything else returns null, which is the interface's way
 * of saying "not an image", and the read tool falls back to its normal path.
 */
export async function detectImageMimeType(ws: string, rel: string): Promise<string | null> {
	// NOT `box.readFile(rel, { maxBytes: 16 })`. In the SDK `maxBytes` is a REFUSAL threshold, not a
	// partial read: a file larger than it throws rather than returning its head. The first version
	// here did exactly that and the catch below swallowed the error, so every image over 16 bytes
	// reported "not an image" in silence. A bounded host read is what a sniff wants, and reading a
	// whole 5 MB PNG to look at eight bytes is what the alternative costs.
	//
	// The containment the SDK would have applied is re-applied here rather than assumed: the caller
	// has already run [[refuseOutsideWorkspace]] on the guest path, which stops `..`, and realpath
	// plus a prefix test stops a symlinked DIRECTORY component, which a path check alone does not.
	// O_NOFOLLOW then stops the final component being a link.
	let head: Buffer;
	try {
		const wsReal = fs.realpathSync(ws);
		const target = fs.realpathSync(path.join(wsReal, rel));
		// Outside the workspace: not an image we are allowed to look at, which IS "not an image"
		// as far as every tool here is concerned. Not a swallowed failure.
		if (target !== wsReal && !target.startsWith(wsReal + path.sep)) return null;
		const fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
		try {
			// POST-OPEN, and this is the last host-side surface in the file. `realpath` then open-by-path
			// is resolve-then-use: between the two, a component of `target` can become a symlink and the
			// open follows it. `O_NOFOLLOW` covers the leaf only. Asking the KERNEL where the descriptor
			// landed closes it, because the fd is bound at open time and cannot be redirected afterwards.
			//
			// It is the SDK's own construction, and measured independently sufficient: with the SDK's
			// pre-walk disabled and this check alone, 7,684 concurrent swaps produced 598,321 refusals
			// and zero host bytes. Copied rather than invented for that reason.
			const landed = fs.readlinkSync(`/proc/self/fd/${fd}`);
			if (landed !== wsReal && !landed.startsWith(wsReal + path.sep)) return null;
			head = Buffer.alloc(16);
			const n = fs.readSync(fd, head, 0, 16, 0);
			head = head.subarray(0, n);
		} finally {
			fs.closeSync(fd);
		}
	} catch (e) {
		// NARROW, because `null` here means "not an image" and the caller cannot tell that apart from
		// "we could not look". Swallowing everything is how `maxBytes` produced a valid-looking answer
		// for every screenshot in a project: a catch may turn an error into a DIFFERENT error, never
		// into a value indistinguishable from success.
		//
		// The three below are cases where "not an image" is the TRUE answer, so null is not a guess:
		// the path is gone, it is a directory, or a component of it is not one. Everything else
		// (EACCES, EIO, a bad descriptor) is a failure to look, and the read tool that is about to
		// open the same file should hear about it now rather than be told there is no picture.
		const code = (e as NodeJS.ErrnoException)?.code;
		if (code === "ENOENT" || code === "EISDIR" || code === "ENOTDIR" || code === "ELOOP") return null;
		throw e;
	}
	if (head.length >= 8 && head.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
		return "image/png";
	}
	if (head.length >= 3 && head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) return "image/jpeg";
	if (head.length >= 6 && head.subarray(0, 6).toString("latin1").match(/^GIF8[79]a$/)) return "image/gif";
	if (
		head.length >= 12 &&
		head.subarray(0, 4).toString("latin1") === "RIFF" &&
		head.subarray(8, 12).toString("latin1") === "WEBP"
	) {
		return "image/webp";
	}
	return null;
}


/**
 * Read a workspace file WITHOUT the possibility of blocking, and without following anything out.
 *
 * `box.readFile` ends in `fs.readFileSync`, which on a FIFO blocks in the kernel forever. Measured:
 * an agent runs `mkfifo /workspace/pipe`, pi calls `read` on it, and the node process never returns.
 * Not slow, DEAD, and no JavaScript deadline can save it: the event loop is inside the syscall, so
 * the `setTimeout` meant to catch it never runs either. One command from the agent ends the session.
 *
 * Four properties, in the order they are established:
 *   O_NONBLOCK  opening a FIFO returns a descriptor instead of waiting for a writer
 *   O_NOFOLLOW  a symlink AT the leaf is refused by the kernel
 *   fstat       a descriptor that is not a REGULAR file is refused: FIFO, device, socket, directory
 *   /proc/self/fd  where the descriptor actually landed, which is race-free because the fd is bound
 *
 * The last one replaces the SDK's pre-open component walk rather than adding to it, and that is a
 * measured choice: with the SDK's walk disabled and this check alone, 7,684 concurrent swaps of an
 * intermediate component produced 598,321 refusals and zero host bytes.
 */
function readWorkspaceFile(ws: string, rel: string, abs: string): Buffer {
	let wsReal: string;
	try {
		wsReal = fs.realpathSync(ws);
	} catch (e) {
		throw fromHost(e, `cannot resolve the workspace`);
	}
	const target = rel ? path.join(wsReal, rel) : wsReal;
	let fd: number;
	try {
		fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
	} catch (e) {
		throw fromHost(e, `cannot read ${abs}`);
	}
	try {
		const landed = fs.readlinkSync(`/proc/self/fd/${fd}`);
		if (landed !== wsReal && !landed.startsWith(wsReal + path.sep)) {
			throw refuse("host", `refusing ${abs}: the open landed outside the workspace`);
		}
		const st = fs.fstatSync(fd);
		if (!st.isFile()) {
			throw refuse("host", `refusing ${abs}: not a regular file (a FIFO, device or socket would block the read)`);
		}
		return fs.readFileSync(fd);
	} finally {
		fs.closeSync(fd);
	}
}

export function kernReadOps(box: Sandbox, ws: string): ReadOperations {
	return {
		readFile: async (abs) => readWorkspaceFile(ws, refuseOutsideWorkspace(abs), abs),
		access: async (abs) => {
			if ((await resolveInBox(box, refuseOutsideWorkspace(abs))) === null) {
				throw refuse("box", `no such path in the box: ${abs}`);
			}
		},
		detectImageMimeType: async (abs) => detectImageMimeType(ws, refuseOutsideWorkspace(abs)),
	};
}

/**
 * Write through a flat temporary name in the workspace ROOT, then place it with `mv` inside the box.
 *
 * WHY NOT `box.writeFile(rel, content)` DIRECTLY, which is what this was. The SDK's write path walks
 * the parent components and MKDIRS the missing ones, so it mutates between its own observations:
 * it validates component k, then creates k+1 inside whatever k has become. It has one guard where
 * the read path has two, and that guard is load-bearing rather than redundant. Measured: with
 * `_ensureParentDirs` disabled, a stable symlinked component and a REACHABLE victim, the write lands
 * outside the workspace.
 *
 * A parent that IS the workspace root makes that walk return immediately: no components, no mkdir,
 * no window. The path construction then happens in the box, where containment is the mount namespace
 * rather than a host-side check racing the agent's own `bash`.
 *
 * TWO THINGS HOLD THIS UP AND BOTH ARE DELIBERATE.
 *
 * 128 bits of entropy in the name. With the parent walk gone the leaf is the whole surface, and the
 * SDK opens it `O_CREAT|O_TRUNC|O_NOFOLLOW`: a planted SYMLINK is refused (verified, ELOOP), a
 * planted REGULAR file at the same name would be truncated rather than refused. `O_EXCL` would turn
 * that into an error and belongs in the SDK; until it is there, guessing the name is the only way in
 * and 128 bits is not guessable. The name is not derived from the target, so it carries nothing.
 *
 * `mv` within one mount is a rename and therefore atomic. `/workspace` is a single bind mount, so
 * temp and target are always on it. A future reader who moves the temp to `/tmp` inside the box
 * turns the rename into copy-then-unlink and loses that silently. */
export function kernWriteOps(box: Sandbox): WriteOperations {
	return {
		writeFile: async (abs, content) => {
			const rel = refuseOutsideWorkspace(abs);
			if (!rel) throw refuse("gate", `refusing to write to the workspace root itself: ${abs}`);
			const target = await resolveMissingInBox(box, rel);
			if (target === null) throw refuse("box", `refusing to write ${abs}: in the box it resolves outside ${GUEST_WORKSPACE}`);
			const tmp = `.kern-pi.${randomBytes(16).toString("hex")}`;
			try {
				await box.writeFile(tmp, content);
			} catch (e) {
				throw fromHost(e, `cannot stage ${abs}`);
			}
			const placed = await box.run([
				"sh",
				"-c",
				'mkdir -p -- "$(dirname "$2")" && mv -f -- "$1" "$2"',
				"_",
				guestPath(tmp),
				target,
			]);
			if (placed.exitCode !== 0 || placed.fault !== null) {
				await box.run(["rm", "-f", "--", guestPath(tmp)]); // no orphan on a failed placement
				throw refuse("box", `could not place ${abs}: the rename inside the box failed`);
			}
		},
		mkdir: async (dir) => {
			const rel = refuseOutsideWorkspace(dir);
			if (!rel) return; // the workspace itself always exists
			const target = await resolveMissingInBox(box, rel);
			if (target === null) throw refuse("box", `refusing to create ${dir}: in the box it resolves outside ${GUEST_WORKSPACE}`);
			if (!(await boxTest(box, ["mkdir", "-p", "--", target]))) {
				throw refuse("box", `could not create ${dir} inside the box`);
			}
		},
	};
}

export function kernEditOps(box: Sandbox, ws: string): EditOperations {
	const r = kernReadOps(box, ws);
	const w = kernWriteOps(box);
	return {
		readFile: (abs) => r.readFile(abs),
		writeFile: (abs, content) => w.writeFile(abs, content),
		access: (abs) => r.access(abs),
	};
}

export function kernLsOps(box: Sandbox): LsOperations {
	return {
		exists: async (abs) => (await resolveInBox(box, refuseOutsideWorkspace(abs))) !== null,
		stat: async (abs) => {
			const p = await probeInBox(box, refuseOutsideWorkspace(abs));
			return { isDirectory: () => p !== null && p.exists && p.isDir };
		},
		readdir: async (abs) => {
			// The TYPE is checked, not just existence. `find <file> -maxdepth 1 -mindepth 1` exits 0
			// with no output, so without this a `readdir` on a regular file returned an empty array and
			// the agent was told a file is an empty directory. Silently returning nothing is the shape
			// this whole file exists to avoid, and `probeInBox` already knows the answer.
			const p = await probeInBox(box, refuseOutsideWorkspace(abs));
			if (p === null || !p.exists) throw refuse("box", `no such path in the box: ${abs}`);
			if (!p.isDir) throw refuse("box", `not a directory in the box: ${abs}`);
			return boxReaddir(box, p.resolved);
		},
	};
}

export function kernGrepOps(box: Sandbox, ws: string): GrepOperations {
	return {
		isDirectory: async (abs) => {
			const p = await probeInBox(box, refuseOutsideWorkspace(abs));
			return p !== null && p.exists && p.isDir;
		},
		readFile: async (abs) => readWorkspaceFile(ws, refuseOutsideWorkspace(abs), abs).toString("utf8"),
	};
}

export function kernFindOps(box: Sandbox): FindOperations {
	return {
		exists: async (abs) => (await resolveInBox(box, refuseOutsideWorkspace(abs))) !== null,
		glob: async (pattern, cwd, options) => {
			// `listFiles` walks the workspace and already excludes `.deps`, so the enumeration is
			// bounded by the workspace rather than by whatever the pattern expands to. Matching
			// happens here so an agent-supplied pattern is never handed to a shell.
			const base = refuseOutsideWorkspace(cwd);
			const files = await box.listFiles(base);
			const ignores = options?.ignore ?? [];
			const out: string[] = [];
			for (const f of files) {
				const rel = base ? `${base}/${f.path}` : f.path;
				if (!globMatches(pattern, f.path) && !globMatches(pattern, rel)) continue;
				if (ignores.some((ig) => globMatches(ig, rel))) continue;
				out.push(path.posix.join(GUEST_WORKSPACE, rel));
				if (out.length >= (options?.limit ?? 100)) break;
			}
			return out;
		},
	};
}

/** One directory's entries, NUL-separated so a filename containing a newline survives the round trip.
 * `ls` would split such a name into two entries.
 *
 * `-print0` rather than `-printf %f\0`: the second is GNU-only and exits 1 on BusyBox, so the prefix
 * is stripped here instead. The binding's own scratch file is dropped for the same reason
 * `Sandbox.listFiles` drops it: it is this library's, not the user's, and an agent that sees it will
 * ask about it. */
/**
 * Is this name the BINDING's, rather than the user's?
 *
 * `Sandbox.listFiles` already excludes it, and the first version of `boxReaddir` re-stated the
 * prefix instead of asking. That is a duplicated policy: the next time the scratch file is renamed,
 * `listFiles` follows the rename and this does not, and the agent starts seeing a file that is not
 * the user's. One predicate, and the SDK's own constant is the source when it is reachable.
 *
 * It is still a copy of a string the SDK owns. The right shape is for the SDK to export the
 * predicate; until it does, this is the single place that knows, and it is named so a grep for the
 * prefix finds it. */
function isBindingScratch(name: string): boolean {
	// Mirrors the SDK's own predicate exactly, INCLUDING the bare name. The first version here wrote
	// only the dotted prefix and had already diverged: `.kern-env` with no suffix is the SDK's and
	// this would have shown it to the agent. And the trailing dot is not decoration, it is the SDK's
	// own note: a user file called `.kern-environment` is theirs, so a bare startsWith would steal it.
	return name === ".kern-env" || name.startsWith(".kern-env.");
}

async function boxReaddir(box: Sandbox, guest: string): Promise<string[]> {
	const r = await box.run(["find", guest, "-maxdepth", "1", "-mindepth", "1", "-print0"]);
	if (r.exitCode !== 0 || r.fault !== null) throw refuse("box", `cannot list ${guest}: not a directory, or gone`);
	const prefix = guest === "/" ? "/" : `${guest}/`;
	return r.stdout
		.split("\0")
		.filter((s) => s.length > 0)
		.map((s) => (s.startsWith(prefix) ? s.slice(prefix.length) : s))
		.filter((n) => n.length > 0 && !isBindingScratch(n));
}

/**
 * Does `candidate` (a workspace-relative POSIX path) match `glob`?
 *
 * NOT a RegExp, and the reason is measured. The first version compiled the glob into an anchored
 * regex, which turns `a*` repeated sixty times into `(a[^/]*){60}b` and makes a match against four
 * hundred `a`s take **149 SECONDS** of catastrophic backtracking. The glob comes from the agent, node
 * is single-threaded, and pi's whole session shares this event loop: that is a denial of service the
 * agent chooses, not a slow function.
 *
 * This is the classic two-pointer wildcard match instead, which never backtracks more than once per
 * star and is O(n*m) in the worst case rather than exponential. Semantics unchanged:
 *
 *   `**`  crosses `/` (matches whole path segments, including none)
 *   `*`   does not cross `/`
 *   `?`   exactly one non-`/` character
 *   everything else is literal, including every regex metacharacter
 */
export function globMatches(glob: string, candidate: string): boolean {
	return matchSegments(glob.split("/"), candidate.split("/"), 0, 0);
}

/** Segment-wise, so `**` is the only thing that can consume a `/`. Recursion depth is bounded by the
 * number of `**` in the pattern, not by the length of either string. */
function matchSegments(pat: string[], seg: string[], pi: number, si: number): boolean {
	while (pi < pat.length) {
		if (pat[pi] === "**") {
			// `**` matches zero or more segments. Try the shortest first so the common case where it
			// stands at the end returns immediately.
			for (let skip = si; skip <= seg.length; skip++) {
				if (matchSegments(pat, seg, pi + 1, skip)) return true;
			}
			return false;
		}
		if (si >= seg.length) return false;
		if (!matchOneSegment(pat[pi], seg[si])) return false;
		pi++;
		si++;
	}
	return si === seg.length;
}

/** One segment against one segment. `*` and `?` here cannot cross a separator because neither string
 * contains one. Two pointers, one remembered star: no recursion, no backtracking blow-up. */
function matchOneSegment(pat: string, s: string): boolean {
	let p = 0;
	let i = 0;
	let starP = -1;
	let starI = 0;
	while (i < s.length) {
		const c = pat[p];
		if (p < pat.length && (c === "?" || c === s[i])) {
			p++;
			i++;
		} else if (p < pat.length && c === "*") {
			starP = p++;
			starI = i;
		} else if (starP >= 0) {
			// The last star eats one more character. This is the ONLY backtrack, and it advances, so
			// the loop runs at most once per position of `s`.
			p = starP + 1;
			i = ++starI;
		} else {
			return false;
		}
	}
	while (p < pat.length && pat[p] === "*") p++;
	return p === pat.length;
}

/**
 * `exec` is the half that actually crosses into the box.
 *
 * pi STREAMS: output arrives through `onData(Buffer)` and the return value carries only the exit
 * code. The SDK's `onStdout`/`onStderr` are the same shape, so both streams are forwarded as they
 * arrive rather than buffered and handed over at the end.
 *
 * `cwd` is honoured by prefixing a `cd`, because each call is a FRESH box: there is no shell to keep
 * a working directory in between calls. `cwd` is validated like every other path.
 *
 * A sandbox fault (timeout, OOM, a blocked syscall) is reported on the stream and mapped to a
 * non-zero exit rather than thrown: pi renders a failed command, and an agent that sees "killed by
 * the sandbox" can react, where an exception would abort the turn.
 */
export function kernBashOps(box: Sandbox): BashOperations {
	return {
		exec: async (command, cwd, { onData, signal, timeout, env }) => {
			if (signal?.aborted) throw new Error("aborted");
			const rel = refuseOutsideWorkspace(cwd);

			// `timeout` is SECONDS. Read off gondolin's `setTimeout(..., timeout * 1000)` rather than
			// guessed: the first draft here divided by 1000 and turned pi's 120 s default into one
			// second, which every command would have hit.
			const timeoutS = timeout && timeout > 0 ? timeout : undefined;

			// Each call is a FRESH box, so there is no shell holding a working directory or an
			// environment between calls: both are re-established in the script. `env` carries pi's
			// PI_* session variables, which an agent's command is meant to see.
			const prelude: string[] = [];
			if (rel) prelude.push(`cd ${shellQuote(`${GUEST_WORKSPACE}/${rel}`)}`);
			for (const [k, v] of Object.entries(env ?? {})) {
				if (typeof v !== "string") continue;
				if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) continue; // a name a shell cannot parse is not exported
				prelude.push(`export ${k}=${shellQuote(v)}`);
			}
			const script = prelude.length > 0 ? `${prelude.join(" && ")} && ${command}` : command;

			// pi cancels a running command through `signal`. The SDK has no abort, so the box is left
			// to its own deadline and the promise is abandoned: the caller is told at once, which is
			// what pi renders, and the box dies on its `timeoutS` rather than living forever. Stated
			// because it is a real difference from gondolin, which aborts the guest process itself.
			// The listener is REMOVED when the call finishes, not left to the signal's own lifetime.
			// pi hands a fresh AbortSignal per tool call so an accumulation would be bounded, but a
			// caller that reuses one grows the heap by about 32 KB per call, measured over 400.
			let onAbort: (() => void) | undefined;
			const aborted = new Promise<never>((_resolve, reject) => {
				if (!signal) return;
				onAbort = () => reject(new Error("aborted"));
				signal.addEventListener("abort", onAbort, { once: true });
			});

			// THE FORWARDING IS WHAT NEEDS THE CAP, not the capture. `maxOutputBytes` bounds what the
			// SDK keeps in `result.stdout`; `onStdout` still fires for every chunk. Measured with a 1
			// MiB cap set and `yes` running for six seconds: 524 MB arrived here and went straight into
			// pi's renderer. So the counter is here, and past the cap the chunks are dropped rather
			// than forwarded. One notice, then silence: repeating it per chunk would be the flood.
			let forwarded = 0;
			let noticed = false;
			const forward = (chunk: Buffer) => {
				if (forwarded >= MAX_OUTPUT) {
					if (!noticed) {
						noticed = true;
						onData(Buffer.from(`\n[kern: output past ${MAX_OUTPUT} bytes is not shown]\n`));
					}
					return;
				}
				forwarded += chunk.length;
				onData(chunk);
			};

			const run = box.runCode(script, {
				language: "bash",
				timeoutS,
				onStdout: forward,
				onStderr: forward,
			});

			// `Promise.race` attaches a handler to BOTH, so an abort arriving after the command has
			// already finished is handled by the race rather than becoming an unhandled rejection.
			// Verified rather than assumed: a late abort on a completed call emits nothing.
			let r: Awaited<typeof run>;
			try {
				r = signal ? await Promise.race([run, aborted]) : await run;
			} finally {
				if (signal && onAbort) signal.removeEventListener("abort", onAbort);
			}

			// A sandbox timeout is reported the way pi's own local operations report it, so the message
			// the agent reads is the same wherever the command ran.
			if (r.fault?.type === "timeout" && timeoutS) throw new Error(`timeout:${timeoutS}`);
			if (r.fault) {
				onData(Buffer.from(`\n[kern: ${r.fault.type}] ${r.fault.message}\n`));
				return { exitCode: r.exitCode === 0 ? 1 : r.exitCode };
			}
			return { exitCode: r.exitCode };
		},
	};
}

/** Single-quote for `sh`. Only ever applied to a path this file produced, never to agent text. */
function shellQuote(s: string): string {
	return `'${s.replace(/'/g, `'\\''`)}'`;
}

// ---------------------------------------------------------------------------------------------
// Extension entry point
// ---------------------------------------------------------------------------------------------

export default function (pi: ExtensionAPI) {
	const hostWorkspace = process.cwd();

	// Built once against the HOST cwd, only for their metadata: name, description, schema, prompt
	// snippet. The execute() below replaces the behaviour with a box-backed tool built against
	// GUEST_WORKSPACE, which is the pattern the gondolin example uses.
	const localRead = createReadTool(hostWorkspace);
	const localWrite = createWriteTool(hostWorkspace);
	const localEdit = createEditTool(hostWorkspace);
	const localBash = createBashTool(hostWorkspace);
	const localGrep = createGrepTool(hostWorkspace);
	const localFind = createFindTool(hostWorkspace);
	const localLs = createLsTool(hostWorkspace);

	let box: Sandbox | undefined;
	let opening: Promise<Sandbox> | undefined;

	/** Opened on the first tool call, not at activation: a user who loads the extension and then
	 * asks a question that needs no tool should not pay an image pull. */
	async function ensureBox(ctx?: ExtensionContext): Promise<Sandbox> {
		if (box) return box;
		if (!opening) {
			opening = (async () => {
				ctx?.ui.setStatus("kern", ctx.ui.theme.fg("accent", `kern: opening ${IMAGE}`));
				const sbx = new Sandbox({
					image: IMAGE,
					workspace: hostWorkspace, // NOT deleted on close: the SDK only removes what it created
					memoryMb: MEMORY_MB,
					pids: PIDS,
					timeoutS: TIMEOUT_S,
					maxOutputBytes: MAX_OUTPUT,
					...(EGRESS.length > 0 ? { egressAllow: EGRESS } : {}),
					trackFiles: false, // pi reports its own file changes; skip the per-call workspace diff
				});
				await sbx.open();
				box = sbx;
				ctx?.ui.setStatus("kern", ctx.ui.theme.fg("muted", `kern: ${IMAGE}`));
				return sbx;
			})().catch((e) => {
				opening = undefined; // a failed open must not poison every later call
				throw e;
			});
		}
		return opening;
	}

	pi.registerTool({
		...localBash,
		async execute(id, params, signal, onUpdate, ctx) {
			const b = await ensureBox(ctx);
			const tool = createBashTool(GUEST_WORKSPACE, { operations: kernBashOps(b) });
			return tool.execute(id, params, signal, onUpdate);
		},
	});

	pi.registerTool({
		...localRead,
		async execute(id, params, signal, onUpdate, ctx) {
			const b = await ensureBox(ctx);
			const tool = createReadTool(GUEST_WORKSPACE, { operations: kernReadOps(b, hostWorkspace) });
			return tool.execute(id, params, signal, onUpdate);
		},
	});

	pi.registerTool({
		...localWrite,
		async execute(id, params, signal, onUpdate, ctx) {
			const b = await ensureBox(ctx);
			const tool = createWriteTool(GUEST_WORKSPACE, { operations: kernWriteOps(b) });
			return tool.execute(id, params, signal, onUpdate);
		},
	});

	pi.registerTool({
		...localEdit,
		async execute(id, params, signal, onUpdate, ctx) {
			const b = await ensureBox(ctx);
			const tool = createEditTool(GUEST_WORKSPACE, { operations: kernEditOps(b, hostWorkspace) });
			return tool.execute(id, params, signal, onUpdate);
		},
	});

	pi.registerTool({
		...localLs,
		async execute(id, params, signal, onUpdate, ctx) {
			const b = await ensureBox(ctx);
			const tool = createLsTool(GUEST_WORKSPACE, { operations: kernLsOps(b) });
			return tool.execute(id, params, signal, onUpdate);
		},
	});

	pi.registerTool({
		...localGrep,
		async execute(id, params, signal, onUpdate, ctx) {
			const b = await ensureBox(ctx);
			const tool = createGrepTool(GUEST_WORKSPACE, { operations: kernGrepOps(b, hostWorkspace) });
			return tool.execute(id, params, signal, onUpdate);
		},
	});

	pi.registerTool({
		...localFind,
		async execute(id, params, signal, onUpdate, ctx) {
			const b = await ensureBox(ctx);
			const tool = createFindTool(GUEST_WORKSPACE, { operations: kernFindOps(b) });
			return tool.execute(id, params, signal, onUpdate);
		},
	});

	// A `!command` the USER types, which is not a tool call and therefore does not go through any of
	// the registrations above. Without this hook it runs on the host with the user's own permissions,
	// so an extension that says it sandboxes pi would be covering the agent and not the operator.
	// This is the half of gondolin's "built-in tools AND ! commands" that is easy to miss.
	pi.on("user_bash", async (_event, ctx) => {
		const b = await ensureBox(ctx);
		return { operations: kernBashOps(b) };
	});

	// The box's supervisor process lives for the box's lifetime, so a session that ends without
	// closing leaves it until pi's own process exits. Cleared before awaiting `close()` so a second
	// shutdown, or a tool call racing it, opens a fresh box instead of using a closing one.
	pi.on("session_shutdown", async (_event, ctx) => {
		const active = box;
		box = undefined;
		opening = undefined;
		if (!active) return;
		ctx.ui.setStatus("kern", ctx.ui.theme.fg("muted", "kern: closing"));
		try {
			await active.close();
		} finally {
			ctx.ui.setStatus("kern", undefined);
		}
	});

	pi.registerCommand("kern", {
		description: "Show the kern box configuration",
		handler: async (_args, ctx) => {
			ctx.ui.notify(
				[
					`image:      ${IMAGE}`,
					`workspace:  ${hostWorkspace} -> ${GUEST_WORKSPACE}`,
					`caps:       ${MEMORY_MB} MiB, ${PIDS} pids, ${TIMEOUT_S}s`,
					`egress:     ${EGRESS.length > 0 ? EGRESS.join(", ") : "none (no network)"}`,
					`box open:   ${box ? "yes" : "no (opens on the first tool call)"}`,
					"",
					"bash and ! run inside the box. read/write/edit/ls/grep/find are host I/O",
					"confined to the workspace by a path check. See this extension's README.",
				].join("\n"),
			);
		},
	});
}
