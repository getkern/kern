/**
 * The assertion harness both suites use.
 *
 * Extracted because it was eleven identical lines in two files, and duplicated test infrastructure
 * drifts the same way duplicated policy does: a fix to the reporting in one suite silently does not
 * apply to the other, and the two start disagreeing about what a failure looks like.
 *
 * ONE RULE THIS FILE ENFORCES BY CONVENTION, because being written down was not enough. A shell
 * pipeline reports the exit code of its LAST command, so `cmd | head` is 0 whatever `cmd` did. A
 * probe in this repo ran `apk add git | head -3; echo rc=$?` and reported `rc=0` for an apk that had
 * failed with `Read-only file system` - in the same session as the scenario documenting that hazard.
 * Any command here whose exit code is read after a pipe must start with `set -o pipefail`, and the
 * SDK suite carries the positive control that fails if the prefix stops working.
 *
 * It is NOT injected into the agent's own commands: `language="bash"` runs bash, and bash without
 * pipefail is what someone writing a pipeline expects.
 *
 * Deliberately not a framework. `node --experimental-strip-types <file>.ts` with no runner is what
 * makes these suites runnable by someone who has just cloned the repo and has no dev dependencies.
 */

let passed = 0;
let failed = 0;

export function ok(name: string, cond: boolean, detail = ""): void {
	if (cond) {
		passed++;
		console.log(`  PASS  ${name}`);
	} else {
		failed++;
		console.log(`  FAIL  ${name}${detail ? `  ${detail}` : ""}`);
	}
}

/** Refused = threw. Anything that RETURNS is a hole, and the returned value says how big. */
export async function throws(name: string, fn: () => unknown, matching?: RegExp): Promise<void> {
	try {
		await fn();
		ok(name, false, "did not throw");
	} catch (e) {
		const msg = e instanceof Error ? e.message : String(e);
		ok(name, matching ? matching.test(msg) : true, matching ? `message was: ${msg}` : "");
	}
}

/** Print the tally and exit non-zero on any failure, so a suite is usable as a gate. */
export function report(): never {
	console.log(`\n${passed} passed, ${failed} failed`);
	process.exit(failed === 0 ? 0 : 1);
}

/** A harness that dies mid-run is not a failing assertion, and must not be read as one.
 *
 * It still prints the tally first. A crash at assertion 57 used to report NOTHING, so the reader could
 * not tell whether 56 had passed or none had, and the exit code (2, distinct from a failing 1) was the
 * only signal that the run was incomplete. Both facts are worth having. */
export function fatal(e: unknown): never {
	console.log(`\n${passed} passed, ${failed} failed BEFORE the harness died (the run is INCOMPLETE)`);
	console.error("harness itself failed:", e);
	process.exit(2);
}
