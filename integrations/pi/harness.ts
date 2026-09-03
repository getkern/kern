/**
 * The assertion harness both suites use.
 *
 * Extracted because it was eleven identical lines in two files, and duplicated test infrastructure
 * drifts the same way duplicated policy does: a fix to the reporting in one suite silently does not
 * apply to the other, and the two start disagreeing about what a failure looks like.
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

/** A harness that dies mid-run is not a failing assertion, and must not be read as one. */
export function fatal(e: unknown): never {
	console.error("\nharness itself failed:", e);
	process.exit(2);
}
