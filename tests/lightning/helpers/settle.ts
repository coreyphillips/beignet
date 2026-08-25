/**
 * Predicate waits for the v2 opening suites (issue #400).
 *
 * These files used to carry four copies of a `settle(pred, ms)` (identical
 * but for their default deadline) that ran the deadline out and RETURNED, so
 * a predicate that never came true read as a pass and every assertion behind
 * such a wait was decorative. The two
 * intents that were sharing one name are now separate:
 *
 *  - `settle(pred, ms)` waits for something that must happen, and throws when
 *    the deadline passes without it.
 *  - `neverSettles(pred, ms)` waits out the whole window for something that
 *    must NOT happen, and throws if it does. This is the shape the silent
 *    timeout was being used for deliberately.
 *
 * Pick by what the assertion after the wait is claiming. A positive wait whose
 * predicate is ALREADY true when it is called does no waiting at all, so it
 * gives the event the following assertion cares about no chance to fire. If
 * the point is "and nothing else happened", that is a `neverSettles` on the
 * thing that must not happen, not a `settle` on the thing that already holds.
 */

/**
 * The most tolerant of the four defaults the copies carried (2000/3000/5000).
 * A positive wait returns the moment its predicate holds, so a generous
 * deadline only buys patience on a loaded machine; it is paid in full only by
 * a wait that was going to fail. `neverSettles` takes no default: that window
 * is burned on EVERY run, so each site states how long it is worth holding.
 */
const DEFAULT_MS = 5000;

/**
 * Poll `pred` until it holds or `ms` elapses; true if it held.
 *
 * Two phases on purpose. The first 25 ms drain the microtask and immediate
 * queues at full speed, so a predicate that only needs the pending promise
 * callbacks (the funding provider's async input selection, a storage write's
 * continuation) resolves with no added latency. After that it parks on a real
 * sleep: spinning on setImmediate for the WHOLE deadline held a core at 100%
 * until it expired, which under mocha --parallel is one pegged core per worker
 * for every wait that is expected to run out.
 */
async function poll(pred: () => boolean, ms: number): Promise<boolean> {
	const deadline = Date.now() + ms;
	const spinUntil = Math.min(deadline, Date.now() + 25);
	while (Date.now() < spinUntil) {
		if (pred()) return true;
		await new Promise((resolve) => setImmediate(resolve));
	}
	while (Date.now() < deadline) {
		if (pred()) return true;
		await new Promise((resolve) => setTimeout(resolve, 5));
	}
	// The last sleep can overshoot the deadline; check what it slept through.
	return pred();
}

/** The predicate's source, for a failure message that names what was awaited. */
function describePred(pred: () => boolean): string {
	const src = pred.toString().replace(/\s+/g, ' ').trim();
	return src.length > 160 ? `${src.slice(0, 157)}...` : src;
}

/**
 * Wait until `pred()` holds. Throws when `ms` elapses first, so a wait for
 * something that never happens fails the test rather than passing quietly.
 */
export async function settle(
	pred: () => boolean,
	ms = DEFAULT_MS
): Promise<void> {
	if (await poll(pred, ms)) return;
	throw new Error(
		`settle: predicate still false after ${ms}ms: ${describePred(pred)}`
	);
}

/**
 * Hold for the full `ms` and require `pred()` to stay false throughout, for the
 * waits that exist to give something that must NOT happen every chance to
 * happen. Throws the moment it does.
 */
export async function neverSettles(
	pred: () => boolean,
	ms: number
): Promise<void> {
	if (await poll(pred, ms)) {
		throw new Error(
			`neverSettles: predicate became true within ${ms}ms: ${describePred(
				pred
			)}`
		);
	}
}
