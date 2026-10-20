/**
 * The daemon's route keys ("GET /info"), read from src/cli/daemon.ts source
 * for the drift tests (OpenAPI completeness, scope classification, CLI
 * parity), so a change to how routes are declared is mirrored in one place.
 */

import * as fs from 'fs';
import * as path from 'path';

let cachedKeys: ReadonlySet<string> | undefined;

/** Every route key in daemon.ts, read once per process. */
export function daemonRouteKeys(): ReadonlySet<string> {
	if (cachedKeys) return cachedKeys;
	const daemonSrc = fs.readFileSync(
		path.join(__dirname, '../../../src/cli/daemon.ts'),
		'utf8'
	);
	const keys = new Set<string>();
	for (const m of daemonSrc.matchAll(/'((?:GET|POST|DELETE) \/[^']+)'/g)) {
		keys.add(m[1]);
	}
	// GET /events and GET /metrics are dispatched outside the routes map by
	// comparing route key literals, so the scan finds them. /stop is matched on
	// req.method and pathname instead.
	keys.add('POST /stop');
	// A scan that stops matching must not pass by finding nothing.
	if (!keys.has('GET /info')) {
		throw new Error('daemon route scan found no GET /info');
	}
	cachedKeys = keys;
	return keys;
}

/** The paths of every daemon route key, without the method. */
export function daemonRoutePaths(): ReadonlySet<string> {
	return new Set(
		[...daemonRouteKeys()].map((key) => key.slice(key.indexOf(' ') + 1))
	);
}
