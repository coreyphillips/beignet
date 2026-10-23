import type Database from 'better-sqlite3';

/**
 * better-sqlite3 is an optional dependency, required here on first use so
 * the protocol layer loads without it (React Native, or an install that
 * omitted optional dependencies). The try block lets Metro skip it when it
 * is not installed. When it is, Metro would bundle it and fail on its fs
 * import, so package.json's react-native field resolves it to an empty
 * module instead.
 */
export function loadBetterSqlite3(): typeof Database {
	try {
		const binding = require('better-sqlite3') as typeof Database;
		if (typeof binding !== 'function') {
			throw new Error('React Native bundles resolve it to an empty module');
		}
		return binding;
	} catch (error) {
		throw new Error(
			`SQLite storage requires the optional better-sqlite3 dependency: ${error.message}`
		);
	}
}
