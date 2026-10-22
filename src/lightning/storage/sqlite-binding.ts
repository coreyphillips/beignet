import type Database from 'better-sqlite3';

/**
 * better-sqlite3 is an optional dependency, required here on first use so
 * the protocol layer loads without it (React Native, or an install that
 * omitted optional dependencies). The require sits in a try block so Metro
 * treats it as optional instead of failing the bundle.
 */
export function loadBetterSqlite3(): typeof Database {
	try {
		return require('better-sqlite3') as typeof Database;
	} catch (error) {
		throw new Error(
			`SQLite storage requires the optional better-sqlite3 dependency: ${error.message}`
		);
	}
}
