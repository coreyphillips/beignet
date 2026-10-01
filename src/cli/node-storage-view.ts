/**
 * The Lightning node's view of the database BeignetNode shares with the
 * on-chain wallet (issue #958).
 *
 * The node closes its storage in destroy(), and its subsystems keep their
 * own reference to that storage from construction: the recovery manager and
 * journal, the metadata ledgers, the offer manager, the JIT service and
 * more. Given the real SqliteStorage, that close shut the database while the
 * wallet, which stops after the node, still waited on writes. Leaving the
 * real one open instead would leave every one of those references writable
 * after the node stopped.
 *
 * The node gets this view instead. Its close() fences the view and leaves
 * the database open for BeignetNode, which closes it once the wallet has
 * stopped. After the fence every method called through the view throws the
 * error better-sqlite3 throws on a closed connection, so each subsystem
 * fails exactly as it did when destroy() closed the real database, whatever
 * reference it holds.
 *
 * - Methods run on the real instance, so its private fields and its own
 *   database handle work unchanged. The wrapper checks the fence on every
 *   call, so a method a subsystem read before the fence and kept still
 *   throws after it (none is kept that way today; a wrapper costs nothing).
 * - Other properties read and write through: a tuning field, and the
 *   class's private fields, which nothing outside the class reads.
 * - The view is a Proxy over the instance, so instanceof SqliteStorage
 *   still holds.
 * - SqliteStorage is synchronous, so a call either ran before the fence or
 *   throws; nothing can start before it and write after it. backup() is
 *   the one async method, and after the fence it rejects, as it does on a
 *   closed connection.
 */

import { SqliteStorage } from '../lightning/storage/sqlite-storage';

/** better-sqlite3's error, word for word, for any use of a closed connection. */
const CLOSED_CONNECTION = 'The database connection is not open';

type Method = (...args: unknown[]) => unknown;

export function nodeStorageView(storage: SqliteStorage): SqliteStorage {
	let fenced = false;
	// Idempotent, like closing a closed better-sqlite3 connection.
	const close = (): void => {
		fenced = true;
	};
	// One wrapper per method, so reading a method twice gives the same
	// function, as it does on the instance.
	const wrappers = new WeakMap<Method, Method>();
	const wrap = (method: Method): Method => {
		let wrapper = wrappers.get(method);
		if (!wrapper) {
			const isAsync =
				Object.prototype.toString.call(method) === '[object AsyncFunction]';
			wrapper = (...args: unknown[]): unknown => {
				if (fenced) {
					const error = new TypeError(CLOSED_CONNECTION);
					if (isAsync) return Promise.reject(error);
					throw error;
				}
				return method.apply(storage, args);
			};
			wrappers.set(method, wrapper);
		}
		return wrapper;
	};
	return new Proxy(storage, {
		get(target, prop): unknown {
			if (prop === 'close') return close;
			const value: unknown = Reflect.get(target, prop, target);
			// The class is not a database call.
			if (typeof value !== 'function' || prop === 'constructor') return value;
			return wrap(value as Method);
		}
	});
}
