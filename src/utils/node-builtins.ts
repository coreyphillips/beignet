/**
 * Node built-ins required on first use rather than at module scope, so
 * `beignet/node` loads on React Native, which has no `fs` and gets `net` and
 * `tls` only from an alias the app sets up. Each require sits in a try block
 * so Metro treats it as optional instead of failing the bundle.
 */

/* eslint-disable @typescript-eslint/no-var-requires */

function unavailable(name: string, error: unknown): Error {
	return new Error(
		`Node '${name}' is unavailable: ${
			error instanceof Error ? error.message : String(error)
		}`
	);
}

export function nodeFs(): typeof import('fs') {
	try {
		return require('fs');
	} catch (error) {
		throw unavailable('fs', error);
	}
}

export function nodeNet(): typeof import('net') {
	try {
		return require('net');
	} catch (error) {
		throw unavailable('net', error);
	}
}

export function nodeTls(): typeof import('tls') {
	try {
		return require('tls');
	} catch (error) {
		throw unavailable('tls', error);
	}
}
