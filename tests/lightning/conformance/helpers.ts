/**
 * Shared loader for the BOLT conformance vectors.
 *
 * Vectors are vendored verbatim from the lightning/bolts spec repo under
 * `vectors/` (see SOURCE.md for provenance). They are loaded from disk as
 * data — never inlined — so re-syncing upstream is a file swap, and the spec
 * remains the canonical oracle the implementation is asserted against.
 */

import fs from 'fs';
import path from 'path';

const VECTORS_DIR = path.join(__dirname, 'vectors');

/**
 * Load a vendored vector file, e.g. loadVectors('bolt03/derivation.json').
 */
export function loadVectors<T = unknown>(relativePath: string): T {
	const full = path.join(VECTORS_DIR, relativePath);
	const raw = fs.readFileSync(full, 'utf8');
	return JSON.parse(raw) as T;
}

/** Coerce a hex string (with or without a leading 0x) to a Buffer. */
export function hexToBuffer(hex: string): Buffer {
	return Buffer.from(hex.replace(/^0x/, ''), 'hex');
}

/** Lower-case hex string of a Buffer, no 0x prefix (matches spec vector style). */
export function bufferToHex(buf: Buffer): string {
	return buf.toString('hex');
}
