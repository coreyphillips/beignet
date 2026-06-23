/**
 * Input validation utilities for Lightning API boundaries.
 *
 * These functions return null on success or an error string on failure.
 * They are designed to be called at the entry point of public methods.
 */

/** BOLT 1: Maximum Lightning message size (bytes). */
export const MAX_MESSAGE_SIZE = 65535;

/** BOLT 3: Maximum script size. */
export const MAX_SCRIPT_SIZE = 520;

/**
 * Validate a hex-encoded compressed public key (33 bytes = 66 hex chars).
 * Returns null on success, error string on failure.
 */
export function validateHexPubkey(value: string, name: string): string | null {
	if (typeof value !== 'string') {
		return `${name} must be a string`;
	}
	if (value.length !== 66) {
		return `${name} must be 66 hex characters (33 bytes), got ${value.length}`;
	}
	if (!/^[0-9a-fA-F]+$/.test(value)) {
		return `${name} contains invalid hex characters`;
	}
	const prefix = value.slice(0, 2);
	if (prefix !== '02' && prefix !== '03') {
		return `${name} must start with 02 or 03 (compressed pubkey)`;
	}
	return null;
}

/**
 * Validate a Buffer has the expected exact length.
 * Returns null on success, error string on failure.
 */
export function validateBuffer(
	value: Buffer,
	expectedLength: number,
	name: string
): string | null {
	if (!Buffer.isBuffer(value)) {
		return `${name} must be a Buffer`;
	}
	if (value.length !== expectedLength) {
		return `${name} must be ${expectedLength} bytes, got ${value.length}`;
	}
	return null;
}

/**
 * Validate a Buffer length is within a range [min, max].
 * Returns null on success, error string on failure.
 */
export function validateBufferMinMax(
	value: Buffer,
	min: number,
	max: number,
	name: string
): string | null {
	if (!Buffer.isBuffer(value)) {
		return `${name} must be a Buffer`;
	}
	if (value.length < min || value.length > max) {
		return `${name} must be ${min}-${max} bytes, got ${value.length}`;
	}
	return null;
}

/**
 * Validate that a bigint is positive (> 0).
 * Returns null on success, error string on failure.
 */
export function validatePositiveBigint(
	value: bigint,
	name: string
): string | null {
	if (typeof value !== 'bigint') {
		return `${name} must be a bigint`;
	}
	if (value <= 0n) {
		return `${name} must be positive, got ${value}`;
	}
	return null;
}

/**
 * Validate a TCP port number (1-65535).
 * Returns null on success, error string on failure.
 */
export function validatePort(port: number): string | null {
	if (!Number.isInteger(port) || port < 1 || port > 65535) {
		return `Port must be 1-65535, got ${port}`;
	}
	return null;
}

/**
 * Validate a non-empty host string.
 * Returns null on success, error string on failure.
 */
export function validateHost(host: string): string | null {
	if (typeof host !== 'string' || host.length === 0) {
		return 'Host must be a non-empty string';
	}
	return null;
}
