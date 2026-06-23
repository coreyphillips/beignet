/**
 * BOLT 3: Shachain — compact per-commitment secret storage.
 *
 * The shachain algorithm allows O(log n) storage for n secrets.
 * It uses a seed-based derivation tree where each secret can be
 * derived by selectively flipping bits and hashing.
 *
 * Maximum index is 2^48 - 1 (281 trillion commitments).
 */

import crypto from 'crypto';

const MAX_INDEX = 0xffffffffffffn; // 2^48 - 1
const INDEX_BITS = 48;

function sha256(data: Buffer): Buffer {
	return crypto.createHash('sha256').update(data).digest();
}

/**
 * Generate a secret at a given index from a seed.
 *
 * For each bit position 47→0: if that bit is set in the index,
 * flip the corresponding byte bit and hash.
 *
 * @param seed - 32-byte seed
 * @param index - Index in range [0, 2^48 - 1], counting DOWN from MAX_INDEX
 * @returns 32-byte secret
 */
export function generateFromSeed(seed: Buffer, index: bigint): Buffer {
	if (seed.length !== 32) {
		throw new Error(`Seed must be 32 bytes, got ${seed.length}`);
	}
	if (index < 0n || index > MAX_INDEX) {
		throw new Error(`Index must be 0..${MAX_INDEX}, got ${index}`);
	}

	let secret = Buffer.from(seed);

	for (let bit = INDEX_BITS - 1; bit >= 0; bit--) {
		if ((index >> BigInt(bit)) & 1n) {
			const byteIndex = Math.floor(bit / 8);
			const bitIndex = bit % 8;
			secret[byteIndex] ^= 1 << bitIndex;
			secret = sha256(secret);
		}
	}

	return secret;
}

/**
 * Derive a child secret from a parent by flipping a bit and hashing.
 */
function deriveChild(
	parent: Buffer,
	fromIndex: bigint,
	toIndex: bigint
): Buffer {
	let secret = Buffer.from(parent);

	for (let bit = INDEX_BITS - 1; bit >= 0; bit--) {
		const fromBit = (fromIndex >> BigInt(bit)) & 1n;
		const toBit = (toIndex >> BigInt(bit)) & 1n;

		if (fromBit === 0n && toBit === 1n) {
			const byteIndex = Math.floor(bit / 8);
			const bitIndex = bit % 8;
			secret[byteIndex] ^= 1 << bitIndex;
			secret = sha256(secret);
		}
	}

	return secret;
}

/**
 * Check if secret at fromIndex can derive secret at toIndex.
 */
function canDerive(fromIndex: bigint, toIndex: bigint): boolean {
	// fromIndex can derive toIndex if toIndex has all bits of fromIndex set,
	// plus possibly more bits set.
	for (let bit = INDEX_BITS - 1; bit >= 0; bit--) {
		const fromBit = (fromIndex >> BigInt(bit)) & 1n;
		const toBit = (toIndex >> BigInt(bit)) & 1n;

		if (fromBit === 1n && toBit === 0n) {
			return false; // fromIndex has a bit set that toIndex doesn't
		}
	}
	return true;
}

export interface IShaChainEntry {
	index: bigint;
	secret: Buffer;
}

/**
 * Compact storage for received per-commitment secrets.
 * Stores at most 49 entries to cover all 2^48 possible secrets.
 */
export class ShaChainStore {
	private entries: IShaChainEntry[] = [];
	private knownCount = 0n;

	/**
	 * Add a new secret to the store.
	 * Secrets must be added in decreasing index order (starting from MAX_INDEX).
	 *
	 * @param index - The commitment index (counting down from MAX_INDEX)
	 * @param secret - 32-byte per-commitment secret
	 * @returns true if the secret was valid and stored
	 */
	addSecret(index: bigint, secret: Buffer): boolean {
		if (secret.length !== 32) {
			throw new Error(`Secret must be 32 bytes, got ${secret.length}`);
		}

		// Validate against existing entries
		for (const entry of this.entries) {
			if (canDerive(index, entry.index)) {
				const derived = deriveChild(secret, index, entry.index);
				if (!derived.equals(entry.secret)) {
					return false; // Invalid: doesn't match previously stored secret
				}
			}
		}

		// Remove entries that can be derived from the new secret
		this.entries = this.entries.filter(
			(entry) => !canDerive(index, entry.index)
		);

		this.entries.push({ index, secret: Buffer.from(secret) });
		this.knownCount++;
		return true;
	}

	/**
	 * Get a secret at a given index.
	 * @returns The 32-byte secret, or null if not derivable from stored entries
	 */
	getSecret(index: bigint): Buffer | null {
		// Check if any stored entry can derive this index
		for (const entry of this.entries) {
			if (canDerive(entry.index, index)) {
				return deriveChild(entry.secret, entry.index, index);
			}
		}
		return null;
	}

	/**
	 * Get the number of entries currently stored.
	 */
	getEntryCount(): number {
		return this.entries.length;
	}

	/**
	 * Get the total number of secrets that have been added.
	 */
	getKnownCount(): bigint {
		return this.knownCount;
	}

	/**
	 * Get all stored entries for serialization.
	 */
	getEntries(): IShaChainEntry[] {
		return this.entries.map((e) => ({
			index: e.index,
			secret: Buffer.from(e.secret)
		}));
	}

	/**
	 * Restore a ShaChainStore from serialized entries.
	 */
	static restore(entries: IShaChainEntry[], knownCount: bigint): ShaChainStore {
		const store = new ShaChainStore();
		store.entries = entries.map((e) => ({
			index: e.index,
			secret: Buffer.from(e.secret)
		}));
		store.knownCount = knownCount;
		return store;
	}
}

export { MAX_INDEX };
