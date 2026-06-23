/**
 * BOLT 12: Tagged Merkle Tree for Signature Verification.
 *
 * BOLT 12 uses a tagged merkle tree construction for computing
 * the signature hash over TLV records:
 *
 * - Leaf: SHA256("LnLeaf" || SHA256("LnLeaf") || record)
 *   Simplified per spec: SHA256(tag || tag || data) where tag = SHA256("LnLeaf")
 * - Branch: SHA256("LnBranch" || SHA256("LnBranch") || left || right)
 *   where left <= right (lexicographic)
 * - Single element: the leaf hash directly
 * - Signature hash: SHA256(SHA256(signatureTag) || SHA256(signatureTag) || merkleRoot)
 */

import crypto from 'crypto';
import { ITlvRecord } from '../message/tlv';
import { encodeTlvRecordRaw } from './tlv';

// ── Tag hashes (precomputed for "LnLeaf" and "LnBranch") ───────────

const LN_LEAF_TAG = 'LnLeaf';
const LN_BRANCH_TAG = 'LnBranch';

function tagHash(tag: string): Buffer {
	return crypto.createHash('sha256').update(tag).digest();
}

/**
 * Compute a tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
 * This is the BIP 340 tagged hash construction.
 */
function taggedHash(tag: string, data: Buffer): Buffer {
	const th = tagHash(tag);
	return crypto
		.createHash('sha256')
		.update(th)
		.update(th)
		.update(data)
		.digest();
}

/**
 * Compute a leaf hash: tagged_hash("LnLeaf", record_bytes)
 */
function leafHash(record: Buffer): Buffer {
	return taggedHash(LN_LEAF_TAG, record);
}

/**
 * Compute a branch hash: tagged_hash("LnBranch", left || right)
 * where left and right are sorted lexicographically.
 */
function branchHash(left: Buffer, right: Buffer): Buffer {
	// Sort lexicographically
	const cmp = left.compare(right);
	const first = cmp <= 0 ? left : right;
	const second = cmp <= 0 ? right : left;
	return taggedHash(LN_BRANCH_TAG, Buffer.concat([first, second]));
}

/**
 * Compute the merkle root from an array of encoded TLV records.
 *
 * @param encodedRecords - Array of raw-encoded TLV records (type || length || value)
 * @returns 32-byte merkle root hash
 */
export function computeMerkleRoot(encodedRecords: Buffer[]): Buffer {
	if (encodedRecords.length === 0) {
		throw new Error('Cannot compute merkle root of empty record set');
	}

	// Compute leaf hashes
	let hashes = encodedRecords.map((r) => leafHash(r));

	// Build tree bottom-up
	while (hashes.length > 1) {
		const nextLevel: Buffer[] = [];
		for (let i = 0; i < hashes.length; i += 2) {
			if (i + 1 < hashes.length) {
				nextLevel.push(branchHash(hashes[i], hashes[i + 1]));
			} else {
				// Odd element — promote to next level
				nextLevel.push(hashes[i]);
			}
		}
		hashes = nextLevel;
	}

	return hashes[0];
}

/**
 * Compute the merkle root from TLV records.
 *
 * @param records - Array of ITlvRecord
 * @returns 32-byte merkle root hash
 */
export function computeMerkleRootFromRecords(records: ITlvRecord[]): Buffer {
	const encoded = records.map((r) => encodeTlvRecordRaw(r));
	return computeMerkleRoot(encoded);
}

/**
 * Compute the signature hash for signing/verifying BOLT 12 messages.
 *
 * @param signatureTag - The tag string (e.g. "lightning" for offers, or a message-specific tag)
 * @param merkleRoot - 32-byte merkle root
 * @returns 32-byte signature hash
 */
export function computeSignatureHash(
	signatureTag: string,
	merkleRoot: Buffer
): Buffer {
	return taggedHash(signatureTag, merkleRoot);
}

/**
 * Compute the offer_id: SHA256 merkle root of all offer TLV records.
 * This is just the merkle root itself (not a tagged hash).
 *
 * @param records - The TLV records from the offer
 * @returns 32-byte offer ID
 */
export function computeOfferId(records: ITlvRecord[]): Buffer {
	return computeMerkleRootFromRecords(records);
}

export { taggedHash, leafHash, branchHash };
