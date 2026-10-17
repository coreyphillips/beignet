/**
 * BOLT 12: Tagged Merkle Tree for Signature Verification.
 *
 * BOLT 12 builds a tagged merkle tree over the message's TLV records. For each
 * (non-signature) TLV, in TLV-ascending order, there are TWO leaves:
 *   1. H("LnLeaf", tlv)                       — the whole record (type||len||value)
 *   2. H("LnNonce" || first-tlv, tlv-type)    — tag is "LnNonce" concatenated with
 *                                               the FIRST record's bytes; the message
 *                                               is the current record's type bytes
 * The two are combined into a per-TLV node H("LnBranch", lesser || greater), and the
 * per-TLV nodes are combined pairwise (again LnBranch, lexicographically ordered)
 * up to the root. Verified byte-for-byte against LDK's BOLT 12 merkle vectors.
 *
 *   H(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
 *
 * The signature hash is H("lightning" || messagename || fieldname, merkle_root).
 */

import crypto from 'crypto';
import { decodeBigSize } from '../message/codec';
import { ITlvRecord } from '../message/tlv';
import { encodeTlvRecordRaw } from './tlv';

const LN_LEAF_TAG = Buffer.from('LnLeaf');
const LN_NONCE_TAG = Buffer.from('LnNonce');
const LN_BRANCH_TAG = Buffer.from('LnBranch');

/** BOLT 12 signature field TLV type; excluded from the signed merkle tree. */
const SIGNATURE_TLV_TYPE = 240n;

function sha256(...parts: Buffer[]): Buffer {
	const h = crypto.createHash('sha256');
	for (const p of parts) h.update(p);
	return h.digest();
}

/** Tagged hash H(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg). */
function taggedHashBuf(tag: Buffer, msg: Buffer): Buffer {
	const th = sha256(tag);
	return sha256(th, th, msg);
}

/** String-tag convenience wrapper (used for the signature hash). */
function taggedHash(tag: string, data: Buffer): Buffer {
	return taggedHashBuf(Buffer.from(tag), data);
}

function branchHash(a: Buffer, b: Buffer): Buffer {
	const [first, second] = a.compare(b) <= 0 ? [a, b] : [b, a];
	return taggedHashBuf(LN_BRANCH_TAG, Buffer.concat([first, second]));
}

/**
 * Compute the BOLT 12 merkle root from raw-encoded TLV records
 * (type || length || value). The signature record (type 240) is excluded.
 */
export function computeMerkleRoot(encodedRecords: Buffer[]): Buffer {
	const records = encodedRecords.filter(
		(r) => decodeBigSize(r, 0).value !== SIGNATURE_TLV_TYPE
	);
	if (records.length === 0) {
		throw new Error('Cannot compute merkle root of empty record set');
	}

	const first = records[0];
	// Per-TLV node = branch(H("LnLeaf", record), H("LnNonce"||first, type-bytes)).
	let level = records.map((record) => {
		const typeBytes = record.subarray(0, decodeBigSize(record, 0).bytesRead);
		const leaf = taggedHashBuf(LN_LEAF_TAG, record);
		const nonce = taggedHashBuf(
			Buffer.concat([LN_NONCE_TAG, first]),
			typeBytes
		);
		return branchHash(leaf, nonce);
	});

	while (level.length > 1) {
		const next: Buffer[] = [];
		for (let i = 0; i < level.length; i += 2) {
			next.push(
				i + 1 < level.length ? branchHash(level[i], level[i + 1]) : level[i]
			);
		}
		level = next;
	}
	return level[0];
}

/** Compute the BOLT 12 merkle root from decoded TLV records. */
export function computeMerkleRootFromRecords(records: ITlvRecord[]): Buffer {
	return computeMerkleRoot(records.map((r) => encodeTlvRecordRaw(r)));
}

/**
 * Compute the signature hash for signing/verifying a BOLT 12 message.
 *
 * @param signatureTag The full tag: "lightning" || messagename || fieldname
 *                     (e.g. "lightninginvoice_requestsignature").
 * @param merkleRoot   32-byte merkle root of the message TLVs.
 */
export function computeSignatureHash(
	signatureTag: string,
	merkleRoot: Buffer
): Buffer {
	return taggedHash(signatureTag, merkleRoot);
}

/**
 * Compute the offer_id: the BOLT 12 merkle root of all offer TLV records.
 */
export function computeOfferId(records: ITlvRecord[]): Buffer {
	return computeMerkleRootFromRecords(records);
}

export { taggedHash };
