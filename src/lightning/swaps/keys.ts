/**
 * Swap key material (issue #737). Nothing secret is ever persisted: the
 * per-swap claim or refund key is re-derived from the node's private key and
 * the swap id whenever it is needed, and a record stores only the public
 * key so the derivation can be checked against it at use.
 */

import crypto from 'crypto';
import { hkdfExpand, hkdfExtract } from '../crypto/hkdf';
import { isValidPrivateKey } from '../crypto/ecdh';

export const SWAP_ID_BYTES = 16;
const SWAP_KEY_SALT = Buffer.from('beignet-swap-v1');

export type SwapKeyRole = 'claim' | 'refund';

/**
 * Deterministic swap id: the requesting peer and the payment hash name the
 * swap, so a repeated create from the same peer for the same hash maps to
 * the same record, and two peers can never collide on one hash.
 */
export function deriveSwapId(peerNodeId: Buffer, paymentHash: Buffer): Buffer {
	if (!Buffer.isBuffer(peerNodeId) || peerNodeId.length !== 33) {
		throw new Error('Peer node id must be a 33-byte public key');
	}
	if (!Buffer.isBuffer(paymentHash) || paymentHash.length !== 32) {
		throw new Error('Payment hash must be 32 bytes');
	}
	return crypto
		.createHash('sha256')
		.update(SWAP_KEY_SALT)
		.update(peerNodeId)
		.update(paymentHash)
		.digest()
		.subarray(0, SWAP_ID_BYTES);
}

/**
 * The private key for one role of one swap. HKDF over the node private key
 * with the swap id and role as info; the counter loop only matters for the
 * astronomically unlikely out-of-range scalar.
 */
export function deriveSwapKey(
	nodePrivkey: Buffer,
	swapId: Buffer,
	role: SwapKeyRole
): Buffer {
	if (!Buffer.isBuffer(nodePrivkey) || nodePrivkey.length !== 32) {
		throw new Error('Node private key must be 32 bytes');
	}
	if (!Buffer.isBuffer(swapId) || swapId.length !== SWAP_ID_BYTES) {
		throw new Error(`Swap id must be ${SWAP_ID_BYTES} bytes`);
	}
	const prk = hkdfExtract(SWAP_KEY_SALT, nodePrivkey);
	for (let counter = 0; counter < 256; counter++) {
		const info = Buffer.concat([
			swapId,
			Buffer.from(role, 'utf8'),
			Buffer.from([counter])
		]);
		const candidate = hkdfExpand(prk, info, 32);
		if (isValidPrivateKey(candidate)) return candidate;
	}
	throw new Error('Swap key derivation exhausted its counter');
}
