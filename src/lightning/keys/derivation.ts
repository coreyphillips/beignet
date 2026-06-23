/**
 * BOLT 3: Channel key derivation.
 *
 * Derives per-commitment keys from basepoints following the formulas
 * specified in BOLT 3 Section 3. These keys are used in commitment
 * transactions, HTLC scripts, and penalty transactions.
 */

import crypto from 'crypto';
import {
	getPublicKey,
	pointAdd,
	pointMultiply,
	privateAdd,
	privateMultiply
} from '../crypto/ecdh';

function sha256(data: Buffer): Buffer {
	return crypto.createHash('sha256').update(data).digest();
}

/**
 * The 6 basepoints each side of a channel contributes.
 */
export interface IChannelBasepoints {
	fundingPubkey: Buffer;
	revocationBasepoint: Buffer;
	paymentBasepoint: Buffer;
	delayedPaymentBasepoint: Buffer;
	htlcBasepoint: Buffer;
	firstPerCommitmentPoint: Buffer;
}

/**
 * Derive a per-commitment public key from a basepoint and per_commitment_point.
 *
 * Formula (BOLT 3):
 *   pubkey = basepoint + SHA256(per_commitment_point || basepoint) * G
 *
 * @param basepoint - 33-byte compressed public key
 * @param perCommitmentPoint - 33-byte per-commitment point
 * @returns 33-byte derived public key
 */
export function derivePublicKey(
	basepoint: Buffer,
	perCommitmentPoint: Buffer
): Buffer {
	const tweak = sha256(Buffer.concat([perCommitmentPoint, basepoint]));
	const tweakPoint = getPublicKey(tweak);
	return pointAdd(basepoint, tweakPoint);
}

/**
 * Derive a per-commitment private key from a basepoint secret and per_commitment_point.
 *
 * Formula (BOLT 3):
 *   privkey = basepoint_secret + SHA256(per_commitment_point || basepoint)
 *
 * @param basepointSecret - 32-byte private key corresponding to the basepoint
 * @param perCommitmentPoint - 33-byte per-commitment point
 * @param basepoint - 33-byte compressed public key of the basepoint
 * @returns 32-byte derived private key
 */
export function derivePrivateKey(
	basepointSecret: Buffer,
	perCommitmentPoint: Buffer,
	basepoint: Buffer
): Buffer {
	const tweak = sha256(Buffer.concat([perCommitmentPoint, basepoint]));
	return privateAdd(basepointSecret, tweak);
}

/**
 * Derive the revocation public key.
 *
 * Formula (BOLT 3):
 *   revocationpubkey = revocation_basepoint * SHA256(revocation_basepoint || per_commitment_point)
 *                    + per_commitment_point * SHA256(per_commitment_point || revocation_basepoint)
 *
 * @param revocationBasepoint - 33-byte revocation basepoint
 * @param perCommitmentPoint - 33-byte per-commitment point
 * @returns 33-byte revocation public key
 */
export function deriveRevocationPubkey(
	revocationBasepoint: Buffer,
	perCommitmentPoint: Buffer
): Buffer {
	const tweakA = sha256(
		Buffer.concat([revocationBasepoint, perCommitmentPoint])
	);
	const tweakB = sha256(
		Buffer.concat([perCommitmentPoint, revocationBasepoint])
	);

	const termA = pointMultiply(revocationBasepoint, tweakA);
	const termB = pointMultiply(perCommitmentPoint, tweakB);

	return pointAdd(termA, termB);
}

/**
 * Derive the revocation private key (used to build penalty transactions).
 *
 * Formula (BOLT 3):
 *   revocationprivkey = revocation_basepoint_secret * SHA256(revocation_basepoint || per_commitment_point)
 *                     + per_commitment_secret * SHA256(per_commitment_point || revocation_basepoint)
 *
 * @param revocationBasepointSecret - 32-byte revocation basepoint private key
 * @param perCommitmentSecret - 32-byte per-commitment secret
 * @param revocationBasepoint - 33-byte revocation basepoint public key
 * @param perCommitmentPoint - 33-byte per-commitment point
 * @returns 32-byte revocation private key
 */
export function deriveRevocationPrivkey(
	revocationBasepointSecret: Buffer,
	perCommitmentSecret: Buffer,
	revocationBasepoint: Buffer,
	perCommitmentPoint: Buffer
): Buffer {
	const tweakA = sha256(
		Buffer.concat([revocationBasepoint, perCommitmentPoint])
	);
	const tweakB = sha256(
		Buffer.concat([perCommitmentPoint, revocationBasepoint])
	);

	const termA = privateMultiply(revocationBasepointSecret, tweakA);
	const termB = privateMultiply(perCommitmentSecret, tweakB);

	return privateAdd(termA, termB);
}

/**
 * Derive the per-commitment point from a per-commitment secret.
 * @param perCommitmentSecret - 32-byte per-commitment secret
 * @returns 33-byte per-commitment point
 */
export function perCommitmentPointFromSecret(
	perCommitmentSecret: Buffer
): Buffer {
	return getPublicKey(perCommitmentSecret);
}
