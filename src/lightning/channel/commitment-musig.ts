/**
 * Simple taproot channels (option_taproot): MuSig2 commitment co-signing (M4.5).
 *
 * For a taproot channel the commitment transaction spends the 2-of-2 MuSig2
 * key-spend funding output, so each commitment is signed with a MuSig2 partial
 * signature (BIP327) over the BIP341 key-spend sighash, rather than an ECDSA
 * signature over a P2WSH 2-of-2. The two partial signatures aggregate into a
 * single 64-byte BIP340 Schnorr signature that becomes the key-spend witness at
 * broadcast time.
 *
 * NONCE SAFETY (catastrophic if violated): each partial signature consumes a
 * single-use secret nonce. The `ourPublicNonce` passed here MUST be the exact
 * object returned by musig.generateNonce for THIS commitment, and must never be
 * reused for another sighash. After the commitment is revoked the channel must
 * rotate to a fresh nonce. This module performs the crypto only; the channel
 * state machine owns the nonce lifecycle.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { taprootKeySpendSighash } from '../script/funding-taproot';
import {
	deriveTaprootFundingKey,
	aggregateNonces,
	startSigningSession,
	partialSign,
	partialVerify,
	aggregatePartialSigs,
	type SessionKey
} from '../crypto/musig';

/**
 * BIP341 key-spend sighash for a commitment (or closing) transaction spending
 * the taproot funding output at input 0.
 */
export function taprootCommitmentSighash(
	commitmentTx: bitcoin.Transaction,
	fundingScriptPubKey: Buffer,
	fundingValueSat: number
): Buffer {
	return taprootKeySpendSighash(
		commitmentTx,
		0,
		[fundingScriptPubKey],
		[fundingValueSat]
	);
}

/**
 * Start a MuSig2 signing session for a commitment. Both parties derive the SAME
 * session from the same sighash, the aggregate of both public nonces, the sorted
 * funding pubkeys and the funding taproot tweak — so partial signatures from each
 * side are mutually verifiable and aggregate to a valid key-spend signature.
 */
export function startCommitmentSigningSession(
	sighash: Buffer,
	localFundingPubkey: Buffer,
	remoteFundingPubkey: Buffer,
	ourPublicNonce: Uint8Array,
	theirPublicNonce: Buffer
): SessionKey {
	const { tweak } = deriveTaprootFundingKey(
		localFundingPubkey,
		remoteFundingPubkey
	);
	// Nonce aggregation is commutative (point sum), so the order is irrelevant.
	const aggNonce = aggregateNonces([
		Buffer.from(ourPublicNonce),
		theirPublicNonce
	]);
	return startSigningSession(
		aggNonce,
		sighash,
		localFundingPubkey,
		remoteFundingPubkey,
		tweak
	);
}

/**
 * Produce OUR partial signature for the commitment. `ourPublicNonce` MUST be the
 * exact object generated for this commitment (single use).
 */
export function partialSignCommitment(
	session: SessionKey,
	ourFundingPrivkey: Buffer,
	ourPublicNonce: Uint8Array
): Buffer {
	return partialSign({
		secretKey: ourFundingPrivkey,
		publicNonce: ourPublicNonce,
		sessionKey: session
	});
}

/** Verify the PEER's partial signature for the commitment. */
export function verifyPartialCommitmentSig(
	session: SessionKey,
	theirPartialSig: Buffer,
	theirFundingPubkey: Buffer,
	theirPublicNonce: Buffer
): boolean {
	return partialVerify({
		sig: theirPartialSig,
		publicKey: theirFundingPubkey,
		publicNonce: theirPublicNonce,
		sessionKey: session
	});
}

/**
 * Aggregate both partial signatures into the final 64-byte BIP340 Schnorr
 * signature used as the key-spend witness when the commitment is broadcast.
 */
export function aggregateCommitmentSig(
	session: SessionKey,
	ourPartialSig: Buffer,
	theirPartialSig: Buffer
): Buffer {
	return aggregatePartialSigs([ourPartialSig, theirPartialSig], session);
}
