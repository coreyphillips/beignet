/**
 * MuSig2 (BIP327) wrapper for simple taproot channels (option_taproot).
 *
 * Wraps @brandonblack/musig (a zero-dependency BIP327 implementation) with a
 * Crypto backend assembled from the library's own pure-BigInt scalar/field math
 * (base_crypto) plus secp256k1 point operations from @bitcoinerlab/secp256k1 and
 * BIP340 tagged hashing. Correctness is pinned to the official BIP327 test
 * vectors (see tests/lightning/musig.test.ts) — DO NOT hand-roll the protocol.
 *
 * Channel usage: the funding output is a 2-of-2 MuSig2 key-spend P2TR. Both
 * parties aggregate their funding pubkeys, apply the BIP341 taproot key-spend
 * tweak (empty merkle root), and co-sign the commitment/closing sighash with
 * fresh per-signature nonces.
 *
 * SAFETY: a MuSig2 secret nonce MUST be used for exactly one partial signature
 * and never persisted. Nonce reuse leaks the secret key. Callers own the nonce
 * lifecycle; this module only provides the primitives.
 */

import { MuSigFactory } from '@brandonblack/musig';
import type { Crypto, KeyGenContext, SessionKey } from '@brandonblack/musig';
import * as ecc from '@bitcoinerlab/secp256k1';
import { sha256 as nobleSha256 } from '@noble/hashes/sha256';

// base_crypto provides the library's pure-BigInt scalar/field math. It is a
// package "exports" subpath, which classic (node) TS module resolution can't see
// at type-level, so it is required at runtime and typed as the partial Crypto
// surface it implements.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const baseCrypto =
	require('@brandonblack/musig/base_crypto') as Partial<Crypto>;

/** BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg...). */
function taggedHash(tag: string, ...messages: Uint8Array[]): Uint8Array {
	const tagHash = nobleSha256(Buffer.from(tag, 'utf8'));
	const h = nobleSha256.create();
	h.update(tagHash);
	h.update(tagHash);
	for (const m of messages) h.update(m);
	return h.digest();
}

function sha256(...messages: Uint8Array[]): Uint8Array {
	const h = nobleSha256.create();
	for (const m of messages) h.update(m);
	return h.digest();
}

/**
 * Crypto backend for the MuSig factory. Scalar/field math comes from the
 * library's base_crypto; elliptic-curve point operations from the tiny-secp256k1
 * compatible @bitcoinerlab/secp256k1; hashing from @noble/hashes.
 */
const cryptoBackend = {
	...baseCrypto,
	pointMultiplyUnsafe(p, a, compress) {
		try {
			return ecc.pointMultiply(p, a, compress) ?? null;
		} catch {
			return null;
		}
	},
	pointMultiplyAndAddUnsafe(p1, a, p2, compress) {
		try {
			const ap1 = ecc.pointMultiply(p1, a, false);
			if (!ap1) return null;
			return ecc.pointAdd(ap1, p2, compress) ?? null;
		} catch {
			return null;
		}
	},
	pointAdd(a, b, compress) {
		try {
			return ecc.pointAdd(a, b, compress) ?? null;
		} catch {
			return null;
		}
	},
	pointAddTweak(p, tweak, compress) {
		try {
			return ecc.pointAddScalar(p, tweak, compress) ?? null;
		} catch {
			return null;
		}
	},
	pointCompress(p, compress = true) {
		return ecc.pointCompress(p, compress);
	},
	liftX(p) {
		// Lift a 32-byte x-only coordinate to a full (even-Y) point, returned
		// uncompressed. An invalid x (not on curve) yields null.
		try {
			const evenY = Buffer.concat([Buffer.from([0x02]), Buffer.from(p)]);
			return ecc.pointCompress(evenY, false) ?? null;
		} catch {
			return null;
		}
	},
	getPublicKey(s, compress) {
		try {
			return ecc.pointFromScalar(s, compress) ?? null;
		} catch {
			return null;
		}
	},
	taggedHash,
	sha256
} as unknown as Crypto;

/** The configured MuSig2 instance. */
export const musig = MuSigFactory(cryptoBackend);

export type { KeyGenContext, SessionKey };

/**
 * Lexicographically sort two funding pubkeys (BIP327 KeySort) and aggregate
 * them. This is the channel's plain aggregate key (the taproot internal key).
 */
export function aggregateFundingPubkeys(
	localFundingPubkey: Buffer,
	remoteFundingPubkey: Buffer
): KeyGenContext {
	return musig.keyAgg(musig.keySort([localFundingPubkey, remoteFundingPubkey]));
}

/**
 * Result of deriving the taproot funding key from two funding pubkeys.
 */
export interface ITaprootFundingKey {
	/** MuSig2 context AFTER the BIP341 key-spend tweak — use this to sign. */
	tweakedCtx: KeyGenContext;
	/** 32-byte x-only INTERNAL key (the untweaked MuSig aggregate). */
	internalKey: Buffer;
	/** 32-byte x-only OUTPUT key (goes in the P2TR scriptPubKey). */
	outputKey: Buffer;
	/** The BIP341 taproot tweak scalar (taggedHash("TapTweak", internalKey)). */
	tweak: Buffer;
}

/**
 * Derive the 2-of-2 MuSig2 key-spend taproot funding key from both funding
 * pubkeys. Applies the BIP341 key-spend taproot tweak with an EMPTY merkle root
 * (no script path) — i.e. tweak = taggedHash("TapTweak", internalKey).
 */
export function deriveTaprootFundingKey(
	localFundingPubkey: Buffer,
	remoteFundingPubkey: Buffer
): ITaprootFundingKey {
	const baseCtx = aggregateFundingPubkeys(
		localFundingPubkey,
		remoteFundingPubkey
	);
	const internalKey = Buffer.from(musig.getXOnlyPubkey(baseCtx));
	const tweak = Buffer.from(taggedHash('TapTweak', internalKey));
	const tweakedCtx = musig.addTweaks(baseCtx, { tweak, xOnly: true });
	const outputKey = Buffer.from(musig.getXOnlyPubkey(tweakedCtx));
	return { tweakedCtx, internalKey, outputKey, tweak };
}

/**
 * Generate a fresh MuSig2 public nonce (66 bytes). The corresponding SECRET
 * nonce is held internally by the library, keyed by the IDENTITY of the returned
 * object — so the EXACT object returned here MUST be passed back to
 * {@link partialSign} (do NOT copy it, and keep a strong reference until you
 * sign). Serialize a copy for the wire; the in-memory original is the single-use
 * secret handle and must never be persisted or reused. `sessionId` should be
 * unique per signing session (or pass `secretKey`/`msg` for nonce entropy).
 */
export function generateNonce(args: {
	publicKey: Buffer;
	secretKey?: Buffer;
	sessionId?: Buffer;
	msg?: Buffer;
	extraInput?: Buffer;
}): Uint8Array {
	return musig.nonceGen({
		publicKey: args.publicKey,
		secretKey: args.secretKey,
		sessionId: args.sessionId,
		msg: args.msg,
		extraInput: args.extraInput
	});
}

/**
 * Register an externally-derived (publicNonce, secretNonce) pair with the
 * library so {@link partialSign} can find the secret nonce. Used for test
 * vectors and deterministic nonces. `publicNonce` identity is the lookup key.
 */
export function registerExternalNonce(
	publicNonce: Uint8Array,
	secretNonce: Uint8Array
): void {
	musig.addExternalNonce(publicNonce, secretNonce);
}

/** Aggregate the two parties' public nonces into the 66-byte aggregate nonce. */
export function aggregateNonces(publicNonces: Buffer[]): Buffer {
	return Buffer.from(musig.nonceAgg(publicNonces));
}

/**
 * Begin a signing session over `msg` (the 32-byte sighash) with the aggregate
 * nonce and the sorted funding pubkeys, applying the same taproot tweak used for
 * the funding key.
 */
export function startSigningSession(
	aggNonce: Buffer,
	msg: Buffer,
	localFundingPubkey: Buffer,
	remoteFundingPubkey: Buffer,
	tweak: Buffer
): SessionKey {
	const sortedKeys = musig.keySort([localFundingPubkey, remoteFundingPubkey]);
	return musig.startSigningSession(aggNonce, msg, sortedKeys, {
		tweak,
		xOnly: true
	});
}

/**
 * Produce our partial signature for the session. `publicNonce` MUST be the exact
 * object returned by {@link generateNonce} (or registered via
 * {@link registerExternalNonce}) so the library can locate the secret nonce.
 */
export function partialSign(args: {
	secretKey: Buffer;
	publicNonce: Uint8Array;
	sessionKey: SessionKey;
}): Buffer {
	return Buffer.from(
		musig.partialSign({
			secretKey: args.secretKey,
			publicNonce: args.publicNonce,
			sessionKey: args.sessionKey,
			verify: true
		})
	);
}

/** Verify a peer's partial signature against the session. */
export function partialVerify(args: {
	sig: Buffer;
	publicKey: Buffer;
	publicNonce: Buffer;
	sessionKey: SessionKey;
}): boolean {
	return !!musig.partialVerify({
		sig: args.sig,
		publicKey: args.publicKey,
		publicNonce: args.publicNonce,
		sessionKey: args.sessionKey
	});
}

/**
 * Aggregate both partial signatures into the final 64-byte BIP340 Schnorr
 * signature for the key-spend witness.
 */
export function aggregatePartialSigs(
	partialSigs: Buffer[],
	sessionKey: SessionKey
): Buffer {
	return Buffer.from(musig.signAgg(partialSigs, sessionKey));
}
