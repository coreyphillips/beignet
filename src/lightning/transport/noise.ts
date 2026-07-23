/**
 * BOLT 8: Noise_XK handshake protocol.
 *
 * Implements the three-act handshake for establishing authenticated,
 * encrypted P2P connections between Lightning nodes. Uses the
 * Noise_XK pattern where the initiator knows the responder's static
 * public key in advance.
 *
 * Handshake pattern:
 *   Act 1: Initiator → Responder (50 bytes)
 *   Act 2: Responder → Initiator (50 bytes)
 *   Act 3: Initiator → Responder (66 bytes)
 */

import crypto from 'crypto';
import { ecdh, getPublicKey, isValidPublicKey } from '../crypto/ecdh';
import { hkdf2 } from '../crypto/hkdf';
import { encrypt, decrypt } from '../crypto/chacha20poly1305';
import { TransportCipher } from './cipher';

const PROTOCOL_NAME = 'Noise_XK_secp256k1_ChaChaPoly_SHA256';
const PROLOGUE = 'lightning';
const ACT_ONE_LENGTH = 50;
const ACT_TWO_LENGTH = 50;
const ACT_THREE_LENGTH = 66;
const VERSION = 0x00;

function sha256(data: Buffer): Buffer {
	return crypto.createHash('sha256').update(data).digest();
}

/**
 * Internal handshake state that is updated through each act.
 */
export interface IHandshakeState {
	h: Buffer; // handshake hash accumulator
	ck: Buffer; // chaining key
	tempK: Buffer; // temporary key for current act
	e?: {
		// local ephemeral keypair
		priv: Buffer;
		pub: Buffer;
	};
	re?: Buffer; // remote ephemeral public key
	s: {
		// local static keypair
		priv: Buffer;
		pub: Buffer;
	};
	rs?: Buffer; // remote static public key
}

/**
 * Result of a completed handshake.
 */
export interface IHandshakeResult {
	/** Encrypted transport cipher for post-handshake communication */
	transport: TransportCipher;
	/** The remote node's static public key (authenticated) */
	remoteStaticPubkey: Buffer;
}

/**
 * Initialize the handshake state common to both initiator and responder.
 */
function initializeHandshakeState(
	localStatic: { priv: Buffer; pub: Buffer },
	remoteStaticPub?: Buffer
): IHandshakeState {
	// ck = SHA256(protocolName)
	const ck = sha256(Buffer.from(PROTOCOL_NAME, 'ascii'));

	// h = SHA256(ck || "lightning")
	const h = sha256(Buffer.concat([ck, Buffer.from(PROLOGUE, 'ascii')]));

	const state: IHandshakeState = {
		h,
		ck: Buffer.from(ck),
		tempK: Buffer.alloc(32),
		s: localStatic
	};

	if (remoteStaticPub) {
		state.rs = remoteStaticPub;
	}

	return state;
}

/**
 * Generate an ephemeral keypair for the handshake.
 */
function generateEphemeral(privOverride?: Buffer): {
	priv: Buffer;
	pub: Buffer;
} {
	const priv = privOverride || crypto.randomBytes(32);
	const pub = getPublicKey(priv);
	return { priv, pub };
}

/**
 * Build a 12-byte nonce from a counter for handshake encryption.
 * Uses the same format as BOLT 8: 4 zero bytes + 8-byte LE counter.
 */
function handshakeNonce(counter: number): Buffer {
	const nonce = Buffer.alloc(12);
	nonce.writeUInt32LE(counter, 4);
	return nonce;
}

// ─── Initiator ─────────────────────────────────────────────────────

/**
 * Initiator creates Act 1 message (50 bytes).
 * @param state - Handshake state (modified in place)
 * @param ephemeralPriv - Optional override for ephemeral private key (for testing)
 * @returns 50-byte Act 1 message
 */
export function initiatorAct1(
	state: IHandshakeState,
	ephemeralPriv?: Buffer
): Buffer {
	if (!state.rs) {
		throw new Error('Initiator must know responder static pubkey');
	}

	// Mix in responder's static pubkey
	state.h = sha256(Buffer.concat([state.h, state.rs]));

	// Generate ephemeral keypair
	state.e = generateEphemeral(ephemeralPriv);

	// h = SHA256(h || e.pub)
	state.h = sha256(Buffer.concat([state.h, state.e.pub]));

	// ss = ECDH(e.priv, rs)
	const ss = ecdh(state.e.priv, state.rs);

	// [ck, tempK] = HKDF(ck, ss)
	const [ck, tempK] = hkdf2(state.ck, ss);
	state.ck = ck;
	state.tempK = tempK;

	// c = encrypt(tempK, nonce=0, "", h) — empty plaintext, AAD=h
	const c = encrypt(state.tempK, handshakeNonce(0), Buffer.alloc(0), state.h);

	// h = SHA256(h || c)
	state.h = sha256(Buffer.concat([state.h, c]));

	// Output: [version || e.pub || c] = 1 + 33 + 16 = 50
	return Buffer.concat([Buffer.from([VERSION]), state.e.pub, c]);
}

/**
 * Initiator processes Act 2 message from responder.
 * @param state - Handshake state (modified in place)
 * @param act2 - 50-byte Act 2 message
 */
export function initiatorProcessAct2(
	state: IHandshakeState,
	act2: Buffer
): void {
	if (act2.length !== ACT_TWO_LENGTH) {
		throw new Error(
			`Act 2 must be ${ACT_TWO_LENGTH} bytes, got ${act2.length}`
		);
	}

	const version = act2[0];
	if (version !== VERSION) {
		throw new Error(`Unsupported handshake version: ${version}`);
	}

	// Extract responder's ephemeral pubkey and ciphertext
	state.re = act2.subarray(1, 34);
	if (!isValidPublicKey(state.re)) {
		throw new Error('Act 2 ephemeral key is not a valid curve point');
	}
	const c = act2.subarray(34, 50);

	// h = SHA256(h || re)
	state.h = sha256(Buffer.concat([state.h, state.re]));

	// ss = ECDH(e.priv, re)
	const ss = ecdh(state.e!.priv, state.re);

	// [ck, tempK] = HKDF(ck, ss)
	const [ck, tempK] = hkdf2(state.ck, ss);
	state.ck = ck;
	state.tempK = tempK;

	// Decrypt and verify tag (empty plaintext)
	decrypt(state.tempK, handshakeNonce(0), c, state.h);

	// h = SHA256(h || c)
	state.h = sha256(Buffer.concat([state.h, c]));
}

/**
 * Initiator creates Act 3 message (66 bytes).
 * @param state - Handshake state (modified in place)
 * @returns 66-byte Act 3 message
 */
export function initiatorAct3(state: IHandshakeState): Buffer {
	// Encrypt static pubkey: c = encrypt(tempK, nonce=1, s.pub, h)
	const c = encrypt(state.tempK, handshakeNonce(1), state.s.pub, state.h);

	// h = SHA256(h || c)
	state.h = sha256(Buffer.concat([state.h, c]));

	// ss = ECDH(s.priv, re) — static-ephemeral
	const ss = ecdh(state.s.priv, state.re!);

	// [ck, tempK] = HKDF(ck, ss)
	const [ck, tempK] = hkdf2(state.ck, ss);
	state.ck = ck;
	state.tempK = tempK;

	// t = encrypt(tempK, nonce=0, "", h) — empty payload tag
	const t = encrypt(state.tempK, handshakeNonce(0), Buffer.alloc(0), state.h);

	// Output: [version || c || t] = 1 + 49 + 16 = 66
	return Buffer.concat([Buffer.from([VERSION]), c, t]);
}

// ─── Responder ─────────────────────────────────────────────────────

/**
 * Responder processes Act 1 message from initiator.
 * @param state - Handshake state (modified in place)
 * @param act1 - 50-byte Act 1 message
 */
export function responderProcessAct1(
	state: IHandshakeState,
	act1: Buffer
): void {
	if (act1.length !== ACT_ONE_LENGTH) {
		throw new Error(
			`Act 1 must be ${ACT_ONE_LENGTH} bytes, got ${act1.length}`
		);
	}

	const version = act1[0];
	if (version !== VERSION) {
		throw new Error(`Unsupported handshake version: ${version}`);
	}

	// Mix in our own static pubkey (responder's perspective)
	state.h = sha256(Buffer.concat([state.h, state.s.pub]));

	// Extract initiator's ephemeral pubkey and ciphertext
	state.re = act1.subarray(1, 34);
	if (!isValidPublicKey(state.re)) {
		throw new Error('Act 1 ephemeral key is not a valid curve point');
	}
	const c = act1.subarray(34, 50);

	// h = SHA256(h || re)
	state.h = sha256(Buffer.concat([state.h, state.re]));

	// ss = ECDH(s.priv, re) — our static, their ephemeral
	const ss = ecdh(state.s.priv, state.re);

	// [ck, tempK] = HKDF(ck, ss)
	const [ck, tempK] = hkdf2(state.ck, ss);
	state.ck = ck;
	state.tempK = tempK;

	// Decrypt and verify tag
	decrypt(state.tempK, handshakeNonce(0), c, state.h);

	// h = SHA256(h || c)
	state.h = sha256(Buffer.concat([state.h, c]));
}

/**
 * Responder creates Act 2 message (50 bytes).
 * @param state - Handshake state (modified in place)
 * @param ephemeralPriv - Optional override for ephemeral private key (for testing)
 * @returns 50-byte Act 2 message
 */
export function responderAct2(
	state: IHandshakeState,
	ephemeralPriv?: Buffer
): Buffer {
	// Generate ephemeral keypair
	state.e = generateEphemeral(ephemeralPriv);

	// h = SHA256(h || e.pub)
	state.h = sha256(Buffer.concat([state.h, state.e.pub]));

	// ss = ECDH(e.priv, re)
	const ss = ecdh(state.e.priv, state.re!);

	// [ck, tempK] = HKDF(ck, ss)
	const [ck, tempK] = hkdf2(state.ck, ss);
	state.ck = ck;
	state.tempK = tempK;

	// c = encrypt(tempK, nonce=0, "", h) — empty plaintext, AAD=h
	const c = encrypt(state.tempK, handshakeNonce(0), Buffer.alloc(0), state.h);

	// h = SHA256(h || c)
	state.h = sha256(Buffer.concat([state.h, c]));

	// Output: [version || e.pub || c] = 1 + 33 + 16 = 50
	return Buffer.concat([Buffer.from([VERSION]), state.e.pub, c]);
}

/**
 * Responder processes Act 3 message from initiator.
 * @param state - Handshake state (modified in place)
 * @returns The initiator's authenticated static public key
 */
export function responderProcessAct3(
	state: IHandshakeState,
	act3: Buffer
): Buffer {
	if (act3.length !== ACT_THREE_LENGTH) {
		throw new Error(
			`Act 3 must be ${ACT_THREE_LENGTH} bytes, got ${act3.length}`
		);
	}

	const version = act3[0];
	if (version !== VERSION) {
		throw new Error(`Unsupported handshake version: ${version}`);
	}

	const c = act3.subarray(1, 50); // encrypted static pubkey (33 + 16)
	const t = act3.subarray(50, 66); // encrypted empty payload tag

	// Decrypt initiator's static pubkey
	const rs = decrypt(state.tempK, handshakeNonce(1), c, state.h);
	state.rs = rs;

	// h = SHA256(h || c)
	state.h = sha256(Buffer.concat([state.h, c]));

	// ss = ECDH(e.priv, rs) — ephemeral-static
	const ss = ecdh(state.e!.priv, state.rs);

	// [ck, tempK] = HKDF(ck, ss)
	const [ck, tempK] = hkdf2(state.ck, ss);
	state.ck = ck;
	state.tempK = tempK;

	// Decrypt and verify tag
	decrypt(state.tempK, handshakeNonce(0), t, state.h);

	return rs;
}

// ─── High-level API ────────────────────────────────────────────────

/**
 * Derive the post-handshake transport cipher from completed handshake state.
 * BOLT 8 Split: sk, rk = HKDF(ck, zerolen) producing two 32-byte keys.
 * The original chaining key is used for key rotation in each CipherState.
 * @param ck - Chaining key from completed handshake
 * @param initiator - True if this side is the initiator
 * @returns TransportCipher for encrypted communication
 */
export function deriveTransportCipher(
	ck: Buffer,
	initiator: boolean
): TransportCipher {
	const [sk, rk] = hkdf2(ck, Buffer.alloc(0));
	if (initiator) {
		return new TransportCipher(sk, rk, ck);
	} else {
		return new TransportCipher(rk, sk, ck);
	}
}

/**
 * Perform a complete Noise_XK handshake as the initiator (in-memory, no TCP).
 * Returns functions that produce Act 1 and Act 3, and process Act 2.
 */
export function createInitiatorHandshake(
	localStaticPriv: Buffer,
	remoteStaticPub: Buffer,
	ephemeralPriv?: Buffer
): {
	state: IHandshakeState;
	act1: Buffer;
	processAct2: (act2: Buffer) => void;
	createAct3: () => Buffer;
	deriveTransport: () => TransportCipher;
} {
	const localPub = getPublicKey(localStaticPriv);
	const state = initializeHandshakeState(
		{ priv: localStaticPriv, pub: localPub },
		remoteStaticPub
	);

	const act1 = initiatorAct1(state, ephemeralPriv);

	return {
		state,
		act1,
		processAct2: (act2: Buffer): void => initiatorProcessAct2(state, act2),
		createAct3: (): Buffer => initiatorAct3(state),
		deriveTransport: (): TransportCipher =>
			deriveTransportCipher(state.ck, true)
	};
}

/**
 * Perform a complete Noise_XK handshake as the responder (in-memory, no TCP).
 * Returns functions that process Act 1 and Act 3, and produce Act 2.
 */
export function createResponderHandshake(
	localStaticPriv: Buffer,
	ephemeralPriv?: Buffer
): {
	state: IHandshakeState;
	processAct1: (act1: Buffer) => void;
	createAct2: () => Buffer;
	processAct3: (act3: Buffer) => Buffer;
	deriveTransport: () => TransportCipher;
} {
	const localPub = getPublicKey(localStaticPriv);
	const state = initializeHandshakeState({
		priv: localStaticPriv,
		pub: localPub
	});

	return {
		state,
		processAct1: (act1: Buffer): void => responderProcessAct1(state, act1),
		createAct2: (): Buffer => responderAct2(state, ephemeralPriv),
		processAct3: (act3: Buffer): Buffer => responderProcessAct3(state, act3),
		deriveTransport: (): TransportCipher =>
			deriveTransportCipher(state.ck, false)
	};
}

export { ACT_ONE_LENGTH, ACT_TWO_LENGTH, ACT_THREE_LENGTH };
