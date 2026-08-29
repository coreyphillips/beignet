/**
 * Sealed frames (rev 2 "Frame encryption"). Every protocol frame in both
 * directions is sealed to the request, with the primitive set a Lightning
 * implementation already carries.
 *
 *   shared   = ECDH(payer_ephemeral, request_encryption_key)
 *              BOLT 8 style: SHA256 of the compressed shared point
 *   send_key = HKDF-SHA256(shared, salt=request_id,
 *                          info="beignet-df:v3:sender-to-receiver", 32)
 *   recv_key = HKDF-SHA256(shared, salt=request_id,
 *                          info="beignet-df:v3:receiver-to-sender", 32)
 *
 * Frames are ChaCha20-Poly1305 with a fresh 96-bit random nonce and
 * associated data `request_id || u16 subtype`.
 *
 * Four properties this layer owes:
 *
 *  - Each direction has its OWN key, so a frame reflected back at its author
 *    fails authentication rather than being accepted as a reply.
 *  - A retransmitted logical frame re-seals under a fresh nonce, so no nonce
 *    ever carries two plaintexts. Nonces are random per seal and nothing here
 *    persists a counter, so a restart cannot reuse one either.
 *  - Opening returns null instead of throwing. A frame sealed to a request we
 *    did not mint, or tampered with, produces SILENCE: no error reply, no log
 *    line a peer can provoke at will, no timing signal.
 *  - The node identity key never appears. It signs the envelope and the
 *    funding attestation; the per-request key does all sealing.
 */

import crypto from 'crypto';
import { decrypt, encrypt } from '../crypto/chacha20poly1305';
import { ecdh, getPublicKey, isValidPrivateKey } from '../crypto/ecdh';
import { hkdf } from '../crypto/hkdf';
import {
	DF_NODE_ID_BYTES,
	DF_REQUEST_ID_BYTES,
	IDfRequestEnvelope
} from './types';

/** Byte-exact HKDF info strings; both sides derive from the same pair. */
export const DF_INFO_SENDER_TO_RECEIVER = 'beignet-df:v3:sender-to-receiver';
export const DF_INFO_RECEIVER_TO_SENDER = 'beignet-df:v3:receiver-to-sender';

export const DF_FRAME_KEY_BYTES = 32;
export const DF_FRAME_NONCE_BYTES = 12;
export const DF_FRAME_TAG_BYTES = 16;

/** First payer frame: carries the request id and ephemeral key in the clear. */
export const DF_FRAME_FORM_OPENING = 1;
/** Every later frame in either direction: nonce and ciphertext only. */
export const DF_FRAME_FORM_CONTINUATION = 0;

/**
 * One endpoint's directional keys. `sendKey` seals what this endpoint emits,
 * `recvKey` opens what it receives; the receiver's pair is the sender's
 * swapped.
 */
export interface IDfLaneKeys {
	sendKey: Buffer;
	recvKey: Buffer;
}

export interface IDfSenderLane {
	keys: IDfLaneKeys;
	/** Published in the clear on the first frame so the receiver can derive. */
	ephemeralPublicKey: Buffer;
}

export interface IDfSealedFrame {
	nonce: Buffer;
	/** Ciphertext with the 16-byte Poly1305 tag appended. */
	ciphertext: Buffer;
}

/** A sealed frame as it arrives, before any key is known. */
export interface IDfWireFrame extends IDfSealedFrame {
	/** Present on an opening frame only. */
	requestId?: Buffer;
	ephemeralPublicKey?: Buffer;
}

export interface IDfRequestEncryptionKeys {
	publicKey: Buffer;
	privateKey: Buffer;
}

function randomPrivateKey(): Buffer {
	let key: Buffer;
	do {
		key = crypto.randomBytes(32);
	} while (!isValidPrivateKey(key));
	return key;
}

/**
 * A fresh per-request keypair. secp256k1 rather than X25519 so the protocol
 * needs no primitive Lightning does not already require.
 */
export function mintRequestEncryptionKeys(): IDfRequestEncryptionKeys {
	const privateKey = randomPrivateKey();
	return { publicKey: getPublicKey(privateKey), privateKey };
}

function requireRequestId(requestId: Buffer): Buffer {
	if (requestId.length !== DF_REQUEST_ID_BYTES) {
		throw new Error(
			`request id must be ${DF_REQUEST_ID_BYTES} bytes, got ${requestId.length}`
		);
	}
	return requestId;
}

function directionalKey(
	shared: Buffer,
	requestId: Buffer,
	info: string
): Buffer {
	return hkdf(
		requireRequestId(requestId),
		shared,
		Buffer.from(info, 'utf8'),
		DF_FRAME_KEY_BYTES
	);
}

/**
 * Payer side: an ephemeral key against the request's published key.
 *
 * @param ephemeralPrivateKey Supply one only to reproduce a fixed vector;
 *   production callers let it be minted.
 */
export function senderLaneKeys(
	requestEncryptionKey: Buffer,
	requestId: Buffer,
	ephemeralPrivateKey?: Buffer
): IDfSenderLane {
	const eph = ephemeralPrivateKey ?? randomPrivateKey();
	const shared = ecdh(eph, requestEncryptionKey);
	return {
		keys: {
			sendKey: directionalKey(shared, requestId, DF_INFO_SENDER_TO_RECEIVER),
			recvKey: directionalKey(shared, requestId, DF_INFO_RECEIVER_TO_SENDER)
		},
		ephemeralPublicKey: getPublicKey(eph)
	};
}

/** Receiver side: the request's private key against the payer's ephemeral. */
export function receiverLaneKeys(
	requestPrivateKey: Buffer,
	ephemeralPublicKey: Buffer,
	requestId: Buffer
): IDfLaneKeys {
	const shared = ecdh(requestPrivateKey, ephemeralPublicKey);
	return {
		sendKey: directionalKey(shared, requestId, DF_INFO_RECEIVER_TO_SENDER),
		recvKey: directionalKey(shared, requestId, DF_INFO_SENDER_TO_RECEIVER)
	};
}

/** Convenience for a payer holding a verified envelope. */
export function senderLaneKeysForEnvelope(
	env: IDfRequestEnvelope,
	ephemeralPrivateKey?: Buffer
): IDfSenderLane {
	return senderLaneKeys(env.encryptionKey, env.requestId, ephemeralPrivateKey);
}

/** Associated data: `request_id || u16 subtype`. */
function frameAad(requestId: Buffer, subtype: number): Buffer {
	if (!Number.isInteger(subtype) || subtype < 0 || subtype > 0xffff) {
		throw new Error(`frame subtype out of range: ${subtype}`);
	}
	const aad = Buffer.alloc(DF_REQUEST_ID_BYTES + 2);
	requireRequestId(requestId).copy(aad, 0);
	aad.writeUInt16BE(subtype, DF_REQUEST_ID_BYTES);
	return aad;
}

/** Seal one frame. The nonce is fresh on every call, retransmits included. */
export function sealFrame(
	key: Buffer,
	requestId: Buffer,
	subtype: number,
	plaintext: Buffer
): IDfSealedFrame {
	const aad = frameAad(requestId, subtype);
	const nonce = crypto.randomBytes(DF_FRAME_NONCE_BYTES);
	return { nonce, ciphertext: encrypt(key, nonce, plaintext, aad) };
}

/** Open one frame, or null when it does not authenticate. Never throws. */
export function openFrame(
	key: Buffer,
	requestId: Buffer,
	subtype: number,
	frame: IDfSealedFrame
): Buffer | null {
	try {
		return decrypt(
			key,
			frame.nonce,
			frame.ciphertext,
			frameAad(requestId, subtype)
		);
	} catch {
		return null;
	}
}

/**
 * Frame wire form:
 *
 *   u8 form
 *   [16 request_id || 33 ephemeral_public_key]   (opening form only)
 *   12 nonce
 *   ciphertext || tag                            (to the end of the payload)
 *
 * The subtype is not in here: it rides the custom-message envelope (#546) and
 * is bound into the frame's associated data, so a relay cannot re-label a
 * frame without breaking authentication.
 */
export function encodeSealedFrame(
	frame: IDfSealedFrame,
	opening?: { requestId: Buffer; ephemeralPublicKey: Buffer }
): Buffer {
	if (frame.nonce.length !== DF_FRAME_NONCE_BYTES) {
		throw new Error(`frame nonce must be ${DF_FRAME_NONCE_BYTES} bytes`);
	}
	if (!opening) {
		return Buffer.concat([
			Buffer.from([DF_FRAME_FORM_CONTINUATION]),
			frame.nonce,
			frame.ciphertext
		]);
	}
	requireRequestId(opening.requestId);
	if (opening.ephemeralPublicKey.length !== DF_NODE_ID_BYTES) {
		throw new Error(`ephemeral key must be ${DF_NODE_ID_BYTES} bytes`);
	}
	return Buffer.concat([
		Buffer.from([DF_FRAME_FORM_OPENING]),
		opening.requestId,
		opening.ephemeralPublicKey,
		frame.nonce,
		frame.ciphertext
	]);
}

/**
 * Parse a frame off the wire, or null when the bytes are not one. Null rather
 * than a throw for the same reason openFrame returns null: a peer probing
 * with junk learns nothing and costs nothing.
 */
export function decodeSealedFrame(data: Buffer): IDfWireFrame | null {
	if (data.length < 1) return null;
	const form = data[0];
	let off = 1;
	let requestId: Buffer | undefined;
	let ephemeralPublicKey: Buffer | undefined;
	if (form === DF_FRAME_FORM_OPENING) {
		if (data.length < 1 + DF_REQUEST_ID_BYTES + DF_NODE_ID_BYTES) return null;
		requestId = Buffer.from(data.subarray(off, off + DF_REQUEST_ID_BYTES));
		off += DF_REQUEST_ID_BYTES;
		ephemeralPublicKey = Buffer.from(
			data.subarray(off, off + DF_NODE_ID_BYTES)
		);
		off += DF_NODE_ID_BYTES;
	} else if (form !== DF_FRAME_FORM_CONTINUATION) {
		return null;
	}
	if (data.length < off + DF_FRAME_NONCE_BYTES + DF_FRAME_TAG_BYTES) {
		return null;
	}
	const nonce = Buffer.from(data.subarray(off, off + DF_FRAME_NONCE_BYTES));
	const ciphertext = Buffer.from(data.subarray(off + DF_FRAME_NONCE_BYTES));
	return {
		nonce,
		ciphertext,
		...(requestId ? { requestId } : {}),
		...(ephemeralPublicKey ? { ephemeralPublicKey } : {})
	};
}
