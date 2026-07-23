/**
 * BOLT 4: Failure Message Handling
 *
 * When a hop fails an HTLC, it creates an encrypted error message that
 * propagates back to the sender. Each intermediate hop wraps the error
 * with its own key, and only the sender can unwrap all layers.
 *
 * Failure packet structure (BOLT 4):
 *   HMAC-SHA256(um, remainder) [32 bytes]
 *   failure_len [2 bytes: actual failuremsg length]
 *   failuremsg [failure_len bytes: failureCode(2) + failureData(var)]
 *   pad_len [2 bytes]
 *   pad [pad_len zero bytes; failuremsg + pad = 256]
 * Total inner = 32 + 2 + 256 + 2 = 292 bytes.
 * Then XOR with generateCipherStream(ammag, 292).
 */

import crypto from 'crypto';
import {
	IOnionFailure,
	INVALID_ONION_VERSION,
	INVALID_ONION_HMAC,
	INVALID_ONION_KEY,
	AMOUNT_BELOW_MINIMUM,
	FEE_INSUFFICIENT,
	INCORRECT_CLTV_EXPIRY,
	EXPIRY_TOO_SOON,
	UNKNOWN_NEXT_PEER,
	REQUIRED_CHANNEL_FEATURE_MISSING,
	TEMPORARY_CHANNEL_FAILURE,
	INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
	FINAL_INCORRECT_CLTV_EXPIRY,
	FINAL_INCORRECT_HTLC_AMOUNT,
	MPP_TIMEOUT,
	TEMPORARY_NODE_FAILURE,
	EXPIRY_TOO_FAR,
	CHANNEL_DISABLED,
	PERMANENT_NODE_FAILURE,
	PERMANENT_CHANNEL_FAILURE,
	REQUIRED_NODE_FEATURE_MISSING
} from './types';
import { deriveHopKeys, generateCipherStream } from './sphinx-crypto';

const FAILURE_PAYLOAD_LENGTH = 256; // failuremsg + pad (BOLT 4 SHOULD)
// 32 (HMAC) + 2 (failure_len) + 256 (failuremsg + pad) + 2 (pad_len)
export const FAILURE_MESSAGE_LENGTH = 292;

/**
 * Encode the failure plaintext the HMAC covers (BOLT 4):
 *   failure_len(2) || failureCode(2) + failureData || pad_len(2) || pad
 * with failuremsg + pad totalling 256 bytes.
 */
export function encodeFailurePayload(
	failureCode: number,
	failureData: Buffer = Buffer.alloc(0)
): Buffer {
	const failureLen = 2 + failureData.length;
	if (failureLen > FAILURE_PAYLOAD_LENGTH) {
		throw new Error('Failure data too large');
	}
	const padLen = FAILURE_PAYLOAD_LENGTH - failureLen;
	const payload = Buffer.alloc(2 + FAILURE_PAYLOAD_LENGTH + 2);
	payload.writeUInt16BE(failureLen, 0);
	payload.writeUInt16BE(failureCode, 2);
	failureData.copy(payload, 4);
	payload.writeUInt16BE(padLen, 2 + failureLen);
	return payload;
}

/**
 * Create an encrypted failure message at the originating hop.
 * Returns a 292-byte encrypted message.
 */
export function createFailureMessage(
	sharedSecret: Buffer,
	failureCode: number,
	failureData: Buffer = Buffer.alloc(0)
): Buffer {
	const keys = deriveHopKeys(sharedSecret);

	// The HMAC covers everything after itself:
	// failure_len || failuremsg || pad_len || pad (spec plaintext).
	const plaintext = encodeFailurePayload(failureCode, failureData);
	const hmac = crypto.createHmac('sha256', keys.um).update(plaintext).digest();

	const inner = Buffer.concat([hmac, plaintext]);

	// XOR with ammag cipher stream
	const stream = generateCipherStream(keys.ammag, FAILURE_MESSAGE_LENGTH);
	const encrypted = Buffer.alloc(FAILURE_MESSAGE_LENGTH);
	for (let i = 0; i < FAILURE_MESSAGE_LENGTH; i++) {
		encrypted[i] = inner[i] ^ stream[i];
	}

	return encrypted;
}

/**
 * Wrap a failure message at an intermediate hop.
 * XOR the existing message with this hop's ammag cipher stream.
 */
export function wrapFailureMessage(
	sharedSecret: Buffer,
	message: Buffer
): Buffer {
	const keys = deriveHopKeys(sharedSecret);
	const stream = generateCipherStream(keys.ammag, message.length);
	const wrapped = Buffer.alloc(message.length);
	for (let i = 0; i < message.length; i++) {
		wrapped[i] = message[i] ^ stream[i];
	}
	return wrapped;
}

/**
 * Decrypt a failure message by trying each shared secret.
 * Returns the originating hop index and decoded failure, or null if invalid.
 */
export function decryptFailureMessage(
	sharedSecrets: Buffer[],
	message: Buffer
): { originIndex: number; failure: IOnionFailure } | null {
	let current = Buffer.from(message);

	for (let i = 0; i < sharedSecrets.length; i++) {
		const keys = deriveHopKeys(sharedSecrets[i]);
		const stream = generateCipherStream(keys.ammag, current.length);
		const decrypted = Buffer.alloc(current.length);
		for (let j = 0; j < current.length; j++) {
			decrypted[j] = current[j] ^ stream[j];
		}

		// Check HMAC
		const hmac = decrypted.subarray(0, 32);
		const lenAndPad = decrypted.subarray(32);
		const expectedHmac = crypto
			.createHmac('sha256', keys.um)
			.update(lenAndPad)
			.digest();

		if (hmac.equals(expectedHmac)) {
			// Valid! Decode failure
			const len = lenAndPad.readUInt16BE(0);
			const payload = lenAndPad.subarray(2, 2 + len);
			const failureCode = payload.readUInt16BE(0);
			const failureData = Buffer.from(payload.subarray(2));
			return {
				originIndex: i,
				failure: {
					failureCode,
					failureData
				}
			};
		}

		// Not this hop — the decrypted version becomes input for next iteration
		current = decrypted;
	}

	return null;
}

/**
 * Extract a channel_update message from failure data.
 * Per BOLT 4, failure types with `hasChannelUpdate` embed a channel_update
 * in the failure data as: [2-byte len][channel_update].
 *
 * Some implementations include the 2-byte type prefix (0x0102 = 258),
 * others omit it. This function handles both cases.
 *
 * @returns The channel_update payload (without type prefix), or null if not present.
 */
export function extractChannelUpdate(
	failureCode: number,
	failureData: Buffer
): Buffer | null {
	const { hasChannelUpdate } = decodeFailureCode(failureCode);
	if (!hasChannelUpdate) return null;

	if (!failureData || failureData.length < 4) return null;

	// Some failure codes have fixed-length fields before the channel_update length:
	// FEE_INSUFFICIENT: 8 bytes (htlc_msat) + 4 bytes (update len prefix)
	// AMOUNT_BELOW_MINIMUM: 8 bytes (htlc_msat) + 2 bytes (len)
	// INCORRECT_CLTV_EXPIRY: 4 bytes (cltv_expiry) + 2 bytes (len)
	// EXPIRY_TOO_SOON: 2 bytes (len)
	// TEMPORARY_CHANNEL_FAILURE: 2 bytes (len)
	let offset = 0;
	if (
		failureCode === FEE_INSUFFICIENT ||
		failureCode === AMOUNT_BELOW_MINIMUM
	) {
		offset = 8; // Skip htlc_msat (8 bytes)
	} else if (failureCode === INCORRECT_CLTV_EXPIRY) {
		offset = 4; // Skip cltv_expiry (4 bytes)
	} else if (failureCode === CHANNEL_DISABLED) {
		offset = 2; // Skip flags (2 bytes)
	}
	// EXPIRY_TOO_SOON and TEMPORARY_CHANNEL_FAILURE start with the length directly

	if (failureData.length < offset + 2) return null;

	const updateLen = failureData.readUInt16BE(offset);
	const updateStart = offset + 2;

	if (failureData.length < updateStart + updateLen || updateLen < 2)
		return null;

	let updatePayload = failureData.subarray(
		updateStart,
		updateStart + updateLen
	);

	// Check if the update starts with the type prefix 0x0102 (258 = channel_update)
	if (updatePayload.length >= 2 && updatePayload.readUInt16BE(0) === 258) {
		updatePayload = updatePayload.subarray(2);
	}

	return updatePayload;
}

/**
 * Decode a failure code to a human-readable name and whether it
 * includes a channel_update in its failure data.
 */
export function decodeFailureCode(code: number): {
	name: string;
	hasChannelUpdate: boolean;
} {
	const codes: Record<number, { name: string; hasChannelUpdate: boolean }> = {
		[INVALID_ONION_VERSION]: {
			name: 'invalid_onion_version',
			hasChannelUpdate: false
		},
		[INVALID_ONION_HMAC]: {
			name: 'invalid_onion_hmac',
			hasChannelUpdate: false
		},
		[INVALID_ONION_KEY]: { name: 'invalid_onion_key', hasChannelUpdate: false },
		[AMOUNT_BELOW_MINIMUM]: {
			name: 'amount_below_minimum',
			hasChannelUpdate: true
		},
		[FEE_INSUFFICIENT]: { name: 'fee_insufficient', hasChannelUpdate: true },
		[INCORRECT_CLTV_EXPIRY]: {
			name: 'incorrect_cltv_expiry',
			hasChannelUpdate: true
		},
		[EXPIRY_TOO_SOON]: { name: 'expiry_too_soon', hasChannelUpdate: true },
		[UNKNOWN_NEXT_PEER]: { name: 'unknown_next_peer', hasChannelUpdate: false },
		[REQUIRED_CHANNEL_FEATURE_MISSING]: {
			name: 'required_channel_feature_missing',
			hasChannelUpdate: false
		},
		[TEMPORARY_CHANNEL_FAILURE]: {
			name: 'temporary_channel_failure',
			hasChannelUpdate: true
		},
		[INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS]: {
			name: 'incorrect_or_unknown_payment_details',
			hasChannelUpdate: false
		},
		[FINAL_INCORRECT_CLTV_EXPIRY]: {
			name: 'final_incorrect_cltv_expiry',
			hasChannelUpdate: false
		},
		[FINAL_INCORRECT_HTLC_AMOUNT]: {
			name: 'final_incorrect_htlc_amount',
			hasChannelUpdate: false
		},
		[MPP_TIMEOUT]: { name: 'mpp_timeout', hasChannelUpdate: false },
		[TEMPORARY_NODE_FAILURE]: {
			name: 'temporary_node_failure',
			hasChannelUpdate: false
		},
		[EXPIRY_TOO_FAR]: { name: 'expiry_too_far', hasChannelUpdate: false },
		[CHANNEL_DISABLED]: { name: 'channel_disabled', hasChannelUpdate: true },
		[PERMANENT_NODE_FAILURE]: {
			name: 'permanent_node_failure',
			hasChannelUpdate: false
		},
		[PERMANENT_CHANNEL_FAILURE]: {
			name: 'permanent_channel_failure',
			hasChannelUpdate: false
		},
		[REQUIRED_NODE_FEATURE_MISSING]: {
			name: 'required_node_feature_missing',
			hasChannelUpdate: false
		}
	};
	const entry = codes[code];
	if (entry) {
		return entry;
	}
	return { name: `unknown(${code})`, hasChannelUpdate: false };
}
