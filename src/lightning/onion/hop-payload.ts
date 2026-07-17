/**
 * BOLT 4: Hop Payload Encoding/Decoding
 *
 * Modern TLV-format hop payloads used in onion routing.
 * Each hop payload contains:
 *   - BigSize payload_length
 *   - TLV records: type 2 (amt_to_forward), type 4 (outgoing_cltv_value),
 *     type 6 (short_channel_id, omitted for final hop)
 *
 * Values use truncated unsigned integer encoding (minimal big-endian).
 */

import { encodeBigSize, decodeBigSize } from '../message/codec';
import { IHopPayload, KEYSEND_TLV_TYPE } from './types';

/**
 * Encode a value as a truncated unsigned integer (minimal big-endian).
 * Value 0 → empty buffer.
 */
export function encodeTruncatedUint(value: bigint): Buffer {
	if (value === 0n) {
		return Buffer.alloc(0);
	}
	const hex = value.toString(16);
	const paddedHex = hex.length % 2 === 1 ? '0' + hex : hex;
	return Buffer.from(paddedHex, 'hex');
}

/**
 * Decode a truncated unsigned integer from a buffer (big-endian).
 * Empty buffer → 0.
 */
export function decodeTruncatedUint(buf: Buffer): bigint {
	if (buf.length === 0) {
		return 0n;
	}
	let result = 0n;
	for (let i = 0; i < buf.length; i++) {
		result = (result << 8n) | BigInt(buf[i]);
	}
	return result;
}

/**
 * Encode a single TLV record: BigSize type + BigSize length + value.
 */
function encodeTlvRecord(type: number, value: Buffer): Buffer {
	const typeBytes = encodeBigSize(BigInt(type));
	const lengthBytes = encodeBigSize(BigInt(value.length));
	return Buffer.concat([typeBytes, lengthBytes, value]);
}

/**
 * Encode a hop payload as TLV with BigSize length prefix.
 */
export function encodeHopPayload(payload: IHopPayload): Buffer {
	const records: { type: number; value: Buffer }[] = [];

	// BOLT 4: a blinded INTERMEDIATE hop's payload carries ONLY
	// encrypted_recipient_data (+ the introduction node's blinding_point). It MUST
	// NOT include amt_to_forward / outgoing_cltv_value (the hop derives those from
	// its encrypted payment_relay + the incoming HTLC). Including them makes LND
	// reject the onion with invalid_onion_blinding.
	if (!payload.omitForwardAmounts) {
		// Type 2: amt_to_forward (tu64)
		records.push({
			type: 2,
			value: encodeTruncatedUint(payload.amountToForwardMsat)
		});

		// Type 4: outgoing_cltv_value (tu32)
		records.push({
			type: 4,
			value: encodeTruncatedUint(BigInt(payload.outgoingCltvValue))
		});
	}

	// Type 6: short_channel_id (8 bytes, omitted for final hop)
	if (payload.shortChannelId) {
		records.push({ type: 6, value: payload.shortChannelId });
	}

	// Type 8: payment_data — payment_secret (32 bytes) + total_msat (tu64)
	if (payload.paymentSecret) {
		const totalMsatBytes = encodeTruncatedUint(
			payload.totalMsat ?? payload.amountToForwardMsat
		);
		records.push({
			type: 8,
			value: Buffer.concat([payload.paymentSecret, totalMsatBytes])
		});
	}

	// Type 10: encrypted_recipient_data (blinded hop)
	if (payload.encryptedRecipientData) {
		records.push({ type: 10, value: payload.encryptedRecipientData });
	}

	// Type 12: blinding_point (33-byte ephemeral key)
	if (payload.blindingPoint) {
		records.push({ type: 12, value: payload.blindingPoint });
	}

	// Type 18: total_amount_msat (tu64) — blinded final hop
	if (payload.totalAmountMsat !== undefined) {
		records.push({
			type: 18,
			value: encodeTruncatedUint(payload.totalAmountMsat)
		});
	}

	// Custom TLV records (e.g. keysend preimage)
	if (payload.customRecords && payload.customRecords.size > 0) {
		for (const [type, value] of payload.customRecords.entries()) {
			records.push({ type, value });
		}
	}

	// BOLT 1: a TLV stream MUST be strictly increasing by type. Sort the FULL
	// record set (a custom record type below 12 would otherwise be appended out
	// of order and rejected by our own hardened decoder).
	records.sort((a, b) => a.type - b.type);
	const tlvData = Buffer.concat(
		records.map((r) => encodeTlvRecord(r.type, r.value))
	);
	const lengthPrefix = encodeBigSize(BigInt(tlvData.length));
	return Buffer.concat([lengthPrefix, tlvData]);
}

/**
 * Decode a hop payload from a buffer at the given offset.
 * Returns the decoded payload and total bytes consumed (including length prefix).
 */
export function decodeHopPayload(
	buf: Buffer,
	offset: number
): { payload: IHopPayload; bytesRead: number } {
	const startOffset = offset;

	// Read payload length
	const { value: payloadLength, bytesRead: lenBytes } = decodeBigSize(
		buf,
		offset
	);
	offset += lenBytes;

	const payloadEnd = offset + Number(payloadLength);
	if (payloadEnd > buf.length) {
		throw new Error('Hop payload extends beyond buffer');
	}
	// BOLT 4: a length of 0 or 1 is the legacy/reserved form and is invalid for
	// a TLV hop payload — reject as invalid_onion_payload rather than parse an
	// empty/garbage TLV stream.
	if (payloadLength < 2n) {
		throw new Error(
			`Invalid hop payload length ${payloadLength} (invalid_onion_payload)`
		);
	}

	let amountToForwardMsat = 0n;
	let outgoingCltvValue = 0;
	let shortChannelId: Buffer | undefined;
	let paymentSecret: Buffer | undefined;
	let totalMsat: bigint | undefined;
	let encryptedRecipientData: Buffer | undefined;
	let blindingPoint: Buffer | undefined;
	let totalAmountMsat: bigint | undefined;
	let customRecords: Map<number, Buffer> | undefined;

	let prevTlvType: number | undefined;
	while (offset < payloadEnd) {
		// Read TLV type
		const typeResult = decodeBigSize(buf, offset);
		offset += typeResult.bytesRead;
		const tlvType = Number(typeResult.value);

		// BOLT 1/4: TLV records MUST be strictly increasing by type (this also
		// rejects duplicates). A misordered/duplicate stream is
		// invalid_onion_payload.
		if (prevTlvType !== undefined && tlvType <= prevTlvType) {
			throw new Error(
				`Hop payload TLV type ${tlvType} out of order after ${prevTlvType} (invalid_onion_payload)`
			);
		}
		prevTlvType = tlvType;

		// Read TLV length
		const lengthResult = decodeBigSize(buf, offset);
		offset += lengthResult.bytesRead;
		const tlvLength = Number(lengthResult.value);

		if (offset + tlvLength > payloadEnd) {
			throw new Error('Hop payload TLV extends beyond the payload');
		}
		const tlvValue = buf.subarray(offset, offset + tlvLength);
		offset += tlvLength;

		switch (tlvType) {
			case 2:
				amountToForwardMsat = decodeTruncatedUint(tlvValue);
				break;
			case 4:
				outgoingCltvValue = Number(decodeTruncatedUint(tlvValue));
				break;
			case 6:
				shortChannelId = Buffer.from(tlvValue);
				break;
			case 8:
				// payment_data: 32-byte payment_secret + remaining bytes as tu64 total_msat
				if (tlvValue.length >= 32) {
					paymentSecret = Buffer.from(tlvValue.subarray(0, 32));
					totalMsat = decodeTruncatedUint(tlvValue.subarray(32));
				}
				break;
			case 10:
				// encrypted_recipient_data (blinded hop)
				encryptedRecipientData = Buffer.from(tlvValue);
				break;
			case 12:
				// blinding_point (33 bytes)
				blindingPoint = Buffer.from(tlvValue);
				break;
			case 18:
				// total_amount_msat (tu64) — blinded final hop
				totalAmountMsat = decodeTruncatedUint(tlvValue);
				break;
			default:
				// Keysend TLV (5482373484) is even but is a widely-deployed de facto standard
				if (tlvType === KEYSEND_TLV_TYPE) {
					if (!customRecords) customRecords = new Map();
					customRecords.set(tlvType, Buffer.from(tlvValue));
				} else if (tlvType % 2 === 0) {
					// Unknown even types are an error per BOLT spec
					throw new Error(
						`Unknown required TLV type ${tlvType} in hop payload`
					);
				} else {
					// Unknown odd types are stored as custom records
					if (!customRecords) customRecords = new Map();
					customRecords.set(tlvType, Buffer.from(tlvValue));
				}
				break;
		}
	}

	const result: IHopPayload = { amountToForwardMsat, outgoingCltvValue };
	if (shortChannelId) {
		result.shortChannelId = shortChannelId;
	}
	if (paymentSecret) {
		result.paymentSecret = paymentSecret;
		result.totalMsat = totalMsat;
	}
	if (encryptedRecipientData) {
		result.encryptedRecipientData = encryptedRecipientData;
	}
	if (blindingPoint) {
		result.blindingPoint = blindingPoint;
	}
	if (totalAmountMsat !== undefined) {
		result.totalAmountMsat = totalAmountMsat;
	}
	if (customRecords) {
		result.customRecords = customRecords;
	}

	return { payload: result, bytesRead: offset - startOffset };
}
