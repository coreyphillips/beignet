/**
 * BOLT 2: `funding_created`, `funding_signed`, and `channel_ready` message
 * encoding/decoding.
 *
 * funding_created (type 34):
 *   [32: temporary_channel_id]
 *   [32: funding_txid]
 *   [2: funding_output_index]
 *   [64: signature]
 *
 * funding_signed (type 35):
 *   [32: channel_id]
 *   [64: signature]
 *
 * channel_ready (type 36):
 *   [32: channel_id]
 *   [33: second_per_commitment_point]
 *   [channel_ready_tlvs]
 */

import { decodeTlvStream, encodeTlvStream, ITlvRecord } from './tlv';

const TLV_SHORT_CHANNEL_ID = 1n;
// option_taproot: next_local_nonce verification nonce (TLV type 4, matching the
// open/accept/revoke convention).
const TLV_NEXT_LOCAL_NONCE = 4n;
// option_taproot: partial_signature_with_nonce (TLV type 2, LND convention;
// pin at interop). Same type/layout as commitment_signed — 32-byte MuSig2
// partial signature || 66-byte public (signing) nonce.
const TLV_PARTIAL_SIG_WITH_NONCE = 2n;

export interface IFundingCreatedMessage {
	temporaryChannelId: Buffer;
	fundingTxid: Buffer;
	fundingOutputIndex: number;
	signature: Buffer;
	/**
	 * option_taproot: the funder's 98-byte partial_signature_with_nonce (32-byte
	 * MuSig2 partial signature over the acceptor's initial commitment #0 || the
	 * funder's 66-byte single-use signing nonce). When present the fixed 64-byte
	 * `signature` field is all-zero. TLV type 2.
	 */
	partialSignatureWithNonce?: Buffer;
}

export interface IFundingSignedMessage {
	channelId: Buffer;
	signature: Buffer;
	/**
	 * option_taproot: the acceptor's 98-byte partial_signature_with_nonce (32-byte
	 * MuSig2 partial signature over the funder's initial commitment #0 || the
	 * acceptor's 66-byte single-use signing nonce). When present the fixed 64-byte
	 * `signature` field is all-zero. TLV type 2.
	 */
	partialSignatureWithNonce?: Buffer;
}

export interface IChannelReadyMessage {
	channelId: Buffer;
	secondPerCommitmentPoint: Buffer;
	shortChannelId?: Buffer;
	/**
	 * option_taproot: our 66-byte MuSig2 verification nonce for commitment #1 — the
	 * bootstrap of the verification-nonce pipeline, mirroring how
	 * second_per_commitment_point seeds the per-commitment-point pipeline. The peer
	 * uses this to co-sign our first post-funding commitment. TLV type 4 (matches
	 * the open/accept/revoke next_local_nonce convention; pin at interop).
	 */
	nextLocalNonce?: Buffer;
}

const FUNDING_CREATED_LENGTH = 130; // 32 + 32 + 2 + 64
const FUNDING_SIGNED_LENGTH = 96; // 32 + 64
const CHANNEL_READY_FIXED_LENGTH = 65; // 32 + 33

/**
 * Encode a `funding_created` message payload.
 */
export function encodeFundingCreatedMessage(
	msg: IFundingCreatedMessage
): Buffer {
	const buf = Buffer.alloc(FUNDING_CREATED_LENGTH);
	let offset = 0;

	msg.temporaryChannelId.copy(buf, offset);
	offset += 32;
	msg.fundingTxid.copy(buf, offset);
	offset += 32;
	buf.writeUInt16BE(msg.fundingOutputIndex, offset);
	offset += 2;
	msg.signature.copy(buf, offset);

	// option_taproot: append partial_signature_with_nonce (TLV type 2).
	if (msg.partialSignatureWithNonce) {
		if (msg.partialSignatureWithNonce.length !== 98) {
			throw new Error(
				`partial_signature_with_nonce must be 98 bytes, got ${msg.partialSignatureWithNonce.length}`
			);
		}
		return Buffer.concat([
			buf,
			encodeTlvStream([
				{
					type: TLV_PARTIAL_SIG_WITH_NONCE,
					value: msg.partialSignatureWithNonce
				}
			])
		]);
	}

	return buf;
}

/**
 * Decode a `funding_created` message payload.
 */
export function decodeFundingCreatedMessage(
	payload: Buffer
): IFundingCreatedMessage {
	if (payload.length < FUNDING_CREATED_LENGTH) {
		throw new Error(
			`funding_created too short: need ${FUNDING_CREATED_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const temporaryChannelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const fundingTxid = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const fundingOutputIndex = payload.readUInt16BE(offset);
	offset += 2;
	const signature = Buffer.from(payload.subarray(offset, offset + 64));
	offset += 64;

	const result: IFundingCreatedMessage = {
		temporaryChannelId,
		fundingTxid,
		fundingOutputIndex,
		signature
	};

	// option_taproot: parse the optional partial_signature_with_nonce (TLV type 2).
	if (offset < payload.length) {
		const { records } = decodeTlvStream(payload, offset);
		for (const record of records) {
			if (
				record.type === TLV_PARTIAL_SIG_WITH_NONCE &&
				record.value.length === 98
			) {
				result.partialSignatureWithNonce = Buffer.from(record.value);
			}
		}
	}

	return result;
}

/**
 * Encode a `funding_signed` message payload.
 */
export function encodeFundingSignedMessage(msg: IFundingSignedMessage): Buffer {
	const buf = Buffer.alloc(FUNDING_SIGNED_LENGTH);
	msg.channelId.copy(buf, 0);
	msg.signature.copy(buf, 32);

	// option_taproot: append partial_signature_with_nonce (TLV type 2).
	if (msg.partialSignatureWithNonce) {
		if (msg.partialSignatureWithNonce.length !== 98) {
			throw new Error(
				`partial_signature_with_nonce must be 98 bytes, got ${msg.partialSignatureWithNonce.length}`
			);
		}
		return Buffer.concat([
			buf,
			encodeTlvStream([
				{
					type: TLV_PARTIAL_SIG_WITH_NONCE,
					value: msg.partialSignatureWithNonce
				}
			])
		]);
	}

	return buf;
}

/**
 * Decode a `funding_signed` message payload.
 */
export function decodeFundingSignedMessage(
	payload: Buffer
): IFundingSignedMessage {
	if (payload.length < FUNDING_SIGNED_LENGTH) {
		throw new Error(
			`funding_signed too short: need ${FUNDING_SIGNED_LENGTH} bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const signature = Buffer.from(payload.subarray(32, 96));

	const result: IFundingSignedMessage = { channelId, signature };

	// option_taproot: parse the optional partial_signature_with_nonce (TLV type 2).
	if (payload.length > FUNDING_SIGNED_LENGTH) {
		const { records } = decodeTlvStream(payload, FUNDING_SIGNED_LENGTH);
		for (const record of records) {
			if (
				record.type === TLV_PARTIAL_SIG_WITH_NONCE &&
				record.value.length === 98
			) {
				result.partialSignatureWithNonce = Buffer.from(record.value);
			}
		}
	}

	return result;
}

/**
 * Encode a `channel_ready` message payload.
 */
export function encodeChannelReadyMessage(msg: IChannelReadyMessage): Buffer {
	const buf = Buffer.alloc(CHANNEL_READY_FIXED_LENGTH);
	msg.channelId.copy(buf, 0);
	msg.secondPerCommitmentPoint.copy(buf, 32);

	const parts: Buffer[] = [buf];

	const tlvRecords: ITlvRecord[] = [];
	if (msg.shortChannelId) {
		tlvRecords.push({ type: TLV_SHORT_CHANNEL_ID, value: msg.shortChannelId });
	}
	if (msg.nextLocalNonce) {
		if (msg.nextLocalNonce.length !== 66) {
			throw new Error(
				`channel_ready next_local_nonce must be 66 bytes, got ${msg.nextLocalNonce.length}`
			);
		}
		tlvRecords.push({
			type: TLV_NEXT_LOCAL_NONCE,
			value: msg.nextLocalNonce
		});
	}
	if (tlvRecords.length > 0) {
		// TLV records must be in ascending type order.
		tlvRecords.sort((a, b) => (a.type < b.type ? -1 : 1));
		parts.push(encodeTlvStream(tlvRecords));
	}

	return Buffer.concat(parts);
}

/**
 * Decode a `channel_ready` message payload.
 */
export function decodeChannelReadyMessage(
	payload: Buffer
): IChannelReadyMessage {
	if (payload.length < CHANNEL_READY_FIXED_LENGTH) {
		throw new Error(
			`channel_ready too short: need ${CHANNEL_READY_FIXED_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;
	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const secondPerCommitmentPoint = Buffer.from(
		payload.subarray(offset, offset + 33)
	);
	offset += 33;

	const result: IChannelReadyMessage = { channelId, secondPerCommitmentPoint };

	if (offset < payload.length) {
		const { records } = decodeTlvStream(payload, offset);
		for (const record of records) {
			if (record.type === TLV_SHORT_CHANNEL_ID) {
				result.shortChannelId = record.value;
			} else if (
				record.type === TLV_NEXT_LOCAL_NONCE &&
				record.value.length === 66
			) {
				result.nextLocalNonce = Buffer.from(record.value);
			}
		}
	}

	return result;
}
