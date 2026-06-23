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

export interface IFundingCreatedMessage {
	temporaryChannelId: Buffer;
	fundingTxid: Buffer;
	fundingOutputIndex: number;
	signature: Buffer;
}

export interface IFundingSignedMessage {
	channelId: Buffer;
	signature: Buffer;
}

export interface IChannelReadyMessage {
	channelId: Buffer;
	secondPerCommitmentPoint: Buffer;
	shortChannelId?: Buffer;
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

	return { temporaryChannelId, fundingTxid, fundingOutputIndex, signature };
}

/**
 * Encode a `funding_signed` message payload.
 */
export function encodeFundingSignedMessage(msg: IFundingSignedMessage): Buffer {
	const buf = Buffer.alloc(FUNDING_SIGNED_LENGTH);
	msg.channelId.copy(buf, 0);
	msg.signature.copy(buf, 32);
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

	return { channelId, signature };
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
	if (tlvRecords.length > 0) {
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
			}
		}
	}

	return result;
}
