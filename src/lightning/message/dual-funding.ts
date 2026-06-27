/**
 * BOLT 2: `open_channel2` and `accept_channel2` message encoding/decoding.
 *
 * open_channel2 (type 64):
 *   [32: channel_id]
 *   [4: funding_feerate_perkw]
 *   [4: commitment_feerate_perkw]
 *   [8: funding_satoshis]
 *   [8: dust_limit_satoshis]
 *   [8: max_htlc_value_in_flight_msat]
 *   [8: htlc_minimum_msat]
 *   [2: to_self_delay]
 *   [2: max_accepted_htlcs]
 *   [4: locktime]
 *   [33: funding_pubkey]
 *   [33: revocation_basepoint]
 *   [33: payment_basepoint]
 *   [33: delayed_payment_basepoint]
 *   [33: htlc_basepoint]
 *   [33: first_per_commitment_point]
 *   [33: second_per_commitment_point]
 *   [1: channel_flags]
 *   [open_channel2_tlvs]
 *
 * accept_channel2 (type 65):
 *   [32: channel_id]
 *   [8: funding_satoshis]
 *   [8: dust_limit_satoshis]
 *   [8: max_htlc_value_in_flight_msat]
 *   [8: htlc_minimum_msat]
 *   [4: minimum_depth]
 *   [2: to_self_delay]
 *   [2: max_accepted_htlcs]
 *   [33: funding_pubkey]
 *   [33: revocation_basepoint]
 *   [33: payment_basepoint]
 *   [33: delayed_payment_basepoint]
 *   [33: htlc_basepoint]
 *   [33: first_per_commitment_point]
 *   [33: second_per_commitment_point]
 *   [accept_channel2_tlvs]
 */

import { decodeTlvStream, encodeTlvStream, ITlvRecord } from './tlv';

/** TLV type for channel_type */
const TLV_CHANNEL_TYPE = 1n;

export interface IOpenChannel2Message {
	channelId: Buffer;
	fundingFeeratePerkw: number;
	commitmentFeeratePerkw: number;
	fundingSatoshis: bigint;
	dustLimitSatoshis: bigint;
	maxHtlcValueInFlightMsat: bigint;
	htlcMinimumMsat: bigint;
	toSelfDelay: number;
	maxAcceptedHtlcs: number;
	locktime: number;
	fundingPubkey: Buffer;
	revocationBasepoint: Buffer;
	paymentBasepoint: Buffer;
	delayedPaymentBasepoint: Buffer;
	htlcBasepoint: Buffer;
	firstPerCommitmentPoint: Buffer;
	secondPerCommitmentPoint: Buffer;
	channelFlags: number;
	channelType?: Buffer;
}

export interface IAcceptChannel2Message {
	channelId: Buffer;
	fundingSatoshis: bigint;
	dustLimitSatoshis: bigint;
	maxHtlcValueInFlightMsat: bigint;
	htlcMinimumMsat: bigint;
	minimumDepth: number;
	toSelfDelay: number;
	maxAcceptedHtlcs: number;
	fundingPubkey: Buffer;
	revocationBasepoint: Buffer;
	paymentBasepoint: Buffer;
	delayedPaymentBasepoint: Buffer;
	htlcBasepoint: Buffer;
	firstPerCommitmentPoint: Buffer;
	secondPerCommitmentPoint: Buffer;
	channelType?: Buffer;
}

// open_channel2 fixed payload length:
// 32 + 4 + 4 + 8 + 8 + 8 + 8 + 2 + 2 + 4 + 33*7 + 1 = 312
const OPEN_CHANNEL2_FIXED_LENGTH = 312;

// accept_channel2 fixed payload length:
// 32 + 8 + 8 + 8 + 8 + 4 + 2 + 2 + 33*7 = 303
const ACCEPT_CHANNEL2_FIXED_LENGTH = 303;

/**
 * Encode an `open_channel2` message payload (without 2-byte type prefix).
 */
export function encodeOpenChannel2Message(msg: IOpenChannel2Message): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}

	const buf = Buffer.alloc(OPEN_CHANNEL2_FIXED_LENGTH);
	let offset = 0;

	msg.channelId.copy(buf, offset);
	offset += 32;
	buf.writeUInt32BE(msg.fundingFeeratePerkw, offset);
	offset += 4;
	buf.writeUInt32BE(msg.commitmentFeeratePerkw, offset);
	offset += 4;
	buf.writeBigUInt64BE(msg.fundingSatoshis, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.dustLimitSatoshis, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.maxHtlcValueInFlightMsat, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.htlcMinimumMsat, offset);
	offset += 8;
	buf.writeUInt16BE(msg.toSelfDelay, offset);
	offset += 2;
	buf.writeUInt16BE(msg.maxAcceptedHtlcs, offset);
	offset += 2;
	buf.writeUInt32BE(msg.locktime, offset);
	offset += 4;
	msg.fundingPubkey.copy(buf, offset);
	offset += 33;
	msg.revocationBasepoint.copy(buf, offset);
	offset += 33;
	msg.paymentBasepoint.copy(buf, offset);
	offset += 33;
	msg.delayedPaymentBasepoint.copy(buf, offset);
	offset += 33;
	msg.htlcBasepoint.copy(buf, offset);
	offset += 33;
	msg.firstPerCommitmentPoint.copy(buf, offset);
	offset += 33;
	msg.secondPerCommitmentPoint.copy(buf, offset);
	offset += 33;
	buf[offset] = msg.channelFlags;

	const parts: Buffer[] = [buf];

	// TLV records
	const tlvRecords: ITlvRecord[] = [];
	if (msg.channelType) {
		tlvRecords.push({ type: TLV_CHANNEL_TYPE, value: msg.channelType });
	}
	if (tlvRecords.length > 0) {
		parts.push(encodeTlvStream(tlvRecords));
	}

	return Buffer.concat(parts);
}

/**
 * Decode an `open_channel2` message payload.
 */
export function decodeOpenChannel2Message(
	payload: Buffer
): IOpenChannel2Message {
	if (payload.length < OPEN_CHANNEL2_FIXED_LENGTH) {
		throw new Error(
			`open_channel2 too short: need ${OPEN_CHANNEL2_FIXED_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const fundingFeeratePerkw = payload.readUInt32BE(offset);
	offset += 4;
	const commitmentFeeratePerkw = payload.readUInt32BE(offset);
	offset += 4;
	const fundingSatoshis = payload.readBigUInt64BE(offset);
	offset += 8;
	const dustLimitSatoshis = payload.readBigUInt64BE(offset);
	offset += 8;
	const maxHtlcValueInFlightMsat = payload.readBigUInt64BE(offset);
	offset += 8;
	const htlcMinimumMsat = payload.readBigUInt64BE(offset);
	offset += 8;
	const toSelfDelay = payload.readUInt16BE(offset);
	offset += 2;
	const maxAcceptedHtlcs = payload.readUInt16BE(offset);
	offset += 2;
	const locktime = payload.readUInt32BE(offset);
	offset += 4;
	const fundingPubkey = Buffer.from(payload.subarray(offset, offset + 33));
	offset += 33;
	const revocationBasepoint = Buffer.from(
		payload.subarray(offset, offset + 33)
	);
	offset += 33;
	const paymentBasepoint = Buffer.from(payload.subarray(offset, offset + 33));
	offset += 33;
	const delayedPaymentBasepoint = Buffer.from(
		payload.subarray(offset, offset + 33)
	);
	offset += 33;
	const htlcBasepoint = Buffer.from(payload.subarray(offset, offset + 33));
	offset += 33;
	const firstPerCommitmentPoint = Buffer.from(
		payload.subarray(offset, offset + 33)
	);
	offset += 33;
	const secondPerCommitmentPoint = Buffer.from(
		payload.subarray(offset, offset + 33)
	);
	offset += 33;
	const channelFlags = payload[offset];
	offset += 1;

	const result: IOpenChannel2Message = {
		channelId,
		fundingFeeratePerkw,
		commitmentFeeratePerkw,
		fundingSatoshis,
		dustLimitSatoshis,
		maxHtlcValueInFlightMsat,
		htlcMinimumMsat,
		toSelfDelay,
		maxAcceptedHtlcs,
		locktime,
		fundingPubkey,
		revocationBasepoint,
		paymentBasepoint,
		delayedPaymentBasepoint,
		htlcBasepoint,
		firstPerCommitmentPoint,
		secondPerCommitmentPoint,
		channelFlags
	};

	// Parse TLV
	if (offset < payload.length) {
		const { records } = decodeTlvStream(payload, offset);
		for (const record of records) {
			if (record.type === TLV_CHANNEL_TYPE) {
				result.channelType = record.value;
			}
		}
	}

	return result;
}

/**
 * Encode an `accept_channel2` message payload (without 2-byte type prefix).
 */
export function encodeAcceptChannel2Message(
	msg: IAcceptChannel2Message
): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}

	const buf = Buffer.alloc(ACCEPT_CHANNEL2_FIXED_LENGTH);
	let offset = 0;

	msg.channelId.copy(buf, offset);
	offset += 32;
	buf.writeBigUInt64BE(msg.fundingSatoshis, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.dustLimitSatoshis, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.maxHtlcValueInFlightMsat, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.htlcMinimumMsat, offset);
	offset += 8;
	buf.writeUInt32BE(msg.minimumDepth, offset);
	offset += 4;
	buf.writeUInt16BE(msg.toSelfDelay, offset);
	offset += 2;
	buf.writeUInt16BE(msg.maxAcceptedHtlcs, offset);
	offset += 2;
	msg.fundingPubkey.copy(buf, offset);
	offset += 33;
	msg.revocationBasepoint.copy(buf, offset);
	offset += 33;
	msg.paymentBasepoint.copy(buf, offset);
	offset += 33;
	msg.delayedPaymentBasepoint.copy(buf, offset);
	offset += 33;
	msg.htlcBasepoint.copy(buf, offset);
	offset += 33;
	msg.firstPerCommitmentPoint.copy(buf, offset);
	offset += 33;
	msg.secondPerCommitmentPoint.copy(buf, offset);
	offset += 33;

	const parts: Buffer[] = [buf];

	const tlvRecords: ITlvRecord[] = [];
	if (msg.channelType) {
		tlvRecords.push({ type: TLV_CHANNEL_TYPE, value: msg.channelType });
	}
	if (tlvRecords.length > 0) {
		parts.push(encodeTlvStream(tlvRecords));
	}

	return Buffer.concat(parts);
}

/**
 * Decode an `accept_channel2` message payload.
 */
export function decodeAcceptChannel2Message(
	payload: Buffer
): IAcceptChannel2Message {
	if (payload.length < ACCEPT_CHANNEL2_FIXED_LENGTH) {
		throw new Error(
			`accept_channel2 too short: need ${ACCEPT_CHANNEL2_FIXED_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const fundingSatoshis = payload.readBigUInt64BE(offset);
	offset += 8;
	const dustLimitSatoshis = payload.readBigUInt64BE(offset);
	offset += 8;
	const maxHtlcValueInFlightMsat = payload.readBigUInt64BE(offset);
	offset += 8;
	const htlcMinimumMsat = payload.readBigUInt64BE(offset);
	offset += 8;
	const minimumDepth = payload.readUInt32BE(offset);
	offset += 4;
	const toSelfDelay = payload.readUInt16BE(offset);
	offset += 2;
	const maxAcceptedHtlcs = payload.readUInt16BE(offset);
	offset += 2;
	const fundingPubkey = Buffer.from(payload.subarray(offset, offset + 33));
	offset += 33;
	const revocationBasepoint = Buffer.from(
		payload.subarray(offset, offset + 33)
	);
	offset += 33;
	const paymentBasepoint = Buffer.from(payload.subarray(offset, offset + 33));
	offset += 33;
	const delayedPaymentBasepoint = Buffer.from(
		payload.subarray(offset, offset + 33)
	);
	offset += 33;
	const htlcBasepoint = Buffer.from(payload.subarray(offset, offset + 33));
	offset += 33;
	const firstPerCommitmentPoint = Buffer.from(
		payload.subarray(offset, offset + 33)
	);
	offset += 33;
	const secondPerCommitmentPoint = Buffer.from(
		payload.subarray(offset, offset + 33)
	);
	offset += 33;

	const result: IAcceptChannel2Message = {
		channelId,
		fundingSatoshis,
		dustLimitSatoshis,
		maxHtlcValueInFlightMsat,
		htlcMinimumMsat,
		minimumDepth,
		toSelfDelay,
		maxAcceptedHtlcs,
		fundingPubkey,
		revocationBasepoint,
		paymentBasepoint,
		delayedPaymentBasepoint,
		htlcBasepoint,
		firstPerCommitmentPoint,
		secondPerCommitmentPoint
	};

	if (offset < payload.length) {
		const { records } = decodeTlvStream(payload, offset);
		for (const record of records) {
			if (record.type === TLV_CHANNEL_TYPE) {
				result.channelType = record.value;
			}
		}
	}

	return result;
}
