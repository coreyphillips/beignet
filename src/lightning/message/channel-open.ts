/**
 * BOLT 2: `open_channel` and `accept_channel` message encoding/decoding.
 *
 * open_channel (type 32):
 *   [32: chain_hash]
 *   [32: temporary_channel_id]
 *   [8: funding_satoshis]
 *   [8: push_msat]
 *   [8: dust_limit_satoshis]
 *   [8: max_htlc_value_in_flight_msat]
 *   [8: channel_reserve_satoshis]
 *   [8: htlc_minimum_msat]
 *   [4: feerate_per_kw]
 *   [2: to_self_delay]
 *   [2: max_accepted_htlcs]
 *   [33: funding_pubkey]
 *   [33: revocation_basepoint]
 *   [33: payment_basepoint]
 *   [33: delayed_payment_basepoint]
 *   [33: htlc_basepoint]
 *   [33: first_per_commitment_point]
 *   [1: channel_flags]
 *   [open_channel_tlvs]
 *
 * accept_channel (type 33):
 *   [32: temporary_channel_id]
 *   [8: dust_limit_satoshis]
 *   [8: max_htlc_value_in_flight_msat]
 *   [8: channel_reserve_satoshis]
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
 *   [accept_channel_tlvs]
 */

import { decodeTlvStream, encodeTlvStream, ITlvRecord } from './tlv';

/** TLV types for open_channel / accept_channel */
const TLV_UPFRONT_SHUTDOWN_SCRIPT = 0n;
const TLV_CHANNEL_TYPE = 1n;

export interface IOpenChannelMessage {
	chainHash: Buffer;
	temporaryChannelId: Buffer;
	fundingSatoshis: bigint;
	pushMsat: bigint;
	dustLimitSatoshis: bigint;
	maxHtlcValueInFlightMsat: bigint;
	channelReserveSatoshis: bigint;
	htlcMinimumMsat: bigint;
	feeratePerKw: number;
	toSelfDelay: number;
	maxAcceptedHtlcs: number;
	fundingPubkey: Buffer;
	revocationBasepoint: Buffer;
	paymentBasepoint: Buffer;
	delayedPaymentBasepoint: Buffer;
	htlcBasepoint: Buffer;
	firstPerCommitmentPoint: Buffer;
	channelFlags: number;
	upfrontShutdownScript?: Buffer;
	channelType?: Buffer;
}

export interface IAcceptChannelMessage {
	temporaryChannelId: Buffer;
	dustLimitSatoshis: bigint;
	maxHtlcValueInFlightMsat: bigint;
	channelReserveSatoshis: bigint;
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
	upfrontShutdownScript?: Buffer;
	channelType?: Buffer;
}

const OPEN_CHANNEL_FIXED_LENGTH = 319;
const ACCEPT_CHANNEL_FIXED_LENGTH = 270;

/**
 * Encode an `open_channel` message payload (without 2-byte type prefix).
 */
export function encodeOpenChannelMessage(msg: IOpenChannelMessage): Buffer {
	const buf = Buffer.alloc(OPEN_CHANNEL_FIXED_LENGTH);
	let offset = 0;

	msg.chainHash.copy(buf, offset);
	offset += 32;
	msg.temporaryChannelId.copy(buf, offset);
	offset += 32;
	buf.writeBigUInt64BE(msg.fundingSatoshis, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.pushMsat, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.dustLimitSatoshis, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.maxHtlcValueInFlightMsat, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.channelReserveSatoshis, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.htlcMinimumMsat, offset);
	offset += 8;
	buf.writeUInt32BE(msg.feeratePerKw, offset);
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
	buf[offset] = msg.channelFlags;

	const parts: Buffer[] = [buf];

	// TLV records
	const tlvRecords: ITlvRecord[] = [];
	if (msg.upfrontShutdownScript) {
		tlvRecords.push({
			type: TLV_UPFRONT_SHUTDOWN_SCRIPT,
			value: msg.upfrontShutdownScript
		});
	}
	if (msg.channelType) {
		tlvRecords.push({ type: TLV_CHANNEL_TYPE, value: msg.channelType });
	}
	if (tlvRecords.length > 0) {
		parts.push(encodeTlvStream(tlvRecords));
	}

	return Buffer.concat(parts);
}

/**
 * Decode an `open_channel` message payload.
 */
export function decodeOpenChannelMessage(payload: Buffer): IOpenChannelMessage {
	if (payload.length < OPEN_CHANNEL_FIXED_LENGTH) {
		throw new Error(
			`open_channel too short: need ${OPEN_CHANNEL_FIXED_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const chainHash = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const temporaryChannelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const fundingSatoshis = payload.readBigUInt64BE(offset);
	offset += 8;
	const pushMsat = payload.readBigUInt64BE(offset);
	offset += 8;
	const dustLimitSatoshis = payload.readBigUInt64BE(offset);
	offset += 8;
	const maxHtlcValueInFlightMsat = payload.readBigUInt64BE(offset);
	offset += 8;
	const channelReserveSatoshis = payload.readBigUInt64BE(offset);
	offset += 8;
	const htlcMinimumMsat = payload.readBigUInt64BE(offset);
	offset += 8;
	const feeratePerKw = payload.readUInt32BE(offset);
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
	const channelFlags = payload[offset];
	offset += 1;

	const result: IOpenChannelMessage = {
		chainHash,
		temporaryChannelId,
		fundingSatoshis,
		pushMsat,
		dustLimitSatoshis,
		maxHtlcValueInFlightMsat,
		channelReserveSatoshis,
		htlcMinimumMsat,
		feeratePerKw,
		toSelfDelay,
		maxAcceptedHtlcs,
		fundingPubkey,
		revocationBasepoint,
		paymentBasepoint,
		delayedPaymentBasepoint,
		htlcBasepoint,
		firstPerCommitmentPoint,
		channelFlags
	};

	// Parse TLV
	if (offset < payload.length) {
		const { records } = decodeTlvStream(payload, offset);
		for (const record of records) {
			if (record.type === TLV_UPFRONT_SHUTDOWN_SCRIPT) {
				result.upfrontShutdownScript = record.value;
			} else if (record.type === TLV_CHANNEL_TYPE) {
				result.channelType = record.value;
			}
		}
	}

	return result;
}

/**
 * Encode an `accept_channel` message payload (without 2-byte type prefix).
 */
export function encodeAcceptChannelMessage(msg: IAcceptChannelMessage): Buffer {
	const buf = Buffer.alloc(ACCEPT_CHANNEL_FIXED_LENGTH);
	let offset = 0;

	msg.temporaryChannelId.copy(buf, offset);
	offset += 32;
	buf.writeBigUInt64BE(msg.dustLimitSatoshis, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.maxHtlcValueInFlightMsat, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.channelReserveSatoshis, offset);
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

	const parts: Buffer[] = [buf];

	const tlvRecords: ITlvRecord[] = [];
	if (msg.upfrontShutdownScript) {
		tlvRecords.push({
			type: TLV_UPFRONT_SHUTDOWN_SCRIPT,
			value: msg.upfrontShutdownScript
		});
	}
	if (msg.channelType) {
		tlvRecords.push({ type: TLV_CHANNEL_TYPE, value: msg.channelType });
	}
	if (tlvRecords.length > 0) {
		parts.push(encodeTlvStream(tlvRecords));
	}

	return Buffer.concat(parts);
}

/**
 * Decode an `accept_channel` message payload.
 */
export function decodeAcceptChannelMessage(
	payload: Buffer
): IAcceptChannelMessage {
	if (payload.length < ACCEPT_CHANNEL_FIXED_LENGTH) {
		throw new Error(
			`accept_channel too short: need ${ACCEPT_CHANNEL_FIXED_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const temporaryChannelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const dustLimitSatoshis = payload.readBigUInt64BE(offset);
	offset += 8;
	const maxHtlcValueInFlightMsat = payload.readBigUInt64BE(offset);
	offset += 8;
	const channelReserveSatoshis = payload.readBigUInt64BE(offset);
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

	const result: IAcceptChannelMessage = {
		temporaryChannelId,
		dustLimitSatoshis,
		maxHtlcValueInFlightMsat,
		channelReserveSatoshis,
		htlcMinimumMsat,
		minimumDepth,
		toSelfDelay,
		maxAcceptedHtlcs,
		fundingPubkey,
		revocationBasepoint,
		paymentBasepoint,
		delayedPaymentBasepoint,
		htlcBasepoint,
		firstPerCommitmentPoint
	};

	if (offset < payload.length) {
		const { records } = decodeTlvStream(payload, offset);
		for (const record of records) {
			if (record.type === TLV_UPFRONT_SHUTDOWN_SCRIPT) {
				result.upfrontShutdownScript = record.value;
			} else if (record.type === TLV_CHANNEL_TYPE) {
				result.channelType = record.value;
			}
		}
	}

	return result;
}
