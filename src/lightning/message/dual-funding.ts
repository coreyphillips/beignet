/**
 * BOLT 2: `open_channel2` and `accept_channel2` message encoding/decoding.
 *
 * open_channel2 (type 64):
 *   [32: chain_hash]
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

import { BITCOIN_CHAIN_HASH } from '../channel/types';
import { decodeTlvStream, encodeTlvStream, ITlvRecord } from './tlv';
import {
	ILeaseRates,
	encodeLeaseRates,
	decodeLeaseRates,
	LEASE_RATES_LENGTH
} from '../gossip/types';

/** TLV type for channel_type */
const TLV_CHANNEL_TYPE = 1n;
/** Liquidity ads (bLIP-0051): request_funds TLV in open_channel2. */
const TLV_REQUEST_FUNDS = 5n;
/** Liquidity ads (bLIP-0051): will_fund TLV in accept_channel2. */
const TLV_WILL_FUND = 5n;

/** Buyer's lease request, carried in open_channel2 (bLIP-0051). */
export interface IRequestFunds {
	/** Inbound liquidity requested from the seller, in satoshis (u64). */
	requestedSats: bigint;
	/** Current block height, bounding lease_expiry (u32). */
	blockheight: number;
}

/** Seller's signed lease commitment, carried in accept_channel2 (bLIP-0051). */
export interface IWillFund {
	/** 64-byte signature over the lease parameters. */
	signature: Buffer;
	/** Lease rates the seller is committing to (echoes node_announcement). */
	leaseRates: ILeaseRates;
}

/** Encode request_funds: requested_sats(u64) || blockheight(u32). */
function encodeRequestFunds(r: IRequestFunds): Buffer {
	const buf = Buffer.alloc(12);
	buf.writeBigUInt64BE(r.requestedSats, 0);
	buf.writeUInt32BE(r.blockheight, 8);
	return buf;
}

/** Decode request_funds. */
function decodeRequestFunds(buf: Buffer): IRequestFunds {
	return {
		requestedSats: buf.readBigUInt64BE(0),
		blockheight: buf.readUInt32BE(8)
	};
}

/** Encode will_fund: signature(64) || lease_rates(14). */
function encodeWillFund(w: IWillFund): Buffer {
	if (w.signature.length !== 64) {
		throw new Error('will_fund signature must be 64 bytes');
	}
	return Buffer.concat([w.signature, encodeLeaseRates(w.leaseRates)]);
}

/** Decode will_fund. */
function decodeWillFund(buf: Buffer): IWillFund {
	return {
		signature: Buffer.from(buf.subarray(0, 64)),
		leaseRates: decodeLeaseRates(buf.subarray(64, 64 + LEASE_RATES_LENGTH))
	};
}

export interface IOpenChannel2Message {
	/**
	 * Genesis hash of the chain the channel opens on (spec: the FIRST field of
	 * open_channel2). Optional on encode for backward compatibility with
	 * existing callers/tests (defaults to Bitcoin mainnet); always present
	 * after decode.
	 */
	chainHash?: Buffer;
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
	/** Liquidity ads (bLIP-0051): buyer's inbound-liquidity request. */
	requestFunds?: IRequestFunds;
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
	/** Liquidity ads (bLIP-0051): seller's signed lease commitment. */
	willFund?: IWillFund;
}

// open_channel2 fixed payload length:
// 32 + 4 + 4 + 8 + 8 + 8 + 8 + 2 + 2 + 4 + 33*7 + 1 = 312
const OPEN_CHANNEL2_FIXED_LENGTH = 344; // incl. the leading 32-byte chain_hash

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

	// chain_hash is the FIRST field per the merged BOLT 2 (CLN rejects the
	// whole message as unparsable without it).
	(msg.chainHash ?? BITCOIN_CHAIN_HASH).copy(buf, offset);
	offset += 32;
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

	// TLV records (strictly increasing type order)
	const tlvRecords: ITlvRecord[] = [];
	if (msg.channelType) {
		tlvRecords.push({ type: TLV_CHANNEL_TYPE, value: msg.channelType });
	}
	if (msg.requestFunds) {
		tlvRecords.push({
			type: TLV_REQUEST_FUNDS,
			value: encodeRequestFunds(msg.requestFunds)
		});
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

	const chainHash = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
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
		chainHash,
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
			} else if (record.type === TLV_REQUEST_FUNDS) {
				result.requestFunds = decodeRequestFunds(record.value);
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
	if (msg.willFund) {
		tlvRecords.push({
			type: TLV_WILL_FUND,
			value: encodeWillFund(msg.willFund)
		});
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
			} else if (record.type === TLV_WILL_FUND) {
				result.willFund = decodeWillFund(record.value);
			}
		}
	}

	return result;
}
