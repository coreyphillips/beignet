/**
 * BOLT 2: Splice message encode/decode (lightning/bolts PR #1160).
 *
 * Field order and type numbers follow the merged spec. The `relativeSatoshis`
 * field is the spec's `funding_contribution_satoshis` (signed: positive =
 * splice-in, negative = splice-out).
 *
 * splice_init (type 80):
 *   [32: channel_id]
 *   [8:  funding_contribution_satoshis] (signed 64-bit)
 *   [4:  funding_feerate_perkw]
 *   [4:  locktime]
 *   [33: funding_pubkey]
 *   TLV: [2: require_confirmed_inputs] (presence = true)
 *
 * splice_ack (type 81):
 *   [32: channel_id]
 *   [8:  funding_contribution_satoshis] (signed 64-bit)
 *   [33: funding_pubkey]
 *   TLV: [2: require_confirmed_inputs]
 *
 * splice_locked (type 77):
 *   [32: channel_id]
 *   [32: splice_txid]
 *
 * NOTE on splice_locked compatibility: CLN v24.11.1 defined splice_locked with
 * channel_id only; the merged spec (and CLN v25.02+) appends splice_txid. We
 * always append the txid when we know it (BOLT 1 requires receivers to ignore
 * extra bytes, so older peers are unaffected) and tolerate both lengths on
 * decode.
 */

// ---- Interfaces ----

export interface ISpliceMessage {
	channelId: Buffer;
	fundingPubkey: Buffer;
	relativeSatoshis: bigint; // signed: positive = splice-in, negative = splice-out
	fundingFeeratePerkw: number;
	locktime: number;
	requireConfirmedInputs?: boolean;
}

export interface ISpliceAckMessage {
	channelId: Buffer;
	fundingPubkey: Buffer;
	relativeSatoshis: bigint; // signed: positive = splice-in, negative = splice-out
	requireConfirmedInputs?: boolean;
}

export interface ISpliceLockedMessage {
	channelId: Buffer;
	/**
	 * The splice transaction id (merged-spec field, sent by CLN v25.02+).
	 * Appended on the wire when known; optional because legacy peers
	 * (CLN v24.x) send channel_id only.
	 */
	fundingTxid?: Buffer;
}

// ---- splice (75) ----

/**
 * Encode a splice message payload (without 2-byte type prefix).
 */
export function encodeSpliceMessage(msg: ISpliceMessage): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}
	if (msg.fundingPubkey.length !== 33) {
		throw new Error(
			`Funding pubkey must be 33 bytes, got ${msg.fundingPubkey.length}`
		);
	}

	const parts: Buffer[] = [];

	// Fixed fields: 32 + 8 + 4 + 4 + 33 = 81 bytes
	const fixed = Buffer.alloc(81);
	let offset = 0;
	msg.channelId.copy(fixed, offset);
	offset += 32;
	fixed.writeBigInt64BE(msg.relativeSatoshis, offset);
	offset += 8;
	fixed.writeUInt32BE(msg.fundingFeeratePerkw, offset);
	offset += 4;
	fixed.writeUInt32BE(msg.locktime, offset);
	offset += 4;
	msg.fundingPubkey.copy(fixed, offset);
	parts.push(fixed);

	// TLV: require_confirmed_inputs (type 2, length 0)
	if (msg.requireConfirmedInputs) {
		const tlv = Buffer.alloc(2);
		tlv[0] = 2; // type
		tlv[1] = 0; // length
		parts.push(tlv);
	}

	return Buffer.concat(parts);
}

/**
 * Decode a splice message payload.
 */
export function decodeSpliceMessage(payload: Buffer): ISpliceMessage {
	if (payload.length < 81) {
		throw new Error(
			`splice message too short: need at least 81 bytes, got ${payload.length}`
		);
	}

	let offset = 0;
	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const relativeSatoshis = payload.readBigInt64BE(offset);
	offset += 8;
	const fundingFeeratePerkw = payload.readUInt32BE(offset);
	offset += 4;
	const locktime = payload.readUInt32BE(offset);
	offset += 4;
	const fundingPubkey = Buffer.from(payload.subarray(offset, offset + 33));
	offset += 33;

	// Parse optional TLV
	let requireConfirmedInputs: boolean | undefined;
	if (offset < payload.length) {
		const tlvType = payload[offset];
		offset += 1;
		if (tlvType === 2) {
			const tlvLen = payload[offset];
			offset += 1;
			if (tlvLen === 0) {
				requireConfirmedInputs = true;
			}
		}
	}

	return {
		channelId,
		fundingPubkey,
		relativeSatoshis,
		fundingFeeratePerkw,
		locktime,
		requireConfirmedInputs
	};
}

// ---- splice_ack (76) ----

/**
 * Encode a splice_ack message payload (without 2-byte type prefix).
 */
export function encodeSpliceAckMessage(msg: ISpliceAckMessage): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}
	if (msg.fundingPubkey.length !== 33) {
		throw new Error(
			`Funding pubkey must be 33 bytes, got ${msg.fundingPubkey.length}`
		);
	}

	const parts: Buffer[] = [];

	// Fixed fields: 32 + 8 + 33 = 73 bytes
	const fixed = Buffer.alloc(73);
	let offset = 0;
	msg.channelId.copy(fixed, offset);
	offset += 32;
	fixed.writeBigInt64BE(msg.relativeSatoshis, offset);
	offset += 8;
	msg.fundingPubkey.copy(fixed, offset);
	parts.push(fixed);

	// TLV: require_confirmed_inputs (type 2, length 0)
	if (msg.requireConfirmedInputs) {
		const tlv = Buffer.alloc(2);
		tlv[0] = 2; // type
		tlv[1] = 0; // length
		parts.push(tlv);
	}

	return Buffer.concat(parts);
}

/**
 * Decode a splice_ack message payload.
 */
export function decodeSpliceAckMessage(payload: Buffer): ISpliceAckMessage {
	if (payload.length < 73) {
		throw new Error(
			`splice_ack message too short: need at least 73 bytes, got ${payload.length}`
		);
	}

	let offset = 0;
	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const relativeSatoshis = payload.readBigInt64BE(offset);
	offset += 8;
	const fundingPubkey = Buffer.from(payload.subarray(offset, offset + 33));
	offset += 33;

	// Parse optional TLV
	let requireConfirmedInputs: boolean | undefined;
	if (offset < payload.length) {
		const tlvType = payload[offset];
		offset += 1;
		if (tlvType === 2) {
			const tlvLen = payload[offset];
			offset += 1;
			if (tlvLen === 0) {
				requireConfirmedInputs = true;
			}
		}
	}

	return {
		channelId,
		fundingPubkey,
		relativeSatoshis,
		requireConfirmedInputs
	};
}

// ---- splice_locked (77) ----

/**
 * Encode a splice_locked message payload (without 2-byte type prefix).
 */
export function encodeSpliceLockedMessage(msg: ISpliceLockedMessage): Buffer {
	if (msg.channelId.length !== 32) {
		throw new Error(`Channel ID must be 32 bytes, got ${msg.channelId.length}`);
	}
	if (msg.fundingTxid && msg.fundingTxid.length !== 32) {
		throw new Error(
			`splice_locked txid must be 32 bytes, got ${msg.fundingTxid.length}`
		);
	}

	// Merged spec: [channel_id][splice_txid]. Older peers (CLN v24.x) ignore the
	// trailing 32 bytes per BOLT 1. Emit channel_id only if the txid is unknown.
	const buf = Buffer.alloc(msg.fundingTxid ? 64 : 32);
	msg.channelId.copy(buf, 0);
	if (msg.fundingTxid) {
		msg.fundingTxid.copy(buf, 32);
	}

	return buf;
}

/**
 * Decode a splice_locked message payload.
 */
export function decodeSpliceLockedMessage(
	payload: Buffer
): ISpliceLockedMessage {
	if (payload.length < 32) {
		throw new Error(
			`splice_locked message too short: need at least 32 bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const fundingTxid =
		payload.length >= 64 ? Buffer.from(payload.subarray(32, 64)) : undefined;

	return { channelId, fundingTxid };
}
