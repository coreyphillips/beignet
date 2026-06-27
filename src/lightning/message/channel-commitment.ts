/**
 * BOLT 2: `commitment_signed` and `revoke_and_ack` message encoding/decoding.
 *
 * commitment_signed (type 132):
 *   [32: channel_id]
 *   [64: signature]
 *   [2: num_htlcs]
 *   [num_htlcs * 64: htlc_signature]
 *   commitment_signed_tlvs:
 *     type 1 (splice_info): [32: funding_txid]
 *
 * Splicing (lightning/bolts #1160, CLN-compatible): during a splice the sender
 * MUST set the `funding_txid` (TLV type 1) to the funding transaction the
 * commitment spends, so the receiver can route it to the right (old vs spliced)
 * funding output. txid is internal byte order (tx.getHash(), CLN
 * `towire_bitcoin_txid`).
 *
 * revoke_and_ack (type 133):
 *   [32: channel_id]
 *   [32: per_commitment_secret]
 *   [33: next_per_commitment_point]
 */

import { encodeTlvStream, decodeTlvStream, ITlvRecord } from './tlv';

export interface ICommitmentSignedMessage {
	channelId: Buffer;
	signature: Buffer;
	htlcSignatures: Buffer[];
	/** Splice: the funding txid this commitment spends (TLV type 1, internal order). */
	fundingTxid?: Buffer;
}

const TLV_SPLICE_INFO = 1n;

export interface IRevokeAndAckMessage {
	channelId: Buffer;
	perCommitmentSecret: Buffer;
	nextPerCommitmentPoint: Buffer;
}

const COMMITMENT_SIGNED_FIXED_LENGTH = 98; // 32 + 64 + 2
const REVOKE_AND_ACK_LENGTH = 97; // 32 + 32 + 33

/**
 * Encode a `commitment_signed` message payload.
 */
export function encodeCommitmentSignedMessage(
	msg: ICommitmentSignedMessage
): Buffer {
	const numHtlcs = msg.htlcSignatures.length;
	const buf = Buffer.alloc(COMMITMENT_SIGNED_FIXED_LENGTH + numHtlcs * 64);
	let offset = 0;

	msg.channelId.copy(buf, offset);
	offset += 32;
	msg.signature.copy(buf, offset);
	offset += 64;
	buf.writeUInt16BE(numHtlcs, offset);
	offset += 2;

	for (const sig of msg.htlcSignatures) {
		sig.copy(buf, offset);
		offset += 64;
	}

	// Splice: append the funding_txid TLV (type 1) when set.
	if (msg.fundingTxid) {
		if (msg.fundingTxid.length !== 32) {
			throw new Error(
				`commitment_signed funding_txid must be 32 bytes, got ${msg.fundingTxid.length}`
			);
		}
		const records: ITlvRecord[] = [
			{ type: TLV_SPLICE_INFO, value: msg.fundingTxid }
		];
		return Buffer.concat([buf, encodeTlvStream(records)]);
	}

	return buf;
}

/**
 * Decode a `commitment_signed` message payload.
 */
export function decodeCommitmentSignedMessage(
	payload: Buffer
): ICommitmentSignedMessage {
	if (payload.length < COMMITMENT_SIGNED_FIXED_LENGTH) {
		throw new Error(
			`commitment_signed too short: need ${COMMITMENT_SIGNED_FIXED_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const signature = Buffer.from(payload.subarray(offset, offset + 64));
	offset += 64;
	const numHtlcs = payload.readUInt16BE(offset);
	offset += 2;

	const expectedLength = COMMITMENT_SIGNED_FIXED_LENGTH + numHtlcs * 64;
	if (payload.length < expectedLength) {
		throw new Error(
			`commitment_signed too short for ${numHtlcs} HTLCs: need ${expectedLength} bytes, got ${payload.length}`
		);
	}

	const htlcSignatures: Buffer[] = [];
	for (let i = 0; i < numHtlcs; i++) {
		htlcSignatures.push(Buffer.from(payload.subarray(offset, offset + 64)));
		offset += 64;
	}

	// Splice: parse the optional funding_txid TLV (type 1).
	let fundingTxid: Buffer | undefined;
	if (offset < payload.length) {
		const { records } = decodeTlvStream(payload, offset);
		for (const record of records) {
			if (record.type === TLV_SPLICE_INFO && record.value.length === 32) {
				fundingTxid = Buffer.from(record.value);
			}
		}
	}

	return { channelId, signature, htlcSignatures, fundingTxid };
}

/**
 * Encode a `revoke_and_ack` message payload.
 */
export function encodeRevokeAndAckMessage(msg: IRevokeAndAckMessage): Buffer {
	const buf = Buffer.alloc(REVOKE_AND_ACK_LENGTH);
	msg.channelId.copy(buf, 0);
	msg.perCommitmentSecret.copy(buf, 32);
	msg.nextPerCommitmentPoint.copy(buf, 64);
	return buf;
}

/**
 * Decode a `revoke_and_ack` message payload.
 */
export function decodeRevokeAndAckMessage(
	payload: Buffer
): IRevokeAndAckMessage {
	if (payload.length < REVOKE_AND_ACK_LENGTH) {
		throw new Error(
			`revoke_and_ack too short: need ${REVOKE_AND_ACK_LENGTH} bytes, got ${payload.length}`
		);
	}

	const channelId = Buffer.from(payload.subarray(0, 32));
	const perCommitmentSecret = Buffer.from(payload.subarray(32, 64));
	const nextPerCommitmentPoint = Buffer.from(payload.subarray(64, 97));

	return { channelId, perCommitmentSecret, nextPerCommitmentPoint };
}
