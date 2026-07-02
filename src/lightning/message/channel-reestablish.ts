/**
 * BOLT 2: `channel_reestablish` message encoding/decoding.
 *
 * channel_reestablish (type 136):
 *   [32: channel_id]
 *   [8: next_commitment_number]
 *   [8: next_revocation_number]
 *   [32: your_last_per_commitment_secret]
 *   [33: my_current_per_commitment_point]
 *   TLV stream:
 *     type 1 (next_funding): [32: next_funding_txid][1: retransmit_flags] —
 *     txid of an in-flight interactive (splice) funding tx, in tx.getHash()
 *     internal byte order (same convention as tx_signatures.txid). Set when we
 *     sent commitment_signed for the new funding tx but have not received the
 *     peer's tx_signatures. Flags bit 0 = "retransmit your commitment_signed".
 *     (Decode also accepts legacy type 0 = bare 32-byte txid.)
 */

import { encodeTlvStream, decodeTlvStream, ITlvRecord } from './tlv';

export interface IChannelReestablishMessage {
	channelId: Buffer;
	nextCommitmentNumber: bigint;
	nextRevocationNumber: bigint;
	yourLastPerCommitmentSecret: Buffer;
	myCurrentPerCommitmentPoint: Buffer;
	/** Splice resumption (merged splice spec): txid of the in-flight funding tx. */
	nextFundingTxid?: Buffer;
	/**
	 * CLN v25.12+ appends a retransmit-flags byte to the next_funding TLV
	 * (bit 0: peer asks us to retransmit commitment_signed). Absent on peers
	 * using the original 32-byte TLV.
	 */
	nextFundingRetransmitFlags?: number;
	/**
	 * option_taproot: a freshly-generated MuSig2 verification public nonce (66
	 * bytes) re-seeding the peer for the next commitment. The in-memory nonces are
	 * lost on reconnect, so both sides regenerate and re-exchange them here (LND
	 * local_nonce, TLV type 4 — same convention as open/accept/revoke).
	 */
	nextLocalNonce?: Buffer;
	/**
	 * FFOR (specs/ffor-offline-receive.md §11.1): TLV 55001 — the sender's
	 * fast-forward epoch state: `[32: epoch_id][2: last_seq][1: state]`
	 * (state: 0 = setup, 1 = epoch, 2 = reconciling, 3 = closed). Absence
	 * means "no epoch" and drives the §7.5 crash-window resolution.
	 */
	fforEpoch?: { epochId: Buffer; lastSeq: number; state: number };
	/**
	 * FFOR prototype extension: TLV 55003 — S's per-commitment point for the
	 * reconciliation catch-up commitment (n0+2 when escape sigs were
	 * exchanged). R holds n0+1 from the last pre-epoch revoke_and_ack but has
	 * no way to learn n0+2 before signing ff_reconcile — spec erratum.
	 */
	fforCatchupPoint?: Buffer;
}

const CHANNEL_REESTABLISH_LENGTH = 113; // 32 + 8 + 8 + 32 + 33

// Current splice spec (CLN v25.12+/wire/peer_wire.csv): `next_funding` is TLV
// type 1 = [32: next_funding_txid][1: retransmit_flags]. Type 1 is ODD, so a
// peer on the older spec simply ignores it. The ORIGINAL merged-spec TLV was
// type 0 (EVEN, bare 32-byte txid) — modern CLN no longer knows type 0 and
// hard-rejects the whole reestablish ("bad reestablish msg") because unknown
// even TLVs are fatal. So: always SEND type 1, ACCEPT both on decode.
const TLV_NEXT_FUNDING = 1n;
const TLV_NEXT_FUNDING_LEGACY = 0n;
/** option_taproot verification nonce (LND local_nonce convention). */
const TLV_NEXT_LOCAL_NONCE = 4n;
/** FFOR epoch state (spec §11.1). */
const TLV_FFOR_EPOCH = 55001n;
/** FFOR reconciliation catch-up point (prototype extension, odd). */
const TLV_FFOR_CATCHUP_POINT = 55003n;

/**
 * Encode a `channel_reestablish` message payload.
 */
export function encodeChannelReestablishMessage(
	msg: IChannelReestablishMessage
): Buffer {
	const buf = Buffer.alloc(CHANNEL_REESTABLISH_LENGTH);
	let offset = 0;

	msg.channelId.copy(buf, offset);
	offset += 32;
	buf.writeBigUInt64BE(msg.nextCommitmentNumber, offset);
	offset += 8;
	buf.writeBigUInt64BE(msg.nextRevocationNumber, offset);
	offset += 8;
	msg.yourLastPerCommitmentSecret.copy(buf, offset);
	offset += 32;
	msg.myCurrentPerCommitmentPoint.copy(buf, offset);

	const parts: Buffer[] = [buf];

	const tlvRecords: ITlvRecord[] = [];
	if (msg.nextFundingTxid) {
		if (msg.nextFundingTxid.length !== 32) {
			throw new Error(
				`next_funding_txid must be 32 bytes, got ${msg.nextFundingTxid.length}`
			);
		}
		tlvRecords.push({
			type: TLV_NEXT_FUNDING,
			value: Buffer.concat([
				msg.nextFundingTxid,
				Buffer.from([msg.nextFundingRetransmitFlags ?? 0])
			])
		});
	}
	if (msg.nextLocalNonce) {
		if (msg.nextLocalNonce.length !== 66) {
			throw new Error(
				`next_local_nonce must be 66 bytes, got ${msg.nextLocalNonce.length}`
			);
		}
		tlvRecords.push({
			type: TLV_NEXT_LOCAL_NONCE,
			value: msg.nextLocalNonce
		});
	}
	if (msg.fforEpoch) {
		if (msg.fforEpoch.epochId.length !== 32) {
			throw new Error('ffor epoch_id must be 32 bytes');
		}
		const v = Buffer.alloc(35);
		msg.fforEpoch.epochId.copy(v, 0);
		v.writeUInt16BE(msg.fforEpoch.lastSeq, 32);
		v.writeUInt8(msg.fforEpoch.state, 34);
		tlvRecords.push({ type: TLV_FFOR_EPOCH, value: v });
	}
	if (msg.fforCatchupPoint) {
		if (msg.fforCatchupPoint.length !== 33) {
			throw new Error('ffor catch-up point must be 33 bytes');
		}
		tlvRecords.push({
			type: TLV_FFOR_CATCHUP_POINT,
			value: msg.fforCatchupPoint
		});
	}
	if (tlvRecords.length > 0) {
		parts.push(encodeTlvStream(tlvRecords));
	}

	return Buffer.concat(parts);
}

/**
 * Decode a `channel_reestablish` message payload.
 */
export function decodeChannelReestablishMessage(
	payload: Buffer
): IChannelReestablishMessage {
	if (payload.length < CHANNEL_REESTABLISH_LENGTH) {
		throw new Error(
			`channel_reestablish too short: need ${CHANNEL_REESTABLISH_LENGTH} bytes, got ${payload.length}`
		);
	}

	let offset = 0;

	const channelId = Buffer.from(payload.subarray(offset, offset + 32));
	offset += 32;
	const nextCommitmentNumber = payload.readBigUInt64BE(offset);
	offset += 8;
	const nextRevocationNumber = payload.readBigUInt64BE(offset);
	offset += 8;
	const yourLastPerCommitmentSecret = Buffer.from(
		payload.subarray(offset, offset + 32)
	);
	offset += 32;
	const myCurrentPerCommitmentPoint = Buffer.from(
		payload.subarray(offset, offset + 33)
	);
	offset += 33;

	const result: IChannelReestablishMessage = {
		channelId,
		nextCommitmentNumber,
		nextRevocationNumber,
		yourLastPerCommitmentSecret,
		myCurrentPerCommitmentPoint
	};

	if (offset < payload.length) {
		const { records } = decodeTlvStream(payload, offset);
		for (const record of records) {
			// Type 1 = current spec ([txid][retransmit_flags]); type 0 = the
			// original merged-spec bare txid (legacy peers). Take the txid either
			// way — dropping it would make us forget the peer has an in-flight
			// splice.
			if (
				(record.type === TLV_NEXT_FUNDING ||
					record.type === TLV_NEXT_FUNDING_LEGACY) &&
				record.value.length >= 32
			) {
				result.nextFundingTxid = Buffer.from(record.value.subarray(0, 32));
				if (record.value.length >= 33) {
					result.nextFundingRetransmitFlags = record.value[32];
				}
			} else if (
				record.type === TLV_NEXT_LOCAL_NONCE &&
				record.value.length === 66
			) {
				result.nextLocalNonce = Buffer.from(record.value);
			} else if (record.type === TLV_FFOR_EPOCH && record.value.length === 35) {
				result.fforEpoch = {
					epochId: Buffer.from(record.value.subarray(0, 32)),
					lastSeq: record.value.readUInt16BE(32),
					state: record.value.readUInt8(34)
				};
			} else if (
				record.type === TLV_FFOR_CATCHUP_POINT &&
				record.value.length === 33
			) {
				result.fforCatchupPoint = Buffer.from(record.value);
			}
		}
	}

	return result;
}
