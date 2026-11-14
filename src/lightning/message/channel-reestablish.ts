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
 *   type 5 (my_current_funding_locked): [32: txid][1: retransmit_flags] -
 *     the funding tx the sender last locked (splice_locked, or channel_ready
 *     for the original funding), same byte order. Flags bit 0 = "retransmit
 *     your announcement_signatures".
 */

import type { ITlvRecord } from './tlv';
import { encodeTlvStream, decodeTlvStream } from './tlv';
import {
	decodeFforReestablishTlv,
	encodeFforReestablishTlv
} from '../ffor/messages';
import type { IFforReestablishTlv } from '../ffor/types';
import { FF_REESTABLISH_TLV_TYPE } from '../ffor/types';

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
	 * Splice spec (bolts#1160) TLV 5: the funding tx the sender last locked.
	 * A receiver treats it as a splice_locked for that txid, which is how a
	 * lock lost across a disconnect is recovered.
	 */
	myCurrentFundingLocked?: IMyCurrentFundingLocked;
	/**
	 * FFOR (docs/specs/ffor-offline-receive.md section 11.1): TLV 55001, the
	 * epoch id, lifecycle state, last_seq and H_act of the channel's epoch.
	 * Odd, so a peer without the feature ignores it.
	 */
	ffor?: IFforReestablishTlv;
}

export interface IMyCurrentFundingLocked {
	/** Internal byte order, as in splice_locked and tx_signatures. */
	txid: Buffer;
	/** Bit 0 ({@link RETRANSMIT_ANNOUNCEMENT_SIGNATURES}) asks for announcement_signatures. */
	retransmitFlags: number;
}

/** my_current_funding_locked retransmit_flags bit 0. */
export const RETRANSMIT_ANNOUNCEMENT_SIGNATURES = 1;

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
const TLV_MY_CURRENT_FUNDING_LOCKED = 5n;
const CHANNEL_REESTABLISH_TLV_TYPES = new Set<bigint>([
	TLV_NEXT_FUNDING_LEGACY,
	TLV_NEXT_FUNDING,
	TLV_NEXT_LOCAL_NONCE,
	TLV_MY_CURRENT_FUNDING_LOCKED,
	FF_REESTABLISH_TLV_TYPE
]);

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
	if (msg.myCurrentFundingLocked) {
		const { txid, retransmitFlags } = msg.myCurrentFundingLocked;
		if (txid.length !== 32) {
			throw new Error(
				`my_current_funding_locked txid must be 32 bytes, got ${txid.length}`
			);
		}
		tlvRecords.push({
			type: TLV_MY_CURRENT_FUNDING_LOCKED,
			value: Buffer.concat([txid, Buffer.from([retransmitFlags & 0xff])])
		});
	}
	if (msg.ffor) {
		tlvRecords.push(encodeFforReestablishTlv(msg.ffor));
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
		const { records } = decodeTlvStream(
			payload,
			offset,
			CHANNEL_REESTABLISH_TLV_TYPES
		);
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
			} else if (
				record.type === TLV_MY_CURRENT_FUNDING_LOCKED &&
				record.value.length >= 33
			) {
				// A short record is dropped like any malformed odd TLV; bytes past
				// the flags are left for a future extension.
				result.myCurrentFundingLocked = {
					txid: Buffer.from(record.value.subarray(0, 32)),
					retransmitFlags: record.value[32]
				};
			} else if (record.type === FF_REESTABLISH_TLV_TYPE) {
				// A malformed epoch TLV is a peer bug in an odd record: drop
				// the record rather than the whole reestablish.
				try {
					result.ffor = decodeFforReestablishTlv(record.value);
				} catch {
					/* ignored: see above */
				}
			}
		}
	}

	return result;
}
